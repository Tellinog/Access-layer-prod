import { randomUUID } from "node:crypto";
import { AuditLogger } from "../audit.js";
import { AppError } from "../errors.js";
import type { Repositories } from "../repositories.js";
import { randomToken, sha256 } from "../security.js";
import type { Config, GoogleIdentity, User } from "../types.js";
import { normalizeEmail } from "../validation.js";
import type { OAuthUpstreamGoogleClient } from "./google.js";
import type { OAuthAuthorizationFlowRepository } from "./flow-repository.js";
import type { OAuthFoundationRepository } from "./repository.js";
import {
  protectOAuthDownstreamState,
  unprotectOAuthDownstreamState
} from "./state-protection.js";
import { isCanonicalOAuthScope, isExactOAuthHttpsUri, isExactOAuthRedirectUri } from "./validation.js";

export const OAUTH_AUTHORIZATION_TRANSACTION_TTL_MS = 600_000;
export const OAUTH_AUTHORIZATION_CODE_TTL_MS = 60_000;
const PKCE_S256_CHALLENGE = /^[A-Za-z0-9_-]{43}$/;
const SCOPE_LIST = /^[a-z][a-z0-9-]{1,62}:[a-z][a-z0-9-]{1,62}:[a-z][a-z0-9-]{1,62}(?: [a-z][a-z0-9-]{1,62}:[a-z][a-z0-9-]{1,62}:[a-z][a-z0-9-]{1,62})*$/;

export type OAuthAuthorizationError =
  | "invalid_request"
  | "unauthorized_client"
  | "unsupported_response_type"
  | "invalid_scope"
  | "invalid_target"
  | "access_denied"
  | "server_error"
  | "temporarily_unavailable";

export type OAuthAuthorizationResult =
  | { kind: "local_error"; error: OAuthAuthorizationError; correlationId: string }
  | { kind: "redirect"; location: string };

export interface OAuthAuthorizationRequestContext {
  correlationId: string;
  requestIpHash: string | null;
  userAgentHash: string | null;
}

export interface OAuthAuthorizationDependencies {
  config: Config;
  foundation: OAuthFoundationRepository;
  flow: OAuthAuthorizationFlowRepository;
  legacy: Repositories;
  audit: AuditLogger;
  google: OAuthUpstreamGoogleClient;
  now?: () => Date;
}

function singleton(query: Record<string, unknown>, name: string): string | null {
  const value = query[name];
  return typeof value === "string" ? value : null;
}

function hasRepeated(query: Record<string, unknown>, names: readonly string[]): boolean {
  return names.some((name) => Array.isArray(query[name]));
}

function authorizationRedirect(
  redirectUri: string,
  params: { state?: string; code?: string; error?: OAuthAuthorizationError },
  issuer: string
): string {
  const question = redirectUri.indexOf("?");
  const base = question === -1 ? redirectUri : redirectUri.slice(0, question);
  const existing = question === -1 ? "" : redirectUri.slice(question + 1);
  const reserved = new Set(["code", "state", "iss", "error", "error_description", "error_uri"]);
  const preserved = existing.split("&").filter((part) => {
    if (part === "") return false;
    try {
      return !reserved.has([...new URLSearchParams(part).keys()][0] ?? "");
    } catch {
      return false;
    }
  });
  const response = new URLSearchParams();
  if (params.code !== undefined) response.set("code", params.code);
  if (params.state !== undefined) response.set("state", params.state);
  if (params.error !== undefined) response.set("error", params.error);
  response.set("iss", issuer);
  return `${base}?${[...preserved, response.toString()].join("&")}`;
}

function safeAuditMetadata(clientId?: string, resourceId?: string, scopes?: string[]): Record<string, unknown> {
  return {
    ...(clientId ? { client_id: clientId } : {}),
    ...(resourceId ? { resource_id: resourceId } : {}),
    ...(scopes ? { scopes } : {})
  };
}

async function auditDenied(
  deps: OAuthAuthorizationDependencies,
  ctx: OAuthAuthorizationRequestContext,
  reason: OAuthAuthorizationError,
  identifiers: { clientId?: string; resourceId?: string; scopes?: string[]; user?: User } = {}
): Promise<void> {
  await deps.audit.write({
    event_type: "oauth.authorization.denied",
    outcome: "denied",
    correlation_id: ctx.correlationId,
    actor_user_id: identifiers.user?.id,
    actor_google_sub: identifiers.user?.google_sub,
    request_ip_hash: ctx.requestIpHash,
    user_agent_hash: ctx.userAgentHash,
    reason_code: reason,
    metadata: safeAuditMetadata(identifiers.clientId, identifiers.resourceId, identifiers.scopes)
  });
}

async function upsertAndLinkVerifiedIdentity(repositories: Repositories, identity: GoogleIdentity): Promise<User> {
  return repositories.db.transaction(async (db) => {
    const tx = repositories.withDb(db);
    const user = await tx.upsertUser({
      googleSub: identity.googleSub,
      email: identity.email,
      emailNormalized: normalizeEmail(identity.email),
      emailVerified: identity.emailVerified,
      hd: identity.hd,
      displayName: identity.displayName,
      pictureUrl: identity.pictureUrl
    });
    await tx.linkPendingEmailGrants(user);
    return user;
  });
}

export class OAuthAuthorizationService {
  constructor(private readonly deps: OAuthAuthorizationDependencies) {}

  async authorize(
    query: Record<string, unknown>,
    ctx: OAuthAuthorizationRequestContext
  ): Promise<OAuthAuthorizationResult> {
    const parameterNames = [
      "response_type", "client_id", "redirect_uri", "scope", "state",
      "code_challenge", "code_challenge_method", "resource"
    ] as const;
    const clientId = singleton(query, "client_id");
    if (hasRepeated(query, ["client_id"]) || !clientId) {
      await auditDenied(this.deps, ctx, "invalid_request");
      return { kind: "local_error", error: "invalid_request", correlationId: ctx.correlationId };
    }

    let client;
    try {
      client = await this.deps.foundation.resolveClientByClientId(clientId);
    } catch {
      await auditDenied(this.deps, ctx, "server_error");
      return { kind: "local_error", error: "server_error", correlationId: ctx.correlationId };
    }
    if (!client) {
      await auditDenied(this.deps, ctx, "unauthorized_client");
      return { kind: "local_error", error: "unauthorized_client", correlationId: ctx.correlationId };
    }
    const redirectUri = singleton(query, "redirect_uri");
    let registeredRedirects: string[];
    try {
      registeredRedirects = await this.deps.foundation.resolveExactRedirectUris(client.id);
    } catch {
      await auditDenied(this.deps, ctx, "server_error", { clientId: client.clientId });
      return { kind: "local_error", error: "server_error", correlationId: ctx.correlationId };
    }
    if (
      hasRepeated(query, ["redirect_uri"]) ||
      !redirectUri ||
      !isExactOAuthRedirectUri(redirectUri) ||
      !registeredRedirects.includes(redirectUri)
    ) {
      await auditDenied(this.deps, ctx, "invalid_request", { clientId: client.clientId });
      return { kind: "local_error", error: "invalid_request", correlationId: ctx.correlationId };
    }

    const downstreamState = singleton(query, "state");
    const redirectError = async (error: OAuthAuthorizationError, resourceId?: string, scopes?: string[]) => {
      await auditDenied(this.deps, ctx, error, { clientId: client.clientId, resourceId, scopes });
      return {
        kind: "redirect" as const,
        location: authorizationRedirect(
          redirectUri,
          { error, ...(downstreamState ? { state: downstreamState } : {}) },
          this.deps.config.authIssuer
        )
      };
    };

    if (hasRepeated(query, parameterNames.filter((name) => name !== "client_id" && name !== "redirect_uri"))) {
      return redirectError("invalid_request");
    }

    if (client.status !== "active" || !client.grantTypes.includes("authorization_code")) {
      return redirectError("unauthorized_client");
    }
    const responseType = singleton(query, "response_type");
    if (responseType !== "code") {
      return redirectError(responseType ? "unsupported_response_type" : "invalid_request");
    }
    if (!downstreamState) return redirectError("invalid_request");

    const resourceId = singleton(query, "resource");
    if (!resourceId || !isExactOAuthHttpsUri(resourceId)) return redirectError("invalid_target");
    let resource;
    try {
      resource = await this.deps.foundation.resolveResourceByResourceId(resourceId);
    } catch {
      return redirectError("temporarily_unavailable", resourceId);
    }
    if (!resource || resource.status !== "active" || resource.audiencePolicy !== "exact_single_resource") {
      return redirectError("invalid_target", resourceId);
    }

    const scopeValue = singleton(query, "scope");
    const scopes = scopeValue && SCOPE_LIST.test(scopeValue) ? scopeValue.split(" ") : [];
    if (
      scopes.length === 0 ||
      new Set(scopes).size !== scopes.length ||
      scopes.some((scope) => !isCanonicalOAuthScope(scope))
    ) {
      return redirectError("invalid_scope", resource.resourceId);
    }
    const challenge = singleton(query, "code_challenge");
    const challengeMethod = singleton(query, "code_challenge_method");
    if (!challenge || !PKCE_S256_CHALLENGE.test(challenge) || challengeMethod !== "S256") {
      return redirectError("invalid_request", resource.resourceId, scopes);
    }
    try {
      for (const scope of scopes) {
        if (!await this.deps.foundation.isClientResourceScopeAllowed(client.id, resource.resourceId, scope)) {
          return redirectError("invalid_scope", resource.resourceId, scopes);
        }
      }
    } catch {
      return redirectError("temporarily_unavailable", resource.resourceId, scopes);
    }

    const protectionKey = this.deps.config.oauthTransactionProtectionKey;
    if (!protectionKey) return redirectError("server_error", resource.resourceId, scopes);
    const now = (this.deps.now ?? (() => new Date()))();
    const transactionId = randomUUID();
    const upstreamState = randomToken("", 32);
    const upstreamNonce = randomToken("", 32);
    try {
      await this.deps.legacy.db.transaction(async (db) => {
        await this.deps.flow.withDb(db).createAuthorizationTransaction({
          id: transactionId,
          oauthClientId: client.id,
          oauthResourceId: resource.id,
          redirectUri,
          requestedScopes: scopes,
          codeChallenge: challenge,
          protectedDownstreamState: protectOAuthDownstreamState(downstreamState, transactionId, protectionKey),
          upstreamStateHash: sha256(upstreamState),
          upstreamNonceHash: sha256(upstreamNonce),
          correlationId: ctx.correlationId,
          createdAt: now,
          expiresAt: new Date(now.getTime() + OAUTH_AUTHORIZATION_TRANSACTION_TTL_MS)
        });
        await new AuditLogger(this.deps.legacy.withDb(db)).write({
          event_type: "oauth.authorization.requested",
          outcome: "info",
          correlation_id: ctx.correlationId,
          request_ip_hash: ctx.requestIpHash,
          user_agent_hash: ctx.userAgentHash,
          metadata: safeAuditMetadata(client.clientId, resource.resourceId, scopes)
        });
      });
    } catch {
      return redirectError("temporarily_unavailable", resource.resourceId, scopes);
    }
    return { kind: "redirect", location: this.deps.google.createAuthorizationUrl({ state: upstreamState, nonce: upstreamNonce }) };
  }

  async callback(
    query: Record<string, unknown>,
    requestContext: OAuthAuthorizationRequestContext
  ): Promise<OAuthAuthorizationResult> {
    if (hasRepeated(query, ["state", "code", "error"])) {
      await auditDenied(this.deps, requestContext, "invalid_request");
      return { kind: "local_error", error: "invalid_request", correlationId: requestContext.correlationId };
    }
    const upstreamState = singleton(query, "state");
    if (!upstreamState) {
      await auditDenied(this.deps, requestContext, "invalid_request");
      return { kind: "local_error", error: "invalid_request", correlationId: requestContext.correlationId };
    }
    const now = (this.deps.now ?? (() => new Date()))();
    const transaction = await this.deps.flow.claimAuthorizationTransaction(sha256(upstreamState), now);
    if (!transaction) {
      await auditDenied(this.deps, requestContext, "invalid_request");
      return { kind: "local_error", error: "invalid_request", correlationId: requestContext.correlationId };
    }
    const ctx = { ...requestContext, correlationId: transaction.correlationId };
    const protectionKey = this.deps.config.oauthTransactionProtectionKey;
    let downstreamState: string;
    try {
      if (!protectionKey) throw new Error("missing protection key");
      downstreamState = unprotectOAuthDownstreamState(
        transaction.protectedDownstreamState,
        transaction.id,
        protectionKey
      );
    } catch {
      await this.denyClaimed(transaction.id, ctx, "server_error");
      return { kind: "local_error", error: "server_error", correlationId: ctx.correlationId };
    }

    const denyRedirect = async (
      error: OAuthAuthorizationError,
      identifiers: { clientId?: string; resourceId?: string; scopes?: string[]; user?: User } = {}
    ): Promise<OAuthAuthorizationResult> => {
      await this.denyClaimed(transaction.id, ctx, error, identifiers);
      return {
        kind: "redirect",
        location: authorizationRedirect(
          transaction.redirectUri,
          { error, state: downstreamState },
          this.deps.config.authIssuer
        )
      };
    };

    if (singleton(query, "error")) return denyRedirect("access_denied");
    const googleCode = singleton(query, "code");
    if (!googleCode) return denyRedirect("invalid_request");

    let identity: GoogleIdentity;
    try {
      identity = await this.deps.google.exchangeCodeForIdentity(googleCode, transaction.correlationId);
    } catch (error) {
      const identityDenied = error instanceof AppError && [
        "AUTH_INVALID_GOOGLE_TOKEN", "AUTH_EMAIL_NOT_VERIFIED", "AUTH_EXTERNAL_DOMAIN"
      ].includes(error.code);
      return denyRedirect(identityDenied ? "access_denied" : "temporarily_unavailable");
    }
    if (!identity.nonce || sha256(identity.nonce) !== transaction.upstreamNonceHash) {
      return denyRedirect("access_denied");
    }

    let user: User;
    try {
      user = await upsertAndLinkVerifiedIdentity(this.deps.legacy, identity);
    } catch {
      return denyRedirect("server_error");
    }
    if (user.status !== "active") return denyRedirect("access_denied", { user });

    let client;
    let resource;
    try {
      [client, resource] = await Promise.all([
        this.deps.foundation.resolveClientById(transaction.oauthClientId),
        this.deps.foundation.resolveResourceById(transaction.oauthResourceId)
      ]);
    } catch {
      return denyRedirect("temporarily_unavailable", { user });
    }
    if (!client || client.status !== "active" || !client.grantTypes.includes("authorization_code")) {
      return denyRedirect("unauthorized_client", { user });
    }
    if (!resource || resource.status !== "active" || resource.audiencePolicy !== "exact_single_resource") {
      return denyRedirect("invalid_target", { clientId: client.clientId, user });
    }
    const identifiers = {
      clientId: client.clientId,
      resourceId: resource.resourceId,
      scopes: transaction.requestedScopes,
      user
    };
    try {
      for (const scope of transaction.requestedScopes) {
        if (!await this.deps.foundation.isClientResourceScopeAllowed(client.id, resource.resourceId, scope)) {
          return denyRedirect("invalid_scope", identifiers);
        }
      }
    } catch {
      return denyRedirect("temporarily_unavailable", identifiers);
    }
    let entitlement;
    let mappings;
    try {
      [entitlement, mappings] = await Promise.all([
        this.deps.foundation.resolveActiveLegacyEntitlement(resource.id),
        this.deps.foundation.resolveResourceScopeMappings(resource.id)
      ]);
    } catch {
      return denyRedirect("temporarily_unavailable", identifiers);
    }
    if (!entitlement) return denyRedirect("invalid_scope", identifiers);
    const mappingsByScope = new Map(mappings.map((mapping) => [mapping.scope, mapping]));
    if (mappingsByScope.size !== mappings.length) return denyRedirect("invalid_scope", identifiers);
    const registeredPermissions = new Set(entitlement.registeredPermissionKeys);
    const requiredPermissions: string[] = [];
    for (const scope of transaction.requestedScopes) {
      const mapping = mappingsByScope.get(scope);
      if (!mapping || mapping.resourceId !== resource.resourceId || !registeredPermissions.has(mapping.legacyPermissionKey)) {
        return denyRedirect("invalid_scope", identifiers);
      }
      requiredPermissions.push(mapping.legacyPermissionKey);
    }
    let grant;
    try {
      grant = await this.deps.legacy.findActiveGrant(
        entitlement.legacyToolId,
        user.id,
        user.email_normalized
      );
    } catch {
      return denyRedirect("temporarily_unavailable", identifiers);
    }
    if (!grant || requiredPermissions.some((permission) => !grant.permissions.includes(permission))) {
      return denyRedirect("access_denied", identifiers);
    }

    const rawCode = randomToken("", 32);
    const issuedAt = (this.deps.now ?? (() => new Date()))();
    try {
      await this.deps.legacy.db.transaction(async (db) => {
        await this.deps.flow.withDb(db).issueAuthorizationCode({
          transactionId: transaction.id,
          userId: user.id,
          oauthClientId: client.id,
          oauthResourceId: resource.id,
          legacyAuthorizationGrantId: grant.id,
          grantedScopes: transaction.requestedScopes,
          redirectUri: transaction.redirectUri,
          codeChallenge: transaction.codeChallenge,
          codeHash: sha256(rawCode),
          correlationId: transaction.correlationId,
          issuedAt,
          expiresAt: new Date(issuedAt.getTime() + OAUTH_AUTHORIZATION_CODE_TTL_MS)
        });
        const audit = new AuditLogger(this.deps.legacy.withDb(db));
        await audit.write({
          event_type: "oauth.authorization.allowed",
          outcome: "success",
          correlation_id: transaction.correlationId,
          actor_user_id: user.id,
          actor_google_sub: user.google_sub,
          metadata: safeAuditMetadata(client.clientId, resource.resourceId, transaction.requestedScopes)
        });
        await audit.write({
          event_type: "oauth.code.issued",
          outcome: "success",
          correlation_id: transaction.correlationId,
          actor_user_id: user.id,
          actor_google_sub: user.google_sub,
          metadata: safeAuditMetadata(client.clientId, resource.resourceId, transaction.requestedScopes)
        });
      });
    } catch {
      return denyRedirect("temporarily_unavailable", identifiers);
    }
    return {
      kind: "redirect",
      location: authorizationRedirect(
        transaction.redirectUri,
        { code: rawCode, state: downstreamState },
        this.deps.config.authIssuer
      )
    };
  }

  private async denyClaimed(
    transactionId: string,
    ctx: OAuthAuthorizationRequestContext,
    error: OAuthAuthorizationError,
    identifiers: { clientId?: string; resourceId?: string; scopes?: string[]; user?: User } = {}
  ): Promise<void> {
    const completedAt = (this.deps.now ?? (() => new Date()))();
    await this.deps.legacy.db.transaction(async (db) => {
      if (!await this.deps.flow.withDb(db).denyClaimedTransaction(transactionId, completedAt)) {
        throw new Error("OAuth authorization transaction denial failed");
      }
      await new AuditLogger(this.deps.legacy.withDb(db)).write({
        event_type: "oauth.authorization.denied",
        outcome: "denied",
        correlation_id: ctx.correlationId,
        actor_user_id: identifiers.user?.id,
        actor_google_sub: identifiers.user?.google_sub,
        request_ip_hash: ctx.requestIpHash,
        user_agent_hash: ctx.userAgentHash,
        reason_code: error,
        metadata: safeAuditMetadata(identifiers.clientId, identifiers.resourceId, identifiers.scopes)
      });
    });
  }
}
