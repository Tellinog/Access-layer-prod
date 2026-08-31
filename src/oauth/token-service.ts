import { createHash, randomUUID } from "node:crypto";
import { decodeJwt } from "jose";
import { randomToken, sha256, verifyOAuthCredentialSecret } from "../security.js";
import type { Config } from "../types.js";
import { isCanonicalOAuthScope, isExactOAuthHttpsUri, isExactOAuthRedirectUri } from "./validation.js";
import {
  OAUTH_ACCESS_TOKEN_TTL_SECONDS,
  OAUTH_VERIFIER_CLOCK_SKEW_SECONDS,
  OAuthAccessTokenSigner,
  OAuthSigningUnavailableError,
  selectOAuthSigningKey,
  verifyOAuthAccessToken,
  type OAuthAccessTokenClaims
} from "./signing.js";
import {
  OAuthTokenRepository,
  type OAuthAuthorizationCodeContext,
  type OAuthClientAuthenticationRecord,
  type OAuthRefreshContext,
  type OAuthResourceAuthenticationRecord
} from "./token-repository.js";

export const OAUTH_REFRESH_IDLE_SECONDS = 28_800;
export const OAUTH_REFRESH_IDLE_MS = OAUTH_REFRESH_IDLE_SECONDS * 1000;
const PKCE_VERIFIER = /^[A-Za-z0-9._~-]{43,128}$/;

export type OAuthCoreErrorCode =
  | "invalid_client"
  | "invalid_grant"
  | "invalid_scope"
  | "invalid_target"
  | "temporarily_unavailable";

export class OAuthCoreError extends Error {
  constructor(readonly code: OAuthCoreErrorCode) {
    super(code);
    this.name = "OAuthCoreError";
  }
}

export interface OAuthTokenResponseMaterial {
  accessToken: string;
  tokenType: "Bearer";
  expiresIn: 900;
  refreshToken: string;
  scope: string;
}

export type OAuthIntrospectionResult = { active: false } | {
  active: true;
  iss: string;
  sub: string;
  aud: string;
  client_id: string;
  scope: string;
  exp: number;
  iat: number;
  jti: string;
  sid: string;
  token_type: "Bearer";
};

function invalid(code: OAuthCoreErrorCode): never {
  throw new OAuthCoreError(code);
}

function s256(verifier: string): string {
  return createHash("sha256").update(verifier).digest("base64url");
}

function exactScopes(value: string): string[] | null {
  if (!value || value.trim() !== value || /\s{2,}/.test(value)) return null;
  const scopes = value.split(" ");
  if (scopes.length === 0 || new Set(scopes).size !== scopes.length || scopes.some((scope) => !isCanonicalOAuthScope(scope))) {
    return null;
  }
  return scopes;
}

function validScopeSet(scopes: readonly string[]): boolean {
  return scopes.length > 0 && new Set(scopes).size === scopes.length &&
    scopes.every((scope) => isCanonicalOAuthScope(scope));
}

function sameScopeSet(left: readonly string[], right: readonly string[]): boolean {
  return validScopeSet(left) && validScopeSet(right) && left.length === right.length &&
    left.every((scope) => right.includes(scope));
}

function isScopeSubset(subset: readonly string[], superset: readonly string[]): boolean {
  return validScopeSet(subset) && validScopeSet(superset) && subset.every((scope) => superset.includes(scope));
}

function grantCurrentlyMatches(context: OAuthAuthorizationCodeContext | OAuthRefreshContext, now: Date): boolean {
  const userMatches = context.grantUserId === context.userId || context.grantEmailNormalized === context.userEmailNormalized;
  return context.grantStatus === "active" && userMatches &&
    context.grantValidFrom.getTime() <= now.getTime() &&
    (context.grantValidUntil === null || context.grantValidUntil.getTime() > now.getTime());
}

async function exactCurrentEntitlement(
  repository: OAuthTokenRepository,
  context: OAuthAuthorizationCodeContext | OAuthRefreshContext,
  scopes: string[],
  now: Date
): Promise<boolean> {
  if (
    context.clientStatus !== "active" || context.resourceStatus !== "active" ||
    context.audiencePolicy !== "exact_single_resource" || context.userStatus !== "active" ||
    context.authorizationStatus !== "active" || !grantCurrentlyMatches(context, now) ||
    scopes.length === 0 || new Set(scopes).size !== scopes.length ||
    scopes.some((scope) => !isCanonicalOAuthScope(scope))
  ) return false;
  const mappings = await repository.lockCurrentEntitlementMappings(
    context.oauthClientId, context.oauthResourceId, context.grantToolId, scopes
  );
  if (mappings.length !== scopes.length || new Set(mappings.map((mapping) => mapping.scope)).size !== scopes.length) {
    return false;
  }
  const permissions = new Set(context.grantPermissions);
  return mappings.every((mapping) => permissions.has(mapping.legacyPermissionKey));
}

export class OAuthTokenLifecycleService {
  private readonly signer: OAuthAccessTokenSigner;

  constructor(private readonly input: {
    config: Pick<Config,
      "authIssuer" | "oauthCredentialSecretPepper" | "oauthSigningKeyRoot" |
      "jwtPrivateKeyPem" | "jwtPrivateKeyPemPath" | "toolClientSecretPepper">;
    repository: OAuthTokenRepository;
    now?: () => Date;
  }) {
    this.signer = new OAuthAccessTokenSigner({
      issuer: input.config.authIssuer,
      signingKeyRoot: input.config.oauthSigningKeyRoot,
      legacyPrivateKeyPath: input.config.jwtPrivateKeyPemPath,
      legacyPrivateKeyPem: input.config.jwtPrivateKeyPem
    });
  }

  async exchangeAuthorizationCode(input: {
    code: string;
    clientId: string;
    clientSecret?: string | null;
    redirectUri: string;
    resource: string;
    codeVerifier: string;
  }): Promise<OAuthTokenResponseMaterial> {
    const codeHash = sha256(input.code);
    const now = (this.input.now ?? (() => new Date()))();
    const denialCorrelationId = randomUUID();
    try {
      if (
        !input.code || !input.clientId || !isExactOAuthRedirectUri(input.redirectUri) ||
        !isExactOAuthHttpsUri(input.resource) || !PKCE_VERIFIER.test(input.codeVerifier)
      ) invalid("invalid_grant");
      return await this.input.repository.transaction(async (repository) => {
        const client = await this.authenticateClient(repository, input.clientId, input.clientSecret, "authorization_code", now);
        const context = await repository.lockAuthorizationCodeByHash(codeHash);
        if (
          !context || context.consumedAt !== null || context.expiresAt.getTime() <= now.getTime() ||
          context.oauthClientId !== client.id || context.clientId !== input.clientId ||
          context.redirectUri !== input.redirectUri || context.resourceId !== input.resource ||
          context.codeChallengeMethod !== "S256" || s256(input.codeVerifier) !== context.codeChallenge ||
          !context.clientGrantTypes.includes("authorization_code") ||
          !sameScopeSet(context.grantedScopes, context.authorizationGrantedScopes) ||
          !await exactCurrentEntitlement(repository, context, context.grantedScopes, now)
        ) invalid("invalid_grant");

        const signingKey = selectOAuthSigningKey(await repository.listSignableKeysForUpdate(), now);
        const sessionId = randomUUID();
        const familyId = randomUUID();
        const refreshTokenId = randomUUID();
        const rawRefreshToken = randomToken("oauth_rt_", 32);
        const idleExpiresAt = new Date(now.getTime() + OAUTH_REFRESH_IDLE_MS);
        const access = await this.signer.issue({
          key: signingKey, subject: context.googleSub, audience: context.resourceId,
          clientId: context.clientId, scopes: context.grantedScopes, sessionId, now
        });
        await repository.persistInitialIssuance({
          codeId: context.codeId, sessionId, familyId, refreshTokenId,
          refreshTokenHash: sha256(rawRefreshToken), context, signingKeyId: signingKey.id,
          now, idleExpiresAt
        });
        return {
          accessToken: access.token, tokenType: "Bearer", expiresIn: OAUTH_ACCESS_TOKEN_TTL_SECONDS,
          refreshToken: rawRefreshToken, scope: context.grantedScopes.join(" ")
        };
      });
    } catch (error) {
      const original = error instanceof OAuthCoreError
        ? error
        : new OAuthCoreError("temporarily_unavailable");
      try {
        await this.input.repository.recordCodeExchangeDeniedAudit({
          correlationId: denialCorrelationId,
          ...(input.clientId ? { clientId: input.clientId } : {}),
          ...(isExactOAuthHttpsUri(input.resource) ? { resourceId: input.resource } : {}),
          reasonCode: original.code
        });
      } catch {
        invalid("temporarily_unavailable");
      }
      throw original;
    }
  }

  async refresh(input: {
    refreshToken: string;
    clientId: string;
    clientSecret?: string | null;
    resource: string;
    scope?: string | null;
  }): Promise<OAuthTokenResponseMaterial> {
    const tokenHash = sha256(input.refreshToken);
    if (!input.refreshToken || !input.clientId || !isExactOAuthHttpsUri(input.resource)) invalid("invalid_grant");
    const now = (this.input.now ?? (() => new Date()))();
    try {
      const outcome = await this.input.repository.transaction(async (repository): Promise<
        { kind: "success"; response: OAuthTokenResponseMaterial } | { kind: "replay" }
      > => {
        const client = await this.authenticateClient(repository, input.clientId, input.clientSecret, "refresh_token", now);
        const context = await repository.lockRefreshByHash(tokenHash);
        if (!context || context.oauthClientId !== client.id || context.clientId !== client.clientId) invalid("invalid_grant");
        if (context.tokenStatus === "consumed") {
          const replayObservedAt = (this.input.now ?? (() => new Date()))();
          await repository.revokeRefreshReplay(context, replayObservedAt);
          return { kind: "replay" };
        }
        if (
          context.tokenStatus !== "current" || context.tokenExpiresAt.getTime() <= now.getTime() ||
          context.familyStatus !== "active" || context.sessionStatus !== "active" ||
          context.sessionIdleExpiresAt.getTime() <= now.getTime() ||
          context.resourceId !== input.resource || !context.clientGrantTypes.includes("refresh_token") ||
          context.tokenGeneration !== context.familyCurrentGeneration ||
          !sameScopeSet(context.tokenScopes, context.currentScopes) ||
          !isScopeSubset(context.currentScopes, context.scopeCeiling) ||
          !isScopeSubset(context.scopeCeiling, context.authorizationGrantedScopes) ||
          !isScopeSubset(context.currentScopes, context.authorizationGrantedScopes)
        ) invalid("invalid_grant");
        const scopes = input.scope === undefined || input.scope === null
          ? context.currentScopes
          : exactScopes(input.scope);
        if (!scopes) invalid("invalid_scope");
        const currentScopeSet = new Set(context.currentScopes);
        if (scopes.some((scope) => !currentScopeSet.has(scope))) invalid("invalid_scope");
        if (!isScopeSubset(scopes, context.authorizationGrantedScopes)) invalid("invalid_grant");
        if (!await exactCurrentEntitlement(repository, context, scopes, now)) invalid("invalid_grant");

        const signingKey = selectOAuthSigningKey(await repository.listSignableKeysForUpdate(), now);
        const rawRefreshToken = randomToken("oauth_rt_", 32);
        const replacementTokenId = randomUUID();
        const idleExpiresAt = new Date(now.getTime() + OAUTH_REFRESH_IDLE_MS);
        const access = await this.signer.issue({
          key: signingKey, subject: context.googleSub, audience: context.resourceId,
          clientId: context.clientId, scopes, sessionId: context.sessionId, now
        });
        await repository.persistRefreshRotation({
          context, replacementTokenId, replacementHash: sha256(rawRefreshToken), scopes,
          signingKeyId: signingKey.id, now, idleExpiresAt
        });
        return { kind: "success", response: {
          accessToken: access.token, tokenType: "Bearer", expiresIn: OAUTH_ACCESS_TOKEN_TTL_SECONDS,
          refreshToken: rawRefreshToken, scope: scopes.join(" ")
        } };
      });
      if (outcome.kind === "replay") invalid("invalid_grant");
      return outcome.response;
    } catch (error) {
      if (error instanceof OAuthCoreError) throw error;
      if (error instanceof OAuthSigningUnavailableError) invalid("temporarily_unavailable");
      invalid("temporarily_unavailable");
    }
  }

  async revoke(input: {
    token: string;
    tokenTypeHint?: string;
    clientId: string;
    clientSecret?: string | null;
  }): Promise<void> {
    const refreshHash = sha256(input.token);
    const now = (this.input.now ?? (() => new Date()))();
    await this.input.repository.transaction(async (repository) => {
      const client = await this.authenticateClient(repository, input.clientId, input.clientSecret, null, now);
      const revokeAccessToken = async (): Promise<boolean> => {
        let claims: OAuthAccessTokenClaims;
        try {
          const unverified = decodeJwt(input.token);
          if (typeof unverified.aud !== "string") return false;
          claims = await verifyOAuthAccessToken({
            token: input.token, issuer: this.input.config.authIssuer,
            audience: unverified.aud, keys: await repository.listVerificationKeys(), now
          });
        } catch {
          // Unknown, malformed and non-OAuth candidates are deliberately non-disclosable.
          return false;
        }
        if (claims.client_id !== client.clientId) return false;
        const oauthResourceId = await repository.resolveOAuthResourceInternalId(claims.aud);
        if (!oauthResourceId) return false;
        const retentionExpiresAt = new Date(
          (claims.exp + OAUTH_VERIFIER_CLOCK_SKEW_SECONDS) * 1000
        );
        await repository.recordAccessTokenRevocation({
          jti: claims.jti, retentionExpiresAt, oauthClientId: client.id,
          oauthResourceId, clientId: client.clientId, resourceId: claims.aud,
          correlationId: randomUUID(), now
        });
        return true;
      };
      const revokeRefreshToken = async (): Promise<boolean> => {
        const context = await repository.lockRefreshByHash(refreshHash);
        if (context && context.oauthClientId === client.id) {
          await repository.revokeRefreshFamily(context, now, "client_revocation");
          return true;
        }
        return false;
      };
      const lookups = input.tokenTypeHint === "refresh_token"
        ? [revokeRefreshToken, revokeAccessToken]
        : [revokeAccessToken, revokeRefreshToken];
      let handled = false;
      for (const lookup of lookups) {
        if (await lookup()) {
          handled = true;
          break;
        }
      }
      if (!handled) {
        await repository.writeRevocationAudit({
          correlationId: randomUUID(), clientId: client.clientId, tokenClass: "unknown"
        });
      }
    });
  }

  async introspect(input: {
    token: string;
    tokenTypeHint?: string;
    credentialId: string;
    credentialSecret: string;
    correlationId?: string;
  }): Promise<OAuthIntrospectionResult> {
    const now = (this.input.now ?? (() => new Date()))();
    const correlationId = input.correlationId ?? randomUUID();
    return this.input.repository.transaction(async (repository) => {
      const resourceCredential = await this.authenticateResource(
        repository, input.credentialId, input.credentialSecret, now
      );
      let claims: OAuthAccessTokenClaims | null = null;
      let active = false;
      try {
        claims = await verifyOAuthAccessToken({
          token: input.token, issuer: this.input.config.authIssuer,
          audience: resourceCredential.resourceId, keys: await repository.listVerificationKeys(), now
        });
        const scopes = exactScopes(claims.scope);
        active = scopes !== null && await repository.isAccessTokenActiveOnline({
          sessionId: claims.sid, clientId: claims.client_id, resourceId: claims.aud,
          subject: claims.sub, jti: claims.jti, scopes, now
        });
      } catch {
        active = false;
      }
      await repository.writeIntrospectionAudit({
        correlationId, resourceId: resourceCredential.resourceId, active,
        ...(active && claims ? { actorGoogleSub: claims.sub } : {})
      });
      if (!active || !claims) return { active: false };
      return {
        active: true, iss: claims.iss, sub: claims.sub, aud: claims.aud,
        client_id: claims.client_id, scope: claims.scope, exp: claims.exp,
        iat: claims.iat, jti: claims.jti, sid: claims.sid, token_type: "Bearer"
      };
    });
  }

  private async authenticateClient(
    repository: OAuthTokenRepository,
    clientId: string,
    clientSecret: string | null | undefined,
    requiredGrant: "authorization_code" | "refresh_token" | null,
    now: Date
  ): Promise<OAuthClientAuthenticationRecord> {
    this.assertCredentialPepperIsolation();
    const client = await repository.lockClientForAuthentication(clientId);
    if (!client || client.status !== "active" || (requiredGrant && !client.grantTypes.includes(requiredGrant))) {
      invalid("invalid_client");
    }
    if (client.clientType === "public" && client.authenticationMethod === "none") {
      if (clientSecret) invalid("invalid_client");
      return client;
    }
    if (client.clientType !== "confidential" || client.authenticationMethod !== "client_secret_basic" || !clientSecret) {
      invalid("invalid_client");
    }
    const pepper = this.input.config.oauthCredentialSecretPepper;
    if (!pepper) invalid("temporarily_unavailable");
    const hashes = await repository.listCurrentClientCredentialHashes(client.id, now);
    for (const hash of hashes) {
      if (await verifyOAuthCredentialSecret(clientSecret, pepper, hash)) return client;
    }
    invalid("invalid_client");
  }

  private async authenticateResource(
    repository: OAuthTokenRepository,
    credentialId: string,
    credentialSecret: string,
    now: Date
  ): Promise<OAuthResourceAuthenticationRecord> {
    this.assertCredentialPepperIsolation();
    const pepper = this.input.config.oauthCredentialSecretPepper;
    if (!pepper) invalid("temporarily_unavailable");
    const records = await repository.listCurrentResourceCredentialRecords(credentialId, now);
    for (const record of records) {
      if (await verifyOAuthCredentialSecret(credentialSecret, pepper, record.secretHash)) return record;
    }
    invalid("invalid_client");
  }

  private assertCredentialPepperIsolation(): void {
    const oauthPepper = this.input.config.oauthCredentialSecretPepper;
    if (oauthPepper && oauthPepper === this.input.config.toolClientSecretPepper) {
      invalid("temporarily_unavailable");
    }
  }
}
