import type { InvocationChannel, RequestContext } from "./request-context.js";

/** Output of the frozen legacy Access Layer validator/session middleware. */
export interface VerifiedLegacyIdentity {
  issuer: string;
  audience: string;
  projectSlug: string;
  userId: string;
  sessionId: string;
  grantId?: string;
  permissions: readonly string[];
  correlationId: string;
  traceId?: string;
}

/** Output of the approved OAuth resource-server validator. */
export interface VerifiedOAuthIdentity {
  issuer: string;
  subject: string;
  audience: string;
  clientId: string;
  scope: readonly string[];
  tokenId: string;
  sessionId?: string;
  authorizationGrantId?: string;
  delegatedActor?: string;
  delegatedSubject?: string;
  principalType: "human" | "service";
  correlationId: string;
  traceId?: string;
}

export interface ContextOptions {
  invocationChannel: InvocationChannel;
  resourceId: string;
  environment: string;
  capabilityId?: string;
  requestStartedAt?: string;
}

export interface LegacyContextOptions extends ContextOptions {
  /** Frozen legacy token audience/tool slug expected by this project. */
  expectedLegacyAudience: string;
}

export function fromLegacyIdentity(
  identity: VerifiedLegacyIdentity,
  options: LegacyContextOptions,
): RequestContext {
  if (identity.audience !== options.expectedLegacyAudience) {
    throw new Error("AUTH_TOKEN_AUDIENCE_INVALID");
  }

  return {
    authProfile: "access-layer-legacy-v1",
    principalType: "human",
    principalId: identity.userId,
    delegatedSubject: null,
    actorId: null,
    clientId: null,
    projectSlug: identity.projectSlug,
    resourceId: options.resourceId,
    capabilityId: options.capabilityId ?? null,
    // Access Layer already uses the canonical colon-separated keys. Preserve
    // them exactly so legacy authorization outcomes cannot change silently.
    permissions: [...new Set(identity.permissions)],
    scopes: [],
    invocationChannel: options.invocationChannel,
    accessSessionId: identity.sessionId,
    authorizationGrantId: identity.grantId ?? null,
    tokenId: null,
    correlationId: identity.correlationId,
    traceId: identity.traceId ?? null,
    environment: options.environment,
    requestStartedAt: options.requestStartedAt ?? new Date().toISOString(),
  };
}

export function fromOAuthIdentity(
  projectSlug: string,
  identity: VerifiedOAuthIdentity,
  options: ContextOptions,
): RequestContext {
  if (identity.audience !== options.resourceId) {
    throw new Error("AUTH_TOKEN_AUDIENCE_INVALID");
  }

  return {
    authProfile: "unguess-oauth-oidc-v1",
    principalType: identity.principalType,
    principalId: identity.subject,
    delegatedSubject: identity.delegatedSubject ?? null,
    actorId: identity.delegatedActor ?? null,
    clientId: identity.clientId,
    projectSlug,
    resourceId: identity.audience,
    capabilityId: options.capabilityId ?? null,
    permissions: [],
    scopes: [...new Set(identity.scope)],
    invocationChannel: options.invocationChannel,
    accessSessionId: identity.sessionId ?? null,
    authorizationGrantId: identity.authorizationGrantId ?? null,
    tokenId: identity.tokenId,
    correlationId: identity.correlationId,
    traceId: identity.traceId ?? null,
    environment: options.environment,
    requestStartedAt: options.requestStartedAt ?? new Date().toISOString(),
  };
}

// Inputs must come from approved UNGUESS Platform SDK authentication
// validators. This reference intentionally performs no JWT, JWKS, introspection, refresh, PKCE, cookie or
// session cryptography itself.
