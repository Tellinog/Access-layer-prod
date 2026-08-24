export type AuthProfile =
  | "access-layer-legacy-v1"
  | "unguess-oauth-oidc-v1"
  | "system-internal";
export type PrincipalType = "human" | "service";
export type InvocationChannel = "web" | "api" | "mcp" | "worker";

/**
 * Internal camelCase representation of schemas/request-context.schema.json.
 * A transport adapter creates this only after the selected authentication
 * profile has been fully verified. Domain code never parses credentials.
 */
export interface RequestContext {
  authProfile: AuthProfile;
  principalType: PrincipalType;
  /** Stable subject identifier. Email is never the primary identity. */
  principalId: string;
  /** Optional human subject represented by a service principal. */
  delegatedSubject: string | null;
  /** Intermediary actor, for example Agent Gateway in delegated OAuth. */
  actorId: string | null;
  clientId: string | null;
  projectSlug: string;
  /** Canonical HTTPS resource/audience of the receiving project API. */
  resourceId: string;
  capabilityId: string | null;
  /** Verified Access Layer permissions for legacy/system profiles. */
  permissions: readonly string[];
  /** Verified OAuth scopes for the OAuth profile. */
  scopes: readonly string[];
  invocationChannel: InvocationChannel;
  accessSessionId: string | null;
  authorizationGrantId: string | null;
  tokenId: string | null;
  correlationId: string;
  traceId: string | null;
  environment: string;
  requestStartedAt: string;
}

const CAPABILITY_PATTERN = /^[a-z][a-z0-9-]+(?::[a-z][a-z0-9-]+){1,}$/;

export function assertCapabilityId(value: string): void {
  if (!CAPABILITY_PATTERN.test(value)) throw new Error("CAPABILITY_ID_INVALID");
}

export function hasCapability(context: RequestContext, capabilityId: string): boolean {
  assertCapabilityId(capabilityId);
  if (!capabilityId.startsWith(`${context.projectSlug}:`)) return false;
  if (context.capabilityId !== null && context.capabilityId !== capabilityId) return false;

  if (context.authProfile === "unguess-oauth-oidc-v1") {
    return context.scopes.includes(capabilityId);
  }
  return context.permissions.includes(capabilityId);
}

export function requireCapability(context: RequestContext, capabilityId: string): void {
  if (!hasCapability(context, capabilityId)) throw new Error("AUTH_CAPABILITY_DENIED");
}
