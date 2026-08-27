export type OAuthRegistrationStatus = "draft" | "active" | "disabled";
export type OAuthClientType = "confidential" | "public";
export type OAuthTokenEndpointAuthMethod = "client_secret_basic" | "none";
export type OAuthGrantType = "authorization_code" | "refresh_token";

export interface OAuthClientCredentialLifecycle {
  secretPresent: boolean;
  rotatedAt: string | null;
  expiresAt: string | null;
}

export interface OAuthClientRegistration {
  clientId: string;
  clientName: string;
  clientType: OAuthClientType;
  status: OAuthRegistrationStatus;
  grantTypes: OAuthGrantType[];
  redirectUris: string[];
  tokenEndpointAuthMethod: OAuthTokenEndpointAuthMethod;
  credentialLifecycle: OAuthClientCredentialLifecycle;
  allowedResources: string[];
  allowedScopes: string[];
  ownerTeam: string;
  ownerContact?: string | null;
}

export interface OAuthScopeEntitlementMapping {
  scope: string;
  legacyPermissionKey: string;
}

export interface OAuthResourceRegistration {
  resourceId: string;
  displayName: string;
  status: OAuthRegistrationStatus;
  ownerTeam: string;
  ownerContact?: string | null;
  scopes: string[];
  scopeEntitlementMappings: OAuthScopeEntitlementMapping[];
  audiencePolicy: "exact_single_resource";
  protectedResourceMetadataUrl: string;
  entitlementBinding: {
    type: "legacy_tool";
    legacyToolSlug: string;
  };
}

export interface LegacyEntitlementSnapshot {
  legacyToolId: string;
  legacyToolSlug: string;
  registeredPermissionKeys: string[];
}

export interface OAuthClientResourceScopeAllowance {
  resourceId: string;
  scope: string;
}

export interface OAuthRegistrationBundle {
  client: OAuthClientRegistration;
  resources: Array<{
    registration: OAuthResourceRegistration;
    legacyEntitlement: LegacyEntitlementSnapshot;
  }>;
  allowances: OAuthClientResourceScopeAllowance[];
}

export interface OAuthClientRecord {
  id: string;
  clientId: string;
  clientName: string;
  clientType: OAuthClientType;
  tokenEndpointAuthMethod: OAuthTokenEndpointAuthMethod;
  grantTypes: OAuthGrantType[];
  status: OAuthRegistrationStatus;
  ownerTeam: string;
  ownerContact: string | null;
}

export interface OAuthResourceRecord {
  id: string;
  resourceId: string;
  displayName: string;
  status: OAuthRegistrationStatus;
  ownerTeam: string;
  ownerContact: string | null;
  audiencePolicy: "exact_single_resource";
  protectedResourceMetadataUrl: string;
}

export interface OAuthResourceScopeMappingRecord {
  resourceId: string;
  scope: string;
  legacyPermissionKey: string;
}

export interface OAuthResourceCredentialMetadata {
  id: string;
  oauthResourceId: string;
  credentialId: string;
  authenticationMethod: "client_secret_basic";
  status: "active" | "disabled" | "retired";
  createdAt: Date;
  activatedAt: Date | null;
  rotatedAt: Date | null;
  expiresAt: Date | null;
  retiredAt: Date | null;
  rotationParentId: string | null;
}

export interface OAuthSigningKeyPublicMetadata {
  id: string;
  kid: string;
  algorithm: "RS256";
  publicJwk: Record<string, unknown>;
  publicKeyFingerprintSha256: string;
  status: "staged" | "published" | "active" | "retired" | "disabled";
  publishedAt: Date | null;
  activatesAt: Date | null;
  lastSignedAt: Date | null;
  retireAfter: Date | null;
  retiredAt: Date | null;
}

export type OAuthAuthorizationTransactionStatus = "pending" | "claimed" | "completed" | "denied" | "expired";

export interface OAuthAuthorizationTransactionRecord {
  id: string;
  oauthClientId: string;
  oauthResourceId: string;
  redirectUri: string;
  requestedScopes: string[];
  codeChallenge: string;
  codeChallengeMethod: "S256";
  protectedDownstreamState: Record<string, unknown> | null;
  upstreamStateHash: string;
  upstreamNonceHash: string;
  correlationId: string;
  status: OAuthAuthorizationTransactionStatus;
  expiresAt: Date;
  claimedAt: Date | null;
  completedAt: Date | null;
  createdAt: Date;
}

export interface OAuthAuthorizationCodeIssuance {
  transactionId: string;
  userId: string;
  oauthClientId: string;
  oauthResourceId: string;
  legacyAuthorizationGrantId: string;
  grantedScopes: string[];
  redirectUri: string;
  codeChallenge: string;
  codeHash: string;
  correlationId: string;
  issuedAt: Date;
  expiresAt: Date;
}
