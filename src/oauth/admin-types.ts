import type { AdminActor } from "../types.js";

export interface OAuthAdminAuditContext {
  actor: AdminActor;
  correlationId: string;
  requestIpHash: string | null;
  userAgentHash: string | null;
}

export interface OAuthAdminScopeInput {
  scope: string;
  description: string;
}

export interface OAuthAdminResourceInput {
  resourceId: string;
  displayName: string;
  ownerTeam: string;
  ownerContact: string | null;
  status: "draft" | "active" | "disabled";
  protectedResourceMetadataUrl: string;
  legacyToolSlug: string;
  scopeMappings: Array<{ scope: string; legacyPermissionKey: string }>;
}

export interface OAuthAdminClientInput {
  clientId: string;
  clientName: string;
  ownerTeam: string;
  ownerContact: string | null;
  status: "draft" | "active" | "disabled";
  grantTypes: Array<"authorization_code" | "refresh_token">;
  redirectUris: string[];
  allowances: Array<{ resourceId: string; scope: string }>;
}

export interface OAuthAdminSnapshot {
  clients: Array<Record<string, unknown>>;
  clientCredentials: Array<Record<string, unknown>>;
  redirectUris: Array<Record<string, unknown>>;
  resources: Array<Record<string, unknown>>;
  resourceCredentials: Array<Record<string, unknown>>;
  scopes: Array<Record<string, unknown>>;
  resourceScopes: Array<Record<string, unknown>>;
  allowances: Array<Record<string, unknown>>;
  entitlementBindings: Array<Record<string, unknown>>;
  signingKeys: Array<Record<string, unknown>>;
}

export interface OAuthGeneratedCredential {
  credentialId?: string;
  secret: string;
}

export type OAuthSigningKeyAction = "publish" | "activate" | "retire" | "disable";
