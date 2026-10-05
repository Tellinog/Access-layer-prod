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

export interface OAuthAdminBulkScopesInput {
  mode: "create_missing";
  updateDescriptions: boolean;
  reactivateDisabled: boolean;
  rows: Array<OAuthAdminScopeInput & { row: number }>;
}

export interface OAuthAdminBulkGrantInput {
  resourceId: string;
  userIds: string[];
  emails: string[];
  scopes: string[];
  validFrom: Date | null;
  validUntil: Date | null;
}

export interface OAuthAdminResourceCommon {
  resourceId: string;
  displayName: string;
  ownerTeam: string;
  ownerContact: string | null;
  status: "draft" | "active" | "disabled";
  protectedResourceMetadataUrl: string;
}

export type OAuthAdminResourceInput = OAuthAdminResourceCommon & (
  { entitlementMode: "native"; scopes: string[]; legacyToolSlug?: never; scopeMappings?: never } |
  { entitlementMode?: "legacy_bridge"; legacyToolSlug: string; scopeMappings: Array<{ scope: string; legacyPermissionKey: string }>; scopes?: never }
);

export interface OAuthAdminNativeGrantInput {
  resourceId: string;
  userId: string;
  scopes: string[];
  validFrom: Date | null;
  validUntil: Date | null;
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

export type OAuthAdminAllowanceState = OAuthAdminClientInput["allowances"][number] & { status: "active" | "disabled" };

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
