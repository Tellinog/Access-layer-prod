export type Outcome = "success" | "denied" | "error" | "info";

export type ToolStatus = "active" | "disabled" | "maintenance";
export type UserStatus = "active" | "suspended" | "disabled";
export type GrantStatus = "active" | "revoked" | "expired" | "pending_user_link";
export type SessionStatus = "active" | "revoked" | "expired";
export type AccessRequestStatus = "pending" | "approved" | "rejected" | "closed" | "expired";

export interface Config {
  appEnv: "development" | "staging" | "production" | "test";
  appBaseUrl: string;
  authIssuer: string;
  publicBasePath: string;
  port: number;
  logLevel: string;
  databaseUrl: string;
  googleClientId: string;
  googleClientSecret: string;
  googleRedirectUri: string;
  googleAllowedHd: string[];
  googleOidcScope: string;
  jwtPrivateKeyPem?: string;
  jwtPrivateKeyPemPath?: string;
  jwtPublicKeyId: string;
  accessTokenTtlSeconds: number;
  refreshTokenTtlSeconds: number;
  oneTimeCodeTtlSeconds: number;
  oauthP0Enabled: boolean;
  oauthTransactionProtectionKey?: Buffer;
  oauthCredentialSecretPepper?: string;
  oauthSigningKeyRoot?: string;
  sessionCookieName: string;
  sessionSecret: string;
  toolClientSecretPepper: string;
  backupEncryptionKey?: string;
  corsAllowedOrigins: string[];
  returnUrlAllowedSchemes: string[];
  adminBootstrapEmails: string[];
  logIpSalt: string;
  auditLogRetentionDays: number;
  auditLogRawIp: boolean;
  accessRequestReopenAfterDays: number;
  enableRefreshTokens: boolean;
  siemExportEnabled: boolean;
  siemExportEndpoint?: string;
  siemExportToken?: string;
  backupApiToken?: string;
  trustProxyHops: number;
}

export interface Tool {
  id: string;
  slug: string;
  display_name: string;
  description: string | null;
  status: ToolStatus;
  allowed_return_urls: string[];
  owner_email: string | null;
  created_at: Date;
  updated_at: Date;
}

export interface ToolClient {
  id: string;
  tool_id: string;
  client_id: string;
  client_secret_hash: string;
  status: "active" | "disabled" | "rotating";
}

export interface User {
  id: string;
  google_sub: string;
  email: string;
  email_normalized: string;
  email_verified: boolean;
  hd: string;
  display_name: string | null;
  picture_url: string | null;
  status: UserStatus;
  first_seen_at: Date;
  last_seen_at: Date;
}

export interface AuthorizationGrant {
  id: string;
  tool_id: string;
  user_id: string | null;
  email_normalized: string | null;
  role: string;
  permissions: string[];
  status: GrantStatus;
  valid_from: Date;
  valid_until: Date | null;
  created_by_user_id: string | null;
}

export interface AuthRequest {
  id: string;
  state_hash: string;
  nonce_hash: string;
  tool_id: string;
  tool_slug: string;
  return_url: string;
  tool_state: string;
  tool_state_hash: string;
  login_hint: string | null;
  correlation_id: string;
  request_ip_hash: string | null;
  user_agent_hash: string | null;
  expires_at: Date;
  consumed_at: Date | null;
}

export interface Session {
  id: string;
  user_id: string;
  tool_id: string;
  grant_id: string;
  status: SessionStatus;
  issued_at: Date;
  expires_at: Date;
  revoked_at: Date | null;
}

export interface RefreshToken {
  id: string;
  token_hash: string;
  session_id: string;
  status: SessionStatus;
  issued_at: Date;
  expires_at: Date;
  revoked_at: Date | null;
}

export interface OneTimeCode {
  id: string;
  code_hash: string;
  user_id: string;
  tool_id: string;
  grant_id: string;
  session_id: string;
  return_url: string;
  correlation_id: string;
  expires_at: Date;
  consumed_at: Date | null;
}

export interface AccessRequest {
  id: string;
  tool_id: string;
  tool_slug: string;
  user_id: string | null;
  google_sub: string | null;
  email: string;
  email_normalized: string;
  hd: string;
  display_name: string | null;
  status: AccessRequestStatus;
  reason_code: string;
  attempts_count: number;
  first_seen_at: Date;
  last_seen_at: Date;
  last_correlation_id: string;
  request_ip_hash: string | null;
  user_agent_hash: string | null;
  reviewed_by_user_id: string | null;
  reviewed_at: Date | null;
  review_note: string | null;
  grant_id: string | null;
}

export interface AuditEventInput {
  event_type: string;
  outcome: Outcome;
  correlation_id: string;
  tool_id?: string | null;
  tool_slug?: string | null;
  actor_user_id?: string | null;
  actor_google_sub?: string | null;
  actor_email?: string | null;
  actor_hd?: string | null;
  request_ip_hash?: string | null;
  user_agent_hash?: string | null;
  reason_code?: string | null;
  metadata?: Record<string, unknown>;
}

export interface GoogleIdentity {
  googleSub: string;
  email: string;
  emailVerified: boolean;
  hd: string;
  displayName?: string | null;
  pictureUrl?: string | null;
  nonce?: string | null;
  issuer: string;
  audience: string;
  expiresAt: number;
}

export interface AdminActor {
  userId: string;
  googleSub: string;
  email: string;
  hd: string;
  role: string;
  permissions: string[];
  assignedToolIds: string[];
}
