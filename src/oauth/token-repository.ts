import { randomUUID } from "node:crypto";
import type { Db } from "../db.js";
import type { OAuthSigningKeyPublicMetadata } from "./types.js";
import type { OAuthSigningKeyRecord } from "./signing.js";

function stringArray(value: unknown): string[] {
  if (Array.isArray(value)) return value.map(String);
  if (typeof value === "string") {
    try {
      const parsed = JSON.parse(value) as unknown;
      return Array.isArray(parsed) ? parsed.map(String) : [];
    } catch {
      return [];
    }
  }
  return [];
}

export interface OAuthClientAuthenticationRecord {
  id: string;
  clientId: string;
  clientType: "confidential" | "public";
  authenticationMethod: "client_secret_basic" | "none";
  grantTypes: Array<"authorization_code" | "refresh_token">;
  status: "draft" | "active" | "disabled";
}

export interface OAuthResourceAuthenticationRecord {
  credentialId: string;
  oauthResourceId: string;
  resourceId: string;
  secretHash: string;
}

export interface OAuthAuthorizationCodeContext {
  codeId: string;
  oauthAuthorizationId: string;
  oauthClientId: string;
  clientId: string;
  clientStatus: string;
  clientGrantTypes: string[];
  oauthResourceId: string;
  resourceId: string;
  resourceStatus: string;
  audiencePolicy: string;
  userId: string;
  googleSub: string;
  userStatus: string;
  redirectUri: string;
  grantedScopes: string[];
  authorizationGrantedScopes: string[];
  codeChallenge: string;
  codeChallengeMethod: string;
  correlationId: string;
  issuedAt: Date;
  expiresAt: Date;
  consumedAt: Date | null;
  authorizationStatus: string;
  legacyAuthorizationGrantId: string;
  grantToolId: string;
  grantUserId: string | null;
  grantEmailNormalized: string | null;
  userEmailNormalized: string;
  grantStatus: string;
  grantValidFrom: Date;
  grantValidUntil: Date | null;
  grantPermissions: string[];
}

export interface OAuthRefreshContext {
  refreshTokenId: string;
  tokenStatus: string;
  tokenGeneration: number;
  tokenScopes: string[];
  tokenExpiresAt: Date;
  familyId: string;
  familyStatus: string;
  familyCurrentGeneration: number;
  scopeCeiling: string[];
  currentScopes: string[];
  sessionId: string;
  sessionStatus: string;
  sessionIdleExpiresAt: Date;
  oauthAuthorizationId: string;
  authorizationStatus: string;
  authorizationGrantedScopes: string[];
  oauthClientId: string;
  clientId: string;
  clientStatus: string;
  clientGrantTypes: string[];
  oauthResourceId: string;
  resourceId: string;
  resourceStatus: string;
  audiencePolicy: string;
  userId: string;
  googleSub: string;
  userStatus: string;
  userEmailNormalized: string;
  legacyAuthorizationGrantId: string;
  grantToolId: string;
  grantUserId: string | null;
  grantEmailNormalized: string | null;
  grantStatus: string;
  grantValidFrom: Date;
  grantValidUntil: Date | null;
  grantPermissions: string[];
  correlationId: string;
}

export interface OAuthEntitlementMapping {
  scope: string;
  legacyPermissionKey: string;
}

export class OAuthTokenRepository {
  constructor(private readonly db: Db) {}

  async transaction<T>(fn: (repository: OAuthTokenRepository) => Promise<T>): Promise<T> {
    return this.db.transaction((db) => fn(new OAuthTokenRepository(db)));
  }

  async lockClientForAuthentication(clientId: string): Promise<OAuthClientAuthenticationRecord | null> {
    const result = await this.db.query<{
      id: string;
      client_id: string;
      client_type: OAuthClientAuthenticationRecord["clientType"];
      token_endpoint_auth_method: OAuthClientAuthenticationRecord["authenticationMethod"];
      grant_types: OAuthClientAuthenticationRecord["grantTypes"];
      status: OAuthClientAuthenticationRecord["status"];
    }>(`SELECT id, client_id, client_type, token_endpoint_auth_method, grant_types, status
        FROM oauth_clients
        WHERE client_id = $1
        FOR SHARE`, [clientId]);
    const row = result.rows[0];
    return row ? {
      id: row.id,
      clientId: row.client_id,
      clientType: row.client_type,
      authenticationMethod: row.token_endpoint_auth_method,
      grantTypes: row.grant_types,
      status: row.status
    } : null;
  }

  async listCurrentClientCredentialHashes(oauthClientId: string, now: Date): Promise<string[]> {
    const result = await this.db.query<{ secret_hash: string }>(
      `SELECT secret_hash
       FROM oauth_client_credentials
       WHERE oauth_client_id = $1
         AND status = 'active'
         AND (activated_at IS NULL OR activated_at <= $2)
         AND (expires_at IS NULL OR expires_at > $2)
         AND retired_at IS NULL
       ORDER BY created_at DESC, id
       FOR SHARE`,
      [oauthClientId, now]
    );
    return result.rows.map((row) => row.secret_hash);
  }

  async listCurrentResourceCredentialRecords(
    credentialId: string,
    now: Date
  ): Promise<OAuthResourceAuthenticationRecord[]> {
    const result = await this.db.query<{
      credential_id: string;
      oauth_resource_id: string;
      resource_id: string;
      secret_hash: string;
    }>(`SELECT credential.credential_id, credential.oauth_resource_id,
               resource.resource_id, credential.secret_hash
        FROM oauth_resource_credentials credential
        JOIN oauth_resources resource ON resource.id = credential.oauth_resource_id
        WHERE credential.credential_id = $1
          AND credential.authentication_method = 'client_secret_basic'
          AND credential.status = 'active'
          AND (credential.activated_at IS NULL OR credential.activated_at <= $2)
          AND (credential.expires_at IS NULL OR credential.expires_at > $2)
          AND credential.retired_at IS NULL
          AND resource.status = 'active'
        ORDER BY credential.created_at DESC, credential.id
        FOR SHARE OF credential, resource`, [credentialId, now]);
    return result.rows.map((row) => ({
      credentialId: row.credential_id,
      oauthResourceId: row.oauth_resource_id,
      resourceId: row.resource_id,
      secretHash: row.secret_hash
    }));
  }

  async resolveOAuthResourceInternalId(resourceId: string): Promise<string | null> {
    const result = await this.db.query<{ id: string }>(
      `SELECT id FROM oauth_resources
       WHERE resource_id = $1 AND audience_policy = 'exact_single_resource'
       FOR SHARE`,
      [resourceId]
    );
    return result.rows[0]?.id ?? null;
  }

  async lockAuthorizationCodeByHash(codeHash: string): Promise<OAuthAuthorizationCodeContext | null> {
    const result = await this.db.query<Record<string, unknown>>(
      `SELECT code.id AS code_id, code.oauth_authorization_id, code.oauth_client_id,
              client.client_id, client.status AS client_status, client.grant_types AS client_grant_types,
              code.oauth_resource_id, resource.resource_id, resource.status AS resource_status,
              resource.audience_policy, code.user_id, human.google_sub,
              human.email_normalized AS user_email_normalized, human.status AS user_status,
              code.redirect_uri, code.granted_scopes, code.code_challenge, code.code_challenge_method,
              code.correlation_id, code.issued_at, code.expires_at, code.consumed_at,
              authorization.status AS authorization_status,
              authorization.granted_scopes AS authorization_granted_scopes,
              authorization.legacy_authorization_grant_id,
              legacy_grant.tool_id AS grant_tool_id, legacy_grant.user_id AS grant_user_id,
              legacy_grant.email_normalized AS grant_email_normalized,
              legacy_grant.status AS grant_status, legacy_grant.valid_from AS grant_valid_from,
              legacy_grant.valid_until AS grant_valid_until, legacy_grant.permissions AS grant_permissions
       FROM oauth_authorization_codes code
       JOIN oauth_authorizations authorization
         ON authorization.id = code.oauth_authorization_id
        AND authorization.oauth_client_id = code.oauth_client_id
        AND authorization.oauth_resource_id = code.oauth_resource_id
        AND authorization.user_id = code.user_id
       JOIN oauth_clients client ON client.id = code.oauth_client_id
       JOIN oauth_resources resource ON resource.id = code.oauth_resource_id
       JOIN users human ON human.id = code.user_id
       JOIN authorization_grants legacy_grant ON legacy_grant.id = authorization.legacy_authorization_grant_id
       WHERE code.code_hash = $1
       FOR UPDATE OF code
       FOR SHARE OF authorization, client, resource, human, legacy_grant`,
      [codeHash]
    );
    const row = result.rows[0];
    return row ? {
      codeId: String(row.code_id),
      oauthAuthorizationId: String(row.oauth_authorization_id),
      oauthClientId: String(row.oauth_client_id),
      clientId: String(row.client_id),
      clientStatus: String(row.client_status),
      clientGrantTypes: stringArray(row.client_grant_types),
      oauthResourceId: String(row.oauth_resource_id),
      resourceId: String(row.resource_id),
      resourceStatus: String(row.resource_status),
      audiencePolicy: String(row.audience_policy),
      userId: String(row.user_id),
      googleSub: String(row.google_sub),
      userStatus: String(row.user_status),
      redirectUri: String(row.redirect_uri),
      grantedScopes: stringArray(row.granted_scopes),
      authorizationGrantedScopes: stringArray(row.authorization_granted_scopes),
      codeChallenge: String(row.code_challenge),
      codeChallengeMethod: String(row.code_challenge_method),
      correlationId: String(row.correlation_id),
      issuedAt: row.issued_at as Date,
      expiresAt: row.expires_at as Date,
      consumedAt: (row.consumed_at as Date | null) ?? null,
      authorizationStatus: String(row.authorization_status),
      legacyAuthorizationGrantId: String(row.legacy_authorization_grant_id),
      grantToolId: String(row.grant_tool_id),
      grantUserId: row.grant_user_id === null ? null : String(row.grant_user_id),
      grantEmailNormalized: row.grant_email_normalized === null ? null : String(row.grant_email_normalized),
      userEmailNormalized: String(row.user_email_normalized),
      grantStatus: String(row.grant_status),
      grantValidFrom: row.grant_valid_from as Date,
      grantValidUntil: (row.grant_valid_until as Date | null) ?? null,
      grantPermissions: stringArray(row.grant_permissions)
    } : null;
  }

  async lockCurrentEntitlementMappings(
    oauthClientId: string,
    oauthResourceId: string,
    grantToolId: string,
    scopes: string[]
  ): Promise<OAuthEntitlementMapping[]> {
    const result = await this.db.query<{ scope: string; legacy_permission_key: string }>(
      `SELECT scope.scope, resource_scope.legacy_permission_key
       FROM oauth_resource_scopes resource_scope
       JOIN oauth_scopes scope ON scope.id = resource_scope.oauth_scope_id
       JOIN oauth_client_resource_scopes allowance
         ON allowance.oauth_resource_id = resource_scope.oauth_resource_id
        AND allowance.oauth_scope_id = resource_scope.oauth_scope_id
       JOIN oauth_resource_entitlement_bindings binding
         ON binding.oauth_resource_id = resource_scope.oauth_resource_id
       JOIN tools legacy_tool ON legacy_tool.id = binding.legacy_tool_id
       JOIN tool_permissions permission
         ON permission.tool_id = legacy_tool.id
        AND permission.permission_key = resource_scope.legacy_permission_key
       WHERE resource_scope.oauth_resource_id = $1
         AND allowance.oauth_client_id = $2
         AND binding.legacy_tool_id = $3
         AND scope.scope = ANY($4::text[])
         AND resource_scope.status = 'active'
         AND scope.status = 'active'
         AND allowance.status = 'active'
         AND binding.status = 'active'
         AND binding.binding_type = 'legacy_tool'
       ORDER BY scope.scope
       FOR SHARE OF resource_scope, scope, allowance, binding, legacy_tool, permission`,
      [oauthResourceId, oauthClientId, grantToolId, scopes]
    );
    return result.rows.map((row) => ({ scope: row.scope, legacyPermissionKey: row.legacy_permission_key }));
  }

  async listSignableKeysForUpdate(): Promise<OAuthSigningKeyRecord[]> {
    const result = await this.db.query<Record<string, unknown>>(
      `SELECT id, kid, algorithm, public_jwk, public_key_fingerprint_sha256,
              protected_private_key_ref, status, published_at, activates_at,
              last_signed_at, retire_after, retired_at
       FROM oauth_signing_keys
       WHERE key_namespace = 'oauth_p0' AND status = 'active' AND retire_after IS NULL
       ORDER BY kid
       FOR UPDATE`
    );
    return result.rows.map((row) => ({
      id: String(row.id),
      kid: String(row.kid),
      algorithm: "RS256",
      publicJwk: row.public_jwk as Record<string, unknown>,
      publicKeyFingerprintSha256: String(row.public_key_fingerprint_sha256),
      protectedPrivateKeyRef: String(row.protected_private_key_ref),
      status: row.status as OAuthSigningKeyRecord["status"],
      publishedAt: (row.published_at as Date | null) ?? null,
      activatesAt: (row.activates_at as Date | null) ?? null,
      lastSignedAt: (row.last_signed_at as Date | null) ?? null,
      retireAfter: (row.retire_after as Date | null) ?? null,
      retiredAt: (row.retired_at as Date | null) ?? null
    }));
  }

  async listVerificationKeys(): Promise<OAuthSigningKeyPublicMetadata[]> {
    const result = await this.db.query<Record<string, unknown>>(
      `SELECT id, kid, algorithm, public_jwk, public_key_fingerprint_sha256,
              status, published_at, activates_at, last_signed_at, retire_after, retired_at
       FROM oauth_signing_keys
       WHERE key_namespace = 'oauth_p0' AND status = 'active'
       ORDER BY kid`
    );
    return result.rows.map((row) => ({
      id: String(row.id),
      kid: String(row.kid),
      algorithm: "RS256",
      publicJwk: row.public_jwk as Record<string, unknown>,
      publicKeyFingerprintSha256: String(row.public_key_fingerprint_sha256),
      status: row.status as OAuthSigningKeyPublicMetadata["status"],
      publishedAt: (row.published_at as Date | null) ?? null,
      activatesAt: (row.activates_at as Date | null) ?? null,
      lastSignedAt: (row.last_signed_at as Date | null) ?? null,
      retireAfter: (row.retire_after as Date | null) ?? null,
      retiredAt: (row.retired_at as Date | null) ?? null
    }));
  }

  async persistInitialIssuance(input: {
    codeId: string;
    sessionId: string;
    familyId: string;
    refreshTokenId: string;
    refreshTokenHash: string;
    context: OAuthAuthorizationCodeContext;
    signingKeyId: string;
    now: Date;
    idleExpiresAt: Date;
  }): Promise<void> {
    const consumed = await this.db.query(
      `UPDATE oauth_authorization_codes
       SET consumed_at = $2
       WHERE id = $1 AND consumed_at IS NULL AND expires_at > $2`,
      [input.codeId, input.now]
    );
    if (consumed.rowCount !== 1) throw new Error("oauth_code_consumption_race");
    await this.db.query(
      `INSERT INTO oauth_sessions (
         id, oauth_authorization_id, user_id, oauth_client_id, oauth_resource_id,
         status, correlation_id, issued_at, last_activity_at, idle_expires_at
       ) VALUES ($1,$2,$3,$4,$5,'active',$6,$7,$7,$8)`,
      [input.sessionId, input.context.oauthAuthorizationId, input.context.userId,
        input.context.oauthClientId, input.context.oauthResourceId, input.context.correlationId,
        input.now, input.idleExpiresAt]
    );
    await this.db.query(
      `INSERT INTO oauth_refresh_token_families (
         id, oauth_authorization_id, oauth_session_id, user_id, oauth_client_id,
         oauth_resource_id, scope_ceiling, current_scopes, current_generation,
         status, created_at
       ) VALUES ($1,$2,$3,$4,$5,$6,$7,$7,0,'active',$8)`,
      [input.familyId, input.context.oauthAuthorizationId, input.sessionId, input.context.userId,
        input.context.oauthClientId, input.context.oauthResourceId, input.context.grantedScopes, input.now]
    );
    await this.db.query(
      `INSERT INTO oauth_refresh_tokens (
         id, oauth_refresh_token_family_id, token_hash, generation,
         parent_refresh_token_id, scopes, status, issued_at, expires_at
       ) VALUES ($1,$2,$3,0,NULL,$4,'current',$5,$6)`,
      [input.refreshTokenId, input.familyId, input.refreshTokenHash,
        input.context.grantedScopes, input.now, input.idleExpiresAt]
    );
    await this.markSigningKeyUsed(input.signingKeyId, input.now);
    await this.writeOAuthAudit({
      eventType: "oauth.code.exchanged",
      outcome: "success",
      correlationId: input.context.correlationId,
      actorUserId: input.context.userId,
      actorGoogleSub: input.context.googleSub,
      metadata: {
        client_id: input.context.clientId,
        resource_id: input.context.resourceId,
        scopes: input.context.grantedScopes,
        oauth_session_id: input.sessionId
      }
    });
  }

  async lockRefreshByHash(tokenHash: string): Promise<OAuthRefreshContext | null> {
    const result = await this.db.query<Record<string, unknown>>(
      `SELECT token.id AS refresh_token_id, token.status AS token_status,
              token.generation AS token_generation, token.scopes AS token_scopes,
              token.expires_at AS token_expires_at,
              family.id AS family_id, family.status AS family_status,
              family.current_generation AS family_current_generation,
              family.scope_ceiling, family.current_scopes,
              session.id AS session_id, session.status AS session_status,
              session.idle_expires_at AS session_idle_expires_at,
              authorization.id AS oauth_authorization_id,
              authorization.status AS authorization_status,
              authorization.granted_scopes AS authorization_granted_scopes,
              client.id AS oauth_client_id, client.client_id, client.status AS client_status,
              client.grant_types AS client_grant_types,
              resource.id AS oauth_resource_id, resource.resource_id,
              resource.status AS resource_status, resource.audience_policy,
              human.id AS user_id, human.google_sub, human.status AS user_status,
              human.email_normalized AS user_email_normalized,
              authorization.legacy_authorization_grant_id,
              legacy_grant.tool_id AS grant_tool_id, legacy_grant.user_id AS grant_user_id,
              legacy_grant.email_normalized AS grant_email_normalized,
              legacy_grant.status AS grant_status, legacy_grant.valid_from AS grant_valid_from,
              legacy_grant.valid_until AS grant_valid_until, legacy_grant.permissions AS grant_permissions,
              session.correlation_id
       FROM oauth_refresh_tokens token
       JOIN oauth_refresh_token_families family ON family.id = token.oauth_refresh_token_family_id
       JOIN oauth_sessions session ON session.id = family.oauth_session_id
       JOIN oauth_authorizations authorization
         ON authorization.id = family.oauth_authorization_id
        AND authorization.oauth_client_id = family.oauth_client_id
        AND authorization.oauth_resource_id = family.oauth_resource_id
        AND authorization.user_id = family.user_id
       JOIN oauth_clients client ON client.id = family.oauth_client_id
       JOIN oauth_resources resource ON resource.id = family.oauth_resource_id
       JOIN users human ON human.id = family.user_id
       JOIN authorization_grants legacy_grant ON legacy_grant.id = authorization.legacy_authorization_grant_id
       WHERE token.token_hash = $1
       FOR UPDATE OF token, family, session
       FOR SHARE OF authorization, client, resource, human, legacy_grant`,
      [tokenHash]
    );
    const row = result.rows[0];
    return row ? {
      refreshTokenId: String(row.refresh_token_id), tokenStatus: String(row.token_status),
      tokenGeneration: Number(row.token_generation), tokenScopes: stringArray(row.token_scopes),
      tokenExpiresAt: row.token_expires_at as Date, familyId: String(row.family_id),
      familyStatus: String(row.family_status), familyCurrentGeneration: Number(row.family_current_generation),
      scopeCeiling: stringArray(row.scope_ceiling), currentScopes: stringArray(row.current_scopes),
      sessionId: String(row.session_id), sessionStatus: String(row.session_status),
      sessionIdleExpiresAt: row.session_idle_expires_at as Date,
      oauthAuthorizationId: String(row.oauth_authorization_id), authorizationStatus: String(row.authorization_status),
      authorizationGrantedScopes: stringArray(row.authorization_granted_scopes),
      oauthClientId: String(row.oauth_client_id), clientId: String(row.client_id),
      clientStatus: String(row.client_status), clientGrantTypes: stringArray(row.client_grant_types),
      oauthResourceId: String(row.oauth_resource_id), resourceId: String(row.resource_id),
      resourceStatus: String(row.resource_status), audiencePolicy: String(row.audience_policy),
      userId: String(row.user_id), googleSub: String(row.google_sub), userStatus: String(row.user_status),
      userEmailNormalized: String(row.user_email_normalized),
      legacyAuthorizationGrantId: String(row.legacy_authorization_grant_id), grantToolId: String(row.grant_tool_id),
      grantUserId: row.grant_user_id === null ? null : String(row.grant_user_id),
      grantEmailNormalized: row.grant_email_normalized === null ? null : String(row.grant_email_normalized),
      grantStatus: String(row.grant_status), grantValidFrom: row.grant_valid_from as Date,
      grantValidUntil: (row.grant_valid_until as Date | null) ?? null,
      grantPermissions: stringArray(row.grant_permissions), correlationId: String(row.correlation_id)
    } : null;
  }

  async persistRefreshRotation(input: {
    context: OAuthRefreshContext;
    replacementTokenId: string;
    replacementHash: string;
    scopes: string[];
    signingKeyId: string;
    now: Date;
    idleExpiresAt: Date;
  }): Promise<void> {
    const consumed = await this.db.query(
      `UPDATE oauth_refresh_tokens SET status = 'consumed', consumed_at = $2
       WHERE id = $1 AND status = 'current' AND expires_at > $2`,
      [input.context.refreshTokenId, input.now]
    );
    if (consumed.rowCount !== 1) throw new Error("oauth_refresh_consumption_race");
    const nextGeneration = input.context.tokenGeneration + 1;
    await this.db.query(
      `INSERT INTO oauth_refresh_tokens (
         id, oauth_refresh_token_family_id, token_hash, generation,
         parent_refresh_token_id, scopes, status, issued_at, expires_at
       ) VALUES ($1,$2,$3,$4,$5,$6,'current',$7,$8)`,
      [input.replacementTokenId, input.context.familyId, input.replacementHash, nextGeneration,
        input.context.refreshTokenId, input.scopes, input.now, input.idleExpiresAt]
    );
    const family = await this.db.query(
      `UPDATE oauth_refresh_token_families
       SET current_generation = $2, current_scopes = $3
       WHERE id = $1 AND status = 'active' AND current_generation = $4`,
      [input.context.familyId, nextGeneration, input.scopes, input.context.familyCurrentGeneration]
    );
    if (family.rowCount !== 1) throw new Error("oauth_refresh_family_race");
    const session = await this.db.query(
      `UPDATE oauth_sessions
       SET last_activity_at = $2, idle_expires_at = $3
       WHERE id = $1 AND status = 'active' AND idle_expires_at > $2`,
      [input.context.sessionId, input.now, input.idleExpiresAt]
    );
    if (session.rowCount !== 1) throw new Error("oauth_session_refresh_race");
    await this.markSigningKeyUsed(input.signingKeyId, input.now);
    await this.writeOAuthAudit({
      eventType: "oauth.token.refreshed", outcome: "success",
      correlationId: input.context.correlationId, actorUserId: input.context.userId,
      actorGoogleSub: input.context.googleSub,
      metadata: { client_id: input.context.clientId, resource_id: input.context.resourceId,
        scopes: input.scopes, oauth_session_id: input.context.sessionId }
    });
  }

  async revokeRefreshReplay(context: OAuthRefreshContext, now: Date): Promise<void> {
    await this.revokeFamilyAndSession(context, now, "refresh_replay", true);
    await this.writeOAuthAudit({
      eventType: "oauth.refresh.replay_detected", outcome: "denied",
      correlationId: context.correlationId, actorUserId: context.userId,
      actorGoogleSub: context.googleSub, reasonCode: "invalid_grant",
      metadata: { client_id: context.clientId, resource_id: context.resourceId,
        oauth_session_id: context.sessionId }
    });
  }

  async revokeRefreshFamily(context: OAuthRefreshContext, now: Date, reason: string): Promise<void> {
    await this.revokeFamilyAndSession(context, now, reason, false);
    await this.writeOAuthAudit({
      eventType: "oauth.token.revoked", outcome: "success", correlationId: context.correlationId,
      actorUserId: context.userId, actorGoogleSub: context.googleSub,
      metadata: { client_id: context.clientId, resource_id: context.resourceId,
        token_class: "refresh_token", oauth_session_id: context.sessionId }
    });
  }

  private async revokeFamilyAndSession(
    context: OAuthRefreshContext,
    now: Date,
    reason: string,
    replay: boolean
  ): Promise<void> {
    await this.db.query(
      `UPDATE oauth_refresh_token_families
       SET status = 'revoked', revoked_at = COALESCE(revoked_at, $2),
           revocation_reason = COALESCE(revocation_reason, $3),
           replay_detected_at = CASE WHEN $4::boolean THEN COALESCE(replay_detected_at, $2) ELSE replay_detected_at END
       WHERE id = $1`,
      [context.familyId, now, reason, replay]
    );
    await this.db.query(
      `UPDATE oauth_sessions
       SET status = 'revoked', revoked_at = COALESCE(revoked_at, $2),
           revocation_reason = COALESCE(revocation_reason, $3)
       WHERE id = $1`,
      [context.sessionId, now, reason]
    );
    await this.db.query(
      `UPDATE oauth_refresh_tokens SET status = 'revoked', revoked_at = COALESCE(revoked_at, $2)
       WHERE oauth_refresh_token_family_id = $1 AND status = 'current'`,
      [context.familyId, now]
    );
    await this.insertDurableRevocation("refresh_family", context.familyId, context, reason, now, null);
    await this.insertDurableRevocation("oauth_session", context.sessionId, context, reason, now, null);
  }

  async recordAccessTokenRevocation(input: {
    jti: string;
    retentionExpiresAt: Date;
    oauthClientId: string;
    oauthResourceId: string;
    clientId: string;
    resourceId: string;
    correlationId: string;
    now: Date;
  }): Promise<void> {
    if (input.retentionExpiresAt.getTime() <= input.now.getTime()) return;
    await this.db.query(
      `INSERT INTO oauth_revocations (
         target_type, target_id, oauth_client_id, oauth_resource_id, reason_code, revoked_at, expires_at
       ) VALUES ('access_token_jti',$1,$2,$3,'client_revocation',$4,$5)
       ON CONFLICT (target_type, target_id) DO UPDATE
       SET expires_at = GREATEST(oauth_revocations.expires_at, EXCLUDED.expires_at)`,
      [input.jti, input.oauthClientId, input.oauthResourceId, input.now, input.retentionExpiresAt]
    );
    await this.writeOAuthAudit({
      eventType: "oauth.token.revoked", outcome: "success", correlationId: input.correlationId,
      metadata: { client_id: input.clientId, resource_id: input.resourceId, token_class: "access_token" }
    });
  }

  async isAccessTokenActiveOnline(input: {
    sessionId: string;
    clientId: string;
    resourceId: string;
    subject: string;
    jti: string;
    scopes: string[];
    now: Date;
  }): Promise<boolean> {
    const result = await this.db.query<Record<string, unknown>>(
      `SELECT session.oauth_authorization_id, session.oauth_client_id, session.oauth_resource_id,
              authorization.legacy_authorization_grant_id,
              legacy_grant.tool_id AS grant_tool_id, legacy_grant.permissions AS grant_permissions
       FROM oauth_sessions session
       JOIN oauth_authorizations authorization ON authorization.id = session.oauth_authorization_id
       JOIN oauth_clients client ON client.id = session.oauth_client_id
       JOIN oauth_resources resource ON resource.id = session.oauth_resource_id
       JOIN users human ON human.id = session.user_id
       JOIN authorization_grants legacy_grant ON legacy_grant.id = authorization.legacy_authorization_grant_id
       WHERE session.id = $1 AND session.status = 'active' AND session.idle_expires_at > $6
         AND authorization.oauth_client_id = session.oauth_client_id
         AND authorization.oauth_resource_id = session.oauth_resource_id
         AND authorization.user_id = session.user_id
         AND $7::text[] <@ authorization.granted_scopes
         AND authorization.status = 'active' AND client.status = 'active' AND client.client_id = $2
         AND resource.status = 'active' AND resource.resource_id = $3
         AND human.status = 'active' AND human.google_sub = $4
         AND legacy_grant.status = 'active' AND legacy_grant.valid_from <= $6
         AND (legacy_grant.valid_until IS NULL OR legacy_grant.valid_until > $6)
         AND (legacy_grant.user_id = human.id OR legacy_grant.email_normalized = human.email_normalized)
         AND NOT EXISTS (
           SELECT 1 FROM oauth_revocations revocation
           WHERE revocation.target_type = 'access_token_jti' AND revocation.target_id = $5
             AND revocation.expires_at > $6
         )`,
      [input.sessionId, input.clientId, input.resourceId, input.subject, input.jti, input.now, input.scopes]
    );
    const row = result.rows[0];
    if (!row) return false;
    const mappings = await this.lockCurrentEntitlementMappings(
      String(row.oauth_client_id), String(row.oauth_resource_id), String(row.grant_tool_id), input.scopes
    );
    if (mappings.length !== input.scopes.length || new Set(mappings.map((mapping) => mapping.scope)).size !== input.scopes.length) {
      return false;
    }
    const permissions = new Set(stringArray(row.grant_permissions));
    return mappings.every((mapping) => permissions.has(mapping.legacyPermissionKey));
  }

  async writeIntrospectionAudit(input: {
    correlationId: string;
    resourceId: string;
    active: boolean;
    actorGoogleSub?: string;
  }): Promise<void> {
    await this.writeOAuthAudit({
      eventType: "oauth.token.introspected", outcome: "info", correlationId: input.correlationId,
      actorGoogleSub: input.actorGoogleSub,
      metadata: { resource_id: input.resourceId, active: input.active }
    });
  }

  async recordCodeExchangeDeniedAudit(input: {
    correlationId: string;
    clientId?: string;
    resourceId?: string;
    reasonCode: string;
  }): Promise<void> {
    await this.transaction(async (repository) => {
      await repository.writeOAuthAudit({
        eventType: "oauth.code.exchange_denied",
        outcome: "denied",
        correlationId: input.correlationId,
        reasonCode: input.reasonCode,
        metadata: {
          ...(input.clientId ? { client_id: input.clientId } : {}),
          ...(input.resourceId ? { resource_id: input.resourceId } : {})
        }
      });
    });
  }

  async writeRevocationAudit(input: {
    correlationId: string;
    clientId: string;
    tokenClass: "access_token" | "refresh_token" | "unknown";
  }): Promise<void> {
    await this.writeOAuthAudit({
      eventType: "oauth.token.revoked", outcome: "success", correlationId: input.correlationId,
      metadata: { client_id: input.clientId, token_class: input.tokenClass }
    });
  }

  private async markSigningKeyUsed(signingKeyId: string, now: Date): Promise<void> {
    const key = await this.db.query(
      `UPDATE oauth_signing_keys
       SET last_signed_at = GREATEST(COALESCE(last_signed_at, $2), $2)
       WHERE id = $1 AND key_namespace = 'oauth_p0' AND status = 'active'
         AND activates_at <= $2 AND retire_after IS NULL`,
      [signingKeyId, now]
    );
    if (key.rowCount !== 1) throw new Error("oauth_signing_key_race");
  }

  private async insertDurableRevocation(
    targetType: "refresh_family" | "oauth_session",
    targetId: string,
    context: OAuthRefreshContext,
    reason: string,
    now: Date,
    expiresAt: Date | null
  ): Promise<void> {
    await this.db.query(
      `INSERT INTO oauth_revocations (
         target_type, target_id, oauth_client_id, oauth_resource_id, reason_code, revoked_at, expires_at
       ) VALUES ($1,$2,$3,$4,$5,$6,$7)
       ON CONFLICT (target_type, target_id) DO NOTHING`,
      [targetType, targetId, context.oauthClientId, context.oauthResourceId, reason, now, expiresAt]
    );
  }

  private async writeOAuthAudit(input: {
    eventType: string;
    outcome: "success" | "denied" | "info";
    correlationId: string;
    actorUserId?: string;
    actorGoogleSub?: string;
    reasonCode?: string;
    metadata: Record<string, unknown>;
  }): Promise<void> {
    await this.db.query(
      `INSERT INTO audit_logs (
         event_id, event_type, outcome, correlation_id, actor_user_id,
         actor_google_sub, reason_code, metadata
       ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb)`,
      [randomUUID(), input.eventType, input.outcome, input.correlationId,
        input.actorUserId ?? null, input.actorGoogleSub ?? null, input.reasonCode ?? null,
        JSON.stringify(input.metadata)]
    );
  }
}
