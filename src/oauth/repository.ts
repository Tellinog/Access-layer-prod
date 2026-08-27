import type { Db } from "../db.js";
import type {
  LegacyEntitlementSnapshot,
  OAuthClientRecord,
  OAuthResourceCredentialMetadata,
  OAuthResourceRecord,
  OAuthResourceScopeMappingRecord,
  OAuthSigningKeyPublicMetadata
} from "./types.js";

function firstOrNull<T>(rows: T[]): T | null {
  return rows[0] ?? null;
}

export class OAuthFoundationRepository {
  constructor(private readonly db: Db) {}

  async resolveClientByClientId(clientId: string): Promise<OAuthClientRecord | null> {
    const result = await this.db.query<{
      id: string;
      client_id: string;
      client_name: string;
      client_type: OAuthClientRecord["clientType"];
      token_endpoint_auth_method: OAuthClientRecord["tokenEndpointAuthMethod"];
      grant_types: OAuthClientRecord["grantTypes"];
      status: OAuthClientRecord["status"];
      owner_team: string;
      owner_contact: string | null;
    }>(`SELECT id, client_id, client_name, client_type, token_endpoint_auth_method,
               grant_types, status, owner_team, owner_contact
        FROM oauth_clients
        WHERE client_id = $1`, [clientId]);
    const row = firstOrNull(result.rows);
    return row && {
      id: row.id,
      clientId: row.client_id,
      clientName: row.client_name,
      clientType: row.client_type,
      tokenEndpointAuthMethod: row.token_endpoint_auth_method,
      grantTypes: row.grant_types,
      status: row.status,
      ownerTeam: row.owner_team,
      ownerContact: row.owner_contact
    };
  }

  async resolveClientById(id: string): Promise<OAuthClientRecord | null> {
    const result = await this.db.query<{
      id: string;
      client_id: string;
      client_name: string;
      client_type: OAuthClientRecord["clientType"];
      token_endpoint_auth_method: OAuthClientRecord["tokenEndpointAuthMethod"];
      grant_types: OAuthClientRecord["grantTypes"];
      status: OAuthClientRecord["status"];
      owner_team: string;
      owner_contact: string | null;
    }>(`SELECT id, client_id, client_name, client_type, token_endpoint_auth_method,
               grant_types, status, owner_team, owner_contact
        FROM oauth_clients
        WHERE id = $1`, [id]);
    const row = firstOrNull(result.rows);
    return row && {
      id: row.id,
      clientId: row.client_id,
      clientName: row.client_name,
      clientType: row.client_type,
      tokenEndpointAuthMethod: row.token_endpoint_auth_method,
      grantTypes: row.grant_types,
      status: row.status,
      ownerTeam: row.owner_team,
      ownerContact: row.owner_contact
    };
  }

  async resolveExactRedirectUris(oauthClientId: string): Promise<string[]> {
    const result = await this.db.query<{ redirect_uri: string }>(
      `SELECT redirect_uri
       FROM oauth_client_redirect_uris
       WHERE oauth_client_id = $1
       ORDER BY redirect_uri`,
      [oauthClientId]
    );
    return result.rows.map((row) => row.redirect_uri);
  }

  async resolveResourceByResourceId(resourceId: string): Promise<OAuthResourceRecord | null> {
    const result = await this.db.query<{
      id: string;
      resource_id: string;
      display_name: string;
      status: OAuthResourceRecord["status"];
      owner_team: string;
      owner_contact: string | null;
      audience_policy: OAuthResourceRecord["audiencePolicy"];
      protected_resource_metadata_url: string;
    }>(`SELECT id, resource_id, display_name, status, owner_team, owner_contact,
               audience_policy, protected_resource_metadata_url
        FROM oauth_resources
        WHERE resource_id = $1`, [resourceId]);
    const row = firstOrNull(result.rows);
    return row && {
      id: row.id,
      resourceId: row.resource_id,
      displayName: row.display_name,
      status: row.status,
      ownerTeam: row.owner_team,
      ownerContact: row.owner_contact,
      audiencePolicy: row.audience_policy,
      protectedResourceMetadataUrl: row.protected_resource_metadata_url
    };
  }

  async resolveResourceById(id: string): Promise<OAuthResourceRecord | null> {
    const result = await this.db.query<{
      id: string;
      resource_id: string;
      display_name: string;
      status: OAuthResourceRecord["status"];
      owner_team: string;
      owner_contact: string | null;
      audience_policy: OAuthResourceRecord["audiencePolicy"];
      protected_resource_metadata_url: string;
    }>(`SELECT id, resource_id, display_name, status, owner_team, owner_contact,
               audience_policy, protected_resource_metadata_url
        FROM oauth_resources
        WHERE id = $1`, [id]);
    const row = firstOrNull(result.rows);
    return row && {
      id: row.id,
      resourceId: row.resource_id,
      displayName: row.display_name,
      status: row.status,
      ownerTeam: row.owner_team,
      ownerContact: row.owner_contact,
      audiencePolicy: row.audience_policy,
      protectedResourceMetadataUrl: row.protected_resource_metadata_url
    };
  }

  async resolveActiveLegacyEntitlement(oauthResourceId: string): Promise<LegacyEntitlementSnapshot | null> {
    const result = await this.db.query<{
      legacy_tool_id: string;
      legacy_tool_slug: string;
      registered_permission_keys: string[];
    }>(`SELECT t.id AS legacy_tool_id,
               t.slug AS legacy_tool_slug,
               COALESCE(array_agg(tp.permission_key ORDER BY tp.permission_key)
                 FILTER (WHERE tp.permission_key IS NOT NULL), ARRAY[]::text[]) AS registered_permission_keys
        FROM oauth_resource_entitlement_bindings b
        JOIN tools t ON t.id = b.legacy_tool_id
        LEFT JOIN tool_permissions tp ON tp.tool_id = t.id
        WHERE b.oauth_resource_id = $1 AND b.status = 'active' AND b.binding_type = 'legacy_tool'
        GROUP BY t.id, t.slug`, [oauthResourceId]);
    const row = firstOrNull(result.rows);
    return row && {
      legacyToolId: row.legacy_tool_id,
      legacyToolSlug: row.legacy_tool_slug,
      registeredPermissionKeys: row.registered_permission_keys
    };
  }

  async resolveResourceScopeMappings(oauthResourceId: string): Promise<OAuthResourceScopeMappingRecord[]> {
    const result = await this.db.query<{
      resource_id: string;
      scope: string;
      legacy_permission_key: string;
    }>(`SELECT r.resource_id, s.scope, rs.legacy_permission_key
        FROM oauth_resource_scopes rs
        JOIN oauth_resources r ON r.id = rs.oauth_resource_id
        JOIN oauth_scopes s ON s.id = rs.oauth_scope_id
        WHERE rs.oauth_resource_id = $1
          AND rs.status = 'active'
          AND r.status = 'active'
          AND s.status = 'active'
        ORDER BY s.scope`, [oauthResourceId]);
    return result.rows.map((row) => ({
      resourceId: row.resource_id,
      scope: row.scope,
      legacyPermissionKey: row.legacy_permission_key
    }));
  }

  async isClientResourceScopeAllowed(oauthClientId: string, resourceId: string, scope: string): Promise<boolean> {
    const result = await this.db.query<{ allowed: boolean }>(
      `SELECT EXISTS (
         SELECT 1
         FROM oauth_client_resource_scopes crs
         JOIN oauth_clients c ON c.id = crs.oauth_client_id
         JOIN oauth_resource_scopes rs
           ON rs.oauth_resource_id = crs.oauth_resource_id AND rs.oauth_scope_id = crs.oauth_scope_id
         JOIN oauth_resources r ON r.id = crs.oauth_resource_id
         JOIN oauth_scopes s ON s.id = crs.oauth_scope_id
         WHERE crs.oauth_client_id = $1
           AND r.resource_id = $2
           AND s.scope = $3
           AND crs.status = 'active'
           AND rs.status = 'active'
           AND c.status = 'active'
           AND r.status = 'active'
           AND s.status = 'active'
       ) AS allowed`,
      [oauthClientId, resourceId, scope]
    );
    return result.rows[0]?.allowed === true;
  }

  async resolveResourceCredentialMetadata(credentialId: string): Promise<OAuthResourceCredentialMetadata | null> {
    const result = await this.db.query<{
      id: string;
      oauth_resource_id: string;
      credential_id: string;
      authentication_method: OAuthResourceCredentialMetadata["authenticationMethod"];
      status: OAuthResourceCredentialMetadata["status"];
      created_at: Date;
      activated_at: Date | null;
      rotated_at: Date | null;
      expires_at: Date | null;
      retired_at: Date | null;
      rotation_parent_id: string | null;
    }>(`SELECT id, oauth_resource_id, credential_id, authentication_method, status,
               created_at, activated_at, rotated_at, expires_at, retired_at, rotation_parent_id
        FROM oauth_resource_credentials
        WHERE credential_id = $1`, [credentialId]);
    const row = firstOrNull(result.rows);
    return row && {
      id: row.id,
      oauthResourceId: row.oauth_resource_id,
      credentialId: row.credential_id,
      authenticationMethod: row.authentication_method,
      status: row.status,
      createdAt: row.created_at,
      activatedAt: row.activated_at,
      rotatedAt: row.rotated_at,
      expiresAt: row.expires_at,
      retiredAt: row.retired_at,
      rotationParentId: row.rotation_parent_id
    };
  }

  async listSigningKeyPublicMetadata(): Promise<OAuthSigningKeyPublicMetadata[]> {
    const result = await this.db.query<{
      id: string;
      kid: string;
      algorithm: OAuthSigningKeyPublicMetadata["algorithm"];
      public_jwk: Record<string, unknown>;
      public_key_fingerprint_sha256: string;
      status: OAuthSigningKeyPublicMetadata["status"];
      published_at: Date | null;
      activates_at: Date | null;
      last_signed_at: Date | null;
      retire_after: Date | null;
      retired_at: Date | null;
    }>(`SELECT id, kid, algorithm, public_jwk, public_key_fingerprint_sha256, status,
               published_at, activates_at, last_signed_at, retire_after, retired_at
        FROM oauth_signing_keys
        WHERE key_namespace = 'oauth_p0'
        ORDER BY created_at, kid`);
    return result.rows.map((row) => ({
      id: row.id,
      kid: row.kid,
      algorithm: row.algorithm,
      publicJwk: row.public_jwk,
      publicKeyFingerprintSha256: row.public_key_fingerprint_sha256,
      status: row.status,
      publishedAt: row.published_at,
      activatesAt: row.activates_at,
      lastSignedAt: row.last_signed_at,
      retireAfter: row.retire_after,
      retiredAt: row.retired_at
    }));
  }
}
