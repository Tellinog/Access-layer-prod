import { randomUUID } from "node:crypto";
import type { Db } from "../db.js";
import { sanitizeMetadata } from "../audit.js";
import type {
  OAuthAdminAuditContext,
  OAuthAdminClientInput,
  OAuthAdminResourceInput,
  OAuthAdminScopeInput,
  OAuthAdminSnapshot
} from "./admin-types.js";
import { OAUTH_SIGNING_PUBLISH_LEAD_MS, OAUTH_SIGNING_RETIRE_GRACE_MS } from "./validation.js";

export class OAuthAdminRepositoryError extends Error {
  constructor(public readonly reason: string) {
    super("OAuth administration request rejected");
    this.name = "OAuthAdminRepositoryError";
  }
}

function reject(reason: string): never {
  throw new OAuthAdminRepositoryError(reason);
}

async function writeAudit(
  db: Db,
  ctx: OAuthAdminAuditContext,
  eventType: string,
  metadata: Record<string, unknown>
): Promise<void> {
  await db.query(
    `INSERT INTO audit_logs (
       event_id, event_type, outcome, correlation_id, actor_user_id,
       actor_google_sub, actor_email, actor_hd, request_ip_hash,
       user_agent_hash, metadata
     ) VALUES ($1, $2, 'success', $3, $4, $5, $6, $7, $8, $9, $10::jsonb)`,
    [
      randomUUID(), eventType, ctx.correlationId, ctx.actor.userId,
      ctx.actor.googleSub, ctx.actor.email, ctx.actor.hd, ctx.requestIpHash,
      ctx.userAgentHash, JSON.stringify(sanitizeMetadata(metadata))
    ]
  );
}

export class OAuthAdminRepository {
  constructor(private readonly db: Db) {}

  async snapshot(): Promise<OAuthAdminSnapshot> {
    return this.db.transaction(async (tx) => {
      await tx.query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY");
      const clients = await tx.query(`SELECT id, client_id, client_name, client_type,
        token_endpoint_auth_method, grant_types, status, owner_team, owner_contact,
        created_at, updated_at FROM oauth_clients ORDER BY client_id`);
      const clientCredentials = await tx.query(`SELECT id, oauth_client_id, status, created_at,
        activated_at, expires_at, retired_at, rotation_parent_id
        FROM oauth_client_credentials ORDER BY created_at, id`);
      const redirectUris = await tx.query(`SELECT id, oauth_client_id, redirect_uri, created_at
        FROM oauth_client_redirect_uris ORDER BY oauth_client_id, redirect_uri`);
      const resources = await tx.query(`SELECT id, resource_id, display_name, status, owner_team,
        owner_contact, audience_policy, protected_resource_metadata_url, created_at, updated_at
        FROM oauth_resources ORDER BY resource_id`);
      const resourceCredentials = await tx.query(`SELECT id, oauth_resource_id, credential_id,
        authentication_method, status, created_at, activated_at, rotated_at, expires_at,
        retired_at, rotation_parent_id FROM oauth_resource_credentials ORDER BY created_at, id`);
      const scopes = await tx.query(`SELECT id, scope, description, status, created_at, updated_at
        FROM oauth_scopes ORDER BY scope`);
      const resourceScopes = await tx.query(`SELECT rs.id, rs.oauth_resource_id, rs.oauth_scope_id,
        r.resource_id, s.scope, rs.legacy_permission_key, rs.status, rs.created_at, rs.updated_at
        FROM oauth_resource_scopes rs JOIN oauth_resources r ON r.id = rs.oauth_resource_id
        JOIN oauth_scopes s ON s.id = rs.oauth_scope_id ORDER BY r.resource_id, s.scope`);
      const allowances = await tx.query(`SELECT crs.id, crs.oauth_client_id, crs.oauth_resource_id,
        crs.oauth_scope_id, c.client_id, r.resource_id, s.scope, crs.status, crs.created_at
        FROM oauth_client_resource_scopes crs JOIN oauth_clients c ON c.id = crs.oauth_client_id
        JOIN oauth_resources r ON r.id = crs.oauth_resource_id
        JOIN oauth_scopes s ON s.id = crs.oauth_scope_id ORDER BY c.client_id, r.resource_id, s.scope`);
      const entitlementBindings = await tx.query(`SELECT b.id, b.oauth_resource_id, r.resource_id,
        b.binding_type, b.legacy_tool_id, t.slug AS legacy_tool_slug, b.status, b.created_at, b.disabled_at
        FROM oauth_resource_entitlement_bindings b JOIN oauth_resources r ON r.id = b.oauth_resource_id
        JOIN tools t ON t.id = b.legacy_tool_id ORDER BY r.resource_id, b.created_at`);
      const signingKeys = await tx.query(`SELECT id, kid, algorithm, public_jwk,
        public_key_fingerprint_sha256, status, published_at, activates_at, last_signed_at,
        retire_after, retired_at, created_at FROM oauth_signing_keys
        WHERE key_namespace = 'oauth_p0' ORDER BY created_at, kid`);
      return {
        clients: clients.rows,
        clientCredentials: clientCredentials.rows,
        redirectUris: redirectUris.rows,
        resources: resources.rows,
        resourceCredentials: resourceCredentials.rows,
        scopes: scopes.rows,
        resourceScopes: resourceScopes.rows,
        allowances: allowances.rows,
        entitlementBindings: entitlementBindings.rows,
        signingKeys: signingKeys.rows
      };
    });
  }

  async createScope(input: OAuthAdminScopeInput, ctx: OAuthAdminAuditContext): Promise<Record<string, unknown>> {
    return this.db.transaction(async (tx) => {
      const result = await tx.query(`INSERT INTO oauth_scopes (scope, description, status)
        VALUES ($1, $2, 'active') RETURNING id, scope, description, status, created_at, updated_at`,
      [input.scope, input.description]);
      await writeAudit(tx, ctx, "oauth.scope.changed", { action: "created", scope: input.scope });
      return result.rows[0] as Record<string, unknown>;
    });
  }

  async updateScope(id: string, input: { description?: string; status?: "active" | "disabled" }, ctx: OAuthAdminAuditContext) {
    return this.db.transaction(async (tx) => {
      const result = await tx.query(`UPDATE oauth_scopes SET
        description = COALESCE($2, description), status = COALESCE($3, status), updated_at = now()
        WHERE id = $1 RETURNING id, scope, description, status, created_at, updated_at`,
      [id, input.description ?? null, input.status ?? null]);
      if (!result.rows[0]) reject("scope_not_found");
      await writeAudit(tx, ctx, "oauth.scope.changed", { action: "updated", oauth_scope_id: id, status: input.status });
      return result.rows[0];
    });
  }

  async resolveLegacyEntitlement(legacyToolSlug: string) {
    const result = await this.db.query<{ legacy_tool_id: string; legacy_tool_slug: string; registered_permission_keys: string[] }>(
      `SELECT t.id AS legacy_tool_id, t.slug AS legacy_tool_slug,
        COALESCE(array_agg(p.permission_key ORDER BY p.permission_key)
          FILTER (WHERE p.permission_key IS NOT NULL), ARRAY[]::text[]) AS registered_permission_keys
       FROM tools t LEFT JOIN tool_permissions p ON p.tool_id = t.id
       WHERE t.slug = $1 GROUP BY t.id, t.slug`, [legacyToolSlug]
    );
    return result.rows[0] ?? null;
  }

  async findScopes(scopeNames: string[]) {
    const result = await this.db.query<{ id: string; scope: string; status: "active" | "disabled" }>(
      `SELECT id, scope, status FROM oauth_scopes WHERE scope = ANY($1::text[]) ORDER BY scope`, [scopeNames]
    );
    return result.rows;
  }

  async createResource(input: OAuthAdminResourceInput, credential: { id: string; secretHash: string }, ctx: OAuthAdminAuditContext) {
    return this.db.transaction(async (tx) => {
      const toolResult = await tx.query<{ id: string }>(`SELECT id FROM tools WHERE slug = $1 FOR SHARE`, [input.legacyToolSlug]);
      const tool = toolResult.rows[0];
      if (!tool) reject("legacy_tool_not_found");
      const permissionResult = await tx.query<{ permission_key: string }>(
        `SELECT permission_key FROM tool_permissions WHERE tool_id = $1 ORDER BY permission_key FOR SHARE`, [tool.id]
      );
      const registeredPermissions = new Set(permissionResult.rows.map((row) => row.permission_key));
      if (input.scopeMappings.some((mapping) => !registeredPermissions.has(mapping.legacyPermissionKey))) {
        reject("legacy_permission_not_registered");
      }
      const scopeResult = await tx.query<{ id: string; scope: string }>(
        `SELECT id, scope FROM oauth_scopes WHERE scope = ANY($1::text[]) AND status = 'active' ORDER BY scope FOR SHARE`,
        [input.scopeMappings.map((mapping) => mapping.scope)]
      );
      if (scopeResult.rows.length !== input.scopeMappings.length) reject("scope_not_found_or_disabled");
      const resourceResult = await tx.query(`INSERT INTO oauth_resources (
        resource_id, display_name, status, owner_team, owner_contact,
        audience_policy, protected_resource_metadata_url
      ) VALUES ($1, $2, $3, $4, $5, 'exact_single_resource', $6)
      RETURNING id, resource_id, display_name, status, owner_team, owner_contact,
        audience_policy, protected_resource_metadata_url, created_at, updated_at`,
      [input.resourceId, input.displayName, input.status, input.ownerTeam, input.ownerContact,
        input.protectedResourceMetadataUrl]);
      const resource = resourceResult.rows[0] as Record<string, unknown> & { id: string };
      await tx.query(`INSERT INTO oauth_resource_entitlement_bindings
        (oauth_resource_id, binding_type, legacy_tool_id, status)
        VALUES ($1, 'legacy_tool', $2, 'active')`, [resource.id, tool.id]);
      const scopeByName = new Map(scopeResult.rows.map((row) => [row.scope, row.id]));
      for (const mapping of input.scopeMappings) {
        await tx.query(`INSERT INTO oauth_resource_scopes
          (oauth_resource_id, oauth_scope_id, legacy_permission_key, status)
          VALUES ($1, $2, $3, 'active')`, [resource.id, scopeByName.get(mapping.scope), mapping.legacyPermissionKey]);
      }
      await tx.query(`INSERT INTO oauth_resource_credentials
        (oauth_resource_id, credential_id, secret_hash, authentication_method, status, activated_at)
        VALUES ($1, $2, $3, 'client_secret_basic', 'active', now())`,
      [resource.id, credential.id, credential.secretHash]);
      await writeAudit(tx, ctx, "oauth.resource.changed", {
        action: "created", oauth_resource_id: resource.id, resource_id: input.resourceId,
        legacy_tool_slug: input.legacyToolSlug, scopes: input.scopeMappings.map((mapping) => mapping.scope),
        resource_credential_id: credential.id
      });
      return resource;
    });
  }

  async createClient(input: OAuthAdminClientInput, secretHash: string, ctx: OAuthAdminAuditContext) {
    return this.db.transaction(async (tx) => {
      for (const allowance of input.allowances) {
        const exists = await tx.query<{ id: string; resource_id: string; scope: string }>(
          `SELECT rs.id, r.resource_id, s.scope FROM oauth_resource_scopes rs
           JOIN oauth_resources r ON r.id = rs.oauth_resource_id
           JOIN oauth_scopes s ON s.id = rs.oauth_scope_id
           WHERE r.resource_id = $1 AND s.scope = $2 AND r.status <> 'disabled'
             AND s.status = 'active' AND rs.status = 'active' FOR SHARE OF rs, r, s`,
          [allowance.resourceId, allowance.scope]
        );
        if (!exists.rows[0]) reject("allowance_target_not_registered");
      }
      const clientResult = await tx.query(`INSERT INTO oauth_clients (
        client_id, client_name, client_type, token_endpoint_auth_method,
        grant_types, status, owner_team, owner_contact
      ) VALUES ($1, $2, 'confidential', 'client_secret_basic', $3::text[], $4, $5, $6)
      RETURNING id, client_id, client_name, client_type, token_endpoint_auth_method,
        grant_types, status, owner_team, owner_contact, created_at, updated_at`,
      [input.clientId, input.clientName, input.grantTypes, input.status, input.ownerTeam, input.ownerContact]);
      const client = clientResult.rows[0] as Record<string, unknown> & { id: string };
      await tx.query(`INSERT INTO oauth_client_credentials
        (oauth_client_id, secret_hash, status, activated_at) VALUES ($1, $2, 'active', now())`,
      [client.id, secretHash]);
      for (const redirectUri of input.redirectUris) {
        await tx.query(`INSERT INTO oauth_client_redirect_uris (oauth_client_id, redirect_uri)
          VALUES ($1, $2)`, [client.id, redirectUri]);
      }
      for (const allowance of input.allowances) {
        await tx.query(`INSERT INTO oauth_client_resource_scopes
          (oauth_client_id, oauth_resource_id, oauth_scope_id, status)
          SELECT $1, rs.oauth_resource_id, rs.oauth_scope_id, 'active'
          FROM oauth_resource_scopes rs JOIN oauth_resources r ON r.id = rs.oauth_resource_id
          JOIN oauth_scopes s ON s.id = rs.oauth_scope_id
          WHERE r.resource_id = $2 AND s.scope = $3`, [client.id, allowance.resourceId, allowance.scope]);
      }
      await writeAudit(tx, ctx, "oauth.client.changed", {
        action: "created", oauth_client_id: client.id, client_id: input.clientId,
        redirect_uris: input.redirectUris, allowances: input.allowances
      });
      return client;
    });
  }

  async updateRegistrationStatus(kind: "client" | "resource", id: string, status: "draft" | "active" | "disabled", ctx: OAuthAdminAuditContext) {
    const table = kind === "client" ? "oauth_clients" : "oauth_resources";
    const event = kind === "client" ? "oauth.client.changed" : "oauth.resource.changed";
    return this.db.transaction(async (tx) => {
      const result = await tx.query(`UPDATE ${table} SET status = $2, updated_at = now()
        WHERE id = $1 RETURNING id, status`, [id, status]);
      if (!result.rows[0]) reject(`${kind}_not_found`);
      await writeAudit(tx, ctx, event, { action: "status_changed", [`oauth_${kind}_id`]: id, status });
      return result.rows[0];
    });
  }

  async replaceRedirectUris(clientId: string, redirectUris: string[], ctx: OAuthAdminAuditContext) {
    return this.db.transaction(async (tx) => {
      const exists = await tx.query(`SELECT id FROM oauth_clients WHERE id = $1 FOR UPDATE`, [clientId]);
      if (!exists.rows[0]) reject("client_not_found");
      await tx.query(`DELETE FROM oauth_client_redirect_uris WHERE oauth_client_id = $1`, [clientId]);
      for (const redirectUri of redirectUris) {
        await tx.query(`INSERT INTO oauth_client_redirect_uris (oauth_client_id, redirect_uri) VALUES ($1, $2)`, [clientId, redirectUri]);
      }
      await writeAudit(tx, ctx, "oauth.client.changed", { action: "redirect_uris_replaced", oauth_client_id: clientId, redirect_uris: redirectUris });
      return { oauth_client_id: clientId, redirect_uris: redirectUris };
    });
  }

  async replaceAllowances(clientId: string, allowances: OAuthAdminClientInput["allowances"], ctx: OAuthAdminAuditContext) {
    return this.db.transaction(async (tx) => {
      const exists = await tx.query(`SELECT id FROM oauth_clients WHERE id = $1 FOR UPDATE`, [clientId]);
      if (!exists.rows[0]) reject("client_not_found");
      const resolved: Array<{ resourceId: string; scope: string; resourcePk: string; scopePk: string }> = [];
      for (const allowance of allowances) {
        const target = await tx.query<{ resource_pk: string; scope_pk: string }>(
          `SELECT rs.oauth_resource_id AS resource_pk, rs.oauth_scope_id AS scope_pk
           FROM oauth_resource_scopes rs JOIN oauth_resources r ON r.id = rs.oauth_resource_id
           JOIN oauth_scopes s ON s.id = rs.oauth_scope_id
           WHERE r.resource_id = $1 AND s.scope = $2 AND rs.status = 'active'
             AND r.status <> 'disabled' AND s.status = 'active' FOR SHARE OF rs, r, s`,
          [allowance.resourceId, allowance.scope]
        );
        if (!target.rows[0]) reject("allowance_target_not_registered");
        resolved.push({ ...allowance, resourcePk: target.rows[0].resource_pk, scopePk: target.rows[0].scope_pk });
      }
      await tx.query(`DELETE FROM oauth_client_resource_scopes WHERE oauth_client_id = $1`, [clientId]);
      for (const allowance of resolved) {
        await tx.query(`INSERT INTO oauth_client_resource_scopes
          (oauth_client_id, oauth_resource_id, oauth_scope_id, status) VALUES ($1, $2, $3, 'active')`,
        [clientId, allowance.resourcePk, allowance.scopePk]);
      }
      await writeAudit(tx, ctx, "oauth.client.changed", { action: "allowances_replaced", oauth_client_id: clientId, allowances });
      return { oauth_client_id: clientId, allowances };
    });
  }

  async setResourceScope(resourceId: string, scopeId: string, input: { legacyPermissionKey: string; status: "active" | "disabled" }, ctx: OAuthAdminAuditContext) {
    return this.db.transaction(async (tx) => {
      const binding = await tx.query<{ legacy_tool_id: string }>(`SELECT legacy_tool_id
        FROM oauth_resource_entitlement_bindings WHERE oauth_resource_id = $1 AND status = 'active' FOR SHARE`, [resourceId]);
      if (!binding.rows[0]) reject("active_entitlement_binding_required");
      const permission = await tx.query(`SELECT 1 FROM tool_permissions WHERE tool_id = $1 AND permission_key = $2 FOR SHARE`,
        [binding.rows[0].legacy_tool_id, input.legacyPermissionKey]);
      if (!permission.rows[0]) reject("legacy_permission_not_registered");
      const result = await tx.query(`INSERT INTO oauth_resource_scopes
        (oauth_resource_id, oauth_scope_id, legacy_permission_key, status)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (oauth_resource_id, oauth_scope_id) DO UPDATE SET
          legacy_permission_key = EXCLUDED.legacy_permission_key, status = EXCLUDED.status, updated_at = now()
        RETURNING id, oauth_resource_id, oauth_scope_id, legacy_permission_key, status`,
      [resourceId, scopeId, input.legacyPermissionKey, input.status]);
      await writeAudit(tx, ctx, "oauth.resource.changed", { action: "scope_mapping_changed", oauth_resource_id: resourceId, oauth_scope_id: scopeId, status: input.status });
      return result.rows[0];
    });
  }

  async setEntitlementBinding(resourceId: string, legacyToolSlug: string, status: "active" | "disabled", ctx: OAuthAdminAuditContext) {
    return this.db.transaction(async (tx) => {
      const resource = await tx.query(`SELECT id FROM oauth_resources WHERE id = $1 FOR UPDATE`, [resourceId]);
      if (!resource.rows[0]) reject("resource_not_found");
      const tool = await tx.query<{ id: string }>(`SELECT id FROM tools WHERE slug = $1 FOR SHARE`, [legacyToolSlug]);
      if (!tool.rows[0]) reject("legacy_tool_not_found");
      if (status === "active") {
        const incompatible = await tx.query(`SELECT 1 FROM oauth_resource_scopes rs
          LEFT JOIN tool_permissions p ON p.tool_id = $2 AND p.permission_key = rs.legacy_permission_key
          WHERE rs.oauth_resource_id = $1 AND rs.status = 'active' AND p.id IS NULL LIMIT 1 FOR SHARE OF rs`,
        [resourceId, tool.rows[0].id]);
        if (incompatible.rows[0]) reject("legacy_permission_not_registered");
      }
      await tx.query(`UPDATE oauth_resource_entitlement_bindings SET status = 'disabled', disabled_at = now()
        WHERE oauth_resource_id = $1 AND status = 'active'`, [resourceId]);
      let result;
      if (status === "active") {
        result = await tx.query(`INSERT INTO oauth_resource_entitlement_bindings
          (oauth_resource_id, binding_type, legacy_tool_id, status)
          VALUES ($1, 'legacy_tool', $2, 'active')
          RETURNING id, oauth_resource_id, legacy_tool_id, status, created_at, disabled_at`, [resourceId, tool.rows[0].id]);
      } else {
        result = await tx.query(`SELECT id, oauth_resource_id, legacy_tool_id, status, created_at, disabled_at
          FROM oauth_resource_entitlement_bindings WHERE oauth_resource_id = $1
          ORDER BY created_at DESC LIMIT 1`, [resourceId]);
      }
      await writeAudit(tx, ctx, "oauth.resource.changed", { action: "entitlement_binding_changed", oauth_resource_id: resourceId, legacy_tool_slug: legacyToolSlug, status });
      return result.rows[0];
    });
  }

  async rotateCredential(kind: "client" | "resource", ownerId: string, generated: { id?: string; secretHash: string }, ctx: OAuthAdminAuditContext) {
    const isClient = kind === "client";
    const table = isClient ? "oauth_client_credentials" : "oauth_resource_credentials";
    const ownerColumn = isClient ? "oauth_client_id" : "oauth_resource_id";
    const ownerTable = isClient ? "oauth_clients" : "oauth_resources";
    return this.db.transaction(async (tx) => {
      const owner = await tx.query(`SELECT id FROM ${ownerTable} WHERE id = $1 FOR UPDATE`, [ownerId]);
      if (!owner.rows[0]) reject(`${kind}_not_found`);
      const current = await tx.query<{ id: string }>(`SELECT id FROM ${table}
        WHERE ${ownerColumn} = $1 AND status = 'active' ORDER BY created_at DESC, id FOR UPDATE`, [ownerId]);
      const parentId = current.rows[0]?.id ?? null;
      await tx.query(`UPDATE ${table} SET status = 'retired', retired_at = now()
        WHERE ${ownerColumn} = $1 AND status = 'active'`, [ownerId]);
      let result;
      if (isClient) {
        result = await tx.query(`INSERT INTO oauth_client_credentials
          (oauth_client_id, secret_hash, status, activated_at, rotation_parent_id)
          VALUES ($1, $2, 'active', now(), $3)
          RETURNING id, oauth_client_id, status, created_at, activated_at, retired_at, rotation_parent_id`,
        [ownerId, generated.secretHash, parentId]);
      } else {
        result = await tx.query(`INSERT INTO oauth_resource_credentials
          (oauth_resource_id, credential_id, secret_hash, authentication_method, status,
           activated_at, rotated_at, rotation_parent_id)
          VALUES ($1, $2, $3, 'client_secret_basic', 'active', now(), now(), $4)
          RETURNING id, oauth_resource_id, credential_id, status, created_at, activated_at,
            rotated_at, retired_at, rotation_parent_id`, [ownerId, generated.id, generated.secretHash, parentId]);
      }
      const event = isClient ? "oauth.client.changed" : "oauth.resource.changed";
      await writeAudit(tx, ctx, event, { action: "credential_rotated", [`oauth_${kind}_id`]: ownerId, credential_id: generated.id });
      return result.rows[0];
    });
  }

  async retireCredential(kind: "client" | "resource", credentialId: string, ctx: OAuthAdminAuditContext) {
    const table = kind === "client" ? "oauth_client_credentials" : "oauth_resource_credentials";
    return this.db.transaction(async (tx) => {
      const result = await tx.query(`UPDATE ${table} SET status = 'retired', retired_at = now()
        WHERE id = $1 AND status <> 'retired'
        RETURNING id, status, retired_at`, [credentialId]);
      if (!result.rows[0]) reject("credential_not_found_or_already_retired");
      await writeAudit(tx, ctx, kind === "client" ? "oauth.client.changed" : "oauth.resource.changed", {
        action: "credential_retired", credential_record_id: credentialId
      });
      return result.rows[0];
    });
  }

  async insertSigningKey(input: {
    kid: string; publicJwk: Record<string, unknown>; fingerprint: string; protectedReference: string;
  }, ctx: OAuthAdminAuditContext) {
    return this.db.transaction(async (tx) => {
      const result = await tx.query(`INSERT INTO oauth_signing_keys
        (key_namespace, kid, algorithm, public_jwk, public_key_fingerprint_sha256,
         protected_private_key_ref, status)
        VALUES ('oauth_p0', $1, 'RS256', $2::jsonb, $3, $4, 'staged')
        RETURNING id, kid, algorithm, public_jwk, public_key_fingerprint_sha256, status,
          published_at, activates_at, last_signed_at, retire_after, retired_at, created_at`,
      [input.kid, JSON.stringify(input.publicJwk), input.fingerprint, input.protectedReference]);
      await writeAudit(tx, ctx, "oauth.signing_key.changed", { action: "generated", kid: input.kid, fingerprint: input.fingerprint });
      return result.rows[0];
    });
  }

  async publishSigningKey(id: string, now: Date, ctx: OAuthAdminAuditContext) {
    return this.db.transaction(async (tx) => {
      const activatesAt = new Date(now.getTime() + OAUTH_SIGNING_PUBLISH_LEAD_MS);
      const result = await tx.query(`UPDATE oauth_signing_keys SET status = 'published',
        published_at = $2, activates_at = $3
        WHERE id = $1 AND status = 'staged'
        RETURNING id, kid, status, published_at, activates_at`, [id, now, activatesAt]);
      if (!result.rows[0]) reject("signing_key_not_staged");
      await writeAudit(tx, ctx, "oauth.signing_key.changed", { action: "published", signing_key_id: id, activates_at: activatesAt.toISOString() });
      return result.rows[0];
    });
  }

  async activateSigningKey(id: string, now: Date, ctx: OAuthAdminAuditContext) {
    return this.db.transaction(async (tx) => {
      await tx.query("SELECT pg_advisory_xact_lock(hashtext('oauth_p0_signing_activation'))");
      const target = await tx.query<{ kid: string; status: string; activates_at: Date | null }>(
        `SELECT kid, status, activates_at FROM oauth_signing_keys WHERE id = $1 FOR UPDATE`, [id]
      );
      const key = target.rows[0];
      if (!key || key.status !== "published" || !key.activates_at || key.activates_at > now) {
        reject("signing_key_publication_lead_not_satisfied");
      }
      const current = await tx.query<{ id: string; last_signed_at: Date | null }>(
        `SELECT id, last_signed_at FROM oauth_signing_keys
         WHERE status = 'active' AND retire_after IS NULL FOR UPDATE`
      );
      if (current.rows.length > 1) reject("ambiguous_active_signing_key");
      for (const active of current.rows) {
        if (active.last_signed_at === null) {
          await tx.query(`UPDATE oauth_signing_keys SET status = 'disabled' WHERE id = $1`, [active.id]);
        } else {
          const deadline = new Date(active.last_signed_at.getTime() + OAUTH_SIGNING_RETIRE_GRACE_MS);
          if (deadline <= now) {
            await tx.query(`UPDATE oauth_signing_keys SET status = 'retired', retire_after = $2, retired_at = $3 WHERE id = $1`, [active.id, deadline, now]);
          } else {
            await tx.query(`UPDATE oauth_signing_keys SET retire_after = $2 WHERE id = $1`, [active.id, deadline]);
          }
        }
      }
      const result = await tx.query(`UPDATE oauth_signing_keys SET status = 'active'
        WHERE id = $1 RETURNING id, kid, status, published_at, activates_at`, [id]);
      await writeAudit(tx, ctx, "oauth.signing_key.changed", { action: "activated", signing_key_id: id, kid: key.kid });
      return result.rows[0];
    });
  }

  async retireSigningKey(id: string, now: Date, ctx: OAuthAdminAuditContext) {
    return this.db.transaction(async (tx) => {
      const target = await tx.query<{ kid: string; status: string; last_signed_at: Date | null; retire_after: Date | null }>(
        `SELECT kid, status, last_signed_at, retire_after FROM oauth_signing_keys WHERE id = $1 FOR UPDATE`, [id]
      );
      const key = target.rows[0];
      if (!key || key.status !== "active") reject("signing_key_not_active");
      let result;
      if (key.last_signed_at === null) {
        result = await tx.query(`UPDATE oauth_signing_keys SET status = 'disabled' WHERE id = $1
          RETURNING id, kid, status, retire_after, retired_at`, [id]);
      } else {
        const deadline = key.retire_after ?? new Date(key.last_signed_at.getTime() + OAUTH_SIGNING_RETIRE_GRACE_MS);
        if (deadline <= now) {
          result = await tx.query(`UPDATE oauth_signing_keys SET status = 'retired', retire_after = $2,
            retired_at = $3 WHERE id = $1 RETURNING id, kid, status, retire_after, retired_at`, [id, deadline, now]);
        } else {
          result = await tx.query(`UPDATE oauth_signing_keys SET retire_after = $2 WHERE id = $1
            RETURNING id, kid, status, retire_after, retired_at`, [id, deadline]);
        }
      }
      await writeAudit(tx, ctx, "oauth.signing_key.changed", { action: "retirement_requested", signing_key_id: id, kid: key.kid });
      return result.rows[0];
    });
  }

  async disableSigningKey(id: string, ctx: OAuthAdminAuditContext) {
    return this.db.transaction(async (tx) => {
      const result = await tx.query(`UPDATE oauth_signing_keys SET status = 'disabled'
        WHERE id = $1 AND (status IN ('staged', 'published') OR (status = 'active' AND last_signed_at IS NULL))
        RETURNING id, kid, status`, [id]);
      if (!result.rows[0]) reject("signing_key_disable_not_safe");
      await writeAudit(tx, ctx, "oauth.signing_key.changed", { action: "disabled", signing_key_id: id });
      return result.rows[0];
    });
  }
}
