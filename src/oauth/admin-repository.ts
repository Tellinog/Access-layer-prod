import { randomUUID } from "node:crypto";
import type { Db } from "../db.js";
import { sanitizeMetadata } from "../audit.js";
import type {
  OAuthAdminAuditContext,
  OAuthAdminAllowanceState,
  OAuthAdminBulkGrantInput,
  OAuthAdminBulkScopesInput,
  OAuthAdminClientInput,
  OAuthAdminNativeGrantInput,
  OAuthAdminResourceInput,
  OAuthAdminScopeInput,
  OAuthAdminSnapshot
} from "./admin-types.js";
import { isCanonicalOAuthScope, OAUTH_SIGNING_PUBLISH_LEAD_MS, OAUTH_SIGNING_RETIRE_GRACE_MS } from "./validation.js";

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
      const resources = await tx.query(`SELECT id, resource_id, display_name, status, entitlement_mode, owner_team,
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

  private async scopeBulkPlan(tx: Db, input: OAuthAdminBulkScopesInput, commit: boolean) {
    const names = input.rows.map((row) => row.scope);
    const found = await tx.query<{ id: string; scope: string; description: string; status: string }>(
      `SELECT id, scope, description, status FROM oauth_scopes WHERE scope = ANY($1::text[])
       ORDER BY scope ${commit ? "FOR UPDATE" : ""}`, [names]);
    const byName = new Map(found.rows.map((row) => [row.scope, row]));
    const seen = new Set<string>();
    const rows = input.rows.map((item) => {
      const existing = byName.get(item.scope);
      let operation: "create" | "skip" | "update_description" | "reactivate" | "error" = "create";
      let result: "ready" | "skip" | "warning" | "error" = "ready";
      let reason = "scope_missing";
      if (!isCanonicalOAuthScope(item.scope)) { operation = "error"; result = "error"; reason = "scope_invalid"; }
      else if (!item.description.trim()) { operation = "error"; result = "error"; reason = "scope_description_required"; }
      else if (seen.has(item.scope)) { operation = "error"; result = "error"; reason = "duplicate_input_scope"; }
      else if (existing) {
        if (existing.status === "disabled") {
          if (!input.reactivateDisabled) { operation = "skip"; result = "warning"; reason = "disabled_requires_opt_in"; }
          else if (existing.description !== item.description && !input.updateDescriptions) {
            operation = "skip"; result = "warning"; reason = "description_change_requires_opt_in";
          } else { operation = "reactivate"; reason = "explicit_reactivation"; }
        } else if (existing.description === item.description) {
          operation = "skip"; result = "skip"; reason = "identical_active";
        } else if (input.updateDescriptions) {
          operation = "update_description"; reason = "explicit_description_update";
        } else { operation = "skip"; result = "warning"; reason = "description_change_requires_opt_in"; }
      }
      seen.add(item.scope);
      return { row: item.row, scope: item.scope, description: item.description, result, operation, reason,
        existing_scope_id: existing?.id ?? null, existing_status: existing?.status ?? null,
        existing_description: existing?.description ?? null };
    });
    return { rows, summary: { total: rows.length, create: rows.filter((r) => r.operation === "create").length,
      skip: rows.filter((r) => r.operation === "skip").length,
      update: rows.filter((r) => r.operation === "update_description").length,
      reactivate: rows.filter((r) => r.operation === "reactivate").length,
      error: rows.filter((r) => r.operation === "error").length } };
  }

  async bulkScopes(input: OAuthAdminBulkScopesInput, commit: boolean, ctx?: OAuthAdminAuditContext) {
    return this.db.transaction(async (tx) => {
      if (!commit) await tx.query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY");
      const plan = await this.scopeBulkPlan(tx, input, commit);
      if (!commit) return plan;
      if (!ctx || plan.summary.error) reject("bulk_scope_validation_failed");
      const changed: string[] = [];
      for (const row of plan.rows) {
        if (row.operation === "create") {
          await tx.query(`INSERT INTO oauth_scopes (scope, description, status) VALUES ($1, $2, 'active')`, [row.scope, row.description]);
        } else if (row.operation === "update_description") {
          await tx.query(`UPDATE oauth_scopes SET description = $2, updated_at = now() WHERE id = $1 AND status = 'active'`,
            [row.existing_scope_id, row.description]);
        } else if (row.operation === "reactivate") {
          await tx.query(`UPDATE oauth_scopes SET description = $2, status = 'active', updated_at = now()
            WHERE id = $1 AND status = 'disabled'`, [row.existing_scope_id, row.description]);
        } else continue;
        changed.push(row.scope);
        await writeAudit(tx, ctx, "oauth.scope.changed", { action: row.operation === "create" ? "created" : "updated",
          operation: row.operation, scope: row.scope, batch: true });
      }
      if (changed.length) await writeAudit(tx, ctx, "oauth.scope.bulk_changed", {
        action: "committed", count: changed.length, scopes: changed
      });
      return { ...plan, committed: changed.length };
    });
  }

  async bulkScopeStatus(scopes: string[], status: "active" | "disabled", commit: boolean, ctx?: OAuthAdminAuditContext) {
    return this.db.transaction(async (tx) => {
      if (!commit) await tx.query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY");
      const found = await tx.query<{ id: string; scope: string; status: string; resource_count: string; client_count: string }>(
        `SELECT s.id, s.scope, s.status,
          (SELECT count(DISTINCT rs.oauth_resource_id)::text FROM oauth_resource_scopes rs WHERE rs.oauth_scope_id = s.id AND rs.status = 'active') AS resource_count,
          (SELECT count(DISTINCT a.oauth_client_id)::text FROM oauth_client_resource_scopes a WHERE a.oauth_scope_id = s.id AND a.status = 'active') AS client_count
         FROM oauth_scopes s WHERE s.scope = ANY($1::text[]) ORDER BY s.scope ${commit ? "FOR UPDATE OF s" : ""}`, [scopes]);
      const byName = new Map(found.rows.map((row) => [row.scope, row]));
      const rows = scopes.map((scope) => {
        const current = byName.get(scope);
        return { scope, status: current?.status ?? null, operation: !current ? "error" : current.status === status ? "skip" : status,
          reason: !current ? "scope_not_found" : current.status === status ? "already_in_status" : "explicit_status_change",
          affected_resources: Number(current?.resource_count ?? 0), affected_clients: Number(current?.client_count ?? 0), id: current?.id ?? null };
      });
      if (!commit) return { rows, summary: { total: rows.length, change: rows.filter((r) => r.operation === status).length,
        skip: rows.filter((r) => r.operation === "skip").length, error: rows.filter((r) => r.operation === "error").length } };
      if (!ctx || rows.some((row) => row.operation === "error")) reject("bulk_scope_status_invalid");
      for (const row of rows) if (row.operation === status) {
        await tx.query(`UPDATE oauth_scopes SET status = $2, updated_at = now() WHERE id = $1`, [row.id, status]);
        await writeAudit(tx, ctx, "oauth.scope.changed", { action: "updated", operation: "status_changed", scope: row.scope, status, batch: true });
      }
      return { rows, committed: rows.filter((row) => row.operation === status).length };
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

  async listLegacyTools() {
    const result = await this.db.query(`SELECT t.id, t.slug, t.display_name,
      COALESCE(array_agg(p.permission_key ORDER BY p.permission_key)
        FILTER (WHERE p.permission_key IS NOT NULL), ARRAY[]::text[]) AS registered_permission_keys
      FROM tools t LEFT JOIN tool_permissions p ON p.tool_id = t.id
      WHERE t.status = 'active' GROUP BY t.id, t.slug, t.display_name
      HAVING count(p.id) > 0 AND bool_and(p.permission_key ~ '^[a-z0-9-]+(:[a-z0-9-]+)+$')
      ORDER BY t.display_name, t.slug LIMIT 200`);
    return result.rows;
  }

  async searchUsers(query: string) {
    const escaped = query.replace(/[\\%_]/g, "\\$&");
    const result = await this.db.query(`SELECT id, email, display_name, status, last_seen_at
      FROM users WHERE email::text ILIKE $1 ESCAPE '\\' OR display_name ILIKE $1 ESCAPE '\\'
      ORDER BY email LIMIT 25`, [`%${escaped}%`]);
    return result.rows;
  }

  async listNativeGrants(resourceId: string, filters: { query: string; scope: string; status: string; effective: string; offset: number } =
    { query: "", scope: "", status: "", effective: "", offset: 0 }) {
    const resource = await this.db.query<{ id: string; entitlement_mode: string }>(
      `SELECT id, entitlement_mode FROM oauth_resources WHERE id = $1`, [resourceId]);
    if (!resource.rows[0]) reject("resource_not_found");
    if (resource.rows[0].entitlement_mode !== "native") reject("native_resource_required");
    const escaped = filters.query.replace(/[\\%_]/g, "\\$&");
    const result = await this.db.query(`SELECT * FROM (SELECT g.id, g.oauth_resource_id AS resource_id, r.display_name AS resource_display_name,
      s.scope, g.user_id, u.email AS user_email, u.display_name AS user_display_name,
      g.status, (g.status = 'active' AND g.revoked_at IS NULL AND u.status = 'active'
        AND g.valid_from <= now() AND (g.valid_until IS NULL OR g.valid_until > now())
        AND r.status = 'active' AND s.status = 'active' AND rs.status = 'active') AS effective,
      g.valid_from, g.valid_until, g.created_at, g.revoked_at
      FROM oauth_native_human_grants g
      JOIN oauth_resources r ON r.id = g.oauth_resource_id
      JOIN oauth_scopes s ON s.id = g.oauth_scope_id
      JOIN oauth_resource_scopes rs ON rs.oauth_resource_id = g.oauth_resource_id AND rs.oauth_scope_id = g.oauth_scope_id
      LEFT JOIN users u ON u.id = g.user_id
      WHERE g.oauth_resource_id = $1) AS grants
      WHERE ($2 = '' OR coalesce(grants.user_email::text, '') ILIKE $2 ESCAPE '\\'
        OR coalesce(grants.user_display_name, '') ILIKE $2 ESCAPE '\\'
        OR grants.user_id::text ILIKE $2 ESCAPE '\\')
        AND ($3 = '' OR grants.scope ILIKE $3 ESCAPE '\\')
        AND ($4 = '' OR grants.status = $4)
        AND ($5 = '' OR grants.effective = ($5 = 'true'))
      ORDER BY grants.created_at DESC, grants.id DESC LIMIT 100 OFFSET $6`,
      [resourceId, escaped ? `%${escaped}%` : "", filters.scope ? `%${filters.scope.replace(/[\\%_]/g, "\\$&")}%` : "",
        filters.status, filters.effective, filters.offset]);
    return result.rows;
  }

  async findScopes(scopeNames: string[]) {
    const result = await this.db.query<{ id: string; scope: string; status: "active" | "disabled" }>(
      `SELECT id, scope, status FROM oauth_scopes WHERE scope = ANY($1::text[]) ORDER BY scope`, [scopeNames]
    );
    return result.rows;
  }

  async createResource(input: OAuthAdminResourceInput, credential: { id: string; secretHash: string }, ctx: OAuthAdminAuditContext) {
    return this.db.transaction(async (tx) => {
      let tool: { id: string } | undefined;
      if (input.entitlementMode !== "native") {
        const toolResult = await tx.query<{ id: string }>(`SELECT id FROM tools WHERE slug = $1 FOR SHARE`, [input.legacyToolSlug]);
        tool = toolResult.rows[0];
        if (!tool) reject("legacy_tool_not_found");
        const permissionResult = await tx.query<{ permission_key: string }>(
          `SELECT permission_key FROM tool_permissions WHERE tool_id = $1 ORDER BY permission_key FOR SHARE`, [tool.id]
        );
        const registeredPermissions = new Set(permissionResult.rows.map((row) => row.permission_key));
        if (input.scopeMappings.some((mapping) => !registeredPermissions.has(mapping.legacyPermissionKey))) {
          reject("legacy_permission_not_registered");
        }
      }
      const scopeNames = input.entitlementMode === "native" ? input.scopes : input.scopeMappings.map((mapping) => mapping.scope);
      const scopeResult = await tx.query<{ id: string; scope: string }>(
        `SELECT id, scope FROM oauth_scopes WHERE scope = ANY($1::text[]) AND status = 'active' ORDER BY scope FOR SHARE`,
        [scopeNames]
      );
      if (scopeResult.rows.length !== scopeNames.length) reject("scope_not_found_or_disabled");
      const resourceResult = await tx.query(`INSERT INTO oauth_resources (
        resource_id, display_name, status, owner_team, owner_contact,
        audience_policy, protected_resource_metadata_url, entitlement_mode
      ) VALUES ($1, $2, $3, $4, $5, 'exact_single_resource', $6, $7)
      RETURNING id, resource_id, display_name, status, owner_team, owner_contact,
        audience_policy, protected_resource_metadata_url, entitlement_mode, created_at, updated_at`,
      [input.resourceId, input.displayName, input.status, input.ownerTeam, input.ownerContact,
        input.protectedResourceMetadataUrl, input.entitlementMode ?? "legacy_bridge"]);
      const resource = resourceResult.rows[0] as Record<string, unknown> & { id: string };
      if (input.entitlementMode !== "native") {
        await tx.query(`INSERT INTO oauth_resource_entitlement_bindings
          (oauth_resource_id, binding_type, legacy_tool_id, status)
          VALUES ($1, 'legacy_tool', $2, 'active')`, [resource.id, tool!.id]);
      }
      const scopeByName = new Map(scopeResult.rows.map((row) => [row.scope, row.id]));
      for (const scope of scopeNames) {
        const permission = input.entitlementMode === "native" ? null
          : input.scopeMappings.find((mapping) => mapping.scope === scope)!.legacyPermissionKey;
        await tx.query(`INSERT INTO oauth_resource_scopes
          (oauth_resource_id, oauth_scope_id, legacy_permission_key, status)
          VALUES ($1, $2, $3, 'active')`, [resource.id, scopeByName.get(scope), permission]);
      }
      await tx.query(`INSERT INTO oauth_resource_credentials
        (oauth_resource_id, credential_id, secret_hash, authentication_method, status, activated_at)
        VALUES ($1, $2, $3, 'client_secret_basic', 'active', now())`,
      [resource.id, credential.id, credential.secretHash]);
      await writeAudit(tx, ctx, "oauth.resource.changed", {
        action: "created", oauth_resource_id: resource.id, resource_id: input.resourceId,
        entitlement_mode: input.entitlementMode ?? "legacy_bridge",
        ...(input.entitlementMode === "native" ? {} : { legacy_tool_slug: input.legacyToolSlug }), scopes: scopeNames,
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

  async previewCommitAllowances(clientId: string, allowances: OAuthAdminClientInput["allowances"],
    expectedCurrent: OAuthAdminAllowanceState[] | null, commit: boolean, ctx?: OAuthAdminAuditContext) {
    return this.db.transaction(async (tx) => {
      if (!commit) await tx.query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY");
      const client = await tx.query(`SELECT id FROM oauth_clients WHERE id = $1 ${commit ? "FOR UPDATE" : ""}`, [clientId]);
      if (!client.rows[0]) reject("client_not_found");
      const currentResult = await tx.query<{ resource_id: string; scope: string; status: "active" | "disabled" }>(
        `SELECT r.resource_id, s.scope, a.status FROM oauth_client_resource_scopes a
         JOIN oauth_resources r ON r.id = a.oauth_resource_id JOIN oauth_scopes s ON s.id = a.oauth_scope_id
         WHERE a.oauth_client_id = $1 ORDER BY r.resource_id, s.scope`, [clientId]);
      const key = (item: { resourceId: string; scope: string }) => `${item.resourceId}\u0000${item.scope}`;
      const current = currentResult.rows.map((row) => ({ resourceId: row.resource_id, scope: row.scope, status: row.status }));
      const stateKey = (item: OAuthAdminAllowanceState) => `${key(item)}\u0000${item.status}`;
      const currentStateKeys = new Set(current.map(stateKey));
      const currentByPair = new Map(current.map((item) => [key(item), item]));
      const activeKeys = new Set(current.filter((item) => item.status === "active").map(key));
      const desiredKeys = new Set(allowances.map(key));
      const diff = [...allowances.map((item) => ({ resource_id: item.resourceId, scope: item.scope,
        operation: activeKeys.has(key(item)) ? "unchanged" : "add", current_status: currentByPair.get(key(item))?.status ?? null })),
        ...current.filter((item) => !desiredKeys.has(key(item))).map((item) => ({ resource_id: item.resourceId,
          scope: item.scope, operation: "remove", current_status: item.status }))];
      const summary = { add: diff.filter((row) => row.operation === "add").length,
        remove: diff.filter((row) => row.operation === "remove").length,
        unchanged: diff.filter((row) => row.operation === "unchanged").length };
      for (const item of allowances) {
        const target = await tx.query<{ resource_pk: string; scope_pk: string }>(
          `SELECT rs.oauth_resource_id AS resource_pk, rs.oauth_scope_id AS scope_pk FROM oauth_resource_scopes rs
           JOIN oauth_resources r ON r.id = rs.oauth_resource_id JOIN oauth_scopes s ON s.id = rs.oauth_scope_id
           WHERE r.resource_id = $1 AND s.scope = $2 AND rs.status = 'active'
             AND r.status <> 'disabled' AND s.status = 'active' ${commit ? "FOR SHARE OF rs, r, s" : ""}`,
          [item.resourceId, item.scope]);
        if (!target.rows[0]) reject("allowance_target_not_registered");
      }
      if (!commit) return { current: current.map((item) => ({ resource_id: item.resourceId, scope: item.scope, status: item.status })), diff, summary };
      if (!ctx || !expectedCurrent ||
        new Set(expectedCurrent.map(stateKey)).size !== currentStateKeys.size ||
        expectedCurrent.some((item) => !currentStateKeys.has(stateKey(item)))) reject("allowance_preview_stale");
      await tx.query(`DELETE FROM oauth_client_resource_scopes WHERE oauth_client_id = $1`, [clientId]);
      for (const item of allowances) await tx.query(`INSERT INTO oauth_client_resource_scopes
        (oauth_client_id, oauth_resource_id, oauth_scope_id, status)
        SELECT $1, rs.oauth_resource_id, rs.oauth_scope_id, 'active' FROM oauth_resource_scopes rs
        JOIN oauth_resources r ON r.id = rs.oauth_resource_id JOIN oauth_scopes s ON s.id = rs.oauth_scope_id
        WHERE r.resource_id = $2 AND s.scope = $3`, [clientId, item.resourceId, item.scope]);
      await writeAudit(tx, ctx, "oauth.client.changed", { action: "allowances_replaced", oauth_client_id: clientId,
        add: summary.add, remove: summary.remove, unchanged: summary.unchanged });
      return { diff, summary, committed: true };
    });
  }

  async previewCommitRedirectUris(clientId: string, redirectUris: string[], expectedCurrent: string[] | null,
    commit: boolean, ctx?: OAuthAdminAuditContext) {
    return this.db.transaction(async (tx) => {
      if (!commit) await tx.query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY");
      const client = await tx.query(`SELECT id FROM oauth_clients WHERE id = $1 ${commit ? "FOR UPDATE" : ""}`, [clientId]);
      if (!client.rows[0]) reject("client_not_found");
      const rows = await tx.query<{ redirect_uri: string }>(
        `SELECT redirect_uri FROM oauth_client_redirect_uris WHERE oauth_client_id = $1 ORDER BY redirect_uri`, [clientId]);
      const current = rows.rows.map((row) => row.redirect_uri);
      const currentSet = new Set(current); const desiredSet = new Set(redirectUris);
      const diff = [...redirectUris.map((uri) => ({ redirect_uri: uri, operation: currentSet.has(uri) ? "unchanged" : "add" })),
        ...current.filter((uri) => !desiredSet.has(uri)).map((uri) => ({ redirect_uri: uri, operation: "remove" }))];
      if (!commit) return { current, diff };
      if (!ctx || !expectedCurrent || new Set(expectedCurrent).size !== currentSet.size ||
        expectedCurrent.some((uri) => !currentSet.has(uri))) reject("redirect_preview_stale");
      await tx.query(`DELETE FROM oauth_client_redirect_uris WHERE oauth_client_id = $1`, [clientId]);
      for (const uri of redirectUris) await tx.query(`INSERT INTO oauth_client_redirect_uris
        (oauth_client_id, redirect_uri) VALUES ($1, $2)`, [clientId, uri]);
      await writeAudit(tx, ctx, "oauth.client.changed", { action: "redirect_uris_replaced", oauth_client_id: clientId,
        added: diff.filter((row) => row.operation === "add").length,
        removed: diff.filter((row) => row.operation === "remove").length });
      return { diff, committed: true };
    });
  }

  async setResourceScope(resourceId: string, scopeId: string, input: { legacyPermissionKey: string | null; status: "active" | "disabled" }, ctx: OAuthAdminAuditContext) {
    return this.db.transaction(async (tx) => {
      const resource = await tx.query<{ entitlement_mode: string }>(`SELECT entitlement_mode FROM oauth_resources WHERE id = $1 FOR SHARE`, [resourceId]);
      if (!resource.rows[0]) reject("resource_not_found");
      const scope = await tx.query<{ status: string }>(`SELECT status FROM oauth_scopes WHERE id = $1 FOR SHARE`, [scopeId]);
      if (!scope.rows[0]) reject("scope_not_found");
      if (input.status === "active" && scope.rows[0].status !== "active") reject("scope_not_active");
      if (resource.rows[0].entitlement_mode === "native") {
        if (input.legacyPermissionKey !== null) reject("native_scope_legacy_permission_forbidden");
      } else {
        if (!input.legacyPermissionKey) reject("legacy_permission_required");
        const binding = await tx.query<{ legacy_tool_id: string }>(`SELECT legacy_tool_id
          FROM oauth_resource_entitlement_bindings WHERE oauth_resource_id = $1 AND status = 'active' FOR SHARE`, [resourceId]);
        if (!binding.rows[0]) reject("active_entitlement_binding_required");
        const permission = await tx.query(`SELECT 1 FROM tool_permissions WHERE tool_id = $1 AND permission_key = $2 FOR SHARE`,
          [binding.rows[0].legacy_tool_id, input.legacyPermissionKey]);
        if (!permission.rows[0]) reject("legacy_permission_not_registered");
      }
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

  async bulkNativeResourceScopes(resourceId: string, operations: Array<{ scope: string; action: "activate" | "disable" }>,
    commit: boolean, ctx?: OAuthAdminAuditContext) {
    return this.db.transaction(async (tx) => {
      if (!commit) await tx.query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY");
      const resource = await tx.query<{ entitlement_mode: string; status: string }>(
        `SELECT entitlement_mode, status FROM oauth_resources WHERE id = $1 ${commit ? "FOR UPDATE" : ""}`, [resourceId]);
      if (!resource.rows[0]) reject("resource_not_found");
      if (resource.rows[0].entitlement_mode !== "native") reject("native_resource_required");
      const names = operations.map((item) => item.scope);
      const found = await tx.query<{ id: string; scope: string; status: string; registration_status: string | null }>(
        `SELECT s.id, s.scope, s.status, rs.status AS registration_status FROM oauth_scopes s
         LEFT JOIN oauth_resource_scopes rs ON rs.oauth_scope_id = s.id AND rs.oauth_resource_id = $1
         WHERE s.scope = ANY($2::text[]) ORDER BY s.scope ${commit ? "FOR SHARE OF s" : ""}`, [resourceId, names]);
      const byName = new Map(found.rows.map((row) => [row.scope, row]));
      const rows = operations.map((item) => {
        const scope = byName.get(item.scope);
        const reason = !scope ? "scope_not_found" : item.action === "activate" && scope.status !== "active"
          ? "scope_inactive" : item.action === "disable" && !scope.registration_status
            ? "registration_not_found" : scope.registration_status === (item.action === "activate" ? "active" : "disabled")
              ? "already_in_status" : "explicit_registration_change";
        return { scope: item.scope, action: item.action, current_status: scope?.registration_status ?? null,
          operation: reason === "explicit_registration_change" ? item.action : reason === "already_in_status" ? "no_change" : "error",
          reason, scope_id: scope?.id ?? null };
      });
      if (!commit) return { rows, summary: { total: rows.length, change: rows.filter((r) => r.operation === "activate" || r.operation === "disable").length,
        no_change: rows.filter((r) => r.operation === "no_change").length, error: rows.filter((r) => r.operation === "error").length } };
      if (!ctx || rows.some((r) => r.operation === "error")) reject("resource_scope_bulk_invalid");
      for (const row of rows) if (row.operation === "activate" || row.operation === "disable") {
        if (row.operation === "activate") await tx.query(`INSERT INTO oauth_resource_scopes
          (oauth_resource_id, oauth_scope_id, legacy_permission_key, status) VALUES ($1, $2, NULL, 'active')
          ON CONFLICT (oauth_resource_id, oauth_scope_id) DO UPDATE SET legacy_permission_key = NULL,
            status = 'active', updated_at = now()`, [resourceId, row.scope_id]);
        else await tx.query(`UPDATE oauth_resource_scopes SET status = 'disabled', updated_at = now()
          WHERE oauth_resource_id = $1 AND oauth_scope_id = $2`, [resourceId, row.scope_id]);
        await writeAudit(tx, ctx, "oauth.resource.changed", { action: "scope_mapping_changed", oauth_resource_id: resourceId,
          scope: row.scope, status: row.operation === "activate" ? "active" : "disabled", batch: true });
      }
      return { rows, committed: rows.filter((r) => r.operation === "activate" || r.operation === "disable").length };
    });
  }

  async setEntitlementBinding(resourceId: string, legacyToolSlug: string, status: "active" | "disabled", ctx: OAuthAdminAuditContext) {
    return this.db.transaction(async (tx) => {
      const resource = await tx.query<{ id: string; entitlement_mode: string }>(`SELECT id, entitlement_mode FROM oauth_resources WHERE id = $1 FOR UPDATE`, [resourceId]);
      if (!resource.rows[0]) reject("resource_not_found");
      if (resource.rows[0].entitlement_mode !== "legacy_bridge") reject("legacy_bridge_resource_required");
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

  async createNativeGrants(input: OAuthAdminNativeGrantInput & { validFrom: Date }, now: Date, ctx: OAuthAdminAuditContext) {
    return this.db.transaction(async (tx) => {
      const user = await tx.query<{ id: string; status: string }>(
        `SELECT id, status FROM users WHERE id = $1 FOR UPDATE`, [input.userId]);
      if (!user.rows[0] || user.rows[0].status !== "active") reject("user_not_found_or_inactive");
      const resource = await tx.query<{ id: string; entitlement_mode: string }>(
        `SELECT id, entitlement_mode FROM oauth_resources WHERE id = $1 FOR SHARE`, [input.resourceId]);
      if (!resource.rows[0]) reject("resource_not_found");
      if (resource.rows[0].entitlement_mode !== "native") reject("native_resource_required");
      const registrations = await tx.query<{ id: string; scope: string; scope_status: string; registration_status: string }>(
        `SELECT s.id, s.scope, s.status AS scope_status, rs.status AS registration_status
         FROM oauth_scopes s JOIN oauth_resource_scopes rs ON rs.oauth_scope_id = s.id
         WHERE rs.oauth_resource_id = $1 AND s.scope = ANY($2::text[])
         ORDER BY s.scope FOR SHARE OF s, rs`, [input.resourceId, input.scopes]);
      const scopeByName = new Map(registrations.rows.map((row) => [row.scope, row]));
      const created: unknown[] = [];
      for (const scope of [...input.scopes].sort()) {
        const registration = scopeByName.get(scope);
        if (!registration || registration.registration_status !== "active") reject("scope_not_registered_on_resource");
        if (registration.scope_status !== "active") reject("scope_not_active");
        const existing = await tx.query<{ id: string; valid_until: Date | null }>(
          `SELECT id, valid_until FROM oauth_native_human_grants
           WHERE user_id = $1 AND oauth_resource_id = $2 AND oauth_scope_id = $3 AND status = 'active'
           FOR UPDATE`, [input.userId, input.resourceId, registration.id]);
        if (existing.rows[0]) {
          if (!existing.rows[0].valid_until || existing.rows[0].valid_until > now) reject("native_grant_already_active");
          await tx.query(`UPDATE oauth_native_human_grants SET status = 'expired', updated_at = $2 WHERE id = $1`,
            [existing.rows[0].id, now]);
        }
        const inserted = await tx.query(`INSERT INTO oauth_native_human_grants
          (oauth_resource_id, oauth_scope_id, user_id, status, valid_from, valid_until, created_by_user_id)
          VALUES ($1, $2, $3, 'active', $4, $5, $6)
          RETURNING id, oauth_resource_id AS resource_id, oauth_scope_id, user_id, status,
            valid_from, valid_until, created_at`,
        [input.resourceId, registration.id, input.userId, input.validFrom, input.validUntil, ctx.actor.userId]);
        created.push({ ...inserted.rows[0], scope });
      }
      await writeAudit(tx, ctx, "oauth.native_grant.changed", {
        action: "created", outcome: "success", oauth_resource_id: input.resourceId, user_id: input.userId,
        scopes: [...input.scopes].sort(), valid_from: input.validFrom.toISOString(),
        valid_until: input.validUntil?.toISOString() ?? null
      });
      return { grants: created };
    });
  }

  async bulkNativeGrants(input: OAuthAdminBulkGrantInput, commit: boolean, ctx?: OAuthAdminAuditContext) {
    return this.db.transaction(async (tx) => {
      if (!commit) await tx.query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY");
      const resource = await tx.query<{ id: string; entitlement_mode: string; display_name: string; status: string }>(
        `SELECT id, entitlement_mode, display_name, status FROM oauth_resources WHERE id = $1 ${commit ? "FOR SHARE" : ""}`, [input.resourceId]);
      if (!resource.rows[0]) reject("resource_not_found");
      if (resource.rows[0].entitlement_mode !== "native") reject("native_resource_required");
      const users = await tx.query<{ id: string; email: string; display_name: string | null; status: string }>(
        `SELECT id, email, display_name, status FROM users
         WHERE id = ANY($1::uuid[]) OR lower(email::text) = ANY($2::text[])
         ORDER BY id ${commit ? "FOR UPDATE" : ""}`,
        [input.userIds, input.emails]);
      const userById = new Map(users.rows.map((row) => [row.id, row]));
      const userByEmail = new Map(users.rows.map((row) => [row.email.toLowerCase(), row]));
      const registrations = await tx.query<{ id: string; scope: string; scope_status: string; registration_status: string }>(
        `SELECT s.id, s.scope, s.status AS scope_status, rs.status AS registration_status
         FROM oauth_scopes s JOIN oauth_resource_scopes rs ON rs.oauth_scope_id = s.id
         WHERE rs.oauth_resource_id = $1 AND s.scope = ANY($2::text[])
         ORDER BY s.scope ${commit ? "FOR SHARE OF s, rs" : ""}`, [input.resourceId, input.scopes]);
      const scopeByName = new Map(registrations.rows.map((row) => [row.scope, row]));
      const existing = await tx.query<{ id: string; user_id: string; oauth_scope_id: string; valid_from: Date; valid_until: Date | null }>(
        `SELECT id, user_id, oauth_scope_id, valid_from, valid_until FROM oauth_native_human_grants
         WHERE oauth_resource_id = $1 AND status = 'active'
           AND user_id = ANY($2::uuid[]) AND oauth_scope_id = ANY($3::uuid[])
         ORDER BY user_id, oauth_scope_id ${commit ? "FOR UPDATE" : ""}`,
        [users.rows.map((row) => row.id), registrations.rows.map((row) => row.id)]);
      const clock = await tx.query<{ current_time: Date }>(`SELECT clock_timestamp() AS current_time`);
      const now = clock.rows[0].current_time;
      const validFrom = input.validFrom ?? now;
      if (input.validUntil && input.validUntil <= validFrom) reject("grant_validity_invalid");
      const existingByPair = new Map(existing.rows.map((row) => [`${row.user_id}:${row.oauth_scope_id}`, row]));
      const identities = [...input.userIds.map((value) => ({ type: "id", value })), ...input.emails.map((value) => ({ type: "email", value }))];
      const seenUsers = new Set<string>();
      const rows = identities.flatMap((identity) => {
        const user = identity.type === "id" ? userById.get(identity.value) : userByEmail.get(identity.value);
        const duplicate = !!user && seenUsers.has(user.id);
        if (user) seenUsers.add(user.id);
        return input.scopes.map((scope) => {
          const registered = scopeByName.get(scope);
          const old = user && registered ? existingByPair.get(`${user.id}:${registered.id}`) : undefined;
          let operation = "create";
          if (!user || user.status !== "active") operation = "user_not_found_or_inactive";
          else if (duplicate) operation = "error";
          else if (!registered || registered.registration_status !== "active") operation = "scope_not_registered";
          else if (registered.scope_status !== "active") operation = "scope_inactive";
          else if (old && old.valid_until && old.valid_until <= now) operation = "elapsed_active_will_expire_then_regrant";
          else if (old && old.valid_from <= now) operation = resource.rows[0].status === "active"
            ? "already_effective" : "already_active_not_effective";
          else if (old) operation = "error";
          return { user_id: user?.id ?? null, user_email: user?.email ?? (identity.type === "email" ? identity.value : null),
            user_display_name: user?.display_name ?? null, scope, resource_id: input.resourceId,
            operation, reason: duplicate ? "duplicate_user_input" : operation, existing_grant_id: old?.id ?? null,
            scope_id: registered?.id ?? null };
        });
      });
      const summary = { total: rows.length, create: rows.filter((r) => r.operation === "create").length,
        already_effective: rows.filter((r) => r.operation === "already_effective").length,
        already_active_not_effective: rows.filter((r) => r.operation === "already_active_not_effective").length,
        regrant: rows.filter((r) => r.operation === "elapsed_active_will_expire_then_regrant").length,
        error: rows.filter((r) => !["create", "already_effective", "already_active_not_effective", "elapsed_active_will_expire_then_regrant"].includes(r.operation)).length };
      if (!commit) return { rows, summary };
      if (!ctx || summary.error) reject("bulk_native_grant_validation_failed");
      const changed: string[] = [];
      const mutations: Array<{ id: string; userId: string; scope: string }> = [];
      for (const row of rows) {
        if (["already_effective", "already_active_not_effective"].includes(row.operation)) continue;
        if (row.operation === "elapsed_active_will_expire_then_regrant") await tx.query(
          `UPDATE oauth_native_human_grants SET status = 'expired', updated_at = $2 WHERE id = $1`, [row.existing_grant_id, now]);
        const inserted = await tx.query<{ id: string }>(`INSERT INTO oauth_native_human_grants
          (oauth_resource_id, oauth_scope_id, user_id, status, valid_from, valid_until, created_by_user_id)
          VALUES ($1, $2, $3, 'active', $4, $5, $6) RETURNING id`,
        [input.resourceId, row.scope_id, row.user_id, validFrom, input.validUntil, ctx.actor.userId]);
        changed.push(inserted.rows[0].id);
        mutations.push({ id: inserted.rows[0].id, userId: row.user_id!, scope: row.scope });
      }
      for (const userId of [...new Set(mutations.map((row) => row.userId))].sort()) {
        const userMutations = mutations.filter((row) => row.userId === userId);
        await writeAudit(tx, ctx, "oauth.native_grant.changed", { action: "created", batch: true,
          oauth_resource_id: input.resourceId, user_id: userId, scopes: userMutations.map((row) => row.scope),
          grant_ids: userMutations.map((row) => row.id), valid_from: validFrom.toISOString(),
          valid_until: input.validUntil?.toISOString() ?? null });
      }
      if (changed.length) await writeAudit(tx, ctx, "oauth.native_grant.bulk_changed", {
        action: "created", oauth_resource_id: input.resourceId, count: changed.length,
        grant_ids: changed, valid_from: validFrom.toISOString(), valid_until: input.validUntil?.toISOString() ?? null
      });
      return { rows, summary, committed: changed.length };
    });
  }

  async bulkRevokeNativeGrants(ids: string[], commit: boolean, ctx?: OAuthAdminAuditContext) {
    return this.db.transaction(async (tx) => {
      if (!commit) await tx.query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY");
      const found = await tx.query<{ id: string; status: string; user_id: string; user_email: string | null;
        scope: string; resource_id: string; resource_display_name: string }>(
        `SELECT g.id, g.status, g.user_id, u.email AS user_email, s.scope,
           g.oauth_resource_id AS resource_id, r.display_name AS resource_display_name
         FROM oauth_native_human_grants g JOIN oauth_scopes s ON s.id = g.oauth_scope_id
         JOIN oauth_resources r ON r.id = g.oauth_resource_id LEFT JOIN users u ON u.id = g.user_id
         WHERE g.id = ANY($1::uuid[]) ORDER BY g.id ${commit ? "FOR UPDATE OF g" : ""}`, [ids]);
      const byId = new Map(found.rows.map((row) => [row.id, row]));
      const rows = ids.map((id) => {
        const current = byId.get(id);
        return { grant_id: id, user_id: current?.user_id ?? null, user_email: current?.user_email ?? null,
          scope: current?.scope ?? null, resource_id: current?.resource_id ?? null,
          resource_display_name: current?.resource_display_name ?? null, current_status: current?.status ?? null,
          operation: !current ? "error" : current.status === "active" ? "revoke" : "skip" };
      });
      if (!commit) return { rows, summary: { total: rows.length, revoke: rows.filter((r) => r.operation === "revoke").length,
        skip: rows.filter((r) => r.operation === "skip").length, error: rows.filter((r) => r.operation === "error").length } };
      if (!ctx || rows.some((r) => r.operation === "error")) reject("bulk_revoke_invalid");
      const changed = rows.filter((row) => row.operation === "revoke").map((row) => row.grant_id);
      for (const id of changed) {
        await tx.query(`UPDATE oauth_native_human_grants SET status = 'revoked',
          revoked_at = GREATEST(now(), created_at), revoked_by_user_id = $2, updated_at = now() WHERE id = $1`,
        [id, ctx.actor.userId]);
        const row = rows.find((item) => item.grant_id === id)!;
        await writeAudit(tx, ctx, "oauth.native_grant.changed", { action: "revoked", batch: true,
          native_grant_id: id, oauth_resource_id: row.resource_id, user_id: row.user_id, scope: row.scope });
      }
      if (changed.length) await writeAudit(tx, ctx, "oauth.native_grant.bulk_changed", {
        action: "revoked", count: changed.length, grant_ids: changed
      });
      return { rows, committed: changed.length };
    });
  }

  async revokeNativeGrant(id: string, ctx: OAuthAdminAuditContext) {
    return this.db.transaction(async (tx) => {
      const grant = await tx.query<{ id: string; status: string; oauth_resource_id: string; user_id: string; scope: string }>(
        `SELECT g.id, g.status, g.oauth_resource_id, g.user_id, s.scope
         FROM oauth_native_human_grants g JOIN oauth_scopes s ON s.id = g.oauth_scope_id
         WHERE g.id = $1 FOR UPDATE OF g`, [id]);
      if (!grant.rows[0]) reject("native_grant_not_found");
      if (grant.rows[0].status !== "active") reject("native_grant_terminal");
      const result = await tx.query(`UPDATE oauth_native_human_grants SET status = 'revoked',
        revoked_at = GREATEST(now(), created_at), revoked_by_user_id = $2, updated_at = now()
        WHERE id = $1 RETURNING id, status, revoked_at, revoked_by_user_id, updated_at`,
      [id, ctx.actor.userId]);
      await writeAudit(tx, ctx, "oauth.native_grant.changed", {
        action: "revoked", outcome: "success", native_grant_id: id,
        oauth_resource_id: grant.rows[0].oauth_resource_id, user_id: grant.rows[0].user_id,
        scope: grant.rows[0].scope
      });
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
