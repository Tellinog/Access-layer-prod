import { readFileSync, readdirSync } from "node:fs";
import { resolve } from "node:path";
import { randomUUID } from "node:crypto";
import pg, { type QueryResultRow } from "pg";
import { describe, expect, it } from "vitest";
import type { Db } from "../src/db.js";
import type { Config } from "../src/types.js";
import { OAuthAdminService } from "../src/oauth/admin-service.js";
import { OAuthAdminRepository } from "../src/oauth/admin-repository.js";
import type { OAuthAdminAuditContext } from "../src/oauth/admin-types.js";

const disposableUrl = process.env.OAUTH_NATIVE_DISPOSABLE_PG_URL;
const confirmed = process.env.OAUTH_NATIVE_DISPOSABLE_PG_CONFIRM === "yes";

describe.skipIf(!disposableUrl || !confirmed)("Phase 9A.3 Admin on disposable PostgreSQL 16", () => {
  it("creates both resource modes and manages exact linked grants with terminal lifecycle and audit", async () => {
    const target = new URL(disposableUrl!);
    expect(["127.0.0.1", "localhost", "::1"]).toContain(target.hostname);
    expect(target.pathname).toMatch(/test|step4b/i);
    const client = new pg.Client({ connectionString: disposableUrl });
    await client.connect();
    const schema = `oauth_admin_native_test_${randomUUID().replaceAll("-", "")}`;
    const db: Db = {
      query: <T extends QueryResultRow = QueryResultRow>(sql: string, params: unknown[] = []) => client.query<T>(sql, params),
      transaction: async <T>(fn: (tx: Db) => Promise<T>) => {
        await client.query("BEGIN");
        try { const value = await fn(db); await client.query("COMMIT"); return value; }
        catch (error) { await client.query("ROLLBACK"); throw error; }
      },
      close: async () => undefined
    };
    try {
      const version = await client.query<{ server_version_num: string }>("SHOW server_version_num");
      expect(Number(version.rows[0].server_version_num)).toBeGreaterThanOrEqual(160000);
      expect(Number(version.rows[0].server_version_num)).toBeLessThan(170000);
      await client.query(`CREATE SCHEMA ${schema}`);
      await client.query(`SET search_path TO ${schema}, public`);
      for (const name of readdirSync(resolve(import.meta.dirname, "../migrations")).filter((file) => file.endsWith(".sql")).sort()) {
        await client.query(readFileSync(resolve(import.meta.dirname, "../migrations", name), "utf8"));
      }
      const actorId = randomUUID();
      const userId = randomUUID();
      const inactiveId = randomUUID();
      await client.query(`INSERT INTO users (id, google_sub, email, email_normalized, email_verified, hd, display_name, status)
        VALUES ($1,'synthetic-admin-sub','admin@example.test','admin@example.test',true,'example.test','Admin','active'),
               ($2,'synthetic-user-sub','user@example.test','user@example.test',true,'example.test','Synthetic User','active'),
               ($3,'synthetic-inactive-sub','inactive@example.test','inactive@example.test',true,'example.test','Inactive','disabled')`,
      [actorId, userId, inactiveId]);
      await client.query(`INSERT INTO tools (slug, display_name, status) VALUES ('synthetic-legacy', 'Synthetic Legacy', 'active')`);
      await client.query(`INSERT INTO tool_permissions (tool_id, permission_key)
        SELECT id, 'synthetic:records:read' FROM tools WHERE slug = 'synthetic-legacy'`);
      const actor: OAuthAdminAuditContext = {
        actor: { userId: actorId, googleSub: "synthetic-admin-sub", email: "admin@example.test", hd: "example.test",
          role: "platform_admin", permissions: ["admin:oauth:read", "admin:oauth:write"], assignedToolIds: [] },
        correlationId: "corr_synthetic_native_admin", requestIpHash: null, userAgentHash: null
      };
      const repository = new OAuthAdminRepository(db);
      const service = new OAuthAdminService({ repository, config: {
        oauthCredentialSecretPepper: "synthetic-oauth-pepper", toolClientSecretPepper: "different-legacy-pepper"
      } as Config, now: () => new Date() });
      const scopeNames = ["synthetic:records:read", "synthetic:records:write"];
      for (const scope of scopeNames) await service.createScope({ scope, description: scope }, actor);
      const common = { displayName: "Native test", ownerTeam: "test", ownerContact: null, status: "active" as const,
        protectedResourceMetadataUrl: "https://synthetic-native.example.test/.well-known/oauth-protected-resource" };
      const native = await service.createResource({ ...common, resourceId: "https://synthetic-native.example.test/v1",
        entitlementMode: "native", scopes: scopeNames }, actor);
      const nativeId = native.resource.id as string;
      expect(native.resource.entitlement_mode).toBe("native");
      expect((await client.query(`SELECT count(*)::int AS n FROM oauth_resource_entitlement_bindings WHERE oauth_resource_id = $1`, [nativeId])).rows[0].n).toBe(0);
      expect((await client.query(`SELECT count(*)::int AS n FROM oauth_resource_scopes WHERE oauth_resource_id = $1 AND legacy_permission_key IS NULL`, [nativeId])).rows[0].n).toBe(2);
      const nativeScopeId = (await client.query<{ id: string }>(`SELECT id FROM oauth_scopes WHERE scope = $1`, [scopeNames[0]])).rows[0].id;
      await expect(service.setResourceScope(nativeId, nativeScopeId,
        { legacyPermissionKey: scopeNames[0], status: "active" }, actor))
        .rejects.toMatchObject({ reason: "native_scope_legacy_permission_forbidden" });
      expect((await service.setResourceScope(nativeId, nativeScopeId,
        { legacyPermissionKey: null, status: "active" }, actor)).legacy_permission_key).toBeNull();
      const tools = await service.legacyTools();
      expect(tools).toEqual(expect.arrayContaining([expect.objectContaining({ slug: "synthetic-legacy", registered_permission_keys: ["synthetic:records:read"] })]));
      const users = await service.searchUsers("user@example.test");
      expect(users).toHaveLength(1);
      expect(Object.keys(users[0]).sort()).toEqual(["display_name", "email", "id", "last_seen_at", "status"]);
      const legacy = await service.createResource({ ...common, resourceId: "https://synthetic-legacy.example.test/v1",
        protectedResourceMetadataUrl: "https://synthetic-legacy.example.test/.well-known/oauth-protected-resource",
        legacyToolSlug: "synthetic-legacy", scopeMappings: [{ scope: scopeNames[0], legacyPermissionKey: scopeNames[0] }] }, actor);
      expect(legacy.resource.entitlement_mode).toBe("legacy_bridge");
      await expect(service.createNativeGrants({ resourceId: legacy.resource.id as string, userId, scopes: [scopeNames[0]], validFrom: null, validUntil: null }, actor))
        .rejects.toMatchObject({ reason: "native_resource_required" });
      await expect(service.createNativeGrants({ resourceId: nativeId, userId: inactiveId, scopes: [scopeNames[0]], validFrom: null, validUntil: null }, actor))
        .rejects.toMatchObject({ reason: "user_not_found_or_inactive" });
      await expect(service.createNativeGrants({ resourceId: nativeId, userId, scopes: ["synthetic:other:read"], validFrom: null, validUntil: null }, actor))
        .rejects.toMatchObject({ reason: "scope_not_registered_on_resource" });
      const granted = await service.createNativeGrants({ resourceId: nativeId, userId, scopes: scopeNames, validFrom: null, validUntil: null }, actor);
      expect(granted.grants).toHaveLength(2);
      expect((await service.listNativeGrants(nativeId)).filter((row) => row.effective)).toHaveLength(2);
      await client.query(`UPDATE users SET status = 'disabled' WHERE id = $1`, [userId]);
      expect((await service.listNativeGrants(nativeId)).filter((row) => row.effective)).toHaveLength(0);
      await client.query(`UPDATE users SET status = 'active' WHERE id = $1`, [userId]);
      await expect(service.createNativeGrants({ resourceId: nativeId, userId, scopes: [scopeNames[0]], validFrom: null, validUntil: null }, actor))
        .rejects.toMatchObject({ reason: "native_grant_already_active" });
      const firstId = (granted.grants[0] as { id: string }).id;
      const revoked = await service.revokeNativeGrant(firstId, actor);
      expect(revoked).toMatchObject({ status: "revoked", revoked_by_user_id: actorId });
      expect(revoked.revoked_at).toBeTruthy();
      await expect(service.revokeNativeGrant(firstId, actor)).rejects.toMatchObject({ reason: "native_grant_terminal" });
      const replacement = await service.createNativeGrants({ resourceId: nativeId, userId, scopes: [scopeNames[0]], validFrom: null, validUntil: null }, actor);
      expect((replacement.grants[0] as { id: string }).id).not.toBe(firstId);
      await client.query(`UPDATE oauth_native_human_grants SET valid_until = now() - interval '1 second', valid_from = now() - interval '2 minutes'
        WHERE id = $1`, [(replacement.grants[0] as { id: string }).id]);
      const afterExpiry = await service.createNativeGrants({ resourceId: nativeId, userId, scopes: [scopeNames[0]], validFrom: null, validUntil: null }, actor);
      expect(afterExpiry.grants).toHaveLength(1);
      expect((await client.query(`SELECT status FROM oauth_native_human_grants WHERE id = $1`, [(replacement.grants[0] as { id: string }).id])).rows[0].status).toBe("expired");
      const clientCreated = await service.createClient({ clientId: "synthetic-native-client", clientName: "Synthetic native client",
        ownerTeam: "test", ownerContact: null, status: "active", grantTypes: ["authorization_code", "refresh_token"],
        redirectUris: ["https://synthetic-client.example.test/callback"],
        allowances: scopeNames.map((scope) => ({ resourceId: "https://synthetic-native.example.test/v1", scope })) }, actor);
      expect(clientCreated.client.client_id).toBe("synthetic-native-client");
      expect((await client.query(`SELECT count(*)::int AS n FROM oauth_client_resource_scopes WHERE oauth_client_id = $1`, [clientCreated.client.id])).rows[0].n).toBe(2);
      const audits = await client.query<{ metadata: Record<string, unknown> }>(`SELECT metadata FROM audit_logs WHERE event_type = 'oauth.native_grant.changed'`);
      expect(audits.rows).toHaveLength(4);
      expect(JSON.stringify(audits.rows)).not.toMatch(/synthetic-(?:admin|user)-sub|secret|token/i);
      const scopeBatch = { mode: "create_missing" as const, updateDescriptions: false, reactivateDisabled: false,
        rows: Array.from({ length: 200 }, (_, index) => ({ row: index + 1,
          scope: `bulk-test:area-${String(index + 1).padStart(3, "0")}:read`, description: `Read synthetic area ${index + 1}` })) };
      const scopesBefore = (await client.query(`SELECT count(*)::int AS n FROM oauth_scopes`)).rows[0].n;
      expect(await service.bulkScopes(scopeBatch, false)).toMatchObject({ summary: { create: 200, error: 0 } });
      expect((await client.query(`SELECT count(*)::int AS n FROM oauth_scopes`)).rows[0].n).toBe(scopesBefore);
      expect(await service.bulkScopes(scopeBatch, true, actor)).toMatchObject({ committed: 200 });
      expect(await service.bulkScopes(scopeBatch, true, actor)).toMatchObject({ committed: 0, summary: { skip: 200 } });
      const lifecycleScope = scopeBatch.rows[199].scope;
      await service.bulkScopeStatus([lifecycleScope], "disabled", true, actor);
      const lifecycleBatch = { ...scopeBatch, rows: [scopeBatch.rows[199]] };
      expect((await service.bulkScopes(lifecycleBatch, false)).rows[0]).toMatchObject({ operation: "skip", result: "warning" });
      await service.bulkScopes({ ...lifecycleBatch, reactivateDisabled: true }, true, actor);
      expect((await client.query(`SELECT status FROM oauth_scopes WHERE scope = $1`, [lifecycleScope])).rows[0].status).toBe("active");
      const staleBatch = { ...scopeBatch, rows: [{ row: 1, scope: "bulk-test:stale:read", description: "Valid" }] };
      expect(await service.bulkScopes(staleBatch, false)).toMatchObject({ summary: { create: 1 } });
      await service.createScope({ scope: staleBatch.rows[0].scope, description: "Changed concurrently" }, actor);
      expect(await service.bulkScopes(staleBatch, true, actor)).toMatchObject({ committed: 0, summary: { skip: 1 } });
      await client.query(`CREATE FUNCTION reject_second_scope_test() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN IF NEW.scope = 'bulk-test:rollback-second:read' THEN RAISE EXCEPTION 'synthetic mutation failure'; END IF; RETURN NEW; END $$`);
      await client.query(`CREATE TRIGGER reject_second_scope_test BEFORE INSERT ON oauth_scopes FOR EACH ROW EXECUTE FUNCTION reject_second_scope_test()`);
      await expect(service.bulkScopes({ ...scopeBatch, rows: [
        { row: 1, scope: "bulk-test:rollback-first:read", description: "First" },
        { row: 2, scope: "bulk-test:rollback-second:read", description: "Second" }
      ] }, true, actor)).rejects.toThrow();
      expect((await client.query(`SELECT count(*)::int AS n FROM oauth_scopes WHERE scope LIKE 'bulk-test:rollback-%'`)).rows[0].n).toBe(0);
      await client.query(`DROP TRIGGER reject_second_scope_test ON oauth_scopes`);
      const extraScopes = scopeBatch.rows.slice(0, 3).map((row) => row.scope);
      const registrationOps = extraScopes.map((scope) => ({ scope, action: "activate" as const }));
      expect(await service.bulkNativeResourceScopes(nativeId, registrationOps, false)).toMatchObject({ summary: { change: 3 } });
      expect(await service.bulkNativeResourceScopes(nativeId, registrationOps, true, actor)).toMatchObject({ committed: 3 });
      expect(await service.bulkNativeResourceScopes(nativeId, registrationOps, true, actor)).toMatchObject({ committed: 0 });
      expect(await service.bulkNativeResourceScopes(nativeId, [{ scope: extraScopes[2], action: "disable" }], true, actor))
        .toMatchObject({ committed: 1 });
      expect((await client.query(`SELECT count(*)::int AS n FROM oauth_resource_scopes
        WHERE oauth_resource_id = $1 AND legacy_permission_key IS NOT NULL`, [nativeId])).rows[0].n).toBe(0);
      await expect(service.bulkNativeResourceScopes(legacy.resource.id as string, registrationOps, true, actor))
        .rejects.toMatchObject({ reason: "native_resource_required" });
      const desiredAllowances = [scopeNames[0], extraScopes[0]].map((scope) => ({ resourceId: "https://synthetic-native.example.test/v1", scope }));
      const allowancePlan = await service.previewCommitAllowances(clientCreated.client.id as string, desiredAllowances, null, false);
      expect(allowancePlan).toMatchObject({ summary: { add: 1, remove: 1, unchanged: 1 } });
      const expectedAllowances = (allowancePlan.current ?? []).map((row) => ({ resourceId: row.resource_id, scope: row.scope, status: row.status }));
      await service.previewCommitAllowances(clientCreated.client.id as string, desiredAllowances, expectedAllowances, true, actor);
      await expect(service.previewCommitAllowances(clientCreated.client.id as string, desiredAllowances, expectedAllowances, true, actor))
        .rejects.toMatchObject({ reason: "allowance_preview_stale" });
      const redirectPlan = await service.previewCommitRedirectUris(clientCreated.client.id as string,
        ["https://synthetic-client.example.test/new-callback"], null, false);
      expect(redirectPlan.diff.map((row) => row.operation).sort()).toEqual(["add", "remove"]);
      await service.previewCommitRedirectUris(clientCreated.client.id as string, ["https://synthetic-client.example.test/new-callback"],
        redirectPlan.current ?? [], true, actor);
      const grantBatch = { resourceId: nativeId, userIds: [actorId, userId], emails: [],
        scopes: [scopeNames[0], extraScopes[0]], validFrom: null, validUntil: null };
      const grantsBefore = (await client.query(`SELECT count(*)::int AS n FROM oauth_native_human_grants`)).rows[0].n;
      expect(await service.bulkNativeGrants(grantBatch, false)).toMatchObject({ summary: { create: 3, already_effective: 1, error: 0 } });
      expect((await client.query(`SELECT count(*)::int AS n FROM oauth_native_human_grants`)).rows[0].n).toBe(grantsBefore);
      expect(await service.bulkNativeGrants(grantBatch, true, actor)).toMatchObject({ committed: 3 });
      expect(await service.bulkNativeGrants(grantBatch, true, actor)).toMatchObject({ committed: 0, summary: { already_effective: 4 } });
      const emailBatch = { ...grantBatch, userIds: [], emails: ["USER@example.test"] };
      expect((await service.bulkNativeGrants(emailBatch, false)).rows.every((row) => row.user_id === userId)).toBe(true);
      expect(await service.bulkNativeGrants({ ...emailBatch, emails: ["missing@example.test", "inactive@example.test"] }, false))
        .toMatchObject({ summary: { error: 4 } });
      expect(() => service.bulkNativeGrants({ ...grantBatch, userIds: [actorId, actorId] }, false)).toThrow();
      expect(() => service.bulkNativeGrants({ ...grantBatch, scopes: [scopeNames[0], scopeNames[0]] }, false)).toThrow();
      expect(await service.bulkNativeGrants({ ...grantBatch, userIds: [actorId], scopes: [extraScopes[2]] }, false))
        .toMatchObject({ summary: { error: 1 } });
      await service.bulkScopeStatus([extraScopes[1]], "disabled", true, actor);
      expect((await service.bulkNativeGrants({ ...grantBatch, userIds: [actorId], scopes: [extraScopes[1]] }, false)).rows[0].operation).toBe("scope_inactive");
      await service.bulkScopeStatus([extraScopes[1]], "active", true, actor);
      const atomicGrantCount = (await client.query(`SELECT count(*)::int AS n FROM oauth_native_human_grants`)).rows[0].n;
      await expect(service.bulkNativeGrants({ ...grantBatch, userIds: [actorId], scopes: [extraScopes[1], extraScopes[2]] }, true, actor))
        .rejects.toMatchObject({ reason: "bulk_native_grant_validation_failed" });
      expect((await client.query(`SELECT count(*)::int AS n FROM oauth_native_human_grants`)).rows[0].n).toBe(atomicGrantCount);
      const actorGrant = (await client.query<{ id: string }>(`SELECT g.id FROM oauth_native_human_grants g JOIN oauth_scopes s ON s.id = g.oauth_scope_id
        WHERE g.user_id = $1 AND g.oauth_resource_id = $2 AND s.scope = $3 AND g.status = 'active'`, [actorId, nativeId, scopeNames[0]])).rows[0].id;
      await client.query(`UPDATE oauth_native_human_grants SET valid_from = now() - interval '2 minutes',
        valid_until = now() - interval '1 second' WHERE id = $1`, [actorGrant]);
      expect(await service.bulkNativeGrants({ ...grantBatch, userIds: [actorId], scopes: [scopeNames[0]] }, false))
        .toMatchObject({ summary: { regrant: 1 } });
      expect(await service.bulkNativeGrants({ ...grantBatch, userIds: [actorId], scopes: [scopeNames[0]] }, true, actor))
        .toMatchObject({ committed: 1 });
      expect((await client.query(`SELECT status FROM oauth_native_human_grants WHERE id = $1`, [actorGrant])).rows[0].status).toBe("expired");
      expect(await service.bulkRevokeNativeGrants([actorGrant], true, actor)).toMatchObject({ committed: 0 });
      const actorCurrent = (await client.query<{ id: string }>(`SELECT id FROM oauth_native_human_grants
        WHERE user_id = $1 AND oauth_resource_id = $2 AND status = 'active' ORDER BY id`, [actorId, nativeId])).rows.map((row) => row.id);
      expect(await service.bulkRevokeNativeGrants([actorCurrent[0]], false)).toMatchObject({ summary: { revoke: 1 } });
      expect(await service.bulkRevokeNativeGrants([actorCurrent[0]], true, actor)).toMatchObject({ committed: 1 });
      expect(await service.bulkRevokeNativeGrants([actorCurrent[0]], true, actor)).toMatchObject({ committed: 0 });
      expect((await service.listNativeGrants(nativeId, { query: "user@example.test", scope: "", status: "active", effective: "true", offset: 0 }))
        .every((row) => row.user_id === userId && row.effective === true)).toBe(true);
      await client.query(`CREATE FUNCTION reject_native_audit_test() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN IF NEW.event_type = 'oauth.native_grant.changed' THEN RAISE EXCEPTION 'synthetic audit failure'; END IF; RETURN NEW; END $$`);
      await client.query(`CREATE TRIGGER reject_native_audit_test BEFORE INSERT ON audit_logs
        FOR EACH ROW EXECUTE FUNCTION reject_native_audit_test()`);
      const beforeFailure = (await client.query(`SELECT count(*)::int AS n FROM oauth_native_human_grants`)).rows[0].n;
      await expect(service.createNativeGrants({ resourceId: nativeId, userId: actorId, scopes: [extraScopes[1]],
        validFrom: null, validUntil: null }, actor)).rejects.toThrow();
      await expect(service.bulkNativeGrants({ ...grantBatch, userIds: [actorId], scopes: [extraScopes[1]] }, true, actor)).rejects.toThrow();
      await expect(service.bulkRevokeNativeGrants([actorCurrent[1]], true, actor)).rejects.toThrow();
      expect((await client.query(`SELECT status FROM oauth_native_human_grants WHERE id = $1`, [actorCurrent[1]])).rows[0].status).toBe("active");
      expect((await client.query(`SELECT count(*)::int AS n FROM oauth_native_human_grants`)).rows[0].n).toBe(beforeFailure);
      await client.query(`DROP TRIGGER reject_native_audit_test ON audit_logs`);
      await client.query(`CREATE FUNCTION reject_scope_audit_test() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN IF NEW.event_type = 'oauth.scope.changed' THEN RAISE EXCEPTION 'synthetic audit failure'; END IF; RETURN NEW; END $$`);
      await client.query(`CREATE TRIGGER reject_scope_audit_test BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION reject_scope_audit_test()`);
      const failedScope = { ...scopeBatch, rows: [{ row: 1, scope: "bulk-test:failure:read", description: "Synthetic rollback" }] };
      await expect(service.bulkScopes(failedScope, true, actor)).rejects.toThrow();
      expect((await client.query(`SELECT count(*)::int AS n FROM oauth_scopes WHERE scope = 'bulk-test:failure:read'`)).rows[0].n).toBe(0);
    } finally {
      await client.query("RESET search_path");
      await client.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
      await client.end();
    }
  });
});
