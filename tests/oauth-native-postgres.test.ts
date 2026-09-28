import { readFileSync, readdirSync } from "node:fs";
import { resolve } from "node:path";
import { randomUUID } from "node:crypto";
import pg from "pg";
import { describe, expect, it } from "vitest";

// Opt-in only. Never point this at production or a shared database.
const disposableUrl = process.env.OAUTH_NATIVE_DISPOSABLE_PG_URL;
const disposableConfirmed = process.env.OAUTH_NATIVE_DISPOSABLE_PG_CONFIRM === "yes";

describe.skipIf(!disposableUrl || !disposableConfirmed)("Phase 9A.1 disposable PostgreSQL 16 qualification", () => {
  it("applies 001–006 and enforces native/bridge grants and authorization provenance", async () => {
    const parsed = new URL(disposableUrl!);
    expect(["localhost", "127.0.0.1", "::1"]).toContain(parsed.hostname);
    expect(parsed.pathname).toMatch(/test|^\/access_layer_step4b_(?:source|restore)_[a-f0-9]{12}$/i);
    const client = new pg.Client({ connectionString: disposableUrl });
    await client.connect();
    const schema = `oauth_native_test_${randomUUID().replaceAll("-", "")}`;
    try {
      const version = await client.query<{ server_version_num: string }>("SHOW server_version_num");
      expect(Number(version.rows[0].server_version_num)).toBeGreaterThanOrEqual(160000);
      expect(Number(version.rows[0].server_version_num)).toBeLessThan(170000);
      await client.query(`CREATE SCHEMA ${schema}`);
      await client.query(`SET search_path TO ${schema}, public`);
      const migrations = readdirSync(resolve(import.meta.dirname, "../migrations")).filter((name) => name.endsWith(".sql")).sort();
      expect(migrations).toHaveLength(6);
      for (const migration of migrations) {
        await client.query(readFileSync(resolve(import.meta.dirname, "../migrations", migration), "utf8"));
      }

      const reject = async (sql: string, params: unknown[] = []) => {
        await client.query("SAVEPOINT invalid_case");
        try {
          await client.query(sql, params);
          throw new Error("Expected PostgreSQL constraint failure");
        } catch (error) {
          if ((error as Error).message === "Expected PostgreSQL constraint failure") throw error;
        } finally {
          await client.query("ROLLBACK TO SAVEPOINT invalid_case");
          await client.query("RELEASE SAVEPOINT invalid_case");
        }
      };
      await client.query("BEGIN");
      const user = (await client.query<{ id: string }>(`INSERT INTO users
        (google_sub, email, email_normalized, email_verified, hd)
        VALUES ('synthetic-sub', 'user@example.test', 'user@example.test', true, 'example.test') RETURNING id`)).rows[0].id;
      const tool = (await client.query<{ id: string }>(`INSERT INTO tools (slug, display_name)
        VALUES ('synthetic-tool', 'Synthetic') RETURNING id`)).rows[0].id;
      const legacyGrant = (await client.query<{ id: string }>(`INSERT INTO authorization_grants
        (tool_id, user_id, role) VALUES ($1, $2, 'user') RETURNING id`, [tool, user])).rows[0].id;
      const scope = (await client.query<{ id: string }>(`INSERT INTO oauth_scopes (scope, description)
        VALUES ('synthetic:records:read', 'Read') RETURNING id`)).rows[0].id;
      const otherScope = (await client.query<{ id: string }>(`INSERT INTO oauth_scopes (scope, description)
        VALUES ('synthetic:records:write', 'Write') RETURNING id`)).rows[0].id;
      const resourceSql = `INSERT INTO oauth_resources
        (resource_id, display_name, owner_team, protected_resource_metadata_url, entitlement_mode)
        VALUES ($1, 'Synthetic', 'test-team', 'https://resource.example.test/.well-known/oauth-protected-resource', $2)
        RETURNING id, entitlement_mode`;
      const legacyResource = (await client.query<{ id: string; entitlement_mode: string }>(`INSERT INTO oauth_resources
        (resource_id, display_name, owner_team, protected_resource_metadata_url)
        VALUES ('https://legacy.example.test/api', 'Legacy', 'test-team', 'https://legacy.example.test/metadata')
        RETURNING id, entitlement_mode`)).rows[0];
      expect(legacyResource.entitlement_mode).toBe("legacy_bridge");
      const nativeResource = (await client.query<{ id: string }>(resourceSql,
        ["https://native.example.test/api", "native"])).rows[0].id;
      await reject(`UPDATE oauth_resources SET entitlement_mode = 'native' WHERE id = $1`, [legacyResource.id]);
      await client.query(`INSERT INTO oauth_resource_entitlement_bindings (oauth_resource_id, legacy_tool_id)
        VALUES ($1, $2)`, [legacyResource.id, tool]);
      await reject(`INSERT INTO oauth_resource_entitlement_bindings (oauth_resource_id, legacy_tool_id)
        VALUES ($1, $2)`, [nativeResource, tool]);
      await reject(`INSERT INTO oauth_resource_scopes (oauth_resource_id, oauth_scope_id)
        VALUES ($1, $2)`, [legacyResource.id, scope]);
      await client.query(`INSERT INTO oauth_resource_scopes (oauth_resource_id, oauth_scope_id, legacy_permission_key)
        VALUES ($1, $2, 'synthetic:records:read')`, [legacyResource.id, scope]);
      await reject(`INSERT INTO oauth_resource_scopes (oauth_resource_id, oauth_scope_id, legacy_permission_key)
        VALUES ($1, $2, 'synthetic:records:read')`, [nativeResource, scope]);
      await client.query(`INSERT INTO oauth_resource_scopes (oauth_resource_id, oauth_scope_id)
        VALUES ($1, $2)`, [nativeResource, scope]);
      await client.query(`INSERT INTO oauth_resource_scopes (oauth_resource_id, oauth_scope_id)
        VALUES ($1, $2)`, [nativeResource, otherScope]);
      await reject(`INSERT INTO oauth_native_human_grants (oauth_resource_id, oauth_scope_id, user_id, status)
        VALUES ($1, $2, $3, 'active')`, [legacyResource.id, scope, user]);
      const unregisteredScope = (await client.query<{ id: string }>(`INSERT INTO oauth_scopes (scope, description)
        VALUES ('synthetic:records:delete', 'Delete') RETURNING id`)).rows[0].id;
      await reject(`INSERT INTO oauth_native_human_grants (oauth_resource_id, oauth_scope_id, user_id, status)
        VALUES ($1, $2, $3, 'active')`, [nativeResource, unregisteredScope, user]);
      await reject(`INSERT INTO oauth_native_human_grants (oauth_resource_id, oauth_scope_id, status)
        VALUES ($1, $2, 'active')`, [nativeResource, scope]);
      await reject(`INSERT INTO oauth_native_human_grants (oauth_resource_id, oauth_scope_id, user_id, status, valid_from, valid_until)
        VALUES ($1, $2, $3, 'active', now(), now())`, [nativeResource, scope, user]);
      const nativeGrant = (await client.query<{ id: string }>(`INSERT INTO oauth_native_human_grants
        (oauth_resource_id, oauth_scope_id, user_id, status)
        VALUES ($1, $2, $3, 'active') RETURNING id`, [nativeResource, scope, user])).rows[0].id;
      const nativeGrant2 = (await client.query<{ id: string }>(`INSERT INTO oauth_native_human_grants
        (oauth_resource_id, oauth_scope_id, user_id, status)
        VALUES ($1, $2, $3, 'active') RETURNING id`, [nativeResource, otherScope, user])).rows[0].id;
      await reject(`INSERT INTO oauth_native_human_grants (oauth_resource_id, oauth_scope_id, user_id, status)
        VALUES ($1, $2, $3, 'active')`, [nativeResource, scope, user]);
      await reject(`INSERT INTO oauth_native_human_grants (oauth_resource_id, oauth_scope_id, email_normalized, status)
        VALUES ($1, $2, 'PENDING@example.test', 'pending_user_link')`, [nativeResource, scope]);
      await client.query(`INSERT INTO oauth_native_human_grants (oauth_resource_id, oauth_scope_id, email_normalized)
        VALUES ($1, $2, 'pending@example.test')`, [nativeResource, scope]);
      await reject(`INSERT INTO oauth_native_human_grants (oauth_resource_id, oauth_scope_id, email_normalized)
        VALUES ($1, $2, 'pending@example.test')`, [nativeResource, scope]);
      await reject(`DELETE FROM users WHERE id = $1`, [user]);
      await reject(`DELETE FROM oauth_resource_scopes WHERE oauth_resource_id = $1 AND oauth_scope_id = $2`, [nativeResource, scope]);
      await reject(`UPDATE oauth_native_human_grants SET status = 'revoked' WHERE id = $1`, [nativeGrant]);
      await client.query(`UPDATE oauth_native_human_grants SET status = 'revoked', revoked_at = now(),
        revoked_by_user_id = $2 WHERE id = $1`, [nativeGrant, user]);
      await reject(`UPDATE oauth_native_human_grants SET status = 'active', revoked_at = NULL,
        revoked_by_user_id = NULL WHERE id = $1`, [nativeGrant]);
      const activeReplacement = (await client.query<{ id: string }>(`INSERT INTO oauth_native_human_grants
        (oauth_resource_id, oauth_scope_id, user_id, status)
        VALUES ($1, $2, $3, 'active') RETURNING id`, [nativeResource, scope, user])).rows[0].id;

      const oauthClient = (await client.query<{ id: string }>(`INSERT INTO oauth_clients
        (client_id, client_name, client_type, token_endpoint_auth_method, grant_types, owner_team)
        VALUES ('synthetic-bff', 'Synthetic BFF', 'confidential', 'client_secret_basic',
          ARRAY['authorization_code']::text[], 'test-team') RETURNING id`)).rows[0].id;
      const txSql = `INSERT INTO oauth_authorization_transactions
        (oauth_client_id, oauth_resource_id, redirect_uri, requested_scopes, code_challenge,
         protected_downstream_state, upstream_state_hash, upstream_nonce_hash, correlation_id, expires_at)
        VALUES ($1, $2, 'https://client.example.test/callback', $7::text[],
          $3, '{}'::jsonb, $4, $5, $6, now() + interval '600 seconds') RETURNING id`;
      const makeTransaction = async (resource: string, scopes = ["synthetic:records:read"]) => (await client.query<{ id: string }>(txSql,
        [oauthClient, resource, "a".repeat(43), randomUUID().replaceAll("-", "").padEnd(43, "a"),
          randomUUID().replaceAll("-", "").padEnd(43, "b"), randomUUID(), scopes])).rows[0].id;
      const legacyTx = await makeTransaction(legacyResource.id);
      const nativeTx = await makeTransaction(nativeResource, ["synthetic:records:read", "synthetic:records:write"]);
      const authorizationSql = `INSERT INTO oauth_authorizations
        (oauth_authorization_transaction_id, user_id, oauth_client_id, oauth_resource_id,
         granted_scopes, legacy_authorization_grant_id, correlation_id)
        VALUES ($1, $2, $3, $4, $7::text[], $5, $6)
        RETURNING id, entitlement_source`;
      const legacyAuth = await client.query<{ id: string; entitlement_source: string }>(authorizationSql,
        [legacyTx, user, oauthClient, legacyResource.id, legacyGrant, randomUUID(), ["synthetic:records:read"]]);
      expect(legacyAuth.rows[0].entitlement_source).toBe("legacy_bridge");
      await reject(authorizationSql, [nativeTx, user, oauthClient, nativeResource, legacyGrant, randomUUID(), ["synthetic:records:read"]]);
      const legacyMismatchTx = await makeTransaction(legacyResource.id);
      const nativeAuthorizationSql = authorizationSql.replace(
        "legacy_authorization_grant_id, correlation_id)", "legacy_authorization_grant_id, correlation_id, entitlement_source)"
      ).replace("$5, $6)", "$5, $6, 'native')");
      await reject(nativeAuthorizationSql, [legacyMismatchTx, user, oauthClient, legacyResource.id, null, randomUUID(), ["synthetic:records:read"]]);
      const nativeAuth = await client.query<{ id: string; entitlement_source: string }>(nativeAuthorizationSql,
        [nativeTx, user, oauthClient, nativeResource, null, randomUUID(), ["synthetic:records:read", "synthetic:records:write"]]);
      expect(nativeAuth.rows[0].entitlement_source).toBe("native");
      const provenanceSql = `INSERT INTO oauth_authorization_native_grants
        (oauth_authorization_id, oauth_native_human_grant_id) VALUES ($1, $2)`;
      await client.query(provenanceSql, [nativeAuth.rows[0].id, activeReplacement]);
      await client.query(provenanceSql, [nativeAuth.rows[0].id, nativeGrant2]);
      await reject(provenanceSql, [nativeAuth.rows[0].id, activeReplacement]);
      await reject(provenanceSql, [legacyAuth.rows[0].id, activeReplacement]);
      await reject(provenanceSql, [randomUUID(), activeReplacement]);
      await reject(provenanceSql, [nativeAuth.rows[0].id, randomUUID()]);
      const otherUser = (await client.query<{ id: string }>(`INSERT INTO users
        (google_sub, email, email_normalized, email_verified, hd)
        VALUES ('other-synthetic-sub', 'other@example.test', 'other@example.test', true, 'example.test') RETURNING id`)).rows[0].id;
      const otherUserGrant = (await client.query<{ id: string }>(`INSERT INTO oauth_native_human_grants
        (oauth_resource_id, oauth_scope_id, user_id, status)
        VALUES ($1, $2, $3, 'active') RETURNING id`, [nativeResource, scope, otherUser])).rows[0].id;
      await reject(provenanceSql, [nativeAuth.rows[0].id, otherUserGrant]);
      await client.query(`INSERT INTO oauth_resource_scopes (oauth_resource_id, oauth_scope_id)
        VALUES ($1, $2)`, [nativeResource, unregisteredScope]);
      const outOfAuthorizationScopeGrant = (await client.query<{ id: string }>(`INSERT INTO oauth_native_human_grants
        (oauth_resource_id, oauth_scope_id, user_id, status)
        VALUES ($1, $2, $3, 'active') RETURNING id`, [nativeResource, unregisteredScope, user])).rows[0].id;
      await reject(provenanceSql, [nativeAuth.rows[0].id, outOfAuthorizationScopeGrant]);
      const otherNativeResource = (await client.query<{ id: string }>(resourceSql,
        ["https://another-native.example.test/api", "native"])).rows[0].id;
      await client.query(`INSERT INTO oauth_resource_scopes (oauth_resource_id, oauth_scope_id)
        VALUES ($1, $2)`, [otherNativeResource, scope]);
      const otherResourceGrant = (await client.query<{ id: string }>(`INSERT INTO oauth_native_human_grants
        (oauth_resource_id, oauth_scope_id, user_id, status)
        VALUES ($1, $2, $3, 'active') RETURNING id`, [otherNativeResource, scope, user])).rows[0].id;
      await reject(provenanceSql, [nativeAuth.rows[0].id, otherResourceGrant]);
      const secondNativeTx = await makeTransaction(nativeResource);
      const secondNativeAuth = (await client.query<{ id: string }>(nativeAuthorizationSql,
        [secondNativeTx, user, oauthClient, nativeResource, null, randomUUID(), ["synthetic:records:read"]])).rows[0].id;
      await client.query(provenanceSql, [secondNativeAuth, activeReplacement]);
      await reject(`DELETE FROM oauth_native_human_grants WHERE id = $1`, [nativeGrant2]);
      await reject(`DELETE FROM oauth_authorizations WHERE id = $1`, [nativeAuth.rows[0].id]);
    } finally {
      await client.query("ROLLBACK");
      await client.query("RESET search_path");
      await client.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
      await client.end();
    }
  });
});
