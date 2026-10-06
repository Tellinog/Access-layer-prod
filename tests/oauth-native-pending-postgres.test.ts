import { readFileSync, readdirSync } from "node:fs";
import { resolve } from "node:path";
import { randomUUID } from "node:crypto";
import pg, { type QueryResultRow } from "pg";
import { describe, expect, it } from "vitest";
import type { Db } from "../src/db.js";
import type { Config } from "../src/types.js";
import { Repositories } from "../src/repositories.js";
import { OAuthAdminService } from "../src/oauth/admin-service.js";
import { OAuthAdminRepository } from "../src/oauth/admin-repository.js";
import type { OAuthAdminAuditContext } from "../src/oauth/admin-types.js";

const disposableUrl = process.env.OAUTH_NATIVE_DISPOSABLE_PG_URL;
const confirmed = process.env.OAUTH_NATIVE_DISPOSABLE_PG_CONFIRM === "yes";

describe.skipIf(!disposableUrl || !confirmed)("D-054 pending native grants on disposable PostgreSQL 16", () => {
  it("pre-authorizes never-signed-in emails in bulk and links them at the first verified login", async () => {
    const target = new URL(disposableUrl!);
    expect(["127.0.0.1", "localhost", "::1"]).toContain(target.hostname);
    expect(target.pathname).toMatch(/test|step4b/i);
    const client = new pg.Client({ connectionString: disposableUrl });
    await client.connect();
    const schema = `oauth_native_pending_test_${randomUUID().replaceAll("-", "")}`;
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
      await client.query(`CREATE SCHEMA ${schema}`);
      await client.query(`SET search_path TO ${schema}, public`);
      for (const name of readdirSync(resolve(import.meta.dirname, "../migrations")).filter((file) => file.endsWith(".sql")).sort()) {
        await client.query(readFileSync(resolve(import.meta.dirname, "../migrations", name), "utf8"));
      }
      const actorId = randomUUID();
      const knownId = randomUUID();
      await client.query(`INSERT INTO users (id, google_sub, email, email_normalized, email_verified, hd, display_name, status)
        VALUES ($1,'synthetic-admin-sub','admin@example.test','admin@example.test',true,'example.test','Admin','active'),
               ($2,'synthetic-known-sub','known@example.test','known@example.test',true,'example.test','Known','active')`,
      [actorId, knownId]);
      const actor: OAuthAdminAuditContext = {
        actor: { userId: actorId, googleSub: "synthetic-admin-sub", email: "admin@example.test", hd: "example.test",
          role: "platform_admin", permissions: ["admin:oauth:read", "admin:oauth:write"], assignedToolIds: [] },
        correlationId: "corr_synthetic_pending", requestIpHash: null, userAgentHash: null
      };
      const service = new OAuthAdminService({ repository: new OAuthAdminRepository(db), config: {
        oauthCredentialSecretPepper: "synthetic-oauth-pepper", toolClientSecretPepper: "different-legacy-pepper",
        googleAllowedHd: ["example.test"], microsoftAllowedEmailDomains: ["partner.test"]
      } as Config, now: () => new Date() });
      const scopes = ["synthetic:records:read", "synthetic:records:write"];
      for (const scope of scopes) await service.createScope({ scope, description: scope }, actor);
      const native = await service.createResource({ resourceId: "https://synthetic-pending.example.test/v1",
        displayName: "Pending test", ownerTeam: "test", ownerContact: null, status: "active",
        protectedResourceMetadataUrl: "https://synthetic-pending.example.test/.well-known/oauth-protected-resource",
        entitlementMode: "native", scopes }, actor);
      const resourceId = native.resource.id as string;
      const batch = (emails: string[]) => ({ resourceId, userIds: [], emails, scopes, validFrom: null, validUntil: null });

      const mixed = await service.bulkNativeGrants(batch(["known@example.test", "new.person@example.test",
        "partner@partner.test", "outsider@elsewhere.test"]), false);
      const operation = (email: string) => mixed.rows.filter((row) => row.user_email === email).map((row) => row.operation);
      expect(operation("known@example.test")).toEqual(["create", "create"]);
      expect(operation("new.person@example.test")).toEqual(["create_pending", "create_pending"]);
      expect(operation("partner@partner.test")).toEqual(["create_pending", "create_pending"]);
      expect(operation("outsider@elsewhere.test")).toEqual(["email_domain_not_allowed", "email_domain_not_allowed"]);
      expect(mixed.summary).toMatchObject({ create: 2, create_pending: 4, error: 2 });
      await expect(service.bulkNativeGrants(batch(["outsider@elsewhere.test"]), true, actor))
        .rejects.toMatchObject({ reason: "bulk_native_grant_validation_failed" });

      const committed = await service.bulkNativeGrants(batch(["known@example.test", "New.Person@example.test", "partner@partner.test"]), true, actor);
      expect(committed).toMatchObject({ committed: 6, summary: { create: 2, create_pending: 4, error: 0 } });
      const pendingRows = await client.query(`SELECT status, user_id, email_normalized::text AS email FROM oauth_native_human_grants
        WHERE status = 'pending_user_link' ORDER BY email`);
      expect(pendingRows.rows.map((row) => [row.email, row.user_id])).toEqual([
        ["new.person@example.test", null], ["new.person@example.test", null], ["partner@partner.test", null], ["partner@partner.test", null]]);
      expect((await service.bulkNativeGrants(batch(["new.person@example.test"]), false)).summary)
        .toMatchObject({ already_pending: 2, error: 0 });
      expect(await service.bulkNativeGrants(batch(["new.person@example.test"]), true, actor)).toMatchObject({ committed: 0 });
      const listed = await service.listNativeGrants(resourceId, { query: "new.person", scope: "", status: "pending_user_link", effective: "", offset: 0 });
      expect(listed).toHaveLength(2);
      expect(listed.every((row) => row.user_email === "new.person@example.test" && row.effective === false)).toBe(true);

      const repositories = new Repositories(db);
      const login = (googleSub: string, email: string, emailVerified = true) => repositories.upsertUser({
        googleSub, email, emailNormalized: email.toLowerCase(), emailVerified, hd: email.split("@")[1] });
      const unverified = await login("synthetic-new-sub", "new.person@example.test", false);
      expect(await repositories.linkPendingNativeGrants(unverified, "corr_synthetic_link")).toEqual([]);
      const verified = await login("synthetic-new-sub", "new.person@example.test");
      const linked = await repositories.linkPendingNativeGrants(verified, "corr_synthetic_link");
      expect(linked).toHaveLength(2);
      const afterLink = await service.listNativeGrants(resourceId, { query: "new.person", scope: "", status: "", effective: "true", offset: 0 });
      expect(afterLink.map((row) => [row.user_id, row.status])).toEqual([[verified.id, "active"], [verified.id, "active"]]);
      expect(await repositories.linkPendingNativeGrants(verified, "corr_synthetic_link")).toEqual([]);

      const partner = await login("microsoft:synthetic-partner", "partner@partner.test");
      const pendingToRevoke = (await client.query<{ id: string }>(`SELECT id FROM oauth_native_human_grants
        WHERE email_normalized = 'partner@partner.test' AND status = 'pending_user_link' ORDER BY id LIMIT 1`)).rows[0].id;
      expect(await service.revokeNativeGrant(pendingToRevoke, actor)).toMatchObject({ status: "revoked" });
      expect(await repositories.linkPendingNativeGrants(partner, "corr_synthetic_link")).toHaveLength(1);

      await client.query(`INSERT INTO oauth_native_human_grants (oauth_resource_id, oauth_scope_id, email_normalized, status, created_by_user_id)
        SELECT $1, id, 'known@example.test', 'pending_user_link', $2 FROM oauth_scopes WHERE scope = $3`, [resourceId, actorId, scopes[0]]);
      const known = await login("synthetic-known-sub", "known@example.test");
      expect(await repositories.linkPendingNativeGrants(known, "corr_synthetic_link")).toEqual([]);
      expect((await client.query(`SELECT status FROM oauth_native_human_grants WHERE email_normalized = 'known@example.test'`)).rows)
        .toEqual([{ status: "expired" }]);

      const audits = await client.query<{ metadata: Record<string, unknown>; actor_user_id: string }>(
        `SELECT metadata, actor_user_id FROM audit_logs WHERE event_type = 'oauth.native_grant.changed' ORDER BY created_at, event_id`);
      const actions = audits.rows.map((row) => row.metadata.action);
      expect(actions.filter((action) => action === "created_pending")).toHaveLength(2);
      expect(audits.rows.filter((row) => row.metadata.action === "linked").map((row) => row.actor_user_id).sort())
        .toEqual([partner.id, verified.id].sort());
      expect(JSON.stringify(audits.rows.filter((row) => row.metadata.action === "created_pending")))
        .not.toMatch(/new\.person@|partner@/);
    } finally {
      await client.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`).catch(() => undefined);
      await client.end();
    }
  });
});
