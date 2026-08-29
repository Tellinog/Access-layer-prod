import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import type { QueryResult, QueryResultRow } from "pg";
import { describe, expect, it } from "vitest";
import type { Db } from "../src/db.js";
import { Repositories } from "../src/repositories.js";

const legacySections = [
  "users",
  "tools",
  "tool_clients",
  "tool_permissions",
  "authorization_grants",
  "admin_tool_assignments",
  "access_requests"
] as const;

const oauthSections = [
  "oauth_clients",
  "oauth_client_credentials",
  "oauth_client_redirect_uris",
  "oauth_resources",
  "oauth_resource_credentials",
  "oauth_resource_entitlement_bindings",
  "oauth_scopes",
  "oauth_resource_scopes",
  "oauth_client_resource_scopes",
  "oauth_signing_keys",
  "oauth_authorization_transactions",
  "oauth_authorizations",
  "oauth_authorization_codes",
  "oauth_sessions",
  "oauth_refresh_token_families",
  "oauth_refresh_tokens",
  "oauth_revocations"
] as const;

type RecordedQuery = { sql: string; params: unknown[]; transactional: boolean };

function result<T extends QueryResultRow>(rows: T[] = []): QueryResult<T> {
  return { rows, rowCount: rows.length, command: "SELECT", oid: 0, fields: [] };
}

class RecordingDb implements Db {
  readonly queries: RecordedQuery[] = [];
  readonly committedMutations: string[] = [];
  transactionCalls = 0;
  rollbackCalls = 0;
  failOn: RegExp | null = null;
  private pendingMutations: string[] = [];

  async query<T extends QueryResultRow = QueryResultRow>(sql: string, params: unknown[] = []): Promise<QueryResult<T>> {
    return this.recordQuery<T>(sql, params, false);
  }

  private async recordQuery<T extends QueryResultRow>(
    sql: string,
    params: unknown[],
    transactional: boolean
  ): Promise<QueryResult<T>> {
    this.queries.push({ sql, params, transactional });
    if (this.failOn?.test(sql)) {
      throw new Error("synthetic database failure");
    }
    if (/^\s*(?:INSERT|UPDATE|DELETE)\b/i.test(sql)) {
      (transactional ? this.pendingMutations : this.committedMutations).push(sql);
    }
    const table = sql.match(/\bFROM\s+([a-z_]+)/i)?.[1];
    return result(table ? ([{ section: table }] as unknown as T[]) : []);
  }

  async transaction<T>(fn: (db: Db) => Promise<T>): Promise<T> {
    this.transactionCalls += 1;
    this.pendingMutations = [];
    const transactionDb: Db = {
      query: <Row extends QueryResultRow = QueryResultRow>(sql: string, params: unknown[] = []) =>
        this.recordQuery<Row>(sql, params, true),
      transaction: <Value>(nested: (db: Db) => Promise<Value>) => nested(transactionDb),
      close: async () => undefined
    };
    try {
      const value = await fn(transactionDb);
      this.committedMutations.push(...this.pendingMutations);
      return value;
    } catch (error) {
      this.rollbackCalls += 1;
      throw error;
    } finally {
      this.pendingMutations = [];
    }
  }

  async close(): Promise<void> {
    return undefined;
  }
}

function legacyBackup(): Record<string, unknown> {
  return Object.fromEntries(legacySections.map((section) => [section, []]));
}

function fullBackup(): Record<string, unknown> {
  return { ...legacyBackup(), ...Object.fromEntries(oauthSections.map((section) => [section, []])) };
}

describe("OAuth backup repository coverage", () => {
  it("exports the seven legacy and exact seventeen OAuth sections with explicit deterministic queries", async () => {
    const db = new RecordingDb();
    const exported = await new Repositories(db).exportBackup();

    expect(Object.keys(exported)).toEqual([...legacySections, ...oauthSections]);
    expect(oauthSections).toHaveLength(17);
    const migrationTables = [
      "migrations/003_oauth_dark_foundation.sql",
      "migrations/004_oauth_authorization_code_flow.sql",
      "migrations/005_oauth_token_lifecycle.sql"
    ].flatMap((path) => [...readFileSync(resolve(import.meta.dirname, "..", path), "utf8").matchAll(/CREATE TABLE IF NOT EXISTS (oauth_[a-z_]+)/g)].map((match) => match[1]));
    expect(migrationTables).toEqual([...oauthSections]);
    expect(db.transactionCalls).toBe(1);
    expect(db.queries[0]).toEqual({
      sql: "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY",
      params: [],
      transactional: true
    });
    const tableReads = db.queries.slice(1);
    expect(tableReads).toHaveLength(24);
    expect(tableReads.every((query) => query.transactional)).toBe(true);
    expect(db.queries.some((query) => !query.transactional)).toBe(false);
    for (const query of tableReads) {
      expect(query.sql).toMatch(/^SELECT\s+/);
      expect(query.sql).not.toMatch(/SELECT\s+\*/i);
      expect(query.sql).toMatch(/ORDER BY\s+/i);
    }

    const oauthSql = tableReads.slice(legacySections.length).map((query) => query.sql).join("\n");
    expect(oauthSql).toContain("secret_hash");
    expect(oauthSql).toContain("code_hash");
    expect(oauthSql).toContain("token_hash");
    expect(oauthSql).toContain("protected_downstream_state");
    expect(oauthSql).toContain("public_jwk");
    expect(oauthSql).toContain("protected_private_key_ref");
    expect(oauthSql).not.toMatch(/\bclient_secret\b|\bresource_secret\b|\bauthorization_code\b|\baccess_token\b|\brefresh_token\b|\bprivate_key\b|\benv_secret\b/i);
  });

  it("rejects missing legacy or partial OAuth sections before opening a transaction", async () => {
    const missingLegacyDb = new RecordingDb();
    const missingLegacy = legacyBackup();
    delete missingLegacy.users;
    await expect(new Repositories(missingLegacyDb).importBackup(missingLegacy, { replaceExisting: false }))
      .rejects.toMatchObject({ name: "BackupValidationError", message: "Invalid backup data", statusCode: 400 });
    expect(missingLegacyDb.transactionCalls).toBe(0);

    const partialDb = new RecordingDb();
    await expect(new Repositories(partialDb).importBackup({ ...legacyBackup(), oauth_clients: [] }, { replaceExisting: true }))
      .rejects.toMatchObject({ name: "BackupValidationError", message: "Invalid backup data", statusCode: 400 });
    expect(partialDb.transactionCalls).toBe(0);

    const wrongTypeDb = new RecordingDb();
    const wrongType = fullBackup();
    wrongType.oauth_revocations = {};
    await expect(new Repositories(wrongTypeDb).importBackup(wrongType, { replaceExisting: true }))
      .rejects.toMatchObject({ name: "BackupValidationError", message: "Invalid backup data", statusCode: 400 });
    expect(wrongTypeDb.transactionCalls).toBe(0);
  });

  it("keeps OAuth state untouched for a legacy-only merge and preserves the legacy count response", async () => {
    const db = new RecordingDb();
    const counts = await new Repositories(db).importBackup(legacyBackup(), { replaceExisting: false });

    expect(counts).toEqual(Object.fromEntries(legacySections.map((section) => [section, 0])));
    expect(db.transactionCalls).toBe(1);
    expect(db.queries.some((query) => /oauth_/i.test(query.sql))).toBe(false);
  });

  it("deletes every OAuth dependant before the existing legacy replacement sequence", async () => {
    const db = new RecordingDb();
    await new Repositories(db).importBackup(legacyBackup(), { replaceExisting: true });

    const deletes = db.queries.filter((query) => /^DELETE FROM/i.test(query.sql)).map((query) => query.sql);
    expect(deletes.slice(0, 17)).toEqual([
      "DELETE FROM oauth_revocations",
      "DELETE FROM oauth_refresh_tokens",
      "DELETE FROM oauth_refresh_token_families",
      "DELETE FROM oauth_sessions",
      "DELETE FROM oauth_authorization_codes",
      "DELETE FROM oauth_authorizations",
      "DELETE FROM oauth_authorization_transactions",
      "DELETE FROM oauth_client_resource_scopes",
      "DELETE FROM oauth_resource_scopes",
      "DELETE FROM oauth_resource_entitlement_bindings",
      "DELETE FROM oauth_resource_credentials",
      "DELETE FROM oauth_client_redirect_uris",
      "DELETE FROM oauth_client_credentials",
      "DELETE FROM oauth_signing_keys",
      "DELETE FROM oauth_scopes",
      "DELETE FROM oauth_resources",
      "DELETE FROM oauth_clients"
    ]);
    expect(deletes[17]).toBe("DELETE FROM audit_logs");
    expect(deletes.indexOf("DELETE FROM oauth_resource_entitlement_bindings")).toBeLessThan(deletes.indexOf("DELETE FROM tools"));
    expect(db.queries.some((query) => /^INSERT INTO oauth_/i.test(query.sql))).toBe(false);
  });

  it("restores OAuth parents, order-independent credential links and refresh lineage deterministically", async () => {
    const db = new RecordingDb();
    const backup = fullBackup();
    backup.users = [{ id: "user" }];
    backup.tools = [{ id: "tool" }];
    backup.authorization_grants = [{ id: "grant" }];
    backup.oauth_clients = [{ id: "client" }];
    backup.oauth_resources = [{ id: "resource" }];
    backup.oauth_scopes = [{ id: "scope" }];
    backup.oauth_signing_keys = [{ id: "signing-key" }];
    backup.oauth_client_redirect_uris = [{ id: "redirect" }];
    backup.oauth_resource_entitlement_bindings = [{ id: "binding" }];
    backup.oauth_resource_scopes = [{ id: "resource-scope" }];
    backup.oauth_client_resource_scopes = [{ id: "client-resource-scope" }];
    backup.oauth_authorization_transactions = [{ id: "transaction" }];
    backup.oauth_authorizations = [{ id: "authorization" }];
    backup.oauth_authorization_codes = [{ id: "authorization-code" }];
    backup.oauth_sessions = [{ id: "session" }];
    backup.oauth_revocations = [{ id: "revocation" }];
    backup.oauth_client_credentials = [
      { id: "client-credential-child", oauth_client_id: "client", created_at: "2026-01-02", rotation_parent_id: "client-credential-parent" },
      { id: "client-credential-parent", oauth_client_id: "client", created_at: "2026-01-01", rotation_parent_id: null }
    ];
    backup.oauth_resource_credentials = [
      { id: "resource-credential-child", oauth_resource_id: "resource", created_at: "2026-01-02", rotation_parent_id: "resource-credential-parent" },
      { id: "resource-credential-parent", oauth_resource_id: "resource", created_at: "2026-01-01", rotation_parent_id: null }
    ];
    backup.oauth_refresh_token_families = [
      { id: "family-b", current_generation: 1 },
      { id: "family-a", current_generation: 0 }
    ];
    backup.oauth_refresh_tokens = [
      { id: "family-b-one", oauth_refresh_token_family_id: "family-b", generation: 1, parent_refresh_token_id: "family-b-zero" },
      { id: "family-b-zero", oauth_refresh_token_family_id: "family-b", generation: 0, parent_refresh_token_id: null },
      { id: "family-a-zero", oauth_refresh_token_family_id: "family-a", generation: 0, parent_refresh_token_id: null }
    ];

    const counts = await new Repositories(db).importBackup(backup, { replaceExisting: false });
    expect(Object.keys(counts)).toEqual([...legacySections, ...oauthSections]);

    const inserts = db.queries.filter((query) => /^INSERT INTO/i.test(query.sql));
    const tableOrder = inserts.map((query) => query.sql.match(/^INSERT INTO ([a-z_]+)/i)?.[1]);
    const oauthTableOrder = tableOrder.filter((table, index) => table?.startsWith("oauth_") && tableOrder.indexOf(table) === index);
    expect(tableOrder.indexOf("users")).toBeLessThan(tableOrder.indexOf("oauth_clients"));
    expect(oauthTableOrder).toEqual([
      "oauth_clients",
      "oauth_resources",
      "oauth_scopes",
      "oauth_signing_keys",
      "oauth_client_credentials",
      "oauth_resource_credentials",
      "oauth_client_redirect_uris",
      "oauth_resource_entitlement_bindings",
      "oauth_resource_scopes",
      "oauth_client_resource_scopes",
      "oauth_authorization_transactions",
      "oauth_authorizations",
      "oauth_authorization_codes",
      "oauth_sessions",
      "oauth_refresh_token_families",
      "oauth_refresh_tokens",
      "oauth_revocations"
    ]);

    const clientCredentialInserts = inserts.filter((query) => /^INSERT INTO oauth_client_credentials/i.test(query.sql));
    expect(clientCredentialInserts.map((query) => query.params[0])).toEqual(["client-credential-parent", "client-credential-child"]);
    expect(clientCredentialInserts.every((query) => !query.sql.includes("rotation_parent_id"))).toBe(true);
    expect(db.queries).toContainEqual(expect.objectContaining({
      sql: "UPDATE oauth_client_credentials SET rotation_parent_id = $2 WHERE id = $1",
      params: ["client-credential-child", "client-credential-parent"]
    }));
    expect(db.queries).toContainEqual(expect.objectContaining({
      sql: "UPDATE oauth_resource_credentials SET rotation_parent_id = $2 WHERE id = $1",
      params: ["resource-credential-child", "resource-credential-parent"]
    }));

    const refreshInserts = inserts.filter((query) => /^INSERT INTO oauth_refresh_tokens/i.test(query.sql));
    expect(refreshInserts.map((query) => [query.params[1], query.params[3]])).toEqual([
      ["family-a", 0],
      ["family-b", 0],
      ["family-b", 1]
    ]);
  });

  it.each([
    {
      label: "a two-row client cycle",
      section: "oauth_client_credentials",
      rows: [
        { id: "client-a", oauth_client_id: "client", secret_hash: "sensitive-client-hash", rotation_parent_id: "client-b" },
        { id: "client-b", oauth_client_id: "client", secret_hash: "sensitive-client-hash", rotation_parent_id: "client-a" }
      ]
    },
    {
      label: "a longer resource cycle",
      section: "oauth_resource_credentials",
      rows: [
        { id: "resource-a", oauth_resource_id: "resource", secret_hash: "sensitive-resource-hash", rotation_parent_id: "resource-b" },
        { id: "resource-b", oauth_resource_id: "resource", secret_hash: "sensitive-resource-hash", rotation_parent_id: "resource-c" },
        { id: "resource-c", oauth_resource_id: "resource", secret_hash: "sensitive-resource-hash", rotation_parent_id: "resource-a" }
      ]
    }
  ])("rejects $label before opening the import transaction", async ({ section, rows }) => {
    const db = new RecordingDb();
    const backup = fullBackup();
    backup[section] = rows;

    const error = await new Repositories(db).importBackup(backup, { replaceExisting: true })
      .then(() => null, (caught: unknown) => caught);
    expect(error).toMatchObject({ name: "BackupValidationError", message: "Invalid backup data", statusCode: 400 });
    expect(String(error)).not.toContain("sensitive-");
    expect(db.transactionCalls).toBe(0);
    expect(db.queries).toHaveLength(0);
  });

  it.each([
    {
      label: "a generation above current_generation",
      families: [{ id: "family", current_generation: 0 }],
      tokens: [
        { id: "zero", oauth_refresh_token_family_id: "family", generation: 0, parent_refresh_token_id: null },
        { id: "one", oauth_refresh_token_family_id: "family", generation: 1, parent_refresh_token_id: "zero" }
      ]
    },
    {
      label: "a gap inside the required generation range",
      families: [{ id: "family", current_generation: 2 }],
      tokens: [
        { id: "zero", oauth_refresh_token_family_id: "family", generation: 0, parent_refresh_token_id: null },
        { id: "two", oauth_refresh_token_family_id: "family", generation: 2, parent_refresh_token_id: "zero" }
      ]
    },
    {
      label: "a parent on generation zero",
      families: [{ id: "family", current_generation: 0 }],
      tokens: [{ id: "zero", oauth_refresh_token_family_id: "family", generation: 0, parent_refresh_token_id: "zero" }]
    },
    {
      label: "a missing explicit null parent on generation zero",
      families: [{ id: "family", current_generation: 0 }],
      tokens: [{ id: "zero", oauth_refresh_token_family_id: "family", generation: 0 }]
    },
    {
      label: "a cross-family immediate parent",
      families: [
        { id: "family-a", current_generation: 1 },
        { id: "family-b", current_generation: 0 }
      ],
      tokens: [
        { id: "a-zero", oauth_refresh_token_family_id: "family-a", generation: 0, parent_refresh_token_id: null },
        { id: "a-one", oauth_refresh_token_family_id: "family-a", generation: 1, parent_refresh_token_id: "b-zero" },
        { id: "b-zero", oauth_refresh_token_family_id: "family-b", generation: 0, parent_refresh_token_id: null }
      ]
    }
  ])("rejects refresh lineage with $label before writes", async ({ families, tokens }) => {
    const db = new RecordingDb();
    const backup = fullBackup();
    backup.oauth_refresh_token_families = families;
    backup.oauth_refresh_tokens = tokens;

    await expect(new Repositories(db).importBackup(backup, { replaceExisting: true }))
      .rejects.toMatchObject({ name: "BackupValidationError", message: "Invalid backup data", statusCode: 400 });
    expect(db.transactionCalls).toBe(0);
    expect(db.queries).toHaveLength(0);
  });

  it("fails closed on inconsistent refresh lineage before writes", async () => {
    const db = new RecordingDb();
    const backup = fullBackup();
    backup.oauth_refresh_token_families = [{ id: "family", current_generation: 1 }];
    backup.oauth_refresh_tokens = [
      { id: "root", oauth_refresh_token_family_id: "family", generation: 0, parent_refresh_token_id: null },
      { id: "child", oauth_refresh_token_family_id: "family", generation: 1, parent_refresh_token_id: "missing" }
    ];

    await expect(new Repositories(db).importBackup(backup, { replaceExisting: true }))
      .rejects.toMatchObject({ name: "BackupValidationError", message: "Invalid backup data", statusCode: 400 });
    expect(db.transactionCalls).toBe(0);
    expect(db.queries).toHaveLength(0);
  });

  it("rolls back the complete import transaction when a database write fails", async () => {
    const db = new RecordingDb();
    db.failOn = /^INSERT INTO oauth_resources/i;
    const backup = fullBackup();
    backup.users = [{ id: "legacy-user" }];
    backup.oauth_clients = [{ id: "oauth-client" }];
    backup.oauth_resources = [{ id: "oauth-resource" }];

    await expect(new Repositories(db).importBackup(backup, { replaceExisting: false }))
      .rejects.toThrow("synthetic database failure");
    expect(db.transactionCalls).toBe(1);
    expect(db.rollbackCalls).toBe(1);
    expect(db.committedMutations).toEqual([]);
  });
});
