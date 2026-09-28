import { randomBytes, randomUUID } from "node:crypto";
import { PostgresDb } from "../../src/db.js";
import { Repositories } from "../../src/repositories.js";
import { decryptJsonPayload, encryptJsonPayload } from "../../src/security.js";

const sourceUrl = process.env.PHASE9A1_SOURCE_DATABASE_URL;
const restoreUrl = process.env.PHASE9A1_RESTORE_DATABASE_URL;
const compatUrl = process.env.PHASE9A1_COMPAT_DATABASE_URL;
if (!sourceUrl || !restoreUrl || !compatUrl) throw new Error("Missing disposable qualification target");
for (const value of [sourceUrl, restoreUrl, compatUrl]) {
  const target = new URL(value);
  if (target.hostname !== "127.0.0.1" || !target.pathname.includes("phase9a1") || !target.pathname.includes("test")) {
    throw new Error("Unsafe qualification target");
  }
}

const source = new PostgresDb(sourceUrl);
const restore = new PostgresDb(restoreUrl);
const compat = new PostgresDb(compatUrl);

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

async function migrationNames(db: PostgresDb): Promise<string[]> {
  const result = await db.query<{ filename: string }>("SELECT filename FROM schema_migrations ORDER BY filename");
  return result.rows.map((row) => row.filename);
}

async function main() {
  const names = await migrationNames(source);
  assert(names.length === 6 && names.at(-1) === "006_oauth_native_entitlements_dark.sql", "source migration sequence mismatch");
  assert(JSON.stringify(names) === JSON.stringify(await migrationNames(restore)), "restore migration sequence mismatch");
  assert(JSON.stringify(names) === JSON.stringify(await migrationNames(compat)), "compat migration sequence mismatch");
  const version = await source.query<{ server_version_num: string }>("SHOW server_version_num");
  const versionNumber = Number(version.rows[0].server_version_num);
  assert(versionNumber >= 160000 && versionNumber < 170000, "PostgreSQL 16 required");

  const user = (await source.query<{ id: string }>(`INSERT INTO users
    (google_sub, email, email_normalized, email_verified, hd)
    VALUES ('phase9a1-synthetic-sub', 'human@example.test', 'human@example.test', true, 'example.test') RETURNING id`)).rows[0].id;
  const tool = (await source.query<{ id: string }>(`INSERT INTO tools (slug, display_name)
    VALUES ('phase9a1-test-tool', 'Synthetic tool') RETURNING id`)).rows[0].id;
  await source.query(`INSERT INTO tool_permissions (tool_id, permission_key)
    VALUES ($1, 'synthetic:records:read')`, [tool]);
  const legacyGrant = (await source.query<{ id: string }>(`INSERT INTO authorization_grants
    (tool_id, user_id, role, permissions) VALUES ($1, $2, 'user', '["synthetic:records:read"]'::jsonb)
    RETURNING id`, [tool, user])).rows[0].id;
  const scopeRead = (await source.query<{ id: string }>(`INSERT INTO oauth_scopes (scope, description)
    VALUES ('synthetic:records:read', 'Read') RETURNING id`)).rows[0].id;
  const scopeWrite = (await source.query<{ id: string }>(`INSERT INTO oauth_scopes (scope, description)
    VALUES ('synthetic:records:write', 'Write') RETURNING id`)).rows[0].id;
  const legacyResource = (await source.query<{ id: string }>(`INSERT INTO oauth_resources
    (resource_id, display_name, owner_team, protected_resource_metadata_url)
    VALUES ('https://legacy.phase9a1.example.test/api', 'Legacy', 'test-team',
      'https://legacy.phase9a1.example.test/metadata') RETURNING id`)).rows[0].id;
  const nativeResource = (await source.query<{ id: string }>(`INSERT INTO oauth_resources
    (resource_id, display_name, owner_team, protected_resource_metadata_url, entitlement_mode)
    VALUES ('https://native.phase9a1.example.test/api', 'Native', 'test-team',
      'https://native.phase9a1.example.test/metadata', 'native') RETURNING id`)).rows[0].id;
  await source.query(`INSERT INTO oauth_resource_entitlement_bindings
    (oauth_resource_id, legacy_tool_id) VALUES ($1, $2)`, [legacyResource, tool]);
  await source.query(`INSERT INTO oauth_resource_scopes
    (oauth_resource_id, oauth_scope_id, legacy_permission_key)
    VALUES ($1, $2, 'synthetic:records:read')`, [legacyResource, scopeRead]);
  for (const scope of [scopeRead, scopeWrite]) {
    await source.query(`INSERT INTO oauth_resource_scopes (oauth_resource_id, oauth_scope_id)
      VALUES ($1, $2)`, [nativeResource, scope]);
  }
  const grantIds: string[] = [];
  for (const scope of [scopeRead, scopeWrite]) {
    const result = await source.query<{ id: string }>(`INSERT INTO oauth_native_human_grants
      (oauth_resource_id, oauth_scope_id, user_id, status, created_by_user_id)
      VALUES ($1, $2, $3, 'active', $3) RETURNING id`, [nativeResource, scope, user]);
    grantIds.push(result.rows[0].id);
  }
  const client = (await source.query<{ id: string }>(`INSERT INTO oauth_clients
    (client_id, client_name, client_type, token_endpoint_auth_method, grant_types, owner_team)
    VALUES ('phase9a1-test-bff', 'Synthetic BFF', 'confidential', 'client_secret_basic',
      ARRAY['authorization_code']::text[], 'test-team') RETURNING id`)).rows[0].id;

  async function addTransaction(resource: string, scopes: string[]) {
    return (await source.query<{ id: string }>(`INSERT INTO oauth_authorization_transactions
      (oauth_client_id, oauth_resource_id, redirect_uri, requested_scopes, code_challenge,
       protected_downstream_state, upstream_state_hash, upstream_nonce_hash, correlation_id, expires_at)
      VALUES ($1, $2, 'https://client.phase9a1.example.test/callback', $3::text[],
        $4, '{}'::jsonb, $5, $6, $7, now() + interval '600 seconds') RETURNING id`,
    [client, resource, scopes, "a".repeat(43), randomBytes(32).toString("base64url"),
      randomBytes(32).toString("base64url"), randomUUID()])).rows[0].id;
  }
  const legacyTransaction = await addTransaction(legacyResource, ["synthetic:records:read"]);
  const nativeTransaction = await addTransaction(nativeResource, ["synthetic:records:read", "synthetic:records:write"]);
  const legacyAuthorization = (await source.query<{ id: string }>(`INSERT INTO oauth_authorizations
    (oauth_authorization_transaction_id, user_id, oauth_client_id, oauth_resource_id,
     granted_scopes, legacy_authorization_grant_id, correlation_id)
    VALUES ($1, $2, $3, $4, ARRAY['synthetic:records:read']::text[], $5, $6) RETURNING id`,
  [legacyTransaction, user, client, legacyResource, legacyGrant, randomUUID()])).rows[0].id;
  const nativeAuthorization = (await source.query<{ id: string }>(`INSERT INTO oauth_authorizations
    (oauth_authorization_transaction_id, user_id, oauth_client_id, oauth_resource_id,
     granted_scopes, entitlement_source, correlation_id)
    VALUES ($1, $2, $3, $4, $5::text[], 'native', $6) RETURNING id`,
  [nativeTransaction, user, client, nativeResource,
    ["synthetic:records:read", "synthetic:records:write"], randomUUID()])).rows[0].id;
  for (const grant of grantIds) {
    await source.query(`INSERT INTO oauth_authorization_native_grants
      (oauth_authorization_id, oauth_native_human_grant_id) VALUES ($1, $2)`, [nativeAuthorization, grant]);
  }

  const sourceBackup = await new Repositories(source).exportBackup();
  assert((sourceBackup.oauth_native_human_grants as unknown[]).length === 2, "native grants absent from export");
  assert((sourceBackup.oauth_authorization_native_grants as unknown[]).length === 2, "native provenance absent from export");
  const backupKey = randomBytes(32).toString("base64url");
  const sealed = encryptJsonPayload(sourceBackup, backupKey);
  assert(sealed.schema === "access-layer-encrypted-backup", "encrypted backup envelope invalid");
  // The secret itself is kept in memory and never printed or persisted.
  const decrypted = decryptJsonPayload(sealed, backupKey);
  await new Repositories(restore).importBackup(decrypted, { replaceExisting: true });
  const restored = await new Repositories(restore).exportBackup();
  const nativeGrants = restored.oauth_native_human_grants as Array<{ id: string }>;
  const nativeLinks = restored.oauth_authorization_native_grants as Array<{
    oauth_authorization_id: string; oauth_native_human_grant_id: string;
  }>;
  assert(nativeGrants.length === 2 && grantIds.every((id) => nativeGrants.some((row) => row.id === id)),
    "native grants changed during restore");
  assert(nativeLinks.length === 2 && grantIds.every((id) => nativeLinks.some((row) =>
    row.oauth_authorization_id === nativeAuthorization && row.oauth_native_human_grant_id === id)),
  "native authorization provenance changed during restore");
  const restoredNativeAuth = await restore.query<{ entitlement_source: string; legacy_authorization_grant_id: string | null }>(
    "SELECT entitlement_source, legacy_authorization_grant_id FROM oauth_authorizations WHERE id = $1", [nativeAuthorization]);
  assert(restoredNativeAuth.rows[0]?.entitlement_source === "native" &&
    restoredNativeAuth.rows[0]?.legacy_authorization_grant_id === null, "native authorization changed during restore");

  // A complete old 17-section snapshot is extracted from the legacy portion
  // of this synthetic graph, with only pre-9A.1 columns and sections.
  const oldBackup = structuredClone(sourceBackup) as Record<string, unknown>;
  delete oldBackup.oauth_native_human_grants;
  delete oldBackup.oauth_authorization_native_grants;
  oldBackup.oauth_resources = (oldBackup.oauth_resources as Array<Record<string, unknown>>)
    .filter((row) => row.id === legacyResource).map(({ entitlement_mode: _mode, ...row }) => row);
  oldBackup.oauth_resource_scopes = (oldBackup.oauth_resource_scopes as Array<Record<string, unknown>>)
    .filter((row) => row.oauth_resource_id === legacyResource);
  oldBackup.oauth_resource_entitlement_bindings = (oldBackup.oauth_resource_entitlement_bindings as Array<Record<string, unknown>>)
    .filter((row) => row.oauth_resource_id === legacyResource);
  oldBackup.oauth_authorization_transactions = (oldBackup.oauth_authorization_transactions as Array<Record<string, unknown>>)
    .filter((row) => row.id === legacyTransaction);
  oldBackup.oauth_authorizations = (oldBackup.oauth_authorizations as Array<Record<string, unknown>>)
    .filter((row) => row.id === legacyAuthorization).map(({ entitlement_source: _source, ...row }) => row);
  await new Repositories(compat).importBackup(oldBackup, { replaceExisting: true });
  const compatResource = await compat.query<{ entitlement_mode: string }>(
    "SELECT entitlement_mode FROM oauth_resources WHERE id = $1", [legacyResource]);
  const compatAuthorization = await compat.query<{ entitlement_source: string }>(
    "SELECT entitlement_source FROM oauth_authorizations WHERE id = $1", [legacyAuthorization]);
  assert(compatResource.rows[0]?.entitlement_mode === "legacy_bridge" &&
    compatAuthorization.rows[0]?.entitlement_source === "legacy_bridge", "old backup defaults failed");
  const compatNativeCount = await compat.query<{ count: string }>("SELECT count(*) FROM oauth_native_human_grants");
  assert(Number(compatNativeCount.rows[0]?.count) === 0, "old backup created native grants");

  console.log(JSON.stringify({
    qualification: "phase9a1",
    postgresqlMajor: 16,
    postgresqlVersionNum: versionNumber,
    migrations: names,
    nativeGrantRows: nativeGrants.length,
    nativeProvenanceRows: nativeLinks.length,
    encryptedFullReplaceRestore: "passed",
    pre9A1CompleteBackupImport: "passed",
    legacyAuthorizationDefault: "passed"
  }));
}

try {
  await main();
} finally {
  await Promise.all([source.close(), restore.close(), compat.close()]);
}
