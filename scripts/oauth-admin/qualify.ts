/** Fresh, loopback-only PostgreSQL qualification for the OAuth P0 Admin repository. */
import { randomUUID } from "node:crypto";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import Fastify from "fastify";
import { decodeProtectedHeader, importJWK, jwtVerify } from "jose";
import { PostgresDb } from "../../src/db.js";
import { OAuthAdminRepository } from "../../src/oauth/admin-repository.js";
import { OAuthAdminService } from "../../src/oauth/admin-service.js";
import type { OAuthAdminAuditContext } from "../../src/oauth/admin-types.js";
import { registerOAuthReadOnlyHttp } from "../../src/oauth/http.js";
import { OAuthFoundationRepository } from "../../src/oauth/repository.js";
import { OAuthAccessTokenSigner, type OAuthSigningKeyRecord } from "../../src/oauth/signing.js";
import { Repositories } from "../../src/repositories.js";
import { verifyOAuthCredentialSecret } from "../../src/security.js";
import type { Config } from "../../src/types.js";

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

const rawUrl = process.env.OAUTH_ADMIN_QUALIFY_DATABASE_URL;
assert(rawUrl, "disposable database URL required");
const databaseUrl = new URL(rawUrl);
assert(databaseUrl.protocol === "postgresql:" && databaseUrl.hostname === "127.0.0.1" &&
  /^\/access_layer_oauth_admin_[a-f0-9]{12}$/.test(databaseUrl.pathname), "unsafe qualification database target");

const db = new PostgresDb(rawUrl);
const root = await mkdtemp(join(tmpdir(), "access-layer-oauth-admin-"));
const pepper = `synthetic-oauth-admin-pepper-${randomUUID()}`;
const config = {
  oauthCredentialSecretPepper: pepper,
  toolClientSecretPepper: `synthetic-legacy-pepper-${randomUUID()}`,
  oauthSigningKeyRoot: root,
  oauthP0Enabled: true,
  appBaseUrl: "https://access-layer.example.invalid",
  authIssuer: "https://access-layer.example.invalid"
} as Config;
const repository = new OAuthAdminRepository(db);
let now = new Date(Date.now() - 301_000);
const service = new OAuthAdminService({ config, repository, now: () => now });
const foundation = new OAuthFoundationRepository(db);
const app = Fastify({ logger: false });
registerOAuthReadOnlyHttp(app, { config, repository: foundation });

try {
  const empty = await db.query<{ count: number }>("SELECT count(*)::int AS count FROM oauth_clients");
  assert(empty.rows[0].count === 0, "qualification database must be fresh");
  const adminId = randomUUID();
  const humanId = randomUUID();
  await db.query(`INSERT INTO users (id, google_sub, email, email_normalized, email_verified, hd, status)
    VALUES ($1, 'oauth-admin-local-admin', 'admin@example.invalid', 'admin@example.invalid', true, 'example.invalid', 'active'),
           ($2, 'oauth-admin-local-human', 'human@example.invalid', 'human@example.invalid', true, 'example.invalid', 'active')`,
  [adminId, humanId]);
  const tool = await db.query<{ id: string }>(`INSERT INTO tools (slug, display_name, status)
    VALUES ('nancy-entitlement-local', 'Synthetic entitlement anchor only', 'active') RETURNING id`);
  const toolId = tool.rows[0].id;
  for (const permission of ["nancy:survey:read", "nancy:survey:write"]) {
    await db.query("INSERT INTO tool_permissions (tool_id, permission_key) VALUES ($1, $2)", [toolId, permission]);
  }
  await db.query(`INSERT INTO authorization_grants (tool_id, user_id, role, permissions, status)
    VALUES ($1, $2, 'user', '["nancy:survey:read","nancy:survey:write"]'::jsonb, 'active')`, [toolId, humanId]);
  const ctx: OAuthAdminAuditContext = {
    actor: {
      userId: adminId, googleSub: "oauth-admin-local-admin", email: "admin@example.invalid", hd: "example.invalid",
      role: "platform_admin", permissions: ["admin:oauth:read", "admin:oauth:write"], assignedToolIds: []
    },
    correlationId: `corr_oauth_admin_local_${randomUUID()}`,
    requestIpHash: "synthetic-loopback-hash", userAgentHash: "synthetic-agent-hash"
  };

  const readScope = await service.createScope({ scope: "nancy:survey:read", description: "Read survey" }, ctx);
  const writeScope = await service.createScope({ scope: "nancy:survey:write", description: "Write survey" }, ctx);
  const resourceId = "https://survey-test.unguess-internal.net/api";
  const resourceCreated = await service.createResource({
    resourceId, displayName: "Nancy synthetic API", ownerTeam: "nancy-local", ownerContact: "owner@example.invalid",
    status: "active", protectedResourceMetadataUrl: "https://survey-test.unguess-internal.net/.well-known/oauth-protected-resource",
    legacyToolSlug: "nancy-entitlement-local", scopeMappings: [
      { scope: "nancy:survey:read", legacyPermissionKey: "nancy:survey:read" },
      { scope: "nancy:survey:write", legacyPermissionKey: "nancy:survey:write" }
    ]
  }, ctx);
  const clientCreated = await service.createClient({
    clientId: "nancy-vnext-bff-local", clientName: "Nancy synthetic BFF", ownerTeam: "nancy-local",
    ownerContact: "owner@example.invalid", status: "active", grantTypes: ["authorization_code", "refresh_token"],
    redirectUris: ["https://survey-test.unguess-internal.net/auth/callback"],
    allowances: [
      { resourceId, scope: "nancy:survey:read" }, { resourceId, scope: "nancy:survey:write" }
    ]
  }, ctx);
  const resourcePk = String(resourceCreated.resource.id);
  const clientPk = String(clientCreated.client.id);
  const snapshot = await service.snapshot();
  assert(snapshot.clients.length === 1 && snapshot.resources.length === 1 && snapshot.scopes.length === 2 &&
    snapshot.resourceScopes.length === 2 && snapshot.allowances.length === 2 &&
    snapshot.entitlementBindings.length === 1, "admin registration graph incomplete");
  assert(!JSON.stringify(snapshot).includes(clientCreated.client_secret) &&
    !JSON.stringify(snapshot).includes(resourceCreated.resource_credential_secret), "plaintext secret in admin read");
  const firstClient = await db.query<{ secret_hash: string; status: string }>(
    "SELECT secret_hash, status FROM oauth_client_credentials WHERE oauth_client_id = $1", [clientPk]);
  const firstResource = await db.query<{ secret_hash: string; status: string }>(
    "SELECT secret_hash, status FROM oauth_resource_credentials WHERE oauth_resource_id = $1", [resourcePk]);
  assert(firstClient.rows.length === 1 && firstResource.rows.length === 1 &&
    await verifyOAuthCredentialSecret(clientCreated.client_secret, pepper, firstClient.rows[0].secret_hash) &&
    await verifyOAuthCredentialSecret(resourceCreated.resource_credential_secret, pepper, firstResource.rows[0].secret_hash),
  "stored credential hash mismatch");
  assert(clientCreated.client_secret !== resourceCreated.resource_credential_secret, "credential domains conflated");

  await service.replaceRedirectUris(clientPk, ["https://survey-test.unguess-internal.net/auth/callback"], ctx);
  await service.replaceAllowances(clientPk, [{ resourceId, scope: "nancy:survey:read" }], ctx);
  await service.replaceAllowances(clientPk, [
    { resourceId, scope: "nancy:survey:read" }, { resourceId, scope: "nancy:survey:write" }
  ], ctx);
  await service.setResourceScope(resourcePk, String(readScope.id), { legacyPermissionKey: "nancy:survey:read", status: "active" }, ctx);
  await service.setEntitlementBinding(resourcePk, "nancy-entitlement-local", "disabled", ctx);
  await service.setEntitlementBinding(resourcePk, "nancy-entitlement-local", "active", ctx);
  await service.updateRegistrationStatus("client", clientPk, "disabled", ctx);
  await service.updateRegistrationStatus("client", clientPk, "active", ctx);
  await service.updateRegistrationStatus("resource", resourcePk, "disabled", ctx);
  await service.updateRegistrationStatus("resource", resourcePk, "active", ctx);
  await service.updateScope(String(writeScope.id), { status: "disabled" }, ctx);
  await service.updateScope(String(writeScope.id), { status: "active" }, ctx);

  const rotatedClient = await service.rotateCredential("client", clientPk, ctx);
  const rotatedResource = await service.rotateCredential("resource", resourcePk, ctx);
  const clientRows = await db.query<{ secret_hash: string; status: string }>(
    "SELECT secret_hash, status FROM oauth_client_credentials WHERE oauth_client_id = $1 ORDER BY created_at", [clientPk]);
  const resourceRows = await db.query<{ secret_hash: string; status: string }>(
    "SELECT secret_hash, status FROM oauth_resource_credentials WHERE oauth_resource_id = $1 ORDER BY created_at", [resourcePk]);
  assert(clientRows.rows.length === 2 && resourceRows.rows.length === 2 &&
    clientRows.rows.filter((row) => row.status === "active").length === 1 &&
    resourceRows.rows.filter((row) => row.status === "active").length === 1 &&
    clientRows.rows.filter((row) => row.status === "retired").length === 1 &&
    resourceRows.rows.filter((row) => row.status === "retired").length === 1, "credential rotation lifecycle invalid");
  assert(await verifyOAuthCredentialSecret(rotatedClient.client_secret!, pepper, clientRows.rows.find((row) => row.status === "active")!.secret_hash) &&
    await verifyOAuthCredentialSecret(rotatedResource.resource_credential_secret!, pepper, resourceRows.rows.find((row) => row.status === "active")!.secret_hash) &&
    !await verifyOAuthCredentialSecret(clientCreated.client_secret, pepper, clientRows.rows.find((row) => row.status === "active")!.secret_hash),
  "credential rotation verifier invalid");

  const staged = await service.generateSigningKey(ctx);
  assert(!JSON.stringify(staged).includes(root), "private reference in Admin response");
  assert(!JSON.stringify(await service.snapshot()).includes(root), "private reference in Admin read");
  assert((await app.inject({ method: "GET", url: "/oauth/jwks" })).statusCode === 503, "staged key must not publish JWKS");
  await service.publishSigningKey(String(staged.id), ctx);
  let earlyDenied = false;
  try { await service.activateSigningKey(String(staged.id), ctx); } catch { earlyDenied = true; }
  assert(earlyDenied, "early key activation was accepted");
  now = new Date();
  await service.activateSigningKey(String(staged.id), ctx);
  const jwksResponse = await app.inject({ method: "GET", url: "/oauth/jwks" });
  assert(jwksResponse.statusCode === 200, "activated key JWKS failed");
  const keys = jwksResponse.json<{ keys: Record<string, unknown>[] }>().keys;
  assert(keys.length === 1 && keys[0].kid === staged.kid, "wrong JWKS key");
  for (const field of ["d", "p", "q", "dp", "dq", "qi", "oth", "k"]) {
    assert(!Object.hasOwn(keys[0], field), "private RSA member in JWKS");
  }
  const storedKey = await db.query<Record<string, unknown>>(`SELECT id, kid, algorithm, public_jwk,
    public_key_fingerprint_sha256, protected_private_key_ref, status, published_at, activates_at,
    last_signed_at, retire_after, retired_at FROM oauth_signing_keys WHERE id = $1`, [staged.id]);
  assert(storedKey.rows.length === 1, "signing key not stored");
  const row = storedKey.rows[0];
  assert(typeof row.protected_private_key_ref === "string" && row.protected_private_key_ref.startsWith("file://"),
    "protected key reference invalid");
  const privatePem = await readFile(fileURLToPath(row.protected_private_key_ref), "utf8");
  assert(privatePem.includes("PRIVATE KEY"), "private key file missing");
  assert(!JSON.stringify(row).includes(privatePem), "private key stored in DB row");
  const signer = new OAuthAccessTokenSigner({ issuer: config.authIssuer, signingKeyRoot: root });
  const keyRecord: OAuthSigningKeyRecord = {
    id: String(row.id), kid: String(row.kid), algorithm: "RS256", publicJwk: row.public_jwk as Record<string, unknown>,
    publicKeyFingerprintSha256: String(row.public_key_fingerprint_sha256),
    protectedPrivateKeyRef: String(row.protected_private_key_ref), status: "active",
    publishedAt: row.published_at as Date, activatesAt: row.activates_at as Date,
    lastSignedAt: row.last_signed_at as Date | null, retireAfter: row.retire_after as Date | null,
    retiredAt: row.retired_at as Date | null
  };
  const issued = await signer.issue({ key: keyRecord, subject: "oauth-admin-local-human", audience: resourceId,
    clientId: "nancy-vnext-bff-local", scopes: ["nancy:survey:read"], sessionId: randomUUID(), now });
  assert(decodeProtectedHeader(issued.token).kid === staged.kid, "unexpected access-token kid");
  const jwksOnlyKey = await importJWK(keys[0] as Parameters<typeof importJWK>[0], "RS256");
  const verified = await jwtVerify(issued.token, jwksOnlyKey, {
    algorithms: ["RS256"], issuer: config.authIssuer, audience: resourceId, currentDate: now
  });
  assert(verified.payload.client_id === "nancy-vnext-bff-local" && verified.payload.scope === "nancy:survey:read",
    "JWKS-only token verification failed");

  const backup = await new Repositories(db).exportBackup();
  const backupJson = JSON.stringify(backup);
  assert(!backupJson.includes(clientCreated.client_secret) && !backupJson.includes(resourceCreated.resource_credential_secret) &&
    !backupJson.includes(rotatedClient.client_secret!) && !backupJson.includes(rotatedResource.resource_credential_secret!) &&
    !backupJson.includes(privatePem), "private material entered database backup");
  const audit = await db.query<{ metadata: Record<string, unknown> }>(
    "SELECT metadata FROM audit_logs WHERE event_type LIKE 'oauth.%.changed'");
  assert(audit.rows.length >= 17 && !JSON.stringify(audit.rows).includes(clientCreated.client_secret) &&
    !JSON.stringify(audit.rows).includes(resourceCreated.resource_credential_secret) &&
    !JSON.stringify(audit.rows).includes(rotatedClient.client_secret!) &&
    !JSON.stringify(audit.rows).includes(rotatedResource.resource_credential_secret!) &&
    !JSON.stringify(audit.rows).includes(privatePem), "Admin audit incomplete or secret-bearing");

  process.stdout.write(JSON.stringify({ result: "PASS", postgres: "disposable-loopback", scopes: 2,
    clients: 1, resources: 1, allowances: 2, signing_keys: 1, admin_audit_events: audit.rows.length,
    checks: ["real_repository", "credential_rotation", "binding_lifecycle", "jwks_503_200",
      "publication_lead", "jwks_only_token_verification", "secret_free_backup_and_audit"] }) + "\n");
} catch (error) {
  const safe = error && typeof error === "object" ? error as { name?: string; code?: string; constraint?: string } : {};
  process.stderr.write(JSON.stringify({ result: "FAIL", error_type: safe.name ?? "unknown",
    sqlstate: safe.code ?? null, constraint: safe.constraint ?? null }) + "\n");
  process.exitCode = 1;
} finally {
  await app.close();
  await db.close();
  const fromTmp = relative(tmpdir(), root);
  assert(fromTmp.startsWith(`access-layer-oauth-admin-`) && !fromTmp.includes(sep), "unsafe temporary root cleanup");
  await rm(root, { recursive: true, force: true });
}
