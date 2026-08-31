import { createHash, createPublicKey, generateKeyPairSync, randomBytes, randomUUID } from "node:crypto";
import { mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { execFileSync } from "node:child_process";
import { exportJWK } from "jose";
import { AuditLogger } from "../../src/audit.js";
import { buildApplication } from "../../src/application.js";
import { PostgresDb, type Db } from "../../src/db.js";
import type { GoogleOidcClient } from "../../src/google.js";
import { OAuthAuthorizationFlowRepository } from "../../src/oauth/flow-repository.js";
import type { OAuthUpstreamGoogleClient } from "../../src/oauth/google.js";
import { OAuthFoundationRepository } from "../../src/oauth/repository.js";
import { OAuthTokenRepository } from "../../src/oauth/token-repository.js";
import { OAuthTokenLifecycleService } from "../../src/oauth/token-service.js";
import {
  loadOAuthPrivateSigningKey,
  OAuthAccessTokenSigner,
  selectOAuthSigningKey,
  verifyOAuthAccessToken
} from "../../src/oauth/signing.js";
import { Repositories } from "../../src/repositories.js";
import {
  decryptJsonPayload,
  hashOAuthCredentialSecret,
  hashToolSecret,
  sha256
} from "../../src/security.js";
import { TokenService } from "../../src/token-service.js";
import type { Config, GoogleIdentity } from "../../src/types.js";

const STEP4A_BASELINE = "1757a40c6369be59427da6618fa8126605a51550";
const LEGACY_BASELINE_REF = "access-layer-v1-baseline";
const EXPECTED_MIGRATIONS = [
  ["001_initial.sql", "62b7ec1d729feb091f5df01bd5ea636614a9c3b60c98a990413e1ba3212c015d"],
  ["002_audit_tool_delete_fk.sql", "ab33b34abb01fa606eeafc9eab3d7dcfdafbc9429bd67bee6a64c35851638b22"],
  ["003_oauth_dark_foundation.sql", "96b3993fcfdb930597cbdeca37e86d51df486fd9e951970d156a21c454f18efe"],
  ["004_oauth_authorization_code_flow.sql", "407b0fe9b3c9e053e22fac7e9640e0b4d02fe341ea6b3e7f05bb32eeaa8efede"],
  ["005_oauth_token_lifecycle.sql", "aaffcb469000f62e680b5d391360fdacc4414e4280ba230e90e7fd4eee4dafbe"]
] as const;

const IDS = {
  user: "10000000-0000-4000-8000-000000000001",
  tool: "10000000-0000-4000-8000-000000000002",
  toolPermission: "10000000-0000-4000-8000-000000000003",
  grant: "10000000-0000-4000-8000-000000000004",
  oauthClient: "10000000-0000-4000-8000-000000000005",
  oauthClientCredential: "10000000-0000-4000-8000-000000000006",
  oauthRedirect: "10000000-0000-4000-8000-000000000007",
  oauthResource: "10000000-0000-4000-8000-000000000008",
  oauthResourceCredential: "10000000-0000-4000-8000-000000000009",
  oauthBinding: "10000000-0000-4000-8000-00000000000a",
  oauthScope: "10000000-0000-4000-8000-00000000000b",
  oauthResourceScope: "10000000-0000-4000-8000-00000000000c",
  oauthAllowance: "10000000-0000-4000-8000-00000000000d",
  oauthSigningKey: "10000000-0000-4000-8000-00000000000e"
};

const CLIENT_ID = "step4b-client";
const CLIENT_SECRET = `step4b_client_${randomBytes(24).toString("base64url")}`;
const LEGACY_TOOL_CLIENT_SECRET = `step4b_legacy_${randomBytes(24).toString("base64url")}`;
const GOOGLE_CLIENT_SECRET = `step4b_google_${randomBytes(24).toString("base64url")}`;
const GOOGLE_AUTHORIZATION_CODE = `step4b_google_code_${randomBytes(24).toString("base64url")}`;
const RESOURCE_ID = "https://step4b-resource.invalid/v1";
const RESOURCE_CREDENTIAL_ID = "step4b-resource";
const RESOURCE_SECRET = `step4b_resource_${randomBytes(24).toString("base64url")}`;
const REDIRECT_URI = "https://step4b-client.invalid/callback";
const LEGACY_RETURN_URI = "https://step4b-legacy.invalid/callback";
const SCOPE = "step4b:records:read";
const PERMISSION = "step4b:records:read";
const BACKUP_API_TOKEN = `step4b_backup_api_${randomBytes(32).toString("base64url")}`;
const BACKUP_KEY = `step4b_backup_key_${randomBytes(32).toString("base64url")}`;
const OAUTH_PEPPER = `step4b_oauth_pepper_${randomBytes(24).toString("base64url")}`;
const TOOL_PEPPER = `step4b_tool_pepper_${randomBytes(24).toString("base64url")}`;

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(`ASSERTION_FAILED:${message}`);
}

function requiredEnv(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`Missing ${name}`);
  const parsed = new URL(value);
  assert(parsed.hostname === "127.0.0.1", `${name} must be loopback-only`);
  assert(parsed.pathname.includes("step4b"), `${name} must name a synthetic Step4B database`);
  assert(!/(prod|production|live)/i.test(parsed.pathname), `${name} must not resemble production`);
  return value;
}

function form(values: Record<string, string>): string {
  return new URLSearchParams(values).toString();
}

function basic(username: string, password: string): string {
  const encodedUsername = encodeURIComponent(username).replace(/%20/g, "+");
  const encodedPassword = encodeURIComponent(password).replace(/%20/g, "+");
  return `Basic ${Buffer.from(`${encodedUsername}:${encodedPassword}`).toString("base64")}`;
}

function stable(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stable).join(",")}]`;
  if (value && typeof value === "object") {
    if (value instanceof Date) return JSON.stringify(value.toISOString());
    return `{${Object.entries(value as Record<string, unknown>)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([key, entry]) => `${JSON.stringify(key)}:${stable(entry)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function fingerprint(value: unknown): string {
  return createHash("sha256").update(stable(value)).digest("hex");
}

function deferred<T = void>() {
  let resolvePromise!: (value: T | PromiseLike<T>) => void;
  let rejectPromise!: (reason?: unknown) => void;
  const promise = new Promise<T>((resolve, reject) => {
    resolvePromise = resolve;
    rejectPromise = reject;
  });
  return { promise, resolve: resolvePromise, reject: rejectPromise };
}

async function withTimeout<T>(promise: Promise<T>, label: string, milliseconds = 15_000): Promise<T> {
  let handle: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_, reject) => {
        handle = setTimeout(() => reject(new Error(`TIMEOUT:${label}`)), milliseconds);
      })
    ]);
  } finally {
    if (handle) clearTimeout(handle);
  }
}

class FakeGoogle implements OAuthUpstreamGoogleClient, GoogleOidcClient {
  nonce = "";

  createAuthorizationUrl(input: { state: string; nonce: string }): string {
    this.nonce = input.nonce;
    const url = new URL("https://accounts.google.invalid/o/oauth2/v2/auth");
    url.searchParams.set("state", input.state);
    url.searchParams.set("nonce", input.nonce);
    return url.toString();
  }

  async exchangeCodeForIdentity(): Promise<GoogleIdentity> {
    return {
      googleSub: "step4b-google-subject",
      email: "step4b-person@example.invalid",
      emailVerified: true,
      hd: "example.invalid",
      displayName: "Synthetic Step4B Person",
      pictureUrl: null,
      nonce: this.nonce,
      issuer: "https://accounts.google.com",
      audience: "step4b-google-client.apps.googleusercontent.com",
      expiresAt: Math.floor(Date.now() / 1000) + 300
    };
  }
}

class CommitGateDb implements Db {
  readonly ready = deferred();
  readonly release = deferred();
  private armed = true;

  constructor(private readonly delegate: Db) {}
  query(sql: string, params: unknown[] = []) { return this.delegate.query(sql, params); }
  close() { return Promise.resolve(); }
  transaction<T>(fn: (db: Db) => Promise<T>): Promise<T> {
    return this.delegate.transaction(async (tx) => {
      const result = await fn(tx);
      if (this.armed) {
        this.armed = false;
        this.ready.resolve();
        await this.release.promise;
      }
      return result;
    });
  }
}

class SnapshotGateDb implements Db {
  readonly established = deferred();
  readonly release = deferred();
  private armed = true;

  constructor(private readonly delegate: Db) {}
  query(sql: string, params: unknown[] = []) { return this.delegate.query(sql, params); }
  close() { return Promise.resolve(); }
  transaction<T>(fn: (db: Db) => Promise<T>): Promise<T> {
    if (!this.armed) return this.delegate.transaction(fn);
    this.armed = false;
    return this.delegate.transaction((tx) => {
      let tail = Promise.resolve();
      let firstDataQuery = true;
      const serialized: Db = {
        query: <R extends import("pg").QueryResultRow = import("pg").QueryResultRow>(sql: string, params: unknown[] = []) => {
          const operation = tail.then(async () => {
            const result = await tx.query<R>(sql, params);
            if (firstDataQuery && /^\s*SELECT\b/i.test(sql)) {
              firstDataQuery = false;
              this.established.resolve();
              await this.release.promise;
            }
            return result;
          });
          tail = operation.then(() => undefined, () => undefined);
          return operation;
        },
        transaction: <R>(inner: (db: Db) => Promise<R>) => inner(serialized),
        close: () => Promise.resolve()
      };
      return fn(serialized);
    });
  }
}

class ObservedDb implements Db {
  readonly state: { lastError: string };

  constructor(private readonly delegate: Db, state = { lastError: "none" }) {
    this.state = state;
  }
  async query<R extends import("pg").QueryResultRow = import("pg").QueryResultRow>(sql: string, params: unknown[] = []) {
    try {
      return await this.delegate.query<R>(sql, params);
    } catch (error) {
      const pgError = error as { code?: unknown; constraint?: unknown; table?: unknown; routine?: unknown; position?: unknown };
      const queryTag = sql.includes("FOR UPDATE OF code") ? "lock_authorization_code"
        : sql.includes("INSERT INTO oauth_sessions") ? "persist_oauth_session"
        : sql.includes("oauth_refresh_token_families") ? "refresh_family"
        : sql.includes("oauth_signing_keys") ? "oauth_signing_key"
        : sql.trim().split(/\s+/).slice(0, 3).join("_").toLowerCase();
      this.state.lastError = [queryTag, pgError.code, typeof pgError.position === "string" ? `position-${pgError.position}` : undefined,
        pgError.table, pgError.constraint, pgError.routine]
        .filter((value) => typeof value === "string")
        .join(":") || "non-postgres-error";
      throw error;
    }
  }
  transaction<T>(fn: (db: Db) => Promise<T>): Promise<T> {
    return this.delegate.transaction((tx) => fn(new ObservedDb(tx, this.state)));
  }
  close() { return Promise.resolve(); }
}

function config(databaseUrl: string, signingRoot: string): Config {
  return {
    appEnv: "test",
    appBaseUrl: "https://step4b-issuer.invalid",
    authIssuer: "https://step4b-issuer.invalid",
    publicBasePath: "",
    port: 8080,
    logLevel: "silent",
    databaseUrl,
    googleClientId: "step4b-google-client.apps.googleusercontent.com",
    googleClientSecret: GOOGLE_CLIENT_SECRET,
    googleRedirectUri: "https://step4b-issuer.invalid/v1/auth/google/callback",
    googleAllowedHd: ["example.invalid"],
    googleOidcScope: "openid email profile",
    jwtPublicKeyId: "step4b-legacy-key",
    accessTokenTtlSeconds: 900,
    refreshTokenTtlSeconds: 28800,
    oneTimeCodeTtlSeconds: 60,
    oauthP0Enabled: true,
    oauthTransactionProtectionKey: randomBytes(32),
    oauthCredentialSecretPepper: OAUTH_PEPPER,
    oauthSigningKeyRoot: signingRoot,
    sessionCookieName: "step4b_admin_session",
    sessionSecret: `step4b_session_${randomBytes(24).toString("base64url")}`,
    toolClientSecretPepper: TOOL_PEPPER,
    backupEncryptionKey: BACKUP_KEY,
    corsAllowedOrigins: [],
    returnUrlAllowedSchemes: ["https", "http"],
    adminBootstrapEmails: [],
    logIpSalt: `step4b_log_${randomBytes(24).toString("base64url")}`,
    auditLogRetentionDays: 365,
    auditLogRawIp: false,
    accessRequestReopenAfterDays: 30,
    enableRefreshTokens: true,
    siemExportEnabled: false,
    backupApiToken: BACKUP_API_TOKEN,
    trustProxyHops: 0
  };
}

async function buildRealApp(db: Db, appConfig: Config, google = new FakeGoogle()) {
  const repositories = new Repositories(db);
  const tokenService = new TokenService(appConfig);
  await tokenService.init();
  const app = await buildApplication({
    config: appConfig,
    repositories,
    oauthRepository: new OAuthFoundationRepository(db),
    oauthFlowRepository: new OAuthAuthorizationFlowRepository(db),
    oauthGoogle: google,
    oauthTokenService: new OAuthTokenLifecycleService({
      config: appConfig,
      repository: new OAuthTokenRepository(db)
    }),
    audit: new AuditLogger(repositories),
    google,
    tokenService
  });
  return { app, repositories, tokenService, google };
}

async function migrationEvidence(db: PostgresDb) {
  const version = await db.query<{ server_version: string; version_num: string }>(
    "SELECT current_setting('server_version') AS server_version, current_setting('server_version_num') AS version_num"
  );
  assert(Number(version.rows[0].version_num) >= 160000 && Number(version.rows[0].version_num) < 170000, "server must be PostgreSQL 16");
  const applied = await db.query<{ filename: string }>("SELECT filename FROM schema_migrations ORDER BY filename");
  assert(stable(applied.rows.map((row) => row.filename)) === stable(EXPECTED_MIGRATIONS.map(([name]) => name)), "migrations 001-005 must be the only applied migrations");
  return { serverVersion: version.rows[0].server_version, applied: applied.rows.map((row) => row.filename) };
}

async function verifyMigrationFiles() {
  for (const [filename, expected] of EXPECTED_MIGRATIONS) {
    const content = await import("node:fs/promises").then((fs) => fs.readFile(resolve("migrations", filename)));
    assert(createHash("sha256").update(content).digest("hex") === expected, `${filename} hash changed`);
  }
}

async function seedSource(db: PostgresDb, privateKeyRef: string, publicJwk: Record<string, unknown>, publicFingerprint: string) {
  const clientHash = await hashOAuthCredentialSecret(CLIENT_SECRET, OAUTH_PEPPER);
  const resourceHash = await hashOAuthCredentialSecret(RESOURCE_SECRET, OAUTH_PEPPER);
  const toolHash = await hashToolSecret(LEGACY_TOOL_CLIENT_SECRET, TOOL_PEPPER);
  await db.transaction(async (tx) => {
    await tx.query(`INSERT INTO users (id, google_sub, email, email_normalized, email_verified, hd, display_name, status)
      VALUES ($1,'step4b-google-subject','step4b-person@example.invalid','step4b-person@example.invalid',true,'example.invalid','Synthetic Step4B Person','active')`, [IDS.user]);
    await tx.query(`INSERT INTO tools (id, slug, display_name, status, allowed_return_urls)
      VALUES ($1,'step4b-tool','Synthetic Step4B Tool','active',$2::jsonb)`, [IDS.tool, JSON.stringify([LEGACY_RETURN_URI])]);
    await tx.query(`INSERT INTO tool_clients (tool_id, client_id, client_secret_hash, status)
      VALUES ($1,'step4b-legacy-client',$2,'active')`, [IDS.tool, toolHash]);
    await tx.query(`INSERT INTO tool_permissions (id, tool_id, permission_key, description)
      VALUES ($1,$2,$3,'Synthetic Step4B permission')`, [IDS.toolPermission, IDS.tool, PERMISSION]);
    await tx.query(`INSERT INTO authorization_grants (id, tool_id, user_id, role, permissions, status)
      VALUES ($1,$2,$3,'tool_user',$4::jsonb,'active')`, [IDS.grant, IDS.tool, IDS.user, JSON.stringify([PERMISSION])]);
    await tx.query(`INSERT INTO oauth_clients (id, client_id, client_name, client_type, token_endpoint_auth_method, grant_types, status, owner_team)
      VALUES ($1,$2,'Synthetic Step4B Client','confidential','client_secret_basic',ARRAY['authorization_code','refresh_token'],'active','step4b')`, [IDS.oauthClient, CLIENT_ID]);
    await tx.query(`INSERT INTO oauth_client_credentials (id, oauth_client_id, secret_hash, status, activated_at)
      VALUES ($1,$2,$3,'active',now())`, [IDS.oauthClientCredential, IDS.oauthClient, clientHash]);
    await tx.query(`INSERT INTO oauth_client_redirect_uris (id, oauth_client_id, redirect_uri) VALUES ($1,$2,$3)`, [IDS.oauthRedirect, IDS.oauthClient, REDIRECT_URI]);
    await tx.query(`INSERT INTO oauth_resources (id, resource_id, display_name, status, owner_team, protected_resource_metadata_url)
      VALUES ($1,$2,'Synthetic Step4B Resource','active','step4b','https://step4b-resource.invalid/.well-known/oauth-protected-resource')`, [IDS.oauthResource, RESOURCE_ID]);
    await tx.query(`INSERT INTO oauth_resource_credentials (id, oauth_resource_id, credential_id, secret_hash, status, activated_at)
      VALUES ($1,$2,$3,$4,'active',now())`, [IDS.oauthResourceCredential, IDS.oauthResource, RESOURCE_CREDENTIAL_ID, resourceHash]);
    await tx.query(`INSERT INTO oauth_resource_entitlement_bindings (id, oauth_resource_id, legacy_tool_id, status) VALUES ($1,$2,$3,'active')`, [IDS.oauthBinding, IDS.oauthResource, IDS.tool]);
    await tx.query(`INSERT INTO oauth_scopes (id, scope, description, status) VALUES ($1,$2,'Synthetic read scope','active')`, [IDS.oauthScope, SCOPE]);
    await tx.query(`INSERT INTO oauth_resource_scopes (id, oauth_resource_id, oauth_scope_id, legacy_permission_key, status)
      VALUES ($1,$2,$3,$4,'active')`, [IDS.oauthResourceScope, IDS.oauthResource, IDS.oauthScope, PERMISSION]);
    await tx.query(`INSERT INTO oauth_client_resource_scopes (id, oauth_client_id, oauth_resource_id, oauth_scope_id, status)
      VALUES ($1,$2,$3,$4,'active')`, [IDS.oauthAllowance, IDS.oauthClient, IDS.oauthResource, IDS.oauthScope]);
    await tx.query(`INSERT INTO oauth_signing_keys (
        id, kid, public_jwk, public_key_fingerprint_sha256, protected_private_key_ref,
        status, published_at, activates_at
      ) VALUES ($1,'step4b-oauth-key',$2::jsonb,$3,$4,'active',now() - interval '10 minutes',now() - interval '5 minutes')`,
      [IDS.oauthSigningKey, JSON.stringify(publicJwk), publicFingerprint, privateKeyRef]);
  });
}

async function loginAndExchange(
  app: Awaited<ReturnType<typeof buildApplication>>,
  google: FakeGoogle,
  state: string,
  diagnostic: () => string = () => "none"
) {
  const verifier = randomBytes(48).toString("base64url");
  const challenge = sha256(verifier);
  const authorize = new URL("https://step4b-issuer.invalid/oauth/authorize");
  for (const [key, value] of Object.entries({
    response_type: "code", client_id: CLIENT_ID, redirect_uri: REDIRECT_URI,
    scope: SCOPE, state, code_challenge: challenge, code_challenge_method: "S256", resource: RESOURCE_ID
  })) authorize.searchParams.set(key, value);
  const authorizationResponse = await app.inject({ method: "GET", url: `${authorize.pathname}${authorize.search}` });
  assert(authorizationResponse.statusCode === 302, "authorize must redirect to synthetic Google boundary");
  const upstream = new URL(String(authorizationResponse.headers.location));
  assert(upstream.hostname === "accounts.google.invalid", "only the Google boundary may be fake");
  assert(upstream.searchParams.get("nonce") === google.nonce, "OAuth upstream nonce must be bound");
  const callback = await app.inject({
    method: "GET",
    url: `/oauth/upstream/google/callback?state=${encodeURIComponent(upstream.searchParams.get("state") ?? "")}&code=${encodeURIComponent(GOOGLE_AUTHORIZATION_CODE)}`
  });
  assert(callback.statusCode === 302, "Google callback must redirect downstream");
  const downstream = new URL(String(callback.headers.location));
  assert(downstream.origin + downstream.pathname === REDIRECT_URI, "callback redirect must be exact");
  assert(downstream.searchParams.get("state") === state, "downstream state must round-trip");
  assert(downstream.searchParams.get("iss") === "https://step4b-issuer.invalid", "authorization response must include exact iss");
  const code = downstream.searchParams.get("code");
  assert(code, "authorization response must include a code");
  const token = await app.inject({
    method: "POST", url: "/oauth/token",
    headers: { "content-type": "application/x-www-form-urlencoded", authorization: basic(CLIENT_ID, CLIENT_SECRET) },
    payload: form({ grant_type: "authorization_code", code, redirect_uri: REDIRECT_URI, client_id: CLIENT_ID, code_verifier: verifier, resource: RESOURCE_ID })
  });
  const tokenError = token.statusCode === 200 ? "none" : String((token.json() as { error?: unknown }).error ?? "unknown");
  assert(token.statusCode === 200, `authorization code exchange must succeed (status=${token.statusCode}, error=${tokenError}, db=${diagnostic()})`);
  return token.json() as { access_token: string; refresh_token: string; token_type: string; expires_in: number; scope: string };
}

async function introspect(app: Awaited<ReturnType<typeof buildApplication>>, token: string) {
  return app.inject({
    method: "POST", url: "/oauth/introspect",
    headers: { "content-type": "application/x-www-form-urlencoded", authorization: basic(RESOURCE_CREDENTIAL_ID, RESOURCE_SECRET) },
    payload: form({ token, token_type_hint: "access_token" })
  });
}

async function refresh(app: Awaited<ReturnType<typeof buildApplication>>, refreshToken: string) {
  return app.inject({
    method: "POST", url: "/oauth/token",
    headers: { "content-type": "application/x-www-form-urlencoded", authorization: basic(CLIENT_ID, CLIENT_SECRET) },
    payload: form({ grant_type: "refresh_token", refresh_token: refreshToken, client_id: CLIENT_ID, resource: RESOURCE_ID })
  });
}

async function seedRestoreAdmin(db: PostgresDb, appConfig: Config, tokenService: TokenService) {
  const userId = "20000000-0000-4000-8000-000000000001";
  const toolId = "20000000-0000-4000-8000-000000000002";
  const grantId = "20000000-0000-4000-8000-000000000003";
  const sessionId = "20000000-0000-4000-8000-000000000004";
  await db.transaction(async (tx) => {
    await tx.query(`INSERT INTO users (id, google_sub, email, email_normalized, email_verified, hd, status)
      VALUES ($1,'step4b-restore-admin-sub','step4b-admin@example.invalid','step4b-admin@example.invalid',true,'example.invalid','active')`, [userId]);
    await tx.query(`INSERT INTO tools (id, slug, display_name, status, allowed_return_urls) VALUES ($1,'access-admin','Synthetic Restore Admin','active','[]'::jsonb)`, [toolId]);
    await tx.query(`INSERT INTO authorization_grants (id, tool_id, user_id, role, permissions, status)
      VALUES ($1,$2,$3,'platform_admin','["admin:backup:write"]'::jsonb,'active')`, [grantId, toolId, userId]);
    await tx.query(`INSERT INTO sessions (id,user_id,tool_id,grant_id,status,issued_at,expires_at)
      VALUES ($1,$2,$3,$4,'active',now(),now() + interval '15 minutes')`, [sessionId, userId, toolId, grantId]);
  });
  const now = new Date();
  return tokenService.issueAccessToken({
    user: { id: userId, google_sub: "step4b-restore-admin-sub", email: "step4b-admin@example.invalid", email_normalized: "step4b-admin@example.invalid", email_verified: true, hd: "example.invalid", display_name: null, picture_url: null, status: "active", first_seen_at: now, last_seen_at: now },
    tool: { id: toolId, slug: "access-admin", display_name: "Synthetic Restore Admin", description: null, status: "active", allowed_return_urls: [], owner_email: null, created_at: now, updated_at: now },
    grant: { id: grantId, tool_id: toolId, user_id: userId, email_normalized: null, role: "platform_admin", permissions: ["admin:backup:write"], status: "active", valid_from: now, valid_until: null, created_by_user_id: null },
    session: { id: sessionId, user_id: userId, tool_id: toolId, grant_id: grantId, status: "active", issued_at: now, expires_at: new Date(now.getTime() + 900_000), revoked_at: null, last_seen_at: null }
  });
}

async function legacyBaselineSmoke(databaseUrl: string, appConfig: Config, tempRoot: string) {
  const baselineCommit = execFileSync("git", ["rev-parse", `${LEGACY_BASELINE_REF}^{commit}`], { encoding: "utf8" }).trim();
  const archivePath = join(tempRoot, "legacy-baseline.tar");
  const checkoutPath = join(tempRoot, "legacy-baseline");
  await import("node:fs/promises").then((fs) => fs.mkdir(checkoutPath));
  const archive = execFileSync("git", ["archive", "--format=tar", LEGACY_BASELINE_REF], { maxBuffer: 32 * 1024 * 1024 });
  await writeFile(archivePath, archive);
  execFileSync("tar", ["-xf", archivePath, "-C", checkoutPath]);
  await symlink(resolve("node_modules"), join(checkoutPath, "node_modules"), "junction");
  const suffix = `?step4b=${Date.now()}`;
  const [{ PostgresDb: BaselineDb }, { Repositories: BaselineRepositories }, { AuditLogger: BaselineAudit }, { TokenService: BaselineToken }, { buildApp }] = await Promise.all([
    import(pathToFileURL(join(checkoutPath, "src", "db.ts")).href + suffix),
    import(pathToFileURL(join(checkoutPath, "src", "repositories.ts")).href + suffix),
    import(pathToFileURL(join(checkoutPath, "src", "audit.ts")).href + suffix),
    import(pathToFileURL(join(checkoutPath, "src", "token-service.ts")).href + suffix),
    import(pathToFileURL(join(checkoutPath, "src", "app.ts")).href + suffix)
  ]);
  const baselineDb = new BaselineDb(databaseUrl);
  const baselineRepositories = new BaselineRepositories(baselineDb);
  const baselineToken = new BaselineToken({ ...appConfig, oauthP0Enabled: false });
  await baselineToken.init();
  const baselineApp = await buildApp({
    config: { ...appConfig, oauthP0Enabled: false },
    repositories: baselineRepositories,
    audit: new BaselineAudit(baselineRepositories),
    google: new FakeGoogle(),
    tokenService: baselineToken
  });
  try {
    const before = await baselineDb.query("SELECT count(*)::int AS count FROM auth_requests");
    const health = await baselineApp.inject({ method: "GET", url: "/health" });
    assert(health.statusCode === 200, "legacy baseline health must be clean on expanded schema");
    const jwksResponse = await baselineApp.inject({ method: "GET", url: "/v1/.well-known/jwks.json" });
    assert(jwksResponse.statusCode === 200, "legacy baseline JWKS must be available on expanded schema");
    const jwks = jwksResponse.json() as { keys?: Array<Record<string, unknown>> };
    assert(Array.isArray(jwks.keys) && jwks.keys.length >= 1, "legacy baseline JWKS must publish at least one key");
    const privateJwkMembers = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"];
    for (const key of jwks.keys) {
      assert(key.kty === "RSA", "legacy baseline JWKS keys must use kty RSA");
      assert(key.alg === "RS256", "legacy baseline JWKS keys must use alg RS256");
      assert(key.use === "sig", "legacy baseline JWKS keys must use sig use");
      assert(typeof key.kid === "string" && key.kid.length > 0, "legacy baseline JWKS keys must have a non-empty kid");
      for (const member of privateJwkMembers) {
        assert(!Object.hasOwn(key, member), `legacy baseline JWKS must omit private member ${member}`);
      }
    }
    const start = await baselineApp.inject({
      method: "GET",
      url: `/v1/auth/start?tool_slug=step4b-tool&return_url=${encodeURIComponent(LEGACY_RETURN_URI)}&state=step4b-legacy-state`
    });
    assert(start.statusCode === 302, "legacy baseline auth start must redirect");
    assert(new URL(String(start.headers.location)).hostname === "accounts.google.invalid", "legacy auth start must use fake Google boundary");
    const after = await baselineDb.query("SELECT count(*)::int AS count FROM auth_requests");
    assert(Number(after.rows[0].count) === Number(before.rows[0].count) + 1, "legacy auth start must write one auth request");
  } finally {
    await baselineApp.close();
    await baselineDb.close();
  }
  return baselineCommit;
}

async function main() {
  const sourceUrl = requiredEnv("STEP4B_SOURCE_DATABASE_URL");
  const restoreUrl = requiredEnv("STEP4B_RESTORE_DATABASE_URL");
  const expectedCommit = process.env.STEP4B_EXPECTED_COMMIT;
  assert(typeof expectedCommit === "string" && /^[a-f0-9]{40}$/.test(expectedCommit), "STEP4B_EXPECTED_COMMIT must be an exact commit");
  assert(sourceUrl !== restoreUrl, "source and restore database URLs must differ");
  const head = execFileSync("git", ["rev-parse", "HEAD"], { encoding: "utf8" }).trim();
  assert(head === expectedCommit, "qualification runtime must match the runner-recorded commit");
  execFileSync("git", ["merge-base", "--is-ancestor", STEP4A_BASELINE, head]);
  assert(head !== STEP4A_BASELINE, "qualification must use a committed hardening descendant, not the failed Step 4A baseline");
  await verifyMigrationFiles();

  const tempRoot = await mkdtemp(join(tmpdir(), "access-layer-step4b-"));
  const sourceDb = new PostgresDb(sourceUrl);
  const restoreDb = new PostgresDb(restoreUrl);
  const apps: Array<Awaited<ReturnType<typeof buildApplication>>> = [];
  try {
    const sourceMigration = await migrationEvidence(sourceDb);
    const restoreMigration = await migrationEvidence(restoreDb);
    assert(sourceMigration.serverVersion === restoreMigration.serverVersion, "source and restore PostgreSQL versions must match");

    const signingRoot = join(tempRoot, "oauth-signing");
    await import("node:fs/promises").then((fs) => fs.mkdir(signingRoot));
    const privateKeyPath = join(signingRoot, "step4b-oauth-private.pem");
    const pair = generateKeyPairSync("rsa", {
      modulusLength: 2048,
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
      publicKeyEncoding: { type: "spki", format: "pem" }
    });
    await writeFile(privateKeyPath, pair.privateKey, { mode: 0o600 });
    const exported = await exportJWK(createPublicKey(pair.publicKey));
    const publicJwk = { kty: "RSA", kid: "step4b-oauth-key", alg: "RS256", use: "sig", n: exported.n, e: exported.e };
    const publicFingerprint = createHash("sha256").update(JSON.stringify({ e: exported.e, kty: "RSA", n: exported.n })).digest("hex");
    await seedSource(sourceDb, pathToFileURL(privateKeyPath).href, publicJwk, publicFingerprint);

    const sourceConfig = config(sourceUrl, signingRoot);
    const signingRecord = await sourceDb.transaction(async (tx) =>
      selectOAuthSigningKey(await new OAuthTokenRepository(tx).listSignableKeysForUpdate(), new Date())
    );
    await loadOAuthPrivateSigningKey({ root: signingRoot, key: signingRecord });
    const signingPreflight = await new OAuthAccessTokenSigner({ issuer: sourceConfig.authIssuer, signingKeyRoot: signingRoot }).issue({
      key: signingRecord,
      subject: "step4b-signing-preflight-subject",
      audience: RESOURCE_ID,
      clientId: CLIENT_ID,
      scopes: [SCOPE],
      sessionId: randomUUID(),
      now: new Date()
    });
    assert(signingPreflight.claims.exp - signingPreflight.claims.iat === 900, "dedicated OAuth signing key preflight must succeed");
    const observedSourceDb = new ObservedDb(sourceDb);
    const source = await buildRealApp(observedSourceDb, sourceConfig);
    apps.push(source.app);

    const first = await loginAndExchange(source.app, source.google, "step4b-normal-state", () => observedSourceDb.state.lastError);
    assert(first.token_type === "Bearer" && first.expires_in === 900 && first.scope === SCOPE, "token response must be exact");
    const keys = await new OAuthTokenRepository(sourceDb).listVerificationKeys();
    const claims = await verifyOAuthAccessToken({ token: first.access_token, issuer: sourceConfig.authIssuer, audience: RESOURCE_ID, keys, now: new Date() });
    assert(claims.iss === sourceConfig.authIssuer && claims.aud === RESOURCE_ID && claims.client_id === CLIENT_ID && claims.scope === SCOPE, "access-token identity, audience, client and scope claims must be exact");
    assert(claims.exp - claims.iat === 900, "OAuth access token TTL must be 900 seconds");
    for (const forbidden of ["email", "hd", "display_name", "picture_url", "role", "permissions"]) assert(!Object.hasOwn(claims, forbidden), `access token must omit ${forbidden}`);
    const jwks = await source.app.inject({ method: "GET", url: "/oauth/jwks" });
    assert(jwks.statusCode === 200 && jwks.json().keys.length === 1, "JWKS must publish the dedicated signing key");
    assert(!stable(jwks.json()).includes("private"), "JWKS must not disclose private material");
    assert((await introspect(source.app, first.access_token)).json().active === true, "resource-owned introspection must be active");
    const normalRefresh = await refresh(source.app, first.refresh_token);
    assert(normalRefresh.statusCode === 200 && normalRefresh.json().refresh_token !== first.refresh_token, "normal refresh must rotate once");
    const revoke = await source.app.inject({
      method: "POST", url: "/oauth/revoke",
      headers: { "content-type": "application/x-www-form-urlencoded", authorization: basic(CLIENT_ID, CLIENT_SECRET) },
      payload: form({ token: normalRefresh.json().refresh_token, token_type_hint: "refresh_token" })
    });
    assert(revoke.statusCode === 200, "refresh-token revocation must succeed");
    assert((await introspect(source.app, normalRefresh.json().access_token)).json().active === false, "revoked family access token must introspect inactive");
    assert((await refresh(source.app, normalRefresh.json().refresh_token)).statusCode === 400, "revoked refresh token must be invalid_grant");

    const concurrent = await loginAndExchange(source.app, source.google, "step4b-concurrency-state");
    const concurrentResponses = await withTimeout(Promise.all([
      refresh(source.app, concurrent.refresh_token),
      refresh(source.app, concurrent.refresh_token)
    ]), "real refresh concurrency", 20_000);
    assert(concurrentResponses.filter((response) => response.statusCode === 200).length === 1, "concurrency must have exactly one rotation success");
    assert(concurrentResponses.filter((response) => response.statusCode === 400 && response.json().error === "invalid_grant").length === 1, "concurrency must have exactly one invalid_grant replay outcome");
    const concurrencyClaims = await verifyOAuthAccessToken({
      token: concurrentResponses.find((response) => response.statusCode === 200)!.json().access_token,
      issuer: sourceConfig.authIssuer, audience: RESOURCE_ID, keys, now: new Date()
    });
    const lineage = await sourceDb.query<Record<string, unknown>>(`SELECT family.status AS family_status, family.current_generation,
        family.replay_detected_at, session.status AS session_status,
        array_agg(token.status ORDER BY token.generation) AS token_statuses,
        array_agg(token.generation ORDER BY token.generation) AS generations,
        array_agg(token.parent_refresh_token_id::text ORDER BY token.generation) AS parents,
        array_agg(token.id::text ORDER BY token.generation) AS ids
      FROM oauth_refresh_token_families family
      JOIN oauth_sessions session ON session.id = family.oauth_session_id
      JOIN oauth_refresh_tokens token ON token.oauth_refresh_token_family_id = family.id
      WHERE family.oauth_session_id = $1
      GROUP BY family.id, session.id`, [concurrencyClaims.sid]);
    assert(lineage.rows.length === 1, "concurrency lineage must resolve to one family");
    const line = lineage.rows[0];
    assert(line.family_status === "revoked" && line.session_status === "revoked" && line.replay_detected_at !== null, "replay must revoke family and session");
    assert(stable(line.generations) === stable([0, 1]) && stable(line.token_statuses) === stable(["consumed", "revoked"]), "concurrency lineage must be generation 0 consumed then generation 1 revoked");
    assert((line.parents as unknown[])[0] === null && (line.parents as unknown[])[1] === (line.ids as unknown[])[0], "refresh parent lineage must be coherent");
    assert((await introspect(source.app, concurrentResponses.find((response) => response.statusCode === 200)!.json().access_token)).json().active === false, "replay winner access token must be inactive online");

    const retained = await loginAndExchange(source.app, source.google, "step4b-backup-state");
    const retainedClaims = await verifyOAuthAccessToken({ token: retained.access_token, issuer: sourceConfig.authIssuer, audience: RESOURCE_ID, keys, now: new Date() });
    const writerGate = new CommitGateDb(sourceDb);
    const writer = await buildRealApp(writerGate, sourceConfig);
    apps.push(writer.app);
    const snapshotGate = new SnapshotGateDb(sourceDb);
    const exporter = await buildRealApp(snapshotGate, sourceConfig);
    apps.push(exporter.app);
    const writerRequest = refresh(writer.app, retained.refresh_token);
    await withTimeout(writerGate.ready.promise, "writer pre-commit gate");
    const exportRequest = exporter.app.inject({ method: "GET", url: "/v1/admin/backup/export", headers: { authorization: `Bearer ${BACKUP_API_TOKEN}` } });
    await withTimeout(snapshotGate.established.promise, "backup snapshot establishment");
    writerGate.release.resolve();
    const writerResponse = await withTimeout(writerRequest, "writer commit");
    assert(writerResponse.statusCode === 200, "controlled writer refresh must commit");
    snapshotGate.release.resolve();
    const exportResponse = await withTimeout(exportRequest, "encrypted backup export");
    assert(exportResponse.statusCode === 200, "encrypted HTTP backup export must succeed");
    const encryptedBackup = exportResponse.json() as Record<string, unknown>;
    assert(encryptedBackup.schema === "access-layer-encrypted-backup" && encryptedBackup.alg === "AES-256-GCM", "backup must use the real encrypted envelope");
    const decrypted = decryptJsonPayload(encryptedBackup, BACKUP_KEY);
    const backupData = decrypted.data as Record<string, unknown>;
    assert(backupData && typeof backupData === "object", "decrypted backup must contain data");
    const snapshotFamily = (backupData.oauth_refresh_token_families as Array<Record<string, unknown>>).find((row) => row.oauth_session_id === retainedClaims.sid);
    const snapshotTokens = (backupData.oauth_refresh_tokens as Array<Record<string, unknown>>).filter((row) => row.oauth_refresh_token_family_id === snapshotFamily?.id);
    assert(snapshotFamily?.current_generation === 0 && snapshotFamily.status === "active", "backup snapshot must preserve the pre-commit family state");
    assert(snapshotTokens.length === 1 && snapshotTokens[0].generation === 0 && snapshotTokens[0].status === "current", "backup snapshot must not tear across the refresh transition");

    const restoreConfig = { ...sourceConfig, databaseUrl: restoreUrl };
    const restore = await buildRealApp(restoreDb, restoreConfig);
    apps.push(restore.app);
    const adminToken = await seedRestoreAdmin(restoreDb, restoreConfig, restore.tokenService);
    const restoreResponse = await restore.app.inject({
      method: "POST", url: "/v1/admin/backup/import",
      headers: { authorization: `Bearer ${adminToken.token}`, "content-type": "application/json" },
      payload: { backup: encryptedBackup, replace_existing: true, confirm_replace: true }
    });
    assert(restoreResponse.statusCode === 200, "encrypted replace_existing restore must succeed through HTTP");
    const restoredData = await restore.repositories.exportBackup();
    assert(fingerprint(restoredData) === fingerprint(backupData), "restored rows and lineage must equal the exported snapshot");
    const invalidConstraints = await restoreDb.query<{ count: number }>("SELECT count(*)::int AS count FROM pg_constraint WHERE connamespace = 'public'::regnamespace AND NOT convalidated");
    assert(Number(invalidConstraints.rows[0].count) === 0, "all restored constraints must be validated");
    assert((await introspect(restore.app, retained.access_token)).json().active === true, "pre-backup access token must remain active after restore");
    const postRestoreRotation = await refresh(restore.app, retained.refresh_token);
    assert(postRestoreRotation.statusCode === 200, "retained in-memory refresh token must rotate once after restore");
    const postRestoreReplay = await refresh(restore.app, retained.refresh_token);
    assert(postRestoreReplay.statusCode === 400 && postRestoreReplay.json().error === "invalid_grant", "retained refresh token second use must be replay invalid_grant");

    const legacyBaselineCommit = await legacyBaselineSmoke(sourceUrl, { ...sourceConfig, oauthP0Enabled: false }, tempRoot);
    const sections = Object.fromEntries(Object.entries(backupData).map(([name, rows]) => [name, Array.isArray(rows) ? rows.length : 0]));
    const evidence = {
      status: "PASS",
      qualified_commit: head,
      legacy_baseline_commit: legacyBaselineCommit,
      postgres: { server_version: sourceMigration.serverVersion, targets: 2, loopback_only: true },
      migrations: EXPECTED_MIGRATIONS.map(([id, sha256]) => ({ id, sha256 })),
      assertions: {
        real_oauth_http_e2e: "PASS",
        exact_issuer_pkce_rs256_ttl_jwks_claims: "PASS",
        resource_owned_introspection_and_revocation: "PASS",
        real_refresh_concurrency_replay: "PASS",
        repeatable_read_snapshot_coordination: "PASS",
        encrypted_replace_restore: "PASS",
        post_restore_access_and_refresh_continuity: "PASS",
        legacy_baseline_expanded_schema_smoke: "PASS"
      },
      backup: {
        row_counts: sections,
        content_fingerprint_sha256: fingerprint(backupData),
        secrets_or_raw_tokens_recorded: false
      }
    };
    process.stdout.write(`${JSON.stringify(evidence, null, 2)}\n`);
  } finally {
    await Promise.allSettled(apps.reverse().map((app) => app.close()));
    await Promise.allSettled([sourceDb.close(), restoreDb.close()]);
    await rm(tempRoot, { recursive: true, force: true });
  }
}

main().catch((error) => {
  const message = error instanceof Error ? error.message : "unknown Step4B qualification failure";
  process.stderr.write(`${message}\n`);
  process.exitCode = 1;
});
