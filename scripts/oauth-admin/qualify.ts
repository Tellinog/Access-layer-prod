/** Fresh, loopback-only PostgreSQL qualification for the OAuth P0 Admin repository. */
import { randomBytes, randomUUID } from "node:crypto";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import Fastify from "fastify";
import { decodeProtectedHeader, importJWK, jwtVerify } from "jose";
import { AuditLogger } from "../../src/audit.js";
import { buildApplication } from "../../src/application.js";
import { PostgresDb } from "../../src/db.js";
import type { GoogleOidcClient } from "../../src/google.js";
import { OAuthAdminRepository } from "../../src/oauth/admin-repository.js";
import { OAuthAdminService } from "../../src/oauth/admin-service.js";
import type { OAuthAdminAuditContext } from "../../src/oauth/admin-types.js";
import { OAuthAuthorizationFlowRepository } from "../../src/oauth/flow-repository.js";
import type { OAuthUpstreamGoogleClient } from "../../src/oauth/google.js";
import { registerOAuthReadOnlyHttp } from "../../src/oauth/http.js";
import { OAuthFoundationRepository } from "../../src/oauth/repository.js";
import { OAuthAccessTokenSigner, type OAuthSigningKeyRecord } from "../../src/oauth/signing.js";
import { OAuthTokenRepository } from "../../src/oauth/token-repository.js";
import { OAuthTokenLifecycleService } from "../../src/oauth/token-service.js";
import { Repositories } from "../../src/repositories.js";
import { hashToolSecret, sha256, verifyOAuthCredentialSecret } from "../../src/security.js";
import { TokenService } from "../../src/token-service.js";
import type { Config, GoogleIdentity } from "../../src/types.js";

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(`ASSERTION_FAILED:${message}`);
}

function form(values: Record<string, string>): string {
  return new URLSearchParams(values).toString();
}

function basic(username: string, password: string): string {
  const user = encodeURIComponent(username).replace(/%20/g, "+");
  const secret = encodeURIComponent(password).replace(/%20/g, "+");
  return `Basic ${Buffer.from(`${user}:${secret}`).toString("base64")}`;
}

class SyntheticGoogle implements GoogleOidcClient, OAuthUpstreamGoogleClient {
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
      googleSub: "oauth-admin-local-human", email: "human@example.invalid", emailVerified: true,
      hd: "example.invalid", displayName: "Synthetic human", pictureUrl: null, nonce: this.nonce,
      issuer: "https://accounts.google.com", audience: "synthetic-google-client.apps.googleusercontent.com",
      expiresAt: Math.floor(Date.now() / 1000) + 300
    };
  }
}

const rawUrl = process.env.OAUTH_ADMIN_QUALIFY_DATABASE_URL;
assert(rawUrl, "disposable database URL required");
const databaseUrl = new URL(rawUrl);
assert(databaseUrl.protocol === "postgresql:" && databaseUrl.hostname === "127.0.0.1" &&
  /^\/access_layer_oauth_admin_[a-f0-9]{12}$/.test(databaseUrl.pathname), "unsafe qualification database target");

const db = new PostgresDb(rawUrl);
const root = await mkdtemp(join(tmpdir(), "access-layer-oauth-admin-"));
const pepper = `synthetic-oauth-admin-pepper-${randomUUID()}`;
const toolPepper = `synthetic-legacy-pepper-${randomUUID()}`;
const config = {
  appEnv: "test",
  appBaseUrl: "https://access-layer.example.invalid",
  authIssuer: "https://access-layer.example.invalid",
  publicBasePath: "",
  port: 8080,
  logLevel: "silent",
  databaseUrl: rawUrl,
  googleClientId: "synthetic-google-client.apps.googleusercontent.com",
  googleClientSecret: `synthetic-google-secret-${randomUUID()}`,
  googleRedirectUri: "https://access-layer.example.invalid/v1/auth/google/callback",
  googleAllowedHd: ["example.invalid"],
  googleOidcScope: "openid email profile",
  jwtPublicKeyId: "synthetic-legacy-key",
  accessTokenTtlSeconds: 900,
  refreshTokenTtlSeconds: 28_800,
  oneTimeCodeTtlSeconds: 60,
  oauthCredentialSecretPepper: pepper,
  toolClientSecretPepper: toolPepper,
  oauthSigningKeyRoot: root,
  oauthP0Enabled: true,
  oauthTransactionProtectionKey: randomBytes(32),
  sessionCookieName: "synthetic_admin_session",
  sessionSecret: `synthetic-session-${randomUUID()}`,
  backupEncryptionKey: `synthetic-backup-${randomUUID()}`,
  corsAllowedOrigins: [],
  returnUrlAllowedSchemes: ["https", "http"],
  adminBootstrapEmails: [],
  logIpSalt: `synthetic-log-${randomUUID()}`,
  auditLogRetentionDays: 365,
  auditLogRawIp: false,
  accessRequestReopenAfterDays: 30,
  enableRefreshTokens: true,
  siemExportEnabled: false,
  trustProxyHops: 0
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
  const legacyClientId = "nancy-entitlement-legacy-local";
  const legacySecret = `synthetic-legacy-${randomUUID()}`;
  await db.query(`INSERT INTO tool_clients (tool_id, client_id, client_secret_hash, status)
    VALUES ($1, $2, $3, 'active')`, [toolId, legacyClientId, await hashToolSecret(legacySecret, toolPepper)]);
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

  const google = new SyntheticGoogle();
  const legacyRepositories = new Repositories(db);
  const legacyTokenService = new TokenService(config);
  await legacyTokenService.init();
  const runtimeApp = await buildApplication({
    config, repositories: legacyRepositories, oauthRepository: foundation,
    oauthFlowRepository: new OAuthAuthorizationFlowRepository(db), oauthGoogle: google,
    oauthTokenService: new OAuthTokenLifecycleService({ config, repository: new OAuthTokenRepository(db) }),
    oauthAdminService: service, audit: new AuditLogger(legacyRepositories), google,
    tokenService: legacyTokenService
  });
  try {
    const callbackUri = "https://survey-test.unguess-internal.net/auth/callback";
    const authorizeUrl = (scope: string, verifier: string) => {
      const url = new URL(`${config.authIssuer}/oauth/authorize`);
      for (const [key, value] of Object.entries({
        response_type: "code", client_id: "nancy-vnext-bff-local", redirect_uri: callbackUri,
        scope, state: `synthetic-state-${randomUUID()}`, code_challenge: sha256(verifier),
        code_challenge_method: "S256", resource: resourceId
      })) url.searchParams.set(key, value);
      return `${url.pathname}${url.search}`;
    };
    const verifier = randomBytes(48).toString("base64url");
    const authorize = await runtimeApp.inject({ method: "GET", url: authorizeUrl("nancy:survey:read", verifier) });
    assert(authorize.statusCode === 302, "Nancy authorization did not redirect upstream");
    const upstream = new URL(String(authorize.headers.location));
    assert(upstream.hostname === "accounts.google.invalid", "unexpected upstream identity boundary");
    const callback = await runtimeApp.inject({ method: "GET",
      url: `/oauth/upstream/google/callback?state=${encodeURIComponent(upstream.searchParams.get("state") ?? "")}&code=synthetic-google-code` });
    assert(callback.statusCode === 302, "Nancy Google callback did not redirect downstream");
    const downstream = new URL(String(callback.headers.location));
    assert(downstream.origin + downstream.pathname === callbackUri && downstream.searchParams.get("iss") === config.authIssuer,
      "Nancy downstream redirect was not exact");
    const code = downstream.searchParams.get("code");
    assert(code, "Nancy callback did not issue a code");
    const token = await runtimeApp.inject({ method: "POST", url: "/oauth/token",
      headers: { "content-type": "application/x-www-form-urlencoded",
        authorization: basic("nancy-vnext-bff-local", rotatedClient.client_secret!) },
      payload: form({ grant_type: "authorization_code", code, redirect_uri: callbackUri,
        client_id: "nancy-vnext-bff-local", code_verifier: verifier, resource: resourceId }) });
    assert(token.statusCode === 200, "Admin-onboarded Nancy code exchange failed");
    const initialTokens = token.json<{ access_token: string; refresh_token: string; scope: string }>();
    assert(initialTokens.scope === "nancy:survey:read", "Nancy token scope mismatch");
    const tokenClaims = await jwtVerify(initialTokens.access_token, jwksOnlyKey, {
      algorithms: ["RS256"], issuer: config.authIssuer, audience: resourceId
    });
    assert(decodeProtectedHeader(initialTokens.access_token).kid === staged.kid &&
      tokenClaims.payload.client_id === "nancy-vnext-bff-local" && tokenClaims.payload.scope === "nancy:survey:read",
    "Nancy access-token kid/client/scope mismatch");

    const introspect = (username: string, secret: string, accessToken: string) => runtimeApp.inject({
      method: "POST", url: "/oauth/introspect",
      headers: { "content-type": "application/x-www-form-urlencoded", authorization: basic(username, secret) },
      payload: form({ token: accessToken, token_type_hint: "access_token" })
    });
    const active = await introspect(rotatedResource.resource_credential_id!,
      rotatedResource.resource_credential_secret!, initialTokens.access_token);
    assert(active.statusCode === 200 && active.json<{ active: boolean }>().active === true,
      "Nancy resource introspection not active");
    const mismatch = await service.createResource({
      resourceId: "https://other-local.unguess-internal.net/api", displayName: "Synthetic mismatch resource",
      ownerTeam: "nancy-local", ownerContact: null, status: "active",
      protectedResourceMetadataUrl: "https://other-local.unguess-internal.net/.well-known/oauth-protected-resource",
      legacyToolSlug: "nancy-entitlement-local", scopeMappings: [
        { scope: "nancy:survey:read", legacyPermissionKey: "nancy:survey:read" }
      ]
    }, ctx);
    const wrongAudience = await introspect(mismatch.resource_credential_id,
      mismatch.resource_credential_secret, initialTokens.access_token);
    assert(wrongAudience.statusCode === 200 && wrongAudience.json<{ active: boolean }>().active === false,
      "audience-mismatch introspection disclosed active state");
    const legacyResource = await introspect(legacyClientId, legacySecret, initialTokens.access_token);
    assert(legacyResource.statusCode !== 200, "legacy credential authenticated as OAuth resource");
    const oldResource = await introspect(resourceCreated.resource_credential_id,
      resourceCreated.resource_credential_secret, initialTokens.access_token);
    assert(oldResource.statusCode !== 200, "retired resource credential remained valid");

    const refresh = await runtimeApp.inject({ method: "POST", url: "/oauth/token",
      headers: { "content-type": "application/x-www-form-urlencoded",
        authorization: basic("nancy-vnext-bff-local", rotatedClient.client_secret!) },
      payload: form({ grant_type: "refresh_token", refresh_token: initialTokens.refresh_token,
        client_id: "nancy-vnext-bff-local", resource: resourceId }) });
    assert(refresh.statusCode === 200, "Nancy refresh failed");
    const refreshed = refresh.json<{ access_token: string; refresh_token: string }>();
    assert((await introspect(rotatedResource.resource_credential_id!,
      rotatedResource.resource_credential_secret!, refreshed.access_token)).json<{ active: boolean }>().active === true,
    "refreshed Nancy access token inactive");
    const oldClient = await runtimeApp.inject({ method: "POST", url: "/oauth/token",
      headers: { "content-type": "application/x-www-form-urlencoded",
        authorization: basic("nancy-vnext-bff-local", clientCreated.client_secret) },
      payload: form({ grant_type: "refresh_token", refresh_token: refreshed.refresh_token,
        client_id: "nancy-vnext-bff-local", resource: resourceId }) });
    assert(oldClient.statusCode !== 200, "retired client credential remained valid");
    const legacyClient = await runtimeApp.inject({ method: "POST", url: "/oauth/token",
      headers: { "content-type": "application/x-www-form-urlencoded", authorization: basic(legacyClientId, legacySecret) },
      payload: form({ grant_type: "refresh_token", refresh_token: refreshed.refresh_token,
        client_id: legacyClientId, resource: resourceId }) });
    assert(legacyClient.statusCode !== 200, "legacy credential authenticated as OAuth client");
    const revoked = await runtimeApp.inject({ method: "POST", url: "/oauth/revoke",
      headers: { "content-type": "application/x-www-form-urlencoded",
        authorization: basic("nancy-vnext-bff-local", rotatedClient.client_secret!) },
      payload: form({ token: refreshed.access_token, token_type_hint: "access_token" }) });
    assert(revoked.statusCode === 200, "Nancy revocation failed");
    assert((await introspect(rotatedResource.resource_credential_id!,
      rotatedResource.resource_credential_secret!, refreshed.access_token)).json<{ active: boolean }>().active === false,
    "revoked Nancy access token remained active");

    await db.query("UPDATE authorization_grants SET status = 'revoked' WHERE tool_id = $1 AND user_id = $2", [toolId, humanId]);
    const deniedAuthorize = await runtimeApp.inject({ method: "GET",
      url: authorizeUrl("nancy:survey:read", randomBytes(48).toString("base64url")) });
    assert(deniedAuthorize.statusCode === 302, "denied grant did not reach upstream identity boundary");
    const deniedUpstream = new URL(String(deniedAuthorize.headers.location));
    const deniedCallback = await runtimeApp.inject({ method: "GET",
      url: `/oauth/upstream/google/callback?state=${encodeURIComponent(deniedUpstream.searchParams.get("state") ?? "")}&code=synthetic-denied-code` });
    const deniedLocation = deniedCallback.headers.location ? new URL(String(deniedCallback.headers.location)) : null;
    assert(deniedCallback.statusCode !== 200 && !deniedLocation?.searchParams.get("code"),
      "revoked entitlement grant issued a code");
    await db.query("UPDATE authorization_grants SET status = 'active' WHERE tool_id = $1 AND user_id = $2", [toolId, humanId]);

    const assertAuthorizeDenied = async (label: string) => {
      const response = await runtimeApp.inject({ method: "GET",
        url: authorizeUrl("nancy:survey:read", randomBytes(48).toString("base64url")) });
      if (response.statusCode !== 302) return;
      const location = new URL(String(response.headers.location));
      if (location.hostname !== "accounts.google.invalid") {
        assert(!location.searchParams.get("code"), `${label} issued a code`);
        return;
      }
      const callbackResponse = await runtimeApp.inject({ method: "GET",
        url: `/oauth/upstream/google/callback?state=${encodeURIComponent(location.searchParams.get("state") ?? "")}&code=synthetic-denied-code` });
      const downstreamLocation = callbackResponse.headers.location
        ? new URL(String(callbackResponse.headers.location)) : null;
      assert(callbackResponse.statusCode !== 200 && !downstreamLocation?.searchParams.get("code"),
        `${label} issued a code`);
    };
    await service.updateScope(String(readScope.id), { status: "disabled" }, ctx);
    await assertAuthorizeDenied("disabled scope");
    await service.updateScope(String(readScope.id), { status: "active" }, ctx);
    await service.replaceAllowances(clientPk, [{ resourceId, scope: "nancy:survey:write" }], ctx);
    await assertAuthorizeDenied("removed client allowance");
    await service.replaceAllowances(clientPk, [
      { resourceId, scope: "nancy:survey:read" }, { resourceId, scope: "nancy:survey:write" }
    ], ctx);
    await service.updateRegistrationStatus("client", clientPk, "disabled", ctx);
    await assertAuthorizeDenied("disabled client");
    await service.updateRegistrationStatus("client", clientPk, "active", ctx);
    await service.updateRegistrationStatus("resource", resourcePk, "disabled", ctx);
    await assertAuthorizeDenied("disabled resource");
    await service.updateRegistrationStatus("resource", resourcePk, "active", ctx);
    await service.setEntitlementBinding(resourcePk, "nancy-entitlement-local", "disabled", ctx);
    await assertAuthorizeDenied("disabled entitlement binding");
    await service.setEntitlementBinding(resourcePk, "nancy-entitlement-local", "active", ctx);
  } finally {
    await runtimeApp.close();
  }

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
    clients: 1, resources: 2, allowances: 2, signing_keys: 1, admin_audit_events: audit.rows.length,
    checks: ["real_repository", "credential_rotation", "binding_lifecycle", "jwks_503_200",
      "publication_lead", "jwks_only_token_verification", "nancy_http_authorize_code_refresh_introspect_revoke",
      "nancy_negative_lifecycle", "legacy_credential_isolation", "secret_free_backup_and_audit"] }) + "\n");
} catch (error) {
  const safe = error && typeof error === "object" ? error as { name?: string; message?: string; code?: string; constraint?: string } : {};
  process.stderr.write(JSON.stringify({ result: "FAIL", error_type: safe.name ?? "unknown",
    assertion: safe.message?.startsWith("ASSERTION_FAILED:") ? safe.message : null,
    sqlstate: safe.code ?? null, constraint: safe.constraint ?? null }) + "\n");
  process.exitCode = 1;
} finally {
  await app.close();
  await db.close();
  const fromTmp = relative(tmpdir(), root);
  assert(fromTmp.startsWith(`access-layer-oauth-admin-`) && !fromTmp.includes(sep), "unsafe temporary root cleanup");
  await rm(root, { recursive: true, force: true });
}
