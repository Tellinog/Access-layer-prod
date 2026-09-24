import { Buffer } from "node:buffer";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import Fastify from "fastify";
import rateLimit from "@fastify/rate-limit";
import { decodeProtectedHeader, importJWK, jwtVerify } from "jose";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { Config } from "../src/types.js";
import type { OAuthAdminRepository } from "../src/oauth/admin-repository.js";
import { OAuthAdminService } from "../src/oauth/admin-service.js";
import type { OAuthAdminAuditContext } from "../src/oauth/admin-types.js";
import { verifyOAuthCredentialSecret } from "../src/security.js";
import { signCookie } from "../src/security.js";
import { selectOAuthJwks } from "../src/oauth/jwks.js";
import { OAuthAccessTokenSigner, verifyOAuthAccessToken, type OAuthSigningKeyRecord } from "../src/oauth/signing.js";
import { registerOAuthReadOnlyHttp } from "../src/oauth/http.js";
import type { OAuthFoundationRepository } from "../src/oauth/repository.js";
import { registerOAuthAdminHttp } from "../src/oauth/admin-http.js";
import { AppError, sendJsonError } from "../src/errors.js";
import type { Repositories } from "../src/repositories.js";
import type { TokenService } from "../src/token-service.js";

const config: Config = {
  appEnv: "test",
  appBaseUrl: "https://access-layer.unguess-internal.net",
  authIssuer: "https://access-layer.unguess-internal.net",
  publicBasePath: "",
  port: 8080,
  logLevel: "silent",
  databaseUrl: "postgresql://synthetic.invalid/access-layer",
  googleClientId: "synthetic.apps.googleusercontent.com",
  googleClientSecret: "synthetic-google-secret",
  googleRedirectUri: "https://access-layer.unguess-internal.net/v1/auth/google/callback",
  googleAllowedHd: ["example.invalid"],
  googleOidcScope: "openid email profile",
  jwtPublicKeyId: "synthetic-legacy-key",
  accessTokenTtlSeconds: 900,
  refreshTokenTtlSeconds: 28_800,
  oneTimeCodeTtlSeconds: 60,
  oauthP0Enabled: false,
  oauthTransactionProtectionKey: Buffer.alloc(32, 3),
  oauthCredentialSecretPepper: "synthetic-oauth-admin-pepper",
  sessionCookieName: "access_layer_admin_session",
  sessionSecret: "synthetic-session-secret",
  toolClientSecretPepper: "synthetic-legacy-tool-pepper",
  backupEncryptionKey: "synthetic-backup-encryption-key-000000",
  corsAllowedOrigins: [],
  returnUrlAllowedSchemes: ["https", "http"],
  adminBootstrapEmails: [],
  logIpSalt: "synthetic-log-salt",
  auditLogRetentionDays: 365,
  auditLogRawIp: false,
  accessRequestReopenAfterDays: 30,
  enableRefreshTokens: true,
  siemExportEnabled: false,
  trustProxyHops: 0
};

const actor: OAuthAdminAuditContext = {
  actor: {
    userId: "00000000-0000-4000-8000-000000000001",
    googleSub: "synthetic-admin-sub",
    email: "admin@example.invalid",
    hd: "example.invalid",
    role: "platform_admin",
    permissions: ["admin:oauth:read", "admin:oauth:write"],
    assignedToolIds: []
  },
  correlationId: "corr_synthetic_oauth_admin",
  requestIpHash: "synthetic-ip-hash",
  userAgentHash: "synthetic-agent-hash"
};

class MemoryOAuthAdminRepository {
  scopes = new Map<string, { id: string; status: "active" | "disabled" }>();
  clientHashes: string[] = [];
  resourceHashes: string[] = [];
  resourceCredentialIds: string[] = [];
  lastClient: unknown;
  lastResource: unknown;
  privateReference: string | null = null;
  key: OAuthSigningKeyRecord | null = null;

  async snapshot() {
    return { clients: [], clientCredentials: [], redirectUris: [], resources: [], resourceCredentials: [],
      scopes: [...this.scopes.entries()].map(([scope, row]) => ({ scope, ...row })), resourceScopes: [],
      allowances: [], entitlementBindings: [], signingKeys: this.key ? [{
        id: this.key.id, kid: this.key.kid, algorithm: this.key.algorithm, public_jwk: this.key.publicJwk,
        public_key_fingerprint_sha256: this.key.publicKeyFingerprintSha256, status: this.key.status,
        published_at: this.key.publishedAt, activates_at: this.key.activatesAt, last_signed_at: this.key.lastSignedAt,
        retire_after: this.key.retireAfter, retired_at: this.key.retiredAt
      }] : [] };
  }

  async createScope(input: { scope: string; description: string }) {
    if (this.scopes.has(input.scope)) throw new Error("duplicate");
    const row = { id: `scope-${this.scopes.size + 1}`, status: "active" as const };
    this.scopes.set(input.scope, row);
    return { ...row, ...input };
  }
  async updateScope() { return {}; }
  async resolveLegacyEntitlement(slug: string) {
    if (slug !== "nancy-entitlement") return null;
    return { legacy_tool_id: "legacy-tool-1", legacy_tool_slug: slug,
      registered_permission_keys: ["nancy:survey:read", "nancy:survey:write"] };
  }
  async findScopes(names: string[]) {
    return names.flatMap((scope) => {
      const found = this.scopes.get(scope);
      return found ? [{ ...found, scope }] : [];
    });
  }
  async createResource(input: unknown, credential: { id: string; secretHash: string }) {
    this.lastResource = input;
    this.resourceHashes.push(credential.secretHash);
    this.resourceCredentialIds.push(credential.id);
    return { id: "resource-1", resource_id: "https://survey-test.unguess-internal.net/api", status: "active" };
  }
  async createClient(input: unknown, secretHash: string) {
    this.lastClient = input;
    this.clientHashes.push(secretHash);
    return { id: "client-1", client_id: "nancy-vnext-bff-local", status: "active" };
  }
  async updateRegistrationStatus() { return {}; }
  async replaceRedirectUris() { return {}; }
  async replaceAllowances() { return {}; }
  async setResourceScope() { return {}; }
  async setEntitlementBinding() { return {}; }
  async rotateCredential(kind: "client" | "resource", _owner: string, generated: { id?: string; secretHash: string }) {
    if (kind === "client") this.clientHashes.push(generated.secretHash);
    else { this.resourceHashes.push(generated.secretHash); this.resourceCredentialIds.push(generated.id!); }
    return { id: `${kind}-credential-${kind === "client" ? this.clientHashes.length : this.resourceHashes.length}`, status: "active" };
  }
  async retireCredential() { return { status: "retired" }; }
  async insertSigningKey(input: { kid: string; publicJwk: Record<string, unknown>; fingerprint: string; protectedReference: string }) {
    this.privateReference = input.protectedReference;
    this.key = { id: "key-1", kid: input.kid, algorithm: "RS256", publicJwk: input.publicJwk,
      publicKeyFingerprintSha256: input.fingerprint, protectedPrivateKeyRef: input.protectedReference,
      status: "staged", publishedAt: null, activatesAt: null, lastSignedAt: null, retireAfter: null, retiredAt: null };
    return { id: this.key.id, kid: this.key.kid, algorithm: this.key.algorithm, public_jwk: this.key.publicJwk,
      public_key_fingerprint_sha256: this.key.publicKeyFingerprintSha256, status: this.key.status };
  }
  async publishSigningKey(_id: string, now: Date) {
    this.key = { ...this.key!, status: "published", publishedAt: now, activatesAt: new Date(now.getTime() + 300_000) };
    return { id: this.key.id, kid: this.key.kid, status: this.key.status, published_at: now, activates_at: this.key.activatesAt };
  }
  async activateSigningKey(_id: string, now: Date) {
    if (!this.key?.activatesAt || this.key.activatesAt > now) throw new Error("publication lead not satisfied");
    this.key = { ...this.key!, status: "active" };
    return { id: this.key.id, kid: this.key.kid, status: this.key.status };
  }
  async retireSigningKey() { return {}; }
  async disableSigningKey() { return {}; }
}

const tempRoots: string[] = [];
afterEach(async () => {
  await Promise.all(tempRoots.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

describe("OAuth P0 administration", () => {
  it("creates the synthetic Nancy registration with separate one-time client and resource credentials", async () => {
    const repository = new MemoryOAuthAdminRepository();
    const service = new OAuthAdminService({ config, repository: repository as unknown as OAuthAdminRepository });
    await service.createScope({ scope: "nancy:survey:read", description: "Read survey state" }, actor);
    await service.createScope({ scope: "nancy:survey:write", description: "Update survey state" }, actor);

    const resource = await service.createResource({
      resourceId: "https://survey-test.unguess-internal.net/api",
      displayName: "Nancy vNext synthetic resource",
      ownerTeam: "nancy",
      ownerContact: "nancy-owner@example.invalid",
      status: "active",
      protectedResourceMetadataUrl: "https://survey-test.unguess-internal.net/.well-known/oauth-protected-resource",
      legacyToolSlug: "nancy-entitlement",
      scopeMappings: [
        { scope: "nancy:survey:read", legacyPermissionKey: "nancy:survey:read" },
        { scope: "nancy:survey:write", legacyPermissionKey: "nancy:survey:write" }
      ]
    }, actor);
    const client = await service.createClient({
      clientId: "nancy-vnext-bff-local",
      clientName: "Nancy vNext synthetic confidential BFF",
      ownerTeam: "nancy",
      ownerContact: "nancy-owner@example.invalid",
      status: "active",
      grantTypes: ["authorization_code", "refresh_token"],
      redirectUris: ["https://survey-test.unguess-internal.net/auth/callback"],
      allowances: [
        { resourceId: "https://survey-test.unguess-internal.net/api", scope: "nancy:survey:read" },
        { resourceId: "https://survey-test.unguess-internal.net/api", scope: "nancy:survey:write" }
      ]
    }, actor);

    expect(repository.lastResource).toMatchObject({ legacyToolSlug: "nancy-entitlement" });
    expect(repository.lastClient).toMatchObject({ clientId: "nancy-vnext-bff-local" });
    expect(client.client_secret).toMatch(/^ocs_/);
    expect(resource.resource_credential_id).toMatch(/^orc_[a-f0-9]{36}$/);
    expect(resource.resource_credential_secret).toMatch(/^ors_/);
    expect(client.client_secret).not.toBe(resource.resource_credential_secret);
    expect(await verifyOAuthCredentialSecret(client.client_secret, config.oauthCredentialSecretPepper!, repository.clientHashes[0])).toBe(true);
    expect(await verifyOAuthCredentialSecret(resource.resource_credential_secret, config.oauthCredentialSecretPepper!, repository.resourceHashes[0])).toBe(true);
    expect(JSON.stringify(await service.snapshot())).not.toContain(client.client_secret);
    expect(JSON.stringify(await service.snapshot())).not.toContain(resource.resource_credential_secret);

    const rotated = await service.rotateCredential("client", "client-1", actor);
    expect(rotated.client_secret).not.toBe(client.client_secret);
    expect(await verifyOAuthCredentialSecret(rotated.client_secret!, config.oauthCredentialSecretPepper!, repository.clientHashes[1])).toBe(true);
    expect(await verifyOAuthCredentialSecret(client.client_secret, config.oauthCredentialSecretPepper!, repository.clientHashes[1])).toBe(false);
    const rotatedResource = await service.rotateCredential("resource", "resource-1", actor);
    expect(rotatedResource.resource_credential_id).toMatch(/^orc_[a-f0-9]{36}$/);
  });

  it("denies normal users and tool admins, enforces browser CSRF, and exposes the same-service UI only to authorised platform admins", async () => {
    let role = "tool_admin";
    let permissions = ["admin:oauth:read", "admin:oauth:write"];
    const repositories = {
      findUserByGoogleSub: async () => ({
        id: "admin-user", google_sub: "admin-sub", email: "admin@example.invalid",
        email_normalized: "admin@example.invalid", hd: "example.invalid", status: "active"
      }),
      findSessionById: async () => ({ id: "session-1", grant_id: "grant-1", status: "active" }),
      findGrantById: async () => ({
        id: "grant-1", role, permissions, status: "active",
        valid_from: new Date(Date.now() - 60_000), valid_until: null
      })
    } as unknown as Repositories;
    const tokenService = { verifyAccessToken: async () => ({ sub: "admin-sub", sid: "session-1" }) } as unknown as TokenService;
    let duplicate = false;
    const duplicateFailure = () => {
      if (duplicate) throw Object.assign(new Error("duplicate"), { code: "23505" });
    };
    const fakeService = {
      snapshot: async () => ({ clients: [], signingKeys: [] }),
      createScope: async (input: unknown) => { duplicateFailure(); return input; },
      createClient: async (input: unknown) => { duplicateFailure(); return input; },
      createResource: async (input: unknown) => { duplicateFailure(); return input; }
    } as unknown as OAuthAdminService;
    const app = Fastify({ logger: false });
    await app.register(rateLimit, { global: false });
    app.setErrorHandler((error, _request, reply) =>
      error instanceof AppError ? sendJsonError(reply, error) : sendJsonError(reply, new AppError("INTERNAL_ERROR", "corr_test")));
    registerOAuthAdminHttp(app, { config, repositories, tokenService, service: fakeService });
    const cookie = `${config.sessionCookieName}=${encodeURIComponent(signCookie("admin-token", config.sessionSecret))}`;

    expect((await app.inject({ method: "GET", url: "/v1/admin/oauth" })).statusCode).toBe(400);
    expect((await app.inject({ method: "GET", url: "/v1/admin/oauth", headers: { cookie } })).statusCode).toBe(403);
    role = "platform_admin";
    permissions = ["admin:oauth:read"];
    const ui = await app.inject({ method: "GET", url: "/admin/oauth", headers: { cookie } });
    expect(ui.statusCode).toBe(200);
    expect(ui.body).toContain("Temporary P0 compatibility state");
    for (const form of ["status-form", "redirect-form", "allowance-form", "mapping-form", "binding-form", "rotate-form", "retire-form", "scope-update-form"]) {
      expect(ui.body).toContain(`id="${form}"`);
    }
    expect(ui.body).not.toContain("private key textarea");
    expect((await app.inject({
      method: "POST", url: "/v1/admin/oauth/scopes", headers: { cookie, "content-type": "application/json" },
      payload: { scope: "nancy:survey:read", description: "Read" }
    })).statusCode).toBe(403);
    permissions = ["admin:oauth:read", "admin:oauth:write"];
    expect((await app.inject({
      method: "POST", url: "/v1/admin/oauth/scopes", headers: { cookie, "content-type": "application/json" },
      payload: { scope: "nancy:survey:read", description: "Read" }
    })).statusCode).toBe(403);
    expect((await app.inject({
      method: "POST", url: "/v1/admin/oauth/scopes",
      headers: { cookie, origin: "https://access-layer.unguess-internal.net", "content-type": "application/json" },
      payload: { scope: "nancy:survey:read", description: "Read" }
    })).statusCode).toBe(200);
    duplicate = true;
    const mutationHeaders = { cookie, origin: "https://access-layer.unguess-internal.net", "content-type": "application/json" };
    expect((await app.inject({ method: "POST", url: "/v1/admin/oauth/scopes", headers: mutationHeaders,
      payload: { scope: "nancy:survey:read", description: "Read" } })).statusCode).toBe(400);
    expect((await app.inject({ method: "POST", url: "/v1/admin/oauth/clients", headers: mutationHeaders,
      payload: { client_id: "nancy-vnext-bff-local", client_name: "Nancy", owner_team: "nancy", owner_contact: null,
        status: "active", grant_types: ["authorization_code"], redirect_uris: ["https://survey-test.unguess-internal.net/auth/callback"],
        allowances: [{ resource_id: "https://survey-test.unguess-internal.net/api", scope: "nancy:survey:read" }] } })).statusCode).toBe(400);
    expect((await app.inject({ method: "POST", url: "/v1/admin/oauth/resources", headers: mutationHeaders,
      payload: { resource_id: "https://survey-test.unguess-internal.net/api", display_name: "Nancy", owner_team: "nancy",
        owner_contact: null, status: "active", protected_resource_metadata_url: "https://survey-test.unguess-internal.net/meta",
        legacy_tool_slug: "nancy-entitlement", scope_mappings: [{ scope: "nancy:survey:read", legacy_permission_key: "nancy:survey:read" }] } })).statusCode).toBe(400);
    duplicate = false;
    expect((await app.inject({ method: "POST", url: "/v1/admin/oauth/resources", headers: mutationHeaders,
      payload: { resource_id: "https://survey-test.unguess-internal.net/api", display_name: "Nancy", owner_team: "nancy",
        owner_contact: null, status: "active", protected_resource_metadata_url: "https://survey-test.unguess-internal.net/meta",
        legacy_tool_slug: "nancy-entitlement", scope_mappings: [{ scope: "nancy:survey:read", legacy_permission_key: "nancy:survey:read", unexpected: "ignored?" }] } })).statusCode).toBe(400);
    let rateLimited = false;
    for (let attempt = 0; attempt < 31; attempt += 1) {
      const response = await app.inject({ method: "POST", url: "/v1/admin/oauth/scopes", headers: mutationHeaders,
        payload: { scope: "nancy:survey:read", description: "Read" } });
      if (response.statusCode === 429) { rateLimited = true; break; }
    }
    expect(rateLimited).toBe(true);
    await app.close();
  });

  it("generates, publishes and activates a dedicated key and proves JWKS-only token verification", async () => {
    const root = await mkdtemp(join(tmpdir(), "access-layer-oauth-admin-"));
    tempRoots.push(root);
    const repository = new MemoryOAuthAdminRepository();
    let now = new Date(Date.now() - 301_000);
    const service = new OAuthAdminService({
      config: { ...config, oauthSigningKeyRoot: root },
      repository: repository as unknown as OAuthAdminRepository,
      now: () => now
    });

    const generated = await service.generateSigningKey(actor);
    expect(JSON.stringify(generated)).not.toContain("PRIVATE KEY");
    expect(JSON.stringify(generated)).not.toContain(root);
    expect(repository.privateReference).not.toBeNull();
    expect(repository.privateReference).toMatch(/^file:\/\//);
    expect(await readFile(fileURLToPath(repository.privateReference!), "utf8")).toContain("PRIVATE KEY");
    const app = Fastify({ logger: false });
    registerOAuthReadOnlyHttp(app, {
      config: { ...config, oauthP0Enabled: true, oauthSigningKeyRoot: root },
      repository: { listSigningKeyPublicMetadata: async () => [repository.key!] } as unknown as OAuthFoundationRepository
    });
    expect((await app.inject({ method: "GET", url: "/oauth/jwks" })).statusCode).toBe(503);
    await service.publishSigningKey("key-1", actor);
    expect(selectOAuthJwks([repository.key!], now).keys).toHaveLength(1);
    await expect(service.activateSigningKey("key-1", actor)).rejects.toThrow("publication lead");
    now = new Date();
    await service.activateSigningKey("key-1", actor);

    const jwksResponse = await app.inject({ method: "GET", url: "/oauth/jwks" });
    expect(jwksResponse.statusCode).toBe(200);
    const jwks = jwksResponse.json<{ keys: Record<string, unknown>[] }>();
    expect(jwks.keys).toHaveLength(1);
    expect(jwks.keys[0]).toEqual(repository.key!.publicJwk);
    for (const privateField of ["d", "p", "q", "dp", "dq", "qi", "oth", "k"]) {
      expect(jwks.keys[0]).not.toHaveProperty(privateField);
    }

    const signer = new OAuthAccessTokenSigner({ issuer: config.authIssuer, signingKeyRoot: root });
    const issued = await signer.issue({
      key: repository.key!, subject: "synthetic-google-sub", audience: "https://survey-test.unguess-internal.net/api",
      clientId: "nancy-vnext-bff-local", scopes: ["nancy:survey:read"], sessionId: "oauth-session-1", now
    });
    expect(issued.token.split(".")).toHaveLength(3);
    expect(decodeProtectedHeader(issued.token).kid).toBe(repository.key!.kid);
    const publicKeyFromHttpJwks = await importJWK(jwks.keys[0] as Parameters<typeof importJWK>[0], "RS256");
    const jwksOnlyVerification = await jwtVerify(issued.token, publicKeyFromHttpJwks, {
      algorithms: ["RS256"], issuer: config.authIssuer,
      audience: "https://survey-test.unguess-internal.net/api", currentDate: now
    });
    expect(jwksOnlyVerification.payload.client_id).toBe("nancy-vnext-bff-local");
    const publicOnlyRecord = {
      id: repository.key!.id, kid: repository.key!.kid, algorithm: repository.key!.algorithm,
      publicJwk: jwks.keys[0], publicKeyFingerprintSha256: repository.key!.publicKeyFingerprintSha256,
      status: repository.key!.status, publishedAt: repository.key!.publishedAt,
      activatesAt: repository.key!.activatesAt, lastSignedAt: repository.key!.lastSignedAt,
      retireAfter: repository.key!.retireAfter, retiredAt: repository.key!.retiredAt
    };
    const verified = await verifyOAuthAccessToken({
      token: issued.token, issuer: config.authIssuer, audience: "https://survey-test.unguess-internal.net/api",
      keys: [publicOnlyRecord], now
    });
    expect(verified.client_id).toBe("nancy-vnext-bff-local");
    expect(verified.aud).toBe("https://survey-test.unguess-internal.net/api");
    expect(verified.scope).toBe("nancy:survey:read");
    expect(verified).not.toHaveProperty("email");
    await app.close();
  });

  it("rejects wildcard callbacks, unknown tools, unknown permission mappings and duplicate allowances", async () => {
    const repository = new MemoryOAuthAdminRepository();
    const service = new OAuthAdminService({ config, repository: repository as unknown as OAuthAdminRepository });
    await service.createScope({ scope: "nancy:survey:read", description: "Read" }, actor);
    await expect(service.createResource({
      resourceId: "https://survey-test.unguess-internal.net/api", displayName: "Nancy", ownerTeam: "nancy",
      ownerContact: null, status: "active", protectedResourceMetadataUrl: "https://survey-test.unguess-internal.net/meta",
      legacyToolSlug: "unknown-tool", scopeMappings: [{ scope: "nancy:survey:read", legacyPermissionKey: "nancy:survey:read" }]
    }, actor)).rejects.toMatchObject({ issues: ["legacy_tool_not_found"] });
    await expect(service.createResource({
      resourceId: "https://survey-test.unguess-internal.net/api", displayName: "Nancy", ownerTeam: "nancy",
      ownerContact: null, status: "active", protectedResourceMetadataUrl: "https://survey-test.unguess-internal.net/meta",
      legacyToolSlug: "nancy-entitlement", scopeMappings: [{ scope: "nancy:survey:read", legacyPermissionKey: "nancy:survey:delete" }]
    }, actor)).rejects.toMatchObject({ issues: expect.arrayContaining(["mapped_legacy_permission_not_registered"]) });
    await expect(service.createClient({
      clientId: "nancy-vnext-bff-local", clientName: "Nancy", ownerTeam: "nancy", ownerContact: null,
      status: "active", grantTypes: ["authorization_code"], redirectUris: ["https://*.unguess-internal.net/auth/callback"],
      allowances: [
        { resourceId: "https://survey-test.unguess-internal.net/api", scope: "nancy:survey:read" },
        { resourceId: "https://survey-test.unguess-internal.net/api", scope: "nancy:survey:read" }
      ]
    }, actor)).rejects.toMatchObject({ issues: expect.arrayContaining(["redirect_uri_invalid", "client_resource_scope_allowance_duplicate"]) });
  });

  it("returns a generated secret once without copying it into automatic request logs", async () => {
    const generatedSecret = "ocs_abcdefghijklmnopqrstuvwxyz012345";
    const repositories = {
      findUserByGoogleSub: async () => ({
        id: "admin-user", google_sub: "admin-sub", email: "admin@example.invalid",
        email_normalized: "admin@example.invalid", hd: "example.invalid", status: "active"
      }),
      findSessionById: async () => ({ id: "session-1", grant_id: "grant-1", status: "active" }),
      findGrantById: async () => ({
        id: "grant-1", role: "platform_admin", permissions: ["admin:oauth:read", "admin:oauth:write"], status: "active",
        valid_from: new Date(Date.now() - 60_000), valid_until: null
      })
    } as unknown as Repositories;
    const tokenService = { verifyAccessToken: async () => ({ sub: "admin-sub", sid: "session-1" }) } as unknown as TokenService;
    const service = {
      createClient: async () => ({ client: { id: "client-1" }, client_secret: generatedSecret })
    } as unknown as OAuthAdminService;
    const capturedWrites: string[] = [];
    const writeSpy = vi.spyOn(process.stdout, "write").mockImplementation(((chunk: string | Uint8Array) => {
      capturedWrites.push(String(chunk));
      return true;
    }) as typeof process.stdout.write);
    try {
      const app = Fastify({ logger: { level: "info" } });
      await app.register(rateLimit, { global: false });
      app.setErrorHandler((error, _request, reply) =>
        error instanceof AppError ? sendJsonError(reply, error) : sendJsonError(reply, new AppError("INTERNAL_ERROR", "corr_test")));
      registerOAuthAdminHttp(app, { config: { ...config, logLevel: "info" }, repositories, tokenService, service });
      const response = await app.inject({
        method: "POST",
        url: "/v1/admin/oauth/clients",
        headers: { authorization: "Bearer synthetic-admin", "content-type": "application/json" },
        payload: {
          client_id: "nancy-vnext-bff-local", client_name: "Nancy", owner_team: "nancy", owner_contact: null,
          status: "active", grant_types: ["authorization_code"],
          redirect_uris: ["https://survey-test.unguess-internal.net/auth/callback"],
          allowances: [{ resource_id: "https://survey-test.unguess-internal.net/api", scope: "nancy:survey:read" }]
        }
      });
      expect(response.statusCode).toBe(200);
      expect(response.body).toContain(generatedSecret);
      expect(response.headers["cache-control"]).toBe("no-store");
      await app.close();
    } finally {
      writeSpy.mockRestore();
    }
    expect(capturedWrites.join("\n")).not.toContain(generatedSecret);
  });
});
