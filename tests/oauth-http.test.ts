import { Buffer } from "node:buffer";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { buildApplication } from "../src/application.js";
import type { AuditLogger } from "../src/audit.js";
import type { OAuthAuthorizationFlowRepository } from "../src/oauth/flow-repository.js";
import type { OAuthUpstreamGoogleClient } from "../src/oauth/google.js";
import type { OAuthFoundationRepository } from "../src/oauth/repository.js";
import {
  OAUTH_BASIC_CHALLENGE,
  OAUTH_FORM_BODY_LIMIT_BYTES,
  parseOAuthBasicAuthorization,
  parseOAuthForm,
  type OAuthTokenHttpService
} from "../src/oauth/token-http.js";
import { OAuthCoreError, type OAuthIntrospectionResult, type OAuthTokenResponseMaterial } from "../src/oauth/token-service.js";
import type { GoogleOidcClient } from "../src/google.js";
import type { Repositories } from "../src/repositories.js";
import type { TokenService } from "../src/token-service.js";
import type { Config } from "../src/types.js";

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
  refreshTokenTtlSeconds: 28800,
  oneTimeCodeTtlSeconds: 60,
  oauthP0Enabled: true,
  oauthTransactionProtectionKey: Buffer.alloc(32, 7),
  oauthCredentialSecretPepper: "synthetic-oauth-only-pepper",
  oauthSigningKeyRoot: "C:\\synthetic-oauth-keys",
  sessionCookieName: "access_layer_admin_session",
  sessionSecret: "synthetic-session-secret",
  toolClientSecretPepper: "synthetic-tool-pepper",
  backupEncryptionKey: "synthetic-backup-encryption-key-000000",
  corsAllowedOrigins: [],
  returnUrlAllowedSchemes: ["https", "http"],
  adminBootstrapEmails: [],
  logIpSalt: "synthetic-log-ip-salt",
  auditLogRetentionDays: 365,
  auditLogRawIp: false,
  accessRequestReopenAfterDays: 30,
  enableRefreshTokens: true,
  siemExportEnabled: false,
  trustProxyHops: 0
};

const tokenMaterial: OAuthTokenResponseMaterial = {
  accessToken: "synthetic-access-token",
  tokenType: "Bearer",
  expiresIn: 900,
  refreshToken: "synthetic-refresh-token",
  scope: "synthetic:records:read"
};

function basic(username: string, password: string): string {
  const encodedUsername = encodeURIComponent(username).replace(/%20/g, "+");
  const encodedPassword = encodeURIComponent(password).replace(/%20/g, "+");
  return `Basic ${Buffer.from(`${encodedUsername}:${encodedPassword}`).toString("base64")}`;
}

function form(values: Record<string, string>): string {
  return Object.entries(values).map(([name, value]) => `${encodeURIComponent(name)}=${encodeURIComponent(value)}`).join("&");
}

class FakeOAuthTokenService implements OAuthTokenHttpService {
  exchangeAuthorizationCode = vi.fn(async (): Promise<OAuthTokenResponseMaterial> => tokenMaterial);
  refresh = vi.fn(async (): Promise<OAuthTokenResponseMaterial> => tokenMaterial);
  revoke = vi.fn(async (): Promise<void> => undefined);
  introspect = vi.fn(async (): Promise<OAuthIntrospectionResult> => ({ active: false }));
}

const openApps: Awaited<ReturnType<typeof buildApplication>>[] = [];

async function testApp(service: OAuthTokenHttpService, oauthP0Enabled = true) {
  const app = await buildApplication({
    config: { ...config, oauthP0Enabled },
    repositories: {} as Repositories,
    audit: {} as AuditLogger,
    google: {} as GoogleOidcClient,
    tokenService: { getJwks: () => ({ keys: [] }) } as unknown as TokenService,
    oauthRepository: {} as OAuthFoundationRepository,
    oauthFlowRepository: {} as OAuthAuthorizationFlowRepository,
    oauthGoogle: {} as OAuthUpstreamGoogleClient,
    oauthTokenService: service
  });
  openApps.push(app);
  return app;
}

afterEach(async () => {
  await Promise.all(openApps.splice(0).map((app) => app.close()));
});

describe("Step 3E strict form and Basic parsing", () => {
  it("decodes form components once and rejects malformed UTF-8, percent escapes, and duplicate names", () => {
    expect(parseOAuthForm(Buffer.from("client_id=client.one&scope=synthetic%3Arecords%3Aread+synthetic%3Arecords%3Awrite")))
      .toEqual({ client_id: "client.one", scope: "synthetic:records:read synthetic:records:write" });
    for (const body of ["client_id=a&client_id=b", "client_id=%", "client_id=%GG", "=value", "client_id=%FF"]) {
      expect(() => parseOAuthForm(Buffer.from(body))).toThrow("invalid_request");
    }
  });

  it("requires canonical Basic and form-decodes encoded credential components", () => {
    expect(parseOAuthBasicAuthorization(basic("client.id", "p@ss:word")))
      .toEqual({ username: "client.id", password: "p@ss:word" });
    expect(parseOAuthBasicAuthorization(basic("client.id", "space value").replace("Basic", "bAsIc")))
      .toEqual({ username: "client.id", password: "space value" });
    for (const value of ["Bearer abc", "Basic !!!=", `Basic ${Buffer.from("missing-colon").toString("base64")}`, `Basic ${Buffer.from("a:b:c").toString("base64")}`]) {
      expect(() => parseOAuthBasicAuthorization(value)).toThrow("invalid_client");
    }
  });

  it("rejects wrong media types, duplicate/unknown fields, empty required values, and oversized bodies", async () => {
    const service = new FakeOAuthTokenService();
    const app = await testApp(service);
    const requests = [
      { headers: { "content-type": "application/json" }, payload: JSON.stringify({ grant_type: "authorization_code" }) },
      { headers: { "content-type": "application/x-www-form-urlencoded" }, payload: "grant_type=authorization_code&code=a&code=b" },
      { headers: { "content-type": "application/x-www-form-urlencoded" }, payload: "grant_type=authorization_code&client_secret=forbidden" },
      { headers: { "content-type": "application/x-www-form-urlencoded" }, payload: "grant_type=authorization_code&code=" },
      { headers: { "content-type": "application/x-www-form-urlencoded" }, payload: `grant_type=authorization_code&code=${"a".repeat(OAUTH_FORM_BODY_LIMIT_BYTES)}` }
    ];
    for (const request of requests) {
      const response = await app.inject({ method: "POST", url: "/oauth/token", ...request });
      expect(response.statusCode).toBe(400);
      expect(response.json()).toEqual({ error: "invalid_request" });
      expect(response.headers["cache-control"]).toBe("no-store");
    }
    expect(service.exchangeAuthorizationCode).not.toHaveBeenCalled();
  });
});

describe("Step 3E token HTTP mapping", () => {
  it("maps confidential code exchange to exact service inputs and exact token wire fields/headers", async () => {
    const service = new FakeOAuthTokenService();
    const app = await testApp(service);
    const payload = form({
      grant_type: "authorization_code",
      code: "raw-code-material",
      redirect_uri: "https://client.invalid/callback",
      client_id: "client.one",
      code_verifier: "a".repeat(43),
      resource: "https://resource.invalid/api"
    });
    const response = await app.inject({
      method: "POST", url: "/oauth/token", payload,
      headers: { "content-type": "application/x-www-form-urlencoded", authorization: basic("client.one", "secret:value") }
    });
    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({
      access_token: "synthetic-access-token", token_type: "Bearer", expires_in: 900,
      refresh_token: "synthetic-refresh-token", scope: "synthetic:records:read"
    });
    expect(response.headers["cache-control"]).toBe("no-store");
    expect(response.headers.pragma).toBe("no-cache");
    expect(service.exchangeAuthorizationCode).toHaveBeenCalledWith({
      code: "raw-code-material", clientId: "client.one", clientSecret: "secret:value",
      redirectUri: "https://client.invalid/callback", resource: "https://resource.invalid/api",
      codeVerifier: "a".repeat(43)
    });
  });

  it("enforces Basic/body identity match while preserving the registered public-none boundary", async () => {
    const service = new FakeOAuthTokenService();
    const app = await testApp(service);
    const values = {
      grant_type: "authorization_code", code: "code", redirect_uri: "https://client.invalid/callback",
      client_id: "client.public", code_verifier: "a".repeat(43), resource: "https://resource.invalid/api"
    };
    const mismatch = await app.inject({
      method: "POST", url: "/oauth/token", payload: form(values),
      headers: { "content-type": "application/x-www-form-urlencoded", authorization: basic("client.other", "secret") }
    });
    expect(mismatch.statusCode).toBe(401);
    expect(mismatch.headers["www-authenticate"]).toBe(OAUTH_BASIC_CHALLENGE);
    expect(service.exchangeAuthorizationCode).not.toHaveBeenCalled();

    const publicResponse = await app.inject({
      method: "POST", url: "/oauth/token", payload: form(values),
      headers: { "content-type": "application/x-www-form-urlencoded" }
    });
    expect(publicResponse.statusCode).toBe(200);
    expect(service.exchangeAuthorizationCode).toHaveBeenCalledWith(expect.objectContaining({ clientSecret: null }));
  });

  it.each([
    ["invalid_client", 401], ["invalid_grant", 400], ["invalid_scope", 400],
    ["invalid_target", 400], ["temporarily_unavailable", 503]
  ] as const)("maps %s to sanitized HTTP %i", async (code, status) => {
    const service = new FakeOAuthTokenService();
    service.exchangeAuthorizationCode.mockRejectedValueOnce(new OAuthCoreError(code));
    const app = await testApp(service);
    const response = await app.inject({
      method: "POST", url: "/oauth/token",
      headers: { "content-type": "application/x-www-form-urlencoded", authorization: basic("client.one", "never-disclose-me") },
      payload: form({ grant_type: "authorization_code", code: "never-disclose-code", redirect_uri: "https://client.invalid/callback", client_id: "client.one", code_verifier: "v".repeat(43), resource: "https://resource.invalid/api" })
    });
    expect(response.statusCode).toBe(status);
    expect(response.json()).toEqual({ error: code });
    expect(response.body).not.toContain("never-disclose");
    expect(response.headers["cache-control"]).toBe("no-store");
    if (code === "invalid_client") expect(response.headers["www-authenticate"]).toBe(OAUTH_BASIC_CHALLENGE);
  });

  it("passes equal/narrow refresh scope without exposing refresh material", async () => {
    const service = new FakeOAuthTokenService();
    const app = await testApp(service);
    const response = await app.inject({
      method: "POST", url: "/oauth/token",
      headers: { "content-type": "application/x-www-form-urlencoded", authorization: basic("client.one", "secret") },
      payload: form({ grant_type: "refresh_token", refresh_token: "raw-refresh", client_id: "client.one", resource: "https://resource.invalid/api", scope: "synthetic:records:read" })
    });
    expect(response.statusCode).toBe(200);
    expect(service.refresh).toHaveBeenCalledWith({
      refreshToken: "raw-refresh", clientId: "client.one", clientSecret: "secret",
      resource: "https://resource.invalid/api", scope: "synthetic:records:read"
    });
  });
});

describe("Step 3E revocation, introspection, discovery, and rate limits", () => {
  it("keeps revocation hints advisory and unknown-token success externally idempotent", async () => {
    const service = new FakeOAuthTokenService();
    const app = await testApp(service);
    const response = await app.inject({
      method: "POST", url: "/oauth/revoke",
      headers: { "content-type": "application/x-www-form-urlencoded", authorization: basic("client.one", "secret") },
      payload: form({ token: "unknown-token", token_type_hint: "unknown_hint" })
    });
    expect(response.statusCode).toBe(200);
    expect(response.body).toBe("");
    expect(response.headers["cache-control"]).toBe("no-store");
    expect(service.revoke).toHaveBeenCalledWith({ token: "unknown-token", tokenTypeHint: "unknown_hint", clientId: "client.one", clientSecret: "secret" });
  });

  it("requires resource-owned Basic introspection and preserves exact inactive/active shapes", async () => {
    const service = new FakeOAuthTokenService();
    const app = await testApp(service);
    const missing = await app.inject({
      method: "POST", url: "/oauth/introspect",
      headers: { "content-type": "application/x-www-form-urlencoded" }, payload: form({ token: "candidate" })
    });
    expect(missing.statusCode).toBe(401);
    expect(missing.headers["www-authenticate"]).toBe(OAUTH_BASIC_CHALLENGE);

    const inactive = await app.inject({
      method: "POST", url: "/oauth/introspect",
      headers: { "content-type": "application/x-www-form-urlencoded", authorization: basic("resource.credential", "resource-secret") },
      payload: form({ token: "refresh-or-unknown", token_type_hint: "refresh_token" })
    });
    expect(inactive.statusCode).toBe(200);
    expect(inactive.json()).toEqual({ active: false });

    service.introspect.mockResolvedValueOnce({
      active: true, iss: config.authIssuer, sub: "google-sub", aud: "https://resource.invalid/api",
      client_id: "client.one", scope: "synthetic:records:read", exp: 1800000900, iat: 1800000000,
      jti: "synthetic-jti", sid: "synthetic-session", token_type: "Bearer"
    });
    const active = await app.inject({
      method: "POST", url: "/oauth/introspect",
      headers: { "content-type": "application/x-www-form-urlencoded", authorization: basic("resource.credential", "resource-secret") },
      payload: form({ token: "access-token" })
    });
    expect(active.json()).toMatchObject({ active: true, aud: "https://resource.invalid/api", token_type: "Bearer" });
    expect(active.headers["cache-control"]).toBe("no-store");
  });

  it("serves exact issuer-preserving RFC 8414 discovery without HEAD or P1/Google fields", async () => {
    const service = new FakeOAuthTokenService();
    const app = await testApp(service);
    const response = await app.inject({ method: "GET", url: "/.well-known/oauth-authorization-server" });
    const expected = JSON.parse(readFileSync(resolve(import.meta.dirname, "../examples/oauth/authorization-server-metadata.expected.json"), "utf8"));
    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual(expected);
    expect(response.headers["cache-control"]).toBe("public, max-age=300");
    expect(response.body).not.toContain("google");
    expect(response.body).not.toContain("client_credentials");
    expect((await app.inject({ method: "HEAD", url: "/.well-known/oauth-authorization-server" })).statusCode).toBe(404);
  });

  it("keeps code and refresh rate limits in separate buckets using non-disclosing responses", async () => {
    const service = new FakeOAuthTokenService();
    const app = await testApp(service);
    const codePayload = form({ grant_type: "authorization_code", code: "rate-secret-code", redirect_uri: "https://client.invalid/callback", client_id: "client.one", code_verifier: "v".repeat(43), resource: "https://resource.invalid/api" });
    let response;
    for (let index = 0; index < 21; index += 1) {
      response = await app.inject({ method: "POST", url: "/oauth/token", headers: { "content-type": "application/x-www-form-urlencoded" }, payload: codePayload });
    }
    expect(response?.statusCode).toBe(503);
    expect(response?.json()).toEqual({ error: "temporarily_unavailable" });
    expect(response?.body).not.toContain("rate-secret-code");
    expect(service.exchangeAuthorizationCode).toHaveBeenCalledTimes(20);

    const refresh = await app.inject({
      method: "POST", url: "/oauth/token", headers: { "content-type": "application/x-www-form-urlencoded" },
      payload: form({ grant_type: "refresh_token", refresh_token: "rate-secret-refresh", client_id: "client.one", resource: "https://resource.invalid/api" })
    });
    expect(refresh.statusCode).toBe(200);
    expect(service.refresh).toHaveBeenCalledTimes(1);
  });
});
