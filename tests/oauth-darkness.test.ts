import { afterEach, describe, expect, it } from "vitest";
import { buildApp } from "../src/app.js";
import type { AuditLogger } from "../src/audit.js";
import type { GoogleOidcClient } from "../src/google.js";
import type { Repositories } from "../src/repositories.js";
import type { TokenService } from "../src/token-service.js";
import type { Config } from "../src/types.js";

const baseConfig: Config = {
  appEnv: "test",
  appBaseUrl: "http://localhost:8080",
  authIssuer: "http://localhost:8080",
  publicBasePath: "",
  port: 8080,
  logLevel: "silent",
  databaseUrl: "postgresql://synthetic.invalid/access-layer",
  googleClientId: "synthetic.apps.googleusercontent.com",
  googleClientSecret: "synthetic-google-secret",
  googleRedirectUri: "http://localhost:8080/v1/auth/google/callback",
  googleAllowedHd: ["example.invalid"],
  googleOidcScope: "openid email profile",
  jwtPublicKeyId: "synthetic-legacy-key",
  accessTokenTtlSeconds: 900,
  refreshTokenTtlSeconds: 28800,
  oneTimeCodeTtlSeconds: 60,
  oauthP0Enabled: false,
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

const openApps: Awaited<ReturnType<typeof buildApp>>[] = [];

async function appWithFlag(oauthP0Enabled: boolean) {
  const app = await buildApp({
    config: { ...baseConfig, oauthP0Enabled },
    repositories: {} as Repositories,
    audit: {} as AuditLogger,
    google: {} as GoogleOidcClient,
    tokenService: {} as TokenService
  });
  openApps.push(app);
  return app;
}

afterEach(async () => {
  await Promise.all(openApps.splice(0).map((app) => app.close()));
});

describe("Step 3A OAuth darkness", () => {
  it("keeps the registered legacy route inventory identical when the flag changes", async () => {
    const disabled = await appWithFlag(false);
    const enabled = await appWithFlag(true);

    expect(enabled.printRoutes()).toBe(disabled.printRoutes());
    expect(enabled.printRoutes()).not.toMatch(/\/oauth\/|oauth-authorization-server|oauth-protected-resource/i);
  });

  it.each([
    ["GET", "/.well-known/oauth-authorization-server"],
    ["GET", "/.well-known/oauth-protected-resource/v1"],
    ["GET", "/oauth/authorize"],
    ["POST", "/oauth/token"],
    ["POST", "/oauth/revoke"],
    ["POST", "/oauth/introspect"],
    ["GET", "/oauth/jwks"],
    ["GET", "/oauth/upstream/google/callback"]
  ] as const)("does not expose %s %s even when OAUTH_P0_ENABLED=true", async (method, url) => {
    const app = await appWithFlag(true);
    const response = await app.inject({ method, url });
    expect(response.statusCode).toBe(404);
  });
});
