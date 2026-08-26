import { generateKeyPairSync } from "node:crypto";
import { SignJWT } from "jose";
import { describe, expect, it } from "vitest";
import { TokenService } from "../src/token-service.js";
import type { AuthorizationGrant, Config, Session, Tool, User } from "../src/types.js";

const config: Config = {
  appEnv: "test",
  appBaseUrl: "http://localhost:8080",
  authIssuer: "http://localhost:8080",
  publicBasePath: "",
  port: 8080,
  logLevel: "silent",
  databaseUrl: "postgresql://test",
  googleClientId: "test-client.apps.googleusercontent.com",
  googleClientSecret: "test-client-secret",
  googleRedirectUri: "http://localhost:8080/v1/auth/google/callback",
  googleAllowedHd: ["unguess.io"],
  googleOidcScope: "openid email profile",
  jwtPublicKeyId: "test-key",
  accessTokenTtlSeconds: 900,
  refreshTokenTtlSeconds: 28800,
  oneTimeCodeTtlSeconds: 60,
  oauthP0Enabled: false,
  sessionCookieName: "access_layer_admin_session",
  sessionSecret: "session-secret",
  toolClientSecretPepper: "pepper",
  backupEncryptionKey: "backup-encryption-key-with-32-chars",
  corsAllowedOrigins: [],
  returnUrlAllowedSchemes: ["https", "http"],
  adminBootstrapEmails: [],
  logIpSalt: "log-salt",
  auditLogRetentionDays: 365,
  auditLogRawIp: false,
  accessRequestReopenAfterDays: 30,
  enableRefreshTokens: true,
  siemExportEnabled: false,
  trustProxyHops: 0
};

function makeTokenInput(): { user: User; tool: Tool; grant: AuthorizationGrant; session: Session } {
  const user = {
    id: "usr",
    google_sub: "110000000000000000000",
    email: "mario.rossi@unguess.io",
    email_normalized: "mario.rossi@unguess.io",
    email_verified: true,
    hd: "unguess.io",
    display_name: "Mario Rossi",
    picture_url: null,
    status: "active",
    first_seen_at: new Date(),
    last_seen_at: new Date()
  } satisfies User;
  const tool = {
    id: "tool",
    slug: "crm",
    display_name: "CRM interno",
    description: null,
    status: "active",
    allowed_return_urls: ["https://crm.draftapps.it/auth/callback"],
    owner_email: null,
    created_at: new Date(),
    updated_at: new Date()
  } satisfies Tool;
  const grant = {
    id: "grant",
    tool_id: "tool",
    user_id: "usr",
    email_normalized: null,
    role: "tool_user",
    permissions: ["crm:read"],
    status: "active",
    valid_from: new Date(),
    valid_until: null,
    created_by_user_id: null
  } satisfies AuthorizationGrant;
  const session = {
    id: "session",
    user_id: "usr",
    tool_id: "tool",
    grant_id: "grant",
    status: "active",
    issued_at: new Date(),
    expires_at: new Date(Date.now() + 1000),
    revoked_at: null
  } satisfies Session;

  return { user, tool, grant, session };
}

describe("TokenService", () => {
  it("issues tool-scoped JWTs and publishes JWKS", async () => {
    const service = new TokenService(config);
    await service.init();
    const { user, tool, grant, session } = makeTokenInput();

    const issued = await service.issueAccessToken({ user, tool, grant, session });
    const claims = await service.verifyAccessToken(issued.token, "crm");

    expect(claims.sub).toBe(user.google_sub);
    expect(claims.aud).toBe("crm");
    expect(claims.sid).toBe(session.id);
    expect(claims.permissions).toEqual(["crm:read"]);
    expect(service.getJwks().keys[0].kid).toBe("test-key");
    await expect(service.verifyAccessToken(issued.token, "reporting")).rejects.toThrow();
  });

  it("rejects expired JWTs", async () => {
    const service = new TokenService({ ...config, accessTokenTtlSeconds: -1 });
    await service.init();
    const issued = await service.issueAccessToken(makeTokenInput());

    await expect(service.verifyAccessToken(issued.token, "crm")).rejects.toThrow();
  });

  it("rejects JWTs signed by an unknown key", async () => {
    const service = new TokenService(config);
    await service.init();
    const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const now = Math.floor(Date.now() / 1000);
    const forged = await new SignJWT({
      sid: "session",
      tool_slug: "crm",
      email: "mario.rossi@unguess.io",
      hd: "unguess.io",
      permissions: ["crm:read"],
      role: "tool_user"
    })
      .setProtectedHeader({ alg: "RS256", kid: "unknown-key", typ: "JWT" })
      .setIssuer(config.authIssuer)
      .setSubject("110000000000000000000")
      .setAudience("crm")
      .setIssuedAt(now)
      .setExpirationTime(now + 900)
      .setJti("jti_forged")
      .sign(privateKey);

    await expect(service.verifyAccessToken(forged, "crm")).rejects.toThrow();
  });
});
