import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { buildApplication } from "../src/application.js";
import { buildApp } from "../src/app.js";
import type { AuditLogger } from "../src/audit.js";
import type { Db } from "../src/db.js";
import type { GoogleOidcClient } from "../src/google.js";
import { selectOAuthJwks } from "../src/oauth/jwks.js";
import {
  buildOAuthAuthorizationServerMetadata,
  buildOAuthProtectedResourceMetadata
} from "../src/oauth/metadata.js";
import { OAuthFoundationRepository } from "../src/oauth/repository.js";
import type { OAuthSigningKeyPublicMetadata } from "../src/oauth/types.js";
import type { Repositories } from "../src/repositories.js";
import type { TokenService } from "../src/token-service.js";
import type { Config } from "../src/types.js";

const root = resolve(import.meta.dirname, "..");
const frozenAuthorizationServerMetadata = JSON.parse(readFileSync(
  resolve(root, "examples/oauth/authorization-server-metadata.expected.json"), "utf8"
));
const frozenProtectedResourceMetadata = JSON.parse(readFileSync(
  resolve(root, "examples/oauth/oauth-protected-resource-metadata.json"), "utf8"
));

const baseConfig: Config = {
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

const legacyJwks = {
  keys: [{ kty: "RSA", kid: "synthetic-legacy-key", use: "sig", alg: "RS256", n: "legacy-n", e: "AQAB" }]
};

class SigningMetadataDb implements Db {
  readonly calls: string[] = [];

  constructor(
    private readonly rows: Record<string, unknown>[] = [],
    private readonly failure: Error | null = null
  ) {}

  async query<T>(sql: string): Promise<{ rows: T[]; rowCount: number } & never> {
    this.calls.push(sql);
    if (this.failure) throw this.failure;
    return { rows: this.rows as T[], rowCount: this.rows.length } as { rows: T[]; rowCount: number } & never;
  }

  async transaction<T>(fn: (db: Db) => Promise<T>): Promise<T> {
    return fn(this);
  }

  async close(): Promise<void> {}
}

function signingKey(
  kid: string,
  overrides: Partial<OAuthSigningKeyPublicMetadata> = {}
): OAuthSigningKeyPublicMetadata {
  return {
    id: `synthetic-${kid}`,
    kid,
    algorithm: "RS256",
    publicJwk: { kty: "RSA", kid, alg: "RS256", use: "sig", n: `n-${kid}`, e: "AQAB" },
    publicKeyFingerprintSha256: "a".repeat(64),
    status: "active",
    publishedAt: new Date("2026-08-26T00:00:00Z"),
    activatesAt: new Date("2026-08-26T00:05:00Z"),
    lastSignedAt: new Date("2026-08-26T00:06:00Z"),
    retireAfter: new Date("2026-08-26T00:27:00Z"),
    retiredAt: null,
    ...overrides
  };
}

function databaseRow(key: OAuthSigningKeyPublicMetadata): Record<string, unknown> {
  return {
    id: key.id,
    kid: key.kid,
    algorithm: key.algorithm,
    public_jwk: key.publicJwk,
    public_key_fingerprint_sha256: key.publicKeyFingerprintSha256,
    status: key.status,
    published_at: key.publishedAt,
    activates_at: key.activatesAt,
    last_signed_at: key.lastSignedAt,
    retire_after: key.retireAfter,
    retired_at: key.retiredAt
  };
}

const openApps: Awaited<ReturnType<typeof buildApp>>[] = [];

async function applicationWithFlag(
  oauthP0Enabled: boolean,
  keys: OAuthSigningKeyPublicMetadata[] = [],
  failure: Error | null = null
) {
  const db = new SigningMetadataDb(keys.map(databaseRow), failure);
  const common = {
    config: { ...baseConfig, oauthP0Enabled },
    repositories: {} as Repositories,
    audit: {} as AuditLogger,
    google: {} as GoogleOidcClient,
    tokenService: { getJwks: () => legacyJwks } as unknown as TokenService
  };
  const app = await buildApplication({ ...common, oauthRepository: new OAuthFoundationRepository(db) });
  openApps.push(app);
  return { app, db, common };
}

afterEach(async () => {
  await Promise.all(openApps.splice(0).map((app) => app.close()));
});

describe("Step 3B OAuth metadata builders", () => {
  it("builds the exact frozen RFC 8414 payload without mounting its route", () => {
    expect(buildOAuthAuthorizationServerMetadata(baseConfig.authIssuer))
      .toEqual(frozenAuthorizationServerMetadata);
  });

  it("builds the exact frozen RFC 9728 header-only Bearer payload", () => {
    expect(buildOAuthProtectedResourceMetadata({
      resource: `${baseConfig.appBaseUrl}/v1`,
      authorizationServer: baseConfig.authIssuer,
      scopesSupported: [],
      resourceName: "Access Layer API target metadata (OAuth disabled)"
    })).toEqual(frozenProtectedResourceMetadata);
  });
});

describe("Step 3B OAuth JWKS selection", () => {
  const now = new Date("2026-08-26T00:10:00Z");

  it("publishes valid active and pre-activation overlap keys in deterministic kid order", () => {
    const published = signingKey("z-published", {
      status: "published",
      publishedAt: new Date("2026-08-26T00:00:00Z"),
      activatesAt: new Date("2026-08-26T00:15:00Z"),
      lastSignedAt: null,
      retireAfter: null
    });
    const active = signingKey("a-active");
    expect(selectOAuthJwks([published, active], now)).toEqual({
      keys: [active.publicJwk, published.publicJwk]
    });
  });

  it("excludes staged, disabled, retired, malformed-JWK, incoherent, and future-published records", () => {
    const retired = signingKey("retired", {
      status: "retired",
      retiredAt: new Date("2026-08-26T00:27:00Z")
    });
    const malformedJwk = signingKey("malformed-jwk", {
      publicJwk: { kty: "RSA", kid: "malformed-jwk", alg: "RS256", use: "sig", e: "AQAB" }
    });
    const incoherent = signingKey("incoherent", {
      activatesAt: new Date("2026-08-26T00:04:59Z")
    });
    const futurePublished = signingKey("future-published", {
      status: "published",
      publishedAt: new Date("2026-08-26T00:11:00Z"),
      activatesAt: new Date("2026-08-26T00:16:00Z"),
      lastSignedAt: null,
      retireAfter: null
    });
    expect(selectOAuthJwks([
      signingKey("staged", {
        status: "staged", publishedAt: null, activatesAt: null, lastSignedAt: null, retireAfter: null
      }),
      signingKey("disabled", { status: "disabled" }),
      retired,
      malformedJwk,
      incoherent,
      futurePublished
    ], now)).toEqual({ keys: [] });
  });
});

describe("Step 3B OAuth dark HTTP composition", () => {
  it("keeps the legacy route inventory exact and every new path 404 when the flag is false", async () => {
    const { app, common } = await applicationWithFlag(false);
    const legacyOnly = await buildApp(common);
    openApps.push(legacyOnly);
    expect(app.printRoutes()).toBe(legacyOnly.printRoutes());
    for (const url of ["/oauth/jwks", "/.well-known/oauth-protected-resource/v1", "/.well-known/oauth-authorization-server"]) {
      expect((await app.inject({ method: "GET", url })).statusCode).toBe(404);
    }
  });

  it("keeps every non-Step-3B OAuth protocol route dark when the flag is true", async () => {
    const { app } = await applicationWithFlag(true);
    for (const [method, url] of [
      ["GET", "/.well-known/oauth-authorization-server"],
      ["GET", "/oauth/authorize"],
      ["POST", "/oauth/token"],
      ["POST", "/oauth/revoke"],
      ["POST", "/oauth/introspect"],
      ["GET", "/oauth/upstream/google/callback"]
    ] as const) {
      expect((await app.inject({ method, url })).statusCode).toBe(404);
    }
  });

  it("leaves the frozen legacy JWKS response untouched for both flag states", async () => {
    for (const flag of [false, true]) {
      const { app } = await applicationWithFlag(flag);
      const response = await app.inject({ method: "GET", url: "/v1/.well-known/jwks.json" });
      expect(response.statusCode).toBe(200);
      expect(response.json()).toEqual(legacyJwks);
    }
  });

  it("serves only valid OAuth public keys with exact caching and no private metadata", async () => {
    const active = signingKey("a-active", {
      publicJwk: {
        kty: "RSA", kid: "a-active", alg: "RS256", use: "sig", n: "n-a-active", e: "AQAB",
        protected_private_key_ref: "must-not-be-serialized"
      },
      publishedAt: new Date("2020-01-01T00:00:00Z"),
      activatesAt: new Date("2020-01-01T00:05:00Z"),
      lastSignedAt: new Date("2020-01-01T00:06:00Z"),
      retireAfter: new Date("2020-01-01T00:27:00Z")
    });
    const published = signingKey("z-published", {
      status: "published",
      publishedAt: new Date("2020-01-01T00:00:00Z"),
      activatesAt: new Date("2099-01-01T00:00:00Z"),
      lastSignedAt: null,
      retireAfter: null
    });
    const staged = signingKey("staged", {
      status: "staged", publishedAt: null, activatesAt: null, lastSignedAt: null, retireAfter: null
    });
    const { app, db } = await applicationWithFlag(true, [published, staged, active]);
    const response = await app.inject({ method: "GET", url: "/oauth/jwks" });
    expect(response.statusCode).toBe(200);
    expect(response.headers["cache-control"]).toBe("public, max-age=300");
    expect(response.json()).toEqual({
      keys: [
        { kty: "RSA", kid: "a-active", alg: "RS256", use: "sig", n: "n-a-active", e: "AQAB" },
        published.publicJwk
      ]
    });
    expect(JSON.stringify(response.json())).not.toMatch(/protected_private_key_ref|fingerprint|private|"d"/i);
    expect(db.calls[0]).toContain("public_jwk");
    expect(db.calls[0]).not.toContain("protected_private_key_ref");
  });

  it("returns sanitized temporarily_unavailable instead of an empty successful JWKS", async () => {
    for (const input of [
      { keys: [] as OAuthSigningKeyPublicMetadata[], failure: null },
      {
        keys: [signingKey("invalid-private", {
          publicJwk: {
            kty: "RSA", kid: "invalid-private", alg: "RS256", use: "sig",
            n: "public-n", e: "AQAB", d: "must-not-leak"
          }
        })],
        failure: null
      },
      { keys: [] as OAuthSigningKeyPublicMetadata[], failure: new Error("synthetic row content must not leak") }
    ]) {
      const { app } = await applicationWithFlag(true, input.keys, input.failure);
      const response = await app.inject({ method: "GET", url: "/oauth/jwks" });
      expect(response.statusCode).toBe(503);
      expect(response.headers["cache-control"]).toBe("no-store");
      expect(response.json()).toEqual({ error: "temporarily_unavailable" });
      expect(response.body).not.toContain("synthetic row content");
    }
  });

  it("serves the exact frozen protected-resource metadata without querying registration rows", async () => {
    const { app, db } = await applicationWithFlag(true);
    const response = await app.inject({ method: "GET", url: "/.well-known/oauth-protected-resource/v1" });
    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual(frozenProtectedResourceMetadata);
    expect(JSON.stringify(response.json())).not.toMatch(/secret|token|email|user|pilot|credential/i);
    expect(db.calls).toEqual([]);
  });
});
