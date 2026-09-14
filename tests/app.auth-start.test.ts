import { describe, expect, it } from "vitest";
import { AuditLogger } from "../src/audit.js";
import { buildApp } from "../src/app.js";
import type { Config, Tool } from "../src/types.js";

const tool: Tool = {
  id: "tool-id",
  slug: "crm",
  display_name: "CRM interno",
  description: null,
  status: "active",
  allowed_return_urls: ["https://crm.draftapps.it/auth/callback"],
  owner_email: null,
  created_at: new Date(),
  updated_at: new Date()
};

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

describe("auth start route", () => {
  it("offers Google and Microsoft only for the allowlisted test-generator slug without persisting auth state", async () => {
    const testGenerator = {
      ...tool,
      slug: "test-generator",
      display_name: "Test Generator",
      allowed_return_urls: ["https://test-generator.example.test/auth/access-layer/callback"]
    };
    let createAuthRequestCalls = 0;
    const repositories = {
      health: async () => true,
      findToolBySlug: async (slug: string) => slug === testGenerator.slug ? testGenerator : null,
      createAuthRequest: async () => { createAuthRequestCalls += 1; },
      writeAudit: async () => undefined
    };
    const app = await buildApp({
      config: {
        ...config,
        legacyMicrosoftEnabled: true,
        legacyMicrosoftToolSlugs: ["test-generator"]
      },
      repositories: repositories as never,
      audit: new AuditLogger(repositories as never),
      google: {
        createAuthorizationUrl: () => "https://accounts.google.com/o/oauth2/v2/auth",
        exchangeCodeForIdentity: async () => { throw new Error("not used"); }
      },
      microsoft: {
        createAuthorizationUrl: () => "https://login.microsoftonline.com/tenant/oauth2/v2.0/authorize",
        exchangeCodeForIdentity: async () => { throw new Error("not used"); }
      },
      tokenService: { getJwks: () => ({ keys: [] }) } as never
    });

    const response = await app.inject({
      method: "GET",
      url: `/v1/auth/start?tool_slug=test-generator&return_url=${encodeURIComponent(testGenerator.allowed_return_urls[0])}&state=test-generator-provider-state`
    });
    expect(response.statusCode).toBe(200);
    expect(response.headers["cache-control"]).toBe("no-store");
    expect(response.headers.pragma).toBe("no-cache");
    expect(response.body).toContain("Continue with Google");
    expect(response.body).toContain("Continue with Microsoft");
    expect(createAuthRequestCalls).toBe(0);
    await app.close();
  });

  it("answers configured CORS preflight requests without touching auth state", async () => {
    const corsConfig = {
      ...config,
      corsAllowedOrigins: ["http://localhost:3000"]
    };
    const repositories = {
      health: async () => true,
      writeAudit: async () => undefined
    };
    const app = await buildApp({
      config: corsConfig,
      repositories: repositories as never,
      audit: new AuditLogger(repositories as never),
      google: {
        createAuthorizationUrl: () => "https://accounts.google.com/o/oauth2/v2/auth",
        exchangeCodeForIdentity: async () => {
          throw new Error("not used");
        }
      },
      tokenService: {
        getJwks: () => ({ keys: [] })
      } as never
    });

    const response = await app.inject({
      method: "OPTIONS",
      url: "/v1/auth/start",
      headers: { origin: "http://localhost:3000" }
    });

    expect(response.statusCode).toBe(204);
    expect(response.headers["access-control-allow-origin"]).toBe("http://localhost:3000");
    await app.close();
  });

  it("rejects bearer tokens in query strings and audits the denial", async () => {
    const events: unknown[] = [];
    const repositories = {
      health: async () => true,
      writeAudit: async (event: unknown) => events.push(event)
    };
    const app = await buildApp({
      config,
      repositories: repositories as never,
      audit: new AuditLogger(repositories as never),
      google: {
        createAuthorizationUrl: () => "https://accounts.google.com/o/oauth2/v2/auth",
        exchangeCodeForIdentity: async () => {
          throw new Error("not used");
        }
      },
      tokenService: {
        getJwks: () => ({ keys: [] })
      } as never
    });

    const response = await app.inject({
      method: "GET",
      url: "/v1/me?access_token=eyJ.bad.token"
    });

    expect(response.statusCode).toBe(400);
    expect(response.json().error.code).toBe("TOKEN_IN_QUERY_REJECTED");
    expect(events).toContainEqual(
      expect.objectContaining({
        event_type: "auth.denied.token_in_query",
        outcome: "denied",
        reason_code: "TOKEN_IN_QUERY_REJECTED"
      })
    );
    await app.close();
  });

  it("denies invalid return URLs before redirecting to Google and audits the denial", async () => {
    const events: unknown[] = [];
    const repositories = {
      health: async () => true,
      findToolBySlug: async () => tool,
      writeAudit: async (event: unknown) => events.push(event)
    };
    const app = await buildApp({
      config,
      repositories: repositories as never,
      audit: new AuditLogger(repositories as never),
      google: {
        createAuthorizationUrl: () => "https://accounts.google.com/o/oauth2/v2/auth",
        exchangeCodeForIdentity: async () => {
          throw new Error("not used");
        }
      },
      tokenService: {
        getJwks: () => ({ keys: [] })
      } as never
    });

    const response = await app.inject({
      method: "GET",
      url:
        "/v1/auth/start?tool_slug=crm&return_url=https%3A%2F%2Fcrm.draftapps.it.evil.com%2Fauth%2Fcallback&state=abcdefghijklmnopqrstuvwxyz"
    });

    expect(response.statusCode).toBe(400);
    expect(events).toContainEqual(expect.objectContaining({ event_type: "auth.requested", outcome: "info" }));
    expect(events).toContainEqual(
      expect.objectContaining({
        event_type: "auth.denied.invalid_return_url",
        outcome: "denied",
        reason_code: "AUTH_INVALID_RETURN_URL"
      })
    );
    await app.close();
  });

  it("fails closed before redirecting when the initial auth audit write fails", async () => {
    let findToolCalls = 0;
    let createAuthRequestCalls = 0;
    let authorizationUrlCalls = 0;
    const repositories = {
      health: async () => true,
      findToolBySlug: async () => {
        findToolCalls += 1;
        return tool;
      },
      createAuthRequest: async () => {
        createAuthRequestCalls += 1;
      },
      writeAudit: async () => {
        throw new Error("audit unavailable");
      }
    };
    const app = await buildApp({
      config,
      repositories: repositories as never,
      audit: new AuditLogger(repositories as never),
      google: {
        createAuthorizationUrl: () => {
          authorizationUrlCalls += 1;
          return "https://accounts.google.com/o/oauth2/v2/auth";
        },
        exchangeCodeForIdentity: async () => {
          throw new Error("not used");
        }
      },
      tokenService: {
        getJwks: () => ({ keys: [] })
      } as never
    });

    const response = await app.inject({
      method: "GET",
      url: `/v1/auth/start?tool_slug=crm&return_url=${encodeURIComponent(tool.allowed_return_urls[0])}&state=abcdefghijklmnopqrstuvwxyz`
    });

    expect(response.statusCode).toBe(500);
    expect(response.json().error.code).toBe("INTERNAL_ERROR");
    expect(findToolCalls).toBe(0);
    expect(createAuthRequestCalls).toBe(0);
    expect(authorizationUrlCalls).toBe(0);
    await app.close();
  });

  it("fails closed on denial when the invalid-return-url audit write fails", async () => {
    const events: unknown[] = [];
    let auditWriteCalls = 0;
    let createAuthRequestCalls = 0;
    let authorizationUrlCalls = 0;
    const repositories = {
      health: async () => true,
      findToolBySlug: async () => tool,
      createAuthRequest: async () => {
        createAuthRequestCalls += 1;
      },
      writeAudit: async (event: unknown) => {
        auditWriteCalls += 1;
        if (auditWriteCalls > 1) {
          throw new Error("audit unavailable");
        }
        events.push(event);
      }
    };
    const app = await buildApp({
      config,
      repositories: repositories as never,
      audit: new AuditLogger(repositories as never),
      google: {
        createAuthorizationUrl: () => {
          authorizationUrlCalls += 1;
          return "https://accounts.google.com/o/oauth2/v2/auth";
        },
        exchangeCodeForIdentity: async () => {
          throw new Error("not used");
        }
      },
      tokenService: {
        getJwks: () => ({ keys: [] })
      } as never
    });

    const response = await app.inject({
      method: "GET",
      url:
        "/v1/auth/start?tool_slug=crm&return_url=https%3A%2F%2Fcrm.draftapps.it.evil.com%2Fauth%2Fcallback&state=abcdefghijklmnopqrstuvwxyz"
    });

    expect(response.statusCode).toBe(500);
    expect(response.json().error.code).toBe("INTERNAL_ERROR");
    expect(events).toEqual([expect.objectContaining({ event_type: "auth.requested", outcome: "info" })]);
    expect(createAuthRequestCalls).toBe(0);
    expect(authorizationUrlCalls).toBe(0);
    await app.close();
  });

  it("rate limits repeated auth start attempts by IP and tool", async () => {
    const repositories = {
      health: async () => true,
      writeAudit: async () => undefined
    };
    const app = await buildApp({
      config,
      repositories: repositories as never,
      audit: new AuditLogger(repositories as never),
      google: {
        createAuthorizationUrl: () => "https://accounts.google.com/o/oauth2/v2/auth",
        exchangeCodeForIdentity: async () => {
          throw new Error("not used");
        }
      },
      tokenService: {
        getJwks: () => ({ keys: [] })
      } as never
    });

    let response;
    for (let index = 0; index < 31; index += 1) {
      response = await app.inject({
        method: "GET",
        url: "/v1/auth/start?tool_slug=crm&return_url=https%3A%2F%2Fcrm.draftapps.it%2Fauth%2Fcallback&state=short"
      });
    }

    expect(response?.statusCode).toBe(429);
    await app.close();
  });
});
