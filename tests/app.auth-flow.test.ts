import { describe, expect, it } from "vitest";
import { AuditLogger } from "../src/audit.js";
import { buildApp } from "../src/app.js";
import { AppError, type ErrorCode } from "../src/errors.js";
import { hashOpaque, hashToolSecret, sha256 } from "../src/security.js";
import type {
  AuthRequest,
  AuthorizationGrant,
  Config,
  GoogleIdentity,
  OneTimeCode,
  RefreshToken,
  Session,
  Tool,
  ToolClient,
  User
} from "../src/types.js";

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

class FakeGoogle {
  state = "";
  nonce = "";
  exchangeCalls = 0;

  constructor(private readonly errorCode?: ErrorCode) {}

  createAuthorizationUrl(input: { state: string; nonce: string }) {
    this.state = input.state;
    this.nonce = input.nonce;
    return `https://accounts.google.test/auth?state=${input.state}`;
  }

  async exchangeCodeForIdentity(_code?: string, correlationId = "corr_test"): Promise<GoogleIdentity> {
    this.exchangeCalls += 1;
    if (this.errorCode) {
      throw new AppError(this.errorCode, correlationId);
    }
    return {
      googleSub: "google-sub-1",
      email: "mario.rossi@unguess.io",
      emailVerified: true,
      hd: "unguess.io",
      displayName: "Mario Rossi",
      pictureUrl: null,
      nonce: this.nonce,
      issuer: "https://accounts.google.com",
      audience: config.googleClientId,
      expiresAt: Math.floor(Date.now() / 1000) + 600
    };
  }
}

class MemoryRepos {
  db = {
    query: async () => ({ rows: [], rowCount: 0 }),
    transaction: async <T>(fn: (db: unknown) => Promise<T>) => fn(this.db),
    close: async () => undefined
  };

  audits: unknown[] = [];
  users = new Map<string, User>();
  authRequests = new Map<string, AuthRequest>();
  accessRequests: Array<Record<string, unknown>> = [];
  oneTimeCodes = new Map<string, OneTimeCode>();
  sessions = new Map<string, Session>();
  grants = new Map<string, AuthorizationGrant>();
  pendingEmailGrant: AuthorizationGrant | null = null;
  client: ToolClient & { tool_slug: string } | null = null;
  refreshTokens = new Map<string, RefreshToken>();
  recentReviewedAccessRequest: Record<string, unknown> | null = null;

  constructor(private readonly hasGrant: boolean) {}

  withDb() {
    return this;
  }

  async health() {
    return true;
  }

  async writeAudit(event: unknown) {
    this.audits.push(event);
  }

  async findToolBySlug(slug: string) {
    return slug === tool.slug ? tool : null;
  }

  async findToolById(id: string) {
    return id === tool.id ? tool : null;
  }

  async createAuthRequest(input: {
    stateHash: string;
    nonceHash: string;
    toolState: string;
    toolStateHash: string;
    correlationId: string;
    expiresAt: Date;
  }) {
    this.authRequests.set(input.stateHash, {
      id: "auth-request-id",
      state_hash: input.stateHash,
      nonce_hash: input.nonceHash,
      tool_id: tool.id,
      tool_slug: tool.slug,
      return_url: tool.allowed_return_urls[0],
      tool_state: input.toolState,
      tool_state_hash: input.toolStateHash,
      login_hint: null,
      correlation_id: input.correlationId,
      request_ip_hash: null,
      user_agent_hash: null,
      expires_at: input.expiresAt,
      consumed_at: null
    });
  }

  async consumeAuthRequest(stateHash: string) {
    const request = this.authRequests.get(stateHash);
    if (!request || request.consumed_at || request.expires_at <= new Date()) return null;
    request.consumed_at = new Date();
    return request;
  }

  async upsertUser(input: { googleSub: string; email: string; emailNormalized: string; emailVerified: boolean; hd: string; displayName?: string | null }) {
    const user: User = {
      id: "user-id",
      google_sub: input.googleSub,
      email: input.email,
      email_normalized: input.emailNormalized,
      email_verified: input.emailVerified,
      hd: input.hd,
      display_name: input.displayName ?? null,
      picture_url: null,
      status: "active",
      first_seen_at: new Date(),
      last_seen_at: new Date()
    };
    this.users.set(user.id, user);
    return user;
  }

  async linkPendingEmailGrants(user: User) {
    if (!this.pendingEmailGrant || this.pendingEmailGrant.email_normalized !== user.email_normalized) return;
    this.pendingEmailGrant = {
      ...this.pendingEmailGrant,
      user_id: user.id,
      status: "active"
    };
    this.grants.set(this.pendingEmailGrant.id, this.pendingEmailGrant);
  }

  async findActiveGrant(toolId: string, userId: string, emailNormalized: string) {
    const linked = [...this.grants.values()].find(
      (grant) =>
        grant.tool_id === toolId &&
        grant.status === "active" &&
        (grant.user_id === userId || grant.email_normalized === emailNormalized)
    );
    if (linked) return linked;
    if (!this.hasGrant) return null;
    const grant = makeGrant();
    this.grants.set(grant.id, grant);
    return grant;
  }

  async upsertAccessRequest(input: { user: User; correlationId: string }) {
    const existing = this.accessRequests[0];
    if (existing) {
      existing.attempts_count = Number(existing.attempts_count) + 1;
      existing.last_correlation_id = input.correlationId;
      return { request: existing, repeated: true };
    }
    const request = {
      id: "access-request-id",
      tool_id: tool.id,
      tool_slug: tool.slug,
      user_id: input.user.id,
      google_sub: input.user.google_sub,
      email: input.user.email,
      email_normalized: input.user.email_normalized,
      hd: input.user.hd,
      display_name: input.user.display_name,
      status: "pending",
      reason_code: "AUTH_NOT_AUTHORIZED_FOR_TOOL",
      attempts_count: 1,
      first_seen_at: new Date(),
      last_seen_at: new Date(),
      last_correlation_id: input.correlationId
    };
    this.accessRequests.push(request);
    return { request, repeated: false };
  }

  async findRecentReviewedAccessRequest() {
    return this.recentReviewedAccessRequest;
  }

  async createSession(input: { userId: string; toolId: string; grantId: string; expiresAt: Date }) {
    const session: Session = {
      id: "session-id",
      user_id: input.userId,
      tool_id: input.toolId,
      grant_id: input.grantId,
      status: "active",
      issued_at: new Date(),
      expires_at: input.expiresAt,
      revoked_at: null
    };
    this.sessions.set(session.id, session);
    return session;
  }

  async createOneTimeCode(input: { codeHash: string; userId: string; toolId: string; grantId: string; sessionId: string; returnUrl: string; correlationId: string; expiresAt: Date }) {
    this.oneTimeCodes.set(input.codeHash, {
      id: "otc-id",
      code_hash: input.codeHash,
      user_id: input.userId,
      tool_id: input.toolId,
      grant_id: input.grantId,
      session_id: input.sessionId,
      return_url: input.returnUrl,
      correlation_id: input.correlationId,
      expires_at: input.expiresAt,
      consumed_at: null
    });
  }

  async createToolClient(secret: string) {
    this.client = {
      id: "client-row-id",
      tool_id: tool.id,
      client_id: "client-id",
      client_secret_hash: await hashToolSecret(secret, config.toolClientSecretPepper),
      status: "active",
      tool_slug: tool.slug
    };
  }

  async findToolClient(clientId: string) {
    return this.client?.client_id === clientId ? this.client : null;
  }

  async markToolClientUsed() {}

  async consumeOneTimeCode(codeHash: string, toolId: string, redirectUri: string) {
    const code = this.oneTimeCodes.get(codeHash);
    if (!code || code.tool_id !== toolId || code.return_url !== redirectUri || code.consumed_at || code.expires_at <= new Date()) {
      return null;
    }
    code.consumed_at = new Date();
    return code;
  }

  async findOneTimeCodeByHash(codeHash: string) {
    return this.oneTimeCodes.get(codeHash) ?? null;
  }

  async findUserById(id: string) {
    return this.users.get(id) ?? null;
  }

  async findUserByGoogleSub(googleSub: string) {
    return [...this.users.values()].find((user) => user.google_sub === googleSub) ?? null;
  }

  async findGrantById(id: string) {
    return this.grants.get(id) ?? null;
  }

  async findSessionById(id: string) {
    return this.sessions.get(id) ?? null;
  }

  async extendSession(id: string, toolId: string, expiresAt: Date) {
    const session = this.sessions.get(id);
    if (!session || session.tool_id !== toolId || session.status !== "active" || session.expires_at <= new Date()) return null;
    session.expires_at = expiresAt;
    return session;
  }

  async createRefreshToken(tokenHash: string, sessionId: string, expiresAt: Date) {
    this.refreshTokens.set(tokenHash, {
      id: `refresh-${this.refreshTokens.size + 1}`,
      token_hash: tokenHash,
      session_id: sessionId,
      status: "active",
      issued_at: new Date(),
      expires_at: expiresAt,
      revoked_at: null
    });
  }

  async findRefreshTokenByHash(tokenHash: string) {
    return this.refreshTokens.get(tokenHash) ?? null;
  }

  async consumeRefreshToken(tokenHash: string) {
    const refresh = this.refreshTokens.get(tokenHash);
    if (!refresh || refresh.status !== "active" || refresh.expires_at <= new Date()) return null;
    refresh.status = "revoked";
    refresh.revoked_at = new Date();
    return refresh;
  }

  async revokeRefreshToken(tokenHash: string) {
    const refresh = this.refreshTokens.get(tokenHash);
    if (!refresh || refresh.status !== "active") return 0;
    refresh.status = "revoked";
    refresh.revoked_at = new Date();
    return 1;
  }
}

function makeGrant(): AuthorizationGrant {
  return {
    id: "grant-id",
    tool_id: tool.id,
    user_id: "user-id",
    email_normalized: "mario.rossi@unguess.io",
    role: "tool_user",
    permissions: ["crm:read"],
    status: "active",
    valid_from: new Date(Date.now() - 1000),
    valid_until: null,
    created_by_user_id: null
  };
}

function fakeTokenService() {
  return {
    getJwks: () => ({ keys: [{ kid: "test-key" }] }),
    issueAccessToken: async () => ({ token: "access-token-value", expiresAt: new Date(Date.now() + 900_000), expiresIn: 900, jti: "jti" }),
    verifyAccessToken: async () => ({ sub: "google-sub-1", sid: "session-id", tool_slug: "crm", email: "mario.rossi@unguess.io", hd: "unguess.io", permissions: ["crm:read"], role: "tool_user" })
  };
}

async function buildFlowApp(repos: MemoryRepos, google: FakeGoogle) {
  return buildApp({
    config,
    repositories: repos as never,
    audit: new AuditLogger(repos as never),
    google,
    tokenService: fakeTokenService() as never
  });
}

async function loginAndExchange(
  app: Awaited<ReturnType<typeof buildFlowApp>>,
  google: FakeGoogle,
  state = "refresh-flow-state-with-entropy"
) {
  await app.inject({
    method: "GET",
    url: `/v1/auth/start?tool_slug=crm&return_url=${encodeURIComponent(tool.allowed_return_urls[0])}&state=${state}`
  });
  const callback = await app.inject({
    method: "GET",
    url: `/v1/auth/google/callback?state=${encodeURIComponent(google.state)}&code=fake-google-code`
  });
  const code = new URL(callback.headers.location as string).searchParams.get("code");
  return app.inject({
    method: "POST",
    url: "/v1/auth/exchange",
    headers: {
      authorization: `Basic ${Buffer.from("client-id:client-secret").toString("base64")}`
    },
    payload: {
      code,
      redirect_uri: tool.allowed_return_urls[0]
    }
  });
}

describe("auth flow routes", () => {
  it("denies callbacks with unknown state before calling Google", async () => {
    const repos = new MemoryRepos(false);
    const google = new FakeGoogle();
    const app = await buildFlowApp(repos, google);

    const callback = await app.inject({
      method: "GET",
      url: "/v1/auth/google/callback?state=unknown-google-state&code=fake-google-code"
    });

    expect(callback.statusCode).toBe(400);
    expect(google.exchangeCalls).toBe(0);
    expect(repos.users.size).toBe(0);
    expect(repos.accessRequests).toHaveLength(0);
    expect(repos.audits).toContainEqual(
      expect.objectContaining({
        event_type: "auth.denied.invalid_state",
        outcome: "denied",
        reason_code: "AUTH_INVALID_STATE"
      })
    );
    await app.close();
  });

  it("creates a pending access request for a valid internal user without a grant", async () => {
    const repos = new MemoryRepos(false);
    const google = new FakeGoogle();
    const app = await buildFlowApp(repos, google);

    await app.inject({
      method: "GET",
      url: `/v1/auth/start?tool_slug=crm&return_url=${encodeURIComponent(tool.allowed_return_urls[0])}&state=${"a".repeat(24)}`
    });
    const callback = await app.inject({
      method: "GET",
      url: `/v1/auth/google/callback?state=${encodeURIComponent(google.state)}&code=fake-google-code`
    });

    expect(callback.statusCode).toBe(403);
    expect(repos.accessRequests).toHaveLength(1);
    expect(repos.audits).toMatchObject([
      { event_type: "auth.requested" },
      { event_type: "google.callback.received" },
      { event_type: "auth.denied.no_grant" },
      { event_type: "access_request.created" }
    ]);
    await app.close();
  });

  it("updates the existing pending access request for repeated valid internal no-grant attempts", async () => {
    const repos = new MemoryRepos(false);
    const google = new FakeGoogle();
    const app = await buildFlowApp(repos, google);

    const attemptNoGrantLogin = async (state: string) => {
      await app.inject({
        method: "GET",
        url: `/v1/auth/start?tool_slug=crm&return_url=${encodeURIComponent(tool.allowed_return_urls[0])}&state=${state}`
      });
      return app.inject({
        method: "GET",
        url: `/v1/auth/google/callback?state=${encodeURIComponent(google.state)}&code=fake-google-code`
      });
    };

    const first = await attemptNoGrantLogin("first-no-grant-state-entropy");
    const second = await attemptNoGrantLogin("second-no-grant-state-entropy");

    expect(first.statusCode).toBe(403);
    expect(second.statusCode).toBe(403);
    expect(repos.accessRequests).toHaveLength(1);
    expect(repos.accessRequests[0]).toMatchObject({
      attempts_count: 2,
      last_correlation_id: expect.any(String)
    });
    expect(repos.audits).toContainEqual(
      expect.objectContaining({
        event_type: "access_request.created",
        outcome: "info",
        metadata: expect.objectContaining({ attempts_count: 1 })
      })
    );
    expect(repos.audits).toContainEqual(
      expect.objectContaining({
        event_type: "access_request.repeated",
        outcome: "info",
        metadata: expect.objectContaining({ attempts_count: 2 })
      })
    );
    await app.close();
  });

  it("denies external Google domains without creating an access request", async () => {
    const repos = new MemoryRepos(false);
    const google = new FakeGoogle("AUTH_EXTERNAL_DOMAIN");
    const app = await buildFlowApp(repos, google);

    await app.inject({
      method: "GET",
      url: `/v1/auth/start?tool_slug=crm&return_url=${encodeURIComponent(tool.allowed_return_urls[0])}&state=external-domain-state-entropy`
    });
    const callback = await app.inject({
      method: "GET",
      url: `/v1/auth/google/callback?state=${encodeURIComponent(google.state)}&code=fake-google-code`
    });

    expect(callback.statusCode).toBe(403);
    expect(repos.users.size).toBe(0);
    expect(repos.accessRequests).toHaveLength(0);
    expect(repos.audits).toContainEqual(
      expect.objectContaining({
        event_type: "auth.denied.external_domain",
        outcome: "denied",
        tool_slug: "crm",
        reason_code: "AUTH_EXTERNAL_DOMAIN"
      })
    );
    await app.close();
  });

  it("denies unverified Google emails without creating an access request", async () => {
    const repos = new MemoryRepos(false);
    const google = new FakeGoogle("AUTH_EMAIL_NOT_VERIFIED");
    const app = await buildFlowApp(repos, google);

    await app.inject({
      method: "GET",
      url: `/v1/auth/start?tool_slug=crm&return_url=${encodeURIComponent(tool.allowed_return_urls[0])}&state=unverified-email-state-entropy`
    });
    const callback = await app.inject({
      method: "GET",
      url: `/v1/auth/google/callback?state=${encodeURIComponent(google.state)}&code=fake-google-code`
    });

    expect(callback.statusCode).toBe(403);
    expect(repos.users.size).toBe(0);
    expect(repos.accessRequests).toHaveLength(0);
    expect(repos.audits).toContainEqual(
      expect.objectContaining({
        event_type: "auth.denied.email_not_verified",
        outcome: "denied",
        tool_slug: "crm",
        reason_code: "AUTH_EMAIL_NOT_VERIFIED"
      })
    );
    await app.close();
  });

  it("issues a one-time code, exchanges it once and denies replay", async () => {
    const repos = new MemoryRepos(true);
    await repos.createToolClient("client-secret");
    const google = new FakeGoogle();
    const app = await buildFlowApp(repos, google);

    await app.inject({
      method: "GET",
      url: `/v1/auth/start?tool_slug=crm&return_url=${encodeURIComponent(tool.allowed_return_urls[0])}&state=tool-state-with-entropy`
    });
    const callback = await app.inject({
      method: "GET",
      url: `/v1/auth/google/callback?state=${encodeURIComponent(google.state)}&code=fake-google-code`
    });
    expect(callback.statusCode).toBe(302);
    const redirect = new URL(callback.headers.location as string);
    const code = redirect.searchParams.get("code");
    expect(code).toMatch(/^otc_/);
    expect(redirect.searchParams.get("state")).toBe("tool-state-with-entropy");

    const exchange = await app.inject({
      method: "POST",
      url: "/v1/auth/exchange",
      headers: {
        authorization: `Basic ${Buffer.from("client-id:client-secret").toString("base64")}`
      },
      payload: {
        code,
        redirect_uri: tool.allowed_return_urls[0]
      }
    });
    expect(exchange.statusCode).toBe(200);
    expect(exchange.json()).toMatchObject({
      access_token: "access-token-value",
      user: { google_sub: "google-sub-1", email: "mario.rossi@unguess.io" },
      grant: { permissions: ["crm:read"] }
    });
    expect(repos.refreshTokens.size).toBe(1);

    const replay = await app.inject({
      method: "POST",
      url: "/v1/auth/exchange",
      headers: {
        authorization: `Basic ${Buffer.from("client-id:client-secret").toString("base64")}`
      },
      payload: {
        code,
        redirect_uri: tool.allowed_return_urls[0]
      }
    });
    expect(replay.statusCode).toBe(400);
    expect(replay.json().error.code).toBe("AUTH_CODE_ALREADY_USED");
    expect(repos.oneTimeCodes.get(hashOpaque(code!, config.toolClientSecretPepper))?.consumed_at).toBeInstanceOf(Date);
    await app.close();
  });

  it("rotates refresh tokens and extends the session while the user remains active", async () => {
    const repos = new MemoryRepos(true);
    await repos.createToolClient("client-secret");
    const google = new FakeGoogle();
    const app = await buildFlowApp(repos, google);
    const exchange = await loginAndExchange(app, google);
    const firstRefreshToken = exchange.json().refresh_token as string;
    const session = repos.sessions.get("session-id")!;
    session.expires_at = new Date(Date.now() + 60_000);
    const previousExpiry = session.expires_at.getTime();

    const refresh = await app.inject({
      method: "POST",
      url: "/v1/auth/refresh",
      headers: {
        authorization: `Basic ${Buffer.from("client-id:client-secret").toString("base64")}`
      },
      payload: {
        refresh_token: firstRefreshToken
      }
    });

    expect(refresh.statusCode).toBe(200);
    expect(refresh.headers["cache-control"]).toBe("no-store");
    expect(refresh.json()).toMatchObject({
      access_token: "access-token-value",
      expires_in: 900,
      session: { id: "session-id" },
      user: { google_sub: "google-sub-1" },
      grant: { permissions: ["crm:read"] }
    });
    expect(refresh.json().refresh_token).toMatch(/^rt_/);
    expect(refresh.json().refresh_token).not.toBe(firstRefreshToken);
    expect(repos.sessions.get("session-id")!.expires_at.getTime()).toBeGreaterThan(previousExpiry);
    expect(repos.refreshTokens.size).toBe(2);
    expect(repos.refreshTokens.get(hashOpaque(firstRefreshToken, config.toolClientSecretPepper))?.status).toBe("revoked");
    expect(repos.audits).toContainEqual(
      expect.objectContaining({
        event_type: "token.refreshed",
        outcome: "success",
        tool_slug: "crm"
      })
    );

    const replay = await app.inject({
      method: "POST",
      url: "/v1/auth/refresh",
      headers: {
        authorization: `Basic ${Buffer.from("client-id:client-secret").toString("base64")}`
      },
      payload: {
        refresh_token: firstRefreshToken
      }
    });
    expect(replay.statusCode).toBe(401);
    expect(replay.json().error.code).toBe("AUTH_REFRESH_TOKEN_INVALID");
    await app.close();
  });

  it("denies refresh after inactivity expiry or grant revocation", async () => {
    const repos = new MemoryRepos(true);
    await repos.createToolClient("client-secret");
    const google = new FakeGoogle();
    const app = await buildFlowApp(repos, google);
    const exchange = await loginAndExchange(app, google, "expired-refresh-state-entropy");
    const refreshToken = exchange.json().refresh_token as string;
    repos.sessions.get("session-id")!.expires_at = new Date(Date.now() - 1);
    repos.grants.get("grant-id")!.status = "revoked";

    const refresh = await app.inject({
      method: "POST",
      url: "/v1/auth/refresh",
      headers: {
        authorization: `Basic ${Buffer.from("client-id:client-secret").toString("base64")}`
      },
      payload: {
        refresh_token: refreshToken
      }
    });

    expect(refresh.statusCode).toBe(401);
    expect(refresh.json().error.code).toBe("AUTH_REFRESH_TOKEN_INVALID");
    expect(repos.refreshTokens.size).toBe(1);
    expect(repos.audits).toContainEqual(
      expect.objectContaining({
        event_type: "token.refresh.denied",
        outcome: "denied",
        reason_code: "AUTH_REFRESH_TOKEN_INVALID"
      })
    );
    await app.close();
  });

  it("denies one-time-code exchange with a wrong tool client secret and audits the denial", async () => {
    const repos = new MemoryRepos(true);
    await repos.createToolClient("client-secret");
    const google = new FakeGoogle();
    const app = await buildFlowApp(repos, google);

    await app.inject({
      method: "GET",
      url: `/v1/auth/start?tool_slug=crm&return_url=${encodeURIComponent(tool.allowed_return_urls[0])}&state=wrong-secret-state-entropy`
    });
    const callback = await app.inject({
      method: "GET",
      url: `/v1/auth/google/callback?state=${encodeURIComponent(google.state)}&code=fake-google-code`
    });
    const code = new URL(callback.headers.location as string).searchParams.get("code");

    const response = await app.inject({
      method: "POST",
      url: "/v1/auth/exchange",
      headers: {
        authorization: `Basic ${Buffer.from("client-id:wrong-secret").toString("base64")}`
      },
      payload: {
        code,
        redirect_uri: tool.allowed_return_urls[0]
      }
    });

    expect(response.statusCode).toBe(401);
    expect(response.json().error.code).toBe("TOOL_AUTH_FAILED");
    expect(repos.oneTimeCodes.get(hashOpaque(code!, config.toolClientSecretPepper))?.consumed_at).toBeNull();
    expect(repos.audits).toContainEqual(
      expect.objectContaining({
        event_type: "token.exchange.denied",
        outcome: "denied",
        tool_slug: "crm",
        reason_code: "TOOL_AUTH_FAILED"
      })
    );
    await app.close();
  });

  it("links a pending email grant on first valid login and allows access", async () => {
    const repos = new MemoryRepos(false);
    repos.pendingEmailGrant = {
      ...makeGrant(),
      id: "pending-email-grant-id",
      user_id: null,
      status: "pending_user_link"
    };
    const google = new FakeGoogle();
    const app = await buildFlowApp(repos, google);

    await app.inject({
      method: "GET",
      url: `/v1/auth/start?tool_slug=crm&return_url=${encodeURIComponent(tool.allowed_return_urls[0])}&state=pending-email-state-entropy`
    });
    const callback = await app.inject({
      method: "GET",
      url: `/v1/auth/google/callback?state=${encodeURIComponent(google.state)}&code=fake-google-code`
    });

    expect(callback.statusCode).toBe(302);
    expect(repos.pendingEmailGrant).toMatchObject({
      id: "pending-email-grant-id",
      user_id: "user-id",
      status: "active"
    });
    expect(repos.accessRequests).toHaveLength(0);
    expect(repos.oneTimeCodes.size).toBe(1);
    expect(repos.audits).toContainEqual(
      expect.objectContaining({
        event_type: "auth.allowed",
        outcome: "success"
      })
    );
    await app.close();
  });

  it("suppresses a new pending request after a recent rejection", async () => {
    const repos = new MemoryRepos(false);
    repos.recentReviewedAccessRequest = {
      id: "recent-request-id",
      status: "rejected",
      tool_id: tool.id,
      tool_slug: tool.slug,
      email_normalized: "mario.rossi@unguess.io"
    };
    const google = new FakeGoogle();
    const app = await buildFlowApp(repos, google);

    await app.inject({
      method: "GET",
      url: `/v1/auth/start?tool_slug=crm&return_url=${encodeURIComponent(tool.allowed_return_urls[0])}&state=${"b".repeat(24)}`
    });
    const callback = await app.inject({
      method: "GET",
      url: `/v1/auth/google/callback?state=${encodeURIComponent(google.state)}&code=fake-google-code`
    });

    expect(callback.statusCode).toBe(403);
    expect(repos.accessRequests).toHaveLength(0);
    expect(repos.audits).toContainEqual(
      expect.objectContaining({
        event_type: "access_request.reopen_suppressed",
        outcome: "info"
      })
    );
    await app.close();
  });

  it("returns active introspection for current grant and inactive after grant revocation", async () => {
    const repos = new MemoryRepos(true);
    await repos.createToolClient("client-secret");
    const google = new FakeGoogle();
    const app = await buildFlowApp(repos, google);

    await app.inject({
      method: "GET",
      url: `/v1/auth/start?tool_slug=crm&return_url=${encodeURIComponent(tool.allowed_return_urls[0])}&state=introspection-state-entropy`
    });
    const callback = await app.inject({
      method: "GET",
      url: `/v1/auth/google/callback?state=${encodeURIComponent(google.state)}&code=fake-google-code`
    });
    const code = new URL(callback.headers.location as string).searchParams.get("code");
    await app.inject({
      method: "POST",
      url: "/v1/auth/exchange",
      headers: {
        authorization: `Basic ${Buffer.from("client-id:client-secret").toString("base64")}`
      },
      payload: {
        code,
        redirect_uri: tool.allowed_return_urls[0]
      }
    });

    const active = await app.inject({
      method: "POST",
      url: "/v1/auth/introspect",
      headers: {
        authorization: `Basic ${Buffer.from("client-id:client-secret").toString("base64")}`
      },
      payload: {
        token: "access-token-value"
      }
    });
    expect(active.statusCode).toBe(200);
    expect(active.json()).toMatchObject({
      active: true,
      user: { google_sub: "google-sub-1", email: "mario.rossi@unguess.io" },
      permissions: ["crm:read"]
    });

    repos.grants.get("grant-id")!.status = "revoked";
    const revoked = await app.inject({
      method: "POST",
      url: "/v1/auth/introspect",
      headers: {
        authorization: `Basic ${Buffer.from("client-id:client-secret").toString("base64")}`
      },
      payload: {
        token: "access-token-value"
      }
    });
    expect(revoked.statusCode).toBe(200);
    expect(revoked.json()).toEqual({ active: false, reason: "revoked" });
    await app.close();
  });
});
