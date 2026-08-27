import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import type { AuditLogger } from "../src/audit.js";
import type { Db } from "../src/db.js";
import type { OAuthUpstreamGoogleClient } from "../src/oauth/google.js";
import {
  OAUTH_AUTHORIZATION_CODE_TTL_MS,
  OAUTH_AUTHORIZATION_TRANSACTION_TTL_MS,
  OAuthAuthorizationService
} from "../src/oauth/authorization.js";
import type { OAuthAuthorizationFlowRepository } from "../src/oauth/flow-repository.js";
import type { OAuthFoundationRepository } from "../src/oauth/repository.js";
import {
  parseOAuthTransactionProtectionKey,
  protectOAuthDownstreamState,
  unprotectOAuthDownstreamState
} from "../src/oauth/state-protection.js";
import type {
  OAuthAuthorizationCodeIssuance,
  OAuthAuthorizationTransactionRecord,
  OAuthClientRecord,
  OAuthResourceRecord
} from "../src/oauth/types.js";
import type { Repositories } from "../src/repositories.js";
import { sha256 } from "../src/security.js";
import type { AuditEventInput, Config, GoogleIdentity, User } from "../src/types.js";

const root = resolve(import.meta.dirname, "..");
const migration = readFileSync(resolve(root, "migrations/004_oauth_authorization_code_flow.sql"), "utf8");
const fixedNow = new Date("2026-08-26T10:00:00.000Z");
const protectionKey = Buffer.alloc(32, 11);
const client: OAuthClientRecord = {
  id: "00000000-0000-4000-8000-000000000101",
  clientId: "synthetic-bff",
  clientName: "Synthetic BFF",
  clientType: "confidential",
  tokenEndpointAuthMethod: "client_secret_basic",
  grantTypes: ["authorization_code", "refresh_token"],
  status: "active",
  ownerTeam: "synthetic",
  ownerContact: null
};
const resource: OAuthResourceRecord = {
  id: "00000000-0000-4000-8000-000000000102",
  resourceId: "https://resource.invalid/api",
  displayName: "Synthetic Resource",
  status: "active",
  ownerTeam: "synthetic",
  ownerContact: null,
  audiencePolicy: "exact_single_resource",
  protectedResourceMetadataUrl: "https://resource.invalid/.well-known/oauth-protected-resource"
};
const user: User = {
  id: "00000000-0000-4000-8000-000000000103",
  google_sub: "synthetic-google-sub",
  email: "person@example.invalid",
  email_normalized: "person@example.invalid",
  email_verified: true,
  hd: "example.invalid",
  display_name: null,
  picture_url: null,
  status: "active",
  first_seen_at: fixedNow,
  last_seen_at: fixedNow
};
const identityBase: GoogleIdentity = {
  googleSub: user.google_sub,
  email: user.email,
  emailVerified: true,
  hd: user.hd,
  displayName: null,
  pictureUrl: null,
  nonce: null,
  issuer: "https://accounts.google.com",
  audience: "synthetic.apps.googleusercontent.com",
  expiresAt: 2_000_000_000
};
const config: Config = {
  appEnv: "test",
  appBaseUrl: "https://issuer.invalid/",
  authIssuer: "https://issuer.invalid/",
  publicBasePath: "",
  port: 8080,
  logLevel: "silent",
  databaseUrl: "postgresql://synthetic.invalid/access-layer",
  googleClientId: "synthetic.apps.googleusercontent.com",
  googleClientSecret: "synthetic-google-secret",
  googleRedirectUri: "https://issuer.invalid/v1/auth/google/callback",
  googleAllowedHd: ["example.invalid"],
  googleOidcScope: "openid email profile",
  jwtPublicKeyId: "synthetic-key",
  accessTokenTtlSeconds: 900,
  refreshTokenTtlSeconds: 28800,
  oneTimeCodeTtlSeconds: 60,
  oauthP0Enabled: true,
  oauthTransactionProtectionKey: protectionKey,
  sessionCookieName: "synthetic",
  sessionSecret: "synthetic-session-secret",
  toolClientSecretPepper: "synthetic-pepper",
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
const validQuery: Record<string, unknown> = {
  response_type: "code",
  client_id: client.clientId,
  redirect_uri: "https://client.invalid/callback?existing=kept",
  scope: "synthetic:records:read synthetic:records:write",
  state: "downstream-state-exact-._~",
  code_challenge: "A".repeat(43),
  code_challenge_method: "S256",
  resource: resource.resourceId
};
const requestContext = {
  correlationId: "synthetic-correlation",
  requestIpHash: "synthetic-ip-hash",
  userAgentHash: "synthetic-user-agent-hash"
};

interface HarnessOverrides {
  client?: OAuthClientRecord | null;
  resource?: OAuthResourceRecord | null;
  callbackClient?: OAuthClientRecord | null;
  callbackResource?: OAuthResourceRecord | null;
  allowed?: boolean;
  entitlement?: boolean;
  permissions?: string[];
  grant?: boolean;
  userStatus?: User["status"];
}

function harness(overrides: HarnessOverrides = {}) {
  let transaction: OAuthAuthorizationTransactionRecord | null = null;
  let upstreamState = "";
  let upstreamNonce = "";
  let claimed = false;
  let linkCalls = 0;
  let transactionDepth = 0;
  const auditEvents: AuditEventInput[] = [];
  const issuances: OAuthAuthorizationCodeIssuance[] = [];
  const selectedClient = Object.hasOwn(overrides, "client") ? overrides.client! : client;
  const selectedResource = Object.hasOwn(overrides, "resource") ? overrides.resource! : resource;

  const foundation = {
    resolveClientByClientId: async () => selectedClient,
    resolveExactRedirectUris: async () => [String(validQuery.redirect_uri)],
    resolveResourceByResourceId: async () => selectedResource,
    isClientResourceScopeAllowed: async () => overrides.allowed !== false,
    resolveClientById: async () => Object.hasOwn(overrides, "callbackClient") ? overrides.callbackClient! : selectedClient,
    resolveResourceById: async () => Object.hasOwn(overrides, "callbackResource") ? overrides.callbackResource! : selectedResource,
    resolveActiveLegacyEntitlement: async () => overrides.entitlement === false ? null : ({
      legacyToolId: "00000000-0000-4000-8000-000000000104",
      legacyToolSlug: "synthetic-tool",
      registeredPermissionKeys: ["records:read", "records:write"]
    }),
    resolveResourceScopeMappings: async () => [
      { resourceId: resource.resourceId, scope: "synthetic:records:read", legacyPermissionKey: "records:read" },
      { resourceId: resource.resourceId, scope: "synthetic:records:write", legacyPermissionKey: "records:write" }
    ]
  } as unknown as OAuthFoundationRepository;
  const flow = {
    withDb: () => flow,
    createAuthorizationTransaction: async (input: Record<string, unknown>) => {
      transaction = {
        id: String(input.id),
        oauthClientId: String(input.oauthClientId),
        oauthResourceId: String(input.oauthResourceId),
        redirectUri: String(input.redirectUri),
        requestedScopes: input.requestedScopes as string[],
        codeChallenge: String(input.codeChallenge),
        codeChallengeMethod: "S256",
        protectedDownstreamState: input.protectedDownstreamState as Record<string, unknown>,
        upstreamStateHash: String(input.upstreamStateHash),
        upstreamNonceHash: String(input.upstreamNonceHash),
        correlationId: String(input.correlationId),
        status: "pending",
        expiresAt: input.expiresAt as Date,
        claimedAt: null,
        completedAt: null,
        createdAt: input.createdAt as Date
      };
    },
    claimAuthorizationTransaction: async (stateHash: string, now: Date) => {
      if (!transaction || claimed || transaction.upstreamStateHash !== stateHash || transaction.expiresAt <= now) return null;
      claimed = true;
      return { ...transaction, status: "claimed", claimedAt: now };
    },
    denyClaimedTransaction: async () => claimed,
    issueAuthorizationCode: async (input: OAuthAuthorizationCodeIssuance) => {
      issuances.push(input);
      return { authorizationId: "00000000-0000-4000-8000-000000000105" };
    }
  } as unknown as OAuthAuthorizationFlowRepository;
  const txRepositories = {
    upsertUser: async () => ({ ...user, status: overrides.userStatus ?? "active" }),
    linkPendingEmailGrants: async () => { linkCalls += 1; },
    writeAudit: async (event: AuditEventInput) => { auditEvents.push(event); }
  };
  const legacy = {
    db: { transaction: async <T>(fn: (db: Db) => Promise<T>) => {
      transactionDepth += 1;
      try {
        return await fn({} as Db);
      } finally {
        transactionDepth -= 1;
      }
    } },
    withDb: () => txRepositories,
    findActiveGrant: async () => overrides.grant === false ? null : ({
      id: "00000000-0000-4000-8000-000000000106",
      tool_id: "00000000-0000-4000-8000-000000000104",
      user_id: user.id,
      email_normalized: user.email_normalized,
      role: "user",
      permissions: overrides.permissions ?? ["records:read", "records:write"],
      status: "active",
      valid_from: fixedNow,
      valid_until: null,
      created_by_user_id: null
    })
  } as unknown as Repositories;
  const audit = {
    write: async (event: AuditEventInput) => { auditEvents.push(event); }
  } as AuditLogger;
  const google = {
    createAuthorizationUrl: (input: { state: string; nonce: string }) => {
      upstreamState = input.state;
      upstreamNonce = input.nonce;
      return `https://accounts.google.invalid/auth?opaque=1`;
    },
    exchangeCodeForIdentity: async () => {
      if (transactionDepth !== 0) throw new Error("Google exchange occurred inside a database transaction");
      return { ...identityBase, nonce: upstreamNonce };
    }
  } as OAuthUpstreamGoogleClient;
  const service = new OAuthAuthorizationService({
    config,
    foundation,
    flow,
    legacy,
    audit,
    google,
    now: () => fixedNow
  });
  return {
    service,
    auditEvents,
    issuances,
    transaction: () => transaction,
    upstreamState: () => upstreamState,
    upstreamNonce: () => upstreamNonce,
    linkCalls: () => linkCalls,
    expire: () => {
      if (transaction) transaction.expiresAt = new Date(fixedNow.getTime() - 1);
    }
  };
}

describe("Step 3C migration 004", () => {
  it("creates exactly the three approved expand-only tables", () => {
    const tables = [...migration.matchAll(/CREATE TABLE IF NOT EXISTS\s+([a-z0-9_]+)/gi)].map((match) => match[1]);
    expect(tables).toEqual([
      "oauth_authorization_transactions",
      "oauth_authorizations",
      "oauth_authorization_codes"
    ]);
    expect(migration).not.toMatch(/\b(?:ALTER|DROP|RENAME|TRUNCATE)\b/i);
    expect(migration).not.toMatch(/\b(?:INSERT INTO|UPDATE|DELETE FROM)\s+(?:users|tools|tool_permissions|authorization_grants|sessions|refresh_tokens|one_time_codes)\b/i);
    expect(migration).not.toMatch(/oauth_(?:sessions|refresh|revocations?)/i);
  });

  it("constrains hash-only state/code persistence and exact 600/60 second TTLs", () => {
    expect(migration).toContain("upstream_state_hash text NOT NULL UNIQUE");
    expect(migration).toContain("upstream_nonce_hash text NOT NULL");
    expect(migration).toContain("protected_downstream_state jsonb NOT NULL");
    expect(migration).toContain("code_hash text NOT NULL UNIQUE");
    expect(migration).not.toMatch(/\b(?:downstream_state|authorization_code|raw_code)\s+text\b/i);
    expect(migration).toContain("interval '600 seconds'");
    expect(migration).toContain("interval '60 seconds'");
  });
});

describe("Step 3C OAuth state protection", () => {
  it("requires a canonical unpadded base64url 32-byte key", () => {
    const encoded = protectionKey.toString("base64url");
    expect(parseOAuthTransactionProtectionKey(encoded)).toEqual(protectionKey);
    for (const invalid of [`${encoded}=`, Buffer.alloc(31).toString("base64url"), "***", `${encoded} `]) {
      expect(() => parseOAuthTransactionProtectionKey(invalid)).toThrow("canonical unpadded base64url");
    }
  });

  it("round-trips exact state with unique IVs and rejects tamper, malformed envelopes and AAD swaps", () => {
    const first = protectOAuthDownstreamState("state exact + %2F", "transaction-a", protectionKey);
    const second = protectOAuthDownstreamState("state exact + %2F", "transaction-a", protectionKey);
    expect(first.iv).not.toBe(second.iv);
    expect(JSON.stringify(first)).not.toContain("state exact");
    expect(unprotectOAuthDownstreamState(first, "transaction-a", protectionKey)).toBe("state exact + %2F");
    expect(() => unprotectOAuthDownstreamState(first, "transaction-b", protectionKey)).toThrow("Invalid protected OAuth state");
    const tamperedTag = Buffer.from(first.tag, "base64url");
    tamperedTag[0] ^= 1;
    expect(() => unprotectOAuthDownstreamState(
      { ...first, tag: tamperedTag.toString("base64url") },
      "transaction-a",
      protectionKey
    )).toThrow("Invalid protected OAuth state");
    expect(() => unprotectOAuthDownstreamState({ ...first, extra: true }, "transaction-a", protectionKey))
      .toThrow("Invalid protected OAuth state");
  });
});

describe("Step 3C authorization request trust boundary", () => {
  it("persists only protected downstream state and independent upstream state/nonce hashes", async () => {
    const h = harness();
    const result = await h.service.authorize(validQuery, requestContext);
    expect(result).toEqual({ kind: "redirect", location: "https://accounts.google.invalid/auth?opaque=1" });
    const stored = h.transaction()!;
    expect(stored.expiresAt.getTime() - stored.createdAt.getTime()).toBe(OAUTH_AUTHORIZATION_TRANSACTION_TTL_MS);
    expect(JSON.stringify(stored.protectedDownstreamState)).not.toContain(String(validQuery.state));
    expect(stored.upstreamStateHash).toBe(sha256(h.upstreamState()));
    expect(stored.upstreamNonceHash).toBe(sha256(h.upstreamNonce()));
    expect(h.upstreamState()).not.toBe(h.upstreamNonce());
    expect(h.upstreamState()).not.toBe(validQuery.state);
    expect(h.upstreamNonce()).not.toBe(validQuery.state);
  });

  it("never redirects an unknown client or untrusted/repeated redirect", async () => {
    const unknown = harness({ client: null });
    expect((await unknown.service.authorize(validQuery, requestContext)).kind).toBe("local_error");

    const untrusted = harness();
    const badRedirect = await untrusted.service.authorize({ ...validQuery, redirect_uri: "https://attacker.invalid/cb" }, requestContext);
    expect(badRedirect).toMatchObject({ kind: "local_error", error: "invalid_request" });

    const repeated = harness();
    const repeatedRedirect = await repeated.service.authorize({
      ...validQuery,
      redirect_uri: [validQuery.redirect_uri, "https://attacker.invalid/cb"]
    }, requestContext);
    expect(repeatedRedirect).toMatchObject({ kind: "local_error", error: "invalid_request" });
  });

  it("rejects singleton, response type, resource, scope and exact PKCE failures after trust", async () => {
    for (const [field, value, error] of [
      ["response_type", "token", "unsupported_response_type"],
      ["resource", "https://unknown.invalid/api", "invalid_target"],
      ["scope", "synthetic:records:read  synthetic:records:write", "invalid_scope"],
      ["scope", "synthetic:records:read synthetic:records:read", "invalid_scope"],
      ["code_challenge", "A".repeat(42), "invalid_request"],
      ["code_challenge_method", "plain", "invalid_request"]
    ] as const) {
      const h = field === "resource" ? harness({ resource: null }) : harness();
      const result = await h.service.authorize({ ...validQuery, [field]: value }, requestContext);
      expect(result.kind).toBe("redirect");
      const location = new URL((result as { location: string }).location);
      expect(location.searchParams.get("error")).toBe(error);
      expect(location.searchParams.get("state")).toBe(validQuery.state);
      expect(location.searchParams.get("iss")).toBe(config.authIssuer);
      expect(location.searchParams.has("error_description")).toBe(false);
    }
    const repeated = harness();
    const result = await repeated.service.authorize({ ...validQuery, scope: [validQuery.scope, validQuery.scope] }, requestContext);
    expect(result.kind).toBe("redirect");
    expect(new URL((result as { location: string }).location).searchParams.get("error")).toBe("invalid_request");
  });

  it("fails closed when an explicit client/resource/scope allowance is absent", async () => {
    const h = harness({ allowed: false });
    const result = await h.service.authorize(validQuery, requestContext);
    expect(new URL((result as { location: string }).location).searchParams.get("error")).toBe("invalid_scope");
    expect(h.transaction()).toBeNull();
  });
});

describe("Step 3C callback, entitlement and issuance", () => {
  async function begin(h: ReturnType<typeof harness>) {
    await h.service.authorize(validQuery, requestContext);
    return { state: h.upstreamState(), code: "synthetic-google-code-never-persist" };
  }

  it("claims once, links pending grants and issues one hash-only 60-second code", async () => {
    const h = harness();
    const callbackQuery = await begin(h);
    const result = await h.service.callback(callbackQuery, requestContext);
    expect(result.kind).toBe("redirect");
    const location = new URL((result as { location: string }).location);
    const rawCode = location.searchParams.get("code")!;
    expect(Buffer.from(rawCode, "base64url")).toHaveLength(32);
    expect(location.origin + location.pathname).toBe("https://client.invalid/callback");
    expect(location.searchParams.get("existing")).toBe("kept");
    expect(location.searchParams.get("state")).toBe(validQuery.state);
    expect(location.searchParams.get("iss")).toBe(config.authIssuer);
    expect([...location.searchParams.keys()].sort()).toEqual(["code", "existing", "iss", "state"]);
    expect(h.linkCalls()).toBe(1);
    expect(h.issuances).toHaveLength(1);
    expect(h.issuances[0].codeHash).toBe(sha256(rawCode));
    expect(h.issuances[0]).not.toHaveProperty("code");
    expect(h.issuances[0].expiresAt.getTime() - h.issuances[0].issuedAt.getTime()).toBe(OAUTH_AUTHORIZATION_CODE_TTL_MS);

    const replay = await h.service.callback(callbackQuery, requestContext);
    expect(replay).toMatchObject({ kind: "local_error", error: "invalid_request" });
    expect(h.issuances).toHaveLength(1);
  });

  it("denies an expired callback before Google exchange", async () => {
    const h = harness();
    const callbackQuery = await begin(h);
    h.expire();
    const result = await h.service.callback(callbackQuery, requestContext);
    expect(result).toMatchObject({ kind: "local_error", error: "invalid_request" });
    expect(h.linkCalls()).toBe(0);
    expect(h.issuances).toHaveLength(0);
  });

  it("fails closed for nonce mismatch, disabled users, missing grants and missing exact permissions", async () => {
    for (const h of [
      harness({ userStatus: "disabled" }),
      harness({ grant: false }),
      harness({ permissions: ["records:read"] })
    ]) {
      const callbackQuery = await begin(h);
      const result = await h.service.callback(callbackQuery, requestContext);
      expect(new URL((result as { location: string }).location).searchParams.get("error")).toBe("access_denied");
      expect(h.issuances).toHaveLength(0);
    }
    const nonce = harness();
    const callbackQuery = await begin(nonce);
    const stored = nonce.transaction()!;
    stored.upstreamNonceHash = sha256("different-nonce");
    const result = await nonce.service.callback(callbackQuery, requestContext);
    expect(new URL((result as { location: string }).location).searchParams.get("error")).toBe("access_denied");
    expect(nonce.issuances).toHaveLength(0);
  });

  it("revalidates registration and exact mappings after the Google round-trip", async () => {
    const disabledClient = { ...client, status: "disabled" as const };
    const h = harness({ callbackClient: disabledClient });
    const callbackQuery = await begin(h);
    const disabledResult = await h.service.callback(callbackQuery, requestContext);
    expect(new URL((disabledResult as { location: string }).location).searchParams.get("error"))
      .toBe("unauthorized_client");
    expect(h.issuances).toHaveLength(0);

    const stale = harness({ entitlement: false });
    const staleQuery = await begin(stale);
    const result = await stale.service.callback(staleQuery, requestContext);
    expect(new URL((result as { location: string }).location).searchParams.get("error")).toBe("invalid_scope");
    expect(stale.issuances).toHaveLength(0);
  });

  it("emits only sanitized required events without state, nonce, PKCE, Google code or issued code", async () => {
    const h = harness();
    const callbackQuery = await begin(h);
    const result = await h.service.callback(callbackQuery, requestContext);
    const rawCode = new URL((result as { location: string }).location).searchParams.get("code")!;
    expect(h.auditEvents.map((event) => event.event_type)).toEqual([
      "oauth.authorization.requested",
      "oauth.authorization.allowed",
      "oauth.code.issued"
    ]);
    const serialized = JSON.stringify(h.auditEvents);
    for (const forbidden of [
      String(validQuery.state),
      String(validQuery.code_challenge),
      h.upstreamState(),
      h.upstreamNonce(),
      callbackQuery.code,
      rawCode
    ]) expect(serialized).not.toContain(forbidden);
  });
});

describe("Step 3C repository boundary", () => {
  it("keeps flow SQL writes confined to oauth_* tables and legacy mutations to the two approved methods", () => {
    const flowSource = readFileSync(resolve(root, "src/oauth/flow-repository.ts"), "utf8");
    expect(flowSource).not.toMatch(/\b(?:INSERT INTO|UPDATE|DELETE FROM)\s+(?:users|tools|tool_permissions|authorization_grants|sessions|refresh_tokens|one_time_codes|access_requests)\b/i);
    const serviceSource = readFileSync(resolve(root, "src/oauth/authorization.ts"), "utf8");
    expect(serviceSource).toContain("upsertUser");
    expect(serviceSource).toContain("linkPendingEmailGrants");
    expect(serviceSource).not.toMatch(/create(?:Grant|Session|AuthRequest|AccessRequest|OneTimeCode)/);
  });

  it("claims callback state atomically before any Google exchange and binds issuance completion to claimed status", () => {
    const source = readFileSync(resolve(root, "src/oauth/flow-repository.ts"), "utf8");
    expect(source).toMatch(/UPDATE oauth_authorization_transactions[\s\S]*status = 'pending'[\s\S]*expires_at > \$2[\s\S]*RETURNING \*/);
    expect(source).toMatch(/SET status = 'completed'[\s\S]*WHERE id = \$1 AND status = 'claimed'/);
  });

  it("suppresses automatic request logging and never logs raw authorization inputs", () => {
    const httpSource = readFileSync(resolve(root, "src/oauth/http.ts"), "utf8");
    expect(httpSource).toContain('logLevel: "silent"');
    expect(httpSource).not.toMatch(/request\.log\.(?:info|warn|error|debug)/);
    const authorizationSource = readFileSync(resolve(root, "src/oauth/authorization.ts"), "utf8");
    expect(authorizationSource).not.toMatch(/metadata:\s*\{[^}]*?(?:state|nonce|challenge|googleCode|rawCode)/s);
  });
});
