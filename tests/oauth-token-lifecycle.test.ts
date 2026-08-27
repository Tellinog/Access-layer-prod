import { createHash, createPrivateKey, generateKeyPairSync } from "node:crypto";
import { mkdtemp, mkdir, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { decodeJwt, decodeProtectedHeader, exportJWK, SignJWT } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { Db } from "../src/db.js";
import { hashOAuthCredentialSecret, sha256 } from "../src/security.js";
import {
  OAUTH_ACCESS_TOKEN_TTL_SECONDS,
  OAUTH_SIGNING_KEY_MAX_BYTES,
  OAuthAccessTokenSigner,
  OAuthSigningUnavailableError,
  loadOAuthPrivateSigningKey,
  selectOAuthSigningKey,
  verifyOAuthAccessToken,
  type OAuthSigningKeyRecord
} from "../src/oauth/signing.js";
import {
  OAuthCoreError,
  OAuthTokenLifecycleService,
  OAUTH_REFRESH_IDLE_MS
} from "../src/oauth/token-service.js";
import {
  OAuthTokenRepository,
  type OAuthAuthorizationCodeContext,
  type OAuthClientAuthenticationRecord,
  type OAuthEntitlementMapping,
  type OAuthRefreshContext,
  type OAuthResourceAuthenticationRecord
} from "../src/oauth/token-repository.js";
import type { OAuthSigningKeyPublicMetadata } from "../src/oauth/types.js";
import { readFileSync } from "node:fs";

const fixedNow = new Date("2026-08-27T10:00:00.000Z");
const issuer = "https://access-layer.example.test";
const resourceId = "https://api.example.test/v1";
const clientId = "client.test";
const oauthClientId = "11111111-1111-4111-8111-111111111111";
const oauthResourceId = "22222222-2222-4222-8222-222222222222";
const userId = "33333333-3333-4333-8333-333333333333";
const authorizationId = "44444444-4444-4444-8444-444444444444";
const grantId = "55555555-5555-4555-8555-555555555555";
const toolId = "66666666-6666-4666-8666-666666666666";
const scopes = ["project:domain:read", "project:domain:write"];
const permissions = ["legacy:read", "legacy:write"];
const pepper = "oauth-only-pepper-value";
const clientSecret = "oauth-client-secret-value";
const resourceSecret = "oauth-resource-secret-value";
const verifier = "v".repeat(43);
const challenge = createHash("sha256").update(verifier).digest("base64url");

let tempRoot: string;
let privateKeyPath: string;
let privateKeyPem: string;
let signingKey: OAuthSigningKeyRecord;

function publicFingerprint(jwk: Record<string, unknown>): string {
  return createHash("sha256")
    .update(JSON.stringify({ e: jwk.e, kty: "RSA", n: jwk.n }))
    .digest("hex");
}

beforeAll(async () => {
  tempRoot = await mkdtemp(join(tmpdir(), "oauth-signing-"));
  const pair = generateKeyPairSync("rsa", { modulusLength: 2048 });
  privateKeyPath = join(tempRoot, "oauth-key.pem");
  privateKeyPem = pair.privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  await writeFile(privateKeyPath, privateKeyPem);
  const publicNumbers = await exportJWK(pair.publicKey);
  const publicJwk = { ...publicNumbers, kid: "oauth-kid-1", alg: "RS256", use: "sig" };
  signingKey = {
    id: "77777777-7777-4777-8777-777777777777",
    kid: "oauth-kid-1",
    algorithm: "RS256",
    publicJwk,
    publicKeyFingerprintSha256: publicFingerprint(publicJwk),
    protectedPrivateKeyRef: privateKeyPath,
    status: "active",
    publishedAt: new Date(fixedNow.getTime() - 600_000),
    activatesAt: new Date(fixedNow.getTime() - 300_000),
    lastSignedAt: null,
    retireAfter: null,
    retiredAt: null
  };
});

afterAll(async () => {
  await rm(tempRoot, { recursive: true, force: true });
});

describe("migration 005 OAuth-only shape", () => {
  const sql = readFileSync(resolve("migrations/005_oauth_token_lifecycle.sql"), "utf8");

  it("creates exactly the four approved tables and remains expand-only", () => {
    const tables = [...sql.matchAll(/CREATE TABLE IF NOT EXISTS\s+([a-z0-9_]+)/gi)].map((match) => match[1]);
    expect(tables).toEqual([
      "oauth_sessions", "oauth_refresh_token_families", "oauth_refresh_tokens", "oauth_revocations"
    ]);
    expect(sql).not.toMatch(/\b(?:ALTER|DROP|TRUNCATE|DELETE|INSERT\s+INTO|UPDATE)\s+(?:users|tools|tool_clients|authorization_grants|sessions|refresh_tokens|one_time_codes)\b/i);
    expect(sql).toContain("interval '28800 seconds'");
    expect(sql).toContain("idx_oauth_refresh_tokens_one_current_family_member");
    expect(sql).toContain("WHERE status = 'current'");
    expect(sql).toContain("token_hash ~ '^[A-Za-z0-9_-]{43}$'");
    expect(sql).toContain("parent_refresh_token_id");
    expect(sql).toContain("replay_detected_at");
    expect(sql).toContain("target_type = 'access_token_jti' AND expires_at IS NOT NULL");
  });

  it("does not modify frozen migrations 001 through 004", () => {
    const hashes = [
      ["001_initial.sql", "62b7ec1d729feb091f5df01bd5ea636614a9c3b60c98a990413e1ba3212c015d"],
      ["002_audit_tool_delete_fk.sql", "ab33b34abb01fa606eeafc9eab3d7dcfdafbc9429bd67bee6a64c35851638b22"],
      ["003_oauth_dark_foundation.sql", "96b3993fcfdb930597cbdeca37e86d51df486fd9e951970d156a21c454f18efe"],
      ["004_oauth_authorization_code_flow.sql", "407b0fe9b3c9e053e22fac7e9640e0b4d02fe341ea6b3e7f05bb32eeaa8efede"]
    ];
    for (const [name, expected] of hashes) {
      const actual = createHash("sha256").update(readFileSync(resolve("migrations", name)).toString().replaceAll("\r\n", "\n")).digest("hex");
      expect(actual, name).toBe(expected);
    }
  });
});

describe("OAuth-only signing boundary", () => {
  it("selects exactly one active non-retiring key and rejects zero or ambiguity", () => {
    expect(selectOAuthSigningKey([signingKey], fixedNow).kid).toBe("oauth-kid-1");
    expect(() => selectOAuthSigningKey([], fixedNow)).toThrow(OAuthSigningUnavailableError);
    expect(() => selectOAuthSigningKey([signingKey, { ...signingKey, id: "other", kid: "other", publicJwk: { ...signingKey.publicJwk, kid: "other" } }], fixedNow))
      .toThrow(OAuthSigningUnavailableError);
    expect(() => selectOAuthSigningKey([{ ...signingKey, retireAfter: new Date(fixedNow.getTime() + 1_260_000) }], fixedNow))
      .toThrow(OAuthSigningUnavailableError);
  });

  it("issues exact 900-second RFC 9068 material with sid and no PII", async () => {
    const signer = new OAuthAccessTokenSigner({ issuer, signingKeyRoot: tempRoot });
    const issued = await signer.issue({
      key: signingKey, subject: "google-subject", audience: resourceId, clientId,
      scopes, sessionId: "oauth-session-id", now: fixedNow
    });
    const header = decodeProtectedHeader(issued.token);
    const claims = decodeJwt(issued.token);
    expect(header).toEqual({ alg: "RS256", kid: "oauth-kid-1", typ: "at+jwt" });
    expect(Object.keys(claims).sort()).toEqual([
      "aud", "client_id", "exp", "iat", "iss", "jti", "principal_type", "scope", "sid", "sub"
    ]);
    expect(claims.exp! - claims.iat!).toBe(OAUTH_ACCESS_TOKEN_TTL_SECONDS);
    expect(claims).toMatchObject({
      iss: issuer, sub: "google-subject", aud: resourceId, client_id: clientId,
      scope: scopes.join(" "), principal_type: "human", sid: "oauth-session-id"
    });
    expect(JSON.stringify(claims)).not.toMatch(/email|hd|role|permissions/i);
    await expect(verifyOAuthAccessToken({
      token: issued.token, issuer, audience: resourceId, keys: [signingKey], now: fixedNow
    })).resolves.toMatchObject({ sub: "google-subject", sid: "oauth-session-id" });
    await expect(verifyOAuthAccessToken({
      token: issued.token, issuer, audience: "https://wrong.example.test", keys: [signingKey], now: fixedNow
    })).rejects.toThrow(OAuthSigningUnavailableError);
  });

  it("rejects relative, unsupported, encoded traversal, outside-root, non-regular, oversized and legacy refs", async () => {
    const outsideRoot = await mkdtemp(join(tmpdir(), "oauth-outside-"));
    const outsideKey = join(outsideRoot, "outside.pem");
    await writeFile(outsideKey, "not-a-key");
    const directory = join(tempRoot, "directory");
    await mkdir(directory);
    const oversized = join(tempRoot, "oversized.pem");
    await writeFile(oversized, Buffer.alloc(OAUTH_SIGNING_KEY_MAX_BYTES + 1));
    const legacy = join(tempRoot, "access-layer-jwt-private.pem");
    await writeFile(legacy, readFileSync(privateKeyPath));
    const refs = [
      "relative.pem", "vault://oauth/key", `file://${tempRoot.replaceAll("\\", "/")}/%2e%2e/key.pem`,
      outsideKey, directory, oversized, legacy
    ];
    for (const reference of refs) {
      await expect(loadOAuthPrivateSigningKey({
        root: tempRoot, key: { ...signingKey, protectedPrivateKeyRef: reference }, legacyPrivateKeyPath: legacy
      }), reference).rejects.toThrow(OAuthSigningUnavailableError);
    }
    await rm(outsideRoot, { recursive: true, force: true });
  });

  it("rejects symlink escape and public-key/fingerprint mismatch", async () => {
    const outsideRoot = await mkdtemp(join(tmpdir(), "oauth-symlink-outside-"));
    const outsideKey = join(outsideRoot, "outside.pem");
    await writeFile(outsideKey, readFileSync(privateKeyPath));
    const link = join(tempRoot, "escaped-link.pem");
    let symlinkSupported = true;
    try {
      await symlink(outsideKey, link, "file");
    } catch (error) {
      symlinkSupported = (error as NodeJS.ErrnoException).code === "EPERM" ? false : (() => { throw error; })();
    }
    if (symlinkSupported) {
      await expect(loadOAuthPrivateSigningKey({
        root: tempRoot, key: { ...signingKey, protectedPrivateKeyRef: link }
      })).rejects.toThrow(OAuthSigningUnavailableError);
    }
    const otherPair = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const otherJwkBase = await exportJWK(otherPair.publicKey);
    const otherJwk = { ...otherJwkBase, kid: signingKey.kid, alg: "RS256", use: "sig" };
    await expect(loadOAuthPrivateSigningKey({
      root: tempRoot, key: { ...signingKey, publicJwk: otherJwk,
        publicKeyFingerprintSha256: publicFingerprint(otherJwk) }
    })).rejects.toThrow(OAuthSigningUnavailableError);
    await expect(loadOAuthPrivateSigningKey({
      root: tempRoot, key: { ...signingKey, publicKeyFingerprintSha256: "0".repeat(64) }
    })).rejects.toThrow(OAuthSigningUnavailableError);
    await rm(outsideRoot, { recursive: true, force: true });
  });

  it("rejects copied or renamed legacy key material and inline legacy PEM identity", async () => {
    const copiedLegacy = join(tempRoot, "innocent-oauth-name.pem");
    await writeFile(copiedLegacy, privateKeyPem);
    for (const legacyInput of [
      { legacyPrivateKeyPath: privateKeyPath },
      { legacyPrivateKeyPem: privateKeyPem }
    ]) {
      await expect(loadOAuthPrivateSigningKey({
        root: tempRoot,
        key: { ...signingKey, protectedPrivateKeyRef: copiedLegacy },
        ...legacyInput
      })).rejects.toThrow(OAuthSigningUnavailableError);
    }
  });

  it("enforces verification retirement boundary and finite integer non-future JWT times", async () => {
    const signer = new OAuthAccessTokenSigner({ issuer, signingKeyRoot: tempRoot });
    const issued = await signer.issue({
      key: signingKey, subject: "google-subject", audience: resourceId, clientId,
      scopes, sessionId: "oauth-session-id", now: fixedNow
    });
    const overlapBase = {
      ...signingKey,
      publishedAt: new Date(fixedNow.getTime() - 1_600_000),
      activatesAt: new Date(fixedNow.getTime() - 1_300_000),
      lastSignedAt: new Date(fixedNow.getTime() - 1_260_000)
    };
    await expect(verifyOAuthAccessToken({
      token: issued.token, issuer, audience: resourceId,
      keys: [{ ...overlapBase, retireAfter: new Date(fixedNow.getTime() + 1) }], now: fixedNow
    })).resolves.toMatchObject({ sub: "google-subject" });
    for (const retireAfter of [fixedNow, new Date(fixedNow.getTime() - 1)]) {
      await expect(verifyOAuthAccessToken({
        token: issued.token, issuer, audience: resourceId,
        keys: [{ ...overlapBase, retireAfter }], now: fixedNow
      })).rejects.toThrow(OAuthSigningUnavailableError);
    }

    const nowSeconds = Math.floor(fixedNow.getTime() / 1000);
    const signWithTimes = async (iat: number, exp: number) => new SignJWT({
      client_id: clientId, scope: scopes.join(" "), principal_type: "human", sid: "oauth-session-id"
    }).setProtectedHeader({ alg: "RS256", kid: signingKey.kid, typ: "at+jwt" })
      .setIssuer(issuer).setSubject("google-subject").setAudience(resourceId)
      .setIssuedAt(iat).setExpirationTime(exp).setJti("oauth-jti-test").sign(createPrivateKey(privateKeyPem));
    const futureToken = await signWithTimes(nowSeconds + 61, nowSeconds + 961);
    await expect(verifyOAuthAccessToken({
      token: futureToken, issuer, audience: resourceId, keys: [signingKey], now: fixedNow
    })).rejects.toThrow(OAuthSigningUnavailableError);
    const fractionalToken = await signWithTimes(nowSeconds + 0.5, nowSeconds + 900.5);
    await expect(verifyOAuthAccessToken({
      token: fractionalToken, issuer, audience: resourceId, keys: [signingKey], now: fixedNow
    })).rejects.toThrow(OAuthSigningUnavailableError);
  });
});

const noDb: Db = {
  query: async () => { throw new Error("unexpected SQL"); },
  transaction: async (fn) => fn(noDb),
  close: async () => undefined
};

function codeContext(): OAuthAuthorizationCodeContext {
  return {
    codeId: "code-id", oauthAuthorizationId: authorizationId, oauthClientId, clientId,
    clientStatus: "active", clientGrantTypes: ["authorization_code", "refresh_token"],
    oauthResourceId, resourceId, resourceStatus: "active", audiencePolicy: "exact_single_resource",
    userId, googleSub: "google-subject", userStatus: "active", redirectUri: "https://client.example.test/callback",
    grantedScopes: [...scopes], authorizationGrantedScopes: [...scopes],
    codeChallenge: challenge, codeChallengeMethod: "S256",
    correlationId: "correlation-code", issuedAt: fixedNow,
    expiresAt: new Date(fixedNow.getTime() + 60_000), consumedAt: null,
    authorizationStatus: "active", legacyAuthorizationGrantId: grantId, grantToolId: toolId,
    grantUserId: userId, grantEmailNormalized: "person@example.test", userEmailNormalized: "person@example.test",
    grantStatus: "active", grantValidFrom: new Date(fixedNow.getTime() - 1_000), grantValidUntil: null,
    grantPermissions: [...permissions]
  };
}

class MemoryOAuthTokenRepository extends OAuthTokenRepository {
  private tail = Promise.resolve();
  clientCredentialHash = "";
  resourceCredentialHash = "";
  code = codeContext();
  mappings: OAuthEntitlementMapping[] = scopes.map((scope, index) => ({ scope, legacyPermissionKey: permissions[index] }));
  refreshByHash = new Map<string, OAuthRefreshContext>();
  lastInitial: Record<string, unknown> | null = null;
  lastRotation: Record<string, unknown> | null = null;
  replayRevoked = false;
  familyRevoked = false;
  accessRevoked = false;
  onlineActive = true;
  introspections: boolean[] = [];
  codeDenials: Array<Record<string, unknown>> = [];
  failCodeDenialAudit = false;
  clientType: "confidential" | "public" = "confidential";

  constructor() { super(noDb); }

  override async transaction<T>(fn: (repository: OAuthTokenRepository) => Promise<T>): Promise<T> {
    let release!: () => void;
    const previous = this.tail;
    this.tail = new Promise<void>((resolvePromise) => { release = resolvePromise; });
    await previous;
    try { return await fn(this); } finally { release(); }
  }

  override async lockClientForAuthentication(value: string): Promise<OAuthClientAuthenticationRecord | null> {
    return value === clientId ? {
      id: oauthClientId, clientId, clientType: this.clientType,
      authenticationMethod: this.clientType === "confidential" ? "client_secret_basic" : "none",
      grantTypes: ["authorization_code", "refresh_token"], status: "active"
    } : null;
  }
  override async listCurrentClientCredentialHashes(): Promise<string[]> { return [this.clientCredentialHash]; }
  override async listCurrentResourceCredentialRecords(value: string): Promise<OAuthResourceAuthenticationRecord[]> {
    return value === "resource-credential" ? [{
      credentialId: value, oauthResourceId, resourceId, secretHash: this.resourceCredentialHash
    }] : [];
  }
  override async lockAuthorizationCodeByHash(value: string): Promise<OAuthAuthorizationCodeContext | null> {
    return value === sha256("raw-code") ? {
      ...this.code,
      grantedScopes: [...this.code.grantedScopes],
      authorizationGrantedScopes: [...this.code.authorizationGrantedScopes]
    } : null;
  }
  override async lockCurrentEntitlementMappings(
    _oauthClientId: string,
    _oauthResourceId: string,
    _grantToolId: string,
    requestedScopes: string[]
  ): Promise<OAuthEntitlementMapping[]> {
    return this.mappings.filter((mapping) => requestedScopes.includes(mapping.scope));
  }
  override async listSignableKeysForUpdate(): Promise<OAuthSigningKeyRecord[]> { return [signingKey]; }
  override async listVerificationKeys(): Promise<OAuthSigningKeyPublicMetadata[]> { return [signingKey]; }
  override async persistInitialIssuance(input: Parameters<OAuthTokenRepository["persistInitialIssuance"]>[0]): Promise<void> {
    if (this.code.consumedAt) throw new Error("race");
    this.code.consumedAt = input.now;
    this.lastInitial = input as unknown as Record<string, unknown>;
    this.refreshByHash.set(input.refreshTokenHash, {
      refreshTokenId: input.refreshTokenId, tokenStatus: "current", tokenGeneration: 0,
      tokenScopes: [...scopes], tokenExpiresAt: input.idleExpiresAt, familyId: input.familyId,
      familyStatus: "active", familyCurrentGeneration: 0, scopeCeiling: [...scopes], currentScopes: [...scopes],
      sessionId: input.sessionId, sessionStatus: "active", sessionIdleExpiresAt: input.idleExpiresAt,
      oauthAuthorizationId: authorizationId, authorizationStatus: "active", oauthClientId, clientId,
      authorizationGrantedScopes: [...scopes],
      clientStatus: "active", clientGrantTypes: ["authorization_code", "refresh_token"], oauthResourceId,
      resourceId, resourceStatus: "active", audiencePolicy: "exact_single_resource", userId,
      googleSub: "google-subject", userStatus: "active", userEmailNormalized: "person@example.test",
      legacyAuthorizationGrantId: grantId, grantToolId: toolId, grantUserId: userId,
      grantEmailNormalized: "person@example.test", grantStatus: "active",
      grantValidFrom: new Date(fixedNow.getTime() - 1_000), grantValidUntil: null,
      grantPermissions: [...permissions], correlationId: "correlation-code"
    });
  }
  override async lockRefreshByHash(value: string): Promise<OAuthRefreshContext | null> {
    return this.refreshByHash.get(value) ?? null;
  }
  override async persistRefreshRotation(input: Parameters<OAuthTokenRepository["persistRefreshRotation"]>[0]): Promise<void> {
    input.context.tokenStatus = "consumed";
    this.lastRotation = input as unknown as Record<string, unknown>;
    this.refreshByHash.set(input.replacementHash, {
      ...input.context, refreshTokenId: input.replacementTokenId, tokenStatus: "current",
      tokenGeneration: input.context.tokenGeneration + 1, tokenScopes: [...input.scopes],
      tokenExpiresAt: input.idleExpiresAt, familyCurrentGeneration: input.context.familyCurrentGeneration + 1,
      currentScopes: [...input.scopes], sessionIdleExpiresAt: input.idleExpiresAt
    });
  }
  override async revokeRefreshReplay(context: OAuthRefreshContext): Promise<void> {
    this.replayRevoked = true; context.familyStatus = "revoked"; context.sessionStatus = "revoked";
  }
  override async revokeRefreshFamily(context: OAuthRefreshContext): Promise<void> {
    this.familyRevoked = true; context.familyStatus = "revoked"; context.sessionStatus = "revoked";
  }
  override async resolveOAuthResourceInternalId(): Promise<string | null> { return oauthResourceId; }
  override async recordAccessTokenRevocation(): Promise<void> { this.accessRevoked = true; }
  override async writeRevocationAudit(): Promise<void> { return undefined; }
  override async isAccessTokenActiveOnline(): Promise<boolean> { return this.onlineActive && !this.accessRevoked; }
  override async writeIntrospectionAudit(input: { active: boolean }): Promise<void> { this.introspections.push(input.active); }
  override async recordCodeExchangeDeniedAudit(input: Record<string, unknown>): Promise<void> {
    if (this.failCodeDenialAudit) throw new Error("audit unavailable");
    this.codeDenials.push(input);
  }
}

async function serviceFixture() {
  const repository = new MemoryOAuthTokenRepository();
  repository.clientCredentialHash = await hashOAuthCredentialSecret(clientSecret, pepper);
  repository.resourceCredentialHash = await hashOAuthCredentialSecret(resourceSecret, pepper);
  return {
    repository,
    service: new OAuthTokenLifecycleService({
      config: {
        authIssuer: issuer,
        oauthCredentialSecretPepper: pepper,
        oauthSigningKeyRoot: tempRoot,
        toolClientSecretPepper: "legacy-tool-only-pepper"
      },
      repository, now: () => fixedNow
    })
  };
}

describe("OAuth token-lifecycle service", () => {
  it("exchanges a code once with exact PKCE/current entitlement and hash-only refresh persistence", async () => {
    const { repository, service } = await serviceFixture();
    const response = await service.exchangeAuthorizationCode({
      code: "raw-code", clientId, clientSecret, redirectUri: repository.code.redirectUri,
      resource: resourceId, codeVerifier: verifier
    });
    expect(response).toMatchObject({ tokenType: "Bearer", expiresIn: 900, scope: scopes.join(" ") });
    expect(response.refreshToken).toMatch(/^oauth_rt_[A-Za-z0-9_-]{43}$/);
    expect(JSON.stringify(repository.lastInitial)).not.toContain(response.refreshToken);
    expect(repository.lastInitial).toMatchObject({
      refreshTokenHash: sha256(response.refreshToken),
      idleExpiresAt: new Date(fixedNow.getTime() + OAUTH_REFRESH_IDLE_MS)
    });
    await expect(service.exchangeAuthorizationCode({
      code: "raw-code", clientId, clientSecret, redirectUri: repository.code.redirectUri,
      resource: resourceId, codeVerifier: verifier
    })).rejects.toMatchObject({ code: "invalid_grant" });
  });

  it("denies wrong bindings, PKCE, credentials and stale entitlement without persistence", async () => {
    for (const mutate of [
      (request: Record<string, string>) => { request.codeVerifier = "x".repeat(43); },
      (request: Record<string, string>) => { request.redirectUri = "https://other.example.test/callback"; },
      (request: Record<string, string>) => { request.resource = "https://other.example.test/v1"; },
      (request: Record<string, string>) => { request.clientSecret = "wrong-secret"; }
    ]) {
      const { repository, service } = await serviceFixture();
      const request = { code: "raw-code", clientId, clientSecret, redirectUri: repository.code.redirectUri,
        resource: resourceId, codeVerifier: verifier };
      mutate(request);
      await expect(service.exchangeAuthorizationCode(request)).rejects.toBeInstanceOf(OAuthCoreError);
      expect(repository.lastInitial).toBeNull();
      expect(repository.codeDenials).toHaveLength(1);
    }
    const { repository, service } = await serviceFixture();
    repository.mappings = [];
    await expect(service.exchangeAuthorizationCode({
      code: "raw-code", clientId, clientSecret, redirectUri: repository.code.redirectUri,
      resource: resourceId, codeVerifier: verifier
    })).rejects.toMatchObject({ code: "invalid_grant" });
    expect(repository.codeDenials).toHaveLength(1);
  });

  it("requires code scopes to equal the active authorization scope set", async () => {
    const { repository, service } = await serviceFixture();
    repository.code.authorizationGrantedScopes = [scopes[0]];
    await expect(service.exchangeAuthorizationCode({
      code: "raw-code", clientId, clientSecret, redirectUri: repository.code.redirectUri,
      resource: resourceId, codeVerifier: verifier
    })).rejects.toMatchObject({ code: "invalid_grant" });
    expect(repository.lastInitial).toBeNull();
    expect(repository.codeDenials).toHaveLength(1);
  });

  it("writes sanitized code denial audit separately and fails closed if that audit cannot persist", async () => {
    const forbidden = {
      code: "raw-code",
      secret: clientSecret,
      verifier,
      access: "oauth-access-token-value",
      refresh: "oauth-refresh-token-value",
      cookie: "session-cookie-value",
      key: privateKeyPem
    };
    for (const request of [
      { code: "unknown-code", clientId, clientSecret, redirectUri: "https://client.example.test/callback",
        resource: resourceId, codeVerifier: verifier },
      { code: "raw-code", clientId: "unknown-client", clientSecret, redirectUri: "https://client.example.test/callback",
        resource: resourceId, codeVerifier: verifier },
      { code: "raw-code", clientId, clientSecret, redirectUri: "https://client.example.test/callback",
        resource: resourceId, codeVerifier: "x".repeat(43) }
    ]) {
      const { repository, service } = await serviceFixture();
      await expect(service.exchangeAuthorizationCode(request)).rejects.toBeInstanceOf(OAuthCoreError);
      expect(repository.codeDenials).toHaveLength(1);
      const serialized = JSON.stringify(repository.codeDenials[0]);
      for (const value of Object.values(forbidden)) expect(serialized).not.toContain(value);
    }

    const { repository, service } = await serviceFixture();
    repository.failCodeDenialAudit = true;
    await expect(service.exchangeAuthorizationCode({
      code: "unknown-code", clientId, clientSecret, redirectUri: "https://client.example.test/callback",
      resource: resourceId, codeVerifier: verifier
    })).rejects.toMatchObject({ code: "temporarily_unavailable" });
  });

  it("fails closed when the OAuth and legacy credential peppers are equal", async () => {
    const repository = new MemoryOAuthTokenRepository();
    const service = new OAuthTokenLifecycleService({
      config: {
        authIssuer: issuer,
        oauthCredentialSecretPepper: pepper,
        oauthSigningKeyRoot: tempRoot,
        toolClientSecretPepper: pepper
      },
      repository,
      now: () => fixedNow
    });
    await expect(service.exchangeAuthorizationCode({
      code: "raw-code", clientId, clientSecret, redirectUri: repository.code.redirectUri,
      resource: resourceId, codeVerifier: verifier
    })).rejects.toMatchObject({ code: "temporarily_unavailable" });
    expect(JSON.stringify(repository.codeDenials)).not.toContain(pepper);
  });

  it("uses public-client none without a secret and never falls back to a legacy credential", async () => {
    const { repository, service } = await serviceFixture();
    repository.clientType = "public";
    await expect(service.exchangeAuthorizationCode({
      code: "raw-code", clientId, redirectUri: repository.code.redirectUri,
      resource: resourceId, codeVerifier: verifier
    })).resolves.toMatchObject({ tokenType: "Bearer" });

    const second = await serviceFixture();
    second.repository.clientType = "public";
    await expect(second.service.exchangeAuthorizationCode({
      code: "raw-code", clientId, clientSecret: "legacy-tool-secret",
      redirectUri: second.repository.code.redirectUri, resource: resourceId, codeVerifier: verifier
    })).rejects.toMatchObject({ code: "invalid_client" });
  });

  it("serializes concurrent code exchange so exactly one succeeds", async () => {
    const { repository, service } = await serviceFixture();
    const request = { code: "raw-code", clientId, clientSecret, redirectUri: repository.code.redirectUri,
      resource: resourceId, codeVerifier: verifier };
    const results = await Promise.allSettled([
      service.exchangeAuthorizationCode(request), service.exchangeAuthorizationCode(request)
    ]);
    expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(1);
    expect(results.filter((result) => result.status === "rejected")).toHaveLength(1);
  });

  it("rotates with exact lineage, monotonic scope narrowing and an exact 28,800-second idle slide", async () => {
    const { repository, service } = await serviceFixture();
    const issued = await service.exchangeAuthorizationCode({
      code: "raw-code", clientId, clientSecret, redirectUri: repository.code.redirectUri,
      resource: resourceId, codeVerifier: verifier
    });
    const refreshed = await service.refresh({
      refreshToken: issued.refreshToken, clientId, clientSecret, resource: resourceId,
      scope: scopes[0]
    });
    expect(refreshed.scope).toBe(scopes[0]);
    expect(repository.lastRotation).toMatchObject({
      replacementHash: sha256(refreshed.refreshToken), scopes: [scopes[0]],
      idleExpiresAt: new Date(fixedNow.getTime() + OAUTH_REFRESH_IDLE_MS)
    });
    await expect(service.refresh({
      refreshToken: refreshed.refreshToken, clientId, clientSecret, resource: resourceId,
      scope: scopes.join(" ")
    })).rejects.toMatchObject({ code: "invalid_scope" });
  });

  it("treats consumed refresh reuse and concurrent losers as replay that revokes family and session", async () => {
    const { repository, service } = await serviceFixture();
    const issued = await service.exchangeAuthorizationCode({
      code: "raw-code", clientId, clientSecret, redirectUri: repository.code.redirectUri,
      resource: resourceId, codeVerifier: verifier
    });
    const results = await Promise.allSettled([
      service.refresh({ refreshToken: issued.refreshToken, clientId, clientSecret, resource: resourceId }),
      service.refresh({ refreshToken: issued.refreshToken, clientId, clientSecret, resource: resourceId })
    ]);
    expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(1);
    expect(results.filter((result) => result.status === "rejected")).toHaveLength(1);
    expect(repository.replayRevoked).toBe(true);
  });

  it("denies expired, revoked or no-longer-authorized refresh state", async () => {
    for (const mutate of [
      (context: OAuthRefreshContext) => { context.tokenExpiresAt = new Date(fixedNow.getTime() - 1); },
      (context: OAuthRefreshContext) => { context.familyStatus = "revoked"; },
      (context: OAuthRefreshContext) => { context.authorizationStatus = "revoked"; }
    ]) {
      const { repository, service } = await serviceFixture();
      const issued = await service.exchangeAuthorizationCode({
        code: "raw-code", clientId, clientSecret, redirectUri: repository.code.redirectUri,
        resource: resourceId, codeVerifier: verifier
      });
      mutate(repository.refreshByHash.get(sha256(issued.refreshToken))!);
      await expect(service.refresh({
        refreshToken: issued.refreshToken, clientId, clientSecret, resource: resourceId
      })).rejects.toMatchObject({ code: "invalid_grant" });
      expect(repository.lastRotation).toBeNull();
    }
  });

  it("rejects every inconsistent persisted refresh generation/scope state", async () => {
    const corruptions: Array<(context: OAuthRefreshContext) => void> = [
      (context) => { context.tokenGeneration = context.familyCurrentGeneration + 1; },
      (context) => { context.tokenScopes = [scopes[0]]; },
      (context) => {
        context.currentScopes = [...scopes, "project:domain:admin"];
        context.tokenScopes = [...context.currentScopes];
        context.authorizationGrantedScopes = [...context.currentScopes];
      },
      (context) => { context.scopeCeiling = [...scopes, "project:domain:admin"]; },
      (context) => { context.authorizationGrantedScopes = [scopes[0]]; }
    ];
    for (const corrupt of corruptions) {
      const { repository, service } = await serviceFixture();
      const issued = await service.exchangeAuthorizationCode({
        code: "raw-code", clientId, clientSecret, redirectUri: repository.code.redirectUri,
        resource: resourceId, codeVerifier: verifier
      });
      corrupt(repository.refreshByHash.get(sha256(issued.refreshToken))!);
      await expect(service.refresh({
        refreshToken: issued.refreshToken, clientId, clientSecret, resource: resourceId
      })).rejects.toMatchObject({ code: "invalid_grant" });
      expect(repository.lastRotation).toBeNull();
    }
  });

  it("revokes access jti or refresh family without legacy fallback or unknown-token disclosure", async () => {
    const { repository, service } = await serviceFixture();
    const issued = await service.exchangeAuthorizationCode({
      code: "raw-code", clientId, clientSecret, redirectUri: repository.code.redirectUri,
      resource: resourceId, codeVerifier: verifier
    });
    await expect(service.revoke({ token: "unknown", clientId, clientSecret })).resolves.toBeUndefined();
    await service.revoke({ token: issued.accessToken, tokenTypeHint: "access_token", clientId, clientSecret });
    expect(repository.accessRevoked).toBe(true);
    await service.revoke({ token: issued.refreshToken, tokenTypeHint: "refresh_token", clientId, clientSecret });
    expect(repository.familyRevoked).toBe(true);
  });

  it("keeps access-token revocation durable across resource disable and re-enable", async () => {
    const { repository, service } = await serviceFixture();
    const issued = await service.exchangeAuthorizationCode({
      code: "raw-code", clientId, clientSecret, redirectUri: repository.code.redirectUri,
      resource: resourceId, codeVerifier: verifier
    });
    repository.onlineActive = false;
    await service.revoke({ token: issued.accessToken, tokenTypeHint: "access_token", clientId, clientSecret });
    expect(repository.accessRevoked).toBe(true);
    repository.onlineActive = true;
    await expect(service.introspect({
      token: issued.accessToken, credentialId: "resource-credential", credentialSecret: resourceSecret
    })).resolves.toEqual({ active: false });
  });

  it("introspects only resource-owned credentials and normalizes wrong audience/inactive tokens", async () => {
    const { repository, service } = await serviceFixture();
    const issued = await service.exchangeAuthorizationCode({
      code: "raw-code", clientId, clientSecret, redirectUri: repository.code.redirectUri,
      resource: resourceId, codeVerifier: verifier
    });
    await expect(service.introspect({
      token: issued.accessToken, credentialId: "resource-credential", credentialSecret: "wrong"
    })).rejects.toMatchObject({ code: "invalid_client" });
    await expect(service.introspect({
      token: issued.accessToken, credentialId: "resource-credential", credentialSecret: resourceSecret
    })).resolves.toMatchObject({ active: true, aud: resourceId, sub: "google-subject", token_type: "Bearer" });
    repository.onlineActive = false;
    await expect(service.introspect({
      token: issued.accessToken, credentialId: "resource-credential", credentialSecret: resourceSecret
    })).resolves.toEqual({ active: false });
    await expect(service.introspect({
      token: "legacy-or-malformed", credentialId: "resource-credential", credentialSecret: resourceSecret
    })).resolves.toEqual({ active: false });
    expect(repository.introspections).toEqual([true, false, false]);
  });
});

describe("repository race and secrecy SQL", () => {
  it("uses row locks, compare-and-set consumption, atomic audit and OAuth-only tables", () => {
    const source = readFileSync(resolve("src/oauth/token-repository.ts"), "utf8");
    expect(source).toContain("FOR UPDATE OF code\n       FOR SHARE OF authorization, client, resource, human, legacy_grant");
    expect(source).toContain("FOR UPDATE OF token, family, session\n       FOR SHARE OF authorization, client, resource, human, legacy_grant");
    expect(source).not.toContain("FOR UPDATE OF code, authorization");
    expect(source).not.toContain("FOR UPDATE OF token, family, session, authorization");
    expect(source).toContain("consumed_at IS NULL AND expires_at > $2");
    expect(source).toContain("status = 'consumed', consumed_at = $2");
    expect(source).toContain("status = 'revoked'");
    expect(source).toContain("oauth.refresh.replay_detected");
    expect(source).toContain("last_signed_at = $2");
    expect(source).toContain("authorization.granted_scopes AS authorization_granted_scopes");
    expect(source).toContain("oauth.code.exchange_denied");
    expect(source).toContain("WHERE resource_id = $1 AND audience_policy = 'exact_single_resource'");
    expect(source).not.toContain("WHERE resource_id = $1 AND status = 'active'");
    expect(source).not.toMatch(/INSERT INTO (sessions|refresh_tokens|one_time_codes|authorization_grants)/);
    expect(source).not.toMatch(/UPDATE (sessions|refresh_tokens|one_time_codes|authorization_grants)/);
    expect(source).not.toContain("TOOL_CLIENT_SECRET_PEPPER");
  });
});
