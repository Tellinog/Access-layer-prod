import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import type { Db } from "../src/db.js";
import { OAuthFoundationRepository } from "../src/oauth/repository.js";
import type {
  OAuthClientRegistration,
  OAuthRegistrationBundle,
  OAuthResourceRegistration,
  OAuthSigningKeyPublicMetadata
} from "../src/oauth/types.js";
import {
  OAuthRegistrationValidationError,
  assertValidOAuthRegistrationBundle,
  isCanonicalOAuthScope,
  isExactOAuthRedirectUri,
  isExactOAuthHttpsUri,
  isExplicitlyAllowedClientResourceScope,
  isUnpaddedBase64urlUInt,
  isValidOAuthPublicJwk,
  validateOAuthClientRegistration,
  validateOAuthResourceRegistration,
  validateOAuthSigningKeyLifecycle
} from "../src/oauth/validation.js";

const migration = readFileSync(resolve(import.meta.dirname, "../migrations/003_oauth_dark_foundation.sql"), "utf8");
const requiredTables = [
  "oauth_clients",
  "oauth_client_credentials",
  "oauth_client_redirect_uris",
  "oauth_resources",
  "oauth_resource_credentials",
  "oauth_resource_entitlement_bindings",
  "oauth_scopes",
  "oauth_resource_scopes",
  "oauth_client_resource_scopes",
  "oauth_signing_keys"
];

function clientFixture(): OAuthClientRegistration {
  return {
    clientId: "synthetic-bff",
    clientName: "Synthetic BFF",
    clientType: "confidential",
    status: "draft",
    grantTypes: ["authorization_code", "refresh_token"],
    redirectUris: ["https://client.invalid/oauth/callback"],
    tokenEndpointAuthMethod: "client_secret_basic",
    credentialLifecycle: { secretPresent: true, rotatedAt: null, expiresAt: null },
    allowedResources: ["https://resource.invalid/api"],
    allowedScopes: ["synthetic:records:read", "synthetic:records:write"],
    ownerTeam: "synthetic-team",
    ownerContact: null
  };
}

function signingKeyFixture(): OAuthSigningKeyPublicMetadata {
  return {
    id: "00000000-0000-4000-8000-000000000030",
    kid: "synthetic-oauth-key",
    algorithm: "RS256",
    publicJwk: {
      kty: "RSA",
      kid: "synthetic-oauth-key",
      alg: "RS256",
      use: "sig",
      n: "AQIDBA",
      e: "AQAB"
    },
    publicKeyFingerprintSha256: "a".repeat(64),
    status: "active",
    publishedAt: new Date("2026-08-26T00:00:00Z"),
    activatesAt: new Date("2026-08-26T00:05:00Z"),
    lastSignedAt: new Date("2026-08-26T00:06:00Z"),
    retireAfter: new Date("2026-08-26T00:27:00Z"),
    retiredAt: null
  };
}

function resourceFixture(): OAuthResourceRegistration {
  return {
    resourceId: "https://resource.invalid/api",
    displayName: "Synthetic Resource",
    status: "draft",
    ownerTeam: "synthetic-team",
    ownerContact: null,
    scopes: ["synthetic:records:read", "synthetic:records:write"],
    scopeEntitlementMappings: [
      { scope: "synthetic:records:read", legacyPermissionKey: "records:read" },
      { scope: "synthetic:records:write", legacyPermissionKey: "records:write" }
    ],
    audiencePolicy: "exact_single_resource",
    protectedResourceMetadataUrl: "https://resource.invalid/.well-known/oauth-protected-resource",
    entitlementBinding: { type: "legacy_tool", legacyToolSlug: "synthetic-tool" }
  };
}

function bundleFixture(): OAuthRegistrationBundle {
  return {
    client: clientFixture(),
    resources: [{
      registration: resourceFixture(),
      legacyEntitlement: {
        legacyToolId: "00000000-0000-4000-8000-000000000001",
        legacyToolSlug: "synthetic-tool",
        registeredPermissionKeys: ["records:read", "records:write"]
      }
    }],
    allowances: [
      { resourceId: "https://resource.invalid/api", scope: "synthetic:records:read" },
      { resourceId: "https://resource.invalid/api", scope: "synthetic:records:write" }
    ]
  };
}

describe("Step 3A expand-only migration", () => {
  it("creates exactly the ten approved OAuth foundation tables after migration 002", () => {
    const tables = [...migration.matchAll(/CREATE TABLE IF NOT EXISTS\s+([a-z0-9_]+)/gi)].map((match) => match[1]);
    expect(tables).toEqual(requiredTables);
    expect(requiredTables).toHaveLength(10);
  });

  it("contains no destructive statement, legacy table mutation, data rewrite, or seed", () => {
    expect(migration).not.toMatch(/^\s*(?:ALTER|DROP|TRUNCATE|DELETE|UPDATE|INSERT)\b/gim);
    expect(migration).not.toMatch(/CREATE\s+(?:OR\s+REPLACE\s+)?(?:FUNCTION|TRIGGER)\b/i);
    for (const legacyTable of [
      "users", "tools", "tool_clients", "tool_permissions", "authorization_grants", "auth_requests",
      "one_time_codes", "sessions", "refresh_tokens", "audit_logs"
    ]) {
      expect(migration).not.toMatch(new RegExp(`(?:ALTER|DROP|TRUNCATE|INSERT\\s+INTO|UPDATE|DELETE\\s+FROM)\\s+${legacyTable}\\b`, "i"));
    }
  });

  it("encodes the frozen identity, mapping, hash-only, and public-key constraints", () => {
    for (const marker of [
      "oauth_clients_type_auth_method",
      "oauth_client_redirect_uris_no_wildcard",
      "idx_oauth_resource_one_active_legacy_binding",
      "oauth_scopes_canonical_three_segment",
      "oauth_resource_scopes_one_mapping",
      "oauth_client_resource_scopes_registered_mapping_fk",
      "oauth_resource_credentials_auth_method",
      "oauth_signing_keys_namespace",
      "oauth_signing_keys_public_jwk_shape",
      "oauth_signing_keys_activation_lead",
      "oauth_signing_keys_retirement_grace",
      "oauth_signing_keys_status_lifecycle",
      "oauth_signing_keys_reference_only",
      "oauth_signing_keys_not_legacy_reference"
    ]) {
      expect(migration).toContain(marker);
    }
    expect(migration).toContain("secret_hash text NOT NULL");
    expect(migration).toContain("public_jwk ?& ARRAY['kty', 'kid', 'alg', 'use', 'n', 'e']");
    expect(migration).toContain("jsonb_typeof(public_jwk -> 'n') = 'string'");
    expect(migration).toContain("interval '300 seconds'");
    expect(migration).toContain("interval '1260 seconds'");
    expect(migration).toMatch(/oauth_signing_keys_public_jwk_shape CHECK \(\s*COALESCE\(/);
    expect(migration).not.toMatch(/\b(?:client_secret|resource_secret|secret_plaintext|private_key_pem|private_key_bytes)\b/i);
    expect(migration).not.toMatch(/oauth_(?:authorization|code|session|refresh|revocation)/i);
  });
});

describe("OAuth foundation registration validation", () => {
  it("accepts a complete synthetic registration with explicit mapping and allowance coverage", () => {
    expect(() => assertValidOAuthRegistrationBundle(bundleFixture())).not.toThrow();
  });

  it("uses the exact P0 scope, legacy slug, and OAuth redirect grammars", () => {
    expect(isCanonicalOAuthScope("synthetic:records:read")).toBe(true);
    expect(isCanonicalOAuthScope("synthetic:read")).toBe(false);
    expect(isCanonicalOAuthScope("synthetic:records:read:all")).toBe(false);
    expect(isExactOAuthRedirectUri("https://client.invalid/oauth/callback")).toBe(true);
    expect(isExactOAuthRedirectUri("http://localhost:3000/oauth/callback")).toBe(true);
    expect(isExactOAuthRedirectUri("https://*.invalid/oauth/callback")).toBe(false);
    expect(isExactOAuthRedirectUri("http://127.0.0.1:3000/oauth/callback")).toBe(false);
  });

  it.each([
    "https://client.invalid/callback with space",
    "https://client.invalid/callback\twith-tab",
    "https://client.invalid/callback\\path",
    "https://client.invalid/%",
    "https://client.invalid/%GG",
    "https://client.invalid/%G0",
    "https://client.invalid/%0G",
    "https://user@client.invalid/callback",
    "https://client.invalid/callback#fragment",
    "https://client.invalid/*"
  ])("rejects schema-invalid redirect URI %j", (uri) => {
    expect(isExactOAuthRedirectUri(uri)).toBe(false);
  });

  it.each([
    "https://resource.invalid/%GG",
    "https://resource.invalid/path with space",
    "https://resource.invalid/path\ncontrol",
    "https://resource.invalid/path\\segment",
    "https://user@resource.invalid/api",
    "https://resource.invalid/api#fragment",
    "https://resource.invalid/*"
  ])("rejects schema-invalid resource or metadata URI %j", (uri) => {
    expect(isExactOAuthHttpsUri(uri)).toBe(false);
    const bundle = bundleFixture();
    bundle.resources[0].registration.resourceId = uri;
    expect(() => assertValidOAuthRegistrationBundle(bundle)).toThrow(OAuthRegistrationValidationError);
    const resource = resourceFixture();
    resource.protectedResourceMetadataUrl = uri;
    expect(validateOAuthResourceRegistration(resource, bundleFixture().resources[0].legacyEntitlement))
      .toContain("protected_resource_metadata_url_invalid");
  });

  it("accepts valid URI spellings without rewriting the registered values", () => {
    const redirect = "https://client.invalid/callback%2Fexact?next=%2fvalue";
    const resource = "https://resource.invalid/api%2Fv1?mode=exact";
    expect(isExactOAuthRedirectUri(redirect)).toBe(true);
    expect(isExactOAuthHttpsUri(resource)).toBe(true);
    expect(redirect).toBe("https://client.invalid/callback%2Fexact?next=%2fvalue");
    expect(resource).toBe("https://resource.invalid/api%2Fv1?mode=exact");
  });

  it("enforces confidential and public credential-presence lifecycle metadata", () => {
    const confidential = clientFixture();
    expect(validateOAuthClientRegistration(confidential)).toEqual([]);
    confidential.credentialLifecycle.secretPresent = false;
    expect(validateOAuthClientRegistration(confidential)).toContain("confidential_client_secret_presence_required");
    confidential.credentialLifecycle.secretPresent = true;
    confidential.tokenEndpointAuthMethod = "none";
    expect(validateOAuthClientRegistration(confidential)).toContain("confidential_client_auth_method_invalid");

    const publicClient = clientFixture();
    publicClient.clientType = "public";
    publicClient.tokenEndpointAuthMethod = "none";
    publicClient.credentialLifecycle.secretPresent = false;
    expect(validateOAuthClientRegistration(publicClient)).toEqual([]);
    publicClient.credentialLifecycle.secretPresent = true;
    expect(validateOAuthClientRegistration(publicClient)).toContain("public_client_secret_presence_forbidden");
    publicClient.credentialLifecycle.secretPresent = false;
    publicClient.tokenEndpointAuthMethod = "client_secret_basic";
    expect(validateOAuthClientRegistration(publicClient)).toContain("public_client_auth_method_invalid");
  });

  it("fails closed when credential lifecycle metadata is absent, malformed, or extended", () => {
    const absent = { ...clientFixture() } as Partial<OAuthClientRegistration>;
    delete absent.credentialLifecycle;
    expect(validateOAuthClientRegistration(absent as OAuthClientRegistration)).toContain("credential_lifecycle_required");

    const malformed = clientFixture();
    malformed.credentialLifecycle.rotatedAt = "not-a-date";
    expect(validateOAuthClientRegistration(malformed)).toContain("credential_rotated_at_invalid");

    const extended = clientFixture();
    Object.assign(extended.credentialLifecycle, { unexpected: true });
    expect(validateOAuthClientRegistration(extended)).toContain("credential_lifecycle_field_invalid");
  });

  it("keeps registration validation metadata free of credential and key material", () => {
    const fixture = clientFixture() as unknown as Record<string, unknown>;
    const lifecycle = fixture.credentialLifecycle as Record<string, unknown>;
    expect(fixture).not.toHaveProperty("clientSecret");
    expect(fixture).not.toHaveProperty("secretHash");
    expect(lifecycle).not.toHaveProperty("clientSecret");
    expect(lifecycle).not.toHaveProperty("secretHash");
    expect(lifecycle).not.toHaveProperty("privateKey");
  });

  it.each([
    ["malformed scope", (bundle: OAuthRegistrationBundle) => { bundle.resources[0].registration.scopes[0] = "synthetic:read"; }],
    ["wrong legacy slug", (bundle: OAuthRegistrationBundle) => { bundle.resources[0].registration.entitlementBinding.legacyToolSlug = "bad-"; }],
    ["wildcard redirect", (bundle: OAuthRegistrationBundle) => { bundle.client.redirectUris[0] = "https://*.invalid/callback"; }],
    ["missing mapping", (bundle: OAuthRegistrationBundle) => { bundle.resources[0].registration.scopeEntitlementMappings.pop(); }],
    ["extra mapping", (bundle: OAuthRegistrationBundle) => { bundle.resources[0].registration.scopeEntitlementMappings.push({ scope: "synthetic:records:delete", legacyPermissionKey: "records:delete" }); }],
    ["duplicate mapping", (bundle: OAuthRegistrationBundle) => { bundle.resources[0].registration.scopeEntitlementMappings[1].scope = "synthetic:records:read"; }],
    ["duplicate resource registration", (bundle: OAuthRegistrationBundle) => { bundle.resources.push(bundle.resources[0]); }],
    ["unregistered permission", (bundle: OAuthRegistrationBundle) => { bundle.resources[0].registration.scopeEntitlementMappings[0].legacyPermissionKey = "records:admin"; }],
    ["missing explicit allowance", (bundle: OAuthRegistrationBundle) => { bundle.allowances = []; }]
  ])("fails closed for %s", (_label, mutate) => {
    const bundle = bundleFixture();
    mutate(bundle);
    expect(() => assertValidOAuthRegistrationBundle(bundle)).toThrow(OAuthRegistrationValidationError);
  });

  it("denies a client/resource/scope tuple when the exact allowance is absent", () => {
    const allowances = bundleFixture().allowances;
    expect(isExplicitlyAllowedClientResourceScope(
      allowances, "https://resource.invalid/api", "synthetic:records:read"
    )).toBe(true);
    expect(isExplicitlyAllowedClientResourceScope(
      allowances, "https://resource.invalid/api", "synthetic:records:delete"
    )).toBe(false);
    expect(isExplicitlyAllowedClientResourceScope(
      allowances, "https://other.invalid/api", "synthetic:records:read"
    )).toBe(false);
  });

  it("does not echo registration values through fail-closed error messages", () => {
    const bundle = bundleFixture();
    bundle.client.redirectUris = ["https://wildcard-credential.invalid/*"];
    try {
      assertValidOAuthRegistrationBundle(bundle);
      throw new Error("expected validation to fail");
    } catch (error) {
      expect(error).toBeInstanceOf(OAuthRegistrationValidationError);
      expect((error as Error).message).not.toContain("wildcard-credential");
    }
  });
});

describe("OAuth signing-key foundation validation", () => {
  it("accepts the frozen publication and retirement boundary intervals", () => {
    expect(validateOAuthSigningKeyLifecycle(signingKeyFixture())).toEqual([]);
  });

  it.each([
    ["activation before 300-second lead", (key: OAuthSigningKeyPublicMetadata) => {
      key.activatesAt = new Date("2026-08-26T00:04:59Z");
    }, "signing_key_publication_lead_invalid"],
    ["retirement grace below 1260 seconds", (key: OAuthSigningKeyPublicMetadata) => {
      key.retireAfter = new Date("2026-08-26T00:26:59Z");
    }, "signing_key_retirement_grace_invalid"],
    ["retirement before retire-after", (key: OAuthSigningKeyPublicMetadata) => {
      key.status = "retired";
      key.retiredAt = new Date("2026-08-26T00:26:59Z");
    }, "signing_key_retired_at_order_invalid"],
    ["active lifecycle missing activation", (key: OAuthSigningKeyPublicMetadata) => {
      key.activatesAt = null;
    }, "signing_key_activation_lifecycle_required"],
    ["retired lifecycle missing last-sign timestamp", (key: OAuthSigningKeyPublicMetadata) => {
      key.status = "retired";
      key.lastSignedAt = null;
      key.retiredAt = new Date("2026-08-26T00:27:00Z");
    }, "retired_signing_key_lifecycle_required"],
    ["staged lifecycle containing publication metadata", (key: OAuthSigningKeyPublicMetadata) => {
      key.status = "staged";
    }, "staged_signing_key_lifecycle_invalid"],
    ["published lifecycle containing signing metadata", (key: OAuthSigningKeyPublicMetadata) => {
      key.status = "published";
    }, "published_signing_key_lifecycle_invalid"],
    ["unknown lifecycle status", (key: OAuthSigningKeyPublicMetadata) => {
      key.status = "unknown" as OAuthSigningKeyPublicMetadata["status"];
    }, "signing_key_status_invalid"]
  ] as const)("rejects %s", (_label, mutate, issue) => {
    const key = signingKeyFixture();
    mutate(key);
    expect(validateOAuthSigningKeyLifecycle(key)).toContain(issue);
  });

  it("accepts only a complete non-empty RSA public JWK matching the row kid", () => {
    const key = signingKeyFixture();
    expect(isValidOAuthPublicJwk(key.publicJwk, key.kid)).toBe(true);
    expect(isValidOAuthPublicJwk(key.publicJwk, "other-kid")).toBe(false);
  });

  it.each([
    ["valid modulus", "AQIDBA", true],
    ["valid exponent", "AQAB", true],
    ["single zero byte", "AA", true],
    ["padding", "AQAB=", false],
    ["whitespace", "AQ AB", false],
    ["non-base64url characters", "***", false],
    ["empty", "", false],
    ["empty-decoded invalid length", "A", false],
    ["non-canonical invalid length", "AAAAA", false]
  ] as const)("validates unpadded Base64urlUInt syntax for %s", (_label, value, expected) => {
    expect(isUnpaddedBase64urlUInt(value)).toBe(expected);
  });

  it.each([
    ["n", "***"],
    ["n", "AQIDBA=="],
    ["n", "AQ IDBA"],
    ["n", "A"],
    ["e", "!!!"],
    ["e", "AQAB="],
    ["e", "AQ\tAB"],
    ["e", "A"]
  ] as const)("rejects malformed RSA %s value %j", (member, value) => {
    expect(isValidOAuthPublicJwk(
      { ...signingKeyFixture().publicJwk, [member]: value },
      "synthetic-oauth-key"
    )).toBe(false);
  });

  it.each(["kty", "kid", "alg", "use", "n", "e"])(
    "rejects a JWK with missing, null, wrong-type, or empty %s",
    (member) => {
      const valid = signingKeyFixture().publicJwk;
      const missing: Record<string, unknown> = { ...valid };
      delete missing[member];
      expect(isValidOAuthPublicJwk(missing, "synthetic-oauth-key")).toBe(false);
      expect(isValidOAuthPublicJwk({ ...valid, [member]: null }, "synthetic-oauth-key")).toBe(false);
      expect(isValidOAuthPublicJwk({ ...valid, [member]: 1 }, "synthetic-oauth-key")).toBe(false);
      expect(isValidOAuthPublicJwk({ ...valid, [member]: "" }, "synthetic-oauth-key")).toBe(false);
      expect(isValidOAuthPublicJwk({ ...valid, [member]: "   " }, "synthetic-oauth-key")).toBe(false);
    }
  );

  it.each(["d", "p", "q", "dp", "dq", "qi", "oth", "k"])(
    "rejects private JWK member %s",
    (member) => {
      expect(isValidOAuthPublicJwk(
        { ...signingKeyFixture().publicJwk, [member]: "forbidden" },
        "synthetic-oauth-key"
      )).toBe(false);
    }
  );
});

class RecordingDb implements Db {
  readonly calls: Array<{ sql: string; params: unknown[] }> = [];
  constructor(private readonly rowsByCall: unknown[][]) {}

  async query<T>(sql: string, params: unknown[] = []): Promise<{ rows: T[]; rowCount: number } & never> {
    this.calls.push({ sql, params });
    const rows = (this.rowsByCall.shift() ?? []) as T[];
    return { rows, rowCount: rows.length } as { rows: T[]; rowCount: number } & never;
  }

  async transaction<T>(fn: (db: Db) => Promise<T>): Promise<T> {
    return fn(this);
  }

  async close(): Promise<void> {}
}

describe("OAuth foundation repository boundary", () => {
  it("fails closed when no explicit active client/resource/scope allowance exists", async () => {
    const db = new RecordingDb([[{ allowed: false }]]);
    const repository = new OAuthFoundationRepository(db);

    await expect(repository.isClientResourceScopeAllowed(
      "00000000-0000-4000-8000-000000000010",
      "https://resource.invalid/api",
      "synthetic:records:read"
    )).resolves.toBe(false);
    expect(db.calls[0].sql).toContain("oauth_client_resource_scopes");
    expect(db.calls[0].sql).toContain("crs.status = 'active'");
  });

  it("returns resource credential metadata without selecting the secret hash", async () => {
    const now = new Date("2026-08-26T00:00:00Z");
    const db = new RecordingDb([[{
      id: "00000000-0000-4000-8000-000000000020",
      oauth_resource_id: "00000000-0000-4000-8000-000000000021",
      credential_id: "synthetic-resource-credential",
      authentication_method: "client_secret_basic",
      status: "active",
      created_at: now,
      activated_at: now,
      rotated_at: null,
      expires_at: null,
      retired_at: null,
      rotation_parent_id: null
    }]]);
    const repository = new OAuthFoundationRepository(db);

    const metadata = await repository.resolveResourceCredentialMetadata("synthetic-resource-credential");
    expect(metadata?.credentialId).toBe("synthetic-resource-credential");
    expect(db.calls[0].sql).not.toContain("secret_hash");
    expect(metadata).not.toHaveProperty("secretHash");
  });

  it("returns only public signing metadata and never selects the protected private-key reference", async () => {
    const db = new RecordingDb([[]]);
    const repository = new OAuthFoundationRepository(db);

    await repository.listSigningKeyPublicMetadata();
    expect(db.calls[0].sql).toContain("public_jwk");
    expect(db.calls[0].sql).not.toContain("protected_private_key_ref");
    expect(db.calls[0].sql).not.toMatch(/private_key_pem|private_key_bytes/i);
  });

  it("contains no legacy write query and limits legacy reads to entitlement tables", () => {
    const source = readFileSync(resolve(import.meta.dirname, "../src/oauth/repository.ts"), "utf8");
    expect(source).not.toMatch(/\b(?:INSERT|UPDATE|DELETE|ALTER|DROP|TRUNCATE)\b/i);
    for (const legacyTable of ["users", "authorization_grants", "sessions", "refresh_tokens", "audit_logs"]) {
      expect(source).not.toMatch(new RegExp(`\\b${legacyTable}\\b`, "i"));
    }
    expect(source).toContain("JOIN tools");
    expect(source).toContain("JOIN tool_permissions");
  });
});
