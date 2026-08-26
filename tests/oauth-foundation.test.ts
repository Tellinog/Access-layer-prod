import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import type { Db } from "../src/db.js";
import { OAuthFoundationRepository } from "../src/oauth/repository.js";
import type {
  OAuthClientRegistration,
  OAuthRegistrationBundle,
  OAuthResourceRegistration
} from "../src/oauth/types.js";
import {
  OAuthRegistrationValidationError,
  assertValidOAuthRegistrationBundle,
  isCanonicalOAuthScope,
  isExactOAuthRedirectUri,
  isExplicitlyAllowedClientResourceScope
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
    allowedResources: ["https://resource.invalid/api"],
    allowedScopes: ["synthetic:records:read", "synthetic:records:write"],
    ownerTeam: "synthetic-team",
    ownerContact: null
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
      "oauth_signing_keys_reference_only",
      "oauth_signing_keys_not_legacy_reference"
    ]) {
      expect(migration).toContain(marker);
    }
    expect(migration).toContain("secret_hash text NOT NULL");
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
