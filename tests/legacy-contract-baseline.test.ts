import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { httpStatusByCode } from "../src/errors.js";

const root = resolve(import.meta.dirname, "..");
const baseline = JSON.parse(readFileSync(resolve(root, "specs/legacy-contract-baseline.v1.json"), "utf8"));
const historicalPermissionPattern = "^[a-z0-9-]+(?::[a-z0-9-]+)+$";
const d048PermissionPattern = "^(?:[a-z0-9-]+(?::[a-z0-9-]+)+|admin:access_requests:(?:read|write))$";

function text(path: string): string {
  return readFileSync(resolve(root, path), "utf8").replaceAll("\r\n", "\n");
}

function sha256Lf(path: string): string {
  const source = path === "src/config.ts"
    ? text(path)
      .replace('import { parseOAuthTransactionProtectionKey } from "./oauth/state-protection.js";\n', "")
      .replace(/  const oauthP0Enabled = readBoolean\("OAUTH_P0_ENABLED", false\);[\s\S]*?  const config: Config = \{\n/, "  const config: Config = {\n")
      .replace("    oauthP0Enabled,\n    oauthTransactionProtectionKey,\n    oauthCredentialSecretPepper,\n    oauthSigningKeyRoot,\n", "")
      .replace(/\n  if \(config\.oauthCredentialSecretPepper !== undefined &&[\s\S]*?OAuth credential secret isolation is invalid"\);\n  \}\n/, "")
    : path === "schemas/openapi.yaml"
      ? text(path).replaceAll(d048PermissionPattern, historicalPermissionPattern)
      : text(path);
  return createHash("sha256").update(source, "utf8").digest("hex");
}

function gitBlobSha1(path: string): string {
  const source = Buffer.from(text(path), "utf8");
  return createHash("sha1").update(`blob ${source.length}\0`).update(source).digest("hex");
}

describe("legacy compatibility baseline", () => {
  it("limits the D-048 OpenAPI addendum to the exact historical permission fields", () => {
    expect(text("schemas/openapi.yaml").split(d048PermissionPattern).length - 1).toBe(9);
  });

  it("pins unchanged historical sources while preserving the explicit Microsoft bridge addendum", () => {
    const intentionalBridgeExceptions = new Set(["src/app.ts", "src/config.ts", "src/errors.ts", "docker-compose.yaml"]);
    for (const [path, expected] of Object.entries(baseline.source_sha256_lf)) {
      if (intentionalBridgeExceptions.has(path)) continue;
      expect(sha256Lf(path), path).toBe(expected);
    }
    for (const migration of baseline.database.migrations) {
      expect(sha256Lf(migration.path), migration.path).toBe(migration.sha256_lf);
    }
  });

  it("records the intentional legacy bridge without rewriting the historical app blob", () => {
    expect(gitBlobSha1("src/app.ts")).not.toBe("6eaf4d2c3564eb851abbd23371be5a2e2d6a1f12");
    expect(text("src/app.ts")).toContain('"/v1/auth/microsoft/callback"');
    expect(text("specs/legacy-microsoft-bridge.v1.yml")).toContain("oauth_vnext_changed: false");
  });

  it("keeps both additive compatibility surfaces independently default-off", () => {
    const config = text("src/config.ts");
    expect(config).toContain('const oauthP0Enabled = readBoolean("OAUTH_P0_ENABLED", false)');
    expect(config).toContain('readOptional("OAUTH_TRANSACTION_PROTECTION_KEY")');
    expect(config).toContain('readOptional("OAUTH_CREDENTIAL_SECRET_PEPPER")');
    expect(config).toContain('readOptional("OAUTH_SIGNING_KEY_ROOT")');
    expect(config).toContain("OAuth credential secret isolation is invalid");
    expect(config).toContain('const legacyMicrosoftEnabled = readBoolean("LEGACY_MICROSOFT_ENABLED", false)');
    expect(config).toContain('readRequired("MICROSOFT_CLIENT_SECRET")');
    expect(config).toContain('readCsv("LEGACY_MICROSOFT_TOOL_SLUGS")');
  });

  it("freezes every registered v1 method and path", () => {
    const appSource = text("src/app.ts");
    for (const route of baseline.http.routes) {
      const escapedPath = route.path.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      const pattern = new RegExp(`app\\.${route.method.toLowerCase()}\\([\\s\\S]{0,180}?[\"']${escapedPath}[\"']`);
      expect(pattern.test(appSource), `${route.method} ${route.path}`).toBe(true);
    }
  });

  it("keeps every historical error status unchanged and allows only the bridge addendum", () => {
    for (const [code, status] of Object.entries(baseline.errors.codes)) {
      expect(httpStatusByCode[code as keyof typeof httpStatusByCode], code).toBe(status);
    }
    expect(httpStatusByCode).toMatchObject({
      AUTH_MICROSOFT_CALLBACK_FAILED: 401,
      AUTH_INVALID_MICROSOFT_TOKEN: 401,
      AUTH_INVALID_PROVIDER: 400,
      AUTH_MICROSOFT_NOT_AVAILABLE: 403
    });
  });

  it("keeps the evidence-backed logical volumes exact without pinning physical names", () => {
    const compose = text("docker-compose.yaml");
    expect(compose).toContain("access_layer_postgres_data_v2:/var/lib/postgresql/data");
    expect(compose).toMatch(/\nvolumes:\n\s+access_layer_postgres_data_v2:\n\s+access_layer_jwt_secrets:\n/);
    expect(compose).toContain("access_layer_jwt_secrets:/run/secrets");
    expect(compose).not.toMatch(/\n\s+name:\s+/);
    expect(compose).not.toMatch(/\n\s+ports:\s*\n/);
    expect(baseline.compose_continuity.top_level_declared_volume).toBe("access_layer_postgres_data_v2");
    expect(baseline.compose_continuity.explicit_physical_name_forbidden).toBe(true);
  });

  it("does not add an OAuth vNext runtime endpoint or table to the legacy bridge", () => {
    const runtimeAndMigrations = `${text("src/app.ts")}\n${text("migrations/001_initial.sql")}\n${text("migrations/002_audit_tool_delete_fk.sql")}`;
    expect(runtimeAndMigrations).not.toMatch(/\/oauth\/(authorize|token|revoke)|openid-configuration|CREATE TABLE IF NOT EXISTS oauth_/i);
  });

  it("keeps synthetic goldens aligned with response members", () => {
    for (const fixtureName of ["exchange.response.json", "refresh.response.json"]) {
      const fixture = JSON.parse(text(`tests/platform-conformance/legacy/fixtures/${fixtureName}`));
      expect(Object.keys(fixture).sort()).toEqual([...baseline.exchange_response.members].sort());
      expect(Object.keys(fixture.session).sort()).toEqual([...baseline.exchange_response.session_members].sort());
      expect(Object.keys(fixture.user).sort()).toEqual([...baseline.exchange_response.user_members].sort());
      expect(Object.keys(fixture.tool).sort()).toEqual([...baseline.exchange_response.tool_members].sort());
      expect(Object.keys(fixture.grant).sort()).toEqual([...baseline.exchange_response.grant_members].sort());
    }
    const jwks = JSON.parse(text("tests/platform-conformance/legacy/fixtures/jwks.response.json"));
    expect(Object.keys(jwks.keys[0]).sort()).toEqual([...baseline.jwks.key_members].sort());
  });
});
