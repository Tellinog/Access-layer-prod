import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { httpStatusByCode } from "../src/errors.js";

const root = resolve(import.meta.dirname, "..");
const baseline = JSON.parse(readFileSync(resolve(root, "specs/legacy-contract-baseline.v1.json"), "utf8"));

function text(path: string): string {
  return readFileSync(resolve(root, path), "utf8").replaceAll("\r\n", "\n");
}

function sha256Lf(path: string): string {
  return createHash("sha256").update(text(path), "utf8").digest("hex");
}

describe("legacy compatibility baseline", () => {
  it("pins the current runtime, Compose, OpenAPI and migration source", () => {
    for (const [path, expected] of Object.entries(baseline.source_sha256_lf)) {
      expect(sha256Lf(path), path).toBe(expected);
    }
    for (const migration of baseline.database.migrations) {
      expect(sha256Lf(migration.path), migration.path).toBe(migration.sha256_lf);
    }
  });

  it("freezes every registered v1 method and path", () => {
    const appSource = text("src/app.ts");
    for (const route of baseline.http.routes) {
      const escapedPath = route.path.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      const pattern = new RegExp(`app\\.${route.method.toLowerCase()}\\([\\s\\S]{0,180}?[\"']${escapedPath}[\"']`);
      expect(pattern.test(appSource), `${route.method} ${route.path}`).toBe(true);
    }
  });

  it("freezes error codes and status mappings", () => {
    expect(httpStatusByCode).toEqual(baseline.errors.codes);
  });

  it("keeps the known volume mismatch visible and unchanged", () => {
    const compose = text("docker-compose.yaml");
    expect(compose).toContain("access_layer_postgres_data_v2:/var/lib/postgresql/data");
    expect(compose).toMatch(/\nvolumes:\n\s+access_layer_postgres_data:\n/);
    expect(compose).not.toMatch(/\n\s+ports:\s*\n/);
    expect(baseline.compose_continuity_blocker.mismatch_frozen).toBe(true);
  });

  it("has no OAuth/OIDC runtime endpoint or table in Step 1", () => {
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
