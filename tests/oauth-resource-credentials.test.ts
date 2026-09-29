import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import type { Db } from "../src/db.js";
import { isResourceCredentialEligible, OAuthTokenRepository } from "../src/oauth/token-repository.js";

describe("OAuth introspection resource credential mode/status boundary", () => {
  const cases = [
    ["legacy_bridge", "active", true],
    ["legacy_bridge", "draft", false],
    ["legacy_bridge", "disabled", false],
    ["native", "active", true],
    ["native", "draft", false],
    ["native", "disabled", true]
  ] as const;

  it.each(cases)("%s resource in %s is eligible: %s", async (mode, status, expected) => {
    let sql = "";
    const db = {
      query: async (statement: string) => {
        sql = statement;
        return { rows: [{
          credential_id: "synthetic-resource-credential",
          oauth_resource_id: "synthetic-resource-id",
          resource_id: "https://resource.example.invalid/api",
          secret_hash: "synthetic-hash",
          entitlement_mode: mode,
          resource_status: status
        }] };
      }
    } as unknown as Db;
    const records = await new OAuthTokenRepository(db).listCurrentResourceCredentialRecords(
      "synthetic-resource-credential", new Date("2026-09-28T00:00:00Z")
    );
    expect(isResourceCredentialEligible(mode, status)).toBe(expected);
    expect(records).toHaveLength(expected ? 1 : 0);
    expect(sql).toContain("resource.entitlement_mode = 'legacy_bridge' AND resource.status = 'active'");
    expect(sql).toContain("resource.entitlement_mode = 'native' AND resource.status IN ('active', 'disabled')");
    expect(sql).toContain("FOR SHARE OF credential, resource");
  });

  it("rejects unknown mode and status and exposes credentials only to introspection", () => {
    expect(isResourceCredentialEligible("unknown", "active")).toBe(false);
    expect(isResourceCredentialEligible("native", "unknown")).toBe(false);
    const service = readFileSync(resolve(import.meta.dirname, "../src/oauth/token-service.ts"), "utf8");
    expect(service.match(/listCurrentResourceCredentialRecords\(/g)).toHaveLength(1);
    expect(service).toMatch(/async introspect\([\s\S]*?private async authenticateResource\(/);
  });
});
