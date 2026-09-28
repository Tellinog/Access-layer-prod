import { readFileSync, readdirSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const root = resolve(import.meta.dirname, "..");
const migration = readFileSync(resolve(root, "migrations/006_oauth_native_entitlements_dark.sql"), "utf8");

describe("Phase 9A.1 dark migration contract", () => {
  it("follows frozen migrations 001–005 and adds only the two native OAuth tables", () => {
    const files = readdirSync(resolve(root, "migrations")).filter((name) => name.endsWith(".sql")).sort();
    expect(files.at(-1)).toBe("006_oauth_native_entitlements_dark.sql");
    expect(files).toHaveLength(6);
    expect([...migration.matchAll(/CREATE TABLE(?: IF NOT EXISTS)?\s+(oauth_[a-z_]+)/gi)].map((match) => match[1]))
      .toEqual(["oauth_native_human_grants", "oauth_authorization_native_grants"]);
    expect(migration).not.toMatch(/\b(?:INSERT INTO|UPDATE|DELETE FROM|TRUNCATE)\s+(?:users|tools|authorization_grants|oauth_resources|oauth_authorizations)\b/i);
  });

  it("defaults existing and old-binary resource/authorization rows to the bridge", () => {
    expect(migration).toMatch(/ADD COLUMN entitlement_mode text NOT NULL DEFAULT 'legacy_bridge'/);
    expect(migration).toMatch(/ADD COLUMN entitlement_source text NOT NULL DEFAULT 'legacy_bridge'/);
    expect(migration).toContain("oauth_resources_entitlement_mode");
    expect(migration).toContain("oauth_resource_mode_guard_trigger");
    expect(migration).toContain("entitlement_mode <> OLD.entitlement_mode");
    expect(migration).toContain("oauth_authorizations_entitlement_source");
    expect(migration).toMatch(/entitlement_source = 'legacy_bridge' AND legacy_authorization_grant_id IS NOT NULL/);
    expect(migration).toMatch(/entitlement_source = 'native' AND legacy_authorization_grant_id IS NULL/);
    expect(migration).toContain("oauth_authorization_source_mode_guard_trigger");
    expect(migration).toContain("NEW.entitlement_source <> resource_mode");
    expect(migration).toContain("BEFORE INSERT ON oauth_authorizations");
  });

  it("retains exact legacy mappings and permits unmapped canonical native scopes", () => {
    expect(migration).toContain("ALTER COLUMN legacy_permission_key DROP NOT NULL");
    expect(migration).toContain("oauth_resource_scope_mode_guard_trigger");
    expect(migration).toContain("resource_mode = 'legacy_bridge' AND NEW.legacy_permission_key IS NULL");
    expect(migration).toContain("resource_mode = 'native' AND NEW.legacy_permission_key IS NOT NULL");
    expect(migration).toContain("oauth_legacy_binding_mode_guard_trigger");
    expect(migration).toContain("resource_mode <> 'legacy_bridge'");
  });

  it("models exact registered resource/scope grants and durable linked identity", () => {
    expect(migration).toContain("oauth_native_grants_registered_scope_fk");
    expect(migration).toMatch(/FOREIGN KEY \(oauth_resource_id, oauth_scope_id\)\s+REFERENCES oauth_resource_scopes\(oauth_resource_id, oauth_scope_id\) ON DELETE RESTRICT/);
    expect(migration).toMatch(/user_id uuid REFERENCES users\(id\) ON DELETE RESTRICT/);
    expect(migration).not.toMatch(/google_sub|tool_permissions|authorization_grants\(id\)/);
    expect(migration).toContain("oauth_native_grant_mode_guard_trigger");
    expect(migration).toContain("oauth_native_grants_one_active_linked");
    expect(migration).toContain("oauth_native_grants_one_pending_email");
    expect(migration).toContain("oauth_native_grant_lifecycle_guard_trigger");
  });

  it("constrains linked/pending targets, validity and revocation lifecycle", () => {
    expect(migration).toContain("status = 'pending_user_link' AND user_id IS NULL AND email_normalized IS NOT NULL");
    expect(migration).toContain("status = 'active' AND user_id IS NOT NULL");
    expect(migration).toContain("valid_until > valid_from");
    expect(migration).toContain("status = 'revoked' AND revoked_at IS NOT NULL");
    expect(migration).toContain("status <> 'revoked' AND revoked_at IS NULL");
    expect(migration).toContain("email_normalized::text = lower(btrim(email_normalized::text))");
    expect(migration).toContain("Terminal native grant cannot be reactivated");
  });

  it("keeps native grant provenance normalized and protected from parent deletion", () => {
    expect(migration).toContain("CREATE TABLE oauth_authorization_native_grants");
    expect(migration).toContain("oauth_authorization_native_grants_unique UNIQUE");
    expect(migration).toContain("oauth_authorization_id uuid NOT NULL REFERENCES oauth_authorizations(id) ON DELETE RESTRICT");
    expect(migration).toContain("oauth_native_human_grant_id uuid NOT NULL REFERENCES oauth_native_human_grants(id) ON DELETE RESTRICT");
    expect(migration).toContain("oauth_authorization_native_grant_pair_guard_trigger");
  });

  it("leaves the authorization and token runtime modules on their existing bridge path", () => {
    const flow = readFileSync(resolve(root, "src/oauth/flow-repository.ts"), "utf8");
    const token = readFileSync(resolve(root, "src/oauth/token-repository.ts"), "utf8");
    expect(flow).toContain("legacy_authorization_grant_id");
    expect(token).toContain("legacy_authorization_grant_id");
    expect(flow + token).not.toContain("oauth_native_human_grants");
    expect(flow + token).not.toContain("entitlement_source");
  });
});
