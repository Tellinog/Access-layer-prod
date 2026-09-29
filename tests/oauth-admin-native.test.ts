import { describe, expect, it, vi } from "vitest";
import { Script } from "node:vm";
import Fastify from "fastify";
import rateLimit from "@fastify/rate-limit";
import { registerOAuthAdminHttp } from "../src/oauth/admin-http.js";
import { AppError, sendJsonError } from "../src/errors.js";
import type { Repositories } from "../src/repositories.js";
import type { TokenService } from "../src/token-service.js";
import { OAuthAdminService } from "../src/oauth/admin-service.js";
import type { OAuthAdminRepository } from "../src/oauth/admin-repository.js";
import type { OAuthAdminAuditContext } from "../src/oauth/admin-types.js";
import type { Config } from "../src/types.js";

const config = {
  oauthCredentialSecretPepper: "synthetic-oauth-pepper",
  toolClientSecretPepper: "different-legacy-pepper"
} as Config;
const ctx = { actor: { userId: "00000000-0000-4000-8000-000000000001" } } as OAuthAdminAuditContext;
const common = {
  resourceId: "https://synthetic.example.invalid/v1",
  displayName: "Synthetic native resource",
  ownerTeam: "test",
  ownerContact: null,
  status: "active" as const,
  protectedResourceMetadataUrl: "https://synthetic.example.invalid/.well-known/oauth-protected-resource"
};
const scopes = ["synthetic:records:read", "synthetic:records:write"];

function service(overrides: Record<string, unknown> = {}) {
  const repository = {
    resolveLegacyEntitlement: vi.fn(() => { throw new Error("native must not resolve legacy tools"); }),
    findScopes: vi.fn(async (names: string[]) => names.map((scope) => ({ id: scope, scope, status: "active" }))),
    createResource: vi.fn(async (input: unknown) => ({ id: "resource-uuid", ...(input as object) })),
    createNativeGrants: vi.fn(async (input: unknown) => input),
    revokeNativeGrant: vi.fn(async () => ({ status: "revoked" })),
    ...overrides
  };
  return { repository, admin: new OAuthAdminService({ config, repository: repository as unknown as OAuthAdminRepository,
    now: () => new Date("2026-09-29T12:00:00.000Z") }) };
}

describe("Phase 9A.3 native Admin service", () => {
  it("creates an explicit native resource without legacy lookup or binding input", async () => {
    const { repository, admin } = service();
    const result = await admin.createResource({ ...common, entitlementMode: "native", scopes }, ctx);
    expect(repository.resolveLegacyEntitlement).not.toHaveBeenCalled();
    expect(repository.createResource).toHaveBeenCalledWith(expect.objectContaining({
      entitlementMode: "native", scopes
    }), expect.objectContaining({ id: expect.stringMatching(/^orc_/) }), ctx);
    expect(JSON.stringify(repository.createResource.mock.calls[0][0])).not.toContain("legacyToolSlug");
    expect(result.resource_credential_secret).toMatch(/^ors_/);
  });

  it("requires exact, unique, active canonical scopes for native resources", async () => {
    const { admin } = service();
    await expect(admin.createResource({ ...common, entitlementMode: "native", scopes: [scopes[0], scopes[0]] }, ctx))
      .rejects.toMatchObject({ issues: ["resource_scope_duplicate"] });
    await expect(admin.createResource({ ...common, entitlementMode: "native", scopes: ["synthetic:records:*"] }, ctx))
      .rejects.toMatchObject({ issues: ["resource_scope_invalid"] });
    const inactive = service({ findScopes: vi.fn(async () => [{ id: "one", scope: scopes[0], status: "disabled" }]) });
    await expect(inactive.admin.createResource({ ...common, entitlementMode: "native", scopes: [scopes[0]] }, ctx))
      .rejects.toMatchObject({ issues: ["scope_not_found_or_disabled"] });
  });

  it("validates multi-scope grants and validity before the repository mutation", async () => {
    const { repository, admin } = service();
    const target = {
      resourceId: "00000000-0000-4000-8000-000000000002",
      userId: "00000000-0000-4000-8000-000000000003",
      scopes,
      validFrom: null,
      validUntil: new Date("2026-09-30T12:00:00.000Z")
    };
    await admin.createNativeGrants(target, ctx);
    expect(repository.createNativeGrants).toHaveBeenCalledWith(expect.objectContaining({
      scopes, validFrom: new Date("2026-09-29T12:00:00.000Z")
    }), new Date("2026-09-29T12:00:00.000Z"), ctx);
    expect(() => admin.createNativeGrants({ ...target, scopes: [scopes[0], scopes[0]] }, ctx))
      .toThrowError(expect.objectContaining({ issues: ["grant_scope_duplicate"] }));
    expect(() => admin.createNativeGrants({ ...target, validUntil: new Date("2026-09-28T12:00:00.000Z") }, ctx))
      .toThrowError(expect.objectContaining({ issues: ["grant_validity_invalid"] }));
    expect(repository.createNativeGrants).toHaveBeenCalledTimes(1);
  });
});

describe("Phase 9A.3 HTTP boundary", () => {
  it("keeps native writes platform-admin-only and rejects mixed resource shapes", async () => {
    let role = "tool_admin";
    const nativeCalls: unknown[] = [];
    const fakeService = {
      snapshot: async () => ({ resources: [], scopes: [], resourceScopes: [], entitlementBindings: [], signingKeys: [] }),
      legacyTools: async () => [{ id: "tool-id", slug: "known-tool", display_name: "Known tool", registered_permission_keys: ["known:read"] }],
      searchUsers: async () => [{ id: "user-id", email: "human@example.invalid", display_name: "Human", status: "active", last_seen_at: "2026-09-29T12:00:00Z" }],
      listNativeGrants: async () => [],
      createResource: async (input: unknown) => { nativeCalls.push(input); return input; },
      createNativeGrants: async (input: unknown) => { nativeCalls.push(input); return input; },
      revokeNativeGrant: async () => ({ status: "revoked" })
    } as unknown as OAuthAdminService;
    const repositories = {
      findUserByGoogleSub: async () => ({ id: ctx.actor.userId, google_sub: "admin-sub", email: "admin@example.invalid", hd: "example.invalid", status: "active" }),
      findSessionById: async () => ({ id: "session-id", grant_id: "grant-id", status: "active" }),
      findGrantById: async () => ({ role, permissions: ["admin:oauth:read", "admin:oauth:write"], status: "active", valid_from: new Date("2020-01-01"), valid_until: null })
    } as unknown as Repositories;
    const tokenService = { verifyAccessToken: async () => ({ sub: "admin-sub", sid: "session-id" }) } as unknown as TokenService;
    const appConfig = { ...config, appBaseUrl: "https://access-layer.example.invalid", publicBasePath: "", logIpSalt: "synthetic-salt", sessionCookieName: "admin", sessionSecret: "synthetic-session" } as Config;
    const app = Fastify({ logger: false });
    await app.register(rateLimit, { global: false });
    app.setErrorHandler((error, _request, reply) => error instanceof AppError
      ? sendJsonError(reply, error) : sendJsonError(reply, new AppError("INTERNAL_ERROR", "corr_test")));
    registerOAuthAdminHttp(app, { config: appConfig, repositories, tokenService, service: fakeService });
    const headers = { authorization: "Bearer synthetic-admin-token", "content-type": "application/json" };
    try {
      expect((await app.inject({ method: "GET", url: "/v1/admin/oauth/users?q=human", headers })).statusCode).toBe(403);
      expect((await app.inject({ method: "POST", url: "/v1/admin/oauth/native-grants", headers, payload: {} })).statusCode).toBe(403);
      role = "platform_admin";
      const users = await app.inject({ method: "GET", url: "/v1/admin/oauth/users?q=human", headers });
      expect(Object.keys(users.json()[0]).sort()).toEqual(["display_name", "email", "id", "last_seen_at", "status"]);
      const tools = await app.inject({ method: "GET", url: "/v1/admin/oauth/legacy-tools", headers });
      expect(tools.json()[0].registered_permission_keys).toEqual(["known:read"]);
      const commonBody = {
        resource_id: common.resourceId, display_name: common.displayName, owner_team: common.ownerTeam,
        status: common.status, protected_resource_metadata_url: common.protectedResourceMetadataUrl
      };
      const mixed = await app.inject({ method: "POST", url: "/v1/admin/oauth/resources", headers,
        payload: { ...commonBody, entitlement_mode: "native", scopes, legacy_tool_slug: "known-tool" } });
      expect(mixed.statusCode).toBe(400);
      const native = await app.inject({ method: "POST", url: "/v1/admin/oauth/resources", headers,
        payload: { ...commonBody, entitlement_mode: "native", scopes } });
      expect(native.statusCode).toBe(200);
      expect(nativeCalls[0]).toMatchObject({ entitlementMode: "native", scopes });
      const legacy = await app.inject({ method: "POST", url: "/v1/admin/oauth/resources", headers,
        payload: { ...commonBody, legacy_tool_slug: "known-tool", scope_mappings: [{ scope: scopes[0], legacy_permission_key: "known:read" }] } });
      expect(legacy.statusCode).toBe(200);
      expect(nativeCalls[1]).toMatchObject({ entitlementMode: "legacy_bridge", legacyToolSlug: "known-tool" });
      const ui = await app.inject({ method: "GET", url: "/admin/oauth", headers });
      expect(ui.body).toContain("OAuth administration");
      expect(ui.body).toContain("id=\"grant-resource\"");
      expect(ui.body).toContain("id=\"legacy-resource-tool\"");
      const inlineScript = ui.body.match(/<script>([\s\S]*?)<\/script>/)?.[1];
      expect(inlineScript).toBeTruthy();
      expect(() => new Script(inlineScript!)).not.toThrow();
    } finally { await app.close(); }
  });
});
