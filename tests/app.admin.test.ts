import { describe, expect, it } from "vitest";
import { AuditLogger } from "../src/audit.js";
import { buildApp } from "../src/app.js";
import { PLATFORM_ADMIN_PERMISSIONS, TOOL_ADMIN_PERMISSIONS } from "../src/permissions.js";
import { decryptJsonPayload, hashOpaque, signCookie, verifyToolSecret } from "../src/security.js";
import type { AccessRequest, AuthorizationGrant, Config, RefreshToken, Session, Tool, User } from "../src/types.js";

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

const accessAdminTool: Tool = {
  id: "access-admin-tool-id",
  slug: "access-admin",
  display_name: "Access Layer Admin",
  description: null,
  status: "active",
  allowed_return_urls: ["http://localhost:8080/admin/auth/callback"],
  owner_email: null,
  created_at: new Date(),
  updated_at: new Date()
};

const adminUser: User = {
  id: "admin-user-id",
  google_sub: "admin-google-sub",
  email: "admin@unguess.io",
  email_normalized: "admin@unguess.io",
  email_verified: true,
  hd: "unguess.io",
  display_name: "Admin",
  picture_url: null,
  status: "active",
  first_seen_at: new Date(),
  last_seen_at: new Date()
};

const targetUser: User = {
  id: "target-user-id",
  google_sub: "target-google-sub",
  email: "mario.rossi@unguess.io",
  email_normalized: "mario.rossi@unguess.io",
  email_verified: true,
  hd: "unguess.io",
  display_name: "Mario Rossi",
  picture_url: null,
  status: "active",
  first_seen_at: new Date(),
  last_seen_at: new Date()
};

const adminSession: Session = {
  id: "admin-session-id",
  user_id: adminUser.id,
  tool_id: "access-admin-tool-id",
  grant_id: "admin-grant-id",
  status: "active",
  issued_at: new Date(),
  expires_at: new Date(Date.now() + 60_000),
  revoked_at: null
};

const adminGrant: AuthorizationGrant = {
  id: adminSession.grant_id,
  tool_id: adminSession.tool_id,
  user_id: adminUser.id,
  email_normalized: adminUser.email_normalized,
  role: "platform_admin",
  permissions: PLATFORM_ADMIN_PERMISSIONS,
  status: "active",
  valid_from: new Date(Date.now() - 1000),
  valid_until: null,
  created_by_user_id: null
};

class AdminRepos {
  db = {
    query: async () => ({ rows: [], rowCount: 0 }),
    transaction: async <T>(fn: (db: unknown) => Promise<T>) => fn(this.db),
    close: async () => undefined
  };

  audits: unknown[] = [];
  session: Session = { ...adminSession };
  refreshTokens = new Map<string, RefreshToken>();
  adminGrant: AuthorizationGrant = adminGrant;
  grant: AuthorizationGrant | null = null;
  users = new Map<string, User>([
    [adminUser.id, adminUser],
    [targetUser.id, targetUser]
  ]);
  usersListCalls = 0;
  usersListFilters: unknown[] = [];
  toolsListCalls = 0;
  toolsListFilters: unknown[] = [];
  grantsListCalls = 0;
  grantsListFilters: unknown[] = [];
  accessRequestsListCalls = 0;
  accessRequestFilters: unknown[] = [];
  auditLogFilters: unknown[] = [];
  tools = new Map<string, Tool>([
    [accessAdminTool.id, accessAdminTool],
    [tool.id, tool]
  ]);
  toolPermissions = new Map<string, string[]>([
    [accessAdminTool.id, ["admin:tools:read", "admin:tools:write"]],
    [tool.id, ["crm:read", "crm:write"]]
  ]);
  toolPermissionReplacements: Array<{ toolId: string; permissionKeys: string[] }> = [];
  toolClients: Array<{ tool_id: string; client_id: string; client_secret_hash: string; status: string }> = [];
  disabledToolClientIds: string[] = [];
  deletedToolIds: string[] = [];
  revokedSessions = 0;
  revokedGrantIds: string[] = [];
  assignedToolIds: string[] = [];
  accessRequest: AccessRequest = {
    id: "access-request-id",
    tool_id: tool.id,
    tool_slug: tool.slug,
    user_id: "target-user-id",
    google_sub: "target-google-sub",
    email: "mario.rossi@unguess.io",
    email_normalized: "mario.rossi@unguess.io",
    hd: "unguess.io",
    display_name: "Mario Rossi",
    status: "pending",
    reason_code: "AUTH_NOT_AUTHORIZED_FOR_TOOL",
    attempts_count: 1,
    first_seen_at: new Date(),
    last_seen_at: new Date(),
    last_correlation_id: "corr-existing",
    request_ip_hash: null,
    user_agent_hash: null,
    reviewed_by_user_id: null,
    reviewed_at: null,
    review_note: null,
    grant_id: null
  };

  withDb() {
    return this;
  }

  async writeAudit(event: unknown) {
    this.audits.push(event);
  }

  async health() {
    return true;
  }

  async findUserByGoogleSub() {
    return adminUser;
  }

  async findSessionById(id?: string) {
    return !id || id === this.session.id ? this.session : null;
  }

  async findGrantById(id: string) {
    if (id === adminGrant.id) return this.adminGrant;
    return this.grant;
  }

  async findToolById(id: string) {
    return this.tools.get(id) ?? null;
  }

  async findToolBySlug(slug: string) {
    return [...this.tools.values()].find((toolItem) => toolItem.slug === slug) ?? null;
  }

  async findUserById(id: string) {
    return this.users.get(id) ?? null;
  }

  async findUserByEmail(email: string) {
    return email === adminUser.email_normalized ? adminUser : null;
  }

  async revokeSession(id: string) {
    if (id !== this.session.id) return 0;
    this.revokedSessions += 1;
    return 1;
  }

  async extendSession(id: string, toolId: string, expiresAt: Date) {
    if (id !== this.session.id || toolId !== this.session.tool_id || this.session.status !== "active" || this.session.expires_at <= new Date()) {
      return null;
    }
    this.session = { ...this.session, expires_at: expiresAt };
    return this.session;
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

  async listAssignedToolIds() {
    return this.assignedToolIds;
  }

  async listUsers(filters: { search?: string; status?: "active" | "suspended" | "disabled" }) {
    this.usersListCalls += 1;
    this.usersListFilters.push(filters);
    const search = filters.search?.toLowerCase();
    return [...this.users.values()].filter((user) => {
      if (filters.status && user.status !== filters.status) return false;
      if (search && !user.email_normalized.includes(search) && !user.google_sub.toLowerCase().includes(search)) return false;
      return true;
    });
  }

  async updateUserStatus(id: string, status: "active" | "suspended" | "disabled") {
    const current = this.users.get(id);
    if (!current) return null;
    const updated = { ...current, status };
    this.users.set(id, updated);
    return updated;
  }

  async revokeSessionsForUser(userId: string) {
    if (!this.users.has(userId)) return 0;
    this.revokedSessions += 1;
    return 1;
  }

  async listTools(filters: {
    assignedToolIds?: string[];
    search?: string;
    status?: "active" | "disabled" | "maintenance";
    ownerEmail?: string;
    limit: number;
  }) {
    this.toolsListCalls += 1;
    this.toolsListFilters.push(filters);
    const search = filters.search?.toLowerCase();
    return [...this.tools.values()].filter((toolItem) => {
      if (filters.assignedToolIds && !filters.assignedToolIds.includes(toolItem.id)) return false;
      if (filters.status && toolItem.status !== filters.status) return false;
      if (filters.ownerEmail && toolItem.owner_email !== filters.ownerEmail) return false;
      if (search && !toolItem.slug.toLowerCase().includes(search) && !toolItem.display_name.toLowerCase().includes(search)) return false;
      return true;
    });
  }

  async createTool(input: {
    slug: string;
    displayName: string;
    description?: string | null;
    allowedReturnUrls: string[];
    ownerEmail?: string | null;
  }) {
    const created: Tool = {
      id: "created-tool-id",
      slug: input.slug,
      display_name: input.displayName,
      description: input.description ?? null,
      status: "active",
      allowed_return_urls: input.allowedReturnUrls,
      owner_email: input.ownerEmail ?? null,
      created_at: new Date(),
      updated_at: new Date()
    };
    this.tools.set(created.id, created);
    return created;
  }

  async updateTool(
    id: string,
    input: Partial<{
      displayName: string;
      description: string | null;
      status: "active" | "disabled" | "maintenance";
      allowedReturnUrls: string[];
      ownerEmail: string | null;
    }>
  ) {
    const current = this.tools.get(id);
    if (!current) return null;
    const updated: Tool = {
      ...current,
      display_name: input.displayName ?? current.display_name,
      description: input.description === undefined ? current.description : input.description,
      status: input.status ?? current.status,
      allowed_return_urls: input.allowedReturnUrls ?? current.allowed_return_urls,
      owner_email: input.ownerEmail === undefined ? current.owner_email : input.ownerEmail,
      updated_at: new Date()
    };
    this.tools.set(id, updated);
    return updated;
  }

  async deleteTool(id: string) {
    const current = this.tools.get(id);
    if (!current) return null;
    this.deletedToolIds.push(id);
    this.tools.delete(id);
    this.toolPermissions.delete(id);
    return current;
  }

  async replaceToolPermissions(toolId: string, permissionKeys: string[]) {
    this.toolPermissionReplacements.push({ toolId, permissionKeys });
    this.toolPermissions.set(toolId, permissionKeys);
  }

  async createToolClient(toolId: string, clientId: string, secretHash: string) {
    const client = {
      tool_id: toolId,
      client_id: clientId,
      client_secret_hash: secretHash,
      status: "active"
    };
    this.toolClients.push(client);
    return client;
  }

  async disableToolClients(toolId: string) {
    this.disabledToolClientIds.push(toolId);
    for (const client of this.toolClients) {
      if (client.tool_id === toolId) {
        client.status = "disabled";
      }
    }
  }

  async listToolClientPublicIds(toolId: string) {
    return this.toolClients
      .filter((client) => client.tool_id === toolId)
      .map((client) => ({
        client_id: client.client_id,
        status: client.status,
        created_at: new Date(),
        last_used_at: null
      }));
  }

  async listGrants(filters: {
    assignedToolIds?: string[];
    toolSlug?: string;
    email?: string;
    status?: "active" | "revoked" | "expired" | "pending_user_link";
    limit: number;
  }) {
    this.grantsListCalls += 1;
    this.grantsListFilters.push(filters);
    if (!this.grant) return [];
    if (filters.assignedToolIds && !filters.assignedToolIds.includes(this.grant.tool_id)) return [];
    if (filters.status && this.grant.status !== filters.status) return [];
    if (filters.email && this.grant.email_normalized !== filters.email) return [];
    return [this.grant];
  }

  async listAccessRequests(filters: unknown) {
    this.accessRequestsListCalls += 1;
    this.accessRequestFilters.push(filters);
    return [this.accessRequest];
  }

  async listAuditLogs(filters: unknown) {
    this.auditLogFilters.push(filters);
    return [];
  }

  async exportBackup() {
    return {
      users: [],
      tools: [{ id: tool.id, slug: tool.slug }],
      tool_clients: [{ tool_id: tool.id, client_id: "tlc_existing", client_secret_hash: "scrypt$v1$salt$hash" }],
      tool_permissions: [],
      authorization_grants: [],
      admin_tool_assignments: [],
      access_requests: []
    };
  }

  async importBackup() {
    return {
      users: 0,
      tools: 1,
      tool_clients: 1,
      tool_permissions: 0,
      authorization_grants: 0,
      admin_tool_assignments: 0,
      access_requests: 0
    };
  }

  async findAccessRequestById(id: string, assignedToolIds?: string[]) {
    if (assignedToolIds && !assignedToolIds.includes(this.accessRequest.tool_id)) return null;
    return id === this.accessRequest.id ? this.accessRequest : null;
  }

  async listToolPermissions(toolId: string) {
    return this.toolPermissions.get(toolId) ?? [];
  }

  async listToolPermissionCatalog(filters: { assignedToolIds?: string[] }) {
    return [...this.tools.values()]
      .filter((toolItem) => !filters.assignedToolIds || filters.assignedToolIds.includes(toolItem.id))
      .flatMap((toolItem) => {
        const permissions = this.toolPermissions.get(toolItem.id) ?? [];
        return (permissions.length ? permissions : [""]).map((permission) => ({
          tool_slug: toolItem.slug,
          tool_name: toolItem.display_name,
          tool_status: toolItem.status,
          permission_key: permission,
          permission_description: null
        }));
      });
  }

  async findGrantForBulkTarget(input: { toolId: string; userId?: string | null; emailNormalized: string; role: string }) {
    if (!this.grant) return null;
    if (this.grant.tool_id !== input.toolId) return null;
    if (this.grant.role !== input.role) return null;
    if (this.grant.status !== "active" && this.grant.status !== "pending_user_link") return null;
    const matchesUser = input.userId ? this.grant.user_id === input.userId || this.grant.email_normalized === input.emailNormalized : false;
    const matchesEmail = !input.userId && !this.grant.user_id && this.grant.email_normalized === input.emailNormalized;
    return matchesUser || matchesEmail ? this.grant : null;
  }

  async findGrantsForBulkRevoke(input: { toolId: string; userId?: string | null; emailNormalized: string; role?: string | null }) {
    if (!this.grant) return [];
    if (this.grant.tool_id !== input.toolId) return [];
    if (this.grant.status === "revoked") return [];
    if (input.role && this.grant.role !== input.role) return [];
    const matchesUser = input.userId ? this.grant.user_id === input.userId || this.grant.email_normalized === input.emailNormalized : false;
    const matchesEmail = this.grant.email_normalized === input.emailNormalized;
    return matchesUser || matchesEmail ? [this.grant] : [];
  }

  async updateGrantTarget(
    grantId: string,
    input: {
      userId?: string | null;
      emailNormalized?: string | null;
      role: string;
      permissions: string[];
      status: "active" | "pending_user_link";
      validUntil?: string | null;
    }
  ) {
    const current = grantId === adminGrant.id ? this.adminGrant : this.grant;
    if (!current) return null;
    const updated: AuthorizationGrant = {
      ...current,
      user_id: input.userId ?? null,
      email_normalized: input.emailNormalized ?? null,
      role: input.role,
      permissions: input.permissions,
      status: input.status,
      valid_until: input.validUntil ? new Date(input.validUntil) : null
    };
    if (grantId === adminGrant.id) this.adminGrant = updated;
    else this.grant = updated;
    return updated;
  }

  async createGrant(input: {
    toolId?: string;
    userId?: string | null;
    emailNormalized?: string | null;
    role: string;
    permissions: string[];
    status?: "active" | "pending_user_link";
    validUntil?: string | null;
    createdByUserId: string;
  }) {
    const targetFromInput = "toolId" in input || "userId" in input || "emailNormalized" in input || "status" in input;
    this.grant = {
      id: "new-grant-id",
      tool_id: input.toolId ?? tool.id,
      user_id: targetFromInput ? (input.userId ?? null) : this.accessRequest.user_id,
      email_normalized: targetFromInput ? (input.emailNormalized ?? null) : this.accessRequest.email_normalized,
      role: input.role,
      permissions: input.permissions,
      status: input.status ?? "active",
      valid_from: new Date(Date.now() - 1000),
      valid_until: input.validUntil ? new Date(input.validUntil) : null,
      created_by_user_id: input.createdByUserId
    };
    return this.grant;
  }

  async updateGrant(
    grantId: string,
    input: {
      role?: string;
      permissions?: string[];
      status?: "active" | "revoked" | "expired" | "pending_user_link";
      validUntil?: string | null;
    }
  ) {
    const current = grantId === adminGrant.id ? this.adminGrant : this.grant;
    if (!current) return null;
    const updated: AuthorizationGrant = {
      ...current,
      role: input.role ?? current.role,
      permissions: input.permissions ?? current.permissions,
      status: input.status ?? current.status,
      valid_until: input.validUntil === undefined ? current.valid_until : input.validUntil ? new Date(input.validUntil) : null
    };
    if (grantId === adminGrant.id) {
      this.adminGrant = updated;
    } else {
      this.grant = updated;
    }
    return updated;
  }

  async revokeSessionsForGrant(grantId: string) {
    this.revokedGrantIds.push(grantId);
    return 2;
  }

  async reviewAccessRequest(input: {
    requestId?: string;
    status: "approved" | "rejected" | "closed";
    actorUserId: string;
    grantId?: string | null;
    note?: string | null;
  }) {
    if (this.accessRequest.status !== "pending") return null;
    this.accessRequest = {
      ...this.accessRequest,
      status: input.status,
      reviewed_by_user_id: input.actorUserId,
      reviewed_at: new Date(),
      review_note: input.note ?? null,
      grant_id: input.grantId ?? null
    };
    return this.accessRequest;
  }
}

function tokenServiceFor(permissions = PLATFORM_ADMIN_PERMISSIONS) {
  const role = permissions.includes("admin:tools:write")
    ? "platform_admin"
    : permissions.includes("admin:tools:read_assigned")
      ? "tool_admin"
      : "auditor";
  return {
    getJwks: () => ({ keys: [] }),
    issueAccessToken: async () => ({
      token: "refreshed-admin-token",
      expiresAt: new Date(Date.now() + config.accessTokenTtlSeconds * 1000),
      expiresIn: config.accessTokenTtlSeconds,
      jti: "refreshed-admin-jti"
    }),
    verifyAccessToken: async () => ({
      sub: adminUser.google_sub,
      sid: adminSession.id,
      tool_slug: "access-admin",
      email: adminUser.email,
      hd: adminUser.hd,
      role,
      permissions
    })
  };
}


function adminSessionCookie(configOverride: Partial<Config> = {}) {
  const effectiveConfig = { ...config, ...configOverride };
  return `${effectiveConfig.sessionCookieName}=${encodeURIComponent(signCookie("admin-token", effectiveConfig.sessionSecret))}`;
}

async function buildAdminApp(repos: AdminRepos, permissions = PLATFORM_ADMIN_PERMISSIONS, configOverride: Partial<Config> = {}) {
  repos.adminGrant = {
    ...adminGrant,
    role: permissions.includes("admin:tools:write")
      ? "platform_admin"
      : permissions.includes("admin:tools:read_assigned")
        ? "tool_admin"
        : "auditor",
    permissions
  };
  return buildApp({
    config: { ...config, ...configOverride },
    repositories: repos as never,
    audit: new AuditLogger(repos as never),
    google: {
      createAuthorizationUrl: () => "https://accounts.google.test/auth",
      exchangeCodeForIdentity: async () => {
        throw new Error("not used");
      }
    },
    tokenService: tokenServiceFor(permissions) as never
  });
}

describe("admin access request routes", () => {
  it("redirects the local root to the Admin UI", async () => {
    const repos = new AdminRepos();
    const app = await buildAdminApp(repos);

    const response = await app.inject({ method: "GET", url: "/" });

    expect(response.statusCode).toBe(302);
    expect(response.headers.location).toBe("/admin");

    const adminResponse = await app.inject({ method: "GET", url: "/admin" });
    expect(adminResponse.statusCode).toBe(302);
    expect(adminResponse.headers.location).toBe("/admin/login");
    await app.close();
  });



  it("serves the Admin UI and API under PUBLIC_BASE_PATH", async () => {
    const repos = new AdminRepos();
    const app = await buildAdminApp(repos, PLATFORM_ADMIN_PERMISSIONS, {
      publicBasePath: "/access-control",
      appBaseUrl: "http://localhost:8080/access-control",
      authIssuer: "http://localhost:8080/access-control",
      googleRedirectUri: "http://localhost:8080/access-control/v1/auth/google/callback"
    });

    const root = await app.inject({ method: "GET", url: "/" });
    expect(root.statusCode).toBe(302);
    expect(root.headers.location).toBe("/access-control");

    const unauthenticatedHtmlResponse = await app.inject({ method: "GET", url: "/access-control" });
    expect(unauthenticatedHtmlResponse.statusCode).toBe(302);
    expect(unauthenticatedHtmlResponse.headers.location).toBe("/access-control/login");

    const htmlResponse = await app.inject({
      method: "GET",
      url: "/access-control",
      headers: { cookie: adminSessionCookie() }
    });
    expect(htmlResponse.statusCode).toBe(200);
    expect(htmlResponse.body).toContain("/access-control/v1");
    expect(htmlResponse.body).toContain('rel="icon" href="/access-control/favicon.svg"');
    expect(htmlResponse.body).toContain('ADMIN_BASE_PATH = "/access-control"');
    expect(htmlResponse.body).toContain('id="auth-action">Logout</button>');
    expect(htmlResponse.body).not.toContain('id="login"');

    const toolsResponse = await app.inject({
      method: "GET",
      url: "/access-control/v1/admin/tools",
      headers: { authorization: "Bearer admin-token" }
    });
    expect(toolsResponse.statusCode).toBe(200);

    const faviconResponse = await app.inject({ method: "GET", url: "/access-control/favicon.svg" });
    expect(faviconResponse.statusCode).toBe(200);
    expect(faviconResponse.headers["content-type"]).toContain("image/svg+xml");
    expect(faviconResponse.body).toContain("#004b63");

    await app.close();
  });

  it("serves parseable Admin UI JavaScript", async () => {
    const repos = new AdminRepos();
    const app = await buildAdminApp(repos, PLATFORM_ADMIN_PERMISSIONS, {
      publicBasePath: "/access-control",
      appBaseUrl: "http://localhost:8080/access-control",
      authIssuer: "http://localhost:8080/access-control",
      googleRedirectUri: "http://localhost:8080/access-control/v1/auth/google/callback"
    });

    const response = await app.inject({ method: "GET", url: "/access-control", headers: { cookie: adminSessionCookie() } });
    expect(response.statusCode).toBe(200);
    const script = response.body.match(/<script>([\s\S]*?)<\/script>/)?.[1];
    if (!script) throw new Error("Admin UI script not found");
    expect(() => new Function(script)).not.toThrow();
    expect(script).toContain("ADMIN_BASE_PATH + '/refresh'");
    expect(script).toContain("return api(path, options, true)");

    await app.close();
  });

  it("returns invalid-session errors for missing admin sessions", async () => {
    const repos = new AdminRepos();
    const app = await buildAdminApp(repos);

    const response = await app.inject({
      method: "GET",
      url: "/v1/admin/tools"
    });

    expect(response.statusCode).toBe(400);
    expect(response.json().error.code).toBe("AUTH_INVALID_STATE");
    await app.close();
  });

  it("creates a tool with a one-time client secret, hashed storage and audit event", async () => {
    const repos = new AdminRepos();
    const app = await buildAdminApp(repos);

    const response = await app.inject({
      method: "POST",
      url: "/v1/admin/tools",
      headers: { authorization: "Bearer admin-token" },
      payload: {
        slug: "reporting",
        display_name: "Reporting",
        description: "Internal reporting tool",
        owner_email: "Owner@unguess.io",
        allowed_return_urls: ["https://reporting.draftapps.it/auth/callback"],
        permission_keys: ["reporting:view:all"]
      }
    });

    expect(response.statusCode).toBe(201);
    const body = response.json();
    expect(body.tool).toMatchObject({
      id: "created-tool-id",
      slug: "reporting",
      display_name: "Reporting",
      owner_email: "owner@unguess.io",
      allowed_return_urls: ["https://reporting.draftapps.it/auth/callback"]
    });
    expect(body.tool_client_id).toMatch(/^tlc_/);
    expect(body.tool_client_secret).toMatch(/^tls_/);
    expect(repos.toolPermissionReplacements).toEqual([
      { toolId: "created-tool-id", permissionKeys: ["reporting:view:all"] }
    ]);
    expect(repos.toolClients).toHaveLength(1);
    expect(repos.toolClients[0].client_id).toBe(body.tool_client_id);
    expect(repos.toolClients[0].client_secret_hash).not.toBe(body.tool_client_secret);
    await expect(
      verifyToolSecret(body.tool_client_secret, config.toolClientSecretPepper, repos.toolClients[0].client_secret_hash)
    ).resolves.toBe(true);
    expect(JSON.stringify(repos.audits)).not.toContain(body.tool_client_secret);
    expect(repos.audits).toContainEqual(
      expect.objectContaining({
        event_type: "admin.tool.created",
        outcome: "success",
        tool_slug: "reporting"
      })
    );
    await app.close();
  });

  it("forwards admin tool search, status and owner filters to the repository", async () => {
    const repos = new AdminRepos();
    repos.tools.set(tool.id, {
      ...tool,
      owner_email: "owner@unguess.io"
    });
    const app = await buildAdminApp(repos);

    const response = await app.inject({
      method: "GET",
      url: "/v1/admin/tools?search=crm&status=active&owner_email=Owner@unguess.io",
      headers: { authorization: "Bearer admin-token" }
    });

    expect(response.statusCode).toBe(200);
    expect(response.json().items).toEqual([
      expect.objectContaining({
        id: tool.id,
        slug: "crm",
        owner_email: "owner@unguess.io"
      })
    ]);
    expect(repos.toolsListFilters).toEqual([
      expect.objectContaining({
        search: "crm",
        status: "active",
        ownerEmail: "owner@unguess.io",
        limit: 200
      })
    ]);
    await app.close();
  });

  it("keeps tool-admin tool lists scoped to assigned tools when filters are used", async () => {
    const repos = new AdminRepos();
    repos.assignedToolIds = [tool.id];
    const app = await buildAdminApp(repos, TOOL_ADMIN_PERMISSIONS);

    const response = await app.inject({
      method: "GET",
      url: "/v1/admin/tools?search=access&status=active",
      headers: { authorization: "Bearer tool-admin-token" }
    });

    expect(response.statusCode).toBe(200);
    expect(response.json().items).toEqual([]);
    expect(repos.toolsListFilters).toEqual([
      expect.objectContaining({
        assignedToolIds: [tool.id],
        search: "access",
        status: "active",
        limit: 200
      })
    ]);
    await app.close();
  });

  it("lists tools with registered permission keys for admin editing", async () => {
    const repos = new AdminRepos();
    const app = await buildAdminApp(repos);

    const response = await app.inject({
      method: "GET",
      url: "/v1/admin/tools",
      headers: { authorization: "Bearer admin-token" }
    });

    expect(response.statusCode).toBe(200);
    expect(response.json().items).toContainEqual(
      expect.objectContaining({
        id: tool.id,
        slug: "crm",
        permission_keys: ["crm:read", "crm:write"]
      })
    );
    await app.close();
  });

  it("updates tool metadata and permission keys and audits the admin change", async () => {
    const repos = new AdminRepos();
    const app = await buildAdminApp(repos);

    const response = await app.inject({
      method: "PATCH",
      url: "/v1/admin/tools/tool-id",
      headers: { authorization: "Bearer admin-token" },
      payload: {
        display_name: "CRM operativo",
        description: "Tool CRM aggiornato",
        owner_email: "Owner@unguess.io",
        allowed_return_urls: ["https://crm.draftapps.it/auth/callback"],
        permission_keys: ["crm:read:all"]
      }
    });

    expect(response.statusCode).toBe(200);
    expect(response.json().tool).toMatchObject({
      id: tool.id,
      display_name: "CRM operativo",
      description: "Tool CRM aggiornato",
      owner_email: "owner@unguess.io",
      permission_keys: ["crm:read:all"]
    });
    expect(repos.toolPermissionReplacements).toEqual([{ toolId: tool.id, permissionKeys: ["crm:read:all"] }]);
    expect(repos.audits).toContainEqual(
      expect.objectContaining({
        event_type: "admin.tool.updated",
        outcome: "success",
        tool_slug: "crm"
      })
    );
    await app.close();
  });

  it("deletes a non-admin tool and audits the destructive change", async () => {
    const repos = new AdminRepos();
    const app = await buildAdminApp(repos);

    const response = await app.inject({
      method: "DELETE",
      url: "/v1/admin/tools/tool-id",
      headers: { authorization: "Bearer admin-token" }
    });

    expect(response.statusCode).toBe(200);
    expect(response.json().tool).toMatchObject({ id: tool.id, slug: "crm" });
    expect(repos.deletedToolIds).toEqual([tool.id]);
    expect(repos.tools.has(tool.id)).toBe(false);
    expect(repos.audits).toContainEqual(
      expect.objectContaining({
        event_type: "admin.tool.deleted",
        outcome: "success",
        tool_slug: "crm"
      })
    );
    await app.close();
  });

  it("prevents deleting the reserved access-admin tool", async () => {
    const repos = new AdminRepos();
    const app = await buildAdminApp(repos);

    const response = await app.inject({
      method: "DELETE",
      url: "/v1/admin/tools/access-admin-tool-id",
      headers: { authorization: "Bearer admin-token" }
    });

    expect(response.statusCode).toBe(403);
    expect(response.json().error.code).toBe("ADMIN_FORBIDDEN");
    expect(repos.deletedToolIds).toEqual([]);
    expect(repos.tools.has(accessAdminTool.id)).toBe(true);
    await app.close();
  });

  it("rotates a tool secret, revokes existing clients when requested and audits without leaking the secret", async () => {
    const repos = new AdminRepos();
    repos.toolClients.push({
      tool_id: tool.id,
      client_id: "existing-client-id",
      client_secret_hash: "existing-secret-hash",
      status: "active"
    });
    const app = await buildAdminApp(repos);

    const response = await app.inject({
      method: "POST",
      url: "/v1/admin/tools/tool-id/rotate-secret",
      headers: { authorization: "Bearer admin-token" },
      payload: {
        revoke_existing: true
      }
    });

    expect(response.statusCode).toBe(200);
    const body = response.json();
    expect(body.tool_client_id).toMatch(/^tlc_/);
    expect(body.tool_client_secret).toMatch(/^tls_/);
    expect(repos.disabledToolClientIds).toEqual([tool.id]);
    expect(repos.toolClients[0]).toMatchObject({ client_id: "existing-client-id", status: "disabled" });
    expect(repos.toolClients).toHaveLength(2);
    const rotatedClient = repos.toolClients[1];
    expect(rotatedClient).toMatchObject({
      tool_id: tool.id,
      client_id: body.tool_client_id,
      status: "active"
    });
    expect(rotatedClient.client_secret_hash).not.toBe(body.tool_client_secret);
    await expect(
      verifyToolSecret(body.tool_client_secret, config.toolClientSecretPepper, rotatedClient.client_secret_hash)
    ).resolves.toBe(true);
    expect(JSON.stringify(repos.audits)).not.toContain(body.tool_client_secret);
    expect(repos.audits).toContainEqual(
      expect.objectContaining({
        event_type: "admin.tool.secret_rotated",
        outcome: "success",
        tool_slug: "crm",
        metadata: { revoked_existing_clients: true }
      })
    );
    await app.close();
  });

  it("exports encrypted backups only with explicit backup read permission", async () => {
    const deniedRepos = new AdminRepos();
    const deniedApp = await buildAdminApp(deniedRepos, ["admin:secrets:rotate"]);

    const denied = await deniedApp.inject({
      method: "GET",
      url: "/v1/admin/backup/export",
      headers: { authorization: "Bearer rotate-only-token" }
    });

    expect(denied.statusCode).toBe(403);
    expect(denied.json().error.code).toBe("ADMIN_FORBIDDEN");
    await deniedApp.close();

    const repos = new AdminRepos();
    const app = await buildAdminApp(repos);
    const response = await app.inject({
      method: "GET",
      url: "/v1/admin/backup/export",
      headers: { authorization: "Bearer admin-token" }
    });

    expect(response.statusCode).toBe(200);
    const encrypted = response.json();
    expect(encrypted.schema).toBe("access-layer-encrypted-backup");
    expect(response.body).not.toContain("client_secret_hash");
    const decrypted = decryptJsonPayload(encrypted, config.backupEncryptionKey!);
    expect(decrypted).toMatchObject({ schema: "access-layer-backup", version: 1 });
    expect(repos.audits).toContainEqual(expect.objectContaining({ event_type: "admin.backup.exported" }));
    await app.close();
  });

  it("exports restore secret material only with explicit backup secret permission", async () => {
    const deniedRepos = new AdminRepos();
    const deniedApp = await buildAdminApp(deniedRepos, ["admin:backup:read"]);

    const denied = await deniedApp.inject({
      method: "GET",
      url: "/v1/admin/backup/secret-material",
      headers: { authorization: "Bearer backup-read-token" }
    });

    expect(denied.statusCode).toBe(403);
    await deniedApp.close();

    const repos = new AdminRepos();
    const app = await buildAdminApp(repos);
    const response = await app.inject({
      method: "GET",
      url: "/v1/admin/backup/secret-material",
      headers: { authorization: "Bearer admin-token" }
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      secret_material: {
        TOOL_CLIENT_SECRET_PEPPER: config.toolClientSecretPepper,
        BACKUP_ENCRYPTION_KEY: config.backupEncryptionKey
      }
    });
    expect(response.body).toContain("Existing per-tool client secrets are not recoverable");
    expect(repos.audits).toContainEqual(expect.objectContaining({ event_type: "admin.backup.secret_material_exported" }));
    await app.close();
  });

  it("creates a pending email grant and audits the admin change", async () => {
    const repos = new AdminRepos();
    const app = await buildAdminApp(repos);

    const response = await app.inject({
      method: "POST",
      url: "/v1/admin/grants",
      headers: { authorization: "Bearer admin-token" },
      payload: {
        tool_slug: "crm",
        email: "Mario.Rossi@unguess.io",
        role: "tool_user",
        permissions: ["crm:read"]
      }
    });

    expect(response.statusCode).toBe(201);
    expect(response.json()).toEqual({
      grant_id: "new-grant-id",
      status: "pending_user_link",
      link_status: "pending_user_link",
      tool_slug: "crm",
      email: "mario.rossi@unguess.io",
      role: "tool_user",
      permissions: ["crm:read"]
    });
    expect(repos.grant).toMatchObject({
      tool_id: tool.id,
      user_id: null,
      email_normalized: "mario.rossi@unguess.io",
      role: "tool_user",
      permissions: ["crm:read"],
      status: "pending_user_link",
      created_by_user_id: adminUser.id
    });
    expect(repos.audits).toContainEqual(
      expect.objectContaining({
        event_type: "admin.grant.created",
        outcome: "success",
        tool_slug: "crm",
        metadata: {
          grant_id: "new-grant-id",
          target_user_id: null,
          target_email: "mario.rossi@unguess.io"
        }
      })
    );
    await app.close();
  });

  it("exports bulk grant templates and tool permission catalog CSV", async () => {
    const repos = new AdminRepos();
    const app = await buildAdminApp(repos);

    const template = await app.inject({
      method: "GET",
      url: "/v1/admin/grants/bulk/template",
      headers: { authorization: "Bearer admin-token" }
    });
    expect(template.statusCode).toBe(200);
    expect(template.headers["content-type"]).toContain("text/csv");
    expect(template.body).toContain("email,tool_slug,role,permissions,valid_until,action,note");

    const permissions = await app.inject({
      method: "GET",
      url: "/v1/admin/tools/permissions/export",
      headers: { authorization: "Bearer admin-token" }
    });
    expect(permissions.statusCode).toBe(200);
    expect(permissions.body).toContain("tool_slug,tool_name,tool_status,permission_key,permission_description");
    expect(permissions.body).toContain("crm:read");
    await app.close();
  });

  it("previews and commits bulk grant imports as pending email grants", async () => {
    const repos = new AdminRepos();
    const app = await buildAdminApp(repos);
    const content = "email,tool_slug,role,permissions,valid_until,action,note\nMario.Rossi@unguess.io,crm,tool_user,crm:read,,upsert,Accesso bulk\n";

    const preview = await app.inject({
      method: "POST",
      url: "/v1/admin/grants/bulk/preview",
      headers: { authorization: "Bearer admin-token" },
      payload: { content }
    });

    expect(preview.statusCode).toBe(200);
    expect(preview.json()).toMatchObject({
      summary: { total_rows: 1, ok: 1, warning: 0, error: 0 },
      rows: [
        {
          row: 2,
          email: "mario.rossi@unguess.io",
          tool_slug: "crm",
          result: "ok",
          resolved_user: "pending_user_link",
          status_after: "pending_user_link",
          operation: "create"
        }
      ]
    });
    expect(repos.grant).toBeNull();

    const commit = await app.inject({
      method: "POST",
      url: "/v1/admin/grants/bulk/commit",
      headers: { authorization: "Bearer admin-token" },
      payload: { content }
    });

    expect(commit.statusCode).toBe(201);
    expect(commit.json()).toMatchObject({
      committed: true,
      summary: { total_rows: 1, ok: 1, warning: 0, error: 0, created: 1 }
    });
    expect(repos.grant).toMatchObject({
      tool_id: tool.id,
      user_id: null,
      email_normalized: "mario.rossi@unguess.io",
      role: "tool_user",
      permissions: ["crm:read"],
      status: "pending_user_link"
    });
    expect(repos.audits).toContainEqual(
      expect.objectContaining({
        event_type: "admin.grant.created",
        metadata: expect.objectContaining({ bulk_import: true, row_number: 2 })
      })
    );
    expect(repos.audits).toContainEqual(expect.objectContaining({ event_type: "admin.grant.bulk_import_committed" }));
    await app.close();
  });

  it("refreshes the Admin UI session on authenticated activity and rotates its refresh cookie", async () => {
    const repos = new AdminRepos();
    const refreshToken = "rt_admin-refresh-token-with-sufficient-entropy";
    await repos.createRefreshToken(
      hashOpaque(refreshToken, config.toolClientSecretPepper),
      adminSession.id,
      new Date(Date.now() + config.refreshTokenTtlSeconds * 1000)
    );
    const app = await buildAdminApp(repos);

    const response = await app.inject({
      method: "POST",
      url: "/admin/refresh",
      headers: {
        origin: config.appBaseUrl,
        cookie: `${config.sessionCookieName}_refresh=${encodeURIComponent(signCookie(refreshToken, config.sessionSecret))}`
      }
    });

    expect(response.statusCode).toBe(204);
    const setCookies = Array.isArray(response.headers["set-cookie"])
      ? response.headers["set-cookie"]
      : [String(response.headers["set-cookie"])];
    expect(setCookies.some((cookie) => cookie.startsWith(`${config.sessionCookieName}=`))).toBe(true);
    expect(setCookies.some((cookie) => cookie.startsWith(`${config.sessionCookieName}_refresh=`))).toBe(true);
    expect(repos.refreshTokens.size).toBe(2);
    expect(repos.refreshTokens.get(hashOpaque(refreshToken, config.toolClientSecretPepper))?.status).toBe("revoked");
    expect(repos.audits).toContainEqual(
      expect.objectContaining({
        event_type: "token.refreshed",
        outcome: "success",
        tool_slug: "access-admin"
      })
    );
    await app.close();
  });

  it("auto-detects semicolon-delimited bulk grant CSV imports", async () => {
    const repos = new AdminRepos();
    const app = await buildAdminApp(repos);
    const content = "email;tool_slug;role;permissions;valid_until;action;note\nMario.Rossi@unguess.io;crm;tool_user;crm:read;;upsert;Accesso bulk\n";

    const preview = await app.inject({
      method: "POST",
      url: "/v1/admin/grants/bulk/preview",
      headers: { authorization: "Bearer admin-token" },
      payload: { content }
    });

    expect(preview.statusCode).toBe(200);
    expect(preview.json()).toMatchObject({
      summary: { total_rows: 1, ok: 1, warning: 0, error: 0 },
      rows: [{ email: "mario.rossi@unguess.io", tool_slug: "crm", result: "ok" }]
    });
    await app.close();
  });

  it("does not commit bulk grant imports with validation errors", async () => {
    const repos = new AdminRepos();
    const app = await buildAdminApp(repos);
    const content = "email,tool_slug,role,permissions,valid_until,action,note\nexternal@gmail.com,crm,tool_user,crm:read,,upsert,Nope\n";

    const response = await app.inject({
      method: "POST",
      url: "/v1/admin/grants/bulk/commit",
      headers: { authorization: "Bearer admin-token" },
      payload: { content }
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      committed: false,
      summary: { total_rows: 1, ok: 0, warning: 0, error: 1 },
      rows: [{ result: "error", reason: expect.stringContaining("EMAIL_DOMAIN_NOT_ALLOWED") }]
    });
    expect(repos.grant).toBeNull();
    await app.close();
  });

  it("rejects pending email grants outside the allowed hosted domains", async () => {
    const repos = new AdminRepos();
    const app = await buildAdminApp(repos);

    const response = await app.inject({
      method: "POST",
      url: "/v1/admin/grants",
      headers: { authorization: "Bearer admin-token" },
      payload: {
        tool_slug: "crm",
        email: "external@gmail.com",
        role: "tool_user",
        permissions: ["crm:read"]
      }
    });

    expect(response.statusCode).toBe(400);
    expect(response.json().error.code).toBe("VALIDATION_ERROR");
    expect(repos.grant).toBeNull();
    await app.close();
  });

  it("creates an active grant for a known user id and audits the admin change", async () => {
    const repos = new AdminRepos();
    const app = await buildAdminApp(repos);

    const response = await app.inject({
      method: "POST",
      url: "/v1/admin/grants",
      headers: { authorization: "Bearer admin-token" },
      payload: {
        tool_slug: "crm",
        user_id: targetUser.id,
        role: "tool_user",
        permissions: ["crm:read"],
        valid_until: "2026-12-31T23:59:59Z"
      }
    });

    expect(response.statusCode).toBe(201);
    expect(response.json()).toEqual({
      grant_id: "new-grant-id",
      status: "active",
      link_status: "linked",
      tool_slug: "crm",
      email: "mario.rossi@unguess.io",
      role: "tool_user",
      permissions: ["crm:read"]
    });
    expect(repos.grant).toMatchObject({
      tool_id: tool.id,
      user_id: targetUser.id,
      email_normalized: targetUser.email_normalized,
      role: "tool_user",
      permissions: ["crm:read"],
      status: "active",
      created_by_user_id: adminUser.id
    });
    expect(repos.grant?.valid_until?.toISOString()).toBe("2026-12-31T23:59:59.000Z");
    expect(repos.audits).toContainEqual(
      expect.objectContaining({
        event_type: "admin.grant.created",
        outcome: "success",
        tool_slug: "crm",
        metadata: {
          grant_id: "new-grant-id",
          target_user_id: targetUser.id,
          target_email: targetUser.email_normalized
        }
      })
    );
    await app.close();
  });

  it("scopes tool-admin grant lists to assigned tools", async () => {
    const repos = new AdminRepos();
    repos.assignedToolIds = [tool.id];
    repos.grant = {
      id: "assigned-grant-id",
      tool_id: tool.id,
      user_id: targetUser.id,
      email_normalized: targetUser.email_normalized,
      role: "tool_user",
      permissions: ["crm:read"],
      status: "active",
      valid_from: new Date(Date.now() - 1000),
      valid_until: null,
      created_by_user_id: adminUser.id
    };
    const app = await buildAdminApp(repos, TOOL_ADMIN_PERMISSIONS);

    const response = await app.inject({
      method: "GET",
      url: "/v1/admin/grants?tool_slug=crm&email=Mario.Rossi@unguess.io&status=active",
      headers: { authorization: "Bearer tool-admin-token" }
    });

    expect(response.statusCode).toBe(200);
    expect(response.json().items).toEqual([expect.objectContaining({ id: "assigned-grant-id", tool_id: tool.id })]);
    expect(repos.grantsListFilters).toEqual([
      expect.objectContaining({
        toolSlug: "crm",
        email: "mario.rossi@unguess.io",
        status: "active",
        assignedToolIds: [tool.id],
        limit: 200
      })
    ]);
    await app.close();
  });

  it("allows tool admins to create grants for assigned tools", async () => {
    const repos = new AdminRepos();
    repos.assignedToolIds = [tool.id];
    const app = await buildAdminApp(repos, TOOL_ADMIN_PERMISSIONS);

    const response = await app.inject({
      method: "POST",
      url: "/v1/admin/grants",
      headers: { authorization: "Bearer tool-admin-token" },
      payload: {
        tool_slug: "crm",
        user_id: targetUser.id,
        role: "tool_user",
        permissions: ["crm:read"]
      }
    });

    expect(response.statusCode).toBe(201);
    expect(repos.grant).toMatchObject({
      tool_id: tool.id,
      user_id: targetUser.id,
      status: "active",
      created_by_user_id: adminUser.id
    });
    expect(repos.audits).toContainEqual(
      expect.objectContaining({
        event_type: "admin.grant.created",
        outcome: "success",
        tool_slug: "crm"
      })
    );
    await app.close();
  });

  it("prevents tool admins from creating grants for unassigned tools", async () => {
    const repos = new AdminRepos();
    repos.assignedToolIds = ["other-tool-id"];
    const app = await buildAdminApp(repos, TOOL_ADMIN_PERMISSIONS);

    const response = await app.inject({
      method: "POST",
      url: "/v1/admin/grants",
      headers: { authorization: "Bearer tool-admin-token" },
      payload: {
        tool_slug: "crm",
        user_id: targetUser.id,
        role: "tool_user",
        permissions: ["crm:read"]
      }
    });

    expect(response.statusCode).toBe(403);
    expect(response.json().error.code).toBe("ADMIN_FORBIDDEN");
    expect(repos.grant).toBeNull();
    expect(repos.audits).not.toContainEqual(expect.objectContaining({ event_type: "admin.grant.created" }));
    await app.close();
  });

  it("prevents tool admins from updating grants for unassigned tools", async () => {
    const repos = new AdminRepos();
    repos.assignedToolIds = ["other-tool-id"];
    repos.grant = {
      id: "unassigned-grant-id",
      tool_id: tool.id,
      user_id: targetUser.id,
      email_normalized: targetUser.email_normalized,
      role: "tool_user",
      permissions: ["crm:read"],
      status: "active",
      valid_from: new Date(Date.now() - 1000),
      valid_until: null,
      created_by_user_id: adminUser.id
    };
    const app = await buildAdminApp(repos, TOOL_ADMIN_PERMISSIONS);

    const response = await app.inject({
      method: "PATCH",
      url: "/v1/admin/grants/unassigned-grant-id",
      headers: { authorization: "Bearer tool-admin-token" },
      payload: {
        permissions: ["crm:read", "crm:write"]
      }
    });

    expect(response.statusCode).toBe(403);
    expect(response.json().error.code).toBe("ADMIN_FORBIDDEN");
    expect(repos.grant).toMatchObject({
      id: "unassigned-grant-id",
      permissions: ["crm:read"],
      status: "active"
    });
    expect(repos.audits).not.toContainEqual(expect.objectContaining({ event_type: "admin.grant.updated" }));
    await app.close();
  });

  it("revokes a grant, revokes active sessions and audits the admin change", async () => {
    const repos = new AdminRepos();
    repos.grant = {
      id: "grant-to-revoke-id",
      tool_id: tool.id,
      user_id: "target-user-id",
      email_normalized: "mario.rossi@unguess.io",
      role: "tool_user",
      permissions: ["crm:read"],
      status: "active",
      valid_from: new Date(Date.now() - 1000),
      valid_until: null,
      created_by_user_id: adminUser.id
    };
    const app = await buildAdminApp(repos);

    const response = await app.inject({
      method: "PATCH",
      url: "/v1/admin/grants/grant-to-revoke-id",
      headers: { authorization: "Bearer admin-token" },
      payload: {
        status: "revoked"
      }
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      grant: {
        id: "grant-to-revoke-id",
        status: "revoked"
      },
      revoked_sessions: 2
    });
    expect(repos.grant).toMatchObject({ id: "grant-to-revoke-id", status: "revoked" });
    expect(repos.revokedGrantIds).toEqual(["grant-to-revoke-id"]);
    expect(repos.audits).toContainEqual(
      expect.objectContaining({
        event_type: "admin.grant.revoked",
        outcome: "success",
        tool_slug: "crm",
        metadata: {
          grant_id: "grant-to-revoke-id",
          revoked_sessions: 2
        }
      })
    );
    await app.close();
  });

  it("updates grant role and permissions without revoking sessions and audits the admin change", async () => {
    const repos = new AdminRepos();
    repos.grant = {
      id: "grant-to-update-id",
      tool_id: tool.id,
      user_id: "target-user-id",
      email_normalized: "mario.rossi@unguess.io",
      role: "tool_user",
      permissions: ["crm:read"],
      status: "active",
      valid_from: new Date(Date.now() - 1000),
      valid_until: null,
      created_by_user_id: adminUser.id
    };
    const app = await buildAdminApp(repos);

    const response = await app.inject({
      method: "PATCH",
      url: "/v1/admin/grants/grant-to-update-id",
      headers: { authorization: "Bearer admin-token" },
      payload: {
        role: "tool_operator",
        permissions: ["crm:read", "crm:write"]
      }
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      grant: {
        id: "grant-to-update-id",
        role: "tool_operator",
        permissions: ["crm:read", "crm:write"],
        status: "active"
      },
      revoked_sessions: 0
    });
    expect(repos.grant).toMatchObject({
      id: "grant-to-update-id",
      role: "tool_operator",
      permissions: ["crm:read", "crm:write"],
      status: "active"
    });
    expect(repos.revokedGrantIds).toEqual([]);
    expect(repos.audits).toContainEqual(
      expect.objectContaining({
        event_type: "admin.grant.updated",
        outcome: "success",
        tool_slug: "crm",
        metadata: {
          grant_id: "grant-to-update-id",
          revoked_sessions: 0
        }
      })
    );
    await app.close();
  });

  it("approves a pending access request by creating a grant and auditing both changes", async () => {
    const repos = new AdminRepos();
    const app = await buildAdminApp(repos);

    const response = await app.inject({
      method: "POST",
      url: "/v1/admin/access-requests/access-request-id/approve",
      headers: { authorization: "Bearer admin-token" },
      payload: {
        role: "tool_user",
        permissions: ["crm:read"],
        note: "Approved for test"
      }
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({
      request_id: "access-request-id",
      status: "approved",
      grant_id: "new-grant-id"
    });
    expect(repos.grant).toMatchObject({ role: "tool_user", permissions: ["crm:read"] });
    expect(repos.accessRequest).toMatchObject({ status: "approved", grant_id: "new-grant-id" });
    expect(repos.audits).toMatchObject([
      { event_type: "admin.grant.created", outcome: "success" },
      { event_type: "admin.access_request.approved", outcome: "success" }
    ]);
    await app.close();
  });

  it("rejects a pending access request without creating a grant and audits the decision", async () => {
    const repos = new AdminRepos();
    const app = await buildAdminApp(repos);

    const response = await app.inject({
      method: "POST",
      url: "/v1/admin/access-requests/access-request-id/reject",
      headers: { authorization: "Bearer admin-token" },
      payload: {
        note: "Not assigned to this tool"
      }
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({
      request_id: "access-request-id",
      status: "rejected"
    });
    expect(repos.grant).toBeNull();
    expect(repos.accessRequest).toMatchObject({
      status: "rejected",
      grant_id: null,
      review_note: "Not assigned to this tool"
    });
    expect(repos.audits).toMatchObject([{ event_type: "admin.access_request.rejected", outcome: "success" }]);
    await app.close();
  });

  it("closes a pending access request without creating a grant and audits the decision", async () => {
    const repos = new AdminRepos();
    const app = await buildAdminApp(repos);

    const response = await app.inject({
      method: "POST",
      url: "/v1/admin/access-requests/access-request-id/close",
      headers: { authorization: "Bearer admin-token" },
      payload: {
        note: "Duplicate request"
      }
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({
      request_id: "access-request-id",
      status: "closed"
    });
    expect(repos.grant).toBeNull();
    expect(repos.accessRequest).toMatchObject({
      status: "closed",
      grant_id: null,
      review_note: "Duplicate request"
    });
    expect(repos.audits).toMatchObject([{ event_type: "admin.access_request.closed", outcome: "success" }]);
    await app.close();
  });

  it("prevents auditor role from approving access requests", async () => {
    const repos = new AdminRepos();
    const app = await buildAdminApp(repos, ["admin:audit:read", "admin:access_requests:read"]);

    const response = await app.inject({
      method: "POST",
      url: "/v1/admin/access-requests/access-request-id/approve",
      headers: { authorization: "Bearer auditor-token" },
      payload: {
        role: "tool_user",
        permissions: ["crm:read"]
      }
    });

    expect(response.statusCode).toBe(403);
    expect(response.json().error.code).toBe("ADMIN_FORBIDDEN");
    expect(repos.grant).toBeNull();
    expect(repos.accessRequest.status).toBe("pending");
    await app.close();
  });

  it("scopes tool-admin access request lists to assigned tools", async () => {
    const repos = new AdminRepos();
    repos.assignedToolIds = [tool.id];
    const app = await buildAdminApp(repos, TOOL_ADMIN_PERMISSIONS);

    const response = await app.inject({
      method: "GET",
      url: "/v1/admin/access-requests?status=pending",
      headers: { authorization: "Bearer tool-admin-token" }
    });

    expect(response.statusCode).toBe(200);
    expect(repos.accessRequestFilters).toEqual([
      expect.objectContaining({
        status: "pending",
        assignedToolIds: [tool.id]
      })
    ]);
    await app.close();
  });

  it("prevents tool admins from approving unassigned access requests", async () => {
    const repos = new AdminRepos();
    repos.assignedToolIds = ["other-tool-id"];
    const app = await buildAdminApp(repos, TOOL_ADMIN_PERMISSIONS);

    const response = await app.inject({
      method: "POST",
      url: "/v1/admin/access-requests/access-request-id/approve",
      headers: { authorization: "Bearer tool-admin-token" },
      payload: {
        role: "tool_user",
        permissions: ["crm:read"]
      }
    });

    expect(response.statusCode).toBe(404);
    expect(response.json().error.code).toBe("ACCESS_REQUEST_NOT_FOUND");
    expect(repos.grant).toBeNull();
    expect(repos.accessRequest.status).toBe("pending");
    await app.close();
  });

  it("forwards admin user search and status filters to the repository", async () => {
    const repos = new AdminRepos();
    const app = await buildAdminApp(repos);

    const response = await app.inject({
      method: "GET",
      url: "/v1/admin/users?search=target-google&status=active",
      headers: { authorization: "Bearer admin-token" }
    });

    expect(response.statusCode).toBe(200);
    expect(response.json().items).toEqual([
      expect.objectContaining({
        id: targetUser.id,
        email: "mario.rossi@unguess.io",
        status: "active"
      })
    ]);
    expect(repos.usersListFilters).toEqual([
      expect.objectContaining({
        search: "target-google",
        status: "active",
        limit: 200
      })
    ]);
    await app.close();
  });

  it("disables a user, revokes active sessions and audits the admin change", async () => {
    const repos = new AdminRepos();
    const app = await buildAdminApp(repos);

    const response = await app.inject({
      method: "PATCH",
      url: "/v1/admin/users/target-user-id",
      headers: { authorization: "Bearer admin-token" },
      payload: {
        status: "disabled"
      }
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      user: {
        id: targetUser.id,
        status: "disabled"
      },
      revoked_sessions: 1
    });
    expect(repos.users.get(targetUser.id)?.status).toBe("disabled");
    expect(repos.audits).toContainEqual(
      expect.objectContaining({
        event_type: "admin.user.status_changed",
        outcome: "success",
        metadata: {
          target_user_id: targetUser.id,
          status: "disabled",
          revoked_sessions: 1
        }
      })
    );
    await app.close();
  });

  it("rejects invalid admin tool status filters before listing tools", async () => {
    const repos = new AdminRepos();
    const app = await buildAdminApp(repos);

    const response = await app.inject({
      method: "GET",
      url: "/v1/admin/tools?status=archived",
      headers: { authorization: "Bearer admin-token" }
    });

    expect(response.statusCode).toBe(400);
    expect(response.json().error.code).toBe("VALIDATION_ERROR");
    expect(repos.toolsListCalls).toBe(0);
    await app.close();
  });

  it("rejects invalid admin user status filters before listing users", async () => {
    const repos = new AdminRepos();
    const app = await buildAdminApp(repos);

    const response = await app.inject({
      method: "GET",
      url: "/v1/admin/users?status=archived",
      headers: { authorization: "Bearer admin-token" }
    });

    expect(response.statusCode).toBe(400);
    expect(response.json().error.code).toBe("VALIDATION_ERROR");
    expect(repos.usersListCalls).toBe(0);
    await app.close();
  });

  it("rejects invalid grant status filters before listing grants", async () => {
    const repos = new AdminRepos();
    const app = await buildAdminApp(repos);

    const response = await app.inject({
      method: "GET",
      url: "/v1/admin/grants?status=deleted",
      headers: { authorization: "Bearer admin-token" }
    });

    expect(response.statusCode).toBe(400);
    expect(response.json().error.code).toBe("VALIDATION_ERROR");
    expect(repos.grantsListCalls).toBe(0);
    await app.close();
  });

  it("rejects invalid access request status filters before listing requests", async () => {
    const repos = new AdminRepos();
    const app = await buildAdminApp(repos);

    const response = await app.inject({
      method: "GET",
      url: "/v1/admin/access-requests?status=deleted",
      headers: { authorization: "Bearer admin-token" }
    });

    expect(response.statusCode).toBe(400);
    expect(response.json().error.code).toBe("VALIDATION_ERROR");
    expect(repos.accessRequestsListCalls).toBe(0);
    await app.close();
  });

  it("audits invalid Admin UI callback state", async () => {
    const repos = new AdminRepos();
    const app = await buildAdminApp(repos);

    const response = await app.inject({
      method: "GET",
      url: "/admin/auth/callback?code=otc_test&state=wrong"
    });

    expect(response.statusCode).toBe(400);
    expect(repos.audits).toContainEqual(
      expect.objectContaining({
        event_type: "auth.denied.invalid_state",
        outcome: "denied",
        tool_slug: "access-admin",
        reason_code: "AUTH_INVALID_STATE"
      })
    );
    await app.close();
  });

  it("revokes and audits the Admin UI session on logout", async () => {
    const repos = new AdminRepos();
    const app = await buildAdminApp(repos);

    const response = await app.inject({
      method: "POST",
      url: "/admin/logout",
      headers: {
        origin: config.appBaseUrl,
        cookie: `${config.sessionCookieName}=${encodeURIComponent(signCookie("admin-token", config.sessionSecret))}`
      }
    });

    expect(response.statusCode).toBe(204);
    expect(repos.revokedSessions).toBe(1);
    expect(repos.audits).toContainEqual(
      expect.objectContaining({
        event_type: "session.revoked",
        outcome: "success",
        tool_slug: "access-admin"
      })
    );
    await app.close();
  });

  it("renders Admin UI audit filters and correlation copy controls", async () => {
    const repos = new AdminRepos();
    const app = await buildAdminApp(repos);

    const response = await app.inject({
      method: "GET",
      url: "/admin",
      headers: { cookie: adminSessionCookie() }
    });

    expect(response.statusCode).toBe(200);
    const html = response.body;
    expect(html).toContain('id="audit-filters"');
    expect(html).toContain('id="audit-date-from"');
    expect(html).toContain('id="audit-tool-slug"');
    expect(html).toContain('id="audit-email"');
    expect(html).toContain('id="audit-google-sub"');
    expect(html).toContain('id="audit-correlation-id"');
    expect(html).toContain("data-copy-correlation");
    await app.close();
  });

  it("renders Admin UI tool metadata and inline creation controls", async () => {
    const repos = new AdminRepos();
    const app = await buildAdminApp(repos);

    const response = await app.inject({
      method: "GET",
      url: "/admin",
      headers: { cookie: adminSessionCookie() }
    });

    expect(response.statusCode).toBe(200);
    const html = response.body;
    expect(html).toContain('id="tool-filters"');
    expect(html).toContain('id="tool-filter-search"');
    expect(html).toContain('id="tool-filter-owner"');
    expect(html).toContain('id="tool-filter-status"');
    expect(html).toContain("Descrizione opzionale");
    expect(html).toContain("Owner email opzionale");
    expect(html).toContain('id="tool-create-form"');
    expect(html).toContain('id="tool-create-permissions"');
    expect(html).toContain("Salva tool");
    expect(html).toContain("Client secret mostrato una sola volta");
    expect(html).not.toContain("prompt('");
    expect(html).not.toContain("alert(");
    expect(html).toContain('id="tool-description"');
    expect(html).toContain('id="tool-permissions"');
    expect(html).toContain('id="edit-tool"');
    expect(html).toContain('id="delete-tool"');
    expect(html).toContain('id="tool-access-heading"');
    expect(html).toContain("data-tool-user-grants");
    expect(html).toContain("data-tool-user-grant");
    expect(html).toContain("Utenti e autorizzazioni");
    expect(html).toContain("Modifica salvata.");
    expect(html).toContain("Tool eliminato.");
    expect(html).toContain("permission_keys: parseList");
    await app.close();
  });

  it("renders Admin UI user filters and disable confirmation", async () => {
    const repos = new AdminRepos();
    const app = await buildAdminApp(repos);

    const response = await app.inject({
      method: "GET",
      url: "/admin",
      headers: { cookie: adminSessionCookie() }
    });

    expect(response.statusCode).toBe(200);
    const html = response.body;
    expect(html).toContain('id="user-filters"');
    expect(html).toContain('id="user-filter-search"');
    expect(html).toContain('id="user-filter-status"');
    expect(html).toContain("data-user-detail");
    expect(html).toContain('id="create-user-grant"');
    expect(html).toContain("user_id: user.id");
    expect(html).toContain('id="user-grant-create-form"');
    expect(html).toContain('id="user-tools-heading"');
    expect(html).toContain("Tool e autorizzazioni");
    expect(html).toContain("permissionPickerMarkup('user-grant-permissions'");
    expect(html).toContain('id="user-grant-valid-until"');
    expect(html).toContain("Salva grant");
    expect(html).toContain("Confermi la revoca dell'accesso?");
    await app.close();
  });

  it("renders Admin UI grant filters, detail edit controls and revocation confirmation", async () => {
    const repos = new AdminRepos();
    const app = await buildAdminApp(repos);

    const response = await app.inject({
      method: "GET",
      url: "/admin",
      headers: { cookie: adminSessionCookie() }
    });

    expect(response.statusCode).toBe(200);
    const html = response.body;
    expect(html).toContain('id="grant-filters"');
    expect(html).toContain('id="grant-filter-tool"');
    expect(html).toContain('id="grant-filter-email"');
    expect(html).toContain('id="grant-filter-status"');
    expect(html).toContain("data-grant-detail");
    expect(html).toContain('id="save-grant"');
    expect(html).toContain('id="revoke-grant"');
    expect(html).toContain("apiUrl('/admin/grants/')");
    expect(html).toContain('id="grant-create-form"');
    expect(html).toContain('id="grant-create-tool"');
    expect(html).toContain("permissionPickerMarkup('grant-create-permissions'");
    expect(html).toContain('id="grant-create-valid-until"');
    expect(html).toContain('id="bulk-grants"');
    expect(html).toContain('id="csv-grants"');
    expect(html).toContain('id="grant-template"');
    expect(html).toContain('id="grant-export"');
    expect(html).toContain('id="permissions-export"');
    expect(html).toContain("apiUrl('/admin/grants/bulk/preview')");
    expect(html).toContain("apiUrl('/admin/grants/bulk/commit')");
    expect(html).toContain('id="grant-bulk-form"');
    expect(html).toContain('id="grant-bulk-emails"');
    expect(html).toContain('id="grant-bulk-tool"');
    expect(html).toContain("permissionPickerMarkup('grant-bulk-permissions'");
    expect(html).toContain("Rilascia grant in blocco");
    expect(html).toContain('type="checkbox"');
    expect(html).toContain('class="permission-picker"');
    expect(html).toContain('.content { width: 100%;');
    expect(html).toContain("Confermi la revoca dell'accesso?");
    await app.close();
  });

  it("renders Admin UI access request filters and inline decision forms", async () => {
    const repos = new AdminRepos();
    const app = await buildAdminApp(repos);

    const response = await app.inject({
      method: "GET",
      url: "/admin",
      headers: { cookie: adminSessionCookie() }
    });

    expect(response.statusCode).toBe(200);
    const html = response.body;
    expect(html).toContain('id="request-filters"');
    expect(html).toContain('id="request-filter-status"');
    expect(html).toContain('id="request-filter-tool"');
    expect(html).toContain('id="request-filter-email"');
    expect(html).toContain("Primo tentativo");
    expect(html).toContain("Ultimo tentativo");
    expect(html).toContain('id="request-approve-form"');
    expect(html).toContain('id="request-approve-valid-until"');
    expect(html).toContain('id="request-decision-form"');
    expect(html).toContain("Nota opzionale");
    expect(html).toContain("valid_until");
    await app.close();
  });

  it("renders shared Admin UI table pagination and empty-state affordances", async () => {
    const repos = new AdminRepos();
    const app = await buildAdminApp(repos);

    const response = await app.inject({
      method: "GET",
      url: "/admin",
      headers: { cookie: adminSessionCookie() }
    });

    expect(response.statusCode).toBe(200);
    const html = response.body;
    expect(html).toContain("const PAGE_SIZE = 25");
    expect(html).toContain("function bindPagination");
    expect(html).toContain('class="empty-state"');
    expect(html).toContain('class="pager"');
    expect(html).toContain("data-page-prev");
    expect(html).toContain("data-page-next");
    expect(html).toContain("Pagina ");
    expect(html).toContain("state.pages.tools = 0");
    expect(html).toContain("state.pages.users = 0");
    expect(html).toContain("state.pages.grants = 0");
    expect(html).toContain("state.pages.requests = 0");
    expect(html).toContain("state.pages.audit = 0");
    await app.close();
  });

  it("renders a non-sensitive Admin UI OAuth settings summary", async () => {
    const repos = new AdminRepos();
    const app = await buildAdminApp(repos);

    const response = await app.inject({
      method: "GET",
      url: "/admin",
      headers: { cookie: adminSessionCookie() }
    });

    expect(response.statusCode).toBe(200);
    const html = response.body;
    expect(html).toContain("Base URL");
    expect(html).toContain("http://localhost:8080");
    expect(html).toContain("OAuth callback");
    expect(html).toContain("http://localhost:8080/v1/auth/google/callback");
    expect(html).toContain("Hosted domains");
    expect(html).toContain("unguess.io");
    expect(html).toContain("OIDC scope");
    expect(html).toContain("openid email profile");
    expect(html).toContain("Access token TTL");
    expect(html).toContain("Refresh tokens");
    expect(html).not.toContain(config.googleClientSecret);
    expect(html).not.toContain(config.sessionSecret);
    expect(html).not.toContain(config.toolClientSecretPepper);
    await app.close();
  });

  it("passes supported audit log filters to the repository", async () => {
    const repos = new AdminRepos();
    const app = await buildAdminApp(repos);

    const response = await app.inject({
      method: "GET",
      url:
        "/v1/admin/audit-logs?tool_slug=crm&email=Mario.Rossi%40unguess.io&google_sub=google-sub-1&outcome=denied&reason_code=AUTH_NOT_AUTHORIZED_FOR_TOOL&correlation_id=corr_123&date_from=2026-06-12T00%3A00%3A00Z&date_to=2026-06-13T00%3A00%3A00Z",
      headers: { authorization: "Bearer admin-token" }
    });

    expect(response.statusCode).toBe(200);
    expect(repos.auditLogFilters).toEqual([
      expect.objectContaining({
        toolSlug: "crm",
        email: "mario.rossi@unguess.io",
        googleSub: "google-sub-1",
        outcome: "denied",
        reasonCode: "AUTH_NOT_AUTHORIZED_FOR_TOOL",
        correlationId: "corr_123",
        dateFrom: "2026-06-12T00:00:00Z",
        dateTo: "2026-06-13T00:00:00Z"
      })
    ]);
    await app.close();
  });

  it("rejects invalid audit log filters before listing logs", async () => {
    const repos = new AdminRepos();
    const app = await buildAdminApp(repos);

    const response = await app.inject({
      method: "GET",
      url: "/v1/admin/audit-logs?outcome=maybe&date_from=2026-06-12",
      headers: { authorization: "Bearer admin-token" }
    });

    expect(response.statusCode).toBe(400);
    expect(response.json().error.code).toBe("VALIDATION_ERROR");
    expect(repos.auditLogFilters).toEqual([]);
    await app.close();
  });
});
