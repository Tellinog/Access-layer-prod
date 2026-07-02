import type { Db } from "./db.js";
import type {
  AccessRequest,
  AuditEventInput,
  AuthRequest,
  AuthorizationGrant,
  OneTimeCode,
  Session,
  Tool,
  ToolClient,
  ToolStatus,
  User,
  UserStatus
} from "./types.js";

function jsonArray(value: unknown): string[] {
  if (Array.isArray(value)) {
    return value.map(String);
  }
  if (typeof value === "string") {
    try {
      const parsed = JSON.parse(value) as unknown;
      return Array.isArray(parsed) ? parsed.map(String) : [];
    } catch {
      return [];
    }
  }
  return [];
}

function mapTool(row: Record<string, unknown>): Tool {
  return {
    ...(row as unknown as Omit<Tool, "allowed_return_urls">),
    allowed_return_urls: jsonArray(row.allowed_return_urls)
  };
}

function mapGrant(row: Record<string, unknown>): AuthorizationGrant {
  return {
    ...(row as unknown as Omit<AuthorizationGrant, "permissions">),
    permissions: jsonArray(row.permissions)
  };
}

export class Repositories {
  constructor(public readonly db: Db) {}

  withDb(db: Db): Repositories {
    return new Repositories(db);
  }

  async health(): Promise<boolean> {
    await this.db.query("SELECT 1");
    return true;
  }

  async writeAudit(input: AuditEventInput & { event_id: string; metadata: Record<string, unknown> }): Promise<void> {
    await this.db.query(
      `INSERT INTO audit_logs (
        event_id, event_type, outcome, correlation_id, tool_id, tool_slug,
        actor_user_id, actor_google_sub, actor_email, actor_hd,
        request_ip_hash, user_agent_hash, reason_code, metadata
      ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14::jsonb)`,
      [
        input.event_id,
        input.event_type,
        input.outcome,
        input.correlation_id,
        input.tool_id ?? null,
        input.tool_slug ?? null,
        input.actor_user_id ?? null,
        input.actor_google_sub ?? null,
        input.actor_email ?? null,
        input.actor_hd ?? null,
        input.request_ip_hash ?? null,
        input.user_agent_hash ?? null,
        input.reason_code ?? null,
        JSON.stringify(input.metadata ?? {})
      ]
    );
  }

  async listAuditLogs(filters: {
    toolSlug?: string;
    email?: string;
    googleSub?: string;
    outcome?: string;
    reasonCode?: string;
    correlationId?: string;
    dateFrom?: string;
    dateTo?: string;
    limit: number;
    assignedToolIds?: string[];
  }): Promise<unknown[]> {
    const clauses: string[] = [];
    const params: unknown[] = [];
    const add = (sql: string, value: unknown) => {
      params.push(value);
      clauses.push(sql.replace("?", `$${params.length}`));
    };
    if (filters.toolSlug) add("tool_slug = ?", filters.toolSlug);
    if (filters.email) add("actor_email = ?", filters.email);
    if (filters.googleSub) add("actor_google_sub = ?", filters.googleSub);
    if (filters.outcome) add("outcome = ?", filters.outcome);
    if (filters.reasonCode) add("reason_code = ?", filters.reasonCode);
    if (filters.correlationId) add("correlation_id = ?", filters.correlationId);
    if (filters.dateFrom) add("created_at >= ?", filters.dateFrom);
    if (filters.dateTo) add("created_at <= ?", filters.dateTo);
    if (filters.assignedToolIds) {
      params.push(filters.assignedToolIds);
      clauses.push(`tool_id = ANY($${params.length}::uuid[])`);
    }
    params.push(filters.limit);
    const where = clauses.length ? `WHERE ${clauses.join(" AND ")}` : "";
    const result = await this.db.query(
      `SELECT event_id, event_type, created_at, outcome, correlation_id, tool_slug,
        actor_google_sub, actor_email, actor_hd, request_ip_hash, user_agent_hash,
        reason_code, metadata
       FROM audit_logs ${where}
       ORDER BY created_at DESC
       LIMIT $${params.length}`,
      params
    );
    return result.rows;
  }

  async findToolBySlug(slug: string): Promise<Tool | null> {
    const result = await this.db.query("SELECT * FROM tools WHERE slug = $1", [slug]);
    return result.rowCount ? mapTool(result.rows[0]) : null;
  }

  async findToolById(id: string): Promise<Tool | null> {
    const result = await this.db.query("SELECT * FROM tools WHERE id = $1", [id]);
    return result.rowCount ? mapTool(result.rows[0]) : null;
  }

  async listTools(filters: {
    assignedToolIds?: string[];
    search?: string;
    status?: ToolStatus;
    ownerEmail?: string;
    limit: number;
  }): Promise<Tool[]> {
    const clauses: string[] = [];
    const params: unknown[] = [];
    if (filters.assignedToolIds) {
      params.push(filters.assignedToolIds);
      clauses.push(`id = ANY($${params.length}::uuid[])`);
    }
    if (filters.search) {
      params.push(`%${filters.search}%`);
      clauses.push(`(slug ILIKE $${params.length} OR display_name ILIKE $${params.length})`);
    }
    if (filters.status) {
      params.push(filters.status);
      clauses.push(`status = $${params.length}`);
    }
    if (filters.ownerEmail) {
      params.push(filters.ownerEmail);
      clauses.push(`owner_email = $${params.length}`);
    }
    params.push(filters.limit);
    const where = clauses.length ? `WHERE ${clauses.join(" AND ")}` : "";
    const result = await this.db.query(`SELECT * FROM tools ${where} ORDER BY slug ASC LIMIT $${params.length}`, params);
    return result.rows.map(mapTool);
  }

  async createTool(input: {
    slug: string;
    displayName: string;
    description?: string | null;
    allowedReturnUrls: string[];
    ownerEmail?: string | null;
  }): Promise<Tool> {
    const result = await this.db.query(
      `INSERT INTO tools (slug, display_name, description, allowed_return_urls, owner_email)
       VALUES ($1,$2,$3,$4::jsonb,$5)
       RETURNING *`,
      [input.slug, input.displayName, input.description ?? null, JSON.stringify(input.allowedReturnUrls), input.ownerEmail ?? null]
    );
    return mapTool(result.rows[0]);
  }

  async updateTool(
    id: string,
    input: Partial<{
      displayName: string;
      description: string | null;
      status: string;
      allowedReturnUrls: string[];
      ownerEmail: string | null;
    }>
  ): Promise<Tool | null> {
    const current = await this.findToolById(id);
    if (!current) return null;
    const result = await this.db.query(
      `UPDATE tools SET
        display_name = $2,
        description = $3,
        status = $4,
        allowed_return_urls = $5::jsonb,
        owner_email = $6,
        updated_at = now()
       WHERE id = $1
       RETURNING *`,
      [
        id,
        input.displayName ?? current.display_name,
        input.description === undefined ? current.description : input.description,
        input.status ?? current.status,
        JSON.stringify(input.allowedReturnUrls ?? current.allowed_return_urls),
        input.ownerEmail === undefined ? current.owner_email : input.ownerEmail
      ]
    );
    return result.rowCount ? mapTool(result.rows[0]) : null;
  }

  async deleteTool(id: string): Promise<Tool | null> {
    const result = await this.db.query("DELETE FROM tools WHERE id = $1 RETURNING *", [id]);
    return result.rowCount ? mapTool(result.rows[0]) : null;
  }

  async createToolClient(toolId: string, clientId: string, secretHash: string): Promise<ToolClient> {
    const result = await this.db.query(
      `INSERT INTO tool_clients (tool_id, client_id, client_secret_hash)
       VALUES ($1,$2,$3)
       RETURNING *`,
      [toolId, clientId, secretHash]
    );
    return result.rows[0] as ToolClient;
  }

  async disableToolClients(toolId: string): Promise<void> {
    await this.db.query("UPDATE tool_clients SET status = 'disabled' WHERE tool_id = $1", [toolId]);
  }

  async findToolClient(clientId: string): Promise<(ToolClient & { tool_slug: string }) | null> {
    const result = await this.db.query(
      `SELECT c.*, t.slug AS tool_slug
       FROM tool_clients c
       JOIN tools t ON t.id = c.tool_id
       WHERE c.client_id = $1`,
      [clientId]
    );
    return result.rowCount ? (result.rows[0] as ToolClient & { tool_slug: string }) : null;
  }

  async markToolClientUsed(clientId: string): Promise<void> {
    await this.db.query("UPDATE tool_clients SET last_used_at = now() WHERE client_id = $1", [clientId]);
  }

  async listToolClientPublicIds(toolId: string): Promise<Array<{ client_id: string; status: string; created_at: Date; last_used_at: Date | null }>> {
    const result = await this.db.query(
      `SELECT client_id, status, created_at, last_used_at
       FROM tool_clients
       WHERE tool_id = $1
       ORDER BY created_at DESC`,
      [toolId]
    );
    return result.rows as Array<{ client_id: string; status: string; created_at: Date; last_used_at: Date | null }>;
  }

  async replaceToolPermissions(toolId: string, permissions: string[]): Promise<void> {
    await this.db.query("DELETE FROM tool_permissions WHERE tool_id = $1", [toolId]);
    for (const permission of permissions) {
      await this.db.query(
        `INSERT INTO tool_permissions (tool_id, permission_key) VALUES ($1,$2)
         ON CONFLICT (tool_id, permission_key) DO NOTHING`,
        [toolId, permission]
      );
    }
  }

  async listToolPermissions(toolId: string): Promise<string[]> {
    const result = await this.db.query(
      "SELECT permission_key FROM tool_permissions WHERE tool_id = $1 ORDER BY permission_key",
      [toolId]
    );
    return result.rows.map((row) => String(row.permission_key));
  }

  async listToolPermissionCatalog(filters: {
    assignedToolIds?: string[];
    limit: number;
  }): Promise<Array<{ tool_slug: string; tool_name: string; tool_status: string; permission_key: string; permission_description: string | null }>> {
    const clauses: string[] = [];
    const params: unknown[] = [];
    if (filters.assignedToolIds) {
      params.push(filters.assignedToolIds);
      clauses.push(`t.id = ANY($${params.length}::uuid[])`);
    }
    params.push(filters.limit);
    const where = clauses.length ? `WHERE ${clauses.join(" AND ")}` : "";
    const result = await this.db.query(
      `SELECT t.slug AS tool_slug, t.display_name AS tool_name, t.status AS tool_status,
        p.permission_key, p.description AS permission_description
       FROM tools t
       LEFT JOIN tool_permissions p ON p.tool_id = t.id
       ${where}
       ORDER BY t.slug ASC, p.permission_key ASC NULLS LAST
       LIMIT $${params.length}`,
      params
    );
    return result.rows.map((row) => ({
      tool_slug: String(row.tool_slug),
      tool_name: String(row.tool_name),
      tool_status: String(row.tool_status),
      permission_key: row.permission_key === null || row.permission_key === undefined ? "" : String(row.permission_key),
      permission_description:
        row.permission_description === null || row.permission_description === undefined ? null : String(row.permission_description)
    }));
  }

  async upsertUser(input: {
    googleSub: string;
    email: string;
    emailNormalized: string;
    emailVerified: boolean;
    hd: string;
    displayName?: string | null;
    pictureUrl?: string | null;
  }): Promise<User> {
    const result = await this.db.query(
      `INSERT INTO users (google_sub, email, email_normalized, email_verified, hd, display_name, picture_url)
       VALUES ($1,$2,$3,$4,$5,$6,$7)
       ON CONFLICT (google_sub) DO UPDATE SET
        email = EXCLUDED.email,
        email_normalized = EXCLUDED.email_normalized,
        email_verified = EXCLUDED.email_verified,
        hd = EXCLUDED.hd,
        display_name = EXCLUDED.display_name,
        picture_url = EXCLUDED.picture_url,
        last_seen_at = now(),
        updated_at = now()
       RETURNING *`,
      [
        input.googleSub,
        input.email,
        input.emailNormalized,
        input.emailVerified,
        input.hd,
        input.displayName ?? null,
        input.pictureUrl ?? null
      ]
    );
    return result.rows[0] as User;
  }

  async findUserById(id: string): Promise<User | null> {
    const result = await this.db.query("SELECT * FROM users WHERE id = $1", [id]);
    return result.rowCount ? (result.rows[0] as User) : null;
  }

  async findUserByEmail(emailNormalized: string): Promise<User | null> {
    const result = await this.db.query("SELECT * FROM users WHERE email_normalized = $1 ORDER BY last_seen_at DESC LIMIT 1", [
      emailNormalized
    ]);
    return result.rowCount ? (result.rows[0] as User) : null;
  }

  async findUserByGoogleSub(googleSub: string): Promise<User | null> {
    const result = await this.db.query("SELECT * FROM users WHERE google_sub = $1", [googleSub]);
    return result.rowCount ? (result.rows[0] as User) : null;
  }

  async listUsers(filters: { search?: string; status?: UserStatus; limit: number }): Promise<User[]> {
    const clauses: string[] = [];
    const params: unknown[] = [];
    if (filters.search) {
      params.push(`%${filters.search}%`);
      clauses.push(`(email::text ILIKE $${params.length} OR google_sub ILIKE $${params.length})`);
    }
    if (filters.status) {
      params.push(filters.status);
      clauses.push(`status = $${params.length}`);
    }
    params.push(filters.limit);
    const where = clauses.length ? `WHERE ${clauses.join(" AND ")}` : "";
    const result = await this.db.query(`SELECT * FROM users ${where} ORDER BY last_seen_at DESC LIMIT $${params.length}`, params);
    return result.rows as User[];
  }

  async updateUserStatus(id: string, status: UserStatus): Promise<User | null> {
    const result = await this.db.query(
      "UPDATE users SET status = $2, updated_at = now() WHERE id = $1 RETURNING *",
      [id, status]
    );
    return result.rowCount ? (result.rows[0] as User) : null;
  }

  async linkPendingEmailGrants(user: User): Promise<void> {
    await this.db.query(
      `UPDATE authorization_grants
       SET user_id = $1, status = 'active', updated_at = now()
       WHERE user_id IS NULL
        AND email_normalized = $2
        AND status = 'pending_user_link'`,
      [user.id, user.email_normalized]
    );
  }

  async findActiveGrant(toolId: string, userId: string, emailNormalized: string): Promise<AuthorizationGrant | null> {
    const result = await this.db.query(
      `SELECT *
       FROM authorization_grants
       WHERE tool_id = $1
        AND status = 'active'
        AND valid_from <= now()
        AND (valid_until IS NULL OR valid_until > now())
        AND (user_id = $2 OR (user_id IS NULL AND email_normalized = $3) OR email_normalized = $3)
       ORDER BY user_id NULLS LAST, created_at DESC
       LIMIT 1`,
      [toolId, userId, emailNormalized]
    );
    return result.rowCount ? mapGrant(result.rows[0]) : null;
  }

  async createGrant(input: {
    toolId: string;
    userId?: string | null;
    emailNormalized?: string | null;
    role: string;
    permissions: string[];
    status: "active" | "pending_user_link";
    validUntil?: string | null;
    createdByUserId?: string | null;
  }): Promise<AuthorizationGrant> {
    const result = await this.db.query(
      `INSERT INTO authorization_grants
        (tool_id, user_id, email_normalized, role, permissions, status, valid_until, created_by_user_id)
       VALUES ($1,$2,$3,$4,$5::jsonb,$6,$7,$8)
       RETURNING *`,
      [
        input.toolId,
        input.userId ?? null,
        input.emailNormalized ?? null,
        input.role,
        JSON.stringify(input.permissions),
        input.status,
        input.validUntil ?? null,
        input.createdByUserId ?? null
      ]
    );
    return mapGrant(result.rows[0]);
  }

  async listGrants(filters: {
    toolSlug?: string;
    email?: string;
    status?: string;
    assignedToolIds?: string[];
    limit: number;
  }): Promise<Array<Record<string, unknown> & { permissions: string[] }>> {
    const clauses: string[] = [];
    const params: unknown[] = [];
    if (filters.toolSlug) {
      params.push(filters.toolSlug);
      clauses.push(`t.slug = $${params.length}`);
    }
    if (filters.email) {
      params.push(filters.email);
      clauses.push(`(g.email_normalized = $${params.length} OR u.email_normalized = $${params.length})`);
    }
    if (filters.status) {
      params.push(filters.status);
      clauses.push(`g.status = $${params.length}`);
    }
    if (filters.assignedToolIds) {
      params.push(filters.assignedToolIds);
      clauses.push(`g.tool_id = ANY($${params.length}::uuid[])`);
    }
    params.push(filters.limit);
    const where = clauses.length ? `WHERE ${clauses.join(" AND ")}` : "";
    const result = await this.db.query(
      `SELECT g.*, t.slug AS tool_slug, t.display_name AS tool_display_name,
        u.email AS user_email, u.google_sub
       FROM authorization_grants g
       JOIN tools t ON t.id = g.tool_id
       LEFT JOIN users u ON u.id = g.user_id
       ${where}
       ORDER BY g.created_at DESC
       LIMIT $${params.length}`,
      params
    );
    return result.rows.map((row) => ({ ...row, permissions: jsonArray(row.permissions) }));
  }

  async findGrantById(id: string): Promise<AuthorizationGrant | null> {
    const result = await this.db.query("SELECT * FROM authorization_grants WHERE id = $1", [id]);
    return result.rowCount ? mapGrant(result.rows[0]) : null;
  }

  async findGrantForBulkTarget(input: {
    toolId: string;
    userId?: string | null;
    emailNormalized: string;
    role: string;
  }): Promise<AuthorizationGrant | null> {
    const result = await this.db.query(
      `SELECT *
       FROM authorization_grants
       WHERE tool_id = $1
        AND role = $4
        AND status IN ('active', 'pending_user_link')
        AND (
          ($2::uuid IS NOT NULL AND (user_id = $2::uuid OR email_normalized = $3))
          OR ($2::uuid IS NULL AND user_id IS NULL AND email_normalized = $3)
        )
       ORDER BY user_id NULLS LAST, updated_at DESC, created_at DESC
       LIMIT 1`,
      [input.toolId, input.userId ?? null, input.emailNormalized, input.role]
    );
    return result.rowCount ? mapGrant(result.rows[0]) : null;
  }

  async findGrantsForBulkRevoke(input: {
    toolId: string;
    userId?: string | null;
    emailNormalized: string;
    role?: string | null;
  }): Promise<AuthorizationGrant[]> {
    const params: unknown[] = [input.toolId, input.userId ?? null, input.emailNormalized];
    const clauses = [
      "tool_id = $1",
      "status <> 'revoked'",
      `(
        ($2::uuid IS NOT NULL AND (user_id = $2::uuid OR email_normalized = $3))
        OR ($2::uuid IS NULL AND email_normalized = $3)
      )`
    ];
    if (input.role) {
      params.push(input.role);
      clauses.push(`role = $${params.length}`);
    }
    const result = await this.db.query(
      `SELECT * FROM authorization_grants
       WHERE ${clauses.join(" AND ")}
       ORDER BY updated_at DESC, created_at DESC`,
      params
    );
    return result.rows.map(mapGrant);
  }

  async updateGrantTarget(
    id: string,
    input: {
      userId?: string | null;
      emailNormalized?: string | null;
      role: string;
      permissions: string[];
      status: "active" | "pending_user_link";
      validUntil?: string | null;
    }
  ): Promise<AuthorizationGrant | null> {
    const result = await this.db.query(
      `UPDATE authorization_grants SET
        user_id = $2,
        email_normalized = $3,
        role = $4,
        permissions = $5::jsonb,
        status = $6,
        valid_until = $7,
        revoked_by_user_id = NULL,
        revoked_at = NULL,
        updated_at = now()
       WHERE id = $1
       RETURNING *`,
      [
        id,
        input.userId ?? null,
        input.emailNormalized ?? null,
        input.role,
        JSON.stringify(input.permissions),
        input.status,
        input.validUntil ?? null
      ]
    );
    return result.rowCount ? mapGrant(result.rows[0]) : null;
  }

  async updateGrant(
    id: string,
    input: Partial<{ role: string; permissions: string[]; status: string; validUntil: string | null; revokedByUserId: string | null }>
  ): Promise<AuthorizationGrant | null> {
    const current = await this.findGrantById(id);
    if (!current) return null;
    const result = await this.db.query(
      `UPDATE authorization_grants SET
        role = $2,
        permissions = $3::jsonb,
        status = $4,
        valid_until = $5,
        revoked_by_user_id = CASE WHEN $4 = 'revoked' THEN $6 ELSE revoked_by_user_id END,
        revoked_at = CASE WHEN $4 = 'revoked' THEN now() ELSE revoked_at END,
        updated_at = now()
       WHERE id = $1
       RETURNING *`,
      [
        id,
        input.role ?? current.role,
        JSON.stringify(input.permissions ?? current.permissions),
        input.status ?? current.status,
        input.validUntil === undefined ? current.valid_until : input.validUntil,
        input.revokedByUserId ?? null
      ]
    );
    return result.rowCount ? mapGrant(result.rows[0]) : null;
  }

  async createAuthRequest(input: {
    stateHash: string;
    nonceHash: string;
    toolId: string;
    toolSlug: string;
    returnUrl: string;
    toolState: string;
    toolStateHash: string;
    loginHint?: string | null;
    correlationId: string;
    requestIpHash?: string | null;
    userAgentHash?: string | null;
    expiresAt: Date;
  }): Promise<void> {
    await this.db.query(
      `INSERT INTO auth_requests
        (state_hash, nonce_hash, tool_id, tool_slug, return_url, tool_state, tool_state_hash,
         login_hint, correlation_id, request_ip_hash, user_agent_hash, expires_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
      [
        input.stateHash,
        input.nonceHash,
        input.toolId,
        input.toolSlug,
        input.returnUrl,
        input.toolState,
        input.toolStateHash,
        input.loginHint ?? null,
        input.correlationId,
        input.requestIpHash ?? null,
        input.userAgentHash ?? null,
        input.expiresAt
      ]
    );
  }

  async consumeAuthRequest(stateHash: string): Promise<AuthRequest | null> {
    const result = await this.db.query(
      `UPDATE auth_requests
       SET consumed_at = now()
       WHERE state_hash = $1
        AND consumed_at IS NULL
        AND expires_at > now()
       RETURNING *`,
      [stateHash]
    );
    return result.rowCount ? (result.rows[0] as AuthRequest) : null;
  }

  async createSession(input: {
    userId: string;
    toolId: string;
    grantId: string;
    expiresAt: Date;
  }): Promise<Session> {
    const result = await this.db.query(
      `INSERT INTO sessions (user_id, tool_id, grant_id, expires_at)
       VALUES ($1,$2,$3,$4)
       RETURNING *`,
      [input.userId, input.toolId, input.grantId, input.expiresAt]
    );
    return result.rows[0] as Session;
  }

  async findSessionById(id: string): Promise<Session | null> {
    const result = await this.db.query("SELECT * FROM sessions WHERE id = $1", [id]);
    return result.rowCount ? (result.rows[0] as Session) : null;
  }

  async revokeSession(id: string, toolId?: string): Promise<number> {
    const params: unknown[] = [id];
    const toolClause = toolId ? "AND tool_id = $2" : "";
    if (toolId) params.push(toolId);
    const result = await this.db.query(
      `UPDATE sessions SET status = 'revoked', revoked_at = now()
       WHERE id = $1 ${toolClause} AND status = 'active'`,
      params
    );
    return result.rowCount ?? 0;
  }

  async revokeSessionsForGrant(grantId: string): Promise<number> {
    const result = await this.db.query(
      "UPDATE sessions SET status = 'revoked', revoked_at = now() WHERE grant_id = $1 AND status = 'active'",
      [grantId]
    );
    return result.rowCount ?? 0;
  }

  async revokeSessionsForUser(userId: string): Promise<number> {
    const result = await this.db.query(
      "UPDATE sessions SET status = 'revoked', revoked_at = now() WHERE user_id = $1 AND status = 'active'",
      [userId]
    );
    return result.rowCount ?? 0;
  }

  async createOneTimeCode(input: {
    codeHash: string;
    userId: string;
    toolId: string;
    grantId: string;
    sessionId: string;
    returnUrl: string;
    correlationId: string;
    expiresAt: Date;
  }): Promise<void> {
    await this.db.query(
      `INSERT INTO one_time_codes
        (code_hash, user_id, tool_id, grant_id, session_id, return_url, correlation_id, expires_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
      [
        input.codeHash,
        input.userId,
        input.toolId,
        input.grantId,
        input.sessionId,
        input.returnUrl,
        input.correlationId,
        input.expiresAt
      ]
    );
  }

  async consumeOneTimeCode(codeHash: string, toolId: string, redirectUri: string): Promise<OneTimeCode | null> {
    const result = await this.db.query(
      `UPDATE one_time_codes
       SET consumed_at = now()
       WHERE code_hash = $1
        AND tool_id = $2
        AND return_url = $3
        AND consumed_at IS NULL
        AND expires_at > now()
       RETURNING *`,
      [codeHash, toolId, redirectUri]
    );
    return result.rowCount ? (result.rows[0] as OneTimeCode) : null;
  }

  async findOneTimeCodeByHash(codeHash: string): Promise<OneTimeCode | null> {
    const result = await this.db.query("SELECT * FROM one_time_codes WHERE code_hash = $1", [codeHash]);
    return result.rowCount ? (result.rows[0] as OneTimeCode) : null;
  }

  async createRefreshToken(tokenHash: string, sessionId: string, expiresAt: Date): Promise<void> {
    await this.db.query(
      "INSERT INTO refresh_tokens (token_hash, session_id, expires_at) VALUES ($1,$2,$3)",
      [tokenHash, sessionId, expiresAt]
    );
  }

  async revokeRefreshToken(tokenHash: string): Promise<number> {
    const result = await this.db.query(
      "UPDATE refresh_tokens SET status = 'revoked', revoked_at = now() WHERE token_hash = $1 AND status = 'active'",
      [tokenHash]
    );
    return result.rowCount ?? 0;
  }

  async upsertAccessRequest(input: {
    tool: Tool;
    user: User;
    correlationId: string;
    requestIpHash?: string | null;
    userAgentHash?: string | null;
  }): Promise<{ request: AccessRequest; repeated: boolean }> {
    const result = await this.db.query(
      `INSERT INTO access_requests
        (tool_id, tool_slug, user_id, google_sub, email, email_normalized, hd, display_name,
         last_correlation_id, request_ip_hash, user_agent_hash)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
       ON CONFLICT (tool_id, email_normalized) WHERE status = 'pending'
       DO UPDATE SET
        user_id = EXCLUDED.user_id,
        google_sub = EXCLUDED.google_sub,
        email = EXCLUDED.email,
        hd = EXCLUDED.hd,
        display_name = EXCLUDED.display_name,
        attempts_count = access_requests.attempts_count + 1,
        last_seen_at = now(),
        last_correlation_id = EXCLUDED.last_correlation_id,
        request_ip_hash = EXCLUDED.request_ip_hash,
        user_agent_hash = EXCLUDED.user_agent_hash,
        updated_at = now()
       RETURNING *, (attempts_count > 1) AS repeated`,
      [
        input.tool.id,
        input.tool.slug,
        input.user.id,
        input.user.google_sub,
        input.user.email,
        input.user.email_normalized,
        input.user.hd,
        input.user.display_name,
        input.correlationId,
        input.requestIpHash ?? null,
        input.userAgentHash ?? null
      ]
    );
    const row = result.rows[0] as AccessRequest & { repeated: boolean };
    return { request: row, repeated: Boolean(row.repeated) };
  }

  async findRecentReviewedAccessRequest(
    toolId: string,
    emailNormalized: string,
    reopenAfterDays: number
  ): Promise<AccessRequest | null> {
    if (reopenAfterDays <= 0) {
      return null;
    }
    const result = await this.db.query(
      `SELECT *
       FROM access_requests
       WHERE tool_id = $1
        AND email_normalized = $2
        AND status IN ('rejected', 'closed')
        AND reviewed_at IS NOT NULL
        AND reviewed_at > now() - make_interval(days => $3::int)
       ORDER BY reviewed_at DESC
       LIMIT 1`,
      [toolId, emailNormalized, reopenAfterDays]
    );
    return result.rowCount ? (result.rows[0] as AccessRequest) : null;
  }

  async listAccessRequests(filters: {
    status?: string;
    toolSlug?: string;
    email?: string;
    assignedToolIds?: string[];
    limit: number;
  }): Promise<unknown[]> {
    const clauses: string[] = [];
    const params: unknown[] = [];
    if (filters.status) {
      params.push(filters.status);
      clauses.push(`ar.status = $${params.length}`);
    }
    if (filters.toolSlug) {
      params.push(filters.toolSlug);
      clauses.push(`ar.tool_slug = $${params.length}`);
    }
    if (filters.email) {
      params.push(filters.email);
      clauses.push(`ar.email_normalized = $${params.length}`);
    }
    if (filters.assignedToolIds) {
      params.push(filters.assignedToolIds);
      clauses.push(`ar.tool_id = ANY($${params.length}::uuid[])`);
    }
    params.push(filters.limit);
    const where = clauses.length ? `WHERE ${clauses.join(" AND ")}` : "";
    const result = await this.db.query(
      `SELECT ar.*, t.display_name AS tool_display_name
       FROM access_requests ar
       JOIN tools t ON t.id = ar.tool_id
       ${where}
       ORDER BY CASE WHEN ar.status = 'pending' THEN 0 ELSE 1 END, ar.last_seen_at DESC
       LIMIT $${params.length}`,
      params
    );
    return result.rows;
  }

  async findAccessRequestById(id: string, assignedToolIds?: string[]): Promise<AccessRequest | null> {
    const params: unknown[] = [id];
    const scope = assignedToolIds ? "AND tool_id = ANY($2::uuid[])" : "";
    if (assignedToolIds) params.push(assignedToolIds);
    const result = await this.db.query(`SELECT * FROM access_requests WHERE id = $1 ${scope}`, params);
    return result.rowCount ? (result.rows[0] as AccessRequest) : null;
  }

  async reviewAccessRequest(input: {
    requestId: string;
    status: "approved" | "rejected" | "closed";
    actorUserId: string;
    note?: string | null;
    grantId?: string | null;
  }): Promise<AccessRequest | null> {
    const result = await this.db.query(
      `UPDATE access_requests
       SET status = $2,
        reviewed_by_user_id = $3,
        reviewed_at = now(),
        review_note = $4,
        grant_id = $5,
        updated_at = now()
       WHERE id = $1 AND status = 'pending'
       RETURNING *`,
      [input.requestId, input.status, input.actorUserId, input.note ?? null, input.grantId ?? null]
    );
    return result.rowCount ? (result.rows[0] as AccessRequest) : null;
  }

  async listAssignedToolIds(userId: string, email: string): Promise<string[]> {
    const result = await this.db.query(
      `SELECT tool_id FROM admin_tool_assignments WHERE user_id = $1
       UNION
       SELECT id AS tool_id FROM tools WHERE owner_email = $2`,
      [userId, email]
    );
    return result.rows.map((row) => String(row.tool_id));
  }

  async exportBackup(): Promise<Record<string, unknown>> {
    const [users, tools, toolClients, toolPermissions, authorizationGrants, adminToolAssignments, accessRequests] = await Promise.all([
      this.db.query(`SELECT id, google_sub, email::text AS email, email_normalized::text AS email_normalized,
          email_verified, hd, display_name, picture_url, status, first_seen_at, last_seen_at, created_at, updated_at
        FROM users ORDER BY created_at ASC, id ASC`),
      this.db.query(`SELECT id, slug, display_name, description, status, allowed_return_urls, owner_email::text AS owner_email,
          created_at, updated_at
        FROM tools ORDER BY created_at ASC, id ASC`),
      this.db.query(`SELECT id, tool_id, client_id, client_secret_hash, status, created_at, last_used_at
        FROM tool_clients ORDER BY created_at ASC, id ASC`),
      this.db.query(`SELECT id, tool_id, permission_key, description, created_at
        FROM tool_permissions ORDER BY created_at ASC, id ASC`),
      this.db.query(`SELECT id, tool_id, user_id, email_normalized::text AS email_normalized, role, permissions, status,
          valid_from, valid_until, created_by_user_id, revoked_by_user_id, revoked_at, created_at, updated_at
        FROM authorization_grants ORDER BY created_at ASC, id ASC`),
      this.db.query(`SELECT id, user_id, tool_id, created_by_user_id, created_at
        FROM admin_tool_assignments ORDER BY created_at ASC, id ASC`),
      this.db.query(`SELECT id, tool_id, tool_slug, user_id, google_sub, email::text AS email, email_normalized::text AS email_normalized,
          hd, display_name, status, reason_code, attempts_count, first_seen_at, last_seen_at, last_correlation_id,
          request_ip_hash, user_agent_hash, reviewed_by_user_id, reviewed_at, review_note, grant_id, created_at, updated_at
        FROM access_requests ORDER BY created_at ASC, id ASC`)
    ]);
    return {
      users: users.rows,
      tools: tools.rows,
      tool_clients: toolClients.rows,
      tool_permissions: toolPermissions.rows,
      authorization_grants: authorizationGrants.rows,
      admin_tool_assignments: adminToolAssignments.rows,
      access_requests: accessRequests.rows
    };
  }

  async importBackup(data: Record<string, unknown>, options: { replaceExisting: boolean }): Promise<Record<string, number>> {
    const rows = (key: string): Record<string, unknown>[] => {
      const value = data[key];
      if (!Array.isArray(value)) {
        throw new Error(`Invalid backup section ${key}`);
      }
      return value as Record<string, unknown>[];
    };
    const counts = {
      users: rows("users").length,
      tools: rows("tools").length,
      tool_clients: rows("tool_clients").length,
      tool_permissions: rows("tool_permissions").length,
      authorization_grants: rows("authorization_grants").length,
      admin_tool_assignments: rows("admin_tool_assignments").length,
      access_requests: rows("access_requests").length
    };

    await this.db.transaction(async (tx) => {
      const query = (sql: string, params: unknown[] = []) => tx.query(sql, params);
      if (options.replaceExisting) {
        await query("DELETE FROM audit_logs");
        await query("DELETE FROM refresh_tokens");
        await query("DELETE FROM one_time_codes");
        await query("DELETE FROM sessions");
        await query("DELETE FROM auth_requests");
        await query("DELETE FROM access_requests");
        await query("DELETE FROM admin_tool_assignments");
        await query("DELETE FROM authorization_grants");
        await query("DELETE FROM tool_permissions");
        await query("DELETE FROM tool_clients");
        await query("DELETE FROM tools");
        await query("DELETE FROM users");
      }

      for (const row of rows("users")) {
        await query(
          `INSERT INTO users (id, google_sub, email, email_normalized, email_verified, hd, display_name, picture_url, status,
             first_seen_at, last_seen_at, created_at, updated_at)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
           ON CONFLICT (id) DO UPDATE SET
             google_sub = EXCLUDED.google_sub,
             email = EXCLUDED.email,
             email_normalized = EXCLUDED.email_normalized,
             email_verified = EXCLUDED.email_verified,
             hd = EXCLUDED.hd,
             display_name = EXCLUDED.display_name,
             picture_url = EXCLUDED.picture_url,
             status = EXCLUDED.status,
             first_seen_at = EXCLUDED.first_seen_at,
             last_seen_at = EXCLUDED.last_seen_at,
             created_at = EXCLUDED.created_at,
             updated_at = EXCLUDED.updated_at`,
          [row.id, row.google_sub, row.email, row.email_normalized, row.email_verified, row.hd, row.display_name ?? null, row.picture_url ?? null, row.status, row.first_seen_at, row.last_seen_at, row.created_at, row.updated_at]
        );
      }

      for (const row of rows("tools")) {
        await query(
          `INSERT INTO tools (id, slug, display_name, description, status, allowed_return_urls, owner_email, created_at, updated_at)
           VALUES ($1,$2,$3,$4,$5,$6::jsonb,$7,$8,$9)
           ON CONFLICT (id) DO UPDATE SET
             slug = EXCLUDED.slug,
             display_name = EXCLUDED.display_name,
             description = EXCLUDED.description,
             status = EXCLUDED.status,
             allowed_return_urls = EXCLUDED.allowed_return_urls,
             owner_email = EXCLUDED.owner_email,
             created_at = EXCLUDED.created_at,
             updated_at = EXCLUDED.updated_at`,
          [row.id, row.slug, row.display_name, row.description ?? null, row.status, JSON.stringify(row.allowed_return_urls ?? []), row.owner_email ?? null, row.created_at, row.updated_at]
        );
      }

      for (const row of rows("tool_clients")) {
        await query(
          `INSERT INTO tool_clients (id, tool_id, client_id, client_secret_hash, status, created_at, last_used_at)
           VALUES ($1,$2,$3,$4,$5,$6,$7)
           ON CONFLICT (id) DO UPDATE SET
             tool_id = EXCLUDED.tool_id,
             client_id = EXCLUDED.client_id,
             client_secret_hash = EXCLUDED.client_secret_hash,
             status = EXCLUDED.status,
             created_at = EXCLUDED.created_at,
             last_used_at = EXCLUDED.last_used_at`,
          [row.id, row.tool_id, row.client_id, row.client_secret_hash, row.status, row.created_at, row.last_used_at ?? null]
        );
      }

      for (const row of rows("tool_permissions")) {
        await query(
          `INSERT INTO tool_permissions (id, tool_id, permission_key, description, created_at)
           VALUES ($1,$2,$3,$4,$5)
           ON CONFLICT (id) DO UPDATE SET
             tool_id = EXCLUDED.tool_id,
             permission_key = EXCLUDED.permission_key,
             description = EXCLUDED.description,
             created_at = EXCLUDED.created_at`,
          [row.id, row.tool_id, row.permission_key, row.description ?? null, row.created_at]
        );
      }

      for (const row of rows("authorization_grants")) {
        await query(
          `INSERT INTO authorization_grants (id, tool_id, user_id, email_normalized, role, permissions, status, valid_from, valid_until,
             created_by_user_id, revoked_by_user_id, revoked_at, created_at, updated_at)
           VALUES ($1,$2,$3,$4,$5,$6::jsonb,$7,$8,$9,$10,$11,$12,$13,$14)
           ON CONFLICT (id) DO UPDATE SET
             tool_id = EXCLUDED.tool_id,
             user_id = EXCLUDED.user_id,
             email_normalized = EXCLUDED.email_normalized,
             role = EXCLUDED.role,
             permissions = EXCLUDED.permissions,
             status = EXCLUDED.status,
             valid_from = EXCLUDED.valid_from,
             valid_until = EXCLUDED.valid_until,
             created_by_user_id = EXCLUDED.created_by_user_id,
             revoked_by_user_id = EXCLUDED.revoked_by_user_id,
             revoked_at = EXCLUDED.revoked_at,
             created_at = EXCLUDED.created_at,
             updated_at = EXCLUDED.updated_at`,
          [row.id, row.tool_id, row.user_id ?? null, row.email_normalized ?? null, row.role, JSON.stringify(row.permissions ?? []), row.status, row.valid_from, row.valid_until ?? null, row.created_by_user_id ?? null, row.revoked_by_user_id ?? null, row.revoked_at ?? null, row.created_at, row.updated_at]
        );
      }

      for (const row of rows("admin_tool_assignments")) {
        await query(
          `INSERT INTO admin_tool_assignments (id, user_id, tool_id, created_by_user_id, created_at)
           VALUES ($1,$2,$3,$4,$5)
           ON CONFLICT (id) DO UPDATE SET
             user_id = EXCLUDED.user_id,
             tool_id = EXCLUDED.tool_id,
             created_by_user_id = EXCLUDED.created_by_user_id,
             created_at = EXCLUDED.created_at`,
          [row.id, row.user_id, row.tool_id, row.created_by_user_id ?? null, row.created_at]
        );
      }

      for (const row of rows("access_requests")) {
        await query(
          `INSERT INTO access_requests (id, tool_id, tool_slug, user_id, google_sub, email, email_normalized, hd, display_name, status,
             reason_code, attempts_count, first_seen_at, last_seen_at, last_correlation_id, request_ip_hash, user_agent_hash,
             reviewed_by_user_id, reviewed_at, review_note, grant_id, created_at, updated_at)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23)
           ON CONFLICT (id) DO UPDATE SET
             tool_id = EXCLUDED.tool_id,
             tool_slug = EXCLUDED.tool_slug,
             user_id = EXCLUDED.user_id,
             google_sub = EXCLUDED.google_sub,
             email = EXCLUDED.email,
             email_normalized = EXCLUDED.email_normalized,
             hd = EXCLUDED.hd,
             display_name = EXCLUDED.display_name,
             status = EXCLUDED.status,
             reason_code = EXCLUDED.reason_code,
             attempts_count = EXCLUDED.attempts_count,
             first_seen_at = EXCLUDED.first_seen_at,
             last_seen_at = EXCLUDED.last_seen_at,
             last_correlation_id = EXCLUDED.last_correlation_id,
             request_ip_hash = EXCLUDED.request_ip_hash,
             user_agent_hash = EXCLUDED.user_agent_hash,
             reviewed_by_user_id = EXCLUDED.reviewed_by_user_id,
             reviewed_at = EXCLUDED.reviewed_at,
             review_note = EXCLUDED.review_note,
             grant_id = EXCLUDED.grant_id,
             created_at = EXCLUDED.created_at,
             updated_at = EXCLUDED.updated_at`,
          [row.id, row.tool_id, row.tool_slug, row.user_id ?? null, row.google_sub ?? null, row.email, row.email_normalized, row.hd, row.display_name ?? null, row.status, row.reason_code, row.attempts_count, row.first_seen_at, row.last_seen_at, row.last_correlation_id, row.request_ip_hash ?? null, row.user_agent_hash ?? null, row.reviewed_by_user_id ?? null, row.reviewed_at ?? null, row.review_note ?? null, row.grant_id ?? null, row.created_at, row.updated_at]
        );
      }
    });

    return counts;
  }

}
