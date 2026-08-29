import type { Db } from "./db.js";
import type {
  AccessRequest,
  AuditEventInput,
  AuthRequest,
  AuthorizationGrant,
  OneTimeCode,
  RefreshToken,
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

type BackupRow = Record<string, unknown>;

const LEGACY_BACKUP_SECTIONS = [
  "users",
  "tools",
  "tool_clients",
  "tool_permissions",
  "authorization_grants",
  "admin_tool_assignments",
  "access_requests"
] as const;

const OAUTH_BACKUP_SECTIONS = [
  "oauth_clients",
  "oauth_client_credentials",
  "oauth_client_redirect_uris",
  "oauth_resources",
  "oauth_resource_credentials",
  "oauth_resource_entitlement_bindings",
  "oauth_scopes",
  "oauth_resource_scopes",
  "oauth_client_resource_scopes",
  "oauth_signing_keys",
  "oauth_authorization_transactions",
  "oauth_authorizations",
  "oauth_authorization_codes",
  "oauth_sessions",
  "oauth_refresh_token_families",
  "oauth_refresh_tokens",
  "oauth_revocations"
] as const;

type OAuthBackupSection = (typeof OAUTH_BACKUP_SECTIONS)[number];

function backupRows(data: Record<string, unknown>, key: string): BackupRow[] {
  const value = data[key];
  if (!Array.isArray(value)) {
    throw new Error(`Invalid backup section ${key}`);
  }
  return value as BackupRow[];
}

function oauthBackupRows(data: Record<string, unknown>): Record<OAuthBackupSection, BackupRow[]> | null {
  const present = OAUTH_BACKUP_SECTIONS.filter((key) => Object.prototype.hasOwnProperty.call(data, key));
  if (present.length === 0) {
    return null;
  }
  if (present.length !== OAUTH_BACKUP_SECTIONS.length) {
    throw new Error("Invalid backup OAuth section set");
  }
  return Object.fromEntries(OAUTH_BACKUP_SECTIONS.map((key) => [key, backupRows(data, key)])) as Record<
    OAuthBackupSection,
    BackupRow[]
  >;
}

function requiredRowId(row: BackupRow, field: string, section: string): string {
  const value = row[field];
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`Invalid ${section} ${field}`);
  }
  return value;
}

function validateCredentialLineage(rows: BackupRow[], section: string, ownerField: string): BackupRow[] {
  const byId = new Map<string, BackupRow>();
  for (const row of rows) {
    const id = requiredRowId(row, "id", section);
    if (byId.has(id)) {
      throw new Error(`Invalid ${section} duplicate id`);
    }
    byId.set(id, row);
  }

  for (const row of rows) {
    const id = requiredRowId(row, "id", section);
    const parentId = row.rotation_parent_id;
    if (parentId === null || parentId === undefined) {
      continue;
    }
    if (typeof parentId !== "string" || parentId === id) {
      throw new Error(`Invalid ${section} rotation lineage`);
    }
    const parent = byId.get(parentId);
    if (!parent || parent[ownerField] !== row[ownerField]) {
      throw new Error(`Invalid ${section} rotation lineage`);
    }
  }

  return [...rows].sort((left, right) => {
    const created = String(left.created_at ?? "").localeCompare(String(right.created_at ?? ""));
    return created || String(left.id).localeCompare(String(right.id));
  });
}

function validateAndSortRefreshLineage(families: BackupRow[], tokens: BackupRow[]): BackupRow[] {
  const familyById = new Map<string, BackupRow>();
  for (const family of families) {
    const familyId = requiredRowId(family, "id", "oauth_refresh_token_families");
    if (familyById.has(familyId) || !Number.isInteger(family.current_generation) || Number(family.current_generation) < 0) {
      throw new Error("Invalid oauth_refresh_token_families lineage");
    }
    familyById.set(familyId, family);
  }

  const tokenById = new Map<string, BackupRow>();
  const generationByFamily = new Map<string, Map<number, BackupRow>>();
  for (const token of tokens) {
    const tokenId = requiredRowId(token, "id", "oauth_refresh_tokens");
    const familyId = requiredRowId(token, "oauth_refresh_token_family_id", "oauth_refresh_tokens");
    const generation = token.generation;
    if (tokenById.has(tokenId) || !familyById.has(familyId) || !Number.isInteger(generation) || Number(generation) < 0) {
      throw new Error("Invalid oauth_refresh_tokens lineage");
    }
    const familyGenerations = generationByFamily.get(familyId) ?? new Map<number, BackupRow>();
    if (familyGenerations.has(Number(generation))) {
      throw new Error("Invalid oauth_refresh_tokens lineage");
    }
    familyGenerations.set(Number(generation), token);
    generationByFamily.set(familyId, familyGenerations);
    tokenById.set(tokenId, token);
  }

  for (const [familyId, family] of familyById) {
    const familyGenerations = generationByFamily.get(familyId);
    const currentGeneration = Number(family.current_generation);
    if (!familyGenerations || !familyGenerations.has(0) || !familyGenerations.has(currentGeneration)) {
      throw new Error("Invalid oauth_refresh_tokens lineage");
    }
    for (let generation = 0; generation <= currentGeneration; generation += 1) {
      if (!familyGenerations.has(generation)) {
        throw new Error("Invalid oauth_refresh_tokens lineage");
      }
    }
  }

  for (const token of tokens) {
    const tokenId = String(token.id);
    const familyId = String(token.oauth_refresh_token_family_id);
    const generation = Number(token.generation);
    const parentId = token.parent_refresh_token_id;
    if (generation === 0) {
      if (parentId !== null && parentId !== undefined) {
        throw new Error("Invalid oauth_refresh_tokens lineage");
      }
      continue;
    }
    if (typeof parentId !== "string" || parentId === tokenId) {
      throw new Error("Invalid oauth_refresh_tokens lineage");
    }
    const parent = tokenById.get(parentId);
    if (!parent || parent.oauth_refresh_token_family_id !== familyId || Number(parent.generation) !== generation - 1) {
      throw new Error("Invalid oauth_refresh_tokens lineage");
    }
  }

  return [...tokens].sort((left, right) => {
    const family = String(left.oauth_refresh_token_family_id).localeCompare(String(right.oauth_refresh_token_family_id));
    const generation = Number(left.generation) - Number(right.generation);
    return family || generation || String(left.id).localeCompare(String(right.id));
  });
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

  async extendSession(id: string, toolId: string, expiresAt: Date): Promise<Session | null> {
    const result = await this.db.query(
      `UPDATE sessions
       SET expires_at = $3, last_seen_at = now()
       WHERE id = $1
        AND tool_id = $2
        AND status = 'active'
        AND expires_at > now()
       RETURNING *`,
      [id, toolId, expiresAt]
    );
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

  async findRefreshTokenByHash(tokenHash: string): Promise<RefreshToken | null> {
    const result = await this.db.query("SELECT * FROM refresh_tokens WHERE token_hash = $1", [tokenHash]);
    return result.rowCount ? (result.rows[0] as RefreshToken) : null;
  }

  async consumeRefreshToken(tokenHash: string): Promise<RefreshToken | null> {
    const result = await this.db.query(
      `UPDATE refresh_tokens
       SET status = 'revoked', revoked_at = now()
       WHERE token_hash = $1
        AND status = 'active'
        AND expires_at > now()
       RETURNING *`,
      [tokenHash]
    );
    return result.rowCount ? (result.rows[0] as RefreshToken) : null;
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
    const [
      users,
      tools,
      toolClients,
      toolPermissions,
      authorizationGrants,
      adminToolAssignments,
      accessRequests,
      oauthClients,
      oauthClientCredentials,
      oauthClientRedirectUris,
      oauthResources,
      oauthResourceCredentials,
      oauthResourceEntitlementBindings,
      oauthScopes,
      oauthResourceScopes,
      oauthClientResourceScopes,
      oauthSigningKeys,
      oauthAuthorizationTransactions,
      oauthAuthorizations,
      oauthAuthorizationCodes,
      oauthSessions,
      oauthRefreshTokenFamilies,
      oauthRefreshTokens,
      oauthRevocations
    ] = await Promise.all([
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
        FROM access_requests ORDER BY created_at ASC, id ASC`),
      this.db.query(`SELECT id, client_id, client_name, client_type, token_endpoint_auth_method, grant_types, status,
          owner_team, owner_contact, created_at, updated_at
        FROM oauth_clients ORDER BY created_at ASC, id ASC`),
      this.db.query(`SELECT id, oauth_client_id, secret_hash, status, created_at, activated_at, expires_at, retired_at,
          rotation_parent_id
        FROM oauth_client_credentials ORDER BY created_at ASC, id ASC`),
      this.db.query(`SELECT id, oauth_client_id, redirect_uri, created_at
        FROM oauth_client_redirect_uris ORDER BY created_at ASC, id ASC`),
      this.db.query(`SELECT id, resource_id, display_name, status, owner_team, owner_contact, audience_policy,
          protected_resource_metadata_url, created_at, updated_at
        FROM oauth_resources ORDER BY created_at ASC, id ASC`),
      this.db.query(`SELECT id, oauth_resource_id, credential_id, secret_hash, authentication_method, status, created_at,
          activated_at, rotated_at, expires_at, retired_at, rotation_parent_id
        FROM oauth_resource_credentials ORDER BY created_at ASC, id ASC`),
      this.db.query(`SELECT id, oauth_resource_id, binding_type, legacy_tool_id, status, created_at, disabled_at
        FROM oauth_resource_entitlement_bindings ORDER BY created_at ASC, id ASC`),
      this.db.query(`SELECT id, scope, description, status, created_at, updated_at
        FROM oauth_scopes ORDER BY created_at ASC, id ASC`),
      this.db.query(`SELECT id, oauth_resource_id, oauth_scope_id, legacy_permission_key, status, created_at, updated_at
        FROM oauth_resource_scopes ORDER BY created_at ASC, id ASC`),
      this.db.query(`SELECT id, oauth_client_id, oauth_resource_id, oauth_scope_id, status, created_at
        FROM oauth_client_resource_scopes ORDER BY created_at ASC, id ASC`),
      this.db.query(`SELECT id, key_namespace, kid, algorithm, public_jwk, public_key_fingerprint_sha256,
          protected_private_key_ref, status, published_at, activates_at, last_signed_at, retire_after, retired_at, created_at
        FROM oauth_signing_keys ORDER BY created_at ASC, id ASC`),
      this.db.query(`SELECT id, oauth_client_id, oauth_resource_id, redirect_uri, requested_scopes, code_challenge,
          code_challenge_method, protected_downstream_state, upstream_state_hash, upstream_nonce_hash, correlation_id,
          status, expires_at, claimed_at, completed_at, created_at
        FROM oauth_authorization_transactions ORDER BY created_at ASC, id ASC`),
      this.db.query(`SELECT id, oauth_authorization_transaction_id, user_id, oauth_client_id, oauth_resource_id,
          granted_scopes, legacy_authorization_grant_id, correlation_id, status, created_at, updated_at
        FROM oauth_authorizations ORDER BY created_at ASC, id ASC`),
      this.db.query(`SELECT id, code_hash, oauth_authorization_transaction_id, oauth_authorization_id, oauth_client_id,
          oauth_resource_id, user_id, redirect_uri, granted_scopes, code_challenge, code_challenge_method, correlation_id,
          issued_at, expires_at, consumed_at
        FROM oauth_authorization_codes ORDER BY issued_at ASC, id ASC`),
      this.db.query(`SELECT id, oauth_authorization_id, user_id, oauth_client_id, oauth_resource_id, status,
          correlation_id, issued_at, last_activity_at, idle_expires_at, revoked_at, revocation_reason
        FROM oauth_sessions ORDER BY issued_at ASC, id ASC`),
      this.db.query(`SELECT id, oauth_authorization_id, oauth_session_id, user_id, oauth_client_id, oauth_resource_id,
          scope_ceiling, current_scopes, current_generation, status, replay_detected_at, revoked_at, revocation_reason, created_at
        FROM oauth_refresh_token_families ORDER BY created_at ASC, id ASC`),
      this.db.query(`SELECT id, oauth_refresh_token_family_id, token_hash, generation, parent_refresh_token_id, scopes,
          status, issued_at, expires_at, consumed_at, revoked_at
        FROM oauth_refresh_tokens ORDER BY oauth_refresh_token_family_id ASC, generation ASC, id ASC`),
      this.db.query(`SELECT id, target_type, target_id, oauth_client_id, oauth_resource_id, reason_code, revoked_at, expires_at
        FROM oauth_revocations ORDER BY revoked_at ASC, target_type ASC, target_id ASC, id ASC`)
    ]);
    return {
      users: users.rows,
      tools: tools.rows,
      tool_clients: toolClients.rows,
      tool_permissions: toolPermissions.rows,
      authorization_grants: authorizationGrants.rows,
      admin_tool_assignments: adminToolAssignments.rows,
      access_requests: accessRequests.rows,
      oauth_clients: oauthClients.rows,
      oauth_client_credentials: oauthClientCredentials.rows,
      oauth_client_redirect_uris: oauthClientRedirectUris.rows,
      oauth_resources: oauthResources.rows,
      oauth_resource_credentials: oauthResourceCredentials.rows,
      oauth_resource_entitlement_bindings: oauthResourceEntitlementBindings.rows,
      oauth_scopes: oauthScopes.rows,
      oauth_resource_scopes: oauthResourceScopes.rows,
      oauth_client_resource_scopes: oauthClientResourceScopes.rows,
      oauth_signing_keys: oauthSigningKeys.rows,
      oauth_authorization_transactions: oauthAuthorizationTransactions.rows,
      oauth_authorizations: oauthAuthorizations.rows,
      oauth_authorization_codes: oauthAuthorizationCodes.rows,
      oauth_sessions: oauthSessions.rows,
      oauth_refresh_token_families: oauthRefreshTokenFamilies.rows,
      oauth_refresh_tokens: oauthRefreshTokens.rows,
      oauth_revocations: oauthRevocations.rows
    };
  }

  async importBackup(data: Record<string, unknown>, options: { replaceExisting: boolean }): Promise<Record<string, number>> {
    const legacyRows = Object.fromEntries(LEGACY_BACKUP_SECTIONS.map((key) => [key, backupRows(data, key)])) as Record<
      (typeof LEGACY_BACKUP_SECTIONS)[number],
      BackupRow[]
    >;
    const oauthRows = oauthBackupRows(data);
    const clientCredentials = oauthRows
      ? validateCredentialLineage(oauthRows.oauth_client_credentials, "oauth_client_credentials", "oauth_client_id")
      : [];
    const resourceCredentials = oauthRows
      ? validateCredentialLineage(oauthRows.oauth_resource_credentials, "oauth_resource_credentials", "oauth_resource_id")
      : [];
    const refreshTokens = oauthRows
      ? validateAndSortRefreshLineage(oauthRows.oauth_refresh_token_families, oauthRows.oauth_refresh_tokens)
      : [];
    const counts: Record<string, number> = Object.fromEntries(
      LEGACY_BACKUP_SECTIONS.map((key) => [key, legacyRows[key].length])
    );
    if (oauthRows) {
      for (const key of OAUTH_BACKUP_SECTIONS) {
        counts[key] = oauthRows[key].length;
      }
    }

    await this.db.transaction(async (tx) => {
      const query = (sql: string, params: unknown[] = []) => tx.query(sql, params);
      const upsert = async (
        table: string,
        sectionRows: BackupRow[],
        columns: ReadonlyArray<{ name: string; cast?: "jsonb" }>
      ): Promise<void> => {
        const names = columns.map((column) => column.name);
        const placeholders = columns.map((column, index) => `$${index + 1}${column.cast ? `::${column.cast}` : ""}`);
        const updates = names.slice(1).map((name) => `${name} = EXCLUDED.${name}`);
        const sql = `INSERT INTO ${table} (${names.join(", ")}) VALUES (${placeholders.join(", ")}) ON CONFLICT (id) DO UPDATE SET ${updates.join(", ")}`;
        for (const row of sectionRows) {
          const params = columns.map((column) => {
            const value = row[column.name];
            return column.cast === "jsonb" && value !== null && value !== undefined ? JSON.stringify(value) : value ?? null;
          });
          await query(sql, params);
        }
      };

      if (options.replaceExisting) {
        await query("DELETE FROM oauth_revocations");
        await query("DELETE FROM oauth_refresh_tokens");
        await query("DELETE FROM oauth_refresh_token_families");
        await query("DELETE FROM oauth_sessions");
        await query("DELETE FROM oauth_authorization_codes");
        await query("DELETE FROM oauth_authorizations");
        await query("DELETE FROM oauth_authorization_transactions");
        await query("DELETE FROM oauth_client_resource_scopes");
        await query("DELETE FROM oauth_resource_scopes");
        await query("DELETE FROM oauth_resource_entitlement_bindings");
        await query("DELETE FROM oauth_resource_credentials");
        await query("DELETE FROM oauth_client_redirect_uris");
        await query("DELETE FROM oauth_client_credentials");
        await query("DELETE FROM oauth_signing_keys");
        await query("DELETE FROM oauth_scopes");
        await query("DELETE FROM oauth_resources");
        await query("DELETE FROM oauth_clients");
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

      await upsert("users", legacyRows.users, [
        { name: "id" }, { name: "google_sub" }, { name: "email" }, { name: "email_normalized" },
        { name: "email_verified" }, { name: "hd" }, { name: "display_name" }, { name: "picture_url" },
        { name: "status" }, { name: "first_seen_at" }, { name: "last_seen_at" }, { name: "created_at" }, { name: "updated_at" }
      ]);
      await upsert("tools", legacyRows.tools, [
        { name: "id" }, { name: "slug" }, { name: "display_name" }, { name: "description" }, { name: "status" },
        { name: "allowed_return_urls", cast: "jsonb" }, { name: "owner_email" }, { name: "created_at" }, { name: "updated_at" }
      ]);
      await upsert("tool_clients", legacyRows.tool_clients, [
        { name: "id" }, { name: "tool_id" }, { name: "client_id" }, { name: "client_secret_hash" },
        { name: "status" }, { name: "created_at" }, { name: "last_used_at" }
      ]);
      await upsert("tool_permissions", legacyRows.tool_permissions, [
        { name: "id" }, { name: "tool_id" }, { name: "permission_key" }, { name: "description" }, { name: "created_at" }
      ]);
      await upsert("authorization_grants", legacyRows.authorization_grants, [
        { name: "id" }, { name: "tool_id" }, { name: "user_id" }, { name: "email_normalized" }, { name: "role" },
        { name: "permissions", cast: "jsonb" }, { name: "status" }, { name: "valid_from" }, { name: "valid_until" },
        { name: "created_by_user_id" }, { name: "revoked_by_user_id" }, { name: "revoked_at" },
        { name: "created_at" }, { name: "updated_at" }
      ]);
      await upsert("admin_tool_assignments", legacyRows.admin_tool_assignments, [
        { name: "id" }, { name: "user_id" }, { name: "tool_id" }, { name: "created_by_user_id" }, { name: "created_at" }
      ]);
      await upsert("access_requests", legacyRows.access_requests, [
        { name: "id" }, { name: "tool_id" }, { name: "tool_slug" }, { name: "user_id" }, { name: "google_sub" },
        { name: "email" }, { name: "email_normalized" }, { name: "hd" }, { name: "display_name" }, { name: "status" },
        { name: "reason_code" }, { name: "attempts_count" }, { name: "first_seen_at" }, { name: "last_seen_at" },
        { name: "last_correlation_id" }, { name: "request_ip_hash" }, { name: "user_agent_hash" },
        { name: "reviewed_by_user_id" }, { name: "reviewed_at" }, { name: "review_note" }, { name: "grant_id" },
        { name: "created_at" }, { name: "updated_at" }
      ]);

      if (!oauthRows) {
        return;
      }

      await upsert("oauth_clients", oauthRows.oauth_clients, [
        { name: "id" }, { name: "client_id" }, { name: "client_name" }, { name: "client_type" },
        { name: "token_endpoint_auth_method" }, { name: "grant_types" }, { name: "status" }, { name: "owner_team" },
        { name: "owner_contact" }, { name: "created_at" }, { name: "updated_at" }
      ]);
      await upsert("oauth_resources", oauthRows.oauth_resources, [
        { name: "id" }, { name: "resource_id" }, { name: "display_name" }, { name: "status" }, { name: "owner_team" },
        { name: "owner_contact" }, { name: "audience_policy" }, { name: "protected_resource_metadata_url" },
        { name: "created_at" }, { name: "updated_at" }
      ]);
      await upsert("oauth_scopes", oauthRows.oauth_scopes, [
        { name: "id" }, { name: "scope" }, { name: "description" }, { name: "status" }, { name: "created_at" }, { name: "updated_at" }
      ]);
      await upsert("oauth_signing_keys", oauthRows.oauth_signing_keys, [
        { name: "id" }, { name: "key_namespace" }, { name: "kid" }, { name: "algorithm" },
        { name: "public_jwk", cast: "jsonb" }, { name: "public_key_fingerprint_sha256" },
        { name: "protected_private_key_ref" }, { name: "status" }, { name: "published_at" }, { name: "activates_at" },
        { name: "last_signed_at" }, { name: "retire_after" }, { name: "retired_at" }, { name: "created_at" }
      ]);
      await upsert("oauth_client_credentials", clientCredentials, [
        { name: "id" }, { name: "oauth_client_id" }, { name: "secret_hash" }, { name: "status" },
        { name: "created_at" }, { name: "activated_at" }, { name: "expires_at" }, { name: "retired_at" }
      ]);
      for (const row of clientCredentials) {
        await query("UPDATE oauth_client_credentials SET rotation_parent_id = $2 WHERE id = $1", [row.id, row.rotation_parent_id ?? null]);
      }
      await upsert("oauth_resource_credentials", resourceCredentials, [
        { name: "id" }, { name: "oauth_resource_id" }, { name: "credential_id" }, { name: "secret_hash" },
        { name: "authentication_method" }, { name: "status" }, { name: "created_at" }, { name: "activated_at" },
        { name: "rotated_at" }, { name: "expires_at" }, { name: "retired_at" }
      ]);
      for (const row of resourceCredentials) {
        await query("UPDATE oauth_resource_credentials SET rotation_parent_id = $2 WHERE id = $1", [row.id, row.rotation_parent_id ?? null]);
      }
      await upsert("oauth_client_redirect_uris", oauthRows.oauth_client_redirect_uris, [
        { name: "id" }, { name: "oauth_client_id" }, { name: "redirect_uri" }, { name: "created_at" }
      ]);
      await upsert("oauth_resource_entitlement_bindings", oauthRows.oauth_resource_entitlement_bindings, [
        { name: "id" }, { name: "oauth_resource_id" }, { name: "binding_type" }, { name: "legacy_tool_id" },
        { name: "status" }, { name: "created_at" }, { name: "disabled_at" }
      ]);
      await upsert("oauth_resource_scopes", oauthRows.oauth_resource_scopes, [
        { name: "id" }, { name: "oauth_resource_id" }, { name: "oauth_scope_id" }, { name: "legacy_permission_key" },
        { name: "status" }, { name: "created_at" }, { name: "updated_at" }
      ]);
      await upsert("oauth_client_resource_scopes", oauthRows.oauth_client_resource_scopes, [
        { name: "id" }, { name: "oauth_client_id" }, { name: "oauth_resource_id" }, { name: "oauth_scope_id" },
        { name: "status" }, { name: "created_at" }
      ]);
      await upsert("oauth_authorization_transactions", oauthRows.oauth_authorization_transactions, [
        { name: "id" }, { name: "oauth_client_id" }, { name: "oauth_resource_id" }, { name: "redirect_uri" },
        { name: "requested_scopes" }, { name: "code_challenge" }, { name: "code_challenge_method" },
        { name: "protected_downstream_state", cast: "jsonb" }, { name: "upstream_state_hash" },
        { name: "upstream_nonce_hash" }, { name: "correlation_id" }, { name: "status" }, { name: "expires_at" },
        { name: "claimed_at" }, { name: "completed_at" }, { name: "created_at" }
      ]);
      await upsert("oauth_authorizations", oauthRows.oauth_authorizations, [
        { name: "id" }, { name: "oauth_authorization_transaction_id" }, { name: "user_id" }, { name: "oauth_client_id" },
        { name: "oauth_resource_id" }, { name: "granted_scopes" }, { name: "legacy_authorization_grant_id" },
        { name: "correlation_id" }, { name: "status" }, { name: "created_at" }, { name: "updated_at" }
      ]);
      await upsert("oauth_authorization_codes", oauthRows.oauth_authorization_codes, [
        { name: "id" }, { name: "code_hash" }, { name: "oauth_authorization_transaction_id" },
        { name: "oauth_authorization_id" }, { name: "oauth_client_id" }, { name: "oauth_resource_id" }, { name: "user_id" },
        { name: "redirect_uri" }, { name: "granted_scopes" }, { name: "code_challenge" },
        { name: "code_challenge_method" }, { name: "correlation_id" }, { name: "issued_at" },
        { name: "expires_at" }, { name: "consumed_at" }
      ]);
      await upsert("oauth_sessions", oauthRows.oauth_sessions, [
        { name: "id" }, { name: "oauth_authorization_id" }, { name: "user_id" }, { name: "oauth_client_id" },
        { name: "oauth_resource_id" }, { name: "status" }, { name: "correlation_id" }, { name: "issued_at" },
        { name: "last_activity_at" }, { name: "idle_expires_at" }, { name: "revoked_at" }, { name: "revocation_reason" }
      ]);
      await upsert("oauth_refresh_token_families", oauthRows.oauth_refresh_token_families, [
        { name: "id" }, { name: "oauth_authorization_id" }, { name: "oauth_session_id" }, { name: "user_id" },
        { name: "oauth_client_id" }, { name: "oauth_resource_id" }, { name: "scope_ceiling" }, { name: "current_scopes" },
        { name: "current_generation" }, { name: "status" }, { name: "replay_detected_at" }, { name: "revoked_at" },
        { name: "revocation_reason" }, { name: "created_at" }
      ]);
      await upsert("oauth_refresh_tokens", refreshTokens, [
        { name: "id" }, { name: "oauth_refresh_token_family_id" }, { name: "token_hash" }, { name: "generation" },
        { name: "parent_refresh_token_id" }, { name: "scopes" }, { name: "status" }, { name: "issued_at" },
        { name: "expires_at" }, { name: "consumed_at" }, { name: "revoked_at" }
      ]);
      await upsert("oauth_revocations", oauthRows.oauth_revocations, [
        { name: "id" }, { name: "target_type" }, { name: "target_id" }, { name: "oauth_client_id" },
        { name: "oauth_resource_id" }, { name: "reason_code" }, { name: "revoked_at" }, { name: "expires_at" }
      ]);
    });

    return counts;
  }

}
