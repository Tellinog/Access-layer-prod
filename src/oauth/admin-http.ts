import type { FastifyInstance, FastifyReply, FastifyRequest, RouteHandlerMethod } from "fastify";
import { AppError } from "../errors.js";
import { hashOpaque, hashRequestField, parseCookies, randomToken, verifySignedCookie } from "../security.js";
import type { Repositories } from "../repositories.js";
import type { TokenService } from "../token-service.js";
import type { AdminActor, Config } from "../types.js";
import type { OAuthAdminAuditContext, OAuthAdminBulkScopesInput, OAuthAdminClientInput, OAuthAdminResourceInput } from "./admin-types.js";
import { isOAuthAdminKnownError, OAuthAdminService } from "./admin-service.js";

const ADMIN_TOOL_SLUG = "access-admin";

export interface OAuthAdminHttpDependencies {
  config: Config;
  repositories: Repositories;
  tokenService: TokenService;
  service: OAuthAdminService;
}

function apiPath(config: Config, path: string): string {
  return `${config.publicBasePath}${path}` || "/";
}

function uiPath(config: Config): string {
  return `${config.publicBasePath || "/admin"}/oauth`;
}

function readAdminToken(request: FastifyRequest, config: Config): string | null {
  const auth = request.headers.authorization ?? "";
  if (auth.startsWith("Bearer ")) return auth.slice("Bearer ".length);
  return verifySignedCookie(parseCookies(request.headers.cookie)[config.sessionCookieName], config.sessionSecret);
}

function grantUsable(grant: { status: string; valid_from: Date; valid_until: Date | null }): boolean {
  const now = new Date();
  return grant.status === "active" && grant.valid_from <= now && (grant.valid_until === null || grant.valid_until > now);
}

async function requireOAuthAdminActor(
  request: FastifyRequest,
  deps: OAuthAdminHttpDependencies,
  requiredPermission: "admin:oauth:read" | "admin:oauth:write"
): Promise<AdminActor> {
  const correlationId = randomToken("corr_", 16);
  const token = readAdminToken(request, deps.config);
  if (!token) throw new AppError("AUTH_INVALID_STATE", correlationId);
  let claims;
  try {
    claims = await deps.tokenService.verifyAccessToken(token, ADMIN_TOOL_SLUG);
  } catch {
    throw new AppError("AUTH_INVALID_STATE", correlationId);
  }
  const user = await deps.repositories.findUserByGoogleSub(claims.sub);
  const session = await deps.repositories.findSessionById(claims.sid);
  const grant = session ? await deps.repositories.findGrantById(session.grant_id) : null;
  if (!user || !session || !grant || user.status !== "active" || session.status !== "active" || !grantUsable(grant)) {
    throw new AppError("AUTH_INVALID_STATE", correlationId);
  }
  if (grant.role !== "platform_admin" || !grant.permissions.includes(requiredPermission)) {
    throw new AppError("ADMIN_FORBIDDEN", correlationId);
  }
  return {
    userId: user.id,
    googleSub: user.google_sub,
    email: user.email,
    hd: user.hd,
    role: grant.role,
    permissions: grant.permissions,
    assignedToolIds: []
  };
}

function sameOriginMutation(request: FastifyRequest, config: Config): boolean {
  if ((request.headers.authorization ?? "").startsWith("Bearer ")) return true;
  return request.headers.origin === new URL(config.appBaseUrl).origin;
}

function auditContext(request: FastifyRequest, actor: AdminActor, config: Config): OAuthAdminAuditContext {
  return {
    actor,
    correlationId: String(request.headers["x-correlation-id"] ?? randomToken("corr_", 16)),
    requestIpHash: hashRequestField(request.ip, config.logIpSalt),
    userAgentHash: hashRequestField(request.headers["user-agent"], config.logIpSalt)
  };
}

function objectBody(request: FastifyRequest): Record<string, unknown> {
  if (!request.body || typeof request.body !== "object" || Array.isArray(request.body)) {
    throw new AppError("VALIDATION_ERROR", randomToken("corr_", 16));
  }
  return request.body as Record<string, unknown>;
}

function exactKeys(body: Record<string, unknown>, allowed: readonly string[]): Record<string, unknown> {
  if (Object.keys(body).some((key) => !allowed.includes(key))) {
    throw new AppError("VALIDATION_ERROR", randomToken("corr_", 16));
  }
  return body;
}

function strings(value: unknown): string[] {
  if (!Array.isArray(value) || value.some((item) => typeof item !== "string")) {
    throw new AppError("VALIDATION_ERROR", randomToken("corr_", 16));
  }
  return value as string[];
}

function text(value: unknown): string {
  if (typeof value !== "string") throw new AppError("VALIDATION_ERROR", randomToken("corr_", 16));
  return value;
}

function nullableText(value: unknown): string | null {
  if (value === null || value === undefined || value === "") return null;
  return text(value);
}

function optionalDate(value: unknown): Date | null {
  if (value === undefined || value === null || value === "") return null;
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?(?:Z|[+-]\d{2}:\d{2})$/.test(value)) {
    throw new AppError("VALIDATION_ERROR", randomToken("corr_", 16), { issues: ["grant_validity_invalid"] });
  }
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) throw new AppError("VALIDATION_ERROR", randomToken("corr_", 16), { issues: ["grant_validity_invalid"] });
  return date;
}

function sendKnownError(error: unknown, correlationId: string): never {
  if (isOAuthAdminKnownError(error)) {
    const issues = "issues" in error ? error.issues : [error.reason];
    throw new AppError("VALIDATION_ERROR", correlationId, { issues });
  }
  const databaseCode = error && typeof error === "object" && "code" in error
    ? String((error as { code: unknown }).code)
    : "";
  if (["23503", "23505", "23514", "22P02"].includes(databaseCode)) {
    throw new AppError("VALIDATION_ERROR", correlationId, { issues: ["oauth_registration_conflict"] });
  }
  throw error;
}

function parseMappings(value: unknown): Array<{ scope: string; legacyPermissionKey: string }> {
  if (!Array.isArray(value)) throw new AppError("VALIDATION_ERROR", randomToken("corr_", 16));
  return value.map((item) => {
    if (!item || typeof item !== "object" || Array.isArray(item)) throw new AppError("VALIDATION_ERROR", randomToken("corr_", 16));
    const record = exactKeys(item as Record<string, unknown>, ["scope", "legacy_permission_key"]);
    return { scope: text(record.scope), legacyPermissionKey: text(record.legacy_permission_key) };
  });
}

function parseAllowances(value: unknown): Array<{ resourceId: string; scope: string }> {
  if (!Array.isArray(value)) throw new AppError("VALIDATION_ERROR", randomToken("corr_", 16));
  return value.map((item) => {
    if (!item || typeof item !== "object" || Array.isArray(item)) throw new AppError("VALIDATION_ERROR", randomToken("corr_", 16));
    const record = exactKeys(item as Record<string, unknown>, ["resource_id", "scope"]);
    return { resourceId: text(record.resource_id), scope: text(record.scope) };
  });
}

function parseAllowanceState(value: unknown): Array<{ resourceId: string; scope: string; status: "active" | "disabled" }> {
  if (!Array.isArray(value)) throw new AppError("VALIDATION_ERROR", randomToken("corr_", 16));
  return value.map((item) => {
    if (!item || typeof item !== "object" || Array.isArray(item)) throw new AppError("VALIDATION_ERROR", randomToken("corr_", 16));
    const row = exactKeys(item as Record<string, unknown>, ["resource_id", "scope", "status"]);
    return { resourceId: text(row.resource_id), scope: text(row.scope), status: text(row.status) as "active" | "disabled" };
  });
}

function parseBulkScopes(body: Record<string, unknown>): OAuthAdminBulkScopesInput {
  exactKeys(body, ["mode", "rows", "update_descriptions", "reactivate_disabled"]);
  if (!Array.isArray(body.rows) || (body.update_descriptions !== undefined && typeof body.update_descriptions !== "boolean") ||
      (body.reactivate_disabled !== undefined && typeof body.reactivate_disabled !== "boolean"))
    throw new AppError("VALIDATION_ERROR", randomToken("corr_", 16));
  return {
    mode: body.mode === undefined ? "create_missing" : text(body.mode) as "create_missing",
    updateDescriptions: body.update_descriptions === true,
    reactivateDisabled: body.reactivate_disabled === true,
    rows: body.rows.map((item, index) => {
      if (!item || typeof item !== "object" || Array.isArray(item)) throw new AppError("VALIDATION_ERROR", randomToken("corr_", 16));
      const row = exactKeys(item as Record<string, unknown>, ["row", "scope", "description"]);
      if (row.row !== undefined && (typeof row.row !== "number" || !Number.isInteger(row.row)))
        throw new AppError("VALIDATION_ERROR", randomToken("corr_", 16));
      return { row: row.row === undefined ? index + 1 : row.row as number,
        scope: text(row.scope), description: text(row.description) };
    })
  };
}

function parseBulkGrant(body: Record<string, unknown>) {
  exactKeys(body, ["resource_id", "user_ids", "emails", "scopes", "valid_from", "valid_until"]);
  return { resourceId: text(body.resource_id), userIds: strings(body.user_ids ?? []),
    emails: strings(body.emails ?? []), scopes: strings(body.scopes),
    validFrom: optionalDate(body.valid_from), validUntil: optionalDate(body.valid_until) };
}

function oauthAdminHtml(config: Config): string {
  const endpoint = apiPath(config, "/v1/admin/oauth");
  const legacyAdmin = config.publicBasePath || "/admin";
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>OAuth administration</title><style>
:root{--brand:rgb(0 75 99);--brand-soft:rgb(230 241 244);--ink:rgb(16 24 40);--muted:rgb(102 112 133);--line:rgb(229 231 235);--bg:rgb(247 248 250);--card:rgb(255 255 255);--warn:rgb(245 158 11);--warn-bg:rgb(255 247 230);--ok:rgb(116 198 157);--ok-bg:rgb(240 255 247);--err:rgb(185 28 28);font-family:Inter,ui-sans-serif,system-ui;color:var(--ink);background:var(--bg)}
body{margin:0;background:var(--bg)}header{background:var(--brand);color:white;padding:14px 28px;display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap}header a{color:white}
.tabs{position:sticky;top:0;z-index:5;display:flex;gap:2px;padding:0 20px;background:var(--card);border-bottom:1px solid var(--line);overflow-x:auto}
.tabs .tab{margin:0;padding:14px;border-radius:0;background:none;color:var(--muted);font-weight:650;border-bottom:3px solid transparent;white-space:nowrap}.tabs .tab.active{color:var(--brand);border-bottom-color:var(--brand)}
.count{display:inline-block;min-width:18px;margin-left:6px;padding:1px 6px;border-radius:999px;background:var(--brand-soft);color:var(--brand);font-size:.75rem;text-align:center}
main{max-width:1480px;margin:auto;padding:20px 28px;display:grid;grid-template-columns:minmax(0,1fr) 380px;gap:20px;align-items:start}
aside{position:sticky;top:64px;display:grid;gap:14px;max-height:calc(100vh - 84px);overflow:auto}
@media (max-width:1100px){main{grid-template-columns:minmax(0,1fr);padding:16px}aside{position:static;max-height:none}}
.panel{display:grid;gap:18px}.panel[hidden]{display:none}.panel-head h1{margin:0 0 4px;font-size:1.45rem}.panel-head p{margin:0}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(340px,100%),1fr));gap:18px;align-items:start}
.card{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:18px;box-shadow:0 8px 24px rgba(15,23,42,.06);min-width:0}.card h2{margin:0 0 6px;font-size:1.1rem}.card h3{margin:18px 0 6px;font-size:1rem}
.notice{border-left:5px solid var(--warn);background:var(--warn-bg);padding:14px 16px;border-radius:8px}.callout{border-left:4px solid var(--brand);background:var(--brand-soft);padding:12px 14px;border-radius:8px;font-size:.92rem}.callout p{margin:4px 0}
label{display:block;font-weight:650;margin-top:10px}input,textarea,select{box-sizing:border-box;width:100%;margin-top:5px;padding:9px;border:1px solid rgb(152 162 179);border-radius:8px;font:inherit}select[size]{padding:4px}
button{margin-top:12px;padding:10px 14px;border:0;border-radius:8px;background:var(--brand);color:white;cursor:pointer;font:inherit}button.secondary{background:rgb(102 112 133)}button:disabled{opacity:.45;cursor:not-allowed}
.row{display:flex;gap:12px;flex-wrap:wrap;align-items:flex-end}.row>label{flex:1 1 180px}.actions{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-top:12px}.actions button{margin-top:0}
.segmented{display:inline-flex;gap:2px;margin-top:8px;padding:3px;border:1px solid var(--line);border-radius:10px;background:var(--bg)}.segmented button{margin:0;background:none;color:var(--muted)}.segmented button.active{background:var(--card);color:var(--brand);box-shadow:0 1px 3px rgba(15,23,42,.15)}
.status-line{margin:6px 0;color:var(--muted);font-size:.88rem}.hint{margin:8px 0;padding:10px;border-radius:8px;background:var(--warn-bg);font-size:.9rem}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}.stat{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px}.stat strong{display:block;font-size:1.6rem;color:var(--brand)}
.steps{margin:8px 0 0;padding-left:20px}.steps li{margin:6px 0}.link{margin:0;padding:0;background:none;color:var(--brand);text-decoration:underline}
.result{white-space:pre-wrap;overflow:auto;background:rgb(249 250 251);padding:10px;border-radius:8px;max-height:420px}.secret{border:2px solid var(--ok);background:var(--ok-bg);padding:12px;word-break:break-all}.muted{color:var(--muted);font-size:.9rem}
.table-wrap{overflow:auto}table{width:100%;border-collapse:collapse;font-size:.88rem}th,td{text-align:left;border-bottom:1px solid rgb(234 236 240);padding:8px;vertical-align:top}
.toast{position:fixed;right:20px;bottom:20px;z-index:20;max-width:min(440px,calc(100vw - 40px));padding:12px 16px;border-radius:10px;background:var(--ink);color:white;box-shadow:0 12px 32px rgba(15,23,42,.25)}.toast.error{background:var(--err)}.toast.ok{background:rgb(4 120 87)}.toast[hidden]{display:none}
</style></head>
<body><header><strong>Access Layer · OAuth administration</strong><a href="${legacyAdmin}">Legacy administration</a></header>
<nav class="tabs" role="tablist" aria-label="OAuth administration sections"><button type="button" class="tab" role="tab" data-tab="overview">Overview</button><button type="button" class="tab" role="tab" data-tab="grants">User access</button><button type="button" class="tab" role="tab" data-tab="scopes">Scopes<span class="count" id="count-scopes">0</span></button><button type="button" class="tab" role="tab" data-tab="resources">Resources<span class="count" id="count-resources">0</span></button><button type="button" class="tab" role="tab" data-tab="clients">Clients<span class="count" id="count-clients">0</span></button><button type="button" class="tab" role="tab" data-tab="security">Lifecycle &amp; keys</button></nav>
<main><div>

<section class="panel" data-panel="overview">
<div class="panel-head"><h1>Overview</h1><p class="muted">Current OAuth registrations and the recommended setup order.</p></div>
<div class="notice"><strong>Temporary P0 compatibility state.</strong> <code>legacy_bridge</code> exists for old consumers; its tool binding is only an entitlement anchor. New native resources use direct human grants. Do not use a legacy tool as a client ID, audience, or introspection credential.</div>
<p class="muted">Protocol enablement remains controlled separately by <code>OAUTH_P0_ENABLED</code>. Creating administration records does not enable OAuth.</p>
<div class="stats"><div class="stat"><strong id="stat-scopes">0</strong>active scopes</div><div class="stat"><strong id="stat-native">0</strong>native resources</div><div class="stat"><strong id="stat-legacy">0</strong>legacy bridge resources</div><div class="stat"><strong id="stat-clients">0</strong>clients</div><div class="stat"><strong id="stat-keys">none</strong>active signing key</div></div>
<section class="card"><h2>Setup order</h2><ol class="steps"><li><button type="button" class="link" data-goto="scopes">Scopes</button> — create canonical scopes in the catalogue.</li><li><button type="button" class="link" data-goto="resources">Resources</button> — register a native resource and its scopes (stores a one-time introspection credential).</li><li><button type="button" class="link" data-goto="clients">Clients</button> — register a confidential client, its exact redirects and scope allowances.</li><li><button type="button" class="link" data-goto="grants">User access</button> — grant native resource scopes to people who have signed in at least once.</li><li><button type="button" class="link" data-goto="security">Lifecycle &amp; keys</button> — activate registrations, rotate credentials and manage signing keys.</li></ol></section>
<section class="card"><h2>Current OAuth administration state</h2><button class="secondary" id="reload">Reload</button><h3>Resources</h3><div id="resource-state" class="table-wrap"></div><h3>Clients</h3><div id="client-state" class="table-wrap"></div><details><summary>Advanced snapshot / UUID details</summary><div id="state" class="result">Loading…</div></details></section>
</section>

<section class="panel" data-panel="grants" hidden>
<div class="panel-head"><h1>User access · Native human grants</h1><p class="muted">Grant exact scopes of a native resource to Access Layer users, one at a time or in bulk — including pending emails that have never signed in.</p></div>
<section class="card"><div class="row"><label>Native resource<select name="resource_id" id="grant-resource" form="native-grant-form" required></select></label></div><p id="grant-resource-empty" class="hint" hidden>No native resource exists yet. Create one in <button type="button" class="link" data-goto="resources">Resources</button> with entitlement mode Native.</p>
<div class="callout"><p><strong>Who can receive a grant?</strong> <strong>One user</strong> grants to people who have already signed in to Access Layer (search by email or name).</p><p><strong>Several users or emails</strong> also accepts emails that have never signed in, when their domain is approved: they are stored as <code>pending_user_link</code> and become active automatically at the person's first verified sign-in (Google or Microsoft). Pending grants do not authorize anything until then and can be revoked like active ones.</p></div></section>
<section class="card"><h2>Grant access</h2><div class="segmented" role="group" aria-label="Grant mode"><button type="button" id="grant-mode-single" class="active">One user</button><button type="button" id="grant-mode-bulk">Several users or emails</button></div>
<div id="grant-single-pane"><form id="native-grant-form"><label>Search existing user by email or name<input id="grant-user-search" autocomplete="off" placeholder="name@company.com or name"></label><p id="grant-user-status" class="status-line">Type at least 2 characters.</p><label>Existing user<select name="user_id" id="grant-user" size="5" required></select></label><label>Registered scopes<select name="scopes" id="grant-scopes" multiple hidden></select></label><div id="single-grant-picker"></div><div class="row"><label>Valid from (optional)<input type="datetime-local" name="valid_from"></label><label>Valid until (optional)<input type="datetime-local" name="valid_until"></label></div><button>Grant selected scopes</button></form></div>
<div id="grant-bulk-pane" hidden><h3>Bulk native grants</h3><select id="bulk-grant-resource" hidden aria-label="Bulk native resource"></select><div class="grid"><div><label>Search existing users<input id="bulk-user-search" autocomplete="off" placeholder="name@company.com or name"></label><p id="bulk-user-status" class="status-line">Type at least 2 characters.</p><select id="bulk-user-results" size="5" aria-label="Matching users"></select><button type="button" id="bulk-add-user">Add selected user</button><div id="bulk-selected-users"></div></div><div><label>Paste emails, one per line<textarea id="bulk-user-emails" rows="7"></textarea></label><p class="status-line">Emails without an Access Layer user become pending grants (approved domains only).</p></div></div><div id="bulk-grant-picker"></div><div class="row"><label>Valid from (optional)<input id="bulk-grant-from" type="datetime-local"></label><label>Valid until (optional)<input id="bulk-grant-until" type="datetime-local"></label></div><div class="actions"><button id="bulk-grant-preview">Preview grants</button><button id="bulk-grant-commit" disabled>Commit grants</button></div><div id="bulk-grant-result" class="table-wrap"></div></div></section>
<section class="card"><h2>Existing grants</h2><div class="row"><label>User/email filter<input id="grant-filter-user"></label><label>Scope filter<input id="grant-filter-scope"></label><label>Persisted status<select id="grant-filter-status"><option value="">All</option><option>active</option><option>expired</option><option>revoked</option><option>pending_user_link</option></select></label><label>Effective<select id="grant-filter-effective"><option value="">All</option><option value="true">Effective</option><option value="false">Not effective</option></select></label></div><div class="actions"><button class="secondary" id="reload-grants">Reload grants</button><span id="grant-selected-count">0 selected</span><button id="bulk-revoke-preview">Preview revoke selected grants</button><button id="bulk-revoke-commit" disabled>Commit exact revocations</button></div><div id="bulk-revoke-result" class="table-wrap"></div><div id="native-grants" class="table-wrap"></div><div class="actions"><button id="grants-previous" disabled>Previous page</button><button id="grants-next">Next page</button></div></section>
</section>

<section class="panel" data-panel="scopes" hidden>
<div class="panel-head"><h1>Scopes</h1><p class="muted">Canonical scope catalogue shared by resources and clients.</p></div>
<div class="grid"><section class="card"><h2>Create scope</h2><form id="scope-form"><label>Canonical scope<input name="scope" placeholder="project:domain:action" required></label><label>Description<input name="description" required></label><button>Create scope</button></form></section>
<section class="card"><h2>Single scope edit</h2><form id="scope-update-form"><label>Scope<select name="id" id="scope-update-id" required></select></label><label>Description (optional)<input name="description"></label><label>Status<select name="status"><option value="">unchanged</option><option>active</option><option>disabled</option></select></label><button>Update scope</button></form></section></div>
<section class="card"><h2>Bulk scope catalogue</h2><p class="muted">One row per line: scope ; description or scope[TAB]description. Commas remain in descriptions.</p><textarea id="bulk-scopes" rows="8" aria-label="Bulk scope catalogue"></textarea><label><input type="checkbox" id="bulk-scope-update" style="width:auto"> Update descriptions of existing scopes</label><label><input type="checkbox" id="bulk-scope-reactivate" style="width:auto"> Reactivate disabled scopes</label><div class="actions"><button type="button" id="bulk-scope-preview">Preview</button><button type="button" id="bulk-scope-commit" disabled>Commit</button><button type="button" class="secondary" id="bulk-scope-clear">Clear</button></div><div id="bulk-scope-result" class="table-wrap"></div></section>
<section class="card"><h2>Scope catalogue</h2><div class="row"><label>Scope search/filter<input id="scope-search" placeholder="Filter by canonical scope"></label><label>Status<select id="scope-filter"><option value="">All</option><option>active</option><option>disabled</option></select></label></div><div class="actions"><span id="scope-selected-count">0 selected</span><select id="scope-target-status" style="width:auto;margin:0" aria-label="Target lifecycle"><option value="disabled">Disable selected</option><option value="active">Activate selected</option></select><button type="button" id="scope-status-preview">Preview selected lifecycle</button><button type="button" id="scope-status-commit" disabled>Commit selected lifecycle</button></div><div id="scope-status-result" class="table-wrap"></div><div class="table-wrap"><table><thead><tr><th>Select</th><th>Scope</th><th>Description</th><th>Status</th><th>Created/updated</th><th>Usage</th></tr></thead><tbody id="scope-catalogue"></tbody></table></div></section>
</section>

<section class="panel" data-panel="resources" hidden>
<div class="panel-head"><h1>Resources</h1><p class="muted">Protected resources (audiences), their registered scopes and legacy bridge bindings.</p></div>
<section class="card"><h2>Create resource</h2><form id="resource-form"><div class="grid"><div><label>HTTPS resource ID<input name="resource_id" required></label><label>Display name<input name="display_name" required></label><label>Owner team<input name="owner_team" required></label><label>Owner contact<input name="owner_contact"></label></div><div><label>Status<select name="status"><option>draft</option><option>active</option><option>disabled</option></select></label><label>Protected-resource metadata URL<input name="metadata_url" required></label><label>Entitlement mode<select name="entitlement_mode" id="resource-mode"><option value="native" selected>Native</option><option value="legacy_bridge">Legacy bridge</option></select></label></div></div><label>Active OAuth scopes<select name="native_scopes" id="native-resource-scopes" multiple hidden></select></label><div id="native-picker"></div><div id="native-resource-fields"><p class="muted">These scopes use native human grants without a legacy tool.</p></div><div id="legacy-resource-fields" hidden><label>Bound legacy tool slug<select name="legacy_tool_slug" id="legacy-resource-tool"></select></label><div id="legacy-resource-mappings"></div></div><button>Create resource + one-time introspection credential</button></form></section>
<section class="card"><h2>Native resource scope administration</h2><label>Native resource<select id="bulk-resource"></select></label><label>Filter scopes<input id="bulk-resource-search"></label><p class="muted">Choose an explicit action for each scope. Unchanged registrations stay untouched.</p><div id="bulk-resource-rows"></div><div class="actions"><button id="bulk-resource-preview">Preview registrations</button><button id="bulk-resource-commit" disabled>Commit registrations</button></div><div id="bulk-resource-result" class="table-wrap"></div></section>
<div class="grid"><section class="card"><h2>Resource scope registration</h2><form id="mapping-form"><label>Resource<select name="resource_id" id="mapping-resource" required></select></label><label>Scope<select name="scope_id" id="mapping-scope" required></select></label><div id="mapping-legacy"><label>Exact legacy permission key<select name="permission" id="mapping-permission"></select></label></div><label>Status<select name="status"><option>active</option><option>disabled</option></select></label><button>Set scope registration</button></form></section>
<section class="card"><h2>Temporary entitlement binding</h2><p class="muted">Legacy bridge resources only.</p><form id="binding-form"><label>Legacy bridge resource<select name="resource_id" id="binding-resource" required></select></label><label>Legacy tool slug<select name="tool" id="binding-tool" required></select></label><label>Status<select name="status"><option>active</option><option>disabled</option></select></label><button>Replace or disable binding</button></form></section></div>
</section>

<section class="panel" data-panel="clients" hidden>
<div class="panel-head"><h1>Clients</h1><p class="muted">Confidential OAuth clients, exact redirect URIs and resource scope allowances.</p></div>
<section class="card"><h2>Create confidential client</h2><form id="client-form"><div class="grid"><div><label>Client ID<input name="client_id" required></label><label>Client name<input name="client_name" required></label><label>Owner team<input name="owner_team" required></label><label>Owner contact<input name="owner_contact"></label><label>Status<select name="status"><option>draft</option><option>active</option><option>disabled</option></select></label><label><input style="width:auto" type="checkbox" name="refresh"> Allow refresh_token</label></div><div><label>Exact redirect URIs (one per line)<textarea name="redirects" required></textarea></label><label>Resource<select id="client-resource" required></select></label><div id="client-picker"></div><button type="button" id="client-select-all">Allow all selected resource scopes</button><details><summary>Advanced allowance paste (resource URI = scope)</summary><textarea name="allowances" aria-label="Advanced allowance paste"></textarea></details></div></div><button>Create client + one-time secret</button></form></section>
<div class="grid"><section class="card"><h2>Client redirect URIs</h2><form id="redirect-form"><label>Client<select name="id" id="redirect-client" required></select></label><p id="redirect-current" class="muted"></p><label>Exact redirect URIs (one per line)<textarea name="redirects" required></textarea></label><div class="actions"><button type="button" id="redirect-preview">Preview redirect diff</button><button type="submit" id="redirect-commit" disabled>Commit redirect replacement</button></div><div id="redirect-diff" class="table-wrap"></div></form></section>
<section class="card"><h2>Client allowances</h2><form id="allowance-form"><label>Client<select name="id" id="allowance-client" required></select></label><label>Resource<select id="allowance-resource" required></select></label><p id="allowance-current" class="muted"></p><div id="allowance-picker"></div><button type="button" id="allowance-select-all">Select all active registered scopes</button><details><summary>Advanced allowance paste (resource URI = scope)</summary><textarea name="allowances" aria-label="Advanced allowance paste"></textarea></details><div class="actions"><button type="button" id="allowance-preview">Preview allowance diff</button><button type="submit" id="allowance-commit" disabled>Commit allowance replacement</button></div><div id="allowance-diff" class="table-wrap"></div></form></section></div>
</section>

<section class="panel" data-panel="security" hidden>
<div class="panel-head"><h1>Lifecycle &amp; keys</h1><p class="muted">Registration status, credential rotation/retirement and signing-key lifecycle.</p></div>
<div class="grid"><section class="card"><h2>Registration lifecycle</h2><form id="status-form"><label>Kind<select name="kind" id="status-kind"><option value="clients">client</option><option value="resources">resource</option></select></label><label>Registration<select name="id" id="status-owner" required></select></label><label>Status<select name="status"><option>draft</option><option>active</option><option>disabled</option></select></label><button>Update status</button></form></section>
<section class="card"><h2>Credential lifecycle</h2><form id="rotate-form"><label>Kind<select name="kind" id="rotate-kind"><option value="clients">client</option><option value="resources">resource</option></select></label><label>Owner<select name="id" id="rotate-owner" required></select></label><button>Rotate and show secret once</button></form><form id="retire-form"><label>Kind<select name="kind" id="retire-kind"><option value="clients">client</option><option value="resources">resource</option></select></label><label>Credential record<select name="id" id="retire-credential" required></select></label><button>Retire credential</button></form></section></div>
<section class="card"><h2>Signing keys</h2><p class="muted">Private keys are generated server-side into the configured protected root and are never returned.</p><button id="generate-key">Generate staged RSA key</button><div id="key-actions"></div></section>
</section>

</div><aside aria-label="Operation output"><section class="card"><h2>One-time credential result</h2><div id="secret" class="secret">No credential generated in this session.</div></section>
<section class="card"><h2>Operation result</h2><div id="result" class="result" aria-live="polite"></div></section></aside>
<div id="toast" class="toast" role="status" hidden></div>
<script>const api=${JSON.stringify(endpoint)};const result=document.querySelector('#result');const secret=document.querySelector('#secret');
const toastBox=document.querySelector('#toast');let toastTimer;function notify(message,kind){toastBox.textContent=message;toastBox.className='toast '+(kind||'');toastBox.hidden=false;clearTimeout(toastTimer);toastTimer=setTimeout(()=>{toastBox.hidden=true},kind==='error'?10000:4000)}
function readableError(e){try{const err=JSON.parse(e.message).error;if(!err)return e.message;const issues=err.details&&err.details.issues;return (err.message||err.code)+(issues&&issues.length?' — '+issues.join(', '):'')+' ['+err.code+(err.correlation_id?' · '+err.correlation_id:'')+']'}catch{return e.message}}
function fail(e){const message=readableError(e);result.textContent=message;notify(message,'error')}
const lines=v=>v.split(/\\r?\\n/).map(x=>x.trim()).filter(Boolean);const pairs=v=>lines(v).map(x=>{const i=x.indexOf('=');if(i<1)throw new Error('Each mapping needs =');return [x.slice(0,i).trim(),x.slice(i+1).trim()]});
let state={resources:[],scopes:[],resourceScopes:[],entitlementBindings:[]},legacyTools=[];
const selectedValues=el=>Array.from(el.selectedOptions).map(o=>o.value);
function options(el,rows,value,label){const previous=el.value;el.replaceChildren();for(const row of rows){const option=document.createElement('option');option.value=value(row);option.textContent=label(row);el.appendChild(option)}if(rows.some(row=>value(row)===previous))el.value=previous}
function nativeResources(){return state.resources.filter(r=>r.entitlement_mode==='native')}
function legacyResources(){return state.resources.filter(r=>r.entitlement_mode!=='native')}
function selectedTool(){return legacyTools.find(t=>t.slug===document.querySelector('#legacy-resource-tool').value)}
function registeredScopes(resourceId){return state.resourceScopes.filter(rs=>rs.oauth_resource_id===resourceId&&rs.status==='active'&&state.scopes.some(s=>s.id===rs.oauth_scope_id&&s.status==='active'))}
function renderLegacyMappings(){const box=document.querySelector('#legacy-resource-mappings');box.replaceChildren();const tool=selectedTool();for(const scope of selectedValues(document.querySelector('#native-resource-scopes'))){const label=document.createElement('label');label.textContent=scope+' → registered permission';const select=document.createElement('select');select.dataset.scope=scope;for(const permission of tool?.registered_permission_keys||[]){const option=document.createElement('option');option.value=permission;option.textContent=permission;select.appendChild(option)}label.appendChild(select);box.appendChild(label)}}
function toggleResourceMode(){const native=document.querySelector('#resource-mode').value==='native';document.querySelector('#native-resource-fields').hidden=!native;document.querySelector('#legacy-resource-fields').hidden=native;document.querySelector('#legacy-resource-tool').required=!native;if(!native)renderLegacyMappings()}
function refreshMappingControls(){const resource=state.resources.find(r=>r.id===document.querySelector('#mapping-resource').value);const legacy=resource&&resource.entitlement_mode!=='native';document.querySelector('#mapping-legacy').hidden=!legacy;document.querySelector('#mapping-permission').required=!!legacy;const binding=state.entitlementBindings.find(b=>b.oauth_resource_id===resource?.id&&b.status==='active');const tool=legacyTools.find(t=>t.slug===binding?.legacy_tool_slug);options(document.querySelector('#mapping-permission'),tool?.registered_permission_keys||[],x=>x,x=>x)}
function refreshGrantScopes(){const id=document.querySelector('#grant-resource').value;options(document.querySelector('#grant-scopes'),registeredScopes(id),r=>r.scope,r=>r.scope);scopePicker('single-grant-picker',()=>registeredScopes(id).map(r=>state.scopes.find(s=>s.id===r.oauth_scope_id)).filter(Boolean),singleGrantChoice,()=>{for(const option of byId('grant-scopes').options)option.selected=singleGrantChoice.has(option.value)});for(const option of byId('grant-scopes').options)option.selected=singleGrantChoice.has(option.value);reloadGrants().catch(fail)}
function userSearch(inputId,selectId,statusId){let timer;document.querySelector('#'+inputId).oninput=e=>{clearTimeout(timer);const q=e.target.value.trim(),select=document.querySelector('#'+selectId),status=document.querySelector('#'+statusId);if(q.length<2){select.replaceChildren();status.textContent='Type at least 2 characters.';return}status.textContent='Searching…';timer=setTimeout(()=>call('/users?q='+encodeURIComponent(q)).then(users=>{options(select,users,u=>u.id,u=>u.email+' · '+(u.display_name||'')+' · '+u.status);status.textContent=users.length?users.length+(users.length===25?'+':'')+' matching user(s) — select one below.':'No Access Layer user matches "'+q+'". The person has not signed in yet.';if(!users.length&&/^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/.test(q))status.appendChild(preauthorizeButton(q))}).catch(x=>{status.textContent='User search failed.';fail(x)}),250)}}
userSearch('grant-user-search','grant-user','grant-user-status');
document.querySelector('#resource-mode').onchange=toggleResourceMode;document.querySelector('#legacy-resource-tool').onchange=renderLegacyMappings;document.querySelector('#native-resource-scopes').onchange=renderLegacyMappings;document.querySelector('#mapping-resource').onchange=refreshMappingControls;document.querySelector('#grant-resource').onchange=refreshGrantScopes;document.querySelector('#reload-grants').onclick=()=>reloadGrants().catch(fail);
async function call(path,method='GET',body){if(method!=='GET')secret.textContent='No new credential; previous one-time value discarded.';const r=await fetch(api+path,{method,headers:body?{'content-type':'application/json'}:{},body:body?JSON.stringify(body):undefined});const data=await r.json().catch(()=>({}));if(!r.ok)throw new Error(JSON.stringify(data));return data}
function show(data){const visible={...data};const s=visible.client_secret||visible.resource_credential_secret;delete visible.client_secret;delete visible.resource_credential_secret;result.textContent=JSON.stringify(visible,null,2);notify(s?'Saved. Copy the one-time secret now — it cannot be shown again.':'Saved.','ok');secret.textContent=s?(data.resource_credential_id?data.resource_credential_id+' : ':'')+s+' — copy now; it cannot be shown again.':'No new credential; previous one-time value discarded.'}
async function reload(){const [data,tools]=await Promise.all([call(''),call('/legacy-tools')]);state=data;legacyTools=tools;document.querySelector('#state').textContent=JSON.stringify(data,null,2);options(document.querySelector('#native-resource-scopes'),data.scopes.filter(s=>s.status==='active'),s=>s.scope,s=>s.scope);options(document.querySelector('#legacy-resource-tool'),tools,t=>t.slug,t=>t.display_name+' ('+t.slug+')');options(document.querySelector('#binding-tool'),tools,t=>t.slug,t=>t.display_name+' ('+t.slug+')');options(document.querySelector('#mapping-resource'),data.resources,r=>r.id,r=>r.display_name+' ('+r.entitlement_mode+')');options(document.querySelector('#mapping-scope'),data.scopes.filter(s=>s.status==='active'),s=>s.id,s=>s.scope);options(document.querySelector('#binding-resource'),legacyResources(),r=>r.id,r=>r.display_name);options(document.querySelector('#grant-resource'),nativeResources(),r=>r.id,r=>r.display_name);toggleResourceMode();refreshMappingControls();await reloadGrants();renderAll();const box=document.querySelector('#key-actions');box.innerHTML='';for(const k of data.signingKeys||[]){const row=document.createElement('div');row.textContent=k.kid+' · '+k.status+(k.status==='published'?' · activation eligible after '+k.activates_at:'')+(k.retire_after?' · verification grace ends '+k.retire_after:'');const actions=k.status==='staged'?['publish','disable']:k.status==='published'?['activate','disable']:k.status==='active'?['retire']:[];for(const action of actions){const b=document.createElement('button');b.className='secondary';b.style.marginLeft='6px';b.textContent=action;if(action==='activate'&&Date.now()<Date.parse(k.activates_at)){b.disabled=true;b.title='Publication lead has not elapsed'}b.onclick=()=>call('/signing-keys/'+k.id+'/'+action,'POST',{}).then(show).then(reload).catch(fail);row.appendChild(b)}box.appendChild(row)}}
document.querySelector('#scope-form').onsubmit=e=>{e.preventDefault();const f=new FormData(e.target);call('/scopes','POST',{scope:f.get('scope'),description:f.get('description')}).then(show).then(reload).catch(fail)};
document.querySelector('#resource-form').onsubmit=e=>{e.preventDefault();const f=new FormData(e.target);const mode=f.get('entitlement_mode');const base={resource_id:f.get('resource_id'),display_name:f.get('display_name'),owner_team:f.get('owner_team'),owner_contact:f.get('owner_contact')||null,status:f.get('status'),protected_resource_metadata_url:f.get('metadata_url'),entitlement_mode:mode};const payload=mode==='native'?{...base,scopes:selectedValues(document.querySelector('#native-resource-scopes'))}:{...base,legacy_tool_slug:f.get('legacy_tool_slug'),scope_mappings:Array.from(document.querySelectorAll('#legacy-resource-mappings select')).map(s=>({scope:s.dataset.scope,legacy_permission_key:s.value}))};call('/resources','POST',payload).then(show).then(reload).catch(fail)};
document.querySelector('#native-grant-form').onsubmit=e=>{e.preventDefault();const f=new FormData(e.target);const date=v=>v?new Date(v).toISOString():undefined;call('/native-grants','POST',{resource_id:f.get('resource_id'),user_id:f.get('user_id'),scopes:selectedValues(document.querySelector('#grant-scopes')),valid_from:date(f.get('valid_from')),valid_until:date(f.get('valid_until'))}).then(show).then(reloadGrants).catch(fail)};
document.querySelector('#status-form').onsubmit=e=>{e.preventDefault();const f=new FormData(e.target);call('/'+f.get('kind')+'/'+f.get('id')+'/status','PATCH',{status:f.get('status')}).then(show).then(reload).catch(fail)};
document.querySelector('#mapping-form').onsubmit=e=>{e.preventDefault();const f=new FormData(e.target);const resource=state.resources.find(r=>r.id===f.get('resource_id'));call('/resources/'+f.get('resource_id')+'/scopes/'+f.get('scope_id'),'PUT',{legacy_permission_key:resource?.entitlement_mode==='native'?null:f.get('permission'),status:f.get('status')}).then(show).then(reload).catch(fail)};
document.querySelector('#binding-form').onsubmit=e=>{e.preventDefault();const f=new FormData(e.target);call('/resources/'+f.get('resource_id')+'/entitlement-binding','PUT',{legacy_tool_slug:f.get('tool'),status:f.get('status')}).then(show).then(reload).catch(fail)};
document.querySelector('#rotate-form').onsubmit=e=>{e.preventDefault();const f=new FormData(e.target);call('/'+f.get('kind')+'/'+f.get('id')+'/credentials/rotate','POST',{}).then(show).then(reload).catch(fail)};
document.querySelector('#retire-form').onsubmit=e=>{e.preventDefault();const f=new FormData(e.target);call('/'+f.get('kind')+'/credentials/'+f.get('id')+'/retire','POST',{}).then(show).then(reload).catch(fail)};
document.querySelector('#scope-update-form').onsubmit=e=>{e.preventDefault();const f=new FormData(e.target),body={};if(f.get('description'))body.description=f.get('description');if(f.get('status'))body.status=f.get('status');call('/scopes/'+f.get('id'),'PATCH',body).then(show).then(reload).catch(fail)};
document.querySelector('#generate-key').onclick=()=>call('/signing-keys','POST',{}).then(show).then(reload).catch(fail);document.querySelector('#reload').onclick=reload;reload().catch(fail);
const byId=id=>document.getElementById(id);const activeScopes=()=>state.scopes.filter(s=>s.status==='active');
const singleGrantChoice=new Set(),nativeChoice=new Set(),clientChoice=new Set(),allowanceChoice=new Set(),bulkGrantChoice=new Set(),selectedCatalogue=new Set(),selectedUsers=new Map(),selectedGrants=new Set(),resourceActions=new Map();
let bulkScopePreview=null,scopeStatusPreview=null,resourceScopePreview=null,allowancePreview=null,redirectPreview=null,bulkGrantPreview=null,revokePreview=null,grantOffset=0,lastGrantRows=[];
const previewVersions={};function invalidate(button,box){previewVersions[button]=(previewVersions[button]||0)+1;byId(button).disabled=true;if(box)byId(box).replaceChildren()}
async function previewRequest(button,path,payload){invalidate(button);const version=previewVersions[button];const data=await call(path,'POST',payload);return previewVersions[button]===version?data:null}
function makeTable(boxId,heads,rows){const box=byId(boxId);box.replaceChildren();const table=document.createElement('table');const head=document.createElement('thead');const tr=document.createElement('tr');for(const h of heads){const th=document.createElement('th');th.textContent=h;tr.appendChild(th)}head.appendChild(tr);table.appendChild(head);const body=document.createElement('tbody');for(const cells of rows){const row=document.createElement('tr');for(const value of cells){const td=document.createElement('td');td.textContent=value===null||value===undefined?'':String(value);row.appendChild(td)}body.appendChild(row)}table.appendChild(body);box.appendChild(table)}
function planSummary(boxId,data){const p=document.createElement('p');const counts=data.summary||data.diff?.reduce((all,row)=>{all[row.operation]=(all[row.operation]||0)+1;return all},{});p.textContent=(data.committed!==undefined?'Committed: '+data.committed+' · ':'')+Object.entries(counts||{}).map(([key,value])=>key+': '+value).join(' · ');byId(boxId).appendChild(p)}
function showBulkResult(data){if(data.rows)makeTable('result',['Entity','Scope','Operation','Reason'],data.rows.map(r=>[r.user_email||r.user_id||r.resource_display_name||r.grant_id||r.scope,r.scope,r.operation,r.reason]));else makeTable('result',['Resource / redirect','Scope','Current status','Operation'],(data.diff||[]).map(r=>[r.resource_id||r.redirect_uri,r.scope,r.current_status,r.operation]));planSummary('result',data);notify(data.committed!==undefined?'Committed: '+data.committed+'.':'Saved.','ok')}
function scopePicker(boxId,source,selected,onChange){const box=byId(boxId);const oldSearch=box.querySelector('input[type=search]')?.value||'';box.replaceChildren();const search=document.createElement('input');search.type='search';search.placeholder='Filter scopes';search.value=oldSearch;box.appendChild(search);const count=document.createElement('p');box.appendChild(count);const controls=document.createElement('div');box.appendChild(controls);const list=document.createElement('div');list.style.maxHeight='220px';list.style.overflow='auto';box.appendChild(list);function render(){const visible=source().filter(s=>s.scope.toLowerCase().includes(search.value.toLowerCase()));count.textContent=selected.size+' selected';list.replaceChildren();for(const scope of visible){const label=document.createElement('label');label.style.fontWeight='normal';const check=document.createElement('input');check.type='checkbox';check.style.width='auto';check.checked=selected.has(scope.scope);check.onchange=()=>{check.checked?selected.add(scope.scope):selected.delete(scope.scope);onChange?.();render()};label.append(check,document.createTextNode(' '+scope.scope+' — '+(scope.description||'')));list.appendChild(label)}}for(const [title,action] of [['Select all visible',()=>source().filter(s=>s.scope.toLowerCase().includes(search.value.toLowerCase())).forEach(s=>selected.add(s.scope))],['Clear visible',()=>source().filter(s=>s.scope.toLowerCase().includes(search.value.toLowerCase())).forEach(s=>selected.delete(s.scope))],['Select all active',()=>source().filter(s=>s.status==='active').forEach(s=>selected.add(s.scope))],['Clear all',()=>selected.clear()]]){const button=document.createElement('button');button.type='button';button.className='secondary';button.textContent=title;button.onclick=()=>{action();onChange?.();render()};controls.appendChild(button)}search.oninput=render;render()}
function syncNativeChoice(){for(const option of byId('native-resource-scopes').options)option.selected=nativeChoice.has(option.value);renderLegacyMappings()}
function resourceLabel(r){return r.display_name+' · '+r.resource_id+' · '+r.entitlement_mode+' · '+r.status}
function scopeImpact(scope){return [state.resourceScopes.filter(r=>r.scope===scope&&r.status==='active').map(r=>resourceLabel(state.resources.find(x=>x.id===r.oauth_resource_id))).join(' | '),[...new Set(state.allowances.filter(a=>a.scope===scope&&a.status==='active').map(a=>a.oauth_client_id))].map(id=>clientLabel(state.clients.find(c=>c.id===id))).join(' | ')]}
function clientLabel(c){return c.client_name+' · '+c.client_id+' · '+c.status}
function ownerSelectors(){const kinds=[['status-kind','status-owner'],['rotate-kind','rotate-owner']];for(const [kindId,ownerId] of kinds){const kind=byId(kindId).value;options(byId(ownerId),kind==='clients'?state.clients:state.resources,x=>x.id,kind==='clients'?clientLabel:resourceLabel)}const kind=byId('retire-kind').value;const owners=new Map((kind==='clients'?state.clients:state.resources).map(x=>[x.id,kind==='clients'?clientLabel(x):resourceLabel(x)]));options(byId('retire-credential'),kind==='clients'?state.clientCredentials:state.resourceCredentials,x=>x.id,x=>(owners.get(x.oauth_client_id||x.oauth_resource_id)||'Unknown owner')+' · '+(x.credential_id||x.id)+' · '+x.status)}
function renderCatalogue(){const filter=byId('scope-search').value.toLowerCase(),status=byId('scope-filter').value,body=byId('scope-catalogue');body.replaceChildren();for(const s of state.scopes.filter(s=>s.scope.toLowerCase().includes(filter)&&(!status||s.status===status))){const tr=document.createElement('tr'),check=document.createElement('input');check.type='checkbox';check.checked=selectedCatalogue.has(s.scope);check.onchange=()=>{check.checked?selectedCatalogue.add(s.scope):selectedCatalogue.delete(s.scope);byId('scope-selected-count').textContent=selectedCatalogue.size+' selected';scopeStatusPreview=null;invalidate('scope-status-commit','scope-status-result')};const td=document.createElement('td');td.appendChild(check);tr.appendChild(td);const resources=new Set(state.resourceScopes.filter(r=>r.oauth_scope_id===s.id&&r.status==='active').map(r=>r.oauth_resource_id));const clients=new Set(state.allowances.filter(a=>a.oauth_scope_id===s.id&&a.status==='active').map(a=>a.oauth_client_id));for(const value of [s.scope,s.description,s.status,String(s.created_at||'')+' / '+String(s.updated_at||''),resources.size+' resources, '+clients.size+' clients']){const cell=document.createElement('td');cell.textContent=value;tr.appendChild(cell)}body.appendChild(tr)}byId('scope-selected-count').textContent=selectedCatalogue.size+' selected'}
function renderResourceActions(){const resourceId=byId('bulk-resource').value,filter=byId('bulk-resource-search').value.toLowerCase(),box=byId('bulk-resource-rows');box.replaceChildren();for(const s of state.scopes.filter(s=>s.scope.toLowerCase().includes(filter))){const current=state.resourceScopes.find(r=>r.oauth_resource_id===resourceId&&r.oauth_scope_id===s.id);const label=document.createElement('label');label.textContent=s.scope+' — '+s.description+' · global '+s.status+' · registration '+(current?.status||'none');const select=document.createElement('select');for(const [value,title] of [['','No change'],['activate','Register / activate'],['disable','Disable registration']]){const option=document.createElement('option');option.value=value;option.textContent=title;select.appendChild(option)}select.value=resourceActions.get(s.scope)||'';select.onchange=()=>{select.value?resourceActions.set(s.scope,select.value):resourceActions.delete(s.scope);resourceScopePreview=null;invalidate('bulk-resource-commit','bulk-resource-result')};label.appendChild(select);box.appendChild(label)}}
function renderAll(){
  options(byId('client-resource'),state.resources.filter(r=>r.status==='active'),r=>r.id,resourceLabel);
  options(byId('allowance-resource'),state.resources,r=>r.id,resourceLabel);
  options(byId('bulk-resource'),nativeResources(),r=>r.id,resourceLabel);
  options(byId('bulk-grant-resource'),nativeResources(),r=>r.id,resourceLabel);byId('bulk-grant-resource').value=byId('grant-resource').value;
  for(const id of ['redirect-client','allowance-client'])options(byId(id),state.clients,c=>c.id,clientLabel);
  options(byId('scope-update-id'),state.scopes,s=>s.id,s=>s.scope+' · '+s.status);
  ownerSelectors();renderCatalogue();renderResourceActions();
  scopePicker('native-picker',activeScopes,nativeChoice,syncNativeChoice);
  scopePicker('client-picker',()=>registeredScopes(byId('client-resource').value).map(r=>state.scopes.find(s=>s.id===r.oauth_scope_id)).filter(Boolean),clientChoice,()=>{});
  scopePicker('bulk-grant-picker',()=>registeredScopes(byId('bulk-grant-resource').value).map(r=>state.scopes.find(s=>s.id===r.oauth_scope_id)).filter(Boolean),bulkGrantChoice,()=>{bulkGrantPreview=null;invalidate('bulk-grant-commit','bulk-grant-result')});
  syncNativeChoice();refreshGrantScopes();refreshRedirectClient();refreshAllowanceClient();
  makeTable('resource-state',['Name','Resource URI','Mode','Status','Registered scopes'],state.resources.map(r=>[r.display_name,r.resource_id,r.entitlement_mode,r.status,registeredScopes(r.id).length]));
  makeTable('client-state',['Name','Client ID','Status','Redirects','Allowances'],state.clients.map(c=>[c.client_name,c.client_id,c.status,state.redirectUris.filter(r=>r.oauth_client_id===c.id).length,state.allowances.filter(a=>a.oauth_client_id===c.id&&a.status==='active').length]));
  renderCounts();
}
function parseScopePaste(value){const rows=[],errors=[];const normalized=value.replace(/^\\uFEFF/,'').replace(/\\r\\n/g,'\\n').replace(/\\r/g,'\\n');normalized.split('\\n').forEach((line,index)=>{if(!line.trim())return;const tab=line.indexOf('\\t'),semi=line.indexOf(';'),split=tab>=0?tab:semi;if(split<0){errors.push({row:index+1,reason:'missing TAB or semicolon separator'});return}const scope=line.slice(0,split).trim(),description=line.slice(split+1).trim();if(!scope||!description){errors.push({row:index+1,reason:'scope and description are required'});return}rows.push({row:index+1,scope,description})});return {rows,errors}}
function scopePayload(){return {mode:'create_missing',update_descriptions:byId('bulk-scope-update').checked,reactivate_disabled:byId('bulk-scope-reactivate').checked,rows:parseScopePaste(byId('bulk-scopes').value).rows}}
function scopePreviewTable(data){makeTable('bulk-scope-result',['Row','Scope','Description','Result','Operation','Reason','Existing status','Existing description'],data.rows.map(r=>[r.row,r.scope,r.description,r.result,r.operation,r.reason,r.existing_status,r.existing_description]));planSummary('bulk-scope-result',data)}
async function previewBulkScopes(){bulkScopePreview=null;invalidate('bulk-scope-commit','bulk-scope-result');const parsed=parseScopePaste(byId('bulk-scopes').value);if(parsed.errors.length){makeTable('bulk-scope-result',['Row','Error'],parsed.errors.map(e=>[e.row,e.reason]));return}const payload=scopePayload(),data=await previewRequest('bulk-scope-commit','/scopes/bulk/preview',payload);if(!data)return;scopePreviewTable(data);if(!data.summary.error){bulkScopePreview=payload;byId('bulk-scope-commit').disabled=false}}
byId('bulk-scope-preview').onclick=()=>previewBulkScopes().catch(fail);byId('bulk-scope-commit').onclick=()=>{if(!bulkScopePreview)return;call('/scopes/bulk/commit','POST',bulkScopePreview).then(data=>{scopePreviewTable(data);bulkScopePreview=null;byId('bulk-scope-commit').disabled=true;return reload()}).catch(fail)};byId('bulk-scope-clear').onclick=()=>{byId('bulk-scopes').value='';byId('bulk-scope-update').checked=false;byId('bulk-scope-reactivate').checked=false;bulkScopePreview=null;invalidate('bulk-scope-commit','bulk-scope-result')};for(const id of ['bulk-scopes','bulk-scope-update','bulk-scope-reactivate'])byId(id).addEventListener('input',()=>{bulkScopePreview=null;invalidate('bulk-scope-commit','bulk-scope-result')});
for(const id of ['scope-search','scope-filter'])byId(id).addEventListener('input',renderCatalogue);byId('scope-target-status').onchange=()=>{scopeStatusPreview=null;invalidate('scope-status-commit','scope-status-result')};byId('scope-status-preview').onclick=()=>{const payload={scopes:[...selectedCatalogue].sort(),status:byId('scope-target-status').value};previewRequest('scope-status-commit','/scopes/bulk-status/preview',payload).then(data=>{if(!data)return;makeTable('scope-status-result',['Scope','Current','Operation','Resources','Clients','Registered resources (snapshot)','Allowed clients (snapshot)'],data.rows.map(r=>[r.scope,r.status,r.operation,r.affected_resources,r.affected_clients,...scopeImpact(r.scope)]));planSummary('scope-status-result',data);if(!data.summary.error){scopeStatusPreview=payload;byId('scope-status-commit').disabled=false}}).catch(fail)};byId('scope-status-commit').onclick=()=>{if(!scopeStatusPreview)return;const impact=byId('scope-status-result').textContent;if(scopeStatusPreview.status==='disabled'&&!confirm('Disable these exact scopes? Active registrations and allowances remain stored, but authorization may stop. '+impact))return;call('/scopes/bulk-status/commit','POST',scopeStatusPreview).then(showBulkResult).then(()=>{selectedCatalogue.clear();scopeStatusPreview=null;invalidate('scope-status-commit','scope-status-result');return reload()}).catch(fail)};
byId('bulk-resource-search').oninput=renderResourceActions;byId('bulk-resource').onchange=()=>{resourceActions.clear();resourceScopePreview=null;invalidate('bulk-resource-commit','bulk-resource-result');renderResourceActions()};byId('bulk-resource-preview').onclick=()=>{const payload={operations:[...resourceActions].map(([scope,action])=>({scope,action}))};previewRequest('bulk-resource-commit','/resources/'+byId('bulk-resource').value+'/scopes/bulk/preview',payload).then(data=>{if(!data)return;makeTable('bulk-resource-result',['Scope','Current','Operation','Reason'],data.rows.map(r=>[r.scope,r.current_status,r.operation,r.reason]));planSummary('bulk-resource-result',data);if(!data.summary.error){resourceScopePreview={resource:byId('bulk-resource').value,payload};byId('bulk-resource-commit').disabled=false}}).catch(fail)};byId('bulk-resource-commit').onclick=()=>{if(!resourceScopePreview)return;call('/resources/'+resourceScopePreview.resource+'/scopes/bulk/commit','POST',resourceScopePreview.payload).then(showBulkResult).then(()=>{resourceActions.clear();resourceScopePreview=null;invalidate('bulk-resource-commit','bulk-resource-result');return reload()}).catch(fail)};
for(const [kind,owner] of [['status-kind','status-owner'],['rotate-kind','rotate-owner'],['retire-kind','retire-credential']])byId(kind).onchange=ownerSelectors;
byId('client-resource').onchange=()=>{clientChoice.clear();scopePicker('client-picker',()=>registeredScopes(byId('client-resource').value).map(r=>state.scopes.find(s=>s.id===r.oauth_scope_id)).filter(Boolean),clientChoice,()=>{})};byId('allowance-resource').onchange=refreshAllowanceClient;byId('allowance-client').onchange=refreshAllowanceClient;byId('redirect-client').onchange=refreshRedirectClient;byId('bulk-grant-resource').onchange=()=>{bulkGrantChoice.clear();bulkGrantPreview=null;invalidate('bulk-grant-commit','bulk-grant-result');scopePicker('bulk-grant-picker',()=>registeredScopes(byId('bulk-grant-resource').value).map(r=>state.scopes.find(s=>s.id===r.oauth_scope_id)).filter(Boolean),bulkGrantChoice,()=>{bulkGrantPreview=null;invalidate('bulk-grant-commit','bulk-grant-result')})};
function refreshRedirectClient(){const id=byId('redirect-client').value,uris=state.redirectUris.filter(r=>r.oauth_client_id===id).map(r=>r.redirect_uri);byId('redirect-current').textContent='Current: '+(uris.join(' · ')||'none');byId('redirect-form').elements.redirects.value=uris.join('\\n');redirectPreview=null;invalidate('redirect-commit','redirect-diff')}
function refreshAllowanceClient(){const client=byId('allowance-client').value,resource=state.resources.find(r=>r.id===byId('allowance-resource').value);const rows=state.allowances.filter(a=>a.oauth_client_id===client&&a.status==='active');byId('allowance-current').textContent='Current: '+(rows.map(a=>a.resource_id+' = '+a.scope).join(' · ')||'none');allowanceChoice.clear();for(const row of rows.filter(a=>a.oauth_resource_id===resource?.id))allowanceChoice.add(row.scope);scopePicker('allowance-picker',()=>registeredScopes(byId('allowance-resource').value).map(r=>state.scopes.find(s=>s.id===r.oauth_scope_id)).filter(Boolean),allowanceChoice,()=>{allowancePreview=null;invalidate('allowance-commit','allowance-diff')});allowancePreview=null;invalidate('allowance-commit','allowance-diff')}
function desiredAllowances(){const pasted=byId('allowance-form').elements.allowances.value.trim();if(pasted)return pairs(pasted).map(([resource_id,scope])=>({resource_id,scope}));const resource=state.resources.find(r=>r.id===byId('allowance-resource').value);return [...state.allowances.filter(a=>a.oauth_client_id===byId('allowance-client').value&&a.status==='active'&&a.oauth_resource_id!==resource?.id).map(a=>({resource_id:a.resource_id,scope:a.scope})),...[...allowanceChoice].map(scope=>({resource_id:resource.resource_id,scope}))]}
byId('redirect-preview').onclick=()=>{const id=byId('redirect-client').value,payload={redirect_uris:lines(byId('redirect-form').elements.redirects.value)};previewRequest('redirect-commit','/clients/'+id+'/redirect-uris/preview',payload).then(data=>{if(!data)return;makeTable('redirect-diff',['Redirect URI','Operation'],data.diff.map(r=>[r.redirect_uri,r.operation]));planSummary('redirect-diff',data);redirectPreview={id,payload:{...payload,expected_current:data.current}};byId('redirect-commit').disabled=false}).catch(fail)};byId('redirect-form').elements.redirects.oninput=()=>{redirectPreview=null;invalidate('redirect-commit','redirect-diff')};byId('redirect-form').onsubmit=e=>{e.preventDefault();if(!redirectPreview)return;call('/clients/'+redirectPreview.id+'/redirect-uris/commit','POST',redirectPreview.payload).then(showBulkResult).then(reload).catch(fail)};
byId('allowance-preview').onclick=()=>{const id=byId('allowance-client').value,payload={allowances:desiredAllowances()};previewRequest('allowance-commit','/clients/'+id+'/allowances/preview',payload).then(data=>{if(!data)return;makeTable('allowance-diff',['Resource','Scope','Current status','Operation'],data.diff.map(r=>[r.resource_id,r.scope,r.current_status,r.operation]));planSummary('allowance-diff',data);allowancePreview={id,payload:{...payload,expected_current:data.current}};byId('allowance-commit').disabled=false}).catch(fail)};byId('allowance-form').elements.allowances.oninput=()=>{allowancePreview=null;invalidate('allowance-commit','allowance-diff')};byId('allowance-form').onsubmit=e=>{e.preventDefault();if(!allowancePreview)return;call('/clients/'+allowancePreview.id+'/allowances/commit','POST',allowancePreview.payload).then(showBulkResult).then(reload).catch(fail)};
byId('client-form').onsubmit=e=>{e.preventDefault();const f=new FormData(e.target),resource=state.resources.find(r=>r.id===byId('client-resource').value);const structured=[...clientChoice].map(scope=>({resource_id:resource.resource_id,scope}));const advanced=pairs(f.get('allowances')||'').map(([resource_id,scope])=>({resource_id,scope}));const allowances=[...structured,...advanced];if(!allowances.length){result.textContent='Select at least one exact allowance.';return}call('/clients','POST',{client_id:f.get('client_id'),client_name:f.get('client_name'),owner_team:f.get('owner_team'),owner_contact:f.get('owner_contact')||null,status:f.get('status'),grant_types:f.get('refresh')?['authorization_code','refresh_token']:['authorization_code'],redirect_uris:lines(f.get('redirects')),allowances}).then(show).then(reload).catch(fail)};
byId('client-select-all').onclick=()=>{for(const row of registeredScopes(byId('client-resource').value))clientChoice.add(row.scope);scopePicker('client-picker',()=>registeredScopes(byId('client-resource').value).map(r=>state.scopes.find(s=>s.id===r.oauth_scope_id)).filter(Boolean),clientChoice,()=>{})};
byId('allowance-select-all').onclick=()=>{for(const row of registeredScopes(byId('allowance-resource').value))allowanceChoice.add(row.scope);allowancePreview=null;invalidate('allowance-commit','allowance-diff');scopePicker('allowance-picker',()=>registeredScopes(byId('allowance-resource').value).map(r=>state.scopes.find(s=>s.id===r.oauth_scope_id)).filter(Boolean),allowanceChoice,()=>{allowancePreview=null;invalidate('allowance-commit','allowance-diff')})};
function renderSelectedUsers(){const box=byId('bulk-selected-users');box.replaceChildren();const p=document.createElement('p');p.textContent=selectedUsers.size+' existing users selected';box.appendChild(p);for(const [id,user] of selectedUsers){const b=document.createElement('button');b.type='button';b.className='secondary';b.textContent=(user.email||id)+' ×';b.onclick=()=>{selectedUsers.delete(id);renderSelectedUsers();bulkGrantPreview=null;invalidate('bulk-grant-commit','bulk-grant-result')};box.appendChild(b)}}
userSearch('bulk-user-search','bulk-user-results','bulk-user-status');byId('bulk-user-results').ondblclick=()=>byId('bulk-add-user').onclick();byId('bulk-add-user').onclick=()=>{const select=byId('bulk-user-results'),id=select.value;if(!id)return;const option=select.selectedOptions[0];selectedUsers.set(id,{email:option?.textContent||id});renderSelectedUsers();bulkGrantPreview=null;invalidate('bulk-grant-commit','bulk-grant-result')};
function bulkGrantPayload(){const date=id=>byId(id).value?new Date(byId(id).value).toISOString():undefined;return {resource_id:byId('bulk-grant-resource').value,user_ids:[...selectedUsers.keys()],emails:lines(byId('bulk-user-emails').value.replace(/^\\uFEFF/,'')),scopes:[...bulkGrantChoice].sort(),valid_from:date('bulk-grant-from'),valid_until:date('bulk-grant-until')}}
for(const id of ['bulk-user-emails','bulk-grant-from','bulk-grant-until'])byId(id).oninput=()=>{bulkGrantPreview=null;invalidate('bulk-grant-commit','bulk-grant-result')};byId('bulk-grant-preview').onclick=()=>{const payload=bulkGrantPayload();previewRequest('bulk-grant-commit','/native-grants/bulk/preview',payload).then(data=>{if(!data)return;makeTable('bulk-grant-result',['User','Scope','Resource','Operation','Reason'],data.rows.map(r=>[r.user_email||r.user_id,r.scope,r.resource_id,r.operation,r.reason]));planSummary('bulk-grant-result',data);unresolvedUserHint(data.rows);if(!data.summary.error){bulkGrantPreview=payload;byId('bulk-grant-commit').disabled=false}}).catch(fail)};byId('bulk-grant-commit').onclick=()=>{if(!bulkGrantPreview)return;call('/native-grants/bulk/commit','POST',bulkGrantPreview).then(showBulkResult).then(()=>{bulkGrantPreview=null;invalidate('bulk-grant-commit','bulk-grant-result');return reloadGrants()}).catch(fail)};
function grantFilterQuery(){const params=new URLSearchParams({resource_id:byId('grant-resource').value,offset:String(grantOffset)});for(const [id,key] of [['grant-filter-user','q'],['grant-filter-scope','scope'],['grant-filter-status','status'],['grant-filter-effective','effective']])if(byId(id).value)params.set(key,byId(id).value);return params.toString()}
async function reloadGrants(){const box=byId('native-grants');box.replaceChildren();byId('grant-resource-empty').hidden=!!byId('grant-resource').value;if(!byId('grant-resource').value){box.textContent='No native resource selected.';return}const rows=await call('/native-grants?'+grantFilterQuery());lastGrantRows=rows;const table=document.createElement('table'),head=document.createElement('tr');for(const name of ['Select','User','Scope','Resource','Status','Effective','Validity','Action']){const cell=document.createElement('th');cell.textContent=name;head.appendChild(cell)}table.appendChild(head);for(const grant of rows){const row=document.createElement('tr');const selectCell=document.createElement('td'),check=document.createElement('input');check.type='checkbox';check.checked=selectedGrants.has(grant.id);check.onchange=()=>{check.checked?selectedGrants.add(grant.id):selectedGrants.delete(grant.id);byId('grant-selected-count').textContent=selectedGrants.size+' selected';revokePreview=null;invalidate('bulk-revoke-commit','bulk-revoke-result')};selectCell.appendChild(check);row.appendChild(selectCell);for(const value of [(grant.user_email||'Pending')+' · '+(grant.user_display_name||'')+' · '+(grant.user_id||'unlinked'),grant.scope,grant.resource_display_name,grant.status,grant.effective?'effective':'not effective',String(grant.valid_from)+(grant.valid_until?' → '+grant.valid_until:'')]){const cell=document.createElement('td');cell.textContent=value;row.appendChild(cell)}const action=document.createElement('td');if(grant.status==='active'||grant.status==='pending_user_link'){const b=document.createElement('button');b.type='button';b.className='secondary';b.textContent='Revoke';b.onclick=()=>{if(!confirm(grant.status==='active'?'Revoke this exact native scope grant?':'Revoke this pending native scope grant before it links?'))return;call('/native-grants/'+grant.id+'/revoke','POST',{}).then(show).then(reloadGrants).catch(fail)};action.appendChild(b)}row.appendChild(action);table.appendChild(row)}box.appendChild(table);if(!rows.length)box.textContent='No grants match these filters.';byId('grants-next').disabled=rows.length<100||grantOffset>=10000;byId('grants-previous').disabled=grantOffset===0;byId('grant-selected-count').textContent=selectedGrants.size+' selected'}
let grantFilterTimer;for(const id of ['grant-filter-user','grant-filter-scope','grant-filter-status','grant-filter-effective'])byId(id).oninput=()=>{clearTimeout(grantFilterTimer);grantOffset=0;selectedGrants.clear();revokePreview=null;invalidate('bulk-revoke-commit','bulk-revoke-result');grantFilterTimer=setTimeout(()=>reloadGrants().catch(fail),200)};byId('grant-resource').onchange=()=>{grantOffset=0;selectedGrants.clear();singleGrantChoice.clear();revokePreview=null;invalidate('bulk-revoke-commit','bulk-revoke-result');refreshGrantScopes();syncBulkGrantResource()};byId('grants-next').onclick=()=>{grantOffset=Math.min(10000,grantOffset+100);reloadGrants().catch(fail)};byId('grants-previous').onclick=()=>{grantOffset=Math.max(0,grantOffset-100);reloadGrants().catch(fail)};
function renderCounts(){const activeKey=(state.signingKeys||[]).find(k=>k.status==='active');for(const [id,value] of [['count-scopes',state.scopes.length],['count-resources',state.resources.length],['count-clients',state.clients.length],['stat-scopes',activeScopes().length],['stat-native',nativeResources().length],['stat-legacy',legacyResources().length],['stat-clients',state.clients.length],['stat-keys',activeKey?activeKey.kid:'none']])byId(id).textContent=String(value)}
function unresolvedUserHint(rows){const list=op=>[...new Set(rows.filter(r=>r.operation===op).map(r=>r.user_email||r.user_id))];for(const [op,text] of [['create_pending',' email(s) have never signed in and will be stored as pending grants, activated automatically at first verified sign-in: '],['already_pending',' email(s) already have these pending grants: '],['email_domain_not_allowed',' email(s) use a domain that is not approved for pending grants: '],['user_not_found_or_inactive',' input(s) match a suspended/disabled user or an unknown user ID: ']]){const items=list(op);if(!items.length)continue;const p=document.createElement('p');p.className='hint';p.textContent=items.length+text+items.join(', ')+'.';byId('bulk-grant-result').appendChild(p)}}
function preauthorizeButton(email){const b=document.createElement('button');b.type='button';b.className='link';b.style.marginLeft='6px';b.textContent='Pre-authorize '+email+' as pending';b.onclick=()=>{const box=byId('bulk-user-emails');if(!lines(box.value).includes(email))box.value=(box.value.trim()?box.value.trim()+'\\n':'')+email;bulkGrantPreview=null;invalidate('bulk-grant-commit','bulk-grant-result');setGrantMode(true)};return b}
function syncBulkGrantResource(){const bulk=byId('bulk-grant-resource');if(bulk.value===byId('grant-resource').value)return;bulk.value=byId('grant-resource').value;bulk.onchange()}
function setGrantMode(bulk){byId('grant-single-pane').hidden=bulk;byId('grant-bulk-pane').hidden=!bulk;byId('grant-mode-single').className=bulk?'':'active';byId('grant-mode-bulk').className=bulk?'active':''}
byId('grant-mode-single').onclick=()=>setGrantMode(false);byId('grant-mode-bulk').onclick=()=>setGrantMode(true);
const panelNames=['overview','grants','scopes','resources','clients','security'];
function showTab(name){if(!panelNames.includes(name))name='overview';for(const panel of document.querySelectorAll('[data-panel]'))panel.hidden=panel.dataset.panel!==name;for(const tab of document.querySelectorAll('[data-tab]')){tab.className=tab.dataset.tab===name?'tab active':'tab';tab.setAttribute('aria-selected',String(tab.dataset.tab===name))}if(typeof history!=='undefined')history.replaceState(null,'','#'+name)}
for(const tab of document.querySelectorAll('[data-tab]'))tab.onclick=()=>showTab(tab.dataset.tab);for(const link of document.querySelectorAll('[data-goto]'))link.onclick=()=>showTab(link.dataset.goto);
showTab(typeof location!=='undefined'?location.hash.slice(1):'overview');
byId('bulk-revoke-preview').onclick=()=>{const payload={grant_ids:[...selectedGrants].sort()};previewRequest('bulk-revoke-commit','/native-grants/bulk-revoke/preview',payload).then(data=>{if(!data)return;makeTable('bulk-revoke-result',['User','Scope','Resource','Status','Operation'],data.rows.map(r=>[r.user_email||r.user_id,r.scope,r.resource_display_name,r.current_status,r.operation]));planSummary('bulk-revoke-result',data);if(!data.summary.error){revokePreview=payload;byId('bulk-revoke-commit').disabled=false}}).catch(fail)};byId('bulk-revoke-commit').onclick=()=>{if(!revokePreview)return;call('/native-grants/bulk-revoke/commit','POST',revokePreview).then(showBulkResult).then(()=>{selectedGrants.clear();revokePreview=null;invalidate('bulk-revoke-commit','bulk-revoke-result');return reloadGrants()}).catch(fail)};
</script></main></body></html>`;
}

export function registerOAuthAdminHttp(app: FastifyInstance, deps: OAuthAdminHttpDependencies): void {
  const mutationLimit = app.createRateLimit({
    max: 30,
    timeWindow: "1 minute",
    keyGenerator: (request) => {
      const token = readAdminToken(request, deps.config);
      return `oauth-admin:${token ? hashOpaque(token, deps.config.logIpSalt) : hashRequestField(request.ip, deps.config.logIpSalt) ?? "unknown"}`;
    }
  });

  const admin = (permission: "admin:oauth:read" | "admin:oauth:write", handler: RouteHandlerMethod): RouteHandlerMethod =>
    async (request, reply) => {
      reply.header("Cache-Control", "no-store").header("Pragma", "no-cache");
      if (request.method !== "GET") {
        if (!sameOriginMutation(request, deps.config)) throw new AppError("ADMIN_FORBIDDEN", randomToken("corr_", 16));
        const limited = await mutationLimit(request);
        if (!limited.isAllowed && (limited.isExceeded || limited.isBanned)) {
          throw new AppError("RATE_LIMITED", randomToken("corr_", 16));
        }
      }
      const actor = await requireOAuthAdminActor(request, deps, permission);
      (request as FastifyRequest & { oauthAdminActor?: AdminActor }).oauthAdminActor = actor;
      return handler.call(app, request, reply);
    };

  const ctx = (request: FastifyRequest) => auditContext(
    request,
    (request as FastifyRequest & { oauthAdminActor: AdminActor }).oauthAdminActor,
    deps.config
  );
  const run = async (request: FastifyRequest, operation: () => Promise<unknown>) => {
    const correlationId = ctx(request).correlationId;
    try { return await operation(); } catch (error) { return sendKnownError(error, correlationId); }
  };

  app.get(uiPath(deps.config), admin("admin:oauth:read", async (_request, reply: FastifyReply) =>
    reply.header("Cache-Control", "no-store").type("text/html; charset=utf-8").send(oauthAdminHtml(deps.config))));

  app.get(apiPath(deps.config, "/v1/admin/oauth"), admin("admin:oauth:read", async () => deps.service.snapshot()));
  app.get(apiPath(deps.config, "/v1/admin/oauth/legacy-tools"), admin("admin:oauth:read", async () => deps.service.legacyTools()));
  app.get(apiPath(deps.config, "/v1/admin/oauth/users"), admin("admin:oauth:read", async (request) => {
    const query = request.query as Record<string, unknown>;
    exactKeys(query, ["q"]);
    return run(request, () => deps.service.searchUsers(text(query.q)));
  }));
  app.get(apiPath(deps.config, "/v1/admin/oauth/native-grants"), admin("admin:oauth:read", async (request) => {
    const query = request.query as Record<string, unknown>;
    exactKeys(query, ["resource_id", "q", "scope", "status", "effective", "offset"]);
    const offset = query.offset === undefined ? 0 : Number(text(query.offset));
    return run(request, () => deps.service.listNativeGrants(text(query.resource_id), {
      query: query.q === undefined ? "" : text(query.q), scope: query.scope === undefined ? "" : text(query.scope),
      status: query.status === undefined ? "" : text(query.status),
      effective: query.effective === undefined ? "" : text(query.effective), offset
    }));
  }));
  app.post(apiPath(deps.config, "/v1/admin/oauth/native-grants"), { logLevel: "silent" }, admin("admin:oauth:write", async (request) => {
    const body = exactKeys(objectBody(request), ["resource_id", "user_id", "scopes", "valid_from", "valid_until"]);
    return run(request, () => deps.service.createNativeGrants({
      resourceId: text(body.resource_id), userId: text(body.user_id), scopes: strings(body.scopes),
      validFrom: optionalDate(body.valid_from), validUntil: optionalDate(body.valid_until)
    }, ctx(request)));
  }));
  app.post(apiPath(deps.config, "/v1/admin/oauth/native-grants/:id/revoke"), { logLevel: "silent" }, admin("admin:oauth:write", async (request) => {
    exactKeys(objectBody(request), []);
    return run(request, () => deps.service.revokeNativeGrant((request.params as { id: string }).id, ctx(request)));
  }));

  for (const action of ["preview", "commit"] as const) {
    app.post(apiPath(deps.config, `/v1/admin/oauth/native-grants/bulk/${action}`), { logLevel: "silent" },
      admin("admin:oauth:write", async (request) =>
        run(request, () => deps.service.bulkNativeGrants(parseBulkGrant(objectBody(request)), action === "commit", ctx(request)))));
    app.post(apiPath(deps.config, `/v1/admin/oauth/native-grants/bulk-revoke/${action}`), { logLevel: "silent" },
      admin("admin:oauth:write", async (request) => {
        const body = exactKeys(objectBody(request), ["grant_ids"]);
        return run(request, () => deps.service.bulkRevokeNativeGrants(strings(body.grant_ids), action === "commit", ctx(request)));
      }));
    app.post(apiPath(deps.config, `/v1/admin/oauth/scopes/bulk/${action}`), { logLevel: "silent" },
      admin("admin:oauth:write", async (request) =>
        run(request, () => deps.service.bulkScopes(parseBulkScopes(objectBody(request)), action === "commit", ctx(request)))));
    app.post(apiPath(deps.config, `/v1/admin/oauth/scopes/bulk-status/${action}`), { logLevel: "silent" },
      admin("admin:oauth:write", async (request) => {
        const body = exactKeys(objectBody(request), ["scopes", "status"]);
        return run(request, () => deps.service.bulkScopeStatus(strings(body.scopes), text(body.status) as "active" | "disabled",
          action === "commit", ctx(request)));
      }));
    app.post(apiPath(deps.config, `/v1/admin/oauth/resources/:id/scopes/bulk/${action}`), { logLevel: "silent" },
      admin("admin:oauth:write", async (request) => {
        const body = exactKeys(objectBody(request), ["operations"]);
        if (!Array.isArray(body.operations)) throw new AppError("VALIDATION_ERROR", randomToken("corr_", 16));
        const operations = body.operations.map((item) => {
          if (!item || typeof item !== "object" || Array.isArray(item)) throw new AppError("VALIDATION_ERROR", randomToken("corr_", 16));
          const record = exactKeys(item as Record<string, unknown>, ["scope", "action"]);
          return { scope: text(record.scope), action: text(record.action) as "activate" | "disable" };
        });
        return run(request, () => deps.service.bulkNativeResourceScopes((request.params as { id: string }).id,
          operations, action === "commit", ctx(request)));
      }));
  }

  app.post(apiPath(deps.config, "/v1/admin/oauth/scopes"), { logLevel: "silent" }, admin("admin:oauth:write", async (request) => {
    const body = exactKeys(objectBody(request), ["scope", "description"]);
    return run(request, () => deps.service.createScope({ scope: text(body.scope), description: text(body.description) }, ctx(request)));
  }));
  app.patch(apiPath(deps.config, "/v1/admin/oauth/scopes/:id"), { logLevel: "silent" }, admin("admin:oauth:write", async (request) => {
    const body = exactKeys(objectBody(request), ["description", "status"]); const { id } = request.params as { id: string };
    return run(request, () => deps.service.updateScope(id, {
      description: body.description === undefined ? undefined : text(body.description),
      status: body.status === undefined ? undefined : text(body.status) as "active" | "disabled"
    }, ctx(request)));
  }));

  app.post(apiPath(deps.config, "/v1/admin/oauth/resources"), { logLevel: "silent" }, admin("admin:oauth:write", async (request) => {
    const body = exactKeys(objectBody(request), [
      "resource_id", "display_name", "owner_team", "owner_contact", "status",
      "protected_resource_metadata_url", "entitlement_mode", "legacy_tool_slug", "scope_mappings", "scopes"
    ]);
    const common = {
      resourceId: text(body.resource_id), displayName: text(body.display_name), ownerTeam: text(body.owner_team),
      ownerContact: nullableText(body.owner_contact), status: text(body.status) as OAuthAdminResourceInput["status"],
      protectedResourceMetadataUrl: text(body.protected_resource_metadata_url)
    };
    const mode = body.entitlement_mode === undefined ? "legacy_bridge" : text(body.entitlement_mode);
    if ((mode !== "native" && mode !== "legacy_bridge") ||
        (mode === "native" && ("legacy_tool_slug" in body || "scope_mappings" in body)) ||
        (mode === "legacy_bridge" && "scopes" in body) ||
        (body.entitlement_mode === undefined && (!Object.hasOwn(body, "legacy_tool_slug") || !Object.hasOwn(body, "scope_mappings")))) {
      throw new AppError("VALIDATION_ERROR", randomToken("corr_", 16), { issues: ["resource_entitlement_payload_invalid"] });
    }
    const input: OAuthAdminResourceInput = mode === "native"
      ? { ...common, entitlementMode: "native", scopes: strings(body.scopes) }
      : { ...common, entitlementMode: "legacy_bridge", legacyToolSlug: text(body.legacy_tool_slug), scopeMappings: parseMappings(body.scope_mappings) };
    return run(request, () => deps.service.createResource(input, ctx(request)));
  }));
  app.patch(apiPath(deps.config, "/v1/admin/oauth/resources/:id/status"), { logLevel: "silent" }, admin("admin:oauth:write", async (request) => {
    const body = exactKeys(objectBody(request), ["status"]); const { id } = request.params as { id: string };
    return run(request, () => deps.service.updateRegistrationStatus("resource", id, text(body.status) as OAuthAdminResourceInput["status"], ctx(request)));
  }));
  app.put(apiPath(deps.config, "/v1/admin/oauth/resources/:id/entitlement-binding"), { logLevel: "silent" }, admin("admin:oauth:write", async (request) => {
    const body = exactKeys(objectBody(request), ["legacy_tool_slug", "status"]); const { id } = request.params as { id: string };
    return run(request, () => deps.service.setEntitlementBinding(id, text(body.legacy_tool_slug), text(body.status) as "active" | "disabled", ctx(request)));
  }));
  app.put(apiPath(deps.config, "/v1/admin/oauth/resources/:resourceId/scopes/:scopeId"), { logLevel: "silent" }, admin("admin:oauth:write", async (request) => {
    const body = exactKeys(objectBody(request), ["legacy_permission_key", "status"]); const params = request.params as { resourceId: string; scopeId: string };
    return run(request, () => deps.service.setResourceScope(params.resourceId, params.scopeId, {
      legacyPermissionKey: nullableText(body.legacy_permission_key), status: text(body.status) as "active" | "disabled"
    }, ctx(request)));
  }));

  app.post(apiPath(deps.config, "/v1/admin/oauth/clients"), { logLevel: "silent" }, admin("admin:oauth:write", async (request) => {
    const body = exactKeys(objectBody(request), [
      "client_id", "client_name", "owner_team", "owner_contact", "status",
      "grant_types", "redirect_uris", "allowances"
    ]);
    const input: OAuthAdminClientInput = {
      clientId: text(body.client_id), clientName: text(body.client_name), ownerTeam: text(body.owner_team),
      ownerContact: nullableText(body.owner_contact), status: text(body.status) as OAuthAdminClientInput["status"],
      grantTypes: strings(body.grant_types) as OAuthAdminClientInput["grantTypes"], redirectUris: strings(body.redirect_uris),
      allowances: parseAllowances(body.allowances)
    };
    return run(request, () => deps.service.createClient(input, ctx(request)));
  }));
  app.patch(apiPath(deps.config, "/v1/admin/oauth/clients/:id/status"), { logLevel: "silent" }, admin("admin:oauth:write", async (request) => {
    const body = exactKeys(objectBody(request), ["status"]); const { id } = request.params as { id: string };
    return run(request, () => deps.service.updateRegistrationStatus("client", id, text(body.status) as OAuthAdminClientInput["status"], ctx(request)));
  }));
  for (const action of ["preview", "commit"] as const) {
    app.post(apiPath(deps.config, `/v1/admin/oauth/clients/:id/allowances/${action}`), { logLevel: "silent" },
      admin("admin:oauth:write", async (request) => {
        const body = exactKeys(objectBody(request), ["allowances", "expected_current"]);
        return run(request, () => deps.service.previewCommitAllowances((request.params as { id: string }).id,
          parseAllowances(body.allowances), body.expected_current === undefined ? null : parseAllowanceState(body.expected_current),
          action === "commit", ctx(request)));
      }));
    app.post(apiPath(deps.config, `/v1/admin/oauth/clients/:id/redirect-uris/${action}`), { logLevel: "silent" },
      admin("admin:oauth:write", async (request) => {
        const body = exactKeys(objectBody(request), ["redirect_uris", "expected_current"]);
        return run(request, () => deps.service.previewCommitRedirectUris((request.params as { id: string }).id,
          strings(body.redirect_uris), body.expected_current === undefined ? null : strings(body.expected_current),
          action === "commit", ctx(request)));
      }));
  }
  app.put(apiPath(deps.config, "/v1/admin/oauth/clients/:id/redirect-uris"), { logLevel: "silent" }, admin("admin:oauth:write", async (request) => {
    const body = exactKeys(objectBody(request), ["redirect_uris"]); const { id } = request.params as { id: string };
    return run(request, () => deps.service.replaceRedirectUris(id, strings(body.redirect_uris), ctx(request)));
  }));
  app.put(apiPath(deps.config, "/v1/admin/oauth/clients/:id/allowances"), { logLevel: "silent" }, admin("admin:oauth:write", async (request) => {
    const body = exactKeys(objectBody(request), ["allowances"]); const { id } = request.params as { id: string };
    return run(request, () => deps.service.replaceAllowances(id, parseAllowances(body.allowances), ctx(request)));
  }));

  for (const kind of ["client", "resource"] as const) {
    const plural = kind === "client" ? "clients" : "resources";
    app.post(apiPath(deps.config, `/v1/admin/oauth/${plural}/:id/credentials/rotate`), { logLevel: "silent" }, admin("admin:oauth:write", async (request) => {
      const { id } = request.params as { id: string };
      return run(request, () => deps.service.rotateCredential(kind, id, ctx(request)));
    }));
    app.post(apiPath(deps.config, `/v1/admin/oauth/${plural}/credentials/:credentialId/retire`), { logLevel: "silent" }, admin("admin:oauth:write", async (request) => {
      const { credentialId } = request.params as { credentialId: string };
      return run(request, () => deps.service.retireCredential(kind, credentialId, ctx(request)));
    }));
  }

  app.post(apiPath(deps.config, "/v1/admin/oauth/signing-keys"), { logLevel: "silent" }, admin("admin:oauth:write", async (request) =>
    run(request, () => deps.service.generateSigningKey(ctx(request)))));
  for (const action of ["publish", "activate", "retire", "disable"] as const) {
    app.post(apiPath(deps.config, `/v1/admin/oauth/signing-keys/:id/${action}`), { logLevel: "silent" }, admin("admin:oauth:write", async (request) => {
      const { id } = request.params as { id: string };
      return run(request, () => action === "publish" ? deps.service.publishSigningKey(id, ctx(request))
        : action === "activate" ? deps.service.activateSigningKey(id, ctx(request))
        : action === "retire" ? deps.service.retireSigningKey(id, ctx(request))
        : deps.service.disableSigningKey(id, ctx(request)));
    }));
  }
}
