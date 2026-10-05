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
:root{font-family:Inter,ui-sans-serif,system-ui;color:rgb(16 24 40);background:rgb(247 248 250)}body{margin:0}header{background:rgb(0 75 99);color:white;padding:18px 28px;display:flex;justify-content:space-between}header a{color:white}main{max-width:1280px;margin:auto;padding:28px}.notice{border-left:5px solid rgb(245 158 11);background:rgb(255 247 230);padding:16px;margin-bottom:20px}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:18px}.card{background:white;border:1px solid rgb(229 231 235);border-radius:16px;padding:18px;box-shadow:0 8px 24px rgba(15,23,42,.06)}label{display:block;font-weight:650;margin-top:10px}input,textarea,select{box-sizing:border-box;width:100%;margin-top:5px;padding:9px;border:1px solid rgb(152 162 179);border-radius:8px}button{margin-top:12px;padding:10px 14px;border:0;border-radius:8px;background:rgb(0 75 99);color:white;cursor:pointer}button.secondary{background:rgb(102 112 133)}.result{white-space:pre-wrap;overflow:auto;background:rgb(249 250 251);padding:10px;border-radius:8px;max-height:320px}.secret{border:2px solid rgb(116 198 157);background:rgb(240 255 247);padding:12px;word-break:break-all}.muted{color:rgb(102 112 133);font-size:.9rem}table{width:100%;border-collapse:collapse;font-size:.88rem}th,td{text-align:left;border-bottom:1px solid rgb(234 236 240);padding:8px;vertical-align:top}</style></head>
<body><header><strong>Access Layer · OAuth administration</strong><a href="${legacyAdmin}">Legacy administration</a></header><main>
<div class="notice"><strong>Temporary P0 compatibility state.</strong> <code>legacy_bridge</code> exists for old consumers; its tool binding is only an entitlement anchor. New native resources use direct human grants. Do not use a legacy tool as a client ID, audience, or introspection credential.</div>
<p class="muted">Protocol enablement remains controlled separately by <code>OAUTH_P0_ENABLED</code>. Creating administration records does not enable OAuth.</p>
<div class="grid">
<section class="card"><h2>1. Scope</h2><form id="scope-form"><label>Canonical scope<input name="scope" placeholder="project:domain:action" required></label><label>Description<input name="description" required></label><button>Create scope</button></form><h3>Bulk scope catalogue</h3><p class="muted">One row per line: scope ; description or scope[TAB]description. Commas remain in descriptions.</p><textarea id="bulk-scopes" rows="8" aria-label="Bulk scope catalogue"></textarea><label><input type="checkbox" id="bulk-scope-update" style="width:auto"> Update descriptions of existing scopes</label><label><input type="checkbox" id="bulk-scope-reactivate" style="width:auto"> Reactivate disabled scopes</label><button type="button" id="bulk-scope-preview">Preview</button> <button type="button" id="bulk-scope-commit" disabled>Commit</button> <button type="button" class="secondary" id="bulk-scope-clear">Clear</button><div id="bulk-scope-result"></div></section>
<section class="card"><h2>Scope catalogue</h2><label>Scope search/filter<input id="scope-search" placeholder="Filter by canonical scope"></label><label>Status<select id="scope-filter"><option value="">All</option><option>active</option><option>disabled</option></select></label><p id="scope-selected-count">0 selected</p><button type="button" id="scope-status-preview">Preview selected lifecycle</button><button type="button" id="scope-status-commit" disabled>Commit selected lifecycle</button><select id="scope-target-status"><option value="disabled">Disable selected</option><option value="active">Activate selected</option></select><div id="scope-status-result"></div><div style="overflow:auto"><table><thead><tr><th>Select</th><th>Scope</th><th>Description</th><th>Status</th><th>Created/updated</th><th>Usage</th></tr></thead><tbody id="scope-catalogue"></tbody></table></div></section>
<section class="card"><h2>2. Resource</h2><form id="resource-form"><label>HTTPS resource ID<input name="resource_id" required></label><label>Display name<input name="display_name" required></label><label>Owner team<input name="owner_team" required></label><label>Owner contact<input name="owner_contact"></label><label>Status<select name="status"><option>draft</option><option>active</option><option>disabled</option></select></label><label>Protected-resource metadata URL<input name="metadata_url" required></label><label>Entitlement mode<select name="entitlement_mode" id="resource-mode"><option value="native" selected>Native</option><option value="legacy_bridge">Legacy bridge</option></select></label><label>Active OAuth scopes<select name="native_scopes" id="native-resource-scopes" multiple hidden></select></label><div id="native-picker"></div><div id="native-resource-fields"><p class="muted">These scopes use native human grants without a legacy tool.</p></div><div id="legacy-resource-fields" hidden><label>Bound legacy tool slug<select name="legacy_tool_slug" id="legacy-resource-tool"></select></label><div id="legacy-resource-mappings"></div></div><button>Create resource + one-time introspection credential</button></form></section>
<section class="card"><h2>3. Confidential client</h2><form id="client-form"><label>Client ID<input name="client_id" required></label><label>Client name<input name="client_name" required></label><label>Owner team<input name="owner_team" required></label><label>Owner contact<input name="owner_contact"></label><label>Status<select name="status"><option>draft</option><option>active</option><option>disabled</option></select></label><label><input style="width:auto" type="checkbox" name="refresh"> Allow refresh_token</label><label>Exact redirect URIs (one per line)<textarea name="redirects" required></textarea></label><label>Resource<select id="client-resource" required></select></label><div id="client-picker"></div><button type="button" id="client-select-all">Allow all selected resource scopes</button><details><summary>Advanced allowance paste (resource URI = scope)</summary><textarea name="allowances" aria-label="Advanced allowance paste"></textarea></details><button>Create client + one-time secret</button></form></section>
<section class="card"><h2>Signing keys</h2><p class="muted">Private keys are generated server-side into the configured protected root and are never returned.</p><button id="generate-key">Generate staged RSA key</button><div id="key-actions"></div></section>
<section class="card"><h2>Registration lifecycle</h2><form id="status-form"><label>Kind<select name="kind" id="status-kind"><option value="clients">client</option><option value="resources">resource</option></select></label><label>Registration<select name="id" id="status-owner" required></select></label><label>Status<select name="status"><option>draft</option><option>active</option><option>disabled</option></select></label><button>Update status</button></form></section>
<section class="card"><h2>Client redirects and allowances</h2><form id="redirect-form"><label>Client<select name="id" id="redirect-client" required></select></label><p id="redirect-current" class="muted"></p><label>Exact redirect URIs (one per line)<textarea name="redirects" required></textarea></label><button type="button" id="redirect-preview">Preview redirect diff</button><button type="submit" id="redirect-commit" disabled>Commit redirect replacement</button><div id="redirect-diff"></div></form><form id="allowance-form"><label>Client<select name="id" id="allowance-client" required></select></label><label>Resource<select id="allowance-resource" required></select></label><p id="allowance-current" class="muted"></p><div id="allowance-picker"></div><button type="button" id="allowance-select-all">Select all active registered scopes</button><details><summary>Advanced allowance paste (resource URI = scope)</summary><textarea name="allowances" aria-label="Advanced allowance paste"></textarea></details><button type="button" id="allowance-preview">Preview allowance diff</button><button type="submit" id="allowance-commit" disabled>Commit allowance replacement</button><div id="allowance-diff"></div></form></section>
<section class="card"><h2>Native resource scope administration</h2><label>Native resource<select id="bulk-resource"></select></label><label>Filter scopes<input id="bulk-resource-search"></label><p class="muted">Choose an explicit action for each scope. Unchanged registrations stay untouched.</p><div id="bulk-resource-rows"></div><button id="bulk-resource-preview">Preview registrations</button><button id="bulk-resource-commit" disabled>Commit registrations</button><div id="bulk-resource-result"></div></section>
<section class="card"><h2>Resource scope registration</h2><form id="mapping-form"><label>Resource<select name="resource_id" id="mapping-resource" required></select></label><label>Scope<select name="scope_id" id="mapping-scope" required></select></label><div id="mapping-legacy"><label>Exact legacy permission key<select name="permission" id="mapping-permission"></select></label></div><label>Status<select name="status"><option>active</option><option>disabled</option></select></label><button>Set scope registration</button></form></section>
<section class="card"><h2>Temporary entitlement binding</h2><form id="binding-form"><label>Legacy bridge resource<select name="resource_id" id="binding-resource" required></select></label><label>Legacy tool slug<select name="tool" id="binding-tool" required></select></label><label>Status<select name="status"><option>active</option><option>disabled</option></select></label><button>Replace or disable binding</button></form></section>
<section class="card"><h2>Native human grants</h2><p class="muted">Users must have logged into Access Layer at least once before receiving a native grant.</p><form id="native-grant-form"><label>Native resource<select name="resource_id" id="grant-resource" required></select></label><label>Search existing user by email or name<input id="grant-user-search" autocomplete="off"></label><label>Existing user<select name="user_id" id="grant-user" required></select></label><label>Registered scopes<select name="scopes" id="grant-scopes" multiple hidden></select></label><div id="single-grant-picker"></div><label>Valid from (optional)<input type="datetime-local" name="valid_from"></label><label>Valid until (optional)<input type="datetime-local" name="valid_until"></label><button>Grant selected scopes</button></form><h3>Bulk native grants</h3><label>Native resource<select id="bulk-grant-resource"></select></label><label>Search existing users<input id="bulk-user-search"></label><select id="bulk-user-results"></select><button type="button" id="bulk-add-user">Add selected user</button><div id="bulk-selected-users"></div><label>Paste existing emails, one per line<textarea id="bulk-user-emails" rows="5"></textarea></label><div id="bulk-grant-picker"></div><label>Valid from (optional)<input id="bulk-grant-from" type="datetime-local"></label><label>Valid until (optional)<input id="bulk-grant-until" type="datetime-local"></label><button id="bulk-grant-preview">Preview grants</button><button id="bulk-grant-commit" disabled>Commit grants</button><div id="bulk-grant-result"></div><h3>Existing grants</h3><label>User/email filter<input id="grant-filter-user"></label><label>Scope filter<input id="grant-filter-scope"></label><label>Persisted status<select id="grant-filter-status"><option value="">All</option><option>active</option><option>expired</option><option>revoked</option><option>pending_user_link</option></select></label><label>Effective<select id="grant-filter-effective"><option value="">All</option><option value="true">Effective</option><option value="false">Not effective</option></select></label><button class="secondary" id="reload-grants">Reload grants</button><p id="grant-selected-count">0 selected</p><button id="bulk-revoke-preview">Preview revoke selected grants</button><button id="bulk-revoke-commit" disabled>Commit exact revocations</button><div id="bulk-revoke-result"></div><div id="native-grants"></div><button id="grants-previous" disabled>Previous page</button><button id="grants-next">Next page</button></section>
<section class="card"><h2>Credential lifecycle</h2><form id="rotate-form"><label>Kind<select name="kind" id="rotate-kind"><option value="clients">client</option><option value="resources">resource</option></select></label><label>Owner<select name="id" id="rotate-owner" required></select></label><button>Rotate and show secret once</button></form><form id="retire-form"><label>Kind<select name="kind" id="retire-kind"><option value="clients">client</option><option value="resources">resource</option></select></label><label>Credential record<select name="id" id="retire-credential" required></select></label><button>Retire credential</button></form></section>
<section class="card"><h2>Single scope edit</h2><form id="scope-update-form"><label>Scope<select name="id" id="scope-update-id" required></select></label><label>Description (optional)<input name="description"></label><label>Status<select name="status"><option value="">unchanged</option><option>active</option><option>disabled</option></select></label><button>Update scope</button></form></section>
</div><section class="card" style="margin-top:18px"><h2>One-time credential result</h2><div id="secret" class="secret">No credential generated in this session.</div></section>
<section class="card" style="margin-top:18px"><h2>Current OAuth administration state</h2><button class="secondary" id="reload">Reload</button><h3>Resources</h3><div id="resource-state"></div><h3>Clients</h3><div id="client-state"></div><details><summary>Advanced snapshot / UUID details</summary><div id="state" class="result">Loading…</div></details></section>
<section class="card" style="margin-top:18px"><h2>Operation result</h2><div id="result" class="result"></div></section>
<script>const api=${JSON.stringify(endpoint)};const result=document.querySelector('#result');const secret=document.querySelector('#secret');
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
function refreshGrantScopes(){const id=document.querySelector('#grant-resource').value;options(document.querySelector('#grant-scopes'),registeredScopes(id),r=>r.scope,r=>r.scope);scopePicker('single-grant-picker',()=>registeredScopes(id).map(r=>state.scopes.find(s=>s.id===r.oauth_scope_id)).filter(Boolean),singleGrantChoice,()=>{for(const option of byId('grant-scopes').options)option.selected=singleGrantChoice.has(option.value)});for(const option of byId('grant-scopes').options)option.selected=singleGrantChoice.has(option.value);reloadGrants().catch(e=>result.textContent=e.message)}
let userSearchTimer;document.querySelector('#grant-user-search').oninput=e=>{clearTimeout(userSearchTimer);const q=e.target.value.trim();if(q.length<2){document.querySelector('#grant-user').replaceChildren();return}userSearchTimer=setTimeout(()=>call('/users?q='+encodeURIComponent(q)).then(users=>options(document.querySelector('#grant-user'),users,u=>u.id,u=>u.email+' · '+(u.display_name||'')+' · '+u.status)).catch(x=>result.textContent=x.message),250)};
document.querySelector('#resource-mode').onchange=toggleResourceMode;document.querySelector('#legacy-resource-tool').onchange=renderLegacyMappings;document.querySelector('#native-resource-scopes').onchange=renderLegacyMappings;document.querySelector('#mapping-resource').onchange=refreshMappingControls;document.querySelector('#grant-resource').onchange=refreshGrantScopes;document.querySelector('#reload-grants').onclick=()=>reloadGrants().catch(e=>result.textContent=e.message);
async function call(path,method='GET',body){if(method!=='GET')secret.textContent='No new credential; previous one-time value discarded.';const r=await fetch(api+path,{method,headers:body?{'content-type':'application/json'}:{},body:body?JSON.stringify(body):undefined});const data=await r.json().catch(()=>({}));if(!r.ok)throw new Error(JSON.stringify(data));return data}
function show(data){const visible={...data};const s=visible.client_secret||visible.resource_credential_secret;delete visible.client_secret;delete visible.resource_credential_secret;result.textContent=JSON.stringify(visible,null,2);secret.textContent=s?(data.resource_credential_id?data.resource_credential_id+' : ':'')+s+' — copy now; it cannot be shown again.':'No new credential; previous one-time value discarded.'}
async function reload(){const [data,tools]=await Promise.all([call(''),call('/legacy-tools')]);state=data;legacyTools=tools;document.querySelector('#state').textContent=JSON.stringify(data,null,2);options(document.querySelector('#native-resource-scopes'),data.scopes.filter(s=>s.status==='active'),s=>s.scope,s=>s.scope);options(document.querySelector('#legacy-resource-tool'),tools,t=>t.slug,t=>t.display_name+' ('+t.slug+')');options(document.querySelector('#binding-tool'),tools,t=>t.slug,t=>t.display_name+' ('+t.slug+')');options(document.querySelector('#mapping-resource'),data.resources,r=>r.id,r=>r.display_name+' ('+r.entitlement_mode+')');options(document.querySelector('#mapping-scope'),data.scopes.filter(s=>s.status==='active'),s=>s.id,s=>s.scope);options(document.querySelector('#binding-resource'),legacyResources(),r=>r.id,r=>r.display_name);options(document.querySelector('#grant-resource'),nativeResources(),r=>r.id,r=>r.display_name);toggleResourceMode();refreshMappingControls();await reloadGrants();renderAll();const box=document.querySelector('#key-actions');box.innerHTML='';for(const k of data.signingKeys||[]){const row=document.createElement('div');row.textContent=k.kid+' · '+k.status+(k.status==='published'?' · activation eligible after '+k.activates_at:'')+(k.retire_after?' · verification grace ends '+k.retire_after:'');const actions=k.status==='staged'?['publish','disable']:k.status==='published'?['activate','disable']:k.status==='active'?['retire']:[];for(const action of actions){const b=document.createElement('button');b.className='secondary';b.style.marginLeft='6px';b.textContent=action;if(action==='activate'&&Date.now()<Date.parse(k.activates_at)){b.disabled=true;b.title='Publication lead has not elapsed'}b.onclick=()=>call('/signing-keys/'+k.id+'/'+action,'POST',{}).then(show).then(reload).catch(e=>result.textContent=e.message);row.appendChild(b)}box.appendChild(row)}}
document.querySelector('#scope-form').onsubmit=e=>{e.preventDefault();const f=new FormData(e.target);call('/scopes','POST',{scope:f.get('scope'),description:f.get('description')}).then(show).then(reload).catch(x=>result.textContent=x.message)};
document.querySelector('#resource-form').onsubmit=e=>{e.preventDefault();const f=new FormData(e.target);const mode=f.get('entitlement_mode');const base={resource_id:f.get('resource_id'),display_name:f.get('display_name'),owner_team:f.get('owner_team'),owner_contact:f.get('owner_contact')||null,status:f.get('status'),protected_resource_metadata_url:f.get('metadata_url'),entitlement_mode:mode};const payload=mode==='native'?{...base,scopes:selectedValues(document.querySelector('#native-resource-scopes'))}:{...base,legacy_tool_slug:f.get('legacy_tool_slug'),scope_mappings:Array.from(document.querySelectorAll('#legacy-resource-mappings select')).map(s=>({scope:s.dataset.scope,legacy_permission_key:s.value}))};call('/resources','POST',payload).then(show).then(reload).catch(x=>result.textContent=x.message)};
document.querySelector('#native-grant-form').onsubmit=e=>{e.preventDefault();const f=new FormData(e.target);const date=v=>v?new Date(v).toISOString():undefined;call('/native-grants','POST',{resource_id:f.get('resource_id'),user_id:f.get('user_id'),scopes:selectedValues(document.querySelector('#grant-scopes')),valid_from:date(f.get('valid_from')),valid_until:date(f.get('valid_until'))}).then(show).then(reloadGrants).catch(x=>result.textContent=x.message)};
document.querySelector('#status-form').onsubmit=e=>{e.preventDefault();const f=new FormData(e.target);call('/'+f.get('kind')+'/'+f.get('id')+'/status','PATCH',{status:f.get('status')}).then(show).then(reload).catch(x=>result.textContent=x.message)};
document.querySelector('#mapping-form').onsubmit=e=>{e.preventDefault();const f=new FormData(e.target);const resource=state.resources.find(r=>r.id===f.get('resource_id'));call('/resources/'+f.get('resource_id')+'/scopes/'+f.get('scope_id'),'PUT',{legacy_permission_key:resource?.entitlement_mode==='native'?null:f.get('permission'),status:f.get('status')}).then(show).then(reload).catch(x=>result.textContent=x.message)};
document.querySelector('#binding-form').onsubmit=e=>{e.preventDefault();const f=new FormData(e.target);call('/resources/'+f.get('resource_id')+'/entitlement-binding','PUT',{legacy_tool_slug:f.get('tool'),status:f.get('status')}).then(show).then(reload).catch(x=>result.textContent=x.message)};
document.querySelector('#rotate-form').onsubmit=e=>{e.preventDefault();const f=new FormData(e.target);call('/'+f.get('kind')+'/'+f.get('id')+'/credentials/rotate','POST',{}).then(show).then(reload).catch(x=>result.textContent=x.message)};
document.querySelector('#retire-form').onsubmit=e=>{e.preventDefault();const f=new FormData(e.target);call('/'+f.get('kind')+'/credentials/'+f.get('id')+'/retire','POST',{}).then(show).then(reload).catch(x=>result.textContent=x.message)};
document.querySelector('#scope-update-form').onsubmit=e=>{e.preventDefault();const f=new FormData(e.target),body={};if(f.get('description'))body.description=f.get('description');if(f.get('status'))body.status=f.get('status');call('/scopes/'+f.get('id'),'PATCH',body).then(show).then(reload).catch(x=>result.textContent=x.message)};
document.querySelector('#generate-key').onclick=()=>call('/signing-keys','POST',{}).then(show).then(reload).catch(x=>result.textContent=x.message);document.querySelector('#reload').onclick=reload;reload().catch(x=>result.textContent=x.message);
const byId=id=>document.getElementById(id);const activeScopes=()=>state.scopes.filter(s=>s.status==='active');
const singleGrantChoice=new Set(),nativeChoice=new Set(),clientChoice=new Set(),allowanceChoice=new Set(),bulkGrantChoice=new Set(),selectedCatalogue=new Set(),selectedUsers=new Map(),selectedGrants=new Set(),resourceActions=new Map();
let bulkScopePreview=null,scopeStatusPreview=null,resourceScopePreview=null,allowancePreview=null,redirectPreview=null,bulkGrantPreview=null,revokePreview=null,grantOffset=0,lastGrantRows=[];
const previewVersions={};function invalidate(button,box){previewVersions[button]=(previewVersions[button]||0)+1;byId(button).disabled=true;if(box)byId(box).replaceChildren()}
async function previewRequest(button,path,payload){invalidate(button);const version=previewVersions[button];const data=await call(path,'POST',payload);return previewVersions[button]===version?data:null}
function makeTable(boxId,heads,rows){const box=byId(boxId);box.replaceChildren();const table=document.createElement('table');const head=document.createElement('thead');const tr=document.createElement('tr');for(const h of heads){const th=document.createElement('th');th.textContent=h;tr.appendChild(th)}head.appendChild(tr);table.appendChild(head);const body=document.createElement('tbody');for(const cells of rows){const row=document.createElement('tr');for(const value of cells){const td=document.createElement('td');td.textContent=value===null||value===undefined?'':String(value);row.appendChild(td)}body.appendChild(row)}table.appendChild(body);box.appendChild(table)}
function planSummary(boxId,data){const p=document.createElement('p');const counts=data.summary||data.diff?.reduce((all,row)=>{all[row.operation]=(all[row.operation]||0)+1;return all},{});p.textContent=(data.committed!==undefined?'Committed: '+data.committed+' · ':'')+Object.entries(counts||{}).map(([key,value])=>key+': '+value).join(' · ');byId(boxId).appendChild(p)}
function showBulkResult(data){if(data.rows)makeTable('result',['Entity','Scope','Operation','Reason'],data.rows.map(r=>[r.user_email||r.user_id||r.resource_display_name||r.grant_id||r.scope,r.scope,r.operation,r.reason]));else makeTable('result',['Resource / redirect','Scope','Current status','Operation'],(data.diff||[]).map(r=>[r.resource_id||r.redirect_uri,r.scope,r.current_status,r.operation]));planSummary('result',data)}
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
  options(byId('bulk-grant-resource'),nativeResources(),r=>r.id,resourceLabel);
  for(const id of ['redirect-client','allowance-client'])options(byId(id),state.clients,c=>c.id,clientLabel);
  options(byId('scope-update-id'),state.scopes,s=>s.id,s=>s.scope+' · '+s.status);
  ownerSelectors();renderCatalogue();renderResourceActions();
  scopePicker('native-picker',activeScopes,nativeChoice,syncNativeChoice);
  scopePicker('client-picker',()=>registeredScopes(byId('client-resource').value).map(r=>state.scopes.find(s=>s.id===r.oauth_scope_id)).filter(Boolean),clientChoice,()=>{});
  scopePicker('bulk-grant-picker',()=>registeredScopes(byId('bulk-grant-resource').value).map(r=>state.scopes.find(s=>s.id===r.oauth_scope_id)).filter(Boolean),bulkGrantChoice,()=>{bulkGrantPreview=null;invalidate('bulk-grant-commit','bulk-grant-result')});
  syncNativeChoice();refreshGrantScopes();refreshRedirectClient();refreshAllowanceClient();
  makeTable('resource-state',['Name','Resource URI','Mode','Status','Registered scopes'],state.resources.map(r=>[r.display_name,r.resource_id,r.entitlement_mode,r.status,registeredScopes(r.id).length]));
  makeTable('client-state',['Name','Client ID','Status','Redirects','Allowances'],state.clients.map(c=>[c.client_name,c.client_id,c.status,state.redirectUris.filter(r=>r.oauth_client_id===c.id).length,state.allowances.filter(a=>a.oauth_client_id===c.id&&a.status==='active').length]));
}
function parseScopePaste(value){const rows=[],errors=[];const normalized=value.replace(/^\\uFEFF/,'').replace(/\\r\\n/g,'\\n').replace(/\\r/g,'\\n');normalized.split('\\n').forEach((line,index)=>{if(!line.trim())return;const tab=line.indexOf('\\t'),semi=line.indexOf(';'),split=tab>=0?tab:semi;if(split<0){errors.push({row:index+1,reason:'missing TAB or semicolon separator'});return}const scope=line.slice(0,split).trim(),description=line.slice(split+1).trim();if(!scope||!description){errors.push({row:index+1,reason:'scope and description are required'});return}rows.push({row:index+1,scope,description})});return {rows,errors}}
function scopePayload(){return {mode:'create_missing',update_descriptions:byId('bulk-scope-update').checked,reactivate_disabled:byId('bulk-scope-reactivate').checked,rows:parseScopePaste(byId('bulk-scopes').value).rows}}
function scopePreviewTable(data){makeTable('bulk-scope-result',['Row','Scope','Description','Result','Operation','Reason','Existing status','Existing description'],data.rows.map(r=>[r.row,r.scope,r.description,r.result,r.operation,r.reason,r.existing_status,r.existing_description]));planSummary('bulk-scope-result',data)}
async function previewBulkScopes(){bulkScopePreview=null;invalidate('bulk-scope-commit','bulk-scope-result');const parsed=parseScopePaste(byId('bulk-scopes').value);if(parsed.errors.length){makeTable('bulk-scope-result',['Row','Error'],parsed.errors.map(e=>[e.row,e.reason]));return}const payload=scopePayload(),data=await previewRequest('bulk-scope-commit','/scopes/bulk/preview',payload);if(!data)return;scopePreviewTable(data);if(!data.summary.error){bulkScopePreview=payload;byId('bulk-scope-commit').disabled=false}}
byId('bulk-scope-preview').onclick=()=>previewBulkScopes().catch(e=>result.textContent=e.message);byId('bulk-scope-commit').onclick=()=>{if(!bulkScopePreview)return;call('/scopes/bulk/commit','POST',bulkScopePreview).then(data=>{scopePreviewTable(data);bulkScopePreview=null;byId('bulk-scope-commit').disabled=true;return reload()}).catch(e=>result.textContent=e.message)};byId('bulk-scope-clear').onclick=()=>{byId('bulk-scopes').value='';byId('bulk-scope-update').checked=false;byId('bulk-scope-reactivate').checked=false;bulkScopePreview=null;invalidate('bulk-scope-commit','bulk-scope-result')};for(const id of ['bulk-scopes','bulk-scope-update','bulk-scope-reactivate'])byId(id).addEventListener('input',()=>{bulkScopePreview=null;invalidate('bulk-scope-commit','bulk-scope-result')});
for(const id of ['scope-search','scope-filter'])byId(id).addEventListener('input',renderCatalogue);byId('scope-target-status').onchange=()=>{scopeStatusPreview=null;invalidate('scope-status-commit','scope-status-result')};byId('scope-status-preview').onclick=()=>{const payload={scopes:[...selectedCatalogue].sort(),status:byId('scope-target-status').value};previewRequest('scope-status-commit','/scopes/bulk-status/preview',payload).then(data=>{if(!data)return;makeTable('scope-status-result',['Scope','Current','Operation','Resources','Clients','Registered resources (snapshot)','Allowed clients (snapshot)'],data.rows.map(r=>[r.scope,r.status,r.operation,r.affected_resources,r.affected_clients,...scopeImpact(r.scope)]));planSummary('scope-status-result',data);if(!data.summary.error){scopeStatusPreview=payload;byId('scope-status-commit').disabled=false}}).catch(e=>result.textContent=e.message)};byId('scope-status-commit').onclick=()=>{if(!scopeStatusPreview)return;const impact=byId('scope-status-result').textContent;if(scopeStatusPreview.status==='disabled'&&!confirm('Disable these exact scopes? Active registrations and allowances remain stored, but authorization may stop. '+impact))return;call('/scopes/bulk-status/commit','POST',scopeStatusPreview).then(showBulkResult).then(()=>{selectedCatalogue.clear();scopeStatusPreview=null;invalidate('scope-status-commit','scope-status-result');return reload()}).catch(e=>result.textContent=e.message)};
byId('bulk-resource-search').oninput=renderResourceActions;byId('bulk-resource').onchange=()=>{resourceActions.clear();resourceScopePreview=null;invalidate('bulk-resource-commit','bulk-resource-result');renderResourceActions()};byId('bulk-resource-preview').onclick=()=>{const payload={operations:[...resourceActions].map(([scope,action])=>({scope,action}))};previewRequest('bulk-resource-commit','/resources/'+byId('bulk-resource').value+'/scopes/bulk/preview',payload).then(data=>{if(!data)return;makeTable('bulk-resource-result',['Scope','Current','Operation','Reason'],data.rows.map(r=>[r.scope,r.current_status,r.operation,r.reason]));planSummary('bulk-resource-result',data);if(!data.summary.error){resourceScopePreview={resource:byId('bulk-resource').value,payload};byId('bulk-resource-commit').disabled=false}}).catch(e=>result.textContent=e.message)};byId('bulk-resource-commit').onclick=()=>{if(!resourceScopePreview)return;call('/resources/'+resourceScopePreview.resource+'/scopes/bulk/commit','POST',resourceScopePreview.payload).then(showBulkResult).then(()=>{resourceActions.clear();resourceScopePreview=null;invalidate('bulk-resource-commit','bulk-resource-result');return reload()}).catch(e=>result.textContent=e.message)};
for(const [kind,owner] of [['status-kind','status-owner'],['rotate-kind','rotate-owner'],['retire-kind','retire-credential']])byId(kind).onchange=ownerSelectors;
byId('client-resource').onchange=()=>{clientChoice.clear();scopePicker('client-picker',()=>registeredScopes(byId('client-resource').value).map(r=>state.scopes.find(s=>s.id===r.oauth_scope_id)).filter(Boolean),clientChoice,()=>{})};byId('allowance-resource').onchange=refreshAllowanceClient;byId('allowance-client').onchange=refreshAllowanceClient;byId('redirect-client').onchange=refreshRedirectClient;byId('bulk-grant-resource').onchange=()=>{bulkGrantChoice.clear();bulkGrantPreview=null;invalidate('bulk-grant-commit','bulk-grant-result');scopePicker('bulk-grant-picker',()=>registeredScopes(byId('bulk-grant-resource').value).map(r=>state.scopes.find(s=>s.id===r.oauth_scope_id)).filter(Boolean),bulkGrantChoice,()=>{bulkGrantPreview=null;invalidate('bulk-grant-commit','bulk-grant-result')})};
function refreshRedirectClient(){const id=byId('redirect-client').value,uris=state.redirectUris.filter(r=>r.oauth_client_id===id).map(r=>r.redirect_uri);byId('redirect-current').textContent='Current: '+(uris.join(' · ')||'none');byId('redirect-form').elements.redirects.value=uris.join('\\n');redirectPreview=null;invalidate('redirect-commit','redirect-diff')}
function refreshAllowanceClient(){const client=byId('allowance-client').value,resource=state.resources.find(r=>r.id===byId('allowance-resource').value);const rows=state.allowances.filter(a=>a.oauth_client_id===client&&a.status==='active');byId('allowance-current').textContent='Current: '+(rows.map(a=>a.resource_id+' = '+a.scope).join(' · ')||'none');allowanceChoice.clear();for(const row of rows.filter(a=>a.oauth_resource_id===resource?.id))allowanceChoice.add(row.scope);scopePicker('allowance-picker',()=>registeredScopes(byId('allowance-resource').value).map(r=>state.scopes.find(s=>s.id===r.oauth_scope_id)).filter(Boolean),allowanceChoice,()=>{allowancePreview=null;invalidate('allowance-commit','allowance-diff')});allowancePreview=null;invalidate('allowance-commit','allowance-diff')}
function desiredAllowances(){const pasted=byId('allowance-form').elements.allowances.value.trim();if(pasted)return pairs(pasted).map(([resource_id,scope])=>({resource_id,scope}));const resource=state.resources.find(r=>r.id===byId('allowance-resource').value);return [...state.allowances.filter(a=>a.oauth_client_id===byId('allowance-client').value&&a.status==='active'&&a.oauth_resource_id!==resource?.id).map(a=>({resource_id:a.resource_id,scope:a.scope})),...[...allowanceChoice].map(scope=>({resource_id:resource.resource_id,scope}))]}
byId('redirect-preview').onclick=()=>{const id=byId('redirect-client').value,payload={redirect_uris:lines(byId('redirect-form').elements.redirects.value)};previewRequest('redirect-commit','/clients/'+id+'/redirect-uris/preview',payload).then(data=>{if(!data)return;makeTable('redirect-diff',['Redirect URI','Operation'],data.diff.map(r=>[r.redirect_uri,r.operation]));planSummary('redirect-diff',data);redirectPreview={id,payload:{...payload,expected_current:data.current}};byId('redirect-commit').disabled=false}).catch(e=>result.textContent=e.message)};byId('redirect-form').elements.redirects.oninput=()=>{redirectPreview=null;invalidate('redirect-commit','redirect-diff')};byId('redirect-form').onsubmit=e=>{e.preventDefault();if(!redirectPreview)return;call('/clients/'+redirectPreview.id+'/redirect-uris/commit','POST',redirectPreview.payload).then(showBulkResult).then(reload).catch(x=>result.textContent=x.message)};
byId('allowance-preview').onclick=()=>{const id=byId('allowance-client').value,payload={allowances:desiredAllowances()};previewRequest('allowance-commit','/clients/'+id+'/allowances/preview',payload).then(data=>{if(!data)return;makeTable('allowance-diff',['Resource','Scope','Current status','Operation'],data.diff.map(r=>[r.resource_id,r.scope,r.current_status,r.operation]));planSummary('allowance-diff',data);allowancePreview={id,payload:{...payload,expected_current:data.current}};byId('allowance-commit').disabled=false}).catch(e=>result.textContent=e.message)};byId('allowance-form').elements.allowances.oninput=()=>{allowancePreview=null;invalidate('allowance-commit','allowance-diff')};byId('allowance-form').onsubmit=e=>{e.preventDefault();if(!allowancePreview)return;call('/clients/'+allowancePreview.id+'/allowances/commit','POST',allowancePreview.payload).then(showBulkResult).then(reload).catch(x=>result.textContent=x.message)};
byId('client-form').onsubmit=e=>{e.preventDefault();const f=new FormData(e.target),resource=state.resources.find(r=>r.id===byId('client-resource').value);const structured=[...clientChoice].map(scope=>({resource_id:resource.resource_id,scope}));const advanced=pairs(f.get('allowances')||'').map(([resource_id,scope])=>({resource_id,scope}));const allowances=[...structured,...advanced];if(!allowances.length){result.textContent='Select at least one exact allowance.';return}call('/clients','POST',{client_id:f.get('client_id'),client_name:f.get('client_name'),owner_team:f.get('owner_team'),owner_contact:f.get('owner_contact')||null,status:f.get('status'),grant_types:f.get('refresh')?['authorization_code','refresh_token']:['authorization_code'],redirect_uris:lines(f.get('redirects')),allowances}).then(show).then(reload).catch(x=>result.textContent=x.message)};
byId('client-select-all').onclick=()=>{for(const row of registeredScopes(byId('client-resource').value))clientChoice.add(row.scope);scopePicker('client-picker',()=>registeredScopes(byId('client-resource').value).map(r=>state.scopes.find(s=>s.id===r.oauth_scope_id)).filter(Boolean),clientChoice,()=>{})};
byId('allowance-select-all').onclick=()=>{for(const row of registeredScopes(byId('allowance-resource').value))allowanceChoice.add(row.scope);allowancePreview=null;invalidate('allowance-commit','allowance-diff');scopePicker('allowance-picker',()=>registeredScopes(byId('allowance-resource').value).map(r=>state.scopes.find(s=>s.id===r.oauth_scope_id)).filter(Boolean),allowanceChoice,()=>{allowancePreview=null;invalidate('allowance-commit','allowance-diff')})};
function renderSelectedUsers(){const box=byId('bulk-selected-users');box.replaceChildren();const p=document.createElement('p');p.textContent=selectedUsers.size+' existing users selected';box.appendChild(p);for(const [id,user] of selectedUsers){const b=document.createElement('button');b.type='button';b.className='secondary';b.textContent=(user.email||id)+' ×';b.onclick=()=>{selectedUsers.delete(id);renderSelectedUsers();bulkGrantPreview=null;invalidate('bulk-grant-commit','bulk-grant-result')};box.appendChild(b)}}
let bulkUserTimer;byId('bulk-user-search').oninput=e=>{clearTimeout(bulkUserTimer);const q=e.target.value.trim();if(q.length<2){byId('bulk-user-results').replaceChildren();return}bulkUserTimer=setTimeout(()=>call('/users?q='+encodeURIComponent(q)).then(users=>options(byId('bulk-user-results'),users,u=>u.id,u=>u.email+' · '+(u.display_name||'')+' · '+u.status)).catch(x=>result.textContent=x.message),250)};byId('bulk-add-user').onclick=()=>{const select=byId('bulk-user-results'),id=select.value;if(!id)return;const option=select.selectedOptions[0];selectedUsers.set(id,{email:option?.textContent||id});renderSelectedUsers();bulkGrantPreview=null;invalidate('bulk-grant-commit','bulk-grant-result')};
function bulkGrantPayload(){const date=id=>byId(id).value?new Date(byId(id).value).toISOString():undefined;return {resource_id:byId('bulk-grant-resource').value,user_ids:[...selectedUsers.keys()],emails:lines(byId('bulk-user-emails').value.replace(/^\\uFEFF/,'')),scopes:[...bulkGrantChoice].sort(),valid_from:date('bulk-grant-from'),valid_until:date('bulk-grant-until')}}
for(const id of ['bulk-user-emails','bulk-grant-from','bulk-grant-until'])byId(id).oninput=()=>{bulkGrantPreview=null;invalidate('bulk-grant-commit','bulk-grant-result')};byId('bulk-grant-preview').onclick=()=>{const payload=bulkGrantPayload();previewRequest('bulk-grant-commit','/native-grants/bulk/preview',payload).then(data=>{if(!data)return;makeTable('bulk-grant-result',['User','Scope','Resource','Operation','Reason'],data.rows.map(r=>[r.user_email||r.user_id,r.scope,r.resource_id,r.operation,r.reason]));planSummary('bulk-grant-result',data);if(!data.summary.error){bulkGrantPreview=payload;byId('bulk-grant-commit').disabled=false}}).catch(e=>result.textContent=e.message)};byId('bulk-grant-commit').onclick=()=>{if(!bulkGrantPreview)return;call('/native-grants/bulk/commit','POST',bulkGrantPreview).then(showBulkResult).then(()=>{bulkGrantPreview=null;invalidate('bulk-grant-commit','bulk-grant-result');return reloadGrants()}).catch(e=>result.textContent=e.message)};
function grantFilterQuery(){const params=new URLSearchParams({resource_id:byId('grant-resource').value,offset:String(grantOffset)});for(const [id,key] of [['grant-filter-user','q'],['grant-filter-scope','scope'],['grant-filter-status','status'],['grant-filter-effective','effective']])if(byId(id).value)params.set(key,byId(id).value);return params.toString()}
async function reloadGrants(){const box=byId('native-grants');box.replaceChildren();if(!byId('grant-resource').value)return;const rows=await call('/native-grants?'+grantFilterQuery());lastGrantRows=rows;const table=document.createElement('table'),head=document.createElement('tr');for(const name of ['Select','User','Scope','Resource','Status','Effective','Validity','Action']){const cell=document.createElement('th');cell.textContent=name;head.appendChild(cell)}table.appendChild(head);for(const grant of rows){const row=document.createElement('tr');const selectCell=document.createElement('td'),check=document.createElement('input');check.type='checkbox';check.checked=selectedGrants.has(grant.id);check.onchange=()=>{check.checked?selectedGrants.add(grant.id):selectedGrants.delete(grant.id);byId('grant-selected-count').textContent=selectedGrants.size+' selected';revokePreview=null;invalidate('bulk-revoke-commit','bulk-revoke-result')};selectCell.appendChild(check);row.appendChild(selectCell);for(const value of [(grant.user_email||'Pending')+' · '+(grant.user_display_name||'')+' · '+(grant.user_id||'unlinked'),grant.scope,grant.resource_display_name,grant.status,grant.effective?'effective':'not effective',String(grant.valid_from)+(grant.valid_until?' → '+grant.valid_until:'')]){const cell=document.createElement('td');cell.textContent=value;row.appendChild(cell)}const action=document.createElement('td');if(grant.status==='active'){const b=document.createElement('button');b.type='button';b.className='secondary';b.textContent='Revoke';b.onclick=()=>{if(!confirm('Revoke this exact native scope grant?'))return;call('/native-grants/'+grant.id+'/revoke','POST',{}).then(show).then(reloadGrants).catch(e=>result.textContent=e.message)};action.appendChild(b)}row.appendChild(action);table.appendChild(row)}box.appendChild(table);if(!rows.length)box.textContent='No grants match these filters.';byId('grants-next').disabled=rows.length<100||grantOffset>=10000;byId('grants-previous').disabled=grantOffset===0;byId('grant-selected-count').textContent=selectedGrants.size+' selected'}
let grantFilterTimer;for(const id of ['grant-filter-user','grant-filter-scope','grant-filter-status','grant-filter-effective'])byId(id).oninput=()=>{clearTimeout(grantFilterTimer);grantOffset=0;selectedGrants.clear();revokePreview=null;invalidate('bulk-revoke-commit','bulk-revoke-result');grantFilterTimer=setTimeout(()=>reloadGrants().catch(e=>result.textContent=e.message),200)};byId('grant-resource').onchange=()=>{grantOffset=0;selectedGrants.clear();singleGrantChoice.clear();revokePreview=null;invalidate('bulk-revoke-commit','bulk-revoke-result');refreshGrantScopes()};byId('grants-next').onclick=()=>{grantOffset=Math.min(10000,grantOffset+100);reloadGrants().catch(e=>result.textContent=e.message)};byId('grants-previous').onclick=()=>{grantOffset=Math.max(0,grantOffset-100);reloadGrants().catch(e=>result.textContent=e.message)};
byId('bulk-revoke-preview').onclick=()=>{const payload={grant_ids:[...selectedGrants].sort()};previewRequest('bulk-revoke-commit','/native-grants/bulk-revoke/preview',payload).then(data=>{if(!data)return;makeTable('bulk-revoke-result',['User','Scope','Resource','Status','Operation'],data.rows.map(r=>[r.user_email||r.user_id,r.scope,r.resource_display_name,r.current_status,r.operation]));planSummary('bulk-revoke-result',data);if(!data.summary.error){revokePreview=payload;byId('bulk-revoke-commit').disabled=false}}).catch(e=>result.textContent=e.message)};byId('bulk-revoke-commit').onclick=()=>{if(!revokePreview)return;call('/native-grants/bulk-revoke/commit','POST',revokePreview).then(showBulkResult).then(()=>{selectedGrants.clear();revokePreview=null;invalidate('bulk-revoke-commit','bulk-revoke-result');return reloadGrants()}).catch(e=>result.textContent=e.message)};
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
