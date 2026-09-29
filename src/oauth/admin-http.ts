import type { FastifyInstance, FastifyReply, FastifyRequest, RouteHandlerMethod } from "fastify";
import { AppError } from "../errors.js";
import { hashOpaque, hashRequestField, parseCookies, randomToken, verifySignedCookie } from "../security.js";
import type { Repositories } from "../repositories.js";
import type { TokenService } from "../token-service.js";
import type { AdminActor, Config } from "../types.js";
import type { OAuthAdminAuditContext, OAuthAdminClientInput, OAuthAdminResourceInput } from "./admin-types.js";
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
<section class="card"><h2>1. Scope</h2><form id="scope-form"><label>Canonical scope<input name="scope" placeholder="project:domain:action" required></label><label>Description<input name="description" required></label><button>Create scope</button></form></section>
<section class="card"><h2>2. Resource</h2><form id="resource-form"><label>HTTPS resource ID<input name="resource_id" required></label><label>Display name<input name="display_name" required></label><label>Owner team<input name="owner_team" required></label><label>Owner contact<input name="owner_contact"></label><label>Status<select name="status"><option>draft</option><option>active</option><option>disabled</option></select></label><label>Protected-resource metadata URL<input name="metadata_url" required></label><label>Entitlement mode<select name="entitlement_mode" id="resource-mode"><option value="native" selected>Native</option><option value="legacy_bridge">Legacy bridge</option></select></label><label>Active OAuth scopes<select name="native_scopes" id="native-resource-scopes" multiple size="5" required></select></label><div id="native-resource-fields"><p class="muted">These scopes use native human grants without a legacy tool.</p></div><div id="legacy-resource-fields" hidden><label>Bound legacy tool slug<select name="legacy_tool_slug" id="legacy-resource-tool"></select></label><div id="legacy-resource-mappings"></div></div><button>Create resource + one-time introspection credential</button></form></section>
<section class="card"><h2>3. Confidential client</h2><form id="client-form"><label>Client ID<input name="client_id" required></label><label>Client name<input name="client_name" required></label><label>Owner team<input name="owner_team" required></label><label>Owner contact<input name="owner_contact"></label><label>Status<select name="status"><option>draft</option><option>active</option><option>disabled</option></select></label><label><input style="width:auto" type="checkbox" name="refresh"> Allow refresh_token</label><label>Exact redirect URIs (one per line)<textarea name="redirects" required></textarea></label><label>Allowances (one per line: resource URI = scope)<textarea name="allowances" required></textarea></label><button>Create client + one-time secret</button></form></section>
<section class="card"><h2>Signing keys</h2><p class="muted">Private keys are generated server-side into the configured protected root and are never returned.</p><button id="generate-key">Generate staged RSA key</button><div id="key-actions"></div></section>
<section class="card"><h2>Registration lifecycle</h2><form id="status-form"><label>Kind<select name="kind"><option value="clients">client</option><option value="resources">resource</option></select></label><label>Internal registration UUID<input name="id" required></label><label>Status<select name="status"><option>draft</option><option>active</option><option>disabled</option></select></label><button>Update status</button></form></section>
<section class="card"><h2>Client redirects and allowances</h2><form id="redirect-form"><label>Client UUID<input name="id" required></label><label>Exact redirect URIs (one per line)<textarea name="redirects" required></textarea></label><button>Replace redirect URIs</button></form><form id="allowance-form"><label>Client UUID<input name="id" required></label><label>Allowances (one per line: resource URI = scope)<textarea name="allowances" required></textarea></label><button>Replace allowances</button></form></section>
<section class="card"><h2>Resource scope registration</h2><form id="mapping-form"><label>Resource<select name="resource_id" id="mapping-resource" required></select></label><label>Scope<select name="scope_id" id="mapping-scope" required></select></label><div id="mapping-legacy"><label>Exact legacy permission key<select name="permission" id="mapping-permission"></select></label></div><label>Status<select name="status"><option>active</option><option>disabled</option></select></label><button>Set scope registration</button></form></section>
<section class="card"><h2>Temporary entitlement binding</h2><form id="binding-form"><label>Legacy bridge resource<select name="resource_id" id="binding-resource" required></select></label><label>Legacy tool slug<select name="tool" id="binding-tool" required></select></label><label>Status<select name="status"><option>active</option><option>disabled</option></select></label><button>Replace or disable binding</button></form></section>
<section class="card"><h2>Native human grants</h2><p class="muted">Users must have logged into Access Layer at least once before receiving a native grant.</p><form id="native-grant-form"><label>Native resource<select name="resource_id" id="grant-resource" required></select></label><label>Search existing user by email or name<input id="grant-user-search" autocomplete="off"></label><label>Existing user<select name="user_id" id="grant-user" required></select></label><label>Registered scopes<select name="scopes" id="grant-scopes" multiple size="5" required></select></label><label>Valid from (optional)<input type="datetime-local" name="valid_from"></label><label>Valid until (optional)<input type="datetime-local" name="valid_until"></label><button>Grant selected scopes</button></form><button class="secondary" id="reload-grants">Reload grants</button><div id="native-grants"></div></section>
<section class="card"><h2>Credential lifecycle</h2><form id="rotate-form"><label>Kind<select name="kind"><option value="clients">client</option><option value="resources">resource</option></select></label><label>Owner UUID<input name="id" required></label><button>Rotate and show secret once</button></form><form id="retire-form"><label>Kind<select name="kind"><option value="clients">client</option><option value="resources">resource</option></select></label><label>Credential record UUID<input name="id" required></label><button>Retire credential</button></form></section>
<section class="card"><h2>Scope lifecycle</h2><form id="scope-update-form"><label>Scope UUID<input name="id" required></label><label>Description (optional)<input name="description"></label><label>Status<select name="status"><option value="">unchanged</option><option>active</option><option>disabled</option></select></label><button>Update scope</button></form></section>
</div><section class="card" style="margin-top:18px"><h2>One-time credential result</h2><div id="secret" class="secret">No credential generated in this session.</div></section>
<section class="card" style="margin-top:18px"><h2>Current OAuth administration state</h2><button class="secondary" id="reload">Reload</button><div id="state" class="result">Loading…</div></section>
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
function toggleResourceMode(){const native=document.querySelector('#resource-mode').value==='native';document.querySelector('#native-resource-fields').hidden=!native;document.querySelector('#legacy-resource-fields').hidden=native;document.querySelector('#native-resource-scopes').required=native;document.querySelector('#legacy-resource-tool').required=!native;if(!native)renderLegacyMappings()}
function refreshMappingControls(){const resource=state.resources.find(r=>r.id===document.querySelector('#mapping-resource').value);const legacy=resource&&resource.entitlement_mode!=='native';document.querySelector('#mapping-legacy').hidden=!legacy;document.querySelector('#mapping-permission').required=!!legacy;const binding=state.entitlementBindings.find(b=>b.oauth_resource_id===resource?.id&&b.status==='active');const tool=legacyTools.find(t=>t.slug===binding?.legacy_tool_slug);options(document.querySelector('#mapping-permission'),tool?.registered_permission_keys||[],x=>x,x=>x)}
function refreshGrantScopes(){const id=document.querySelector('#grant-resource').value;options(document.querySelector('#grant-scopes'),registeredScopes(id),r=>r.scope,r=>r.scope);reloadGrants().catch(e=>result.textContent=e.message)}
async function reloadGrants(){const id=document.querySelector('#grant-resource').value;const box=document.querySelector('#native-grants');box.replaceChildren();if(!id)return;const rows=await call('/native-grants?resource_id='+encodeURIComponent(id));for(const grant of rows){const line=document.createElement('div');line.textContent=(grant.user_email||grant.user_id||'Pending')+' · '+grant.scope+' · '+grant.status+' · '+(grant.effective?'effective':'not effective')+' · '+grant.valid_from+(grant.valid_until?' → '+grant.valid_until:'');if(grant.status==='active'){const button=document.createElement('button');button.className='secondary';button.textContent='Revoke';button.onclick=()=>{if(!confirm('Revoke this exact native scope grant?'))return;call('/native-grants/'+grant.id+'/revoke','POST',{}).then(show).then(reloadGrants).catch(e=>result.textContent=e.message)};line.appendChild(button)}box.appendChild(line)}if(rows.length===0)box.textContent='No grants for this resource.'}
let userSearchTimer;document.querySelector('#grant-user-search').oninput=e=>{clearTimeout(userSearchTimer);const q=e.target.value.trim();if(q.length<2){document.querySelector('#grant-user').replaceChildren();return}userSearchTimer=setTimeout(()=>call('/users?q='+encodeURIComponent(q)).then(users=>options(document.querySelector('#grant-user'),users,u=>u.id,u=>u.email+' · '+(u.display_name||'')+' · '+u.status)).catch(x=>result.textContent=x.message),250)};
document.querySelector('#resource-mode').onchange=toggleResourceMode;document.querySelector('#legacy-resource-tool').onchange=renderLegacyMappings;document.querySelector('#native-resource-scopes').onchange=renderLegacyMappings;document.querySelector('#mapping-resource').onchange=refreshMappingControls;document.querySelector('#grant-resource').onchange=refreshGrantScopes;document.querySelector('#reload-grants').onclick=()=>reloadGrants().catch(e=>result.textContent=e.message);
async function call(path,method='GET',body){if(method!=='GET')secret.textContent='No new credential; previous one-time value discarded.';const r=await fetch(api+path,{method,headers:body?{'content-type':'application/json'}:{},body:body?JSON.stringify(body):undefined});const data=await r.json().catch(()=>({}));if(!r.ok)throw new Error(JSON.stringify(data));return data}
function show(data){const visible={...data};const s=visible.client_secret||visible.resource_credential_secret;delete visible.client_secret;delete visible.resource_credential_secret;result.textContent=JSON.stringify(visible,null,2);secret.textContent=s?(data.resource_credential_id?data.resource_credential_id+' : ':'')+s+' — copy now; it cannot be shown again.':'No new credential; previous one-time value discarded.'}
async function reload(){const [data,tools]=await Promise.all([call(''),call('/legacy-tools')]);state=data;legacyTools=tools;document.querySelector('#state').textContent=JSON.stringify(data,null,2);options(document.querySelector('#native-resource-scopes'),data.scopes.filter(s=>s.status==='active'),s=>s.scope,s=>s.scope);options(document.querySelector('#legacy-resource-tool'),tools,t=>t.slug,t=>t.display_name+' ('+t.slug+')');options(document.querySelector('#binding-tool'),tools,t=>t.slug,t=>t.display_name+' ('+t.slug+')');options(document.querySelector('#mapping-resource'),data.resources,r=>r.id,r=>r.display_name+' ('+r.entitlement_mode+')');options(document.querySelector('#mapping-scope'),data.scopes.filter(s=>s.status==='active'),s=>s.id,s=>s.scope);options(document.querySelector('#binding-resource'),legacyResources(),r=>r.id,r=>r.display_name);options(document.querySelector('#grant-resource'),nativeResources(),r=>r.id,r=>r.display_name);toggleResourceMode();refreshMappingControls();await reloadGrants();const box=document.querySelector('#key-actions');box.innerHTML='';for(const k of data.signingKeys||[]){const row=document.createElement('div');row.textContent=k.kid+' · '+k.status+(k.status==='published'?' · activation eligible after '+k.activates_at:'')+(k.retire_after?' · verification grace ends '+k.retire_after:'');const actions=k.status==='staged'?['publish','disable']:k.status==='published'?['activate','disable']:k.status==='active'?['retire']:[];for(const action of actions){const b=document.createElement('button');b.className='secondary';b.style.marginLeft='6px';b.textContent=action;if(action==='activate'&&Date.now()<Date.parse(k.activates_at)){b.disabled=true;b.title='Publication lead has not elapsed'}b.onclick=()=>call('/signing-keys/'+k.id+'/'+action,'POST',{}).then(show).then(reload).catch(e=>result.textContent=e.message);row.appendChild(b)}box.appendChild(row)}}
document.querySelector('#scope-form').onsubmit=e=>{e.preventDefault();const f=new FormData(e.target);call('/scopes','POST',{scope:f.get('scope'),description:f.get('description')}).then(show).then(reload).catch(x=>result.textContent=x.message)};
document.querySelector('#resource-form').onsubmit=e=>{e.preventDefault();const f=new FormData(e.target);const mode=f.get('entitlement_mode');const base={resource_id:f.get('resource_id'),display_name:f.get('display_name'),owner_team:f.get('owner_team'),owner_contact:f.get('owner_contact')||null,status:f.get('status'),protected_resource_metadata_url:f.get('metadata_url'),entitlement_mode:mode};const payload=mode==='native'?{...base,scopes:selectedValues(document.querySelector('#native-resource-scopes'))}:{...base,legacy_tool_slug:f.get('legacy_tool_slug'),scope_mappings:Array.from(document.querySelectorAll('#legacy-resource-mappings select')).map(s=>({scope:s.dataset.scope,legacy_permission_key:s.value}))};call('/resources','POST',payload).then(show).then(reload).catch(x=>result.textContent=x.message)};
document.querySelector('#native-grant-form').onsubmit=e=>{e.preventDefault();const f=new FormData(e.target);const date=v=>v?new Date(v).toISOString():undefined;call('/native-grants','POST',{resource_id:f.get('resource_id'),user_id:f.get('user_id'),scopes:selectedValues(document.querySelector('#grant-scopes')),valid_from:date(f.get('valid_from')),valid_until:date(f.get('valid_until'))}).then(show).then(reloadGrants).catch(x=>result.textContent=x.message)};
document.querySelector('#client-form').onsubmit=e=>{e.preventDefault();const f=new FormData(e.target);call('/clients','POST',{client_id:f.get('client_id'),client_name:f.get('client_name'),owner_team:f.get('owner_team'),owner_contact:f.get('owner_contact')||null,status:f.get('status'),grant_types:f.get('refresh')?['authorization_code','refresh_token']:['authorization_code'],redirect_uris:lines(f.get('redirects')),allowances:pairs(f.get('allowances')).map(([resource_id,scope])=>({resource_id,scope}))}).then(show).then(reload).catch(x=>result.textContent=x.message)};
document.querySelector('#status-form').onsubmit=e=>{e.preventDefault();const f=new FormData(e.target);call('/'+f.get('kind')+'/'+f.get('id')+'/status','PATCH',{status:f.get('status')}).then(show).then(reload).catch(x=>result.textContent=x.message)};
document.querySelector('#redirect-form').onsubmit=e=>{e.preventDefault();const f=new FormData(e.target);call('/clients/'+f.get('id')+'/redirect-uris','PUT',{redirect_uris:lines(f.get('redirects'))}).then(show).then(reload).catch(x=>result.textContent=x.message)};
document.querySelector('#allowance-form').onsubmit=e=>{e.preventDefault();const f=new FormData(e.target);call('/clients/'+f.get('id')+'/allowances','PUT',{allowances:pairs(f.get('allowances')).map(([resource_id,scope])=>({resource_id,scope}))}).then(show).then(reload).catch(x=>result.textContent=x.message)};
document.querySelector('#mapping-form').onsubmit=e=>{e.preventDefault();const f=new FormData(e.target);const resource=state.resources.find(r=>r.id===f.get('resource_id'));call('/resources/'+f.get('resource_id')+'/scopes/'+f.get('scope_id'),'PUT',{legacy_permission_key:resource?.entitlement_mode==='native'?null:f.get('permission'),status:f.get('status')}).then(show).then(reload).catch(x=>result.textContent=x.message)};
document.querySelector('#binding-form').onsubmit=e=>{e.preventDefault();const f=new FormData(e.target);call('/resources/'+f.get('resource_id')+'/entitlement-binding','PUT',{legacy_tool_slug:f.get('tool'),status:f.get('status')}).then(show).then(reload).catch(x=>result.textContent=x.message)};
document.querySelector('#rotate-form').onsubmit=e=>{e.preventDefault();const f=new FormData(e.target);call('/'+f.get('kind')+'/'+f.get('id')+'/credentials/rotate','POST',{}).then(show).then(reload).catch(x=>result.textContent=x.message)};
document.querySelector('#retire-form').onsubmit=e=>{e.preventDefault();const f=new FormData(e.target);call('/'+f.get('kind')+'/credentials/'+f.get('id')+'/retire','POST',{}).then(show).then(reload).catch(x=>result.textContent=x.message)};
document.querySelector('#scope-update-form').onsubmit=e=>{e.preventDefault();const f=new FormData(e.target),body={};if(f.get('description'))body.description=f.get('description');if(f.get('status'))body.status=f.get('status');call('/scopes/'+f.get('id'),'PATCH',body).then(show).then(reload).catch(x=>result.textContent=x.message)};
document.querySelector('#generate-key').onclick=()=>call('/signing-keys','POST',{}).then(show).then(reload).catch(x=>result.textContent=x.message);document.querySelector('#reload').onclick=reload;reload().catch(x=>result.textContent=x.message);</script></main></body></html>`;
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
    exactKeys(query, ["resource_id"]);
    return run(request, () => deps.service.listNativeGrants(text(query.resource_id)));
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
