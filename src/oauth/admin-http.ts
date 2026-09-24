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
<title>OAuth P0 administration</title><style>
:root{font-family:Inter,ui-sans-serif,system-ui;color:rgb(16 24 40);background:rgb(247 248 250)}body{margin:0}header{background:rgb(0 75 99);color:white;padding:18px 28px;display:flex;justify-content:space-between}header a{color:white}main{max-width:1280px;margin:auto;padding:28px}.notice{border-left:5px solid rgb(245 158 11);background:rgb(255 247 230);padding:16px;margin-bottom:20px}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:18px}.card{background:white;border:1px solid rgb(229 231 235);border-radius:16px;padding:18px;box-shadow:0 8px 24px rgba(15,23,42,.06)}label{display:block;font-weight:650;margin-top:10px}input,textarea,select{box-sizing:border-box;width:100%;margin-top:5px;padding:9px;border:1px solid rgb(152 162 179);border-radius:8px}button{margin-top:12px;padding:10px 14px;border:0;border-radius:8px;background:rgb(0 75 99);color:white;cursor:pointer}button.secondary{background:rgb(102 112 133)}.result{white-space:pre-wrap;overflow:auto;background:rgb(249 250 251);padding:10px;border-radius:8px;max-height:320px}.secret{border:2px solid rgb(116 198 157);background:rgb(240 255 247);padding:12px;word-break:break-all}.muted{color:rgb(102 112 133);font-size:.9rem}table{width:100%;border-collapse:collapse;font-size:.88rem}th,td{text-align:left;border-bottom:1px solid rgb(234 236 240);padding:8px;vertical-align:top}</style></head>
<body><header><strong>Access Layer · OAuth P0 administration</strong><a href="${legacyAdmin}">Legacy administration</a></header><main>
<div class="notice"><strong>Temporary P0 compatibility state.</strong> OAuth resources remain bound to one legacy tool only for entitlement evaluation. Do not use that tool as a client ID, resource, audience, or introspection credential. Native OAuth entitlement domains must replace this bridge after the Nancy Phase 8 pilot and before broad SDK-native rollout.</div>
<p class="muted">Protocol enablement remains controlled separately by <code>OAUTH_P0_ENABLED</code>. Creating administration records does not enable OAuth.</p>
<div class="grid">
<section class="card"><h2>1. Scope</h2><form id="scope-form"><label>Canonical scope<input name="scope" placeholder="project:domain:action" required></label><label>Description<input name="description" required></label><button>Create scope</button></form></section>
<section class="card"><h2>2. Resource and entitlement bridge</h2><form id="resource-form"><label>HTTPS resource ID<input name="resource_id" required></label><label>Display name<input name="display_name" required></label><label>Owner team<input name="owner_team" required></label><label>Owner contact<input name="owner_contact"></label><label>Status<select name="status"><option>draft</option><option>active</option><option>disabled</option></select></label><label>Protected-resource metadata URL<input name="metadata_url" required></label><label>Bound legacy tool slug<input name="legacy_tool_slug" required></label><label>Scope mappings (one per line: scope = legacy:permission)<textarea name="mappings" required></textarea></label><button>Create resource + one-time introspection credential</button></form></section>
<section class="card"><h2>3. Confidential client</h2><form id="client-form"><label>Client ID<input name="client_id" required></label><label>Client name<input name="client_name" required></label><label>Owner team<input name="owner_team" required></label><label>Owner contact<input name="owner_contact"></label><label>Status<select name="status"><option>draft</option><option>active</option><option>disabled</option></select></label><label><input style="width:auto" type="checkbox" name="refresh"> Allow refresh_token</label><label>Exact redirect URIs (one per line)<textarea name="redirects" required></textarea></label><label>Allowances (one per line: resource URI = scope)<textarea name="allowances" required></textarea></label><button>Create client + one-time secret</button></form></section>
<section class="card"><h2>Signing keys</h2><p class="muted">Private keys are generated server-side into the configured protected root and are never returned.</p><button id="generate-key">Generate staged RSA key</button><div id="key-actions"></div></section>
<section class="card"><h2>Registration lifecycle</h2><form id="status-form"><label>Kind<select name="kind"><option value="clients">client</option><option value="resources">resource</option></select></label><label>Internal registration UUID<input name="id" required></label><label>Status<select name="status"><option>draft</option><option>active</option><option>disabled</option></select></label><button>Update status</button></form></section>
<section class="card"><h2>Client redirects and allowances</h2><form id="redirect-form"><label>Client UUID<input name="id" required></label><label>Exact redirect URIs (one per line)<textarea name="redirects" required></textarea></label><button>Replace redirect URIs</button></form><form id="allowance-form"><label>Client UUID<input name="id" required></label><label>Allowances (one per line: resource URI = scope)<textarea name="allowances" required></textarea></label><button>Replace allowances</button></form></section>
<section class="card"><h2>Resource scope mapping</h2><form id="mapping-form"><label>Resource UUID<input name="resource_id" required></label><label>Scope UUID<input name="scope_id" required></label><label>Exact legacy permission key<input name="permission" required></label><label>Status<select name="status"><option>active</option><option>disabled</option></select></label><button>Set explicit mapping</button></form></section>
<section class="card"><h2>Temporary entitlement binding</h2><form id="binding-form"><label>Resource UUID<input name="resource_id" required></label><label>Legacy tool slug<input name="tool" required></label><label>Status<select name="status"><option>active</option><option>disabled</option></select></label><button>Replace or disable binding</button></form></section>
<section class="card"><h2>Credential lifecycle</h2><form id="rotate-form"><label>Kind<select name="kind"><option value="clients">client</option><option value="resources">resource</option></select></label><label>Owner UUID<input name="id" required></label><button>Rotate and show secret once</button></form><form id="retire-form"><label>Kind<select name="kind"><option value="clients">client</option><option value="resources">resource</option></select></label><label>Credential record UUID<input name="id" required></label><button>Retire credential</button></form></section>
<section class="card"><h2>Scope lifecycle</h2><form id="scope-update-form"><label>Scope UUID<input name="id" required></label><label>Description (optional)<input name="description"></label><label>Status<select name="status"><option value="">unchanged</option><option>active</option><option>disabled</option></select></label><button>Update scope</button></form></section>
</div><section class="card" style="margin-top:18px"><h2>One-time credential result</h2><div id="secret" class="secret">No credential generated in this session.</div></section>
<section class="card" style="margin-top:18px"><h2>Current OAuth administration state</h2><button class="secondary" id="reload">Reload</button><div id="state" class="result">Loading…</div></section>
<section class="card" style="margin-top:18px"><h2>Operation result</h2><div id="result" class="result"></div></section>
<script>const api=${JSON.stringify(endpoint)};const result=document.querySelector('#result');const secret=document.querySelector('#secret');
const lines=v=>v.split(/\\r?\\n/).map(x=>x.trim()).filter(Boolean);const pairs=v=>lines(v).map(x=>{const i=x.indexOf('=');if(i<1)throw new Error('Each mapping needs =');return [x.slice(0,i).trim(),x.slice(i+1).trim()]});
async function call(path,method='GET',body){if(method!=='GET')secret.textContent='No new credential; previous one-time value discarded.';const r=await fetch(api+path,{method,headers:body?{'content-type':'application/json'}:{},body:body?JSON.stringify(body):undefined});const data=await r.json().catch(()=>({}));if(!r.ok)throw new Error(JSON.stringify(data));return data}
function show(data){const visible={...data};const s=visible.client_secret||visible.resource_credential_secret;delete visible.client_secret;delete visible.resource_credential_secret;result.textContent=JSON.stringify(visible,null,2);secret.textContent=s?(data.resource_credential_id?data.resource_credential_id+' : ':'')+s+' — copy now; it cannot be shown again.':'No new credential; previous one-time value discarded.'}
async function reload(){const data=await call('');document.querySelector('#state').textContent=JSON.stringify(data,null,2);const box=document.querySelector('#key-actions');box.innerHTML='';for(const k of data.signingKeys||[]){const row=document.createElement('div');row.textContent=k.kid+' · '+k.status+(k.status==='published'?' · activation eligible after '+k.activates_at:'')+(k.retire_after?' · verification grace ends '+k.retire_after:'');const actions=k.status==='staged'?['publish','disable']:k.status==='published'?['activate','disable']:k.status==='active'?['retire']:[];for(const action of actions){const b=document.createElement('button');b.className='secondary';b.style.marginLeft='6px';b.textContent=action;if(action==='activate'&&Date.now()<Date.parse(k.activates_at)){b.disabled=true;b.title='Publication lead has not elapsed'}b.onclick=()=>call('/signing-keys/'+k.id+'/'+action,'POST',{}).then(show).then(reload).catch(e=>result.textContent=e.message);row.appendChild(b)}box.appendChild(row)}}
document.querySelector('#scope-form').onsubmit=e=>{e.preventDefault();const f=new FormData(e.target);call('/scopes','POST',{scope:f.get('scope'),description:f.get('description')}).then(show).then(reload).catch(x=>result.textContent=x.message)};
document.querySelector('#resource-form').onsubmit=e=>{e.preventDefault();const f=new FormData(e.target);call('/resources','POST',{resource_id:f.get('resource_id'),display_name:f.get('display_name'),owner_team:f.get('owner_team'),owner_contact:f.get('owner_contact')||null,status:f.get('status'),protected_resource_metadata_url:f.get('metadata_url'),legacy_tool_slug:f.get('legacy_tool_slug'),scope_mappings:pairs(f.get('mappings')).map(([scope,legacy_permission_key])=>({scope,legacy_permission_key}))}).then(show).then(reload).catch(x=>result.textContent=x.message)};
document.querySelector('#client-form').onsubmit=e=>{e.preventDefault();const f=new FormData(e.target);call('/clients','POST',{client_id:f.get('client_id'),client_name:f.get('client_name'),owner_team:f.get('owner_team'),owner_contact:f.get('owner_contact')||null,status:f.get('status'),grant_types:f.get('refresh')?['authorization_code','refresh_token']:['authorization_code'],redirect_uris:lines(f.get('redirects')),allowances:pairs(f.get('allowances')).map(([resource_id,scope])=>({resource_id,scope}))}).then(show).then(reload).catch(x=>result.textContent=x.message)};
document.querySelector('#status-form').onsubmit=e=>{e.preventDefault();const f=new FormData(e.target);call('/'+f.get('kind')+'/'+f.get('id')+'/status','PATCH',{status:f.get('status')}).then(show).then(reload).catch(x=>result.textContent=x.message)};
document.querySelector('#redirect-form').onsubmit=e=>{e.preventDefault();const f=new FormData(e.target);call('/clients/'+f.get('id')+'/redirect-uris','PUT',{redirect_uris:lines(f.get('redirects'))}).then(show).then(reload).catch(x=>result.textContent=x.message)};
document.querySelector('#allowance-form').onsubmit=e=>{e.preventDefault();const f=new FormData(e.target);call('/clients/'+f.get('id')+'/allowances','PUT',{allowances:pairs(f.get('allowances')).map(([resource_id,scope])=>({resource_id,scope}))}).then(show).then(reload).catch(x=>result.textContent=x.message)};
document.querySelector('#mapping-form').onsubmit=e=>{e.preventDefault();const f=new FormData(e.target);call('/resources/'+f.get('resource_id')+'/scopes/'+f.get('scope_id'),'PUT',{legacy_permission_key:f.get('permission'),status:f.get('status')}).then(show).then(reload).catch(x=>result.textContent=x.message)};
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
      "protected_resource_metadata_url", "legacy_tool_slug", "scope_mappings"
    ]);
    const input: OAuthAdminResourceInput = {
      resourceId: text(body.resource_id), displayName: text(body.display_name), ownerTeam: text(body.owner_team),
      ownerContact: nullableText(body.owner_contact), status: text(body.status) as OAuthAdminResourceInput["status"],
      protectedResourceMetadataUrl: text(body.protected_resource_metadata_url), legacyToolSlug: text(body.legacy_tool_slug),
      scopeMappings: parseMappings(body.scope_mappings)
    };
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
      legacyPermissionKey: text(body.legacy_permission_key), status: text(body.status) as "active" | "disabled"
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
