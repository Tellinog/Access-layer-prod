# SCOPE.md

## Project goals

- Create a shared access layer for all internal web tools.
- Authenticate users with Google company accounts.
- Prevent external users from accessing internal tools.
- Let platform admins authorize users per tool.
- Identify the user inside each tool with verified claims.
- Produce central access logs: who requested access, for which tool, when, from where, with what outcome.
- Provide stable API and integration instructions for existing and future tools.

## In scope

- Google OpenID Connect login.
- Company domain enforcement through `hd` claim.
- Tool registry with `tool_slug`, display name, status, client credentials and return URL allow-list.
- User registry with Google `sub`, email, hosted domain, profile metadata and status.
- Pending grants by email and linked grants by user ID.
- Per-tool authorization grants and roles.
- One-time code exchange flow.
- Signed Access Layer JWT and JWKS endpoint.
- Token introspection endpoint.
- Admin APIs and minimal admin UI.
- Audit logging.
- Documentation, OpenAPI schema, payload examples and DB seed/migration baseline.

## Out of scope

- Managing Google Workspace accounts.
- Reading Gmail, Drive, Calendar or other Google APIs.
- Replacing per-tool business permissions beyond the access envelope.
- User provisioning from HR systems.
- Automatic Google Group synchronization.
- Device posture and endpoint management.
- Password login.
- Public user registration.

## Step 2 target-contract boundary

The additive OAuth vNext P0 protocol and proposed data model are in scope as design contracts only. OAuth handlers, discovery responses, SQL migrations/tables, production registrations, downstream OIDC, machine grants, token exchange and deployment remain out of scope until a separately approved implementation step.

## Step 3A dark-foundation boundary

The separately approved Step 3A scope implements one expand-only ten-table registration/signing foundation migration, an optional default-false flag, isolated OAuth types/repository/validation primitives and deterministic darkness/compatibility tests.

Still out of scope are every OAuth protocol or metadata route, upstream Google callback runtime, authorization transaction/code/session/refresh/revocation tables, token signing/verification, credential authentication, registration/admin HTTP API, pilot/seed data, production enablement/deploy and consumer or Platform SDK changes.

## Step 3B read-only metadata/JWKS boundary

Step 3B implements pure frozen RFC 8414/RFC 9728 builders, deterministic public OAuth JWKS selection and only two default-off HTTP routes: `/oauth/jwks` and `/.well-known/oauth-protected-resource/v1`. RFC 8414 authorization-server metadata is not routed until its advertised endpoints exist.

Authorize, token, refresh, revoke, introspect, upstream Google, private-key loading/signing, protocol transaction tables, registration/admin APIs, pilots/seeds, production actions, consumers and SDKs remain out of scope.

## Step 3C dark authorization-issuance boundary

Step 3C adds only three OAuth authorization-flow tables, GET `/oauth/authorize`, the separate GET `/oauth/upstream/google/callback`, protected downstream-state persistence, current-entitlement evaluation and opaque authorization-code issuance. These paths remain behind the optional default-false flag and have no automatic HEAD siblings.

Token exchange/client authentication, OAuth access/refresh tokens and sessions, signing/private-key loading, RFC 8414 routing, revoke, introspect, registration/admin APIs, pilot/seed data, production/Google Console actions, consumers and SDKs remain out of scope.

## Step 3D dark token-lifecycle-core boundary

Step 3D adds only the OAuth session/refresh-family/refresh-token/revocation tables plus unmounted services for code exchange, dedicated-key RFC 9068 signing, refresh rotation/replay, revocation and resource-owned introspection. OAuth credential hashes use a dedicated pepper, key references are confined to a dedicated local root, and every successful issue/rotate transition is transactional with audit and `last_signed_at`.

Still out of scope are mounting `/oauth/token`, `/oauth/revoke`, `/oauth/introspect` or RFC 8414; registration/admin APIs, pilots/seeds, production secret/key provisioning or enablement, consumers/SDKs, backup implementation changes, deployment and Step 3E.

## Personas

| Persona | Goal | Main needs | Notes |
|---|---|---|---|
| Internal user | Access a tool they are authorized to use | Fast Google login, clear denial messages | No admin permissions by default |
| Platform admin | Manage tools, users, grants and logs | Admin UI/API, safe bulk operations, audit trail | Bootstrap via `ADMIN_BOOTSTRAP_EMAILS` |
| Tool developer | Integrate a tool | Stable endpoints, examples, SDK-style guidance | Must implement backend callback and token exchange |
| Auditor/security | Review access attempts | Immutable-ish logs, filters, export | Read-only access |
| Tool owner | Decide who can use a specific tool | Tool-level grants and roles | May be delegated in future |

## Non-negotiables

- A valid Google login alone is not enough: the user needs a grant for the requested tool.
- External Google accounts must be denied.
- Return URLs must be allow-listed per tool.
- Tool clients must authenticate for token exchange and introspection.
- Tokens and secrets must not be logged.
- Every access decision must be logged.

## Success metrics

| Metric | Target | How measured |
|---|---:|---|
| Tool integration time after first integration | <= 1 day | Developer feedback and checklist |
| Access attempts logged centrally | 100% | Audit events generated per auth flow |
| Unauthorized external access | 0 successful | Security tests and audit review |
| One-time code replay accepted | 0 | Automated security tests |
| Admin grant changes logged | 100% | Audit event coverage |

## Constraints

- Works for current and future internal web tools through HTTP API.
- Must support multiple tools under different domains/subdomains.
- Must be deployable behind HTTPS.
- Must keep Google secrets, JWT private keys and tool secrets out of code and logs.

## Access requests

In scope v1:

- creare una richiesta pendente quando un utente aziendale valido tenta un tool senza grant;
- mostrare le richieste pendenti nella Admin UI;
- permettere ad admin/tool admin di approvare o rifiutare;
- creare automaticamente il grant durante l'approvazione;
- mantenere audit log separati per tentativi e decisioni admin.

Out of scope v1 obbligatorio:

- auto-approvazione;
- richieste provenienti da account esterni;
- notifiche email/Slack obbligatorie, che restano configurabili.
