# DECISIONS.md

## D-001 - Central Access Layer instead of per-tool Google login

Status: accepted

Decision: each internal tool delegates authentication and access checks to a shared Access Layer.

Rationale: this creates consistent identity checks, centralized authorization, common logging and a single integration contract for all tools.

## D-002 - Google OpenID Connect as identity source

Status: accepted

Decision: Google is the identity provider. Access Layer uses OpenID Connect with `openid email profile` scopes.

Rationale: company accounts are already managed in Google Workspace. Access Layer only needs identity, email and basic profile claims, not access to Gmail, Drive or other Google APIs.

## D-003 - Validate `hd`, not only email domain

Status: accepted

Decision: Access Layer must validate the Google ID token and check that `hd` matches an allowed Workspace domain. The email domain alone is not sufficient.

Rationale: Google documentation says `hd` is the claim that indicates the hosted Workspace/Cloud organization domain, while `email` can change and is not enough to prove organizational membership.

## D-004 - Use Google `sub` as primary user identifier

Status: accepted

Decision: store and propagate Google `sub` as the immutable user key. Store email for display, lookup and pending grants, but not as the primary key.

Rationale: `sub` is stable for the Google Account. Email can change.

## D-005 - Tool-specific authorization is required

Status: accepted

Decision: a successful Google login is necessary but not sufficient. User access requires an active grant for the requested `tool_slug`.

Rationale: different internal tools have different entitlement needs.

## D-006 - One-time code exchange between Access Layer and tool backend

Status: accepted

Decision: after Google login and authorization, Access Layer redirects to the tool callback with a short-lived one-time code. The tool backend exchanges the code via server-to-server API using its client credentials.

Rationale: this avoids placing access tokens in URLs and ensures only registered tools can consume login results.

## D-007 - Signed internal access token plus introspection endpoint

Status: accepted

Decision: Access Layer issues short-lived JWT access tokens signed by its own key and exposes JWKS for validation. Tools may also call introspection for online status checks.

Rationale: local JWT validation is fast; introspection supports revocation checks and simpler integrations.

## D-008 - Audit logging is a first-class feature

Status: accepted

Decision: every access attempt, denial, token exchange, admin change and sensitive operation must produce a structured audit event with `correlation_id`, `tool_slug`, actor identity when known, outcome and reason.

Rationale: secure logs are required to identify who requested access and for which tool.

## D-009 - Reference implementation stack

Status: accepted

Decision: implement the first version with Node.js 22 LTS, TypeScript, Fastify, PostgreSQL, SQL migrations, OpenAPI, `google-auth-library` and `jose`.

Rationale: typed API implementation, broad compatibility, simple deployment and good library support.

A different stack is allowed only if this decision is updated before implementation.

## D-010 - Admin UI is hosted by the same service

Status: accepted

Decision: v1 serves the minimal Admin UI from the Access Layer service and protects it with the same Access Layer flow using the reserved `access-admin` tool.

Rationale: this keeps v1 deployment simple and makes admin authentication, admin session cookies and admin APIs share the same authorization and audit path.

## D-011 - SQL migrations instead of Prisma migrations

Status: accepted

Decision: v1 uses explicit SQL migrations plus the `pg` driver instead of Prisma.

Rationale: the repository already provides a PostgreSQL reference schema, and direct SQL keeps security-sensitive atomic operations such as one-time code consumption and access-request approval easy to audit.

## D-012 - Registered permission keys for tool grants

Status: accepted

Decision: non-empty grant permissions must be registered in `tool_permissions` for the target tool. Empty permission arrays are allowed.

Rationale: this implements `unknown_permission_behavior: deny` while still letting tools onboard with role-only grants before they define finer permission keys.

## D-013 - Delegated tool-admin scope

Status: accepted

Decision: delegated `tool_admin` scope is resolved from `admin_tool_assignments` and, for compatibility with the existing data model, tools whose `owner_email` matches the admin email.

Rationale: the visibility policy requires assigned-tool scoping, while v1 documentation already defines tool ownership. The explicit assignment table supports future admin UI assignment controls without changing the auth model.

## D-014 - Tool callback state persistence

Status: accepted

Decision: v1 stores the tool-provided callback `state` in `auth_requests` so the callback can return it after Google redirects. The value is never written to application logs or audit metadata.

Rationale: the tool state is required for the tool callback contract. Tool integration rules already forbid secrets in state, and Access Layer still stores a hash for validation/audit support.

## D-015 - Confirmed v1 Google Workspace domain and Access Layer URLs

Status: accepted

Confirmed: 2026-06-17

Decision: v1 uses `unguess.io` as the only confirmed Google Workspace hosted domain in `GOOGLE_ALLOWED_HD`. The local Access Layer base URL is `http://localhost:8080`; the production Access Layer base URL was originally `https://draftapps.it` and is superseded by D-022. The authorized OAuth redirect URIs for v1 were originally:

- `http://localhost:8080/access-control/v1/auth/google/callback`
- `https://draftapps.it/access-control/v1/auth/google/callback` (superseded by D-022)

No separate staging environment is required for v1 unless specified later.

Rationale: Google hosted-domain validation must use only Workspace domains from the Google ID token `hd` claim. Google returns `hd=unguess.io` for company accounts. Runtime hosts such as `draftapps.it`, `access-layer.unguess-internal.net` and `localhost` are not Google Workspace hosted domains, so they must never be included in `GOOGLE_ALLOWED_HD`.

## D-016 - Local Docker Compose runtime

Status: accepted

Decision: v1 local development uses Docker Compose to run the Access Layer service and PostgreSQL together. The app container waits for PostgreSQL health, runs SQL migrations at startup, may run local seed data when `RUN_SEED_ON_START=true`, and serves on `http://localhost:8080`.

Rationale: local verification requires a PostgreSQL database, but developer machines should not need a manually installed database. The production deploy sequence still treats migrations as an explicit controlled step before traffic.

## 2026-06-17 - Access Layer public base path for Coolify

Decision: the Access Layer dashboard and all Access Layer APIs were served under `/access-control` in production. This production topology is superseded by D-022. Local Docker development may still use `/access-control`.

Historical production URLs, superseded by D-022:

- Admin dashboard: `https://draftapps.it/access-control`
- Google callback: `https://draftapps.it/access-control/v1/auth/google/callback`
- Admin API: `https://draftapps.it/access-control/v1/admin/*`
- Tool auth API: `https://draftapps.it/access-control/v1/auth/*`

Operational consequence: this historical production base-path guidance is no longer canonical for production. Use D-022 for production URLs.

Tool records are managed through the Admin UI for v1. Seed files remain limited to `access-admin` and optional demo data.

## D-017 - Inline Admin UI forms for multi-field operations

Status: accepted

Decision: v1 Admin UI multi-field operations use same-page inline forms instead of browser `prompt()` chains. One-time client secrets are displayed in an inline result panel with copy affordance instead of browser `alert()`.

Rationale: inline forms are easier to review before submit, improve keyboard/accessibility behavior, and reduce the risk of partial or sequential input mistakes during tool onboarding and grant/access-request administration.


## D-018 - Admin UI dashboard is not rendered before admin login

Status: accepted

Decision: unauthenticated requests to the Admin UI root must redirect into the reserved `access-admin` Google login flow instead of serving the Admin UI dashboard shell.

Rationale: the Admin UI is an administrative surface. Even though Admin APIs remain protected independently, the dashboard navigation, labels and client-side code should only be delivered after a valid admin session exists.

Operational consequence: in Docker/Coolify, opening `/access-control` without a valid admin session should move directly to Google OAuth. Successful login sets the signed admin session cookie and then renders the dashboard.

## D-019 - Keep Docker healthcheck enabled but silence health route request logs

Status: accepted

Decision: Docker Compose continues to check `/health` or `/{PUBLIC_BASE_PATH}/health` every 10 seconds, while application request logging for health routes is disabled.

Rationale: the container healthcheck is useful for restart/orchestration behavior, but successful probes are noisy and can be mistaken for unexpected user or browser traffic during local testing.

## D-020 - Explicit backup permissions and encrypted backup exports

Status: accepted

Decision: backup read, backup write and restore secret material export use explicit permissions and do not inherit from `admin:secrets:rotate`. Backup exports are encrypted with `BACKUP_ENCRYPTION_KEY`. Restore secret material export may return `TOOL_CLIENT_SECRET_PEPPER` and `BACKUP_ENCRYPTION_KEY` only to platform admins with the explicit backup-secret permission.

Rationale: backup data contains identity, grant and tool-client hash material, so it needs a narrower authorization surface than generic secret rotation and must remain protected if copied to external storage. Existing per-tool client secrets cannot be exported after creation/rotation because they are never stored in plaintext.

## D-021 - Bounded reverse-proxy trust for Coolify

Status: accepted

Decision: client IP resolution uses `TRUST_PROXY_HOPS` instead of unlimited proxy trust. Production/Coolify uses one trusted proxy hop by default; direct local development uses zero trusted proxy hops.

Rationale: Access Layer rate limits and audit hashes depend on client IP. Bounding proxy trust preserves Coolify compatibility while avoiding spoofable unlimited `X-Forwarded-*` trust when the app is exposed incorrectly.

## D-022 - Dedicated Access Layer production subdomain

Status: accepted

Decision: production Access Layer runs on the dedicated origin `https://access-layer.unguess-internal.net` without the `/access-control` public base path. Local Docker development continues to use `http://localhost:8080/access-control`.

Canonical production URLs:

- Admin UI: `https://access-layer.unguess-internal.net/admin`
- Google callback: `https://access-layer.unguess-internal.net/v1/auth/google/callback`
- Admin API: `https://access-layer.unguess-internal.net/v1/admin/*`
- Tool auth API: `https://access-layer.unguess-internal.net/v1/auth/*`

Operational consequence: production must set `PUBLIC_BASE_PATH=` (empty), `APP_BASE_URL=https://access-layer.unguess-internal.net`, `AUTH_ISSUER=https://access-layer.unguess-internal.net` and `GOOGLE_REDIRECT_URI=https://access-layer.unguess-internal.net/v1/auth/google/callback`. Tools should configure `ACCESS_LAYER_BASE_URL=https://access-layer.unguess-internal.net` and call `/v1/...` paths relative to that base URL.

Rationale: a dedicated `access-layer` subdomain avoids mounting Access Layer below `draftapps.it/access-control`, simplifies reverse-proxy routing and makes the production service boundary explicit while preserving local base-path coverage.

## D-023 - Admin tool deletion preserves audit history

Status: accepted

Decision: platform admins may delete non-reserved tool registrations from Admin UI/API. Deletion is a database cascade for operational records tied to the tool, while audit history is preserved by changing the `audit_logs.tool_id` foreign key to `ON DELETE SET NULL` and retaining denormalized `tool_slug` in audit rows. The reserved `access-admin` tool cannot be deleted.

Rationale: admins need a real delete action for incorrect or obsolete tool registrations, but audit history must remain intact and searchable after deletion.

## D-024 - Hierarchical tool permission-key format

Status: accepted

Decision: registered tool permission keys may use two or more colon-separated lowercase segments in the form `namespace:action[:scope...]`, for example `tool:read` or `petyr:read:all`. Each segment may contain lowercase letters, numbers and hyphens only. Empty segments, uppercase characters and dot-separated permissions remain invalid.

Rationale: some tools need action scopes such as `read:all` without encoding scope into a single opaque action string. The expanded format preserves fail-closed validation and registered-permission enforcement while supporting hierarchical tool permissions.


## D-025 - Bulk grant import operates on grants, not Google users

Status: accepted

Decision: bulk onboarding imports grant rows by company email and tool, not manually-created Google user records. Known emails are linked to existing users and committed as `active` grants. Unknown but allowed company emails are committed as `pending_user_link` grants and activate automatically at first verified Google login. Bulk `upsert` is idempotent for the same email/tool/role and updates existing active or pending grants instead of creating duplicates. Bulk `revoke` revokes matching non-revoked grants and active sessions.

Rationale: Google `sub` remains the stable identity source. Pre-creating local users would weaken identity semantics, while pending email grants preserve the current OAuth-first model and let admins authorize access before the user's first login.

## D-026 - Admin UI UNGUESS visual alignment is presentation-only

Status: accepted

Decision: the v1 same-service Admin UI uses the UNGUESS-aligned visual direction for the administrative shell: white and near-white surfaces, petrol-teal primary color, mint accent, subtle borders, light shadows, rounded cards, modern sans-serif typography and spacious enterprise SaaS layouts. This decision is limited to visual presentation.

Rationale: Access Layer is an internal administrative product for the UNGUESS ecosystem and should feel native to that environment, while preserving the already accepted v1 API, security, authorization, routing and data-flow decisions.

Operational consequence: visual refactors must not change authentication flows, permission behavior, API contracts, database behavior, environment variables, tool integrations or business logic unless a separate product/security decision explicitly authorizes that change.

## D-027 - Production Access Layer origin moved to UNGUESS internal domain

Status: accepted

Confirmed: 2026-07-02

Decision: production Access Layer uses `https://access-layer.unguess-internal.net` as its public origin, with no `/access-control` public base path. This supersedes the previous production origin `https://access-layer.draftapps.it`. Local Docker development remains on `http://localhost:8080/access-control`.

Canonical production URLs:

- Admin UI: `https://access-layer.unguess-internal.net/admin`
- Google callback: `https://access-layer.unguess-internal.net/v1/auth/google/callback`
- Admin API: `https://access-layer.unguess-internal.net/v1/admin/*`
- Tool auth API: `https://access-layer.unguess-internal.net/v1/auth/*`

Operational consequence: production must set `PUBLIC_BASE_PATH=` (empty), `APP_BASE_URL=https://access-layer.unguess-internal.net`, `AUTH_ISSUER=https://access-layer.unguess-internal.net`, `GOOGLE_REDIRECT_URI=https://access-layer.unguess-internal.net/v1/auth/google/callback` and `CORS_ALLOWED_ORIGINS=https://access-layer.unguess-internal.net`. Google Cloud must allow the matching redirect URI and origin. Tools should configure their Access Layer public/internal base URL as `https://access-layer.unguess-internal.net` unless a documented private internal URL is introduced.

Rationale: the Access Layer production service now belongs on the UNGUESS internal domain. The Google Workspace hosted-domain allow-list remains `unguess.io,nuotounostiledivita.it`; runtime service hosts such as `access-layer.unguess-internal.net` must not be added to `GOOGLE_ALLOWED_HD`.
