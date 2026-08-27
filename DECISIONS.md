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

## D-028 - Native SVG favicon for the Admin UI

Status: accepted

Decision: the Admin UI uses a native SVG favicon with an Access Layer "A" mark, petrol-teal primary background and mint accent. It is served beneath `PUBLIC_BASE_PATH` and linked from the Admin UI HTML.

Rationale: SVG keeps the mark sharp at the small dimensions used by browser tabs while following the accepted presentation-only UNGUESS UI direction.

## D-029 - Activity-driven sliding sessions with rotating refresh tokens

Status: accepted

Confirmed: 2026-07-24

Decision: Access Layer keeps authenticated sessions alive while the user remains active. Access tokens retain a 15-minute TTL. A successful server-to-server refresh, performed while handling authenticated user activity, atomically consumes the current opaque refresh token, issues a replacement, issues a new access token and moves the session idle deadline forward by 8 hours.

Unconditional background refresh is forbidden because an open but inactive page must not keep a session alive. If no valid refresh occurs within 8 hours, or if the tool, user, session or grant is no longer active, refresh is denied and the tool must clear its local session and restart login.

Operational consequence: tool backends must store refresh tokens only server-side, serialize concurrent refreshes for the same session, replace the rotated token atomically and treat `AUTH_REFRESH_TOKEN_INVALID` as a terminal local-session condition. The same-service Admin UI uses a protected HttpOnly refresh cookie and retries an Admin API request once after a successful activity-driven refresh.

Rationale: short-lived JWTs retain a small exposure window while active users are not interrupted every 15 minutes. Rotation prevents routine reuse of a refresh credential and online revalidation preserves immediate user/grant/session revocation.

## D-030 - Relationship-oriented grant administration UI

Status: accepted

Confirmed: 2026-08-05

Decision: the Admin UI presents authorization through the user-tool relationship. A platform-admin tool detail shows registered users and their effective access state; a user detail shows that user's grants per tool. Grant forms select from the visible tool catalog and from permission keys registered for the selected tool through an expandable checkbox list rather than accepting a manually typed tool slug or free-text permission list. Desktop views use the full available main-content width with responsive form columns.

The standard bulk-release form accepts one company email per line with one selected tool/role/permission set and converts that input to the existing guarded bulk-preview/commit payload. The advanced CSV import remains for mixed operations.

Rationale: access administration is primarily an entitlement-management task. Exposing the relationship in both directions reduces lookup and transcription errors while preserving the backend's existing validation, audit events, pending-email grants and atomic commit behavior.

Operational consequence: this is an Admin UI behavior change only. No API, grant model, permission policy or delegated tool-admin visibility is expanded; platform admins alone may see a complete registered-user access matrix.

## D-031 - Adopt Template v2.1 in legacy-migration mode

Status: accepted

Confirmed: 2026-08-24

Decision: Access Layer is classified as a `platform_service` and adopts Agent Ready Project Template v2.1.0 additively in `legacy-migration` mode. Existing repository documentation, decisions, tests, runtime files and history remain authoritative. Copied OAuth, MCP, Garden, AI-governance and telemetry material is target/reference documentation until explicitly implemented and recorded in `CURRENT_STATE.md`.

Rationale: the repository needs the platform contract and governance structure without changing the production authentication authority during the adoption step.

## D-032 - Freeze legacy v1 compatibility and block deployment on volume ambiguity

Status: accepted

Confirmed: 2026-08-24

Decision: the repository-observed v1 endpoints, callback, JWT/JWKS, session, refresh, grant, cookie, error and database contracts are frozen in `specs/legacy-contract-baseline.v1.json`. Step 1 makes no runtime or database change. The Compose reference `access_layer_postgres_data_v2` and declaration `access_layer_postgres_data` must remain untouched, and deployment is prohibited until the live Coolify mapping and a verified backup are available.

Rationale: preserving active sessions, refresh tokens, grant semantics and PostgreSQL continuity is more important than normalizing configuration whose live binding is unknown.

## D-033 - Require a redacted production-continuity evidence gate

Status: accepted

Confirmed: 2026-08-24

Decision: production continuity facts are captured in a versioned, schema-validated evidence bundle that distinguishes observed live state from repository expectations. The committed Step 1.5 bundle remains `NOT_READY`. It may become `READY` only when the validator confirms all Coolify, domain, runtime, storage, backup/restore, database metadata, environment-presence, public-key, registry, ownership and approval evidence. Validation is read-only and never propagates values into platform manifests or production.

Sensitive environment variables were initially recorded only as presence booleans; D-034 supersedes that representation with absent/empty/non-empty states, external sameness proof, and signing-key persistence evidence. Public JWT `kid` and public-key SHA-256 fingerprints are allowed; secrets, private keys, connection strings, cookies, tokens and personal rows are forbidden. The Compose volume mismatch remains untouched.

Rationale: later runtime work needs reproducible continuity proof without turning an evidence file or collection command into a secret-export path, and without mistaking declared configuration for live state.

## D-034 - Separate secret continuity proof and restore/upgrade readiness

Status: accepted

Confirmed: 2026-08-25

Decision: production-continuity evidence schema v2 replaces presence booleans with `UNOBSERVED`, `ABSENT`, `PRESENT_EMPTY`, and `PRESENT_NON_EMPTY` states for the complete environment/configuration surface derived from runtime, Compose, and entrypoint sources. Empty `PUBLIC_BASE_PATH` remains valid. Safe effective non-secret configuration is recorded separately from state-only secret inputs.

Presence never proves secret continuity. JWT signing-key continuity and the same-value binding of `SESSION_SECRET`, `TOOL_CLIENT_SECRET_PEPPER`, `BACKUP_ENCRYPTION_KEY`, `GOOGLE_CLIENT_SECRET`, and `LOG_IP_SALT` require operator/time/method records that reference access-controlled external evidence. Secret values, private key material, low-entropy hashes, HMACs, or other reusable verifiers are forbidden in Git. File-backed JWT mode additionally requires observation of the actual persistent storage/mount backing `/run/secrets`; Compose intent is not proof.

Readiness is staged. `ready_for_isolated_restore` permits only a separately authorised isolated restore exercise after all pre-restore evidence and approvals are complete. `ready_for_n_to_n_plus_1` additionally requires that isolated restore to be recorded `PASSED` with evidence and approval. Final `READY` is not weakened.

Rationale: session and refresh survival depends on stable signing and symmetric secrets as well as database persistence. A staged, secret-safe evidence gate makes the next operation explicit without claiming continuity from variable presence or from an unexecuted restore.

## D-035 - Preserve the live-resolved logical Compose volumes

Status: accepted

Confirmed: 2026-08-25

Decision: production evidence resolves the PostgreSQL source mismatch in favour of logical volume `access_layer_postgres_data_v2`, which is already mounted by the service and resolves live to `u3cyw3y1obp88to9la0w8c75_access-layer-postgres-data-v2`. The source top-level declaration is corrected to that logical name. JWT signing storage remains logical volume `access_layer_jwt_secrets`, resolving live to `u3cyw3y1obp88to9la0w8c75_access-layer-jwt-secrets`, and is represented as a named volume.

No explicit Compose `name:` is added. The service mount paths, UUID-prefixed physical volumes, database, network, resource and JWT volume are not renamed. This decision supersedes only D-032's instruction to leave the now-proven source mismatch untouched; the frozen legacy runtime contract and all remaining deployment gates continue unchanged.

Rationale: the resolved Coolify Compose supplies the previously missing continuity evidence. Matching the source declaration to the already-running logical mount prevents creation of an unintended empty PostgreSQL volume while leaving Coolify's physical-name management intact.

## D-036 - Freeze additive OAuth vNext P0 without implementation

Status: accepted

Confirmed: 2026-08-25

Decision: `specs/oauth-p0.v1.yml` is the normative Access Layer OAuth vNext P0 profile. Stable RFCs are normative and OAuth 2.1 is described only as a work-in-progress draft alignment. P0 contains RFC 8414 metadata, Authorization Code and Refresh Token, mandatory PKCE `S256`, exact redirect matching, one RFC 8707 resource, exact single audience, RFC 9068 JWT access tokens with `typ=at+jwt`, RFC 9207 authorization-response `iss`, RFC 7009 revocation, RFC 7662 introspection, RFC 9700 controls and RFC 9728 protected-resource metadata.

Human OAuth `sub` remains `users.google_sub` under D-004. OAuth tokens are PII-minimised and exclude email, hosted domain, profile data, legacy role and legacy permissions by default. Business scopes are exact `project:domain:action` capability IDs and are granted only by the intersection of resource registration, client/resource allowance, effective human entitlement and central policy.

OAuth client and resource identities are separate. As hardened by D-037, every P0 resource requires exactly one legacy-tool entitlement-only binding without changing the legacy tool model or making that tool the client or resource. P0 first-party browser applications remain BFF/server-side-token based and use centrally administered grants without a new end-user consent screen. A public authorization-code client contract exists, but production rollout is disabled until a concrete approved consumer exists.

OAuth uses a dedicated signing key ring and `/oauth/jwks`; legacy signing material and `/v1/.well-known/jwks.json` remain untouched. New keys are published 300 seconds before activation, JWKS cache age is 300 seconds, verifier skew is 60 seconds, and old verification keys remain for at least 1,260 seconds after last use. OAuth refresh replay revokes the complete family and linked OAuth session.

`client_credentials`, token exchange, `private_key_jwt`, downstream OIDC discovery/ID Token/UserInfo, dynamic registration, Client ID Metadata Documents, PAR, JAR and DPoP remain P1/deferred. Step 2 adds no handler, dependency, environment variable, table or migration.

Rationale: a complete machine-testable contract is required before implementation, while signing-key isolation, role separation and additive storage preserve rollback and every frozen legacy consumer contract.

## D-037 - Harden the OAuth P0 contract without runtime changes

Status: accepted

Confirmed: 2026-08-26

Decision: the shared RequestContext v1 schema retains its canonical two-or-more-segment hierarchical identifier grammar under the existing schema ID. The stricter exact `project:domain:action` grammar belongs only to OAuth P0 scope, token and resource contracts.

P0 PKCE accepts only verifiers of 43–128 RFC 7636 unreserved characters and S256 challenges of exactly 43 unpadded base64url characters; `plain` remains forbidden. Every P0 resource registration has exactly one `legacy_tool` entitlement-only binding. OAuth clients, OAuth resources and legacy tools remain separate identities, and native OAuth entitlement domains are deferred beyond P0.

P0 introspection requires separately authorised resource-server credentials and discloses only audience-authorised RFC 9068 Bearer access tokens as active. Refresh, inactive, unknown and otherwise non-disclosable tokens return exactly `{"active":false}`; invalid caller credentials return HTTP 401. Refresh-token rotation and RFC 7009 revocation remain unchanged.

Future OAuth vNext Google transactions return to `/oauth/upstream/google/callback`. It is an internal, non-advertised path, is not implemented in Step 2 and never reuses `/v1/auth/google/callback`. A later production Google registration must add the new URI without removing the legacy URI. Exact downstream client state is retained only in short-lived reversible protected storage, optionally indexed by a hash and never logged; upstream Google state and nonce may remain hash-only.

Rationale: these rules remove incompatible shared-schema semantics and underspecified security behavior before implementation while preserving all frozen legacy contracts and keeping Step 2 contract-only.

## D-038 - Freeze explicit entitlement mappings, resource introspection ownership and separate release gates

Status: accepted

Confirmed: 2026-08-26

Decision: an OAuth P0 resource's mandatory `legacy_tool` binding uses the exact frozen runtime tool-slug grammar. Every canonical resource scope has exactly one explicit `legacy_permission_key` mapping, and the mapping set covers the resource's declared scopes exactly. The key may equal the canonical scope, but no prefix, segment or alias conversion is inferred. The exact mapped key must be registered for the bound tool and present in the human's effective active grant; missing, duplicate, extra, stale, unknown or ungranted mappings fail closed as `invalid_scope`/deny. Legacy permission and grant data remain unchanged.

P0 introspection authenticates with `client_secret_basic` credentials owned by one OAuth resource. The proposed `oauth_resource_credentials` model stores a resource FK, stable credential ID, non-reversible secret hash, status and lifecycle/rotation metadata. It is not an OAuth client credential or legacy tool client. `active=true` may be disclosed only when the access token's exact `aud` equals the authenticated credential's resource; every audience mismatch returns exactly `{"active":false}`.

After Step 2 approval, generic Step 3 implementation may proceed locally/dark with OAuth globally disabled. A concrete pilot registration is required before enablement or production registration, not before generic implementation. Production deploy/enable remains blocked by the Coolify `Changes pending` review, verified backup/restore, destination, central registry, named ownership, deployed revision/image identity, secret/key continuity and later N→N+1 gates.

Rationale: exact mappings prevent Step 3 from inventing authorization conversions, resource-owned credentials preserve identity separation, and distinct development/release gates allow safe dark implementation without weakening operational continuity requirements.

## D-039 - Isolate the Step 3A OAuth dark foundation from legacy request handling

Status: accepted

Confirmed: 2026-08-26

Decision: implement Step 3A through one expand-only `003_oauth_dark_foundation.sql` migration and a standalone `src/oauth/` module. The migration creates only the ten approved registration, entitlement-bridge, allow-list, credential-hash and signing-metadata tables. Cross-table registration facts that cannot be represented safely by PostgreSQL `CHECK` constraints are validated by pure fail-closed domain helpers before any future persistence path. Repository primitives resolve foundation metadata from `oauth_*` tables and may read only `tools` and `tool_permissions` for the frozen entitlement bridge.

`OAUTH_P0_ENABLED` is an optional default-false configuration input. Step 3A intentionally does not branch on it in `buildApp`, so neither `false` nor `true` registers a protocol route. The module exposes no HTTP registration API, secret issuance, credential authentication, token signing or authorization decision path.

Rationale: a separate schema/module boundary makes the additive storage reviewable and old-binary compatible, prevents accidental coupling to the frozen legacy path, and leaves all protocol behavior for a later separately approved step. This decision records implementation structure only; D-036, D-037, D-038 and `specs/oauth-p0.v1.yml` remain the protocol semantics.

Hardening note, 2026-08-26: the same boundary owns schema-parity URI and client-credential-lifecycle validation plus a pure signing-key lifecycle/public-JWK validator. Because migration `003` is unreleased, its signing constraints are hardened in place to encode the already-frozen 300/1,260-second rules and NULL-safe public-JWK shape. This refines D-039's implementation structure and introduces no protocol decision.

## D-040 - Sequence read-only OAuth metadata before authorization-server discovery

Status: accepted

Confirmed: 2026-08-26

Decision: compose Step 3B outside the frozen legacy `buildApp` boundary. `OAUTH_P0_ENABLED=true` registers only the dedicated read-only `/oauth/jwks` and RFC 9728 protected-resource metadata routes. The exact frozen RFC 8414 payload is built and tested now but its well-known route remains unregistered while authorize, token, revoke and introspect are absent, so the service does not advertise endpoints that return 404.

OAuth JWKS publication uses only repository-returned public metadata, validates lifecycle and public-JWK shape, publishes valid pre-activation `published` and `active` records in deterministic `kid` order, and returns sanitized `temporarily_unavailable` when no safe key exists. It never falls back to or changes the legacy key ring.

Rationale: a separate default-off composer preserves the frozen legacy source and route inventory while allowing truthful incremental publication. This decision records implementation sequencing only and does not revise D-036 through D-039 or the frozen target contract.

Hardening note, 2026-08-26: the unreleased no-pilot RFC 9728 example incorrectly emitted `scopes_supported: []`. It now omits that zero-valued multi-value parameter, while a present member requires at least one canonical scope. This is a conformance correction because stable published RFCs remain normative over repository examples; it does not create a new protocol choice. The same implementation boundary now preserves issuer identity exactly, disables automatic `HEAD` siblings for the two GET routes, and requires RSA `n`/`e` to be valid unpadded Base64urlUInt before publication. These are fail-closed implementation hardenings within D-040, not Step 3C semantics.

## D-041 - Isolate dark authorization issuance and transaction protection

Status: accepted

Confirmed: 2026-08-26

Decision: implement Step 3C outside the frozen legacy `buildApp` boundary through one OAuth flow repository, one authorization service, one separate upstream-Google adapter and one dedicated state-protection primitive. Migration 004 owns only authorization transactions, authorizations and authorization codes. The service may call the frozen legacy user upsert and pending-grant-link methods, read the active grant, and append sanitized audit rows; every other OAuth write remains confined to `oauth_*` tables.

The dedicated `OAUTH_TRANSACTION_PROTECTION_KEY` is decoded only when configured, is mandatory only under the existing true OAuth flag and is never derived from a legacy secret. Transaction creation/audit, denial/audit and authorization/code/completion/audit execute atomically in short database transactions. The Google network exchange occurs only after the upstream-state claim transaction has completed.

Rationale: this structure makes the narrow legacy mutation exception auditable, keeps external I/O outside database transactions, and prevents partial code issuance or missing decision audits. The 600-second transaction TTL, 60-second code TTL, exact redirect/error behavior, AES-256-GCM parameters and entropy/hash rules are authorised frozen Step 3C inputs, not new protocol semantics.

## D-042 - Keep the Step 3D OAuth token lifecycle atomic, key-isolated and unmounted

Status: accepted

Confirmed: 2026-08-27

Decision: implement Step 3D through one expand-only four-table migration plus a separate OAuth token repository, lifecycle service and signing boundary. Authorization-code consumption, OAuth session/refresh-family/root-token persistence, sanitized audit and signing-key `last_signed_at` update commit as one transaction. Refresh rotation applies the same rule; a consumed-token replay commits whole-family and linked-session revocation before the service returns `invalid_grant`.

OAuth client/resource credentials use only the dedicated `OAUTH_CREDENTIAL_SECRET_PEPPER`, which must not equal `TOOL_CLIENT_SECRET_PEPPER`; public clients use registered method `none`, and no credential lookup falls back to legacy `tool_clients`. OAuth signing uses only one active, non-retiring OAuth key whose local file reference resolves inside `OAUTH_SIGNING_KEY_ROOT`, has a different derived RSA public identity from the actual configured legacy key, and matches the persisted public JWK and canonical public fingerprint. Old active overlap keys remain verification-only strictly before `retire_after`. Zero or multiple signable keys fail closed.

Read-only client/authorization/resource/user/grant rows use SHARE locks only; code exchange UPDATE-locks only the code row, while refresh UPDATE-locks only token/family/session rows. Stored authorization/code/family/token scope and generation state is cross-checked before signing. A failed code transaction is followed by a separate bounded sanitized `oauth.code.exchange_denied` audit transaction; if that write fails, the caller receives `temporarily_unavailable`. Access-token revocation resolves an exact OAuth resource independent of active status so jti revocation remains durable across resource disable/re-enable.

Step 3D exposes no HTTP route. `/oauth/token`, `/oauth/revoke`, `/oauth/introspect` and RFC 8414 remain unregistered until a separately approved Step 3E. The new credential pepper and signing root are optional at route-composition/config-load time so the existing Step 3B/3C dark surface remains usable for isolated tests; invoking a Step 3D operation that needs either input fails closed when it is absent.

Rationale: transactional shared state closes code/refresh races and preserves audit completeness, while strict OAuth-only credentials and realpath-bound key loading prevent legacy fallback or cross-key-domain signing. Keeping the core unmounted permits review and deterministic testing without advertising or enabling the protocol surface.
