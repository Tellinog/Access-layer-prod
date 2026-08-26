# CURRENT_STATE.md

## Phase

V1 legacy implementation complete. Step 3B adds a local, default-off read-only OAuth metadata/JWKS module over the Step 3A foundation. Authorization, token and upstream Google runtime remain unimplemented.

## Step 3B read-only OAuth metadata/JWKS dark module, 2026-08-26

- Added a separate application composer and `src/oauth/` metadata, JWKS-selection and HTTP modules. The frozen `src/app.ts` legacy builder remains byte-identical; when `OAUTH_P0_ENABLED` is absent/false, the composer registers nothing and the legacy route inventory is exact.
- With `OAUTH_P0_ENABLED=true`, only `GET /oauth/jwks` and `GET /.well-known/oauth-protected-resource/v1` are added; explicit `HEAD` requests remain 404. Authorization-server metadata, authorize, token, revoke, introspect and upstream Google callback routes remain 404.
- Pure RFC 8414 and RFC 9728 builders reproduce the corrected target examples while preserving supplied issuer identity exactly and normalizing only the base used to construct endpoint URLs. RFC 8414 is deliberately not routed until its advertised protocol endpoints exist. In accordance with RFC 9728, no-pilot metadata omits zero-valued `scopes_supported`; the member is emitted only for a non-empty scope list.
- OAuth JWKS reads only public signing metadata through `OAuthFoundationRepository`, validates lifecycle and public-JWK shape, including unpadded Base64urlUInt `n`/`e`, exposes valid `published` pre-activation overlap plus `active` verification keys, sorts by `kid`, and excludes staged/disabled/retired/malformed records. A successful response uses `Cache-Control: public, max-age=300`; no valid key or repository failure returns sanitized HTTP 503 `temporarily_unavailable` rather than an empty 200.
- The legacy `/v1/.well-known/jwks.json` route, key material and response are unchanged. No private-key reference is selected, no key loader/signing path exists, and no migration, dependency, pilot/seed, registration/admin API, consumer/SDK or production/Coolify action was added.
- Before Step 3D signing, any future file/reference loader must reject path traversal, unsafe paths and unsupported schemes. This is recorded as a blocker; Step 3B implements no loader.
- Step 3B hardening corrects an unreleased zero-value RFC 9728 example/schema error, rejects malformed RSA encodings before publication, enforces the documented GET-only surface and preserves exact issuer identifiers. Stable published RFC requirements remain normative; no Step 2 protocol flow semantics were invented or changed.
- Final hardening verification passes: TypeScript lint/build; 211 Vitest tests across 14 files; Python 60 passed and 2 skipped (62 collected); all 24 OAuth validator groups; continuity as `VALID_BUT_NOT_READY` with both gates false; non-strict platform validation with 27 passes/seven known warnings; frozen legacy/dependency/migration audit; and `git diff --check`. Live PostgreSQL remains unavailable because Docker has no reachable daemon, no local PostgreSQL listener exists, and `psql` is absent; Step 3B hardening adds no migration.

## Step 3A OAuth Dark Foundation, 2026-08-26

- The local/unreleased Step 3A candidate is hardened in place: exact redirect/resource URI validation now rejects raw whitespace/control characters, backslashes, malformed percent escapes, userinfo, fragments and wildcards before applying the frozen HTTPS/localhost rules, without rewriting the registered string.
- Normalized client registration metadata now includes only non-secret credential lifecycle fields and requires `secretPresent=true` for confidential `client_secret_basic` clients and `false` for public `none` clients. No plaintext secret or hash is part of the validation object.
- Dedicated OAuth signing metadata now enforces the frozen 300-second publication lead, 1,260-second post-signature retention, retirement ordering and coherent staged/published/active/retired lifecycle states in both migration constraints and a pure future-selection validator. The public-JWK `CHECK` is NULL-safe and requires non-empty string `kty`, `kid`, `alg`, `use`, `n` and `e` members while continuing to reject private members.
- Added the expand-only `migrations/003_oauth_dark_foundation.sql` after the two frozen legacy migrations. It creates exactly the ten approved `oauth_*` client, redirect, resource, entitlement bridge, scope allow-list, credential and signing-metadata tables without altering or writing any legacy table.
- Added `OAUTH_P0_ENABLED`, default `false`. An environment that omits it continues to load with the legacy requirements only. The value is deliberately not consumed by `buildApp`; setting it to `true` registers no OAuth route in Step 3A.
- Added isolated `src/oauth/` types, read-only foundation repository resolution and pure fail-closed controlled-registration validation. Repository SQL is limited to `oauth_*` tables plus read-only `tools`/`tool_permissions` entitlement lookups; it performs no inferred scope-to-permission conversion.
- Database constraints enforce separate client/resource identity domains, exact non-wildcard redirect records, at most one active legacy-tool binding per resource, canonical three-segment scopes, one explicit resource/scope mapping, explicit client/resource/scope allow-list rows, resource-owned introspection credential metadata, hash-only credential columns and OAuth-only public signing metadata/private-key references. Exact bound-tool permission membership and complete registration coverage are additionally fail-closed domain validations because they cross table boundaries.
- No authorization transaction, authorization, code, OAuth session, refresh family/token or revocation table exists. No metadata, authorize, token, revoke, introspect, OAuth JWKS or upstream Google callback route exists. No seed, pilot, production/Coolify action, legacy data migration, key provisioning or secret rotation occurred.
- `specs/oauth-p0.v1.yml`, target OAuth schemas/OpenAPI/examples, legacy `/v1/*` runtime, legacy OpenAPI, legacy migrations, dependencies, consumers and Platform SDK remain semantically unchanged.
- The production-continuity inventory now includes the optional `OAUTH_P0_ENABLED` input as its 42nd source-derived variable; the committed production evidence remains `NOT_READY` and the optional flag is `UNOBSERVED` there.
- Verification passes: TypeScript lint/build; 145 Vitest tests across 14 files; 62 Python tests with two expected skips; 24 OAuth validator check groups; non-strict platform check with 27 passes/seven known warnings; continuity schema validation as `VALID_BUT_NOT_READY`; environment-template parity; and `git diff --check`. Live migration application remains unverified because the Docker daemon and local PostgreSQL are unavailable; deterministic migration tests cover the shape and the limitation is in `BACKLOG.md`.
- Before the first non-empty production OAuth registration/pilot, backup/export/import/replace-restore must be extended and restore-tested for `oauth_*` state and dependency-safe legacy-tool deletion ordering. This is a release blocker only; Step 3A hardening does not change backup behavior.
- Step 3A hardening verification passes: TypeScript lint/build; 190 Vitest tests across 14 files; 62 Python tests with two expected skips; all 24 OAuth validator check groups; continuity validation as `VALID_BUT_NOT_READY`; non-strict platform validation with 27 passes/seven known warnings; exact ten-table/destructive-SQL shape checks; frozen-file diff audit; and `git diff --check`. Disposable PostgreSQL remains unavailable because the Docker daemon is unreachable and no local server listens on port 5432.

## Step 2 OAuth P0 hardening, 2026-08-26

- Final hardening aligns the OAuth resource bridge with the exact legacy tool-slug grammar and aligns `specs/validation.v1.yml` with the runtime's two-or-more-segment legacy permission grammar. Runtime validation is unchanged.
- Every declared P0 resource scope now has exactly one explicit `legacy_permission_key` mapping. Coverage must be exact with no missing, extra or duplicate scope; inferred conversion is forbidden, and missing/stale/unknown/ungranted mappings fail closed.
- Proposed `oauth_resource_credentials` are owned by one OAuth resource, use `client_secret_basic`, store only a non-reversible secret hash plus lifecycle/rotation metadata, and are separate from OAuth client credentials and legacy tool clients. `active=true` requires the token's exact `aud` to equal the credential's resource.
- The target contract is hardened without runtime implementation: shared RequestContext v1 again accepts canonical hierarchical identifiers with two or more segments, while OAuth P0 alone retains exact `project:domain:action` scope grammar.
- PKCE now enforces 43–128 RFC 7636 unreserved verifier characters and an exact 43-character unpadded base64url S256 challenge; `plain` remains forbidden.
- Every P0 resource now requires exactly one legacy-tool entitlement-only binding. OAuth client, resource and legacy tool identities remain separate; native OAuth entitlement domains are deferred beyond P0.
- P0 introspection discloses only RFC 9068 Bearer access tokens whose exact audience matches the authenticated resource-owned credential. Refresh, audience-mismatched, inactive, unknown and otherwise non-disclosable tokens return exactly `{"active":false}`.
- Future OAuth-to-Google transactions use the separate internal `/oauth/upstream/google/callback`, which is neither advertised nor implemented and never reuses the frozen legacy callback. Future production Google registration adds it without removing the legacy URI.
- The additive transaction proposal retains exact downstream client state in short-lived reversible protected storage, with an optional hash and no logging; upstream Google state and nonce remain hash-only. No migration exists.
- After Step 2 approval, generic Step 3 work may proceed locally/dark with OAuth globally disabled. Pilot registration details are required before enablement/production registration, not before generic implementation. Production deploy/enable remains blocked by `Changes pending`, backup/restore, destination, registry, ownership, deployed revision/image, secret/key continuity and later N→N+1 gates.
- Final-hardening verification results are recorded in `DEVLOG.md`; no concrete pilot mapping or resource credential was seeded.

## Step 2 production evidence reconciliation, 2026-08-25

- Non-secret Coolify evidence now identifies server `agentic-unguess-prod` (`wx513ojqd80kdicevubog7`), project `agentic-unguess` (`xdihnb979tvyh9gdk72zfy7y`), environment `production` (`rd3mt4dkpqyghxlx9h96sdlo`), production resource `access-layer-prod` (`u3cyw3y1obp88to9la0w8c75`), observed resource type `application`, managed Docker Compose, `main` branch, deploy-on-push, disabled previews and isolated networking. Destination identity remains unresolved.
- The live origin is `https://access-layer.unguess-internal.net`; app port `8080` has no shown public host-port mapping and PostgreSQL port `5432` remains private.
- Live resolved Compose proves logical PostgreSQL volume `access_layer_postgres_data_v2` and logical JWT volume `access_layer_jwt_secrets`, backed by the recorded UUID-prefixed named volumes. The source Compose top-level PostgreSQL declaration now matches the unchanged service mount. No explicit physical volume name was added and no live resource was changed.
- The volume-name mismatch is resolved. Coolify visibly reported `Changes pending`; that state requires explicit pre-production-deploy diff review and is not a runtime change. Production remains blocked by that review plus unverified backup/restore, destination identity, central registry, named ownership, deployed revision/image and continuity-secret/key evidence. No deployment was performed.

## Step 2 OAuth vNext P0 contract freeze, 2026-08-25

- The additive P0 OAuth contract is frozen in `specs/oauth-p0.v1.yml`, `docs/OAUTH_P0_CONTRACT.md` and the target-only OAuth OpenAPI/schemas/examples. Protocol runtime remains unimplemented and disabled; the later Step 3A foundation does not change these semantics.
- P0 defines RFC 8414 metadata, Authorization Code and Refresh Token, PKCE `S256`, exact redirects, one RFC 8707 resource/audience, RFC 9068 `typ=at+jwt`, RFC 9207 `iss`, revocation, introspection, RFC 9700 controls, RFC 9728 metadata, OAuth errors, controlled registration, refresh-family replay, dedicated key rotation and audit requirements.
- Human OAuth `sub` remains Google `sub`; access tokens are PII-minimised. OAuth clients/resources are separate, and every P0 resource has exactly one legacy-tool entitlement-only binding. Browser applications remain BFF/server-side-token based.
- `client_credentials`, token exchange, `private_key_jwt`, downstream OIDC ID Token/UserInfo/discovery and dynamic registration remain P1/deferred. No OAuth handler, migration, dependency, production registration or deploy was added.
- Verification passes: lint, build, 113 Vitest tests, 50 Python tests (two template-bootstrap skips), 12 OAuth contract check groups, schema/example/OpenAPI reference validation, legacy baseline checks and resolved Compose inspection. Non-strict platform conformance passes with 27 checks and seven known warnings; strict release conformance remains blocked on five external operational gates.

## Step 1.5B continuity evidence hardening, 2026-08-25

- Production-continuity evidence is schema v2 and remains deliberately redacted and `NOT_READY`. It distinguishes absent, empty, and non-empty environment states, preserves an empty production `PUBLIC_BASE_PATH` as valid, and now inventories all 42 configuration inputs derived from `src/config.ts`, `docker-compose.yaml`, and `docker/entrypoint.sh`, including Step 3A's optional default-false flag.
- File-backed and inline JWT signing modes are explicit. File-backed readiness requires proof of the actual persistent `/run/secrets` storage/mount as well as public `kid`/public-key fingerprint evidence; private key material and private verifiers remain forbidden.
- `SESSION_SECRET`, `TOOL_CLIENT_SECRET_PEPPER`, `BACKUP_ENCRYPTION_KEY`, `GOOGLE_CLIENT_SECRET`, and `LOG_IP_SALT` require external, secret-safe sameness proof. Presence alone is insufficient, and no secret value or reusable verifier may be committed.
- Validation exposes separate `ready_for_isolated_restore` and `ready_for_n_to_n_plus_1` gates. The final gate still requires a `PASSED` isolated restore. The committed template has both gates false; no restore, live collection, or upgrade exercise was performed.
- Runtime sources, Compose, entrypoint, production configuration, endpoints, JWT/session/refresh/grant behavior, database and migrations are unchanged. The PostgreSQL Compose-name mismatch remains an unresolved deployment blocker.

## Step 1.5 workspace hygiene and continuity evidence preparation, 2026-08-24

- Repository line endings are deterministic: text is LF by default, Windows command scripts remain CRLF, and common binary assets are marked binary. Renormalization produced no tracked content changes beyond `.gitattributes`.
- A versioned production-continuity evidence schema, intentionally incomplete `NOT_READY` bundle, fail-closed validator, read-only metadata helpers and manual Coolify/terminal collection checklist are present.
- The evidence model separates the unobserved live/current domain from the documented intended target `https://access-layer.unguess-internal.net`, and separates all observed runtime fields from repository expectations.
- No live facts were inferred or copied into `project.platform.yaml` or `deployment.registration.yaml`. Coolify identifiers, owners, central registry proof, backup schedule/retention, real volume identity and isolated restore result remain unresolved.
- The Compose mismatch remains unchanged: PostgreSQL references `access_layer_postgres_data_v2`, while the top-level volume declaration is `access_layer_postgres_data`. Deployment remains blocked.
- The N→N+1 harness remains `DOCUMENTED_NOT_RUN`; its original single-gate description is superseded by the schema-v2 staged gates described above.

## Current status

This repository now contains the product/security/API/data specifications plus a Node.js/TypeScript Fastify implementation for the Access Layer Google SSO v1 service.

## Latest Admin authorization usability update, 2026-08-05

- Tool detail now includes a user-access table: platform admins can see every registered user, whether access to the selected tool is currently effective, and the related roles, permissions and grant states. Grants can be created or managed directly from that table.
- User detail remains one row per person in the Users list and now shows all of that user's tool grants in a dedicated table, with a direct `Aggiungi tool` action.
- Grant creation, editing, access-request approval and bulk release now use the visible tool catalog and the selected tool's registered permission keys instead of manual tool-slug and free-text permission entry. Permission keys are selected through an expandable checkbox list with a visible selection count.
- Desktop Admin UI views now use the full available main-content width and responsive multi-column forms; compact screens retain the single-column layout.
- The primary bulk release flow accepts one corporate email per line and creates the guarded CSV payload internally; Preview and error-blocked Commit semantics remain unchanged. Advanced CSV import remains available for mixed batch operations.
- Tool-admin visibility was not broadened: the complete registered-user matrix remains available only to platform admins, while delegated admins retain assigned-tool grant scope.
- Verification: `npm.cmd run lint`, `npm.cmd run build` and `npm.cmd test` passed (10 test files, 100 tests).

## Latest Coolify Docker build fix, 2026-07-24

- Coolify deploys at commits `bb3cac7d68935bc4f8478196774cfcadaee443e1` and `81d95a87adb09343fdc1195efe7f9f61b8b66867` failed at `RUN npm run build`.
- Root cause: the favicon asset build script and `assets/` directory were not copied into the Docker builder stage.
- The Dockerfile now copies both build-time inputs before compilation, and regression coverage protects their ordering.
- Clean builder-stage simulation, lint and build passed; the full suite passes with 10 files and 100 tests.
- Full local image construction remains unverified because the Docker daemon is unavailable in this workspace.

## Latest activity-driven session refresh update, 2026-07-24

- Added `POST /v1/auth/refresh` with tool client authentication, opaque refresh-token rotation, active tool/user/session/grant revalidation and a new 15-minute JWT.
- Successful refresh extends the session and replacement refresh token idle deadline by 8 hours from authenticated user activity.
- Refresh tokens are single-use; invalid, expired, reused or no-longer-authorized refresh attempts return `AUTH_REFRESH_TOKEN_INVALID`.
- The Admin UI now stores its refresh credential in a separate signed HttpOnly cookie, refreshes and retries once on authenticated activity, and clears both cookies when renewal fails or the user logs out.
- The reference tool harness demonstrates server-side, activity-driven refresh and explicitly avoids background keepalive timers.
- Verification passes with lint, build and the current full automated suite: 10 test files and 100 tests.

## Latest Admin UI favicon update, 2026-07-23

- Added an SVG Access Layer favicon, served beneath the configured public base path and linked by the Admin UI HTML.
- The favicon is copied into the compiled runtime output, so it is available through both local `npm start` and the production image.

## Latest bulk grant CSV delimiter fix, 2026-07-21

- Bulk grant preview and commit now detect whether the required header row uses comma or semicolon delimiters when the client does not specify one.
- The Admin UI explicitly documents both accepted separators, avoiding false `missing_headers` errors for semicolon-delimited CSV content.
- API, UI and test documentation now describe the automatic detection behavior.
- Verification: targeted Admin bulk-import regression coverage was added; final check results are recorded in `DEVLOG.md`.

## Latest production domain update, 2026-07-02

- Production Access Layer configuration and documentation now target `https://access-layer.unguess-internal.net` instead of `https://access-layer.draftapps.it`.
- Production remains root-mounted with `PUBLIC_BASE_PATH=`, Admin UI at `/admin`, APIs under `/v1/*` and Google OAuth callback at `/v1/auth/google/callback`.
- Updated production env template, Coolify/deployment guidance, Google OAuth setup, OpenAPI server URL, integration examples, reference seed return URL and config test coverage.
- `GOOGLE_ALLOWED_HD` remains restricted to Google Workspace hosted domains: `unguess.io,nuotounostiledivita.it`.
- Verification: config test coverage was updated; final lint/build/test results for this task are recorded in `DEVLOG.md`.

## Latest Admin UI authenticated logout update, 2026-07-02

- The authenticated Admin UI top bar no longer renders a fixed `Login` button after a valid admin session is present.
- The same action area now starts as `Logout`, calls the existing Admin UI logout route, clears the admin cookie through the server response and revokes the server-side Access Layer session.
- `Login` remains only as a fallback if the already-rendered page cannot confirm `/me`, after which the normal invalid-session redirect behavior still applies.
- Added Admin UI regression coverage for the authenticated shell markup so the old fixed login button does not reappear.
- Verification: `npm.cmd run lint`, `npm.cmd test -- tests/app.admin.test.ts` and `npm.cmd test` passed; full test suite result is 9 files and 95 tests.

## Latest Admin UI visual alignment update, 2026-07-02

- The same-service Admin UI has been visually restyled to align with the UNGUESS enterprise SaaS direction: white primary background, subtle neutral surfaces, petrol-teal primary color, mint accent, Inter/system sans-serif typography, larger spacing, rounded cards, refined tables and calmer form/button states.
- The update is presentation-only. API routes, authentication, permissions, admin workflows, backend logic, database behavior, environment variables, integrations, function names and data flow are unchanged.
- Verification in this workspace was limited because `node_modules` is absent and the task explicitly disallowed external fetches. `npm run lint`, `npm run build` and `npm test -- tests/app.admin.test.ts` could not run without installing dependencies.
- A no-dependency static check confirmed the new table wrapper is balanced and the requested primary/accent palette tokens are present in `src/app.ts`.

## Defined

- Centralized Google OIDC login flow.
- Tool registration model.
- User, grant, tool, session and audit-log domain model.
- Admin authorization workflow.
- API contract and payload examples.
- PostgreSQL reference schema.
- Google Cloud setup guide.
- Integration guide for existing and future tools.
- Implementation plan for Codex or other coding agents.
- SQL migration baseline in `migrations/001_initial.sql`.
- Runtime configuration loader with fail-closed validation.
- Backend routes for auth start/callback, exchange, introspection, logout, JWKS, `me`, admin tools/users/grants/access-requests/audit logs.
- Minimal same-service Admin UI under the configured public base path, with local Docker using `/access-control` and production using `/admin` on the dedicated Access Layer origin.
- Unit tests for validation, fail-closed config loading, hosted-domain config validation, security helpers, encrypted backup payloads, audit redaction, Google ID token claim validation, JWT issuing/JWKS/audience/expiration/unknown-key rejection, configured CORS preflight behavior, auth-start denial/rate-limit/audit-write-failure behavior, callback unknown-state denial, mocked external-domain and unverified-email callback denial without access-request creation, mocked no-grant access request creation/repetition, pending email grant linking, mocked allowed callback, exchange success, wrong tool-secret denial, code replay denial, introspection active/revoked behavior, admin tool creation/list/search-status-owner filtering/update/delete/secret rotation with one-time secret hashing/registered permission keys/audit, encrypted backup export and restore secret material authorization, admin user search/status filtering and disable/session-revocation audit, admin email and known-user grant creation, pending external email grant denial, admin grant update/revocation/session revocation, delegated tool-admin grant read/write assigned-scope enforcement, admin access-request approval/rejection/closure, tool-admin access-request assigned-scope enforcement, auditor write denial, admin status filter validation and Admin UI callback/logout/tool-onboarding/tool-filtering/user-filtering/known-user-grant/audit-filter/grant-management/access-request-management/pagination-empty-state/settings-summary behavior.
- Dependency-free tool integration harness under `examples/tool-harness/`.
- Docker Compose local development stack for Access Layer plus PostgreSQL, with container startup migrations and local seed execution.
- Backup security hardening with encrypted export/import and explicit backup permissions.

## Implemented

- Backend service source under `src/`.
- Runtime config validation rejects invalid `GOOGLE_ALLOWED_HD` values such as `localhost`, URLs and IP addresses.
- PostgreSQL migration runner that requires only `DATABASE_URL`, plus seed command.
- Google OIDC adapter using `google-auth-library`.
- Access Layer JWT/JWKS using `jose`.
- Tool registry, grants, one-time code exchange, refresh token hashing, logout and introspection.
- Admin tool list/create/update/delete responses expose registered permission keys without exposing tool client secrets after the one-time create/rotate response; tool lists support search, status and owner-email filters while preserving assigned-tool scoping. Permission keys support colon-separated hierarchical segments such as `tool:read` and `petyr:read:all`.
- Admin UI tool detail starts read-only, supports explicit edit mode for metadata/Return URL/permission-key changes, supports non-reserved tool deletion and shows inline success/error feedback for save/delete actions, including backend correlation IDs when the API returns an error.
- Already-rendered Admin UI pages redirect back to the admin login flow when an API response indicates an invalid or expired admin session. Admin UI JSON headers are only sent for requests with a body, so empty-body deletes are accepted by Fastify route handling.
- Admin user list supports search/status filters and Admin UI exposes those filters; disabling or suspending a user revokes active sessions and requires a destructive confirmation in the UI.
- Admin UI user detail can create an active grant for an already-known user through the existing audited grant creation API.
- Delegated `tool_admin` grants are constrained to assigned tools for list, create and update routes.
- Access request creation/repetition, admin approval/rejection/close and Admin UI filtering/decision controls.
- Access request reopen suppression using `ACCESS_REQUEST_REOPEN_AFTER_DAYS`.
- Audit events for access decisions, token exchange/introspection/logout and admin changes.
- Auth-start audit write failures fail closed before Google redirect or auth request persistence.
- Endpoint-specific rate limits for auth start, token exchange, introspection and admin writes, in addition to the global baseline limit.
- Baseline HTTP security headers.
- CORS allow-list handling from `CORS_ALLOWED_ORIGINS`.
- API-wide token-in-query rejection before route handling.
- Fail-closed admin status filter validation for users, grants and access requests.
- Explicit validation for grant creation with unknown user IDs.
- Server-side Admin UI session revocation on logout.
- Denied logout audit events for stale or already-inactive session and refresh-token revocation attempts.
- Transaction-bound audit writes for admin tool update/delete/secret rotation, user status changes, grant creation/updates and access-request rejection/closure.
- Audit log filtering by date range, tool, email, Google sub, outcome, reason code and correlation ID, exposed through API and the minimal Admin UI.
- Minimal Admin UI detail/edit views for tools, users and grants, including tool description/owner/return URL/permission-key onboarding controls, client-side table pagination/empty states and a non-sensitive OAuth/runtime settings summary.
- Admin UI root routes render the dashboard only after a valid `access-admin` admin session is present; unauthenticated visits redirect directly into the Google admin login flow.
- Admin UI create/decision workflows for tools, grants, access requests and tool-secret rotation now use inline same-page forms instead of sequential browser prompt/alert dialogs.
- Backup export now returns an AES-256-GCM encrypted JSON envelope using `BACKUP_ENCRYPTION_KEY`; backup import can decrypt the encrypted envelope.
- Backup read, write and restore secret material export require explicit backup permissions and no longer inherit from `admin:secrets:rotate`.
- Restore secret material export can return `TOOL_CLIENT_SECRET_PEPPER` and `BACKUP_ENCRYPTION_KEY` to explicitly authorized platform admins; existing per-tool client secrets remain non-recoverable because only hashes are stored.
- Admin cookie-authenticated write requests require same-origin validation.
- Client IP proxy trust is bounded by `TRUST_PROXY_HOPS`, defaulting to one hop for production/Coolify and zero for local development.
- Pending grant creation by email now requires a well-formed company email domain listed in `GOOGLE_ALLOWED_HD`.
- Example native Node tool harness that demonstrates login, callback, exchange, local session and logout.
- Reference seed data aligned to the confirmed `unguess.io` Google Workspace domain, while production service URLs are prepared for `access-layer.unguess-internal.net`.
- `Dockerfile`, `docker-compose.yml`, `.env.docker.example` and `docker/entrypoint.sh` for local Docker execution. The app container waits for PostgreSQL health, runs migrations, optionally runs seed data, probes the app health endpoint every 10 seconds and starts the built service on port `8080`. App health routes are intentionally silent in request logs.
- The runtime seed reconciles the reserved `access-admin` tool return URLs with the configured public base path, so persisted local databases are updated from legacy `/admin/auth/callback` URLs to `/access-control/auth/callback` when the current Docker seed runs.

## Verified in this environment

- Dependency installation is present and `npm.cmd ls --depth=0` reports all declared dependencies installed.
- Typecheck passes with `npm.cmd run lint`.
- Production build passes with `npm.cmd run build`.
- Automated test suite passes with `npm test`: 9 files, 92 tests.
- Docker Compose YAML parses successfully in this environment; full `docker compose config` was not run here because the Docker CLI is unavailable in this container.
- `npm.cmd run start` points at the emitted build entrypoint and served `/access-control` on `http://127.0.0.1:18080/access-control` during local verification with a temporary ignored JWT key and `GOOGLE_ALLOWED_HD=unguess.io,nuotounostiledivita.it` override.

## Not verified in this environment

- PostgreSQL migrations against a live database.
  - `npm.cmd run migrate` reaches the local database connection step but `localhost:5432` refused connections in this environment.
- Docker is installed but the daemon/API is not reachable in this environment, so an ephemeral PostgreSQL container could not be used for verification.
- Docker Compose startup of the new local stack.
  - Docker daemon/API access was previously unavailable at `npipe:////./pipe/docker_engine` in this environment, so live compose verification remains pending.
- Real Google OAuth callback flow.
- Browser automation verification of the Admin UI.
  - The local service served `/access-control` over HTTP, but the in-app browser kernel failed to start in this Windows sandbox with `CreateProcessAsUserW failed: 5`.
  - Static served-script parse verification is now covered by an automated test and `node --check`, but visual/browser interaction remains pending.

## Not implemented yet

- Google Cloud project creation.
- Dedicated Tool SDK/helper packages.
- CI/CD pipeline.
- External SIEM export implementation.

## Confirmed before production

- Company Google Workspace hosted domain is confirmed as `unguess.io` for `GOOGLE_ALLOWED_HD`.
- `access-layer.unguess-internal.net` is the Access Layer production service domain, not the Google Workspace `hd` value.
- Local base URL is confirmed as `http://localhost:8080/access-control`.
- Production base URL is confirmed as `https://access-layer.unguess-internal.net`.
- Authorized OAuth redirect URIs are confirmed as:
  - `http://localhost:8080/access-control/v1/auth/google/callback`
  - `https://access-layer.unguess-internal.net/v1/auth/google/callback`
- No separate staging environment is required for v1 unless specified later.

## Assumptions to validate before production

- PostgreSQL is acceptable as first persistence layer.
- Node.js/TypeScript is acceptable as reference implementation stack.
- Audit log retention target is 365 days unless legal/compliance requires a different value.
- Delegated `tool_admin` assignment model should be validated against operational ownership rules.
- Tool callback state persistence should be approved by security/privacy reviewers.

## Latest Admin UI behavior update, 2026-06-18

- Tool creation now uses an inline form with one `Salva tool` action instead of sequential browser prompts.
- Tool client secret creation/rotation now shows the one-time secret in an inline result panel with a copy action instead of browser alerts.
- Grant creation from the grant list, grant creation from user detail, and access-request approve/reject/close decisions now use inline forms with explicit labels and cancel actions.
- Destructive revocation/user-disable browser confirmations remain in place as documented safety confirmations.
- Verification after the update: `npm install`, `npm run lint`, `npm run build` and `npm test` passed; follow-up hotfix verification now includes served Admin UI script parsing; test suite result is 9 files and 81 tests.

## Latest Admin UI click hotfix, 2026-06-18

- Fixed a generated Admin UI JavaScript parse error caused by the tool permission placeholder rendering `read\nwrite` as a literal newline inside a browser script string.
- Symptom fixed: Admin UI visible in local Docker but navigation/login/buttons did not react because the browser aborted the inline script before binding handlers.
- Added automated coverage that extracts the served Admin UI script and checks it is parseable.
- Verification: `npm run lint`, `npm run build`, served-script `node --check` and `npm test` passed; test suite result is 9 files and 81 tests.


## Latest Admin UI login gate and healthcheck log tuning, 2026-06-18

- Changed the Admin UI root behavior so unauthenticated requests to `/admin` or the configured public base path such as `/access-control` redirect to the Admin UI login route instead of rendering the dashboard shell.
- Because the login route starts the reserved `access-admin` Google OAuth flow, an unauthenticated browser goes directly to Google and does not see admin navigation, tables or inline scripts.
- Kept authenticated Admin UI rendering unchanged after a valid signed admin session cookie is present.
- Kept Docker Compose health checks enabled; the repeated `GET /access-control/health` requests every 10 seconds are expected container health probes. The health routes now use silent route logging so they do not spam normal application request logs.
- Updated seed behavior so the reserved `access-admin` tool return URLs are reconciled to the current public base path when seed runs, avoiding stale local `/admin/auth/callback` data after previous package versions.
- Verification: `npm run lint`, `npm run build` and `npm test` passed; test suite result is 9 files and 81 tests.

## Recommended next step

For production, create a Coolify compose app from this package, fill variables from `.env.production.example`, then verify `GET https://access-layer.unguess-internal.net/health` and complete the Google OAuth flow. In local Docker, repeated health probes are expected; open `http://localhost:8080/access-control` to start the admin Google login when no session is present.

## Latest local production env file update, 2026-06-22

- Created ignored local `prod.env` from `.env.production.example` using the available `.env.docker` source because no root `.env` file was present in this workspace.
- Production URL values are aligned to `https://access-layer.unguess-internal.net`, with an empty production `PUBLIC_BASE_PATH`, root `/v1/auth/google/callback`, `GOOGLE_ALLOWED_HD=unguess.io,nuotounostiledivita.it` and `TRUST_PROXY_HOPS=1`.
- Required copied/generated secret values were written only to `prod.env` and were not printed in logs or documentation.
- Added `prod.env` to `.gitignore` because the existing `.env.*` pattern does not cover that filename.
- Verification: `prod.env` contains 41 environment keys and no placeholder values. `git status` could not run because Git is unavailable in this shell.

## Latest commit and Coolify readiness hardening, 2026-06-22

- `.env.production.example` is explicitly unignored so the Coolify production template can be committed, while real `.env*`, `prod.env` and `.local/` secret material remain ignored.
- Docker build context excludes `.local/` secret material.
- Docker Compose now accepts the documented empty production `PUBLIC_BASE_PATH=` value and persists the generated local JWT signing key in the app service's named `/run/secrets` volume.
- `.env.production.example` leaves `BACKUP_API_TOKEN` empty by default instead of carrying a concrete token-like value.
- Coolify deployment docs now call out `.local` keys as non-uploadable local secret material.

## Latest production URL topology update, 2026-06-21

- Production is now prepared for the dedicated origin `https://access-layer.unguess-internal.net` with no `/access-control` public base path.
- Production configuration should set `PUBLIC_BASE_PATH=` (empty), `APP_BASE_URL=https://access-layer.unguess-internal.net`, `AUTH_ISSUER=https://access-layer.unguess-internal.net` and `GOOGLE_REDIRECT_URI=https://access-layer.unguess-internal.net/v1/auth/google/callback`.
- Local Docker development remains on `http://localhost:8080/access-control`.
- Verification for this update: `npm.cmd run lint`, `npm.cmd run build` and `npm.cmd test` passed; test suite result is 9 files and 87 tests.

## Latest security hardening plan update, 2026-06-19

- Introduced explicit backup permissions, encrypted backup export/import, admin-only restore secret material export, bounded proxy trust, same-origin checks for cookie-backed admin writes and company-domain validation for pending email grants.
- New required production variables: `BACKUP_ENCRYPTION_KEY` and `TRUST_PROXY_HOPS=1` for the expected Coolify proxy path.
- Existing per-tool client secrets cannot be downloaded after creation/rotation because Access Layer stores only hashes; rotate the tool client if a plaintext `tls_...` value was lost.
- Verification: `npm run lint`, `npm run build`, `npm test` and `npm audit --package-lock-only --audit-level=moderate` passed; audit reports 0 vulnerabilities.

## Latest Admin UI session/detail update, 2026-06-22

- Already-rendered Admin UI pages now treat invalid or expired admin sessions as expired sessions, replace the current page with `Sessione scaduta. Accedi di nuovo.` and redirect to the Admin UI login route.
- Tool detail now starts in read-only mode and exposes explicit `Modifica`, `Salva modifiche`, `Elimina` and `Ruota secret` actions.
- Tool save/delete operations now show inline success or failure feedback.
- Non-reserved tool deletion is available through `DELETE /v1/admin/tools/{tool_id}` and the Admin UI; deleting `access-admin` remains blocked.
- Audit history is preserved after tool deletion through migration `002_audit_tool_delete_fk.sql`, which sets `audit_logs.tool_id` to null on tool deletion while retaining `tool_slug`.
- Verification: `npm run lint`, `npm run build` and `npm test` passed locally; test suite result is 9 files and 92 tests.

## Latest bulk grant import/export update, 2026-06-25

- Added Admin API and UI support for CSV bulk grant operations.
- New CSV exports: grant template, current grants and tool permission catalog.
- Bulk preview validates email domain, tool slug, delegated tool-admin scope, permission format, registered permission keys and UTC expiry values without writing data.
- Bulk commit creates or updates grants idempotently, keeps unknown company emails as `pending_user_link`, links known users as `active`, and revokes matching grant sessions for `revoke` rows.
- Bulk commit refuses to write when any row has validation errors; warning rows such as no-op revokes are reported without failing the whole import.
- Added per-row audit events and a summary `admin.grant.bulk_import_committed` event.
- Verification: `npm ci`, `npm run lint`, `npm run build` and `npm test` passed locally; test suite result is 9 files and 95 tests.

## Step 1 template adoption and compatibility freeze, 2026-08-24

- Adopted Agent Ready Project Template v2.1.0 additively in `legacy-migration` mode.
- Classified Access Layer as a Coolify-deployed `platform_service` at `https://access-layer.unguess-internal.net`, app port `8080`, private PostgreSQL and no published host ports.
- Froze repository-observed v1 route, JWKS, callback, JWT, exchange, refresh, session, grant, cookie, error and database behavior in `specs/legacy-contract-baseline.v1.json`.
- Added synthetic golden-contract fixtures and source/route/error/database conformance tests without changing runtime behavior.
- Documented supplied Nancy, Test Generator, Goodman and Petyr compatibility evidence. Consumer and current-production archive hashes do not match the instruction-pack reference hashes; conclusions are limited to the supplied archives.
- No OAuth/OIDC implementation, database migration, UI translation/redesign, telemetry integration, Platform SDK adoption, secret rotation or deployment was performed.
- The Compose PostgreSQL volume mismatch is a continuity `BLOCKER`: the service mounts `access_layer_postgres_data_v2`, while the top-level declaration is `access_layer_postgres_data`. Neither side was renamed.
- The N→N+1 survival harness is documented but has status `DOCUMENTED_NOT_RUN` because two immutable real versions/images were not provided.
- Verification passed: TypeScript lint/build, 106 Vitest tests, non-strict platform conformance and 34 Python conformance tests (two pristine-template bootstrap tests skipped). Strict release conformance remains intentionally blocked on six documented gates.

## Current release posture

Do not deploy. The Compose logical-volume mismatch is resolved from live evidence, but a tested backup/restore, remaining continuity evidence, named ownership and central deployment registration are still required. The earlier production deployment recommendation remains superseded.
