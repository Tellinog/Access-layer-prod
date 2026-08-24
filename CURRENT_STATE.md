# CURRENT_STATE.md

## Phase

V1 implementation scaffold complete, with local dependency, typecheck, build and automated test verification complete. Environment-backed integration verification remains pending.

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

Do not deploy the Step 1 commit. Verify the live Coolify volume mapping and create a tested backup first. The previous deployment recommendation above is superseded while this blocker is open.
