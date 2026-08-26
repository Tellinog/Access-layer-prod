# DEVLOG.md

## 2026-08-26 - Final Step 2 OAuth P0 contract hardening

Changed by: Codex
Related task: Resolve the final contract blockers without starting Step 3.

### Changed

- Aligned the target OAuth resource bridge to the exact legacy tool-slug grammar and reconciled the legacy permission machine spec to the runtime's two-or-more-segment grammar without changing runtime validation.
- Required an explicit one-to-one canonical OAuth scope to legacy permission mapping for every declared resource scope; exact coverage, no inferred rewriting and fail-closed entitlement evaluation are machine validated.
- Added the target-only `oauth_resource_credentials` data contract for `client_secret_basic` introspection and bound active disclosure to an exact match between token `aud` and the credential's resource.
- Restored the gate distinction: after Step 2 approval, generic Step 3 may proceed locally/dark with OAuth globally disabled; pilot registration and all operational continuity gates still block enablement/production registration/deploy.

### Behavior

- OAuth runtime endpoints, migrations, dependencies, production configuration, secrets, SDKs and consumers changed: no.
- Legacy `/v1/*`, Google callback, JWT/JWKS, sessions, refresh tokens, grants, permissions, tool clients, cookies and Admin UI behavior changed: no.
- Compose and the approved logical-volume correction changed: no. No pilot mapping or resource credential was seeded.

### Tests/checks

- `npm.cmd run lint` and `npm.cmd run build` passed.
- Full Vitest passed: 12 files, 113 tests; targeted frozen legacy baseline passed: one file, six tests.
- Full Python conformance passed: 61 tests with two expected pristine-template bootstrap skips.
- OAuth P0 validator passed all 24 check groups, including exact legacy grammars, scope-mapping coverage, resource credential ownership, OpenAPI references and schema/example validation.
- Production-continuity evidence remains `VALID_BUT_NOT_READY` with zero errors: isolated-restore false with 167 missing facts; N→N+1 false with 175 missing facts.
- Non-strict platform check passed 27 checks with seven known warnings. Strict platform release validation remains intentionally non-passing only on five external gates and four legacy-migration warnings.
- Resolved Compose reports exactly `access_layer_postgres_data_v2` and `access_layer_jwt_secrets` as logical volumes.
- `git diff --check` passed, and the final-hardening range has no changes under runtime, migrations, dependencies, frozen legacy OpenAPI or Compose.

### Decisions and follow-up

- Recorded D-038 for exact entitlement mappings, resource-owned introspection credentials and separate local-development/production-release gates.
- Stop before Step 3. Production release blockers remain in `BACKLOG.md`.

## 2026-08-26 - Step 2 OAuth P0 contract hardening

Changed by: Codex
Related task: Resolve independent-audit blockers without starting OAuth runtime implementation.

### Changed

- Restored the shared RequestContext v1 capability/scope grammar to the canonical two-or-more-segment hierarchy while retaining exact three-segment OAuth P0 scope rules.
- Enforced RFC 7636 verifier syntax and exact unpadded S256 challenge syntax in the machine profile, target OpenAPI, fixtures and regressions.
- Required exactly one legacy-tool entitlement-only binding per P0 resource, while keeping OAuth client/resource/tool identities separate and deferring native OAuth entitlement domains.
- Limited P0 active introspection disclosure to RFC 9068 Bearer access tokens for separately authorised resource-server credentials; refresh and other non-disclosable tokens use exact `{"active":false}` responses.
- Froze the future internal `/oauth/upstream/google/callback` without advertising or implementing it and preserved the legacy callback registration.
- Replaced the hash-only downstream-state proposal with short-lived reversible protected storage plus optional hash and a no-logging rule.
- Recorded the proven Coolify server/project/environment IDs, left destination unresolved, and added the visible `Changes pending` pre-deploy review blocker.
- Removed the Step 2 Markdown trailing whitespace reported by `git diff --check`.

### Behavior

- OAuth runtime endpoints, migrations, dependencies, production environment, SDKs and consumers changed: no.
- Legacy `/v1/*`, Google callback, JWT/JWKS, sessions, refresh tokens, grants, permissions, tool clients, cookies and Admin UI behavior changed: no.
- Compose, live volumes, production resource and deployment changed: no; the approved logical-volume correction remains intact.

### Tests/checks

- `npm.cmd run lint` passed.
- `npm.cmd run build` passed.
- `npm.cmd test` passed: 12 files, 113 tests.
- Targeted legacy baseline passed: one file, six tests.
- Full Python conformance passed: 57 tests, two expected pristine-template bootstrap skips.
- OAuth P0 validator passed all 18 check groups, including OpenAPI references and schema/example validation.
- Production-continuity evidence remains `VALID_BUT_NOT_READY` with zero errors: isolated-restore false with 167 missing facts; N→N+1 false with 175 missing facts.
- Non-strict platform check passed 27 checks with seven known warnings.
- Strict platform check remains intentionally non-passing only on five external release gates and four legacy-migration warnings.
- Resolved Compose keeps top-level volumes `access_layer_postgres_data_v2` and `access_layer_jwt_secrets`, the matching service sources, and null published `ports` for app/PostgreSQL.
- `git diff --check` passed.

### Decisions and follow-up

- Recorded D-037 for the hardening rules above.
- Superseded by D-038's gate distinction: after Step 2 approval, generic Step 3 may proceed locally/dark with OAuth globally disabled. Do not enable or deploy until the `Changes pending` review, destination, backup/restore, registry, ownership, deployed-image and secret/key continuity gates pass.

## 2026-08-25 - Step 2 OAuth vNext P0 contract freeze

Changed by: Codex
Related task: Freeze the additive OAuth authorization-server contract without implementing runtime.

### Changed

- Added a normative machine-readable P0 profile and human contract for metadata, code/refresh grants, PKCE, exact redirects, resource/audience, JWT token profile, transport, errors, registration, refresh replay, key rotation and audit.
- Rebuilt the target-only OAuth OpenAPI so it advertises only P0 and uses OAuth-standard errors.
- Added JSON Schemas and synthetic examples for authorization metadata, token header/claims, confidential client registration, resource registration, protected-resource metadata and RFC 9207 authorization response.
- Added the proposed expand-only `oauth_*` data model without a SQL migration.
- Added an OAuth contract validator and Python conformance tests; extended example/platform validation.

### Decisions

- Preserved Google `sub` for P0 human tokens, PII-minimised access tokens, exact three-segment capability scopes, separate client/resource identity, explicit legacy entitlement bridge, BFF browser architecture, dedicated OAuth keys and full refresh-family replay revocation.
- Kept `client_credentials`, token exchange, `private_key_jwt`, downstream OIDC and dynamic registration in P1/deferred scope.

### Behavior

- OAuth runtime implemented/enabled: no.
- Legacy `/v1/*`, database/migrations, dependencies, Admin UI and consumer behavior changed: no.
- Deployment or publication: no.

### Tests/checks

- `npm.cmd run lint` passed.
- `npm.cmd run build` passed.
- `npm.cmd test` passed: 12 files, 113 tests.
- Full Python conformance passed: 50 tests, two expected pristine-template bootstrap skips.
- OAuth P0 validator passed all 12 check groups, including target OpenAPI internal references and schemas/examples.
- Legacy baseline targeted suite passed: 6 tests; the OAuth slice has no diff under runtime, migrations, dependencies, legacy OpenAPI, Compose, Dockerfile or entrypoint.
- Resolved `docker compose config` targets only logical volumes `access_layer_postgres_data_v2` and `access_layer_jwt_secrets`, with zero published app/PostgreSQL host ports.
- Non-strict platform check passed: 27 checks and seven known warnings.
- Strict platform check intentionally remains non-passing only on five external gates: deployment readiness, backup/restore policy, central registration status, missing authoritative registry input and named ownership.
- Continuity evidence remains schema-valid `VALID_BUT_NOT_READY`: zero errors, isolated-restore gate false (170 missing facts), N→N+1 gate false (178 missing facts).

## 2026-08-25 - Step 2 production evidence and Compose continuity reconciliation

Changed by: Codex
Related task: Reconcile only proven non-secret Coolify facts before the OAuth P0 contract freeze.

### Changed

- Recorded the observed Coolify server/project/resource topology, public/private ports, managed Compose mode, repository/branch, deployment trigger, preview state and isolated network facts.
- Corrected only the PostgreSQL top-level Compose declaration to `access_layer_postgres_data_v2`; the service mount remains unchanged and no explicit physical volume name was added.
- Recorded both UUID-prefixed live named-volume identities and corrected `/run/secrets` from bind-mount intent to named-volume evidence in the platform manifest.
- Updated continuity validation and regression assertions for the resolved logical PostgreSQL and JWT volumes.

### Behavior

- Application runtime, `/v1/*`, database schema/data, sessions, tokens, grants, cookies, tool clients and Admin UI behavior changed: no.
- Production deployment or live resource mutation: no.

### Remaining gates

- Backup/restore, exact destination, central registry, named ownership, deployed revision/image, runtime configuration, secret sameness and JWT key continuity remain unresolved.

### Tests/checks

- Final verification is recorded with the Step 2 OAuth contract entry and task handoff.

## 2026-08-25 - Step 1.5B continuity evidence hardening

Changed by: Codex
Related task: Harden production-continuity evidence before any live collection.

### Changed

- Replaced evidence presence booleans with `UNOBSERVED`/`ABSENT`/`PRESENT_EMPTY`/`PRESENT_NON_EMPTY` states across the 41-variable source-derived configuration inventory.
- Added explicit inline/file-backed JWT signing-source evidence, public-key identity, external same-key verification, and mandatory real `/run/secrets` persistence proof for file-backed mode.
- Added external, non-reusable sameness verification records for session, pepper, backup encryption, Google client, and log-IP salt continuity.
- Added allowlisted safe effective configuration and a runtime collector that fails closed, does not read keys/secrets, accepts empty `PUBLIC_BASE_PATH`, and suppresses credential-bearing URLs.
- Added separate machine-readable readiness gates for starting an isolated restore and starting N→N+1; final readiness continues to require a passed isolated restore.
- Preserved runtime, Compose, entrypoint, database, deployment, platform manifests, line-ending policy, and all frozen v1 behavior.

### Docs/specs/schemas updated

- Updated the production-continuity schema/template, collection runbook, N→N+1 plan, security/deployment/database/testing documentation, project memory, helper READMEs, and Step 1.5B handoff.
- No API, policy, permission, database, migration, runtime environment, or deployment record changed.

### Tests/checks

- Added Python gate/redaction tests and Node helper inventory, state, URL-redaction, JWT, PostgreSQL-error, and runtime-invariance tests.
- Final lint, build, full test, platform conformance, continuity validation, and platform checker results are recorded in `STEP_1_5B_HANDOFF.md`.

### Decisions

- Recorded D-034: continuity evidence uses external sameness proof and staged restore/N→N+1 gates.

### Follow-ups

- Obtain the unresolved operator evidence listed in `BACKLOG.md` only after live collection is separately authorised.
- Do not start an isolated restore until its machine gate is true; do not start N→N+1 until a real isolated restore is recorded `PASSED` and two immutable images are supplied.

## 2026-08-05 - Relationship-oriented grant administration UI

Changed by: Codex
Related task: Improve the accessibility and usability of Tools, Users and Grants administration.

### Changed

- Added a platform-admin `Utenti e autorizzazioni` table to tool detail, with registered users, effective access, role/permission summary, grant state and direct grant actions.
- Added a `Tool e autorizzazioni` table to user detail so the Users list stays person-oriented while exposing every grant for the selected user.
- Replaced manual tool-slug fields in grant and access-request approval workflows with visible-tool dropdowns.
- Replaced free-text permission fields in those workflows with labelled keyboard-accessible expandable checkbox lists populated from registered permission keys; each closed picker reports the selected-count summary.
- Added `Rilascia grant in blocco`: one corporate email per line, one selected tool/role/permission set, mandatory preview and error-blocked confirmation. Preserved advanced mixed-operation CSV import separately.
- Expanded desktop content and form cards to use the full available main width, with responsive field columns and the existing compact single-column breakpoint.
- Preserved all existing API validation, audit events, pending-email behavior and delegated tool-admin scope.

### Docs/specs/schemas updated

- Updated `CURRENT_STATE.md`, `DECISIONS.md`, `docs/ADMIN_GUIDE.md`, `docs/UX.md`, `docs/UI_SYSTEM.md`, `docs/COPY.md` and `docs/TESTING.md`.
- No API, policy, schema, database or environment-variable change was required.

### Tests/checks

- `npm.cmd run lint` passed.
- `npm.cmd run build` passed.
- `npm.cmd test` passed: 10 test files, 100 tests.
- Added Admin UI rendering assertions for relationship tables, catalog-driven grant controls and one-email-per-line bulk release.

### Decisions

- Recorded D-030: relationship-oriented grant administration UI.

### Follow-ups

- Browser-smoke test the relationship tables and multiple-select controls with a live PostgreSQL-backed Admin session.
- Confirm the required server-side pagination design before a user or tool-grant result can exceed the current Admin endpoint cap of 200 rows.

## 2026-07-24 - Fix Coolify Docker build after favicon asset pipeline

Changed by: Codex
Related task: Diagnose and correct repeated Coolify deployment failures at `RUN npm run build`.

### Changed
- Updated the Docker build stage to copy `scripts/copy-assets.mjs` and `assets/` before running the package build.
- Preserved the multi-stage production image and existing runtime asset copy through `dist`.
- Added a Dockerfile regression test that requires both build-time inputs to be copied before `RUN npm run build`.

### Root cause
- The favicon update changed the package build to run `node scripts/copy-assets.mjs` after TypeScript compilation.
- The Docker builder stage still copied only `tsconfig.json` and `src`, so the script and its source assets were absent inside `/app`.
- Coolify's `APP_ENV=production` warning was informational and unrelated to the failed command.

### Docs/specs/schemas updated
- Updated `CURRENT_STATE.md`, `BACKLOG.md`, `docs/TESTING.md` and `COOLIFY.md`.
- No API, policy, schema, database or environment-variable change was required.

### Tests/checks
- Clean builder-stage simulation passed and produced `dist/assets/ui/favicon.svg`.
- `npm.cmd run lint` passed.
- `npm.cmd run build` passed.
- `npm.cmd test` passed: 10 files, 100 tests.
- A complete local `docker build` was not available because the Docker daemon is not running in this workspace.

### Decisions
- No new product or architecture decision. The Docker context now matches the already accepted asset build pipeline.

### Follow-ups
- Push the Dockerfile/test/docs changes and redeploy the resulting commit in Coolify.
- Verify `/health`, `/v1/.well-known/jwks.json`, `/admin` and `/favicon.svg` after deployment.

## 2026-07-24 - Activity-driven sliding session refresh

Changed by: Codex
Related task: Keep authenticated users signed in while they remain active and provide migration instructions for existing Access Layer tools.

### Changed
- Added tool-authenticated `POST /v1/auth/refresh`.
- Added atomic single-use refresh-token consumption, replacement-token creation, active tool/user/session/grant revalidation and 15-minute JWT re-issuance.
- Successful refresh now extends the Access Layer session and replacement refresh-token idle deadline by 8 hours from authenticated user activity.
- Added `AUTH_REFRESH_TOKEN_INVALID` for invalid, expired, reused or no-longer-authorized refresh attempts.
- Added no-store token responses and refresh-specific rate limiting.
- Updated tool logout with a refresh token to revoke the linked session only when it belongs to the authenticated tool.
- Added a separate signed HttpOnly refresh cookie for the Admin UI, one refresh-and-retry attempt on authenticated Admin API activity, root-page recovery from an expired access cookie, and clearing of both auth cookies on failure/logout.
- Updated the reference tool harness to store tokens only in its server-side session, refresh on an authenticated request near token expiry, rotate state and clear the local session if renewal fails; it now also separates public/internal Access Layer URLs while preserving configured base paths.
- Added `prompts/TOOL_REFRESH_MIGRATION_PROMPT.md` as a ready-to-send Codex migration prompt for existing tools.

### Docs/specs/schemas updated
- Updated OpenAPI, API payloads, protocols, integration, architecture, domain, DB, security, logging/analytics, deployment, Admin UX/guide and testing documentation.
- Updated `specs/policy.v1.yml` and `specs/feature_flags.v1.yml` with rotation, sliding idle timeout and the prohibition on background keepalive.
- Recorded accepted decision `D-029`, resolved the token/session TTL assumptions in `BACKLOG.md` and updated `CURRENT_STATE.md`.

### Tests/checks
- `npm.cmd run lint` passed.
- `npm.cmd run build` passed.
- `npm.cmd test` passed: 9 files, 99 tests.
- Added refresh success/rotation/sliding-extension/replay-denial coverage, inactivity/grant-revocation denial coverage, Admin refresh-cookie rotation coverage and Admin UI retry-script coverage.

### Decisions
- Access tokens remain valid for 15 minutes.
- The 8-hour refresh/session TTL is a sliding inactivity timeout.
- Only authenticated user activity renews the session; unconditional background timers are forbidden.
- Refresh tokens rotate on every successful use and old tokens cannot be reused.

### Follow-ups
- Deploy Access Layer before or alongside tool migrations.
- Migrate every existing tool using `prompts/TOOL_REFRESH_MIGRATION_PROMPT.md`; tools not yet migrated retain the previous 15-minute interruption behavior.
- Define and automate retention cleanup for consumed/expired refresh-token rows.
- Run an environment-backed PostgreSQL/Google OAuth smoke test after deployment.

## 2026-07-23 - Add Access Layer favicon

Changed by: Codex
Related task: Create a favicon for the tool.

### Changed
- Added a native SVG favicon with an Access Layer "A" mark, using the Admin UI petrol-teal primary color and mint accent.
- Added a public favicon route that respects `PUBLIC_BASE_PATH`, and linked it from the Admin UI document head.
- Added the asset to the compiled runtime output, making it available to both local `npm start` and the production image.

### Docs/specs/schemas updated
- `CURRENT_STATE.md`
- `DECISIONS.md`
- `BACKLOG.md`
- `docs/UI_SYSTEM.md`

### Tests/checks
- Added Admin UI route and markup coverage for the favicon.

### Decisions
- Used SVG rather than a bitmap so the mark remains crisp at browser favicon sizes.

### Follow-ups
- Replace the mark only if/when an approved company logo system becomes available.

## 2026-07-21 - Accept semicolon-delimited bulk grant CSV imports

Changed by: Codex
Related task: Fix the bulk grant import reporting missing headers when the CSV uses semicolons.

### Changed
- Added header-based delimiter detection for bulk grant preview and commit when the request does not set `delimiter` explicitly.
- Preserved explicit `,` and `;` API delimiter choices and the existing comma-delimited template output.
- Updated the Admin UI help copy to state that comma- and semicolon-delimited CSV files are accepted.
- Added regression coverage for a semicolon-delimited bulk grant preview submitted through the Admin API/UI payload shape.

### Docs/specs/schemas updated
- `CURRENT_STATE.md`
- `docs/ADMIN_GUIDE.md`
- `docs/API_PAYLOADS.md`
- `docs/TESTING.md`
- `docs/UI_SYSTEM.md`
- `docs/UX.md`
- `schemas/openapi.yaml`

### Tests/checks
- `npm.cmd run lint` passed.
- `npm.cmd test -- tests/app.admin.test.ts` passed: 1 file, 50 tests.
- `npm.cmd test` passed: 9 files, 96 tests.

### Follow-ups
- Validate the updated import flow in the deployed Admin UI with an actual semicolon-delimited CSV exported by the local spreadsheet tool.

## 2026-07-02 - Production domain migration to UNGUESS internal origin

Changed by: ChatGPT
Related task: Make the application run on `https://access-layer.unguess-internal.net/` instead of `https://access-layer.draftapps.it/`.

### Changed
- Updated the production Access Layer origin to `https://access-layer.unguess-internal.net` across runtime templates, Coolify/deployment docs, Google OAuth guidance, OpenAPI, integration examples, reference seed callback URL and config tests.
- Kept production root-mounted with `PUBLIC_BASE_PATH=`, Admin UI at `/admin`, APIs under `/v1/*` and Google OAuth callback at `/v1/auth/google/callback`.
- Kept local Docker development on `http://localhost:8080/access-control` and left third-party tool example domains such as `crm.draftapps.it` unchanged.

### Docs/specs/schemas updated
- `.env.production.example`
- `COOLIFY.md`
- `DEPLOY.md`
- `README.md`
- `CURRENT_STATE.md`
- `DECISIONS.md`
- `BACKLOG.md`
- `docs/DEPLOYMENT.md`
- `docs/GOOGLE_CLOUD_SETUP.md`
- `docs/INTEGRATION_GUIDE.md`
- `docs/API_PAYLOADS.md`
- `docs/PROTOCOLS.md`
- `docs/TESTING.md`
- `schemas/openapi.yaml`
- `examples/api/`
- `seeds/010_reference_data.sql`

### Tests/checks
- Updated `tests/config.test.ts` for the new production root-domain deployment.
- `npm.cmd ci` completed and restored local dependencies.
- `npm.cmd run lint` passed.
- `npm.cmd run build` passed.
- `npm.cmd test` passed with 9 files and 95 tests.

### Follow-ups
- Add `https://access-layer.unguess-internal.net` as an authorized JavaScript origin and `https://access-layer.unguess-internal.net/v1/auth/google/callback` as an authorized redirect URI in Google Cloud before switching traffic.
- Update Coolify environment variables from `.env.production.example`, then smoke-test `/health`, `/v1/.well-known/jwks.json`, `/admin` and the Google admin login flow on the new domain.

## 2026-07-02 - Admin UI authenticated logout action

Changed by: ChatGPT
Related task: Hide the Admin UI login button for already-authenticated users and expose logout instead.

### Changed
- Replaced the fixed Admin UI top-bar `Login` button with a session-aware auth action that shows `Logout` when the dashboard is rendered for a valid admin session.
- The logout action calls the existing Admin UI `/logout` route, which clears the admin cookie and revokes the server-side Access Layer session before redirecting back to login.
- Kept `Login` only as a fallback action when `/me` cannot confirm an active admin session.

### Docs/specs/schemas updated
- `CURRENT_STATE.md`
- `DEVLOG.md`
- `docs/COPY.md`
- `docs/TESTING.md`
- `docs/UX.md`

### Tests/checks
- Added Admin UI regression coverage asserting the authenticated shell renders `Logout` and no longer emits the old fixed `id="login"` button.
- `npm.cmd run lint` passed.
- `npm.cmd test -- tests/app.admin.test.ts` passed with 49 tests.
- `npm.cmd test` passed with 9 files and 95 tests.

## 2026-07-02 - Admin UI UNGUESS visual alignment

Changed by: ChatGPT
Related task: Refactor the application visually to align the Admin UI with the UNGUESS enterprise SaaS style without changing behavior.

### Changed
- Restyled the same-service Admin UI shell with a white, airy content area, dark petrol-teal navigation, Inter/system font stack, refined spacing, rounded cards, subtle borders and light shadows.
- Updated visual treatment for filters, forms, inputs, buttons, badges, KPI summaries, tables, pagination, detail definition lists, empty states and feedback states.
- Added a table wrapper and dashboard KPI class for presentation only; API calls, routing, authentication, permissions, business logic, database behavior, function names and data flow were not changed.

### Docs/specs/schemas updated
- `CURRENT_STATE.md`
- `DECISIONS.md`
- `docs/UI_SYSTEM.md`
- `BACKLOG.md`

### Tests/checks
- `npm run lint`, `npm run build` and `npm test -- tests/app.admin.test.ts` could not run because `node_modules` is absent and the requested no-fetch constraint prevents installing dependencies.
- Static no-dependency checks confirmed the new table wrapper is balanced and the UNGUESS palette tokens are present in `src/app.ts`.

### Follow-ups
- Re-run `npm ci`, `npm run lint`, `npm run build`, `npm test` and a browser smoke test in an environment where dependency installation is already available or explicitly allowed.

## 2026-06-22 - Hierarchical tool permission keys

- Expanded permission-key validation from exactly two colon-separated segments to two or more lowercase colon-separated segments, allowing keys such as `petyr:read:all` while still rejecting empty segments, uppercase characters and dot-separated formats.
- Updated Admin UI helper copy, permission specs, API payload examples, OpenAPI/schema patterns and validation/admin tests for hierarchical permission keys.
- Verification: `npm run lint`, `npm run build` and `npm test` passed locally; test suite result is 9 files and 92 tests.

## 2026-06-22 - Admin session expiry and tool detail actions

- Changed Admin API auth failures caused by missing, invalid or inactive admin sessions to return the existing invalid-session error code instead of a generic permission error.
- Updated the Admin UI API helper so an expired admin session replaces the visible page with `Sessione scaduta. Accedi di nuovo.` and redirects to the Admin UI login route.
- Reworked tool detail into explicit read/edit flow with `Modifica`, `Salva modifiche`, `Elimina` and inline success/error feedback.
- Added tool deletion API support for non-reserved tools, including audit event creation and protection against deleting the reserved `access-admin` tool.
- Added migration `002_audit_tool_delete_fk.sql` so audit rows are preserved when a tool is deleted by setting `audit_logs.tool_id` to null while keeping `tool_slug`.
- Updated API/Admin UI/UX/testing docs and OpenAPI for tool deletion and tool-detail feedback behavior.
- Verification: `npm run lint`, `npm run build` and `npm test` passed locally; test suite result is 9 files and 92 tests.

## 2026-06-22 - Commit and Coolify readiness hardening

- Updated Git/Docker ignore rules so local secret material under `.local/` is excluded and `.env.production.example` remains committable as the production template.
- Fixed Docker Compose production compatibility with empty `PUBLIC_BASE_PATH=` and moved the generated local JWT signing key to the app service's named `/run/secrets` volume.
- Replaced a concrete-looking `BACKUP_API_TOKEN` value in `.env.production.example` with an empty disabled default.
- Clarified Coolify documentation to avoid uploading `.local` keys and to replace placeholder values from `.env.production.example`.

## 2026-06-22 - Local production env file

- Created local `prod.env` from `.env.production.example`, using the available local `.env.docker` values for copied credentials and production URL defaults for `https://access-layer.unguess-internal.net`.
- Generated missing required production secret values without printing them to logs or documentation.
- Added `prod.env` to `.gitignore` because it contains real secret-bearing environment values and does not match the existing `.env.*` ignore pattern.
- Verification: checked `prod.env` contains the expected 41 environment keys and no placeholder values. `git status` could not run because Git is unavailable in this shell.

## 2026-06-21 - Production access-layer subdomain

- Prepared production configuration for `https://access-layer.unguess-internal.net` with `PUBLIC_BASE_PATH=` instead of serving production under `https://draftapps.it/access-control`.
- Updated Coolify/deployment examples, Google OAuth redirect guidance, OpenAPI production paths, integration examples, seed reference callback URL and current-state documentation.
- Kept local Docker development on `http://localhost:8080/access-control` and retained base-path route coverage.
- Added config coverage for the production root-domain deployment.
- Verification: `npm.cmd run lint`, `npm.cmd run build` and `npm.cmd test` passed; test suite result is 9 files and 87 tests.

## 2026-06-19 - Backup and admin security hardening

- Removed the backup permission fallback from `admin:secrets:rotate`; backup read, backup write and restore secret material export now require explicit backup permissions.
- Added AES-256-GCM encrypted backup export using `BACKUP_ENCRYPTION_KEY`, with encrypted-backup import support.
- Added an admin-only restore secret material export for `TOOL_CLIENT_SECRET_PEPPER` and `BACKUP_ENCRYPTION_KEY`; existing per-tool `tls_...` client secrets remain non-recoverable because only hashes are stored.
- Replaced unlimited Fastify proxy trust with `TRUST_PROXY_HOPS`, defaulting to one trusted proxy hop in production/Coolify and zero in local development.
- Added same-origin validation for cookie-authenticated admin write requests.
- Added pending-grant email validation requiring a well-formed company email domain listed in `GOOGLE_ALLOWED_HD`.
- Updated deployment examples, security/API/admin/backup documentation, config schema and decisions.

## 2026-06-17 - Workspace hosted-domain correction

- Corrected the v1 Google Workspace hosted domain from `draftapps.it` to `unguess.io` for `GOOGLE_ALLOWED_HD`, fixtures, seeds and identity examples.
- Clarified that `draftapps.it` is the Access Layer service domain and OAuth redirect host, not the Google ID token `hd` value.
- Added a root route that redirects `/` to `/access-control` so local browser checks do not land on a bare 404.
- Updated the ignored local `.env.docker` when present so Docker login tests use `GOOGLE_ALLOWED_HD=unguess.io,nuotounostiledivita.it`.

## 2026-06-17 - Docker Compose local runtime

- Added a Dockerfile for the Node.js 22 production build.
- Added Docker Compose services for Access Layer and PostgreSQL 16 with persistent Docker volumes.
- Added a container entrypoint that generates a local JWT signing key when missing, runs migrations, optionally runs local seed data and starts the built service.
- Added `.env.docker.example` and npm scripts for Docker startup, shutdown and app logs.
- Updated deployment, database, testing and current-state docs with the Docker workflow and remaining verification requirement.

## 2026-06-10 - Specification bootstrap

- Created source-of-truth package for Access Layer Google SSO.
- Defined centralized login, authorization and audit model.
- Added Google Cloud setup, API contract, data model, security model, integration guide and Codex prompt.
- No production code implemented yet.

## 2026-06-10 - V1 service implementation scaffold

- Added Node.js/TypeScript Fastify service with PostgreSQL SQL migrations.
- Implemented Google OIDC start/callback flow, hosted-domain enforcement, pending access requests, tool client exchange, Access Layer JWT/JWKS, introspection and logout.
- Added admin APIs and minimal same-service Admin UI for tools, users, grants, access requests and audit logs.
- Added audit sanitization, deny-by-default validation, hashed one-time codes/refresh tokens/tool secrets and config validation.
- Added tests for validation helpers, secret hashing, audit redaction, Google ID token claim validation, JWT/JWKS behavior, configured CORS preflight behavior, invalid return URL denial, mocked no-grant access request creation, active-grant callback, exchange success, code replay denial, introspection active/revoked behavior, admin access-request approval and auditor write denial.
- Added dependency-free native Node tool integration harness under `examples/tool-harness/`.
- Added user-token logout support, failed logout audit event and baseline HTTP security headers.
- Added `ACCESS_REQUEST_REOPEN_AFTER_DAYS` and `access_request.reopen_suppressed` to match documented access-request reopen behavior.
- Added Admin UI tool/user detail edit views, stricter admin update validation, `revoke_existing` support for tool secret rotation and CORS allow-list handling.
- Added API-wide token-in-query rejection and fail-closed admin status filter validation for user, grant and access-request list endpoints.
- Added Admin UI callback/logout audit coverage, server-side Admin UI session revocation and transaction-bound audit writes for admin mutations.
- Added denied logout audit events for stale or already-inactive session/refresh token revocation attempts.
- Added explicit validation for grant creation with unknown user IDs.
- Could not install dependencies or run the TypeScript/test suite in this shell because `npm` is unavailable and the system `node.exe` is blocked; bundled Node exists but does not include a package manager.

## 2026-06-12 - Confirmed v1 domain and OAuth URLs

- Confirmed `GOOGLE_ALLOWED_HD=unguess.io,nuotounostiledivita.it`.
- Confirmed local Access Layer base URL `http://localhost:8080`.
- Confirmed production Access Layer base URL `https://draftapps.it`.
- Confirmed authorized OAuth redirect URIs:
  - `http://localhost:8080/access-control/v1/auth/google/callback`
  - `https://draftapps.it/access-control/v1/auth/google/callback`
- Confirmed no separate staging environment is required for v1 unless specified later.
- Marked the Google Workspace domain and redirect URI blockers resolved; bootstrap platform admin recipient remains open.

## 2026-06-12 - Local dependency and test verification

- Installed npm dependencies and added `package-lock.json`.
- Updated `npm test` to use Vitest's runner config loader so the test suite runs inside the restricted workspace.
- Fixed TypeScript narrowing for the Google callback transaction result.
- Fixed test fixtures after the confirmed hosted-domain update and aligned the admin authorization fake with persisted grant permissions.
- Verified:
  - `npm.cmd ls --depth=0`
  - `npm.cmd run lint`
  - `npm.cmd run build`
  - `npm.cmd test` (then-current suite after the rate-limit and audit-filter hardening pass)

## 2026-06-12 - Rate-limit and audit filter hardening

- Added endpoint-specific rate limits for `/access-control/v1/auth/start`, `/access-control/v1/auth/exchange`, `/access-control/v1/auth/introspect` and admin write requests.
- Added audit log filters for Google sub, reason code and UTC date range.
- Added fail-closed validation for audit log outcome, tool slug and date filters.
- Added route tests for auth-start rate limiting plus supported and invalid audit log filters.
- Narrowed the migration runner so `npm run migrate` requires only `DATABASE_URL`, not JWT or Google runtime secrets.
- Migration verification still requires a running local PostgreSQL server; the local `localhost:5432` connection was refused.

## 2026-06-12 - Authorization coverage hardening

- Added route coverage proving pending email grants are linked on first valid Google login before the access decision.
- Added route coverage proving delegated `tool_admin` access-request views and writes are scoped to assigned tools.
- Verified affected suites with `npm.cmd test -- tests/app.auth-flow.test.ts tests/app.admin.test.ts` (2 files, 16 tests).
- Docker was present but the daemon was not reachable, so live PostgreSQL migration verification remains pending.

## 2026-06-12 - Tool credential and JWT audience coverage

- Added route coverage proving `/access-control/v1/auth/exchange` rejects a wrong tool client secret, writes `token.exchange.denied` and leaves the one-time code unconsumed.
- Added token-service coverage proving a JWT issued for one tool audience is rejected for another audience.
- Verified affected suites with `npm.cmd test -- tests/app.auth-flow.test.ts tests/token-service.test.ts` (2 files, 7 tests).

## 2026-06-12 - External domain callback coverage

- Added route coverage proving a callback rejected for `AUTH_EXTERNAL_DOMAIN` writes `auth.denied.external_domain` and creates neither a user nor an access request.
- Verified affected suite with `npm.cmd test -- tests/app.auth-flow.test.ts` (1 file, 7 tests).

## 2026-06-14 - Callback state coverage

- Added route coverage proving an unknown Google callback `state` is denied before calling Google, creating a user or creating an access request.
- Verified affected suite with `npm.cmd test -- tests/app.auth-flow.test.ts` (1 file, 8 tests).

## 2026-06-14 - Email verification callback coverage

- Added route coverage proving a callback rejected for `AUTH_EMAIL_NOT_VERIFIED` writes `auth.denied.email_not_verified` and creates neither a user nor an access request.
- Verified affected suite with `npm.cmd test -- tests/app.auth-flow.test.ts` (1 file, 9 tests).

## 2026-06-14 - JWT rejection coverage

- Added token-service coverage proving expired Access Layer JWTs are rejected.
- Added token-service coverage proving JWTs signed by an unknown key are rejected.
- Aligned reference seed callback URLs and example emails to the confirmed `draftapps.it` domain.
- Verified affected suite with `npm.cmd test -- tests/token-service.test.ts` (1 file, 3 tests).

## 2026-06-15 - Repeated access request coverage

- Added route coverage proving repeated valid internal no-grant attempts update one pending access request instead of creating duplicates.
- Verified the repeated attempt writes `access_request.repeated` with `attempts_count=2`.
- Verified affected suite with `npm.cmd test -- tests/app.auth-flow.test.ts` (1 file, 10 tests).

## 2026-06-15 - Access request rejection coverage

- Added admin route coverage proving access-request rejection marks the request rejected without creating a grant.
- Verified the rejection writes `admin.access_request.rejected` and preserves the optional review note.
- Verified affected suite with `npm.cmd test -- tests/app.admin.test.ts` (1 file, 12 tests).

## 2026-06-15 - Access request closure coverage

- Added admin route coverage proving access-request closure marks the request closed without creating a grant.
- Verified the closure writes `admin.access_request.closed` and preserves the optional review note.
- Verified affected suite with `npm.cmd test -- tests/app.admin.test.ts` (1 file, 13 tests).

## 2026-06-15 - Hosted-domain config hardening

- Added fail-closed runtime validation for `GOOGLE_ALLOWED_HD` so it accepts hosted-domain names only.
- Rejected local runtime hosts, URL origins and IP literals such as `localhost`, `http://localhost:8080`, `https://draftapps.it`, `127.0.0.1` and `::1`.
- Updated `schemas/config.schema.json` and `.env.example` to document the hosted-domain-only rule.
- Verified affected suite with `npm.cmd test -- tests/config.test.ts` (1 file, 7 tests).

## 2026-06-15 - Admin tool creation coverage

- Added admin route coverage proving tool creation returns a one-time client secret and stores only a verifiable hash.
- Verified tool permission registration and `admin.tool.created` audit creation without logging the secret value.
- Verified affected suite with `npm.cmd test -- tests/app.admin.test.ts` (1 file, 14 tests).

## 2026-06-15 - Admin tool secret rotation coverage

- Added admin route coverage proving tool secret rotation returns a one-time client secret and stores only a verifiable hash.
- Verified `revoke_existing=true` disables existing clients and writes `admin.tool.secret_rotated` without logging the secret value.
- Verified affected suite with `npm.cmd test -- tests/app.admin.test.ts` (1 file, 15 tests).

## 2026-06-15 - Admin email grant coverage

- Added admin route coverage proving direct email grant creation normalizes the email and creates a `pending_user_link` grant when no user is linked yet.
- Verified the route writes `admin.grant.created` with target email metadata.
- Verified affected suite with `npm.cmd test -- tests/app.admin.test.ts` (1 file, 16 tests).

## 2026-06-15 - Admin grant revocation coverage

- Added admin route coverage proving grant revocation updates grant status, revokes active sessions for the grant and reports the revoked session count.
- Verified the route writes `admin.grant.revoked` with non-sensitive grant/session metadata.
- Verified affected suite with `npm.cmd test -- tests/app.admin.test.ts` (1 file, 17 tests).

## 2026-06-15 - Admin grant update coverage

- Added admin route coverage proving grant role and permission updates preserve active sessions.
- Verified the route writes `admin.grant.updated` with non-sensitive grant metadata.
- Verified affected suite with `npm.cmd test -- tests/app.admin.test.ts` (1 file, 18 tests).

## 2026-06-16 - Admin UI audit filter controls

- Added minimal Admin UI audit-log filters for date range, tool, email, Google sub, outcome, reason code and correlation ID.
- Added a correlation ID copy control on audit rows.
- Verified affected suite with `npm.cmd test -- tests/app.admin.test.ts` (1 file, 19 tests).

## 2026-06-16 - Admin UI grant management controls

- Added minimal Admin UI grant filters for tool, email and status.
- Added grant detail controls for role, permissions, status and valid-until updates through the existing grant PATCH API.
- Added grant revocation with the documented destructive confirmation copy.
- Verified affected suite with `npm.cmd test -- tests/app.admin.test.ts` (1 file, 20 tests).

## 2026-06-16 - Admin UI access-request management controls

- Added minimal Admin UI access-request filters for status, tool and email.
- Added first/last-attempt columns to the access-request table.
- Extended the approve action to send optional valid-until and note fields through the existing approval API.
- Verified affected suite with `npm.cmd test -- tests/app.admin.test.ts` (1 file, 21 tests).

## 2026-06-16 - Admin UI OAuth settings summary

- Expanded the Admin UI Settings page with a non-sensitive runtime and OAuth summary: environment, base URL, issuer, JWKS path, callback URL, hosted domains, OIDC scope, token TTL, refresh-token mode, CORS state and access-request reopen delay.
- Verified the settings page does not expose configured secret values in the served HTML.
- Verified affected suite with `npm.cmd test -- tests/app.admin.test.ts` (1 file, 22 tests).

## 2026-06-16 - Reconfirmed v1 domain and OAuth URLs

- Reconfirmed `GOOGLE_ALLOWED_HD=unguess.io,nuotounostiledivita.it` as the only v1 hosted-domain allow-list value.
- Reconfirmed local and production Access Layer base URLs and authorized OAuth redirect URIs.
- Reconfirmed that `localhost` is allowed only as a local runtime/OAuth redirect host, never as a `GOOGLE_ALLOWED_HD` value.
- Aligned the README reference stack wording with the accepted SQL migrations decision.
- Kept the bootstrap platform admin recipient blocker open.

## 2026-06-16 - Admin tool onboarding controls

- Added registered permission keys to admin tool list/create/update responses.
- Extended the minimal Admin UI tool create/detail flow to manage description, owner email, return URLs and permission keys.
- Tightened admin tool `permission_keys` validation so non-array values fail with the standard validation error.
- Fixed `npm start` to use the emitted build entrypoint at `dist/src/server.js`.
- Updated OpenAPI and API payload examples for tool response shapes.
- Verified:
  - `npm.cmd test -- tests/app.admin.test.ts` (1 file, 25 tests)
  - `npm.cmd run lint`
  - `npm.cmd run build`
  - `npm.cmd test` (9 files, 64 tests)
  - `npm.cmd run start` serving `/access-control` locally with an ignored temporary JWT key and documented hosted-domain override
- Non-passing environment checks:
  - `npm.cmd run migrate` could not connect to PostgreSQL on localhost:5432.
  - `docker info` could not reach the Docker daemon.
  - In-app browser automation failed to start in this Windows sandbox, so browser interaction verification remains pending.

## 2026-06-16 - Admin user management controls

- Added Admin UI user search/status filters backed by the existing `/access-control/v1/admin/users` query parameters.
- Added Admin UI destructive confirmation before changing a user from `active` to `suspended` or `disabled`.
- Added admin route coverage for user search/status filter forwarding.
- Added admin route coverage proving user disable revokes active sessions and writes `admin.user.status_changed`.
- Documented `/access-control/v1/admin/users` query parameters and user status update responses in OpenAPI.
- Verified:
  - `npm.cmd test -- tests/app.admin.test.ts` (1 file, 28 tests)
  - `npm.cmd run lint`
  - `npm.cmd run build`
  - `npm.cmd test` (9 files, 67 tests)
  - `npm.cmd run start` serving `/access-control` locally with an ignored temporary JWT key and documented hosted-domain override
- Non-passing environment checks:
  - `npm.cmd run migrate` could not connect to PostgreSQL on localhost:5432.
  - `docker info` could not access the Docker daemon/API.
  - `git status --short` could not run because `git` is unavailable in this shell.

## 2026-06-16 - Admin tool filters

- Added `/access-control/v1/admin/tools` filters for search, status and owner email.
- Preserved assigned-tool scoping for delegated `tool_admin` users when tool filters are applied.
- Added fail-closed validation for unknown tool status filters before list queries.
- Added Admin UI tool search/status/owner filter controls.
- Documented tool list query parameters in OpenAPI and the API guide.
- Verified:
  - `npm.cmd test -- tests/app.admin.test.ts` (1 file, 31 tests)
  - `npm.cmd run lint`
  - `npm.cmd run build`
  - `npm.cmd test` (9 files, 70 tests)
  - `npm.cmd run start` serving `/access-control` locally with an ignored temporary JWT key and documented hosted-domain override
- Non-passing environment checks:
  - `npm.cmd run migrate` could not connect to PostgreSQL on localhost:5432.
  - `docker info` could not access the Docker daemon/API.
  - `git status --short` could not run because `git` is unavailable in this shell.

## 2026-06-16 - Known-user grant creation

- Added an Admin UI user-detail action to create a grant for an already-known user via `user_id`.
- Added route coverage proving `POST /access-control/v1/admin/grants` creates an active grant for a known user ID and writes `admin.grant.created`.
- Added Admin UI coverage for the known-user grant action and optional expiry prompt.
- Verified:
  - `npm.cmd test -- tests/app.admin.test.ts` (1 file, 32 tests)
  - `npm.cmd run lint`
  - `npm.cmd run build`
  - `npm.cmd test` (9 files, 71 tests)
  - `npm.cmd run start` serving `/access-control` locally with an ignored temporary JWT key and documented hosted-domain override
- Non-passing environment checks:
  - `npm.cmd run migrate` could not connect to PostgreSQL on localhost:5432.
  - `docker info` could not access the Docker daemon/API.
  - `git status --short` could not run because `git` is unavailable in this shell.

## 2026-06-16 - Delegated grant scope coverage

- Added route coverage for delegated `tool_admin` grant boundaries:
  - grant list filters carry assigned tool IDs;
  - grant creation succeeds for assigned tools;
  - grant creation is denied for unassigned tools without audit mutation;
  - grant update is denied for unassigned tools without changing the grant.
- Verified:
  - `npm.cmd test -- tests/app.admin.test.ts` (1 file, 36 tests)
  - `npm.cmd run lint`
  - `npm.cmd run build`
  - `npm.cmd test` (9 files, 75 tests)
- Non-passing environment checks:
  - `npm.cmd run migrate` could not connect to PostgreSQL on localhost:5432.
  - `docker info` could not access the Docker daemon/API.
  - `git status --short` could not run because `git` is unavailable in this shell.
- Pending external verification:
  - configured Google OAuth/browser flow verification.

## 2026-06-16 - Auth-start audit fail-closed coverage

- Added auth-start route coverage proving audit write failures fail closed:
  - initial `auth.requested` audit failure stops before tool lookup, auth request persistence or Google redirect;
  - invalid-return-url denial audit failure stops before auth request persistence or Google redirect.
- Verified:
  - `npm.cmd test -- tests/app.auth-start.test.ts` (1 file, 6 tests)
  - `npm.cmd run lint`
  - `npm.cmd run build`
  - `npm.cmd test` (9 files, 77 tests)
- Non-passing environment checks:
  - `npm.cmd run migrate` could not connect to PostgreSQL on localhost:5432.
  - `docker info` could not access the Docker daemon/API.
  - `git status --short` could not run because `git` is unavailable in this shell.
- Pending external verification:
  - PostgreSQL-backed migration verification;
  - configured Google OAuth/browser flow verification.

## 2026-06-16 - Admin UI table pagination state

- Added shared client-side pagination for Admin UI tables with a fixed 25-row page size.
- Added a styled empty-state affordance for tables with no rows.
- Reset table page positions when filters are submitted or cleared.
- Added Admin UI coverage for the shared pagination controls, empty state and filter page resets.
- Verified:
  - `npm.cmd test -- tests/app.admin.test.ts` (1 file, 37 tests)
  - `npm.cmd run lint`
  - `npm.cmd run build`
  - `npm.cmd test` (9 files, 78 tests)
- Non-passing environment checks:
  - `npm.cmd run migrate` could not connect to PostgreSQL on localhost:5432.
  - `docker info` could not access the Docker daemon/API.
  - `git status --short` could not run because `git` is unavailable in this shell.
- Pending external verification:
  - PostgreSQL-backed migration verification;
  - configured Google OAuth/browser flow verification.

## 2026-06-17 - Coolify Access Control base path hardening

- Added `PUBLIC_BASE_PATH` runtime config and validated that `APP_BASE_URL`, `AUTH_ISSUER` and `GOOGLE_REDIRECT_URI` stay aligned when the service is mounted under `/access-control`.
- Moved canonical production Admin UI and API paths under `/access-control`, including `/access-control/v1/auth/*`, `/access-control/v1/admin/*`, JWKS and `/access-control/health`.
- Updated Admin UI JavaScript to derive API URLs from the configured base path instead of hardcoding `/v1/*`; this fixes the Tools section loading problem when the app is served below `/access-control`.
- Scoped Admin UI cookies to `/access-control` in base-path deployments while preserving root-path behavior for legacy/local root setups.
- Updated seed behavior so `access-admin` uses the base-path callback and demo CRM seed data is opt-in via `SEED_EXAMPLE_TOOLS=true`.
- Reworked Docker Compose for Coolify-style environment variables without committing real `.env` files, added `.env.production.example`, and documented deployment in `COOLIFY.md`.
- Validation run: `npm run lint`, `npm run build`, `npm test` all passed. Test suite: 9 files, 80 tests.
- Docker CLI is not available in this container, so full `docker compose config` and runtime container smoke tests remain to be executed on the target machine/Coolify host.

## 2026-06-18 — Admin inline forms for tool and grant workflows

Changed by: ChatGPT
Related task: Replace sequential browser prompt/alert inputs in the Admin UI with minimal grouped forms.

### Changed
- Replaced `prompt()` based tool creation with an inline `Nuovo tool` form and a single `Salva tool` action.
- Replaced one-time client secret `alert()` dialogs with an inline one-time secret result panel and copy action.
- Added inline forms for tool secret rotation, grant creation from the grant list, grant creation from user detail, and access-request approve/reject/close decisions.
- Kept destructive revocation/user-disable confirmations because they are documented safety confirmations, not data-entry prompts.

### Why
- Admins can review all fields together before submitting, reducing sequential input mistakes during onboarding and authorization operations.

### Docs/specs/schemas updated
- `docs/UX.md`
- `docs/UI_SYSTEM.md`
- `docs/COPY.md`
- `docs/TESTING.md`
- `DECISIONS.md`

### Tests/checks
- Updated Admin UI rendering tests for inline forms and the absence of prompt/alert data-entry flows.
- `npm install` completed successfully.
- `npm run lint` passed.
- `npm run build` passed.
- `npm test` passed: 9 test files, 80 tests.

### Follow-ups
- Browser smoke-test the inline forms against a real PostgreSQL-backed local or Coolify environment.

## 2026-06-18 — Admin UI click-handler hotfix

Changed by: ChatGPT
Related task: Fix local Docker Admin UI rendering where visible buttons and login did not react to clicks.

### Changed
- Escaped the `Nuovo tool` permission placeholder so the generated inline Admin UI script remains valid JavaScript.
- Added automated coverage that extracts the served Admin UI `<script>` and verifies it is parseable before release.

### Why
- The previous inline-forms update rendered `placeholder="read\nwrite"` as a literal newline inside a single-quoted JavaScript string in the served HTML. Browsers aborted the whole script before attaching click handlers, leaving the UI visible but non-interactive.

### Docs/specs/schemas updated
- `CURRENT_STATE.md`
- `docs/TESTING.md`

### Tests/checks
- `npm run lint` passed.
- `npm run build` passed.
- Served Admin UI script extraction plus `node --check` passed.
- `npm test` passed: 9 test files, 81 tests.

### Follow-ups
- Rebuild the local Docker image without cache and smoke-test the login button plus Tools navigation at `http://localhost:8080/access-control`.

## 2026-06-18 — Admin login gate and Docker healthcheck log tuning

Changed by: ChatGPT
Related task: Hide Admin UI until the admin has completed Google login and clarify repeated local Docker health requests.

### Changed
- Added a server-side Admin UI gate: unauthenticated or invalid admin sessions on `/admin` or the configured public base path redirect to the Admin UI login route.
- The Admin UI login route already starts the reserved `access-admin` Google OAuth flow, so unauthenticated admins now go straight to Google instead of seeing the dashboard shell.
- Left authenticated Admin UI rendering unchanged after the signed admin session cookie is valid.
- Set both root and public-base health routes to silent route logging. Docker Compose still probes the health endpoint every 10 seconds, but those expected checks no longer clutter normal request logs.
- Reconciled `access-admin` seed return URLs with the configured public base path when `RUN_SEED_ON_START=true`, so existing local DBs can move from legacy `/admin/auth/callback` URLs to `/access-control/auth/callback`.

### Why
- The admin dashboard should not expose navigation, labels or client-side Admin UI code before an admin session exists.
- Local Docker health probes are operationally useful, but repeated successful `/access-control/health` log lines were confusing during manual testing.

### Docs/specs/schemas updated
- `CURRENT_STATE.md`
- `DECISIONS.md`
- `docs/UX.md`
- `docs/COPY.md`
- `docs/TESTING.md`
- `docs/DEPLOYMENT.md`
- `docs/LOGGING.md`
- `seeds/010_reference_data.sql`

### Tests/checks
- Updated Admin UI tests so unauthenticated root access redirects to login while authenticated access still serves the dashboard.
- `npm run lint` passed.
- `npm run build` passed.
- `npm test` passed: 9 test files, 81 tests.

### Follow-ups
- Rebuild the local Docker image and verify that `http://localhost:8080/access-control` redirects into Google when the admin cookie is absent.

## 2026-06-25 - Bulk grant import/export

Changed by: ChatGPT
Related task: Add operational bulk import/export for users/grants while preserving pending-email grant behavior.

### Changed
- Added Admin API endpoints for grant CSV export, grant CSV template download, permission catalog export, bulk preview and bulk commit.
- Added idempotent bulk `upsert` behavior for existing active/pending grants by email, tool and role.
- Added bulk `revoke` behavior that revokes matching non-revoked grants and active sessions.
- Added Admin UI controls on the Grants page for `Template CSV`, `Export grant`, `Export permessi` and `Bulk import` with inline preview/commit.
- Added repository methods for permission catalog export, bulk target lookup, bulk revoke lookup and target-preserving grant updates.
- Added tests for template export, permission catalog export, preview, commit, validation-error no-write behavior and Admin UI rendering.

### Why
- Admins need to pre-authorize many users without manually creating Google user records. The existing `pending_user_link` model is preserved so first verified Google login activates preloaded grants automatically.

### Docs/specs/schemas updated
- `docs/API.md`
- `docs/API_PAYLOADS.md`
- `docs/ADMIN_GUIDE.md`
- `docs/UI_SYSTEM.md`
- `docs/UX.md`
- `docs/TESTING.md`
- `schemas/openapi.yaml`
- `CURRENT_STATE.md`
- `DECISIONS.md`

### Tests/checks
- `npm ci` passed.
- `npm run lint` passed.
- `npm run build` passed.
- `npm test` passed: 9 test files, 95 tests.

### Follow-ups
- Browser-smoke the inline bulk import form against a real PostgreSQL-backed environment and verify downloaded CSV files in Chrome/Edge.

## 2026-08-24 - Template v2.1 adoption and legacy compatibility freeze

Changed by: Codex
Related task: Step 1 only — template adoption and legacy compatibility freeze.

### Changed

- Added Template v2.1 platform documentation, schemas, examples and conformance scaffolding without replacing existing files.
- Added project/deployment manifests for a Coolify `platform_service`, app port 8080, private PostgreSQL and no published host ports.
- Added a machine-readable legacy contract baseline, synthetic golden fixtures, a capability inventory, consumer compatibility matrix and N→N+1 harness plan.
- Added explicit no-AI, no-SDK, no-telemetry and no-OAuth implementation status records.
- Preserved the known Compose volume-name mismatch and recorded it as a deployment blocker.

### Behavior

- Production runtime behavior changed: no.
- Database migrations added: no.
- Dependencies added: no.
- Deployment performed: no.

### Checks

- `npm.cmd run lint` passed.
- `npm.cmd run build` passed.
- `npm.cmd test` passed: 11 files, 106 tests.
- Non-strict platform check passed: 24 checks, eight explicit warnings.
- Python template/conformance suite passed: 34 tests, two pristine-template bootstrap tests skipped after adoption.
- Strict platform release check was run and failed only on the six documented ownership/deployment/backup/registry/volume release gates in `STEP_1_HANDOFF.md`.

## 2026-08-24 - Step 1.5 workspace hygiene and continuity evidence preparation

Changed by: Codex
Related task: Step 1.5 only — deterministic line endings and production-continuity evidence preparation.

### Changed

- Added deterministic Git line-ending rules and safely renormalized tracked files; no existing tracked file required a content rewrite.
- Added the v1 production-continuity evidence schema and an intentionally `NOT_READY` redacted bundle.
- Added a fail-closed, read-only evidence validator and tests for incomplete, invalid/unsafe and synthetic-ready cases.
- Added read-only helpers for allowlisted runtime/environment-presence facts, public JWKS fingerprints, and PostgreSQL schema/migration metadata.
- Added the manual Coolify/storage/backup collection runbook and connected the future N→N+1 plan to the evidence gate.
- Recorded the evidence-gate decision and preserved all live-fact blockers.

### Behavior

- Production runtime behavior changed: no.
- Database migrations or data changes: no.
- Compose, Coolify or production configuration changes: no.
- Secrets or environment values rotated: no.
- Deployment or package publication: no.

### Checks

- Final command results are recorded in `STEP_1_5_HANDOFF.md`.
