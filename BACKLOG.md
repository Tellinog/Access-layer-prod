# BACKLOG.md

## BLOCKER

- Confirm who receives bootstrap platform admin access after first deploy.
- 2026-08-27 Step 3D prerequisite: authorization-code exchange must re-check the current client, resource, authorization and legacy grant state before any token issuance so disablement/revocation after code creation fails closed. Do not implement token exchange or signing in Step 3C hardening.
- 2026-08-26 Step 3C: before any OAuth enablement, provision `OAUTH_TRANSACTION_PROTECTION_KEY` as a dedicated canonical base64url 32-byte secret through the approved secret manager and add the separate OAuth callback URI in Google Cloud without removing the legacy callback. Neither action is authorised or performed by Step 3C.
- 2026-08-26 Step 3B: before Step 3D introduces any `protected_private_key_ref` consumer, define and test an allow-list for supported reference schemes and file roots; reject `..` traversal, relative/unsafe paths, encoded traversal and unsupported schemes before any read. Step 3B must not implement a private-key loader.
- 2026-08-26 Step 3A hardening: before the first non-empty production OAuth registration or pilot, extend and prove backup/export/import/replace-restore coverage for all `oauth_*` state. The current legacy backup surfaces do not preserve these tables, and future `oauth_resource_entitlement_bindings` rows use `ON DELETE RESTRICT`, so a replace restore that runs `DELETE FROM tools` must use dependency-safe ordering. Do not register production OAuth state until this is implemented and restore-tested; no backup code changes are authorised in Step 3A hardening.
- 2026-08-26 Step 2 hardening: production deployment remains blocked until the exact Coolify destination identity and central registry record are verified. Server `wx513ojqd80kdicevubog7`, project `xdihnb979tvyh9gdk72zfy7y`, environment `rd3mt4dkpqyghxlx9h96sdlo` and resource `u3cyw3y1obp88to9la0w8c75` are proven non-secret facts.
- 2026-08-26 Step 2 hardening: Coolify visibly reported `Changes pending`. Before any future production deploy, an authorised operator must inspect the pending diff and resolve or explicitly accept it; this task does not apply it.
- 2026-08-24 Step 1.5: `operations/production-continuity.evidence.yml` remains `NOT_READY`; verified backup and isolated restore results remain unproven. Do not deploy or begin N→N+1 execution.
- 2026-08-25 Step 1.5B: observe whether live JWT signing uses inline PEM or a file and prove same-key continuity using public-key/external evidence. The live `/run/secrets` named-volume identity is proven, but key source/state and continuity are not. Do not read, hash, copy, rotate, or regenerate the private key.
- 2026-08-25 Step 1.5B: the isolated-restore gate is blocked until external secret-safe sameness evidence exists for `SESSION_SECRET`, `TOOL_CLIENT_SECRET_PEPPER`, `BACKUP_ENCRYPTION_KEY`, `GOOGLE_CLIENT_SECRET`, and `LOG_IP_SALT`. Presence/state alone is not proof.
- 2026-08-25 Step 1.5B: both machine gates remain false. The intermediate gate additionally needs complete live configuration/topology/storage/backup/database/registry/ownership evidence and approvals; final N→N+1 readiness additionally needs a real `PASSED` isolated restore and two immutable N/N+1 artifacts.

## RESOLVED

- 2026-08-27 Step 3C hardening: terminal/expired OAuth authorization transactions now purge reversible downstream-state ciphertext atomically. A bounded opportunistic cleanup handles abandoned pending/claimed rows without a timer or background job; cleaned rows cannot be claimed or issue a code.
- 2026-08-26 Step 3C: the default-off dark Authorization Code issuance path is implemented with migration 004, separate Google callback, protected downstream state, atomic state claim, exact entitlement revalidation and SHA-256-only 60-second codes. Token exchange and every later lifecycle remain unimplemented.
- 2026-08-26 Step 3A: the generic OAuth dark foundation is implemented locally through one expand-only migration, a default-false optional flag, an isolated `src/oauth/` module and deterministic darkness/migration/validation tests. No protocol route, pilot, seed, transaction table, production action or legacy behavior change was introduced.
- 2026-08-26 Step 3A historical result: `.env.example` and `.env.production.example` exposed the same 42 variable names, with optional `OAUTH_P0_ENABLED=false`; Step 3C later adds the state-only conditional protection-key input as variable 43.
- 2026-08-25 Step 2: Coolify evidence proves PostgreSQL logical volume `access_layer_postgres_data_v2` resolves to `u3cyw3y1obp88to9la0w8c75_access-layer-postgres-data-v2`; the source top-level declaration now matches the unchanged service mount. JWT logical volume `access_layer_jwt_secrets` is also proven as the named volume `u3cyw3y1obp88to9la0w8c75_access-layer-jwt-secrets`. No explicit physical name was added and no live volume was renamed.
- 2026-08-25 Step 2: confirmed Coolify server `agentic-unguess-prod`, project `agentic-unguess`, environment `production`, resource `access-layer-prod` (`u3cyw3y1obp88to9la0w8c75`), resource type `application`, managed Docker Compose, `main` branch, deploy-on-push, disabled previews, isolated predefined-network setting, public app port 8080 without a shown host mapping, and private PostgreSQL port 5432.
- 2026-08-24: restored root `.env.example` as a compatibility copy with the same 41 variable names as `.env.production.example`; production values and secret handling remain unchanged.
- 2026-06-17: Corrected and confirmed real Google Workspace domain list for `GOOGLE_ALLOWED_HD`: `unguess.io`.
- 2026-06-16: Confirmed production and local redirect URIs before creating OAuth clients:
  - `http://localhost:8080/access-control/v1/auth/google/callback`
  - `https://access-layer.unguess-internal.net/v1/auth/google/callback`
  - No separate staging redirect URI is required for v1 unless specified later.
- 2026-07-24: Confirmed 15-minute access tokens and activity-driven sliding sessions. Each valid refresh rotates the token and moves the 8-hour idle deadline forward; background refresh without user activity is forbidden.
- 2026-07-24: Resolved Coolify build failure introduced by the favicon asset pipeline by copying `scripts/copy-assets.mjs` and `assets/` into the Docker builder stage.

## QUESTION

- Should raw IP be stored for audit, or only salted hash plus country/ASN metadata?
- Should logs be exported to an external SIEM in v1?
- Should per-tool role labels remain free-form strings after v1, or become centrally managed values?
- Define retention/cleanup for revoked and expired refresh-token rows now that active sessions rotate tokens repeatedly.
- 2026-08-24: confirm the exact owner team, technical owner and product owner for platform/deployment registration.
- 2026-08-24: confirm the backup schedule, retention, storage destination and restore-test frequency from live Coolify operations.
- 2026-08-24: confirm whether `GET /v1/admin/backup/secret-material`, present in runtime but absent from `schemas/openapi.yaml`, should be added to a future OpenAPI revision or intentionally remain undocumented. Step 1 freezes the drift.
- 2026-08-24: confirm Nancy's production callback and live registration; only its local callback was present in the supplied evidence.
- 2026-08-24: approve measurable availability, latency, correctness, error-budget and alert-window SLO targets; repository evidence does not define them.
- 2026-08-24: export the live tool, callback and permission catalogue before asserting that the repository-only capability inventory is operationally complete.
- 2026-08-24 Step 1.5: provide the exact remaining Coolify destination identifier, deployed revision/image identity, replica/deploy facts and named continuity operator; server/project/environment/resource IDs, current live domain and auto-deploy state are now observed.
- 2026-08-24 Step 1.5: identify the authoritative central deployment registry location and the Access Layer record identifier/evidence reference.
- 2026-08-25 Step 1.5B: identify the approved access-controlled evidence system and authorised operators for secret-manager version references, side-by-side comparisons, or controlled binding records. No secret value or reusable verifier may be stored in Git.
- 2026-08-26 Step 2: before OAuth enablement or production registration, approve the first P0 pilot client, resource, exact redirects, mandatory legacy-tool entitlement binding, canonical scopes, exact legacy-permission mappings and resource introspection credentials. These details do not block generic Step 3 local/dark implementation with OAuth globally disabled.
- 2026-08-26 Step 2: define the operational owner and protected production storage mechanism for the dedicated OAuth signing key ring before OAuth enablement or production deployment; the legacy key ring cannot be reused. This does not block generic Step 3 local/dark implementation with synthetic local-only material.

## ASSUMPTION_TO_VALIDATE

- 2026-08-26 Step 3C: apply `001`→`004` to a disposable PostgreSQL 16 database and run the legacy binary/schema-consumer smoke test on a host with an available daemon. Deterministic migration-shape tests cover migration 004 locally; no production database may be used.
- 2026-08-26 Step 3A: apply `001`→`003` to a disposable PostgreSQL 16 database and run the legacy binary/schema-consumer smoke test on a host with an available daemon. This workspace has the Docker CLI but no reachable Docker API and no PostgreSQL listener on `127.0.0.1:5432`; deterministic migration-shape/constraint tests are green, but live SQL application is not claimed.
- 2026-08-05: the relationship tables reuse the current v1 Admin list endpoints, which return at most 200 users/grants per request. Confirm and design server-side pagination before the registered-user directory or a tool's grant set can exceed that operational limit.
- The current SVG favicon is a project-created interim mark based on the documented UI palette. Replace it if an approved company logo/favicons system becomes available.
- `prod.env` generation used `.env.docker` as the available local env source because no root `.env` file was present in the workspace; validate whether a separate canonical `.env` should exist for future production-env generation tasks.
- Runtime stack availability in the target environment: Node.js 22 LTS, TypeScript build pipeline, PostgreSQL and SQL migration runner.
- One-time code TTL: 60 seconds.
- Audit log retention: 365 days.
- All tools have a server-side component able to keep a tool client secret. Frontend-only tools must add a backend proxy.
- Delegated `tool_admin` scope can use `admin_tool_assignments` plus matching `tools.owner_email` for v1.
- Storing tool callback `state` in `auth_requests` is acceptable because tool integrations must not include secrets in state.
- Admin-only restore secret material export includes runtime secrets such as `TOOL_CLIENT_SECRET_PEPPER` and `BACKUP_ENCRYPTION_KEY`; existing per-tool client secrets remain non-recoverable because only hashes are stored, so lost per-tool secrets require rotation.
- 2026-08-24: the user-supplied Access Layer, Nancy, Test Generator, Goodman and Petyr archives are acceptable Step 1 compatibility evidence despite not matching the instruction-pack checksums. Obtain the referenced revisions or formally accept the supplied hashes.
- 2026-08-24: Coolify resource type was assumed to be `service`; live Step 2 evidence supersedes this with observed type `application`.
- 2026-08-24: the named central deployment registry ID is `unguess-coolify-deployments`; its authoritative location and record ownership remain unverified.
- 2026-08-24: Nancy, Test Generator and Goodman in-memory refresh locks are sufficient only for their observed single-replica assumptions; multi-replica safety is not proven.
- 2026-08-24: Petyr's supplied registration and code are deployed as inspected. Evidence contains a superseded Access Layer origin and a permission used in code but absent from the supplied tool registration.
- 2026-08-24 Step 1.5: repository expectations (app `8080`, PostgreSQL `5432` private, no shown public host-port mapping, target domain) are now verified by the 2026-08-25 Step 2 evidence.
- 2026-08-25 Step 1.5B / 2026-08-26 Step 3C: current live safe effective configuration is still unproven. All 43 source-derived variables, including optional `OAUTH_P0_ENABLED` and state-only `OAUTH_TRANSACTION_PROTECTION_KEY`, remain `UNOBSERVED` in the committed evidence template until an operator supplies state/effective-value proof.

## DEFERRED_SCOPE

- SCIM or Google Workspace Directory provisioning.
- Automatic group-to-tool synchronization from Google Groups.
- Device posture checks.
- Risk-based access and step-up authentication.
- Full SIEM integration.
- Dedicated SDK packages per framework.
- Immutable append-only log storage with WORM retention.
- OAuth authorization-server discovery routing, token exchange/authentication, signing/private-key loading, refresh, revoke, introspect, OAuth session/refresh/revocation tables, registration/admin HTTP APIs and pilot records remain outside Step 3C. Production client/resource/scope/mapping/credential registration and any enablement remain deferred until separately approved steps and the release gates pass.
- OAuth P1 features: service principals, `client_credentials`, token exchange, `private_key_jwt`, downstream OIDC ID Token/UserInfo/discovery and dynamic client registration.
- Native OAuth entitlement domains; every P0 resource instead requires exactly one existing `legacy_tool` entitlement-only binding.
- UNGUESS Platform SDK dependency adoption and telemetry SDK integration.
- Tool Observatory registration and synthetic monitor deployment.
- MCP exposure and stable platform capability/OAuth-scope mapping.
- Garden UI migration and English-first UI translation/redesign.
- N→N+1 survival execution until two real immutable versions/images and an isolated production-shaped database are available.
- Production-like backup restore and N→N+1 execution; Step 1.5 prepares evidence only and does not run either operation.
- Live continuity evidence collection and the isolated restore exercise are outside Step 1.5B. Reaching `ready_for_isolated_restore` does not itself authorise or execute a restore.

## RESOLVED_2026_06_17

- Access Layer production base path was previously confirmed as `/access-control`; this is superseded for production by the 2026-06-21 dedicated-subdomain update below.
- 2026-06-21: Superseded the production `/access-control` base path with the dedicated production origin `https://access-layer.unguess-internal.net`; local Docker remains on `/access-control`.
- Tool onboarding will be performed through the Admin UI for v1, not through production seed files.
- Coolify variables will be configured in the Coolify UI from `.env.production.example`; real `.env` files must not be included in deployment packages.

## FOLLOW_UP

- After the production domain switch, update Google Cloud, Coolify and any integrated tools to use `https://access-layer.unguess-internal.net`, then verify `GET https://access-layer.unguess-internal.net/health`, `GET https://access-layer.unguess-internal.net/v1/.well-known/jwks.json` and the Google OAuth callback flow.
- Re-run Admin UI verification for the 2026-07-02 UNGUESS visual alignment once dependencies are already available locally or external dependency installation is explicitly allowed: `npm ci`, `npm run lint`, `npm run build`, `npm test` and a browser smoke test.
- Run `docker compose config` and a real container smoke test on a host with Docker/Coolify access.
- After Coolify deploy, verify `GET https://access-layer.unguess-internal.net/health` and `GET https://access-layer.unguess-internal.net/v1/.well-known/jwks.json`.
- Login as bootstrap admin and create the first real tool from the Tools UI.
