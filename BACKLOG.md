# BACKLOG.md

## BLOCKER

- 2026-08-31 Step 4B approval gate: hardened candidate `d8998e1fbc1789d71a19cef78714c74c3dbfed37` passed three complete consecutive local qualifications on fresh paired PostgreSQL 16.15 targets, including 24/24 same-refresh races and the full snapshot/restore/legacy-smoke chain. A new independent audit must reproduce the result before `step-4b-completed` may be created. Until then do not enable OAuth, deploy, access production/Coolify or proceed to Step 5.
- Confirm who receives bootstrap platform admin access after first deploy.
- 2026-08-26 Step 3C: before any OAuth enablement, provision `OAUTH_TRANSACTION_PROTECTION_KEY` as a dedicated canonical base64url 32-byte secret through the approved secret manager and add the separate OAuth callback URI in Google Cloud without removing the legacy callback. Neither action is authorised or performed by Step 3C.
- 2026-08-27 Step 3D production gate: before any OAuth enablement, provision a dedicated OAuth credential pepper, dedicated signing-key root and OAuth-only RSA key through approved secret/storage controls; prove key/secret continuity without recording values or paths. No provisioning is authorised or performed here.
- 2026-08-29 Step 4B gate: the local synthetic encrypted export/replace restore and lifecycle proof now has three consecutive PASS results on the hardened candidate, but independent approval remains open above. Before any later production pilot, separately provision and prove continuity for approved external OAuth secrets/key storage; never use production as the audit substitute.
- 2026-08-26 Step 2 hardening: production deployment remains blocked until the exact Coolify destination identity and central registry record are verified. Server `wx513ojqd80kdicevubog7`, project `xdihnb979tvyh9gdk72zfy7y`, environment `rd3mt4dkpqyghxlx9h96sdlo` and resource `u3cyw3y1obp88to9la0w8c75` are proven non-secret facts.
- 2026-08-26 Step 2 hardening: Coolify visibly reported `Changes pending`. Before any future production deploy, an authorised operator must inspect the pending diff and resolve or explicitly accept it; this task does not apply it.
- 2026-08-24 Step 1.5: `operations/production-continuity.evidence.yml` remains `NOT_READY`; verified backup and isolated restore results remain unproven. Do not deploy or begin N→N+1 execution.
- 2026-08-25 Step 1.5B: observe whether live JWT signing uses inline PEM or a file and prove same-key continuity using public-key/external evidence. The live `/run/secrets` named-volume identity is proven, but key source/state and continuity are not. Do not read, hash, copy, rotate, or regenerate the private key.
- 2026-08-25 Step 1.5B: the isolated-restore gate is blocked until external secret-safe sameness evidence exists for `SESSION_SECRET`, `TOOL_CLIENT_SECRET_PEPPER`, `BACKUP_ENCRYPTION_KEY`, `GOOGLE_CLIENT_SECRET`, and `LOG_IP_SALT`. Presence/state alone is not proof.
- 2026-08-25 Step 1.5B: both machine gates remain false. The intermediate gate additionally needs complete live configuration/topology/storage/backup/database/registry/ownership evidence and approvals; final N→N+1 readiness additionally needs a real `PASSED` isolated restore and two immutable N/N+1 artifacts.

## RESOLVED

- 2026-08-31 Step 4B intermittent refresh blocker: pre-fix sanitized real-PG evidence proved SQLSTATE `23514` on `oauth_refresh_tokens_revoked_order` when an older observed request lost the lock and tried to revoke the winner's newer generation. Replay now re-observes time after the lock and clamps revocation to the family maximum `issued_at`; 24/24 races across three complete qualifications on `d8998e1fbc1789d71a19cef78714c74c3dbfed37` returned one 200 and one 400 `invalid_grant` with atomic replay revocation. Historical failures remain in the report; independent approval remains a blocker above.
- 2026-08-31 Step 4B export warning: the 24 snapshot reads are sequential on the one transaction client while remaining `REPEATABLE READ, READ ONLY`; three full qualifications emitted no `pg` concurrent-query deprecation warning and retained the coordinated anti-torn snapshot proof.
- 2026-08-31 Step 4B SQL blocker: the 2026-08-30 PostgreSQL `42601` failure is closed by replacing the unquoted reserved `authorization` alias in all three token-repository queries with `oauth_authorization`; the hardened real-PG rerun passed authorization-code exchange. The new concurrency blocker remains open above, and the original failure remains recorded in the qualification report and DEVLOG.
- 2026-08-29 Step 4A hardening: the torn-export risk is closed with one transaction-bound `REPEATABLE READ, READ ONLY` snapshot; refresh families require exactly generations `0..current_generation`; client/resource credential rotation graphs must be owner-local, acyclic and NULL-terminating; and deterministic malformed-backup failures carry sanitized validation/400 semantics before writes.
- 2026-08-28 Step 4A: the repository-level OAuth backup gap is closed for exactly all 17 current `oauth_*` tables. Version-1 legacy-only imports remain compatible; merge leaves OAuth untouched, replace removes OAuth dependants before legacy parents, full restore ordering handles credential self-links and refresh lineage transactionally, and raw OAuth secret/token/private-key material remains excluded. Real PostgreSQL restore proof remains the Step 4B blocker above.
- 2026-08-28 Step 3E: the audited Step 3D lifecycle is mounted through a default-off strict form/Basic HTTP adapter with separate non-disclosing rate limits and exact RFC 8414 discovery. False/absent remains all-OAuth 404; no migration, pilot, registration or production action was added.
- 2026-08-27 Step 3D: authorization-code exchange now re-checks current client/resource/authorization/user/exact mappings and the exact active legacy grant inside the code-consumption transaction. Refresh applies the same fail-closed entitlement rules.
- 2026-08-27 Step 3D: the OAuth private-key loader accepts only local references confined by realpath to the dedicated root and rejects traversal, symlink escape, unsupported/relative references, non-regular/oversized files, the legacy key and public/private/fingerprint mismatch.
- 2026-08-27 Step 3D hardening: mixed row locks no longer upgrade read-only rows; code and refresh persisted scope/generation invariants fail closed; legacy/OAuth RSA and pepper identity reuse is rejected; overlap retirement, future `iat`, disabled-resource revocation durability and separate sanitized code-denial audit behavior are covered by local tests.
- 2026-08-27 Step 3D final hardening: RFC 7009/7662 hints are advisory, access-jti revocation retention covers the verifier-skew window, and signing-key `last_signed_at` is monotonic. Target schemas/contracts and local regression tests are aligned without mounting routes or changing migration 005.
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

- 2026-08-27 Step 3D: apply migrations 001→005 to disposable PostgreSQL 16, run the old-binary/schema-consumer smoke test, and execute real same-refresh concurrency proving one rotation success plus one consumed-token replay revocation without deadlock. Static SQL-shape and serialized service tests are local evidence only; never use production for this check.
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
- 2026-08-25 Step 1.5B / 2026-08-27 Step 3D: current live safe effective configuration is still unproven. All 45 source-derived variables, including optional OAuth flag/protection/credential-pepper/signing-root inputs, remain `UNOBSERVED` in the committed evidence template until an operator supplies approved state/effective-value proof.

## DEFERRED_SCOPE

- SCIM or Google Workspace Directory provisioning.
- Automatic group-to-tool synchronization from Google Groups.
- Device posture checks.
- Risk-based access and step-up authentication.
- Full SIEM integration.
- Dedicated SDK packages per framework.
- Immutable append-only log storage with WORM retention.
- OAuth registration/admin HTTP APIs, pilot records, production client/resource/scope/mapping/credential registration and any enablement remain deferred until separately approved steps and the release gates pass. Step 3E completes only the default-off protocol mount.
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
