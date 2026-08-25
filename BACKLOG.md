# BACKLOG.md

## BLOCKER

- Confirm who receives bootstrap platform admin access after first deploy.
- 2026-08-24: `docker-compose.yaml` mounts `access_layer_postgres_data_v2` but declares `access_layer_postgres_data`. Do not rename either value or deploy until the live Coolify volume mapping is identified and a verified backup/restore point exists.
- 2026-08-24: production deployment remains blocked until exact Coolify server/project/resource/destination identifiers and the central registry record are verified.
- 2026-08-24 Step 1.5: `operations/production-continuity.evidence.yml` is intentionally `NOT_READY`; the actual PostgreSQL storage identity, verified backup, and isolated restore result remain unproven. Do not deploy, rename volumes, or begin N→N+1 execution.
- 2026-08-25 Step 1.5B: observe whether live JWT signing uses inline PEM or a file. If file-backed, prove the actual persistent storage/mount identity for `/run/secrets`; also prove same-key continuity using public-key/external evidence. Do not read, hash, copy, rotate, or regenerate the private key.
- 2026-08-25 Step 1.5B: the isolated-restore gate is blocked until external secret-safe sameness evidence exists for `SESSION_SECRET`, `TOOL_CLIENT_SECRET_PEPPER`, `BACKUP_ENCRYPTION_KEY`, `GOOGLE_CLIENT_SECRET`, and `LOG_IP_SALT`. Presence/state alone is not proof.
- 2026-08-25 Step 1.5B: both machine gates remain false. The intermediate gate additionally needs complete live configuration/topology/storage/backup/database/registry/ownership evidence and approvals; final N→N+1 readiness additionally needs a real `PASSED` isolated restore and two immutable N/N+1 artifacts.

## RESOLVED

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
- 2026-08-24 Step 1.5: provide the exact Coolify server/project/environment/resource/destination identifiers, current live domain, deployed revision/image identity, replica/deploy/auto-deploy facts and named continuity operator.
- 2026-08-24 Step 1.5: identify the authoritative central deployment registry location and the Access Layer record identifier/evidence reference.
- 2026-08-25 Step 1.5B: identify the approved access-controlled evidence system and authorised operators for secret-manager version references, side-by-side comparisons, or controlled binding records. No secret value or reusable verifier may be stored in Git.

## ASSUMPTION_TO_VALIDATE

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
- 2026-08-24: Coolify represents this Docker Compose deployment as resource type `service`; verify against the live resource before central registration.
- 2026-08-24: the named central deployment registry ID is `unguess-coolify-deployments`; its authoritative location and record ownership remain unverified.
- 2026-08-24: Nancy, Test Generator and Goodman in-memory refresh locks are sufficient only for their observed single-replica assumptions; multi-replica safety is not proven.
- 2026-08-24: Petyr's supplied registration and code are deployed as inspected. Evidence contains a superseded Access Layer origin and a permission used in code but absent from the supplied tool registration.
- 2026-08-24 Step 1.5: repository expectations (app `8080`, PostgreSQL `5432` private, no public host-port mapping, target domain) match the live Coolify topology. They remain unverified observations.
- 2026-08-25 Step 1.5B: current live safe effective configuration matches the frozen production defaults and intended values. All 41 source-derived variables remain `UNOBSERVED` in the committed evidence template until an operator supplies state/effective-value proof.

## DEFERRED_SCOPE

- SCIM or Google Workspace Directory provisioning.
- Automatic group-to-tool synchronization from Google Groups.
- Device posture checks.
- Risk-based access and step-up authentication.
- Full SIEM integration.
- Dedicated SDK packages per framework.
- Immutable append-only log storage with WORM retention.
- OAuth/OIDC endpoints, discovery metadata, authorization-server tables, scopes, service principals and token exchange.
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
