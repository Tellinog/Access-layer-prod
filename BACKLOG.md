# BACKLOG.md

## BLOCKER

- Confirm who receives bootstrap platform admin access after first deploy.

## RESOLVED

- 2026-06-17: Corrected and confirmed real Google Workspace domain list for `GOOGLE_ALLOWED_HD`: `unguess.io`.
- 2026-06-16: Confirmed production and local redirect URIs before creating OAuth clients:
  - `http://localhost:8080/access-control/v1/auth/google/callback`
  - `https://access-layer.draftapps.it/v1/auth/google/callback`
  - No separate staging redirect URI is required for v1 unless specified later.

## QUESTION

- Should raw IP be stored for audit, or only salted hash plus country/ASN metadata?
- Should logs be exported to an external SIEM in v1?
- Should per-tool role labels remain free-form strings after v1, or become centrally managed values?

## ASSUMPTION_TO_VALIDATE

- `prod.env` generation used `.env.docker` as the available local env source because no root `.env` file was present in the workspace; validate whether a separate canonical `.env` should exist for future production-env generation tasks.
- Runtime stack availability in the target environment: Node.js 22 LTS, TypeScript build pipeline, PostgreSQL and SQL migration runner.
- Access token TTL: 15 minutes.
- Refresh token TTL: 8 hours.
- One-time code TTL: 60 seconds.
- Audit log retention: 365 days.
- All tools have a server-side component able to keep a tool client secret. Frontend-only tools must add a backend proxy.
- Delegated `tool_admin` scope can use `admin_tool_assignments` plus matching `tools.owner_email` for v1.
- Storing tool callback `state` in `auth_requests` is acceptable because tool integrations must not include secrets in state.
- Admin-only restore secret material export includes runtime secrets such as `TOOL_CLIENT_SECRET_PEPPER` and `BACKUP_ENCRYPTION_KEY`; existing per-tool client secrets remain non-recoverable because only hashes are stored, so lost per-tool secrets require rotation.

## DEFERRED_SCOPE

- SCIM or Google Workspace Directory provisioning.
- Automatic group-to-tool synchronization from Google Groups.
- Device posture checks.
- Risk-based access and step-up authentication.
- Full SIEM integration.
- Dedicated SDK packages per framework.
- Immutable append-only log storage with WORM retention.

## RESOLVED_2026_06_17

- Access Layer production base path was previously confirmed as `/access-control`; this is superseded for production by the 2026-06-21 dedicated-subdomain update below.
- 2026-06-21: Superseded the production `/access-control` base path with the dedicated production origin `https://access-layer.draftapps.it`; local Docker remains on `/access-control`.
- Tool onboarding will be performed through the Admin UI for v1, not through production seed files.
- Coolify variables will be configured in the Coolify UI from `.env.production.example`; real `.env` files must not be included in deployment packages.

## FOLLOW_UP

- Re-run Admin UI verification for the 2026-07-02 UNGUESS visual alignment once dependencies are already available locally or external dependency installation is explicitly allowed: `npm ci`, `npm run lint`, `npm run build`, `npm test` and a browser smoke test.
- Run `docker compose config` and a real container smoke test on a host with Docker/Coolify access.
- After Coolify deploy, verify `GET https://access-layer.draftapps.it/health` and `GET https://access-layer.draftapps.it/v1/.well-known/jwks.json`.
- Login as bootstrap admin and create the first real tool from the Tools UI.
