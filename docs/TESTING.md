# TESTING.md

## Test strategy

Testing must cover authentication, authorization, denial paths, token lifecycle, admin changes and audit logging.

## Current automated coverage

The v1 implementation includes Vitest tests for:

- fail-closed runtime config loading for required secrets and hosted-domain-only `GOOGLE_ALLOWED_HD`;
- tool slug, permission key and exact return URL validation;
- localhost-only HTTP callback handling;
- opaque hashing, tool secret hashing and signed admin cookies;
- encrypted backup payload round-trip behavior;
- audit metadata redaction for token/secret-like fields;
- Google ID token claim validation for `aud`, `iss`, `exp`, `email_verified` and `hd`;
- Access Layer JWT issuing, audience scoping and JWKS publishing;
- Access Layer JWT audience mismatch rejection;
- Access Layer JWT expiration rejection;
- Access Layer JWT unknown signing key rejection;
- `/access-control/v1/auth/start` invalid return URL denial with audit event creation.
- `/access-control/v1/auth/start` endpoint-specific rate limiting by IP and tool.
- `/access-control/v1/auth/start` fail-closed behavior when auth request or denial audit writes fail.
- configured CORS preflight behavior.
- token-like query string rejection with audit event creation.
- mocked callback unknown-state denial before Google exchange;
- mocked external-domain callback denial with no user or access request creation;
- mocked unverified-email callback denial with no user or access request creation;
- mocked valid-internal/no-grant callback creating a single pending access request;
- mocked repeated valid-internal/no-grant callback updating the pending access request and writing `access_request.repeated`;
- mocked pending-email grant linking on first valid Google login;
- mocked active-grant callback creating a one-time code;
- mocked one-time-code exchange success, refresh token hashing path and replay denial.
- mocked activity-driven refresh success, refresh-token rotation, sliding session extension and old-token replay denial.
- mocked refresh denial after inactivity expiry or grant revocation.
- mocked one-time-code exchange denial with wrong tool client secret and audit event creation.
- mocked introspection active result and inactive result after grant revocation.
- mocked admin tool creation returning a one-time client secret, storing only a verifiable hash and writing `admin.tool.created`;
- mocked admin tool listing returning registered permission keys for admin editing;
- mocked admin tool search/status/owner filter forwarding and assigned-tool scoping;
- mocked admin tool update changing metadata and registered permission keys with `admin.tool.updated` audit;
- mocked admin tool secret rotation with existing-client revocation, verifiable hashed storage and `admin.tool.secret_rotated` audit;
- mocked admin user search/status filter forwarding;
- mocked admin user disable with active-session revocation and `admin.user.status_changed` audit;
- mocked admin email grant creation with `pending_user_link` status and `admin.grant.created` audit;
- mocked admin known-user grant creation with `active` status and `admin.grant.created` audit;
- mocked admin grant role/permission update with `admin.grant.updated` audit;
- mocked admin grant revocation with active-session revocation and `admin.grant.revoked` audit;
- mocked delegated tool-admin grant list, creation and update scoping to assigned tools;
- mocked admin access-request approval creating a grant and writing both audit events;
- mocked admin access-request rejection without grant creation and with audit event creation;
- mocked admin access-request closure without grant creation and with audit event creation;
- mocked delegated tool-admin access-request scoping for assigned tools;
- mocked auditor denial when attempting to approve access requests.
- explicit backup permission behavior and encrypted backup surfaces through admin route coverage.
- pending grant email validation for company-domain-only pending grants.
- configured access-request reopen delay behavior through repository/service coverage.
- audit log filter forwarding and fail-closed validation for invalid audit filters.
- Admin UI tool search/status/owner filters, metadata, permission-key onboarding controls and inline create/secret result forms.
- Admin UI user search/status filters and destructive disable confirmation.
- Admin UI known-user grant creation controls from user detail through an inline form.
- Admin UI audit log filter controls and correlation copy affordance.
- Admin UI grant filters, inline create controls, detail edit controls and revocation confirmation.
- Admin UI tool/user relationship views, registered tool selectors, checkbox permission pickers, full-width desktop layout and one-email-per-line bulk grant preview controls.
- Admin UI access-request filters, first/last-attempt columns and inline approval/reject/close forms.
- Admin UI shared table pagination controls and empty-state affordance.
- Admin UI non-sensitive OAuth/runtime settings summary without secret disclosure.
- Admin UI encrypted backup and restore secret material controls.
- Admin UI served inline JavaScript parseability, catching generated-script errors before browser smoke tests.
- Docker builder-stage asset inputs are copied before `npm run build`, preventing the favicon copy step from failing only in container builds.
- Admin UI authenticated shell renders logout instead of the old fixed login button.
- Admin UI refresh route rotates the protected refresh cookie and the client retries an Admin API request once after successful renewal.
- Admin CSV bulk grant template export, permission catalog export, preview, commit and error-blocked commit behavior.
- Local root redirect to the Admin UI.

Latest visual-alignment verification attempt, 2026-07-02:

- `npm run lint`, `npm run build` and `npm test -- tests/app.admin.test.ts` could not run because `node_modules` is absent in this workspace.
- Dependency installation was not performed because the task explicitly disallowed external fetches.
- No-dependency static checks confirmed the new Admin UI table wrapper is balanced and the UNGUESS palette tokens are present in `src/app.ts`.
- Full automated and browser verification remains a follow-up once dependencies are already available or external installation is explicitly allowed.

Latest local verification, 2026-06-18:

- `npm.cmd run lint` passed.
- `npm.cmd run build` passed.
- `npm test` passed with 9 test files and 81 tests.
- Served Admin UI script extraction plus `node --check` passed, covering parseability of the inline Admin UI JavaScript.
- Previous `npm.cmd run start` verification served `/access-control` on `http://127.0.0.1:18080/access-control` with a temporary ignored JWT key and `GOOGLE_ALLOWED_HD=unguess.io,nuotounostiledivita.it` override; the response contained the tool filters, tool description, permission-key controls, user filters, known-user grant creation controls and user disable confirmation copy.

Latest security hardening verification, 2026-06-19:

- `npm.cmd run lint` passed.
- `npm.cmd run build` passed.
- `npm.cmd test` passed with 9 files and 86 tests.
- `npm.cmd audit --package-lock-only --audit-level=moderate` passed with 0 vulnerabilities after the `vite -> esbuild@0.28.1` override.

Latest production URL topology verification, 2026-06-21:

- `npm.cmd run lint` passed.
- `npm.cmd run build` passed.
- `npm.cmd test` passed with 9 files and 87 tests.
- Added config coverage for production on `https://access-layer.unguess-internal.net` with empty `PUBLIC_BASE_PATH` and root `/v1/auth/google/callback`.

Docker verification status, 2026-06-17:

- Local Docker Compose support was added for Access Layer plus PostgreSQL.
- `docker compose --env-file .env.docker config --quiet` passed in this environment, with Docker warning that `C:\Users\loren\.docker\config.json` could not be read.
- Verification command to run in an environment with Docker daemon access:
  - `Copy-Item .env.docker.example .env.docker`
  - edit `.env.docker` placeholders;
  - `npm.cmd run docker:up`;
  - `Invoke-WebRequest http://localhost:8080/health`.

Non-passing environment checks, 2026-06-16:

- `npm.cmd run migrate` failed with `ECONNREFUSED` for `::1:5432` and `127.0.0.1:5432`.
- `docker info` failed because Docker daemon/API access was unavailable at `npipe:////./pipe/docker_engine`.
- In-app browser automation did not start in this Windows sandbox (`CreateProcessAsUserW failed: 5`), so visual/browser interaction verification remains pending.

Additional integration coverage should be added after PostgreSQL and configured Google OAuth credentials are available in the target environment.

## Unit tests

- Tool slug validation.
- Return URL allow-list matching.
- Email normalization.
- Grant resolution by user ID and pending email.
- JWT claims generation.
- Audit event builder redacts sensitive fields.
- Error code mapping.

## Integration tests

Use mocked Google OIDC responses unless running a dedicated configured-environment flow.

Required cases:

- valid Google token with allowed `hd`;
- missing `hd` denied;
- wrong `hd` denied;
- `email_verified=false` denied;
- invalid `aud` denied;
- expired token denied;
- unknown tool denied;
- invalid return URL denied;
- no grant denied;
- active grant allowed;
- pending email grant links to first valid login;
- one-time code exchange success;
- one-time code replay denied;
- introspection active/inactive;
- revoked grant makes introspection inactive if online revocation is enabled.

## End-to-end tests

For the configured v1 environment:

1. Register pilot tool.
2. Create grant for test internal user.
3. Complete login through browser.
4. Verify tool session contains identity.
5. Verify audit logs for request, callback, allowed and exchange.
6. Test internal user without grant.
7. Test external account.

## Security tests

- CSRF state mismatch.
- Callback without known state.
- Manipulated return URL.
- Tool exchange with wrong secret.
- JWT audience mismatch.
- JWT signed by unknown key.
- Expired JWT.
- Token in query string rejected for API calls.
- Auth-start audit write failure fails closed before Google redirect or auth request persistence.
- Unknown admin status filters rejected before list queries.
- Unknown audit outcomes and malformed audit date filters rejected before list queries.
- Admin UI callback state failures write denied audit events.
- Admin UI logout revokes the server-side session and writes a logout audit event.
- Stale logout/revocation attempts write `session.revoke.denied`.
- Refresh tokens are single-use, old-token replay is denied and inactive sessions/grants cannot be refreshed.
- Logs do not contain token-like values.
- Backup export is encrypted and backup/restore permissions are explicit.
- Cookie-authenticated admin write requests require same-origin validation.
- Pending email grants reject external or malformed email addresses.
- Bulk grant import accepts comma- and semicolon-delimited templates, and rejects external domains, unknown tools, unassigned tools for delegated admins, malformed dates and unknown permission keys before writing.
- Bulk grant commit creates or updates grants idempotently, keeps unknown company emails as `pending_user_link`, and revokes matching sessions on `revoke` rows.

## Manual test checklist

- [ ] Admin can create tool.
- [ ] Admin can create grant by email.
- [ ] User can access authorized tool.
- [ ] User cannot access unauthorized tool.
- [ ] External account denied.
- [ ] Logout clears local session.
- [ ] Admin can query audit logs by email/tool/correlation ID.

## Access request tests

Required cases:

- valid internal Google user without grant creates one pending access request;
- repeated attempt for same user/tool increments `attempts_count` and does not create duplicates;
- external-domain denial does not create access request;
- invalid return URL does not create access request;
- admin approval creates grant and marks request approved in one transaction;
- admin rejection marks request rejected and does not create grant;
- admin close marks request closed and does not create grant;
- tool admin can see only requests for assigned tools;
- auditor can read audit logs but cannot approve requests.


## Admin UI login gate regression

Automated Admin UI tests must cover both states:

- unauthenticated `GET /admin` or `GET /access-control` redirects to the corresponding login route;
- authenticated `GET /admin` or `GET /access-control` with a valid signed admin session cookie serves the dashboard HTML and parseable inline JavaScript.

Health route checks should verify availability, but successful health probes are intentionally silent in request logs.

## Admin tool detail and session-expiry regression

Automated Admin UI/API tests must cover:

- expired or invalid admin sessions returning the invalid-session error code so the browser redirects back to admin login;
- served Admin UI inline JavaScript remains parseable after tool-detail changes;
- tool detail exposes `Modifica`, `Salva modifiche` and `Elimina` controls;
- tool update persists permission keys and shows save feedback;
- deleting a non-reserved tool writes an audit event;
- deleting the reserved `access-admin` tool is denied.

Verification for the 2026-06-22 update: `npm run lint`, `npm run build` and `npm test` passed locally with 9 files and 92 tests.
# Step 1 conformance

`tests/legacy-contract-baseline.test.ts` verifies normalized source hashes, every observed `/v1/*` method/path, error/status mappings, migration hashes, the known Compose volume mismatch, absence of OAuth/OIDC runtime additions and synthetic golden shapes. Template conformance tests under `tests/platform-conformance/` validate the additive platform records. The future live-version procedure is `../N_TO_N_PLUS_1_SURVIVAL_PLAN.md`; it is not a passing test until two immutable images are exercised.
