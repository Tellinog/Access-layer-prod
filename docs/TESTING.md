# TESTING.md

## Step 3B read-only OAuth metadata/JWKS conformance

`tests/oauth-darkness.test.ts` compares the default-off composed route inventory to the unchanged legacy `buildApp`, proves the two new paths remain 404 when disabled, and proves only GET `/oauth/jwks` plus GET RFC 9728 protected-resource metadata become reachable when enabled. Their automatic `HEAD` siblings, authorization-server metadata, authorize, token, revoke, introspect and upstream Google remain 404. The legacy JWKS response is identical for both flag states.

Pure tests deep-equal both current metadata examples, prove that RFC 9728 omits zero-valued `scopes_supported` but emits a non-empty canonical list, and preserve a trailing-slash issuer identifier while avoiding duplicate slashes in constructed endpoints. JWKS tests use a Node-core-generated, test-only 2048-bit RSA public JWK and commit no private key. They include valid active and published pre-activation overlap keys in deterministic `kid` order; reject missing, padded, whitespace-bearing, non-base64url and empty-decoded values, redundant leading-zero integers, sub-2048-bit/zero moduli, exponents 0/1/2, even exponents and exponents greater than or equal to the modulus; exclude staged, disabled, retired, malformed, incoherent and not-yet-published rows; enforce the exact 300-second public cache header; prove serialization is restricted to six public RSA members even for an injected extra reference-like field; and require sanitized 503 `temporarily_unavailable` for empty/invalid/repository-failure states.

Final Step 3B candidate result before this hardening: lint/build passed; Vitest passed 191 tests across 14 files; Python reported 60 passed, 2 skipped (62 collected); the OAuth validator passed 24 check groups; continuity remained `VALID_BUT_NOT_READY` with both gates false; non-strict platform validation passed 27 checks with seven known warnings; and the frozen-file audit plus `git diff --check` passed. Live PostgreSQL application remains unavailable for the previously recorded environmental reasons; Step 3B adds no migration.

Final Step 3B hardening result: lint/build passed; Vitest passed 211 tests across 14 files; Python reported 60 passed, 2 skipped (62 collected); the OAuth validator passed 24 check groups; continuity remained `VALID_BUT_NOT_READY` with both gates false; non-strict platform validation passed 27 checks with seven known warnings; and the frozen legacy/dependency/migration audit plus `git diff --check` passed. Docker has no reachable daemon, `psql` is absent and port 5432 is closed, so no live PostgreSQL test or production connection occurred; this hardening adds no migration.

Final Step 3B RSA/JWK hardening result: lint/build passed; Vitest passed 231 tests across 14 files; Python reported 60 passed, 2 skipped (62 collected); the OAuth validator passed 24 check groups; the non-strict platform checker passed 27 checks with seven known warnings; continuity remained `VALID_BUT_NOT_READY` with both gates false; and frozen legacy/dependency/migration checks plus `git diff --check` passed. This change adds no migration and does not claim independent/live PostgreSQL validation.

## Step 3A OAuth dark-foundation conformance

`tests/oauth-foundation.test.ts` deterministically verifies that `migrations/003_oauth_dark_foundation.sql` creates exactly the ten approved tables, contains no destructive/legacy DDL or data write, omits all protocol transaction tables and includes the required identity, redirect, mapping, allow-list, hash-only credential and signing-key constraints. Signing coverage includes the exact 300-second publication lead, 1,260-second post-signature retention, retirement ordering, status/timestamp coherence and NULL-safe required-string public JWK checks.

The same suite exercises synthetic fail-closed registration helpers for exact three-segment OAuth scopes, exact legacy tool-slug and permission grammars, schema-parity redirect/resource URI syntax, confidential/public credential-presence lifecycle metadata, complete one-to-one entitlement mapping coverage, registered permissions and explicit client/resource/scope allow-list rows. URI cases cover raw whitespace/control, backslash, malformed percent escapes, userinfo, fragments and wildcards while proving valid strings are not rewritten. Signing tests reject insufficient lead/retention, incoherent active/retired timestamps, missing/null/wrong-type/empty required public JWK members and every forbidden private member. Repository tests prove absence denies, legacy access is read-only and limited to entitlement lookup, resource credential queries do not select hashes, and signing-key queries expose neither private material nor the protected private-key reference.

Step 3B supersedes the Step 3A all-dark HTTP assertion while preserving the default-off result. `tests/config.test.ts` proves an old environment with the variable absent defaults to false and that the optional flag creates no new OAuth secret/key/credential requirement.

The frozen legacy source/route/error/payload checks remain active. The legacy config hash witness removes only the exact additive default-false assignment before comparing to the Step 1 hash; any other change still fails. `specs/oauth-p0.v1.yml`, target OAuth OpenAPI/schemas/examples and the historical legacy OpenAPI remain unchanged.

Live migration application was unavailable in this workspace: the Docker client cannot reach `npipe:////./pipe/docker_engine`, no PostgreSQL tools are installed, and `127.0.0.1:5432` refuses connections. No production database was contacted. A disposable PostgreSQL 16 apply plus old-binary smoke test remains recorded in `../BACKLOG.md`; until then, the deterministic migration test is the Step 3A evidence for expand-only shape and required constraints.

Final Step 3A hardening result: lint/build passed; Vitest passed 190 tests across 14 files; the Python suite reported 60 passed, 2 skipped (62 collected); the OAuth validator passed 24 check groups; continuity remained schema-valid `VALID_BUT_NOT_READY`; non-strict platform validation passed 27 checks with seven known warnings; the frozen-file diff audit and `git diff --check` passed. Migration `003` contains exactly ten tables and has hardening SHA-256 `96B3993FCFDB930597CBDECA37E86D51DF486FD9E951970D156A21C454F18EFE`.

## Step 2 OAuth P0 contract conformance

`scripts/validate_oauth_p0_contract.py` and `tests/test_oauth_p0_contract.py` validate the target OpenAPI, machine profile, registration schemas and synthetic examples without invoking runtime endpoints. Checks freeze the exact P0 path/grant/auth-method set, RFC 9207 `iss`, RFC 7636 verifier and exact S256 challenge grammar, one RFC 8707 resource, exact single audience, RFC 9068 `typ=at+jwt`, Google-sub mapping, PII minimisation, canonical three-segment OAuth scopes, BFF architecture, exact legacy tool/permission grammars, mandatory legacy-tool entitlement binding, exact one-to-one scope-entitlement mapping coverage, resource-owned introspection credentials, exact-audience access-token introspection disclosure, the separate non-advertised Google upstream callback, reversible protected downstream-state survival, replay-family behavior, dedicated key rotation, OAuth errors and P1 exclusions.

The validator also resolves every internal OpenAPI component reference and rejects wildcard redirects, invalid PKCE characters/lengths, refresh-token or wrong-audience active introspection, missing P0 entitlement bridges, missing/extra/duplicate scope mappings, shared RequestContext-v1 narrowing, legacy grammar drift, P1 advertisement and real-looking fixture credentials. It still proves that protocol runtime is absent from `src/app.ts` and that the frozen legacy migrations contain no OAuth table. Step 3A migration shape is covered separately by the stricter TypeScript foundation suite above.

Final Step 2 hardening result: the validator passed 24 check groups; the full Python suite passed 61 tests with two expected template-bootstrap skips; Vitest passed 113 tests across 12 files; lint/build, schema/OpenAPI/reference validation, targeted legacy baseline checks, resolved Compose inspection and `git diff --check` passed. Non-strict platform validation passed 27 checks with seven known warnings. Strict platform release validation still reports only the five external operational gates documented in `CURRENT_STATE.md` and `BACKLOG.md`.

## Step 1.5 production-continuity evidence checks

`scripts/validate_production_continuity.py` validates `operations/production-continuity.evidence.yml` against its v2 JSON Schema, rejects secret-bearing fields/values and reusable verifiers, and reports separate isolated-restore and N→N+1 gates. Exit codes are `0` (final `READY`), `2` (`VALID_BUT_NOT_READY`) and `1` (`INVALID`). The committed bundle is expected to return exit `2` with both gates false until live operator evidence and a later isolated restore exist.

Python tests cover the committed incomplete state, staged gates, JWT source alternatives/persistence, secret sameness, false `READY` claims, unsafe evidence rejection without value echoing, and a fully synthetic ready bundle. Vitest covers state-only secret output, the source-derived configuration inventory, safe effective configuration, public-JWK fingerprint safety, PostgreSQL helper fail-closed constraints, and runtime-source invariance. No test in Step 1.5B connects to production or runs a restore/upgrade.

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

## Step 1.5B evidence conformance

`tests/test_production_continuity_evidence.py` exercises schema-v2 gate separation, inline/file-backed JWT alternatives, persistent key-mount proof, empty-secret rejection, valid empty `PUBLIC_BASE_PATH`, external secret-sameness proof, isolated-restore promotion, final restore gating, and unsafe-verifier/credential rejection. `tests/continuity-tools.test.ts` verifies the 42-variable source inventory, including optional default-false `OAUTH_P0_ENABLED`, state classification, helper redaction, credential-bearing URL suppression, public-JWK-only behavior, and invariant hashes for `src/config.ts`, `docker-compose.yaml`, and `docker/entrypoint.sh`.

The committed evidence template must validate as `VALID_BUT_NOT_READY` with both gates false. A synthetic test fixture may reach either gate; it is not production evidence and must use only `.invalid` identities and non-secret placeholders.
