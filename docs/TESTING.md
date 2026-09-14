# TESTING.md

## Temporary legacy Microsoft bridge coverage

The bridge suite uses only synthetic provider data. `tests/microsoft-claims.test.ts` covers tenant-specific URLs and strict issuer/audience/tenant/expiry/object/nonce/email/domain checks, preferred-username fallback, synthetic subject mapping, no Graph dependency and sanitized upstream failures. `tests/config.test.ts` covers default-off behavior and conditional completeness/format/callback/scope/slug validation.

Legacy HTTP tests cover provider selection, no state creation for the chooser, direct Google when disabled or non-allowlisted, `gst_`/`mst_` callback isolation, missing/unknown/expired/replayed/error state, nonce mismatch, full Microsoft callback/exchange shape, pending-email grant linking, no-grant access request and disabled user/tool denial. Token tests prove the synthetic subject still receives the frozen legacy claim set, TTL and audience. The legacy contract baseline test permits only the reviewed bridge-source differences and continues to validate all pre-existing frozen payload/error mappings.

No test calls Microsoft, Google, production, Coolify or a real credential. A separately authorized real-tenant smoke test remains an operational assumption to validate.

## Step 4B disposable PostgreSQL 16 qualification

`scripts/step4b/run-qualification.ps1` creates two distinct synthetic PostgreSQL 16 containers on random loopback-only ports, applies the existing migration runner to each, invokes the real-HTTP qualification harness and removes both containers in `finally`. The harness allows only a fake upstream Google dependency; database, repository, service, signing, HTTP backup and legacy-baseline boundaries remain real. Temporary credentials, refresh material and RSA files are never emitted as evidence.

The runner now requires an entirely clean worktree, resolves the exact 40-character commit before execution and makes the harness prove equality plus ancestry from approved Step 4A `1757a40c6369be59427da6618fa8126605a51550`. `legacyBaselineSmoke()` now also calls `GET /v1/.well-known/jwks.json` and requires status 200, at least one `RSA`/`RS256`/`sig` key with non-empty `kid`, and no private JWK members.

The hardened harness exposes only response status/OAuth error code and sanitized SQLSTATE/constraint/query-tag. It explicitly distinguishes timeout, deadlock, rate-limit, constraint, other database and HTTP 5xx outcomes and attempts family/session/generation/parent/revocation-order evidence before failing. Each complete run performs eight real same-refresh races and requires exactly one 200 plus one 400 `invalid_grant`, zero 429/5xx/database error, revoked family/session with replay marker, gen0 consumed, gen1 revoked, coherent parent and online inactivity of the winner access token.

Exact clean commit `d8998e1fbc1789d71a19cef78714c74c3dbfed37` passed three complete consecutive qualifications on fresh paired PostgreSQL 16.15 containers. All 24 races passed, as did OAuth authorize/fake callback/code exchange, claims/TTL/JWKS/introspection/revocation, coordinated repeatable-read snapshot, encrypted replace restore, pre-backup access/refresh continuity after restore and legacy health/JWKS/auth-start smoke. No `pg` concurrent-query deprecation warning appeared; cleanup left zero Step 4B containers after every run. This is local candidate evidence, not the required subsequent independent approval.

The pre-fix diagnostic run on `59cc07957dee6f1f9d576ef1823cd9e59b28bee0` preserved only safe evidence: one 200, one 503 `temporarily_unavailable`, SQLSTATE `23514`, `oauth_refresh_tokens_revoked_order` and query-tag `revoke_current_refresh_token`, with active family/session and gen0 consumed/gen1 current after rollback. It confirms the older pre-lock timestamp race without recording tokens, hashes, credentials, keys, arbitrary bodies or private paths.

The 2026-08-31 rerun used exact commit `ac3a4c54f4f865d0193f254b9a525f5b06e6b28d`. Both PostgreSQL 16 targets applied migrations 001–005; authorize/callback, real code exchange, exact access-token claims/TTL, dedicated JWKS, resource introspection, normal refresh and revocation passed. Two concurrent uses of the same refresh credential completed with exactly one success, but the loser did not match the required HTTP 400 `invalid_grant`. The harness stopped before replay-state, snapshot/export/restore, post-restore continuity and legacy-baseline assertions. Step 4B remains `FAIL — BLOCKED_IMPLEMENTATION`; cleanup left no Step 4B container.

The 2026-08-30 run on PostgreSQL 16.15 is `FAIL — BLOCKED_IMPLEMENTATION`. Both targets applied exactly migrations 001–005 and the generated OAuth signing-key preflight plus real HTTP authorize/callback passed. Real authorization-code exchange then returned sanitized 503 because PostgreSQL reported SQLSTATE `42601`, parser position 661, in `OAuthTokenRepository.lockAuthorizationCodeByHash()`; the position maps to the unquoted `authorization.status` alias reference. The harness stopped rather than patching or bypassing the frozen runtime, so claims/JWKS/introspection, refresh/revocation, same-token concurrency, coordinated encrypted snapshot/restore and legacy-baseline schema smoke are not claimed. Full sanitized evidence is in `../operations/STEP_4B_QUALIFICATION_REPORT.md`.

## Step 4A snapshot and lineage hardening conformance

The export regression uses distinct pool/root and transaction-bound query recorders. It requires exactly one transaction, `SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY` as the first callback statement, and all 24 explicit deterministic table `SELECT`s sequentially through only the transaction-bound `Db`. The real coordination gate still proves a concurrent committed rotation cannot tear the snapshot.

Import regressions require the refresh generation set to equal exactly `0..current_generation`, covering current zero with an extra generation, internal gaps, an illegal root parent, missing/wrong and cross-family parents. Separate client and resource fixtures reject two-row and longer credential rotation cycles before a transaction, while the existing unordered acyclic-chain test continues to prove second-pass restoration. Partial OAuth sets and invalid lineage expose only a sanitized backup-validation error with `statusCode=400`, which the frozen global handler maps to legacy `VALIDATION_ERROR`/400.

Final hardening result: TypeScript lint/build passed; Vitest passed 315 tests across 18 files, including 14 backup repository tests; Python passed 61 tests with two expected skips (63 collected); the OAuth validator passed all 24 groups; continuity remained `VALID_BUT_NOT_READY` with both gates false; and non-strict platform validation passed 27 checks with seven known warnings. Migration 005 and the approved `src/app.ts` blob witnesses passed, no migration 006 exists, and `git diff --check` passed. No real PostgreSQL restore is claimed.

## Step 4A OAuth backup repository conformance

`tests/backup-repositories.test.ts` verifies that export returns the unchanged seven legacy sections plus exactly all 17 current OAuth sections. Every query names persisted columns, uses deterministic ordering and excludes raw OAuth client/resource secrets, authorization codes, access/refresh tokens, private-key contents and environment secrets while retaining only stored hashes, protected ciphertext, public signing metadata/fingerprint and the protected key reference.

Import tests require all seven legacy arrays and enforce zero-or-all-17 OAuth arrays before opening a transaction. They prove that legacy-only merge emits no OAuth SQL, legacy-only replace deletes all OAuth dependants before the existing legacy sequence, full import orders legacy/OAuth parents safely, credential rotation self-links use a second pass independent of input order, refresh rows are validated/sorted by family and generation, inconsistent lineage fails before writes and a synthetic database failure rolls back the complete transaction.

`tests/legacy-contract-baseline.test.ts` additionally pins the normalized Git blob for `src/app.ts` to the approved Step 3E blob `6eaf4d2c3564eb851abbd23371be5a2e2d6a1f12`, while the existing baseline continues to pin legacy sources, routes, errors, migrations, OpenAPI and Compose. Step 4A adds no live PostgreSQL test; the real encrypted backup/replace restore is Step 4B.

Final Step 4A result: TypeScript lint/build passed; Vitest passed 308 tests across 18 files; Python passed 61 tests with two expected skips (63 collected); the OAuth validator passed all 24 groups; continuity remained `VALID_BUT_NOT_READY` with both gates false; and non-strict platform validation passed 27 checks with seven known warnings. Migration 005 and the approved `src/app.ts` blob witnesses passed, no migration 006 exists, and `git diff --check` passed. No real PostgreSQL restore is claimed.

## Step 3E strict OAuth HTTP conformance

`tests/oauth-http.test.ts` covers the encapsulated 16 KiB form boundary, single decoding, malformed percent/UTF-8 input, duplicate names, unknown fields, empty required values, unsupported media and oversized bodies. OAuth Basic tests require canonical Base64, exactly one raw separator and form-decoded credential components, including encoded colon/space characters; malformed Basic, Bearer, missing separators and Basic/body client mismatch fail as sanitized `invalid_client`.

Token tests assert exact Step 3D service inputs for confidential and registered public-`none` boundaries, exact token wire field names and values, no-store/no-cache headers, refresh scope forwarding and status mapping for `invalid_client`, `invalid_grant`, `invalid_scope`, `invalid_target` and `temporarily_unavailable`. Submitted code/secret material is absent from errors.

Revocation tests preserve wrong/unknown advisory hints and externally idempotent empty 200 output. Introspection requires resource-owned Basic and proves exact inactive output plus active access-token metadata. Discovery deep-equals the frozen issuer-preserving example, advertises no Google/P1 member, uses the bounded 300-second cache policy and exposes no HEAD sibling. Repeated requests prove code and refresh buckets are separate and rate failure is sanitized.

The Step 3E hardening regression uses a fresh application and 241 valid revocation requests with distinct raw token values. It proves the first 240 requests reach the service, so no dedicated 60-per-key revocation bucket collides, while the inherited parent/global rejection becomes exact HTTP 503 `{ "error": "temporarily_unavailable" }` with `Cache-Control: no-store`. A separate info-level capture exercises failing code, refresh and revocation requests and proves raw authorization code, PKCE verifier, Basic secret, access token and refresh token are absent from HTTP errors, automatic logs and HTTP-boundary audit observations. Static guards retain all three POST `logLevel: "silent"` settings and the parent Authorization/body redaction paths; Step 3D service tests retain sanitized lifecycle-audit evidence.

`tests/oauth-darkness.test.ts` remains the route boundary source: false/absent deep-compares to the frozen legacy builder and keeps every OAuth route 404; true adds exactly the four Step 3E routes to the existing Step 3B/3C surface. Config tests require all three OAuth-only inputs only in true mode. The OAuth contract validator uses a duplicate-key-rejecting YAML loader and reconciled dark-runtime state without altering frozen protocol rules.

Initial Step 3E candidate result: TypeScript lint/build passed; Vitest passed 298 tests across 17 files; Python passed 61 with two expected skips (63 collected); all 24 OAuth validator groups passed; continuity remained `VALID_BUT_NOT_READY` with both gates false; non-strict platform validation passed 27 checks with seven known warnings; migration/frozen-boundary and `git diff --check` passed.

Final Step 3E hardening result: TypeScript lint/build passed; Vitest passed 300 tests across 17 files; Python passed 61 with two expected skips (63 collected); all 24 OAuth validator groups passed; continuity remained `VALID_BUT_NOT_READY` with both gates false; non-strict platform validation passed 27 checks with seven known warnings; migration/frozen-boundary and `git diff --check` passed. Migration 005 remains byte-identical with SHA-256 `aaffcb469000f62e680b5d391360fdacc4414e4280ba230e90e7fd4eee4dafbe`, and no migration 006 exists. No live PostgreSQL, real concurrency or production operation is claimed.

## Step 3D dark token-lifecycle-core conformance

`tests/oauth-token-lifecycle.test.ts` verifies migration 005 creates exactly the four approved OAuth tables, contains no destructive/legacy data SQL and retains the frozen hashes for migrations 001–004. It checks the exact 28,800-second idle constraints, SHA-256 hash form, generation/same-family parent lineage, one-current-member partial index, replay state and access-jti expiry.

Service tests use synthetic local RSA and OAuth registration/state only. Coverage includes salted OAuth-only credential verification, OAuth/tool pepper inequality, confidential and public-`none` clients without legacy fallback, immediate code hashing, exact client/resource/redirect/PKCE, code/authorization scope equality, current user/authorization/grant/mapping/permission re-check, single/concurrent code consumption, sanitized separately committed denial audits and fail-closed audit-write failure, exact RFC 9068 header/claims/900-second TTL/unique jti/sid/PII exclusion, hash-only refresh issuance, rotation lineage, persisted generation/current/ceiling/authorization corruption denial, monotonic scope narrowing, exact idle slide, expired/revoked/current-entitlement denial, concurrent replay family/session revocation, disabled-resource revocation durability, access/refresh/unknown revocation behavior and exact-audience/inactive introspection normalization.

Key-boundary tests cover zero/ambiguous/non-active signing selection, relative and unsupported references, encoded traversal, outside-root paths, symlink realpath escape where supported by the host, non-regular/empty/oversized files, copied/renamed and inline legacy-key public-identity rejection, public/private mismatch and fingerprint mismatch. Verification tests cover overlap-key acceptance before and rejection at/after `retire_after`, finite integer times, future-`iat` denial and exact TTL. Errors expose no key material or path.

Final-hardening regressions require wrong RFC 7009 access/refresh hints to fall through to the other supported token class, unknown revocation hints to retain successful non-disclosing semantics, and wrong/unknown RFC 7662 hints to be schema-accepted and ignored without allowing refresh-token active disclosure. Access-jti tests exercise revocation before expiry, revocation initiated at `exp + 30 seconds`, inactivity at `exp + 30` and `exp + 59`, and no resurrection at/after the `exp + 60` verifier boundary. Repository tests require monotonic `last_signed_at` SQL and projected backwards-clock behavior.

Static repository tests require mixed lock clauses that UPDATE-lock only code or token/family/session and SHARE-lock related read-only rows, plus compare-and-set consumption and OAuth-only writes. A real disposable PostgreSQL 16 same-refresh race remains an explicit release assumption whenever Docker/PostgreSQL is unavailable; the serialized in-memory race is not presented as PostgreSQL evidence.

At the Step 3D boundary, `tests/oauth-darkness.test.ts` required token/revoke/introspect/RFC 8414 to stay 404. Step 3E supersedes that historical true-flag expectation while retaining the false-flag and frozen legacy assertions. Final command results, counts and live PostgreSQL limitations are recorded in `../DEVLOG.md`.

The previous Step 3D hardening result was: TypeScript lint/build passed; Vitest passed 278 tests across 16 files; Python passed 60 with two expected skips (62 collected); the OAuth validator passed 24 check groups; continuity was `VALID_BUT_NOT_READY` with both gates false; non-strict platform validation passed 27 checks with seven known warnings; migration/frozen-legacy/dependency checks and `git diff --check` passed. Migration 005 SHA-256 is `aaffcb469000f62e680b5d391360fdacc4414e4280ba230e90e7fd4eee4dafbe`.

Final Step 3D semantic-hardening result: TypeScript lint/build passed; Vitest passed 283 tests across 16 files, including 28 token-lifecycle tests; Python passed 60 with two expected skips (62 collected); the OAuth validator passed 24 check groups; continuity was schema-valid `VALID_BUT_NOT_READY` with both gates false; non-strict platform validation passed 27 checks with seven known warnings; and migration/frozen-file checks plus `git diff --check` passed. Migration 005 remains byte-unchanged at SHA-256 `aaffcb469000f62e680b5d391360fdacc4414e4280ba230e90e7fd4eee4dafbe` and no migration 006 exists. The Docker API was unreachable, `psql` was absent and local port 5432 was closed, so no disposable-PG apply or real same-refresh race is claimed; the existing `../BACKLOG.md` release assumption remains open and production was not contacted.

## Step 3C dark authorization-code issuance conformance

`tests/oauth-authorization.test.ts` verifies migration 004 creates exactly the three approved tables with no destructive SQL or legacy data writes; fixes transaction/code TTLs at 600/60 seconds; and keeps downstream state protected, Google state/nonce hash-only and code material SHA-256-only at rest. AEAD tests cover exact round trip, unique 96-bit IVs, malformed envelopes, tag tamper and transaction/AAD swaps with a synthetic non-secret key.

Authorization tests cover singleton parameters, client-before-redirect trust, no redirect to untrusted URIs, active client/resource checks, canonical non-duplicate scopes, exact allowances, PKCE S256, exact state/issuer error responses, atomic callback claim, replay/expiry, nonce mismatch, disabled users, pending-grant linking, current grant/permission checks, registration revalidation, 32-byte code entropy, exact 60-second code TTL and audit/persistence secrecy. Lifecycle tests require a protected object only for pending/claimed rows, require null for every terminal row, prove success/denial purge, expire pending and stale claimed rows, repeat cleanup idempotently, reject claim/issuance after cleanup and retain exact state in the immediate redirect. Repository-shape tests require the bounded lock-safe cleanup and atomic nulling compare-and-set. The Google test adapter asserts exchange occurs with no database transaction open. Static boundaries reject any flow-repository legacy write and any legacy grant/access-request/session/code creation.

`tests/oauth-darkness.test.ts` continues to deep-compare false/omitted composition with the frozen legacy builder. Under true, only the two Step 3B GETs and two Step 3C GETs are reachable; all four HEAD forms plus RFC 8414, token, revoke and introspect remain 404, and legacy JWKS stays unchanged. Route-level automatic logging for authorize/callback is configured silent.

Original Step 3C candidate result: TypeScript lint/build passed; Vitest passed 249 tests across 15 files; the repository Python suite reported 60 passed, 2 skipped (62 collected); the OAuth validator passed 24 check groups; continuity remained `VALID_BUT_NOT_READY` with both gates false; the non-strict platform checker passed 27 checks with seven known warnings; and the frozen legacy/dependency/migration audit plus `git diff --check` passed. Candidate migration 004 SHA-256 was `96c37fe2a043a1aae6f813ca36db36cb1aa7ce67f2abfbff42c4883e35f72772`.

Final protected-state lifecycle hardening result: TypeScript lint/build passed; Vitest passed 253 tests across 15 files; the repository Python suite reported 60 passed, 2 skipped (62 collected); all 24 OAuth validator groups passed; continuity remained `VALID_BUT_NOT_READY` with both gates false; non-strict platform validation passed 27 checks with seven known warnings; and migration-shape, frozen legacy/dependency/migrations 001–003 plus `git diff --check` passed. Hardened migration 004 SHA-256 is `407b0fe9b3c9e053e22fac7e9640e0b4d02fe341ea6b3e7f05bb32eeaa8efede`. No background job or Step 3D token behavior is part of this verification.

Live PostgreSQL application was unavailable: Docker could not reach its API, `psql` was absent and `127.0.0.1:5432` was closed. The deterministic migration tests are the local evidence; no live application/previous-binary smoke result is claimed and no production database was contacted.

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
