# Step 4B disposable PostgreSQL 16 qualification report

Status: **HARDENED CANDIDATE — 3 LOCAL PASS; INDEPENDENT AUDIT REQUIRED**

- Latest qualification date: 2026-08-31
- Exact qualified commit: `d8998e1fbc1789d71a19cef78714c74c3dbfed37`
- Required ancestor: approved Step 4A `1757a40c6369be59427da6618fa8126605a51550`
- Independently audited predecessor: `2ff5d226b186afd75a79aa4010d7e656f82213e7`
- Legacy baseline: `access-layer-v1-baseline` (`6e8221ade74591c23c3f9606f7d696ea2810d873`)
- PostgreSQL runtime: `16.15 (Debian 16.15-1.pgdg13+2)`

This was a local qualification only. It contacted no production, Coolify, external database, real Google endpoint, real client/resource/user or consumer. All database names, credentials and RSA material were synthetic and disposable. OAuth remains default-off. No raw code, token, token hash, cookie, secret, private-key material or private path is recorded here.

## Root-cause evidence collected before the fix

The harness diagnostics were committed separately as exact clean commit `59cc07957dee6f1f9d576ef1823cd9e59b28bee0`, then run before changing runtime behavior. The first qualification reproduced the intermittent failure:

- response summaries: one HTTP 200 with no OAuth error; one HTTP 503 `temporarily_unavailable`;
- PostgreSQL: SQLSTATE `23514`, constraint `oauth_refresh_tokens_revoked_order`, sanitized query-tag `revoke_current_refresh_token`;
- post-rollback state: family active, session active, no replay marker, generations `[0,1]`, statuses `consumed,current`, coherent immediate parent and no persisted invalid revocation ordering;
- timeout/deadlock: none;
- cleanup: zero Step 4B containers.

This confirms the audited hypothesis. `refresh()` observed time before waiting on the row/family/session lock. A later-timestamp request could win, consume generation 0 and issue generation 1; the older observation then attempted to revoke generation 1 before its `issued_at`, violating the unchanged check constraint. PostgreSQL correctly rolled the replay transaction back and the HTTP boundary correctly returned 503 rather than masking the database failure as `invalid_grant`.

## Hardened behavior

- The consumed-token replay path obtains a new clock observation after the existing PostgreSQL lock wait.
- The repository derives one revocation time as the greater of that observation and the maximum `issued_at` in the locked family.
- Family, linked session, current refresh token, both durable revocations and replay audit remain in one transaction. The service returns `invalid_grant` only after that transaction commits.
- Constraints, lock serialization, atomic replay behavior, TTLs, scopes, audience, entitlement, signing and error contracts are unchanged. Database failures are not converted to `invalid_grant`.
- Backup export still establishes `REPEATABLE READ, READ ONLY` before the first read and keeps all seven legacy plus 17 OAuth queries on one transaction client. The 24 reads are now sequential, eliminating the `pg` concurrent-query deprecation warning while retaining coordinated anti-torn-snapshot evidence.
- Failure evidence is restricted to HTTP status/OAuth code, sanitized SQLSTATE/constraint/query-tag and non-identifying family/session/lineage state. Timeout, deadlock, rate-limit, constraint, other database and HTTP 5xx outcomes are explicitly classified.

## Exact-commit, migration and cleanup evidence

The runner rejected tracked or untracked changes, resolved `HEAD`, passed it through `STEP4B_EXPECTED_COMMIT`, and the harness required exact equality plus Step 4A ancestry. All final runs qualified exactly `d8998e1fbc1789d71a19cef78714c74c3dbfed37`.

Each run created a new source and restore container with distinct synthetic databases and random loopback-only ports. Both databases applied exactly these migrations:

| Migration | SHA-256 |
|---|---|
| `001_initial.sql` | `62b7ec1d729feb091f5df01bd5ea636614a9c3b60c98a990413e1ba3212c015d` |
| `002_audit_tool_delete_fk.sql` | `ab33b34abb01fa606eeafc9eab3d7dcfdafbc9429bd67bee6a64c35851638b22` |
| `003_oauth_dark_foundation.sql` | `96b3993fcfdb930597cbdeca37e86d51df486fd9e951970d156a21c454f18efe` |
| `004_oauth_authorization_code_flow.sql` | `407b0fe9b3c9e053e22fac7e9640e0b4d02fe341ea6b3e7f05bb32eeaa8efede` |
| `005_oauth_token_lifecycle.sql` | `aaffcb469000f62e680b5d391360fdacc4414e4280ba230e90e7fd4eee4dafbe` |

Migrations 001–005 were not edited and migration 006 does not exist. Cleanup was queried before runs 2 and 3 and after run 3; every check found zero Step 4B containers.

## Three consecutive complete qualifications

| Assertion | Run 1 | Run 2 | Run 3 |
|---|---:|---:|---:|
| Exact clean commit and Step 4A ancestry | PASS | PASS | PASS |
| Two isolated PostgreSQL 16.15 targets; exactly migrations 001–005 | PASS | PASS | PASS |
| Synthetic registration, entitlement and dedicated RS256 key preflight | PASS | PASS | PASS |
| HTTP authorize and fake-only Google callback | PASS | PASS | PASS |
| Authorization-code exchange | PASS | PASS | PASS |
| Claims, 900-second TTL, OAuth JWKS and resource introspection | PASS | PASS | PASS |
| Normal refresh, revocation and inactive introspection | PASS | PASS | PASS |
| Eight same-refresh races per run | PASS | PASS | PASS |
| Each race: one 200 and one 400 `invalid_grant`; zero 429/5xx/DB error | PASS | PASS | PASS |
| Each race: family/session revoked, replay marker present | PASS | PASS | PASS |
| Each race: gen0 consumed, gen1 revoked, coherent parent | PASS | PASS | PASS |
| Each race: winner access token inactive online | PASS | PASS | PASS |
| Coordinated repeatable-read non-torn snapshot | PASS | PASS | PASS |
| Encrypted backup and `replace_existing=true` restore | PASS | PASS | PASS |
| Pre-backup access token valid/introspectable after restore | PASS | PASS | PASS |
| Pre-backup refresh rotates once after restore | PASS | PASS | PASS |
| Legacy runtime build/start, `/health`, JWKS and `/v1/auth/start` | PASS | PASS | PASS |
| No `pg` deprecation warning | PASS | PASS | PASS |
| Cleanup | PASS | PASS | PASS |

The three runs exercised 24 same-refresh races in total. There were zero timeouts, deadlocks, rate-limit responses, HTTP 5xx outcomes or database errors. Backup row counts were consistent at seven legacy plus exactly 17 OAuth sections; per-run fingerprints differ by intentionally generated timestamps/identifiers and no raw secret/token material was evidence.

## Repository validation

- `npm run lint`: PASS.
- `npm run build`: PASS.
- Full Vitest: PASS, 317 tests across 18 files.
- Python unittest discovery: PASS, 61 passed and two expected skips (63 collected).
- OAuth P0 validator: PASS, 24 check groups.
- Production continuity validator: expected `VALID_BUT_NOT_READY`, both readiness gates false, exit 2.
- Non-strict platform checker: PASS, 27 checks and seven known warnings.
- Migration/frozen-boundary checks and `git diff --check`: PASS.

## Preserved audit history

### Independent audit of `2ff5d226b186afd75a79aa4010d7e656f82213e7`

Five clean-worktree qualifications ran on the same exact commit: four FAIL and one complete PASS. Every FAIL produced exactly one HTTP 200, but the loser was not HTTP 400 `invalid_grant`; none timed out or deadlocked. The one complete PASS covered the full OAuth, snapshot, encrypted restore, post-restore and legacy-smoke chain, but emitted `pg`'s warning about calling `client.query()` while that client was already executing a query. The variable 4/1 result established the intermittent blocker and remains FAIL evidence; it is not rewritten by the hardened local passes.

### Local alias-hardened run `ac3a4c54f4f865d0193f254b9a525f5b06e6b28d`

The reserved-alias fix passed code exchange and non-concurrent lifecycle assertions, then stopped because the concurrent loser was not the required 400 `invalid_grant`. Its older harness had not yet queried replay state after the response assertion. Snapshot, restore and legacy smoke were not claimed for that run; cleanup passed.

### Initial PostgreSQL failure on approved Step 4A

The 2026-08-30 run on `1757a40c6369be59427da6618fa8126605a51550` applied migrations 001–005 and passed signing preflight plus authorize/callback, then code exchange failed closed as HTTP 503. PostgreSQL reported SQLSTATE `42601`, parser position 661, in `lockAuthorizationCodeByHash()` because `authorization` was an unquoted alias. Later hardening renamed it in all three affected queries; this historical failure remains preserved.

## Disposition

The hardened candidate has complete, repeated local evidence, but Step 4B is not frozen or approved. A new independent positive audit is required before creating `step-4b-completed`. This report authorizes no OAuth enablement, production/Coolify action, deployment, Step 5 or rollout.
