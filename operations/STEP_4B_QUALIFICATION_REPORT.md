# Step 4B disposable PostgreSQL 16 qualification report

Status: **FAIL — BLOCKED_IMPLEMENTATION**

- Latest attempt: 2026-08-31
- Qualified commit: `ac3a4c54f4f865d0193f254b9a525f5b06e6b28d`
- Required ancestor: approved Step 4A `1757a40c6369be59427da6618fa8126605a51550`
- Legacy baseline ref: `access-layer-v1-baseline` (`6e8221ade74591c23c3f9606f7d696ea2810d873`)
- PostgreSQL runtime: two distinct local `postgres:16` containers; the harness verified both servers were PostgreSQL major 16 and the same version.

This was a local qualification only. It contacted no production, Coolify, external database, real client/resource/user, Google endpoint or consumer. All database names, credentials and RSA material were synthetic and disposable. No raw code, token, cookie, secret, private-key material or private path is recorded here.

## Exact-commit and cleanup evidence

- The runner rejected any tracked or untracked worktree change before invoking the harness.
- The runner resolved the exact 40-character `HEAD`, passed it through `STEP4B_EXPECTED_COMMIT`, and the harness required exact equality, Step 4A ancestry and a commit different from the failed Step 4A baseline.
- The attempted runtime was exactly `ac3a4c54f4f865d0193f254b9a525f5b06e6b28d`.
- Two distinct synthetic source/restore containers used random loopback-only ports and different Step4B database names.
- The runner's `finally` cleanup completed. A post-run Docker label query returned no remaining Step 4B container.

## Migration evidence

Both databases applied exactly migrations 001–005 before the failing concurrency assertion.

| Migration | SHA-256 | Result |
|---|---|---|
| `001_initial.sql` | `62b7ec1d729feb091f5df01bd5ea636614a9c3b60c98a990413e1ba3212c015d` | PASS |
| `002_audit_tool_delete_fk.sql` | `ab33b34abb01fa606eeafc9eab3d7dcfdafbc9429bd67bee6a64c35851638b22` | PASS |
| `003_oauth_dark_foundation.sql` | `96b3993fcfdb930597cbdeca37e86d51df486fd9e951970d156a21c454f18efe` | PASS |
| `004_oauth_authorization_code_flow.sql` | `407b0fe9b3c9e053e22fac7e9640e0b4d02fe341ea6b3e7f05bb32eeaa8efede` | PASS |
| `005_oauth_token_lifecycle.sql` | `aaffcb469000f62e680b5d391360fdacc4414e4280ba230e90e7fd4eee4dafbe` | PASS |

No migration 006 was created, and migrations 001–005 were not edited.

## Latest assertion evidence

| Assertion | Result | Sanitized evidence |
|---|---|---|
| Exact clean hardened commit | PASS | Runner and harness agreed on full commit `ac3a4c54f4f865d0193f254b9a525f5b06e6b28d`; Step 4A ancestry passed. |
| Two isolated real PG16 targets and migration application | PASS | Both targets reached readiness and applied exactly 001–005. |
| Synthetic OAuth registration, legacy entitlement and dedicated generated signing key | PASS | Seed transaction and dedicated RS256 signing/load preflight succeeded. |
| HTTP authorize and fake-only Google callback | PASS | Real application produced the upstream redirect, accepted the callback and produced the exact trusted downstream redirect. |
| HTTP authorization-code token exchange | PASS | The former PostgreSQL `42601` alias blocker did not recur. |
| Claims, 900-second TTL, dedicated OAuth JWKS and resource-owned introspection | PASS | The harness reached and passed all assertions before normal refresh. |
| Normal refresh, revocation and inactive introspection | PASS | One normal rotation succeeded; revocation made its access token inactive and the revoked refresh unusable. |
| Same-refresh concurrency: exactly one success | PASS | Both requests completed before the 20-second timeout and exactly one response was HTTP 200. |
| Same-refresh concurrency: exactly one `invalid_grant` loser | **FAIL** | The second response did not match the required HTTP 400 `invalid_grant`. The current fail-fast evidence intentionally does not include credential material or an unreviewed response body. |
| Family/session replay revocation and lineage | NOT RUN | The harness stopped at the loser-response assertion before querying replay state. |
| Coordinated repeatable-read encrypted export | NOT RUN | Dependent on the concurrency section completing. |
| Encrypted `replace_existing=true` restore and continuity | NOT RUN | No qualifying source snapshot was produced. |
| Legacy-baseline health/JWKS/auth-start smoke | NOT RUN | The fail-fast harness stopped before this final section. The JWKS assertions are implemented but not claimed as executed evidence. |

No backup row counts or content fingerprint were produced; no backup/restore PASS is claimed. The absence of a timeout is not a substitute for the unexecuted database replay-state assertions.

## Repository validation after the latest attempt

- `npm run lint`: PASS.
- `npm run build`: PASS.
- Full Vitest: PASS, 316 tests across 18 files.
- Python unittest discovery: PASS, 61 passed and two expected pristine-template skips (63 collected).
- OAuth P0 validator: PASS, 24 check groups.
- Production continuity validator: expected `VALID_BUT_NOT_READY`, zero validation errors and both readiness gates false (exit 2).
- Non-strict platform checker: PASS, 27 checks and seven known warnings.
- The local ignored `.platform-deps` cache was moved beneath excluded `.venv` only while the Python/platform scan ran and was restored in `finally`.

## Disposition after the latest attempt

The approved SQL-alias hardening is effective on real PostgreSQL, but Step 4B is still blocked by the real same-refresh loser outcome. The failed assertion was not bypassed and the qualification was not rerun after failure. Diagnose and separately approve the loser-path correction, then qualify a new exact clean commit from zero.

Step 4B is not complete. This report is not production N→N+1 evidence and authorizes no completion branch, Step 5, deployment or rollout.

## Preserved historical failure — 2026-08-30

The first independent run qualified approved Step 4A commit `1757a40c6369be59427da6618fa8126605a51550` on two PostgreSQL 16.15 targets (`postgres:16`, Debian package `16.15-1.pgdg13+2`). Both databases applied the same frozen migrations 001–005, signing preflight and real HTTP authorize/callback passed, and cleanup removed both containers.

Authorization-code exchange then failed closed as HTTP 503 `temporarily_unavailable`. PostgreSQL reported SQLSTATE `42601`, parser position 661, in `OAuthTokenRepository.lockAuthorizationCodeByHash()`; the parser position mapped to the unquoted reserved `authorization.status` alias. Claims/JWKS/introspection, refresh/revocation, concurrency, snapshot/restore and legacy-baseline smoke were not run in that attempt.

That run's repository checks passed: lint, build, 315 Vitest tests across 18 files, 61 Python tests with two expected skips, all 24 OAuth validator groups, expected continuity `VALID_BUT_NOT_READY`, non-strict platform validation with 27 passes/seven known warnings, migration/frozen-boundary checks and `git diff --check`. Runtime code was not patched or bypassed during the failed audit.

The hardened commit renamed the alias consistently in `lockAuthorizationCodeByHash()`, `lockRefreshByHash()` and `isAccessTokenActiveOnline()` and added a static anti-regression. The 2026-08-31 real-PG code-exchange PASS closes only that historical SQL blocker; it does not convert either overall Step 4B attempt into a pass.
