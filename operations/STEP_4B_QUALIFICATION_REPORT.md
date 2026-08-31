# Step 4B disposable PostgreSQL 16 qualification report

Status: **FAIL — BLOCKED_IMPLEMENTATION**

Date: 2026-08-30  
Qualified commit: `1757a40c6369be59427da6618fa8126605a51550`  
Legacy baseline ref: `access-layer-v1-baseline` (`6e8221ade74591c23c3f9606f7d696ea2810d873`)  
PostgreSQL image/runtime: PostgreSQL `16.15` (`postgres:16`, Debian package `16.15-1.pgdg13+2`)

This was a local qualification only. It contacted no production, Coolify, external database, real client/resource/user, Google endpoint or consumer. All database names, credentials and RSA material were synthetic and disposable. No raw code, token, cookie, secret, private-key material or private path is recorded here.

## Environment and migration evidence

- Two distinct containers were created with `access-layer-step4b-source-*` and `access-layer-step4b-restore-*` names.
- Each container exposed PostgreSQL only on a random `127.0.0.1` host port and held a distinct `access_layer_step4b_*` database.
- The runner used `finally` cleanup. A post-run Docker label query returned no remaining Step 4B container.
- Both databases applied exactly migrations 001–005 before the failing OAuth assertion.

| Migration | SHA-256 | Result |
|---|---|---|
| `001_initial.sql` | `62b7ec1d729feb091f5df01bd5ea636614a9c3b60c98a990413e1ba3212c015d` | PASS |
| `002_audit_tool_delete_fk.sql` | `ab33b34abb01fa606eeafc9eab3d7dcfdafbc9429bd67bee6a64c35851638b22` | PASS |
| `003_oauth_dark_foundation.sql` | `96b3993fcfdb930597cbdeca37e86d51df486fd9e951970d156a21c454f18efe` | PASS |
| `004_oauth_authorization_code_flow.sql` | `407b0fe9b3c9e053e22fac7e9640e0b4d02fe341ea6b3e7f05bb32eeaa8efede` | PASS |
| `005_oauth_token_lifecycle.sql` | `aaffcb469000f62e680b5d391360fdacc4414e4280ba230e90e7fd4eee4dafbe` | PASS |

No migration 006 was created, and migrations 001–005 were not edited.

## Assertion evidence

| Assertion | Result | Sanitized evidence |
|---|---|---|
| Two isolated real PG16 targets and migration application | PASS | Both targets reached readiness and applied 001–005. |
| Synthetic OAuth registration, legacy entitlement and dedicated generated signing key | PASS | Seed transaction and dedicated RS256 signing/load preflight succeeded. |
| HTTP authorize and fake-only Google callback | PASS | Real application produced the upstream redirect, accepted the callback and produced the exact trusted downstream redirect. |
| HTTP authorization-code token exchange | FAIL | `/oauth/token` returned sanitized HTTP 503 `temporarily_unavailable`. The real repository recorded PostgreSQL SQLSTATE `42601`, parser position `661`, in `lockAuthorizationCodeByHash`. That position maps to the unquoted `authorization.status` alias reference in `src/oauth/token-repository.ts`. |
| Claims/JWKS/introspection/normal refresh/revocation | NOT RUN | Dependent on successful code exchange; no bypass or runtime test branch was introduced. |
| Concurrent same-refresh rotation/replay | NOT RUN | Dependent on a real issued refresh token. |
| Coordinated repeatable-read encrypted export | NOT RUN | Dependent on the controlled real refresh writer. |
| Encrypted `replace_existing=true` restore and continuity | NOT RUN | No successful source snapshot was available. |
| Legacy-baseline expanded-schema smoke | NOT RUN | The fail-fast harness stopped at the critical OAuth exchange failure. |

Backup row counts and a non-secret backup fingerprint are therefore unavailable; no backup PASS is claimed.

## Repository validation

- `npm run lint`: PASS.
- `npm run build`: PASS.
- Full Vitest: PASS, 315 tests across 18 files.
- Python unittest discovery: PASS, 61 passed and two expected skips (63 collected).
- OAuth P0 validator: PASS, 24 check groups.
- Production continuity validator: expected `VALID_BUT_NOT_READY`, both readiness gates false (exit 2).
- Non-strict platform checker: PASS, 27 checks and seven known warnings.
- `git diff --check`: PASS; only line-ending normalization notices were emitted.
- Frozen runtime/dependency check: no diff under `src/`, `migrations/`, `schemas/`, package files, Dockerfile or Compose.

## Boundary and disposition

The frozen runtime was not patched or bypassed. In particular, `src/app.ts`, `src/oauth/`, migrations, OpenAPI, packages, Docker/Compose, consumers and protocol contracts remain unchanged. The qualification runner and harness are the only implementation artifacts added.

Step 4B is not complete. The blocking row-lock SQL must be handled in a separately approved runtime-fix task, followed by a complete rerun from an approved commit. This report is not production N→N+1 evidence and authorizes no Step 5 or rollout.
