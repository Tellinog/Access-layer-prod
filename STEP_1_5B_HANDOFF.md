# Step 1.5B handoff — continuity evidence hardening

Date: 2026-08-25

## Outcome

Step 1.5B is complete as repository-only evidence hardening. The committed production evidence remains redacted, schema-valid, `NOT_READY`, and contains no invented live facts. Runtime behavior, endpoints, JWT/session/refresh/grant contracts, database/migrations, Docker/Compose, production configuration, platform manifests, line-ending policy, deployed state, and secrets are unchanged. OAuth/OIDC, live evidence collection, restore execution, deployment, Step 1.6, and N→N+1 execution were not started.

The focused Step 1.5B commit is the commit containing this handoff; use `git log -1 --format="%H %s"` for its immutable hash.

## Hardened evidence model

- `operations/production-continuity.evidence.yml` and its JSON Schema are version 2. The committed template remains `NOT_READY` with observations unfilled.
- The configuration inventory contains all 41 environment/configuration names mechanically derived from `src/config.ts`, `docker-compose.yaml`, and `docker/entrypoint.sh`.
- Every variable uses `UNOBSERVED`, `ABSENT`, `PRESENT_EMPTY`, or `PRESENT_NON_EMPTY`; an empty `PUBLIC_BASE_PATH` remains valid.
- Safe effective values cover environment/base path/origins, public Google and JWT identity, TTLs, refresh/cookie settings, CORS/return schemes/proxy trust, audit settings, startup migration/seed flags, SIEM state, PostgreSQL names, and a non-identifying bootstrap-email count.
- JWT evidence distinguishes inline and file-backed signing. File-backed readiness requires observation of the actual persistent `/run/secrets` mount/storage plus public `kid`/fingerprint and external same-key proof. Helpers never read the key.
- `SESSION_SECRET`, `TOOL_CLIENT_SECRET_PEPPER`, `BACKUP_ENCRYPTION_KEY`, `GOOGLE_CLIENT_SECRET`, and `LOG_IP_SALT` require same-value verification through an access-controlled external evidence reference. Secret values, private keys, low-entropy hashes, HMACs, and reusable equality verifiers are forbidden in Git.
- The validator reports independent `ready_for_isolated_restore` and `ready_for_n_to_n_plus_1` gates. Final readiness still requires a real `PASSED` isolated restore.

## Current gate result

The committed bundle returns exit `2`, result `VALID_BUT_NOT_READY`, and zero validation errors.

- `ready_for_isolated_restore=false`: 191 exact missing paths, grouped as approvals 7, backup 7, capture identity 2, configuration 99, Coolify 7, database 7, deployment registry 3, domains 2, JWT signing material 9, ownership 4, runtime/topology 12, secret continuity 25, PostgreSQL storage 7.
- `ready_for_n_to_n_plus_1=false`: 199 exact missing paths. In addition to every pre-restore path, the eight final-only paths are `approvals.ready_for_n_to_n_plus_1=true`, `approvals.restore_test_verified=true`, `backup.restore_test.completed_at`, `backup.restore_test.evidence_reference`, `backup.restore_test.isolated_target=true`, `backup.restore_test.status=PASSED`, `backup.restore_test.target_identifier`, and `backup.restore_test.verified_by`.

The validator JSON arrays are the authoritative path-level list; counts must be regenerated after any local evidence edit.

## Remaining operator inputs

- capture time/operator and exact Coolify server, project, environment, resource, destination, resource type, and auto-deploy state;
- live/current origin and its observation source, separate from intended target origin;
- deployed revision/image, replica count, strategy, deploy time, app/PostgreSQL services, target ports, exposure, and no-public-host-port proof;
- actual PostgreSQL storage type/identity/mapping and actual file-backed JWT `/run/secrets` storage/mount identity when that signing mode is observed;
- backup mechanism, schedule, retention, destination class, latest verified backup, and evidence reference;
- database version/name/schema fingerprint/migration metadata without rows;
- all 41 environment states and every allowlisted safe effective configuration field;
- JWT source mode, public JWKS source/`kid`/fingerprint, and external same-key verification;
- external secret-sameness records for all five continuity secrets, without values or reusable verifiers;
- registry record, owner team, technical/product owners, continuity operator, and pre-restore approvals;
- later, under separate authorisation, a `PASSED` isolated restore and final approvals; two real immutable N/N+1 artifacts remain required before the upgrade harness.

The PostgreSQL Compose mismatch remains a deployment `BLOCKER`: service mount `access_layer_postgres_data_v2` versus top-level declaration `access_layer_postgres_data`. Neither value was changed.

## Verification

- `npm.cmd run lint`: passed.
- `npm.cmd run build`: passed.
- `npm.cmd test`: passed, 12 files and 113 tests.
- Python conformance: passed, 45 tests with two pristine-template bootstrap tests skipped.
- Continuity validator: `VALID_BUT_NOT_READY`, exit `2`, zero errors; intermediate gate false (191 paths), final gate false (199 paths).
- Non-strict `scripts/platform_check.py --json`: passed, 24 checks and eight expected legacy/unresolved warnings.
- Strict `scripts/platform_check.py --strict --json`: expected exit `1`, 23 checks passed, four legacy warnings, and exactly six unresolved errors:

  1. `Coolify deployment configuration_status is not ready`
  2. `Required backup schedule, retention or restore-test policy is unresolved`
  3. `Production deployment must be registered in the central deployment registry`
  4. `Central deployment registry was not supplied; pass --registry or PLATFORM_DEPLOYMENT_REGISTRY_PATH`
  5. `Named project ownership is unresolved: owner_team, technical_owner, product_owner`
  6. `Continuity blocker: Compose PostgreSQL volume reference and declaration do not match`

The helper-invariance test confirms unchanged LF-normalized SHA-256 values for `src/config.ts`, `docker-compose.yaml`, and `docker/entrypoint.sh` relative to Step 1.5.

## Human commands next

Do not run these until live evidence collection is separately authorised. Then work only in the ignored local copy and follow `operations/PRODUCTION_CONTINUITY_COLLECTION.md`:

```powershell
Copy-Item operations/production-continuity.evidence.yml operations/production-continuity.local.yml
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-platform.txt
.\.venv\Scripts\python.exe scripts/validate_production_continuity.py operations/production-continuity.local.yml --json
```

Run read-only helpers only from an authorised operator checkout/context and store their raw output outside Git:

```powershell
node scripts/continuity/collect-runtime-metadata.mjs
node scripts/continuity/fingerprint-public-jwks.mjs --jwks-url https://<observed-live-host>/v1/.well-known/jwks.json
node scripts/continuity/collect-postgres-metadata.mjs
```

After obtaining the authoritative registry file, rerun strict platform validation without auto-populating manifests:

```powershell
.\.venv\Scripts\python.exe scripts/platform_check.py --strict --registry <authoritative-central-registry-path> --json
```

Stop when `ready_for_isolated_restore` becomes true and request separate approval for the isolated restore. Do not run N→N+1 until the restore is genuinely `PASSED`, the final gate is true, and immutable N/N+1 artifacts are supplied.
