# Step 1.5 handoff — workspace hygiene and production continuity evidence

Date: 2026-08-24

## Outcome

Step 1.5 is complete as evidence preparation only. Runtime behavior, APIs, JWT/session/refresh/grant/cookie contracts, database migrations, Compose configuration, production configuration and deployed state are unchanged. OAuth/OIDC and later platform capabilities were not started.

## Part A — deterministic line endings

- Initial `git status --short --branch` showed a clean `main` worktree, ahead of `origin/main` by the accepted Step 1 commit.
- `git diff --ignore-cr-at-eol --exit-code` and the cached equivalent both returned exit `0`; no semantic pre-existing diff was present.
- `.gitattributes` now stores repository text as LF, retains CRLF for `.bat`/`.cmd`, and marks common binary assets as binary. `.editorconfig` was preserved.
- `git add --renormalize .` produced no tracked-file content changes; only `.gitattributes` was staged.
- The dedicated hygiene commit is `4bd507f` (`chore: enforce deterministic repository line endings`). The worktree was clean before Part B began.

## Part B — continuity evidence workflow

- `schemas/production-continuity-evidence.schema.json` defines the closed v1 evidence shape.
- `operations/production-continuity.evidence.yml` is a committed redacted template with status `NOT_READY`. It separates live/current and intended target domains, and observed facts from repository expectations.
- `scripts/validate_production_continuity.py` rejects unsafe/secret-bearing evidence, validates schema, evaluates readiness without inference, and never edits manifests. Exit codes are `0` ready, `2` valid-but-not-ready and `1` invalid.
- `scripts/continuity/` contains read-only helpers for allowlisted runtime facts/environment presence, public JWKS fingerprints, and PostgreSQL schema/migration metadata. No helper prints secret values, private key material, database connection details, driver messages or application rows.
- `operations/PRODUCTION_CONTINUITY_COLLECTION.md` provides the manual Coolify and narrow terminal workflow, especially for the actual persistent-volume mapping and backup facts that cannot safely be inferred from a container.

The committed bundle validates as `VALID_BUT_NOT_READY` with exit `2`. It currently reports 90 missing fact/approval paths. The validator command is the authoritative exact list; the remaining operator inputs are:

- Coolify server, project, environment, resource and destination identifiers; resource type and auto-deploy state;
- live/current domain and its observation source, kept separate from the documented target domain;
- deployed commit or immutable image digest, last deploy time, replicas and deployment strategy;
- observed app/PostgreSQL service names, ports, exposure and absence of public host-port mapping;
- exact live PostgreSQL storage type/identifier/mapping and operator verification;
- backup mechanism, schedule, retention, destination class, latest verified backup and later isolated restore proof;
- read-only PostgreSQL version/name/schema fingerprint/applied migration metadata;
- observed true/false presence results for the repository-defined continuity-sensitive environment variables (absence is recorded, not treated as a value leak);
- public JWKS observation source, `kid`, and public-key SHA-256 fingerprint;
- authoritative deployment-registry record and evidence reference;
- owner team, technical owner, product owner, continuity operator and all final approvals.

The missing-count value must be re-read from the validator after every evidence edit; readiness is never inferred from this document.

## Part C — next gate prepared, not executed

`N_TO_N_PLUS_1_SURVIVAL_PLAN.md` now requires a reviewed `READY` evidence bundle and records its hash before execution. Status remains `DOCUMENTED_NOT_RUN`. No production-like restore or version transition was run because two immutable N/N+1 artifacts and an isolated restored database were not supplied.

## Verification

- `npm.cmd run lint`: passed.
- `npm.cmd run build`: passed.
- `npm.cmd test`: passed, 12 files and 109 tests.
- Python conformance: passed, 39 tests with two pristine-template bootstrap tests skipped.
- Continuity validator: `VALID_BUT_NOT_READY`, exit `2`, no validation errors.
- Non-strict `scripts/platform_check.py`: passed with 24 checks and eight expected legacy/unresolved warnings.
- Strict `scripts/platform_check.py --strict --json`: expected exit `1`, 23 checks passed, four legacy warnings, and exactly these six unresolved errors:

  1. `Coolify deployment configuration_status is not ready`
  2. `Required backup schedule, retention or restore-test policy is unresolved`
  3. `Production deployment must be registered in the central deployment registry`
  4. `Central deployment registry was not supplied; pass --registry or PLATFORM_DEPLOYMENT_REGISTRY_PATH`
  5. `Named project ownership is unresolved: owner_team, technical_owner, product_owner`
  6. `Continuity blocker: Compose PostgreSQL volume reference and declaration do not match`

## Human commands next

From a clean checkout of this commit, an authorised operator should create an ignored copy, fill only observed/redacted facts following the runbook, and validate it:

```powershell
Copy-Item operations/production-continuity.evidence.yml operations/production-continuity.local.yml
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-platform.txt
.\.venv\Scripts\python.exe scripts/validate_production_continuity.py operations/production-continuity.local.yml --json
```

After obtaining the authoritative registry file, rerun strict platform validation without editing manifests automatically:

```powershell
.\.venv\Scripts\python.exe scripts/platform_check.py --strict --registry <authoritative-central-registry-path> --json
```

Do not deploy, rename/create volumes, restore over production, rotate secrets, or run N→N+1 as the next action. The next safe action is operator evidence collection and review.
