# Production continuity evidence collection

## Purpose and boundary

This runbook prepares evidence required before any vNext runtime, deployment, database, or authentication work. It is read-only in Step 1.5. Do not deploy, restart services, alter environment variables, create or rename volumes, run migrations, restore over production, or change Coolify configuration.

The committed `production-continuity.evidence.yml` is an intentionally incomplete, redacted record. Repository expectations are not observations. In particular, the intended target domain is documented, while the live/current domain remains unknown until an operator observes it.

Create an ignored working copy before entering operator evidence:

```powershell
Copy-Item operations/production-continuity.evidence.yml operations/production-continuity.local.yml
```

Do not paste screenshots, tokens, environment values, database connection strings, private keys, personal data, or unredacted Coolify exports into the repository. Record stable identifiers and references to access-controlled operator evidence only.

## Coolify UI checklist

An authorised operator must observe and record each item separately:

- server, project, environment, resource, and destination identifiers/names;
- resource type and auto-deploy setting;
- live/current configured domain and the Coolify screen from which it was read;
- intended target domain, kept separate even if it equals the current domain;
- deployed Git revision and immutable image digest when Coolify exposes them;
- last deployment time, replica count, and deployment strategy;
- app and PostgreSQL service names, target container ports, proxy exposure, and absence of public host-port publication;
- owner team, technical owner, product owner, and continuity operator;
- central deployment-registry record identifier and evidence reference.

Do not mark a field verified merely because it matches `docker-compose.yaml` or a platform manifest. Those files describe repository intent, not the live resource.

## Persistent PostgreSQL storage — mandatory manual proof

The repository currently mounts `access_layer_postgres_data_v2` in the PostgreSQL service but declares `access_layer_postgres_data` at the Compose top level. This mismatch is a continuity `BLOCKER`. Do not correct either name.

In the Coolify resource UI, inspect the PostgreSQL service’s persistent storage configuration and record:

- storage type: named volume, bind mount, managed storage, or other;
- exact live source/volume identifier;
- exact container target `/var/lib/postgresql/data`;
- destination/host path if one is explicitly shown;
- evidence location, observation time, and operator.

If authorised host terminal access exists, identify the exact PostgreSQL container first, then use only narrow, read-only output:

```sh
docker ps --filter label=com.docker.compose.service=postgres --format '{{.ID}} {{.Names}} {{.Image}} {{.Ports}}'
docker inspect --format '{{json .Mounts}}' <exact-postgres-container-id>
docker volume inspect <exact-observed-volume-name>
```

Never run a broad `docker inspect` export: it can expose environment values. Never infer the live volume name from the Compose file. Stop if more than one candidate container or volume exists.

## Backup and restore evidence

In Coolify and the backup system, observe without changing:

- backup mechanism and schedule;
- retention rule;
- destination class (for example off-host object storage), not credentials;
- latest successfully verified backup identifier and completion time;
- monitoring/alert ownership.

Step 1.5 does not execute a restore. Leave restore status `NOT_RUN` and the bundle `NOT_READY`. A later authorised exercise must restore one identified backup into an isolated target, verify schema/migration metadata and application continuity, and retain an access-controlled evidence reference. Never restore over production.

## Read-only helper commands

Do not deploy or copy these scripts into production merely to collect evidence. Run the JWKS helper from an operator checkout. Run the runtime or PostgreSQL helper only if an authorised operator already has a safe checkout with access to the relevant container environment/network; otherwise use the Coolify UI checklist and leave the fact unobserved. Redirect output to an access-controlled location outside the repository, review it, and copy only allowed fields into the local evidence file.

Application runtime and environment presence (values are never emitted):

```sh
node scripts/continuity/collect-runtime-metadata.mjs
```

Public JWKS key id and RFC 7638 SHA-256 fingerprint:

```sh
node scripts/continuity/fingerprint-public-jwks.mjs --jwks-url https://<live-host>/v1/.well-known/jwks.json
```

PostgreSQL schema and migration metadata using the existing connection environment (no application row contents):

```sh
node scripts/continuity/collect-postgres-metadata.mjs
```

Each helper fails non-zero when required facts cannot be observed. PostgreSQL errors intentionally omit driver messages because they may include connection details.

## Validation and promotion rule

Validate the ignored working copy:

```powershell
python scripts/validate_production_continuity.py operations/production-continuity.local.yml --json
```

If the Python validation dependencies are not installed in the operator environment, install the pinned checker requirements first with `python -m pip install -r requirements-platform.txt` in an isolated environment.

Exit code `2` and result `VALID_BUT_NOT_READY` are expected until all live facts, the isolated restore, registry proof, ownership, and approvals exist. Exit code `1` means invalid or unsafe evidence. Exit code `0` is possible only for a schema-valid bundle declared `READY` with every readiness condition satisfied.

The validator never edits `project.platform.yaml`, `deployment.registration.yaml`, Coolify, or production. Promotion of reviewed redacted evidence into the committed bundle requires a separate, explicit decision and review.
