# Production continuity evidence collection

## Purpose and boundary

This runbook prepares evidence required before an isolated restore exercise or any vNext runtime, deployment, database, or authentication work. Step 2 reconciled only the supplied non-secret Coolify facts. Do not deploy, restart services, alter environment variables, create or rename volumes, run migrations, restore a database, rotate secrets, or change Coolify configuration.

The committed `production-continuity.evidence.yml` is an incomplete, redacted schema-v2 record with status `NOT_READY`. It contains the non-secret live topology and named-volume observations supplied on 2026-08-25; every other repository expectation remains distinct from an observation.

When live collection is separately authorised, first create the ignored working copy:

```powershell
Copy-Item operations/production-continuity.evidence.yml operations/production-continuity.local.yml
```

Do not commit screenshots, environment dumps, tokens, secret values, reusable secret verifiers, connection strings, private keys, personal data, or unredacted Coolify exports. Store sensitive operator proof outside Git and record only its stable access-controlled reference.

## Coolify UI checklist

An authorised operator must observe and record each item separately:

- server, project, environment, resource, and destination identifiers/names;
- resource type and auto-deploy setting;
- live/current configured domain and the screen from which it was read;
- intended target domain, kept separate even if it equals the current domain;
- deployed Git revision and immutable image digest when observable;
- last deployment time, replica count, and deployment strategy;
- app and PostgreSQL service names, target container ports, proxy exposure, and absence of public host-port publication;
- owner team, technical owner, product owner, and continuity operator;
- central deployment-registry record identifier and evidence reference.

Do not mark a field verified merely because it matches `docker-compose.yaml` or a platform manifest. Those files describe repository intent, not the live resource.

## Persistent PostgreSQL storage — proven mapping and remaining protection

Supplied Coolify evidence proves that the PostgreSQL service and top-level source use logical volume `access_layer_postgres_data_v2`, resolving live to `u3cyw3y1obp88to9la0w8c75_access-layer-postgres-data-v2`. The source declaration has been reconciled without an explicit physical `name:`. Preserve both identities exactly.

In the Coolify resource UI, inspect the PostgreSQL service's persistent storage configuration and record the storage type, exact live source/volume identifier, container target `/var/lib/postgresql/data`, any explicitly shown destination/host path, evidence location, observation time, and operator.

If authorised host terminal access exists, identify the exact PostgreSQL container first, then use only narrow, read-only output:

```sh
docker ps --filter label=com.docker.compose.service=postgres --format '{{.ID}} {{.Names}} {{.Image}} {{.Ports}}'
docker inspect --format '{{json .Mounts}}' <exact-postgres-container-id>
docker volume inspect <exact-observed-volume-name>
```

Never run a broad `docker inspect` export: it can expose environment values. Never infer a future live volume name from Compose or use inspection to justify renaming the proven volume. Stop if more than one candidate container or volume exists.

## JWT signing-key source and persistence

The application accepts an inline `JWT_PRIVATE_KEY_PEM` or a `JWT_PRIVATE_KEY_PEM_PATH`. When the file path is configured and the file is absent, `docker/entrypoint.sh` generates a new key before startup. Compose intends to mount `access_layer_jwt_secrets` at `/run/secrets`, but that declaration is not proof of the live mount.

Record whether the observed source is `inline_env` or `file_path`, the state of both alternative variables, the configured path only when it is under `/run/secrets`, and the key-file state without reading the file. For file-backed mode, separately prove the actual live `/run/secrets` mount/storage identity, target path, and persistence. A source-mode or mount change is a continuity failure until reviewed.

Use the public JWKS helper to record only the public `kid` and RFC 7638 SHA-256 public-key fingerprint. Record an external operator proof that N and the isolated environment use the same signing key. Never output or store the private PEM, a private-key digest, or another reusable private-key verifier.

If authorised host access is needed, use the narrow mount command only after selecting the exact app container:

```sh
docker ps --filter label=com.docker.compose.service=app --format '{{.ID}} {{.Names}} {{.Image}} {{.Ports}}'
docker inspect --format '{{json .Mounts}}' <exact-app-container-id>
```

## Secret continuity without secret disclosure

Presence is necessary but does not prove continuity. Before an isolated restore, an authorised operator must prove that the source and isolated target bind the same `SESSION_SECRET`, `TOOL_CLIENT_SECRET_PEPPER`, `BACKUP_ENCRYPTION_KEY`, `GOOGLE_CLIENT_SECRET`, and `LOG_IP_SALT` where applicable.

Use one approved method recorded in the evidence model:

- reference the same immutable secret-manager version from both bindings;
- perform an operator side-by-side comparison in an access-controlled console;
- record a controlled injection/change record showing the same protected source was bound to both targets;
- use another explicitly approved method documented outside Git.

For every record, capture the method, operator, time, and external evidence reference. Never store the secret, its length, a checksum/HMAC, a low-entropy hash, or any reusable equality verifier in Git. A bundle that asserts a reusable verifier or secret was committed is invalid.

## Complete configuration observation

The evidence inventory is mechanically derived from `src/config.ts`, `docker-compose.yaml`, and `docker/entrypoint.sh`. Every listed variable must be classified as `ABSENT`, `PRESENT_EMPTY`, or `PRESENT_NON_EMPTY`; `UNOBSERVED` keeps both gates closed. The runtime helper never emits secret values. An empty `PUBLIC_BASE_PATH` is a valid observed state and maps to the safe effective value `""`.

Record safe effective values for behavior-sensitive configuration, including:

- `APP_ENV`, `PUBLIC_BASE_PATH`, `APP_BASE_URL`, `AUTH_ISSUER`, `PORT`, and log level;
- public Google client ID, redirect URI, allowed hosted domains, and OIDC scopes;
- public JWT `kid`;
- access, refresh, and one-time-code TTLs; refresh enablement; session cookie name;
- CORS origins, allowed return-URL schemes, and trusted proxy hops;
- audit retention/raw-IP settings and access-request reopen period;
- startup migration/seed/example-seed flags;
- SIEM enablement and endpoint only when safely observable;
- PostgreSQL user/database names and only the non-identifying count/state of bootstrap emails.

Secret-bearing variables—including database credentials/URL, session secret, pepper, private key/paths except the allowlisted `/run/secrets` path, Google client secret, backup secrets, salt, and tokens—remain state-only. `ADMIN_BOOTSTRAP_EMAILS` is state/count-only because addresses are personal data; it is not a session-continuity prerequisite after bootstrap.

Container-local observation may not expose Compose interpolation inputs such as PostgreSQL variables. Leave them unobserved in helper output and supplement them from an authorised Coolify configuration view without copying values. Never weaken the gate to convert an unobservable fact into an inferred fact.

## Backup and restore evidence

Observe without changing the backup mechanism, schedule, retention rule, destination class (not credentials), latest verified backup identifier/time, and monitoring/alert ownership.

Step 1.5B does not execute a restore. Leave restore status `NOT_RUN` and the bundle `NOT_READY`. A later separately authorised exercise may start only when `ready_for_isolated_restore` is true. It must restore the identified backup into an isolated target, verify schema/migration/application continuity, and retain an access-controlled evidence reference. Never restore over production.

## Read-only helper commands

Do not deploy or copy these scripts into production merely to collect evidence. Run the JWKS helper from an operator checkout. Run runtime/PostgreSQL helpers only if an authorised operator already has a safe checkout with access to the relevant container environment/network. Redirect output to access-controlled storage outside the repository, review it, and transfer only allowed fields into the ignored evidence file.

Application runtime and configuration states:

```sh
node scripts/continuity/collect-runtime-metadata.mjs
```

Public JWKS key ID and fingerprint:

```sh
node scripts/continuity/fingerprint-public-jwks.mjs --jwks-url https://<live-host>/v1/.well-known/jwks.json
```

PostgreSQL schema/migration metadata using the existing connection environment, without application rows:

```sh
node scripts/continuity/collect-postgres-metadata.mjs
```

Each helper fails non-zero when required facts cannot be observed. PostgreSQL errors omit driver messages because they can include connection details. The runtime helper screens allowlisted URLs for embedded credentials and never reads key or secret contents.

## Two machine-readable gates

Validate the ignored working copy:

```powershell
python scripts/validate_production_continuity.py operations/production-continuity.local.yml --json
```

The JSON result exposes two independent gates:

- `gates.ready_for_isolated_restore` becomes true only after live topology/storage/backup/database/registry/ownership evidence, JWT persistence, secret sameness, complete configuration observation, and pre-restore approvals are proven. It authorises only a separately reviewed isolated restore exercise.
- `gates.ready_for_n_to_n_plus_1` remains false until the isolated restore is recorded `PASSED`, restore evidence and approval are present, and final N→N+1 approval is recorded.

Exit `2` with `VALID_BUT_NOT_READY` is expected for the committed template and may also occur when the intermediate gate is true but final readiness is false. Exit `1` means invalid or unsafe evidence. Exit `0` requires a schema-valid bundle explicitly declared `READY` with final N→N+1 readiness true.

The validator never edits platform manifests, Coolify, or production. Promotion of reviewed redacted evidence into the committed bundle requires a separate explicit decision and review.
