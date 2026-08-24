# Platform Template v2.1 Adoption Report

## Outcome

Agent Ready Project Template v2.1.0 was adopted additively in `legacy-migration` mode on 2026-08-24. Existing documentation, decisions, history, runtime code, tests, migrations, Compose, Docker and package files were preserved. Step 1 changes records and conformance tests only; it does not change production behavior.

## Classification

- Project kind: `platform_service`
- Runtime: Node.js 22+, TypeScript, Fastify
- Deployment platform: Coolify, Docker Compose resource
- Canonical production origin: `https://access-layer.unguess-internal.net`
- Application container port: `8080`, bound by the app to `0.0.0.0`
- Database: PostgreSQL 16, private service, no public host-port mapping
- Mode: `legacy-migration`
- Current authentication profile: `access-layer-legacy-v1` only
- AI profile: `no_ai`

The authoritative project and deployment records are `project.platform.yaml` and `deployment.registration.yaml`. Current runtime behavior is frozen by `specs/legacy-contract-baseline.v1.json` and synthetic fixtures under `tests/platform-conformance/legacy/fixtures/`.

## Additive merge boundaries

Template folders and reference material were copied only where the repository had no file at the same path. Existing files were not replaced. No file under `src/` or `migrations/` changed. `docker-compose.yaml`, `Dockerfile`, `package.json`, `package-lock.json`, `schemas/openapi.yaml`, seeds and runtime environment semantics remain unchanged.

The copied OAuth, MCP, telemetry, Garden and Platform SDK material is reference/target-state documentation. It is not evidence that those capabilities are implemented. In particular:

- no OAuth/OIDC endpoint or table was added;
- MCP is disabled;
- telemetry and Tool Observatory integration are not implemented;
- the UNGUESS Platform SDK is not a dependency;
- the existing Italian admin/error UI was not translated or redesigned;
- Garden assets are target-state references only and are not wired into the runtime.

## Evidence and limitations

The accepted SDK archive matches the instruction-pack checksum and was used only as read-only future-compatibility evidence. The template archive also matches. The Access Layer production and four consumer archives supplied for this task do not match the checksums recorded in the instruction pack. They were inspected as the user-supplied evidence set, and the mismatch is recorded as an `ASSUMPTION_TO_VALIDATE`; conclusions from those archives are not represented as proof of the pack's referenced revisions.

The current runtime registers `GET /v1/admin/backup/secret-material`, but `schemas/openapi.yaml` does not document it. Step 1 freezes that observed drift rather than silently altering either runtime or historical OpenAPI.

## Adoption exceptions

The following are explicit, visible Step 1 exceptions, not completed adoption claims:

- owners and exact Coolify identifiers are unresolved;
- central deployment registry registration is pending;
- backup schedule, retention and restore-test evidence are unresolved;
- Garden and English-first conformance are deferred to avoid UI behavior change;
- OpenTelemetry, Platform SDK and Tool Observatory integration are deferred;
- stable platform capability IDs and one-to-one OAuth scopes are not approved;
- N→N+1 session/refresh survival has a documented harness but no two real versions/images were supplied, so it has not passed.

## Deployment prohibition

`docker-compose.yaml` mounts `access_layer_postgres_data_v2` while declaring `access_layer_postgres_data`. This is a continuity `BLOCKER`. Neither name was changed. No deployment may occur until the live Coolify volume mapping is identified and a verified backup/restore point exists.

## Conformance result

The non-strict platform checker passes with 24 checks and eight documented warnings. Strict release conformance intentionally fails on six release gates: deployment readiness, backup policy, central registration status, missing registry input, named ownership and the Compose volume continuity blocker. The exact messages are retained in `STEP_1_HANDOFF.md`.
