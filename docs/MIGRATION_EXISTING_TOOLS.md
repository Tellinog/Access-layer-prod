# Migration Guide for Existing Tools

## Principle

Adoption is modular. A project does not need to replace its web login to gain a capability manifest, telemetry, OpenAPI or MCP exposure.

## Phase 0 — Inventory and freeze

Document:

- current Access Layer endpoints and configured base paths;
- callback URLs;
- legacy JWT issuer/audience/claims;
- required permissions;
- local cookie and session behavior;
- refresh coordination and replica constraints;
- introspection policy;
- active fallback/demo modes;
- current health, logging and AI data flows;
- current Coolify server, project, environment, resource, build strategy and deployment source;
- communicated domains and route paths;
- every service, internal container port and direct host-port mapping;
- private/shared network dependencies;
- persistent volumes, databases, backup/restore and rollback behavior.

Create golden tests before refactoring.

## Phase 1 — Repository and capability contract

Add this template’s files without changing runtime behavior. Record the current deployment in `project.platform.yaml` and `deployment.registration.yaml` before editing Coolify. Map existing permissions to canonical capability IDs. Existing colon-separated permissions may be retained directly. Submit the non-secret deployment entry to the central registry before the first production release governed by this template.

## Phase 2 — RequestContext

Wrap current auth middleware in a `LegacyAuthAdapter`. Domain handlers accept only `RequestContext`. Preserve the old cookie, token and session records.

## Phase 3 — Observability

Add:

- `/health/live` and `/health/ready`;
- correlation and W3C trace propagation;
- low-cardinality request/capability metrics;
- asynchronous product events;
- synthetic check registration.

Do not put telemetry in the business transaction’s required synchronous path.

## Phase 4 — Canonical API

Expose only stable, bounded application services. Use OAuth-ready security declarations in OpenAPI even if a temporary legacy-compatible gateway is used in staging. Do not expose raw database, shell, filesystem or arbitrary query operations.

## Phase 5 — OAuth dual mode

When Access Layer vNext is available:

- register the project API as a resource;
- register one canary client;
- enable the OAuth adapter for that resource/client only;
- validate audience, scope, subject, actor, introspection and audit;
- keep web legacy auth untouched;
- compare outcomes between legacy and OAuth paths.

## Phase 6 — Agent Gateway

Map approved capabilities to tools/resources/prompts. Start read-only or low-risk. Mutations require idempotency and confirmation policy.

## Phase 7 — Optional web OIDC migration

Treat web OIDC as a separate project. Preserve active legacy sessions or provide a controlled coexistence window. Do not combine it with schema, signing-key, callback and business-feature changes.

## Completion criteria

The project deployment contract is considered adopted only when the actual Coolify resource, local registration and central registry match and route/storage/rollback smoke evidence exists.

Legacy retirement is permitted only when:

- every intended consumer has migrated;
- legacy usage is measured at zero for the approved period;
- active legacy sessions have expired or been safely transitioned;
- rollback no longer depends on legacy records;
- security, product and operations owners approve the contract phase.
