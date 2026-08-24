# Platform contract

## Purpose

Every project created from this template participates in the shared UNGUESS
internal platform. The contract is stronger than a documentation checklist: it
defines project type, Coolify deployment, identity, capability naming,
observability, compliance and release evidence.

## Mandatory capabilities

| Area | Mandatory default | Exception mechanism |
|---|---|---|
| Project type | Explicit `project.kind` | None |
| Runtime deployment | Coolify | `sdk_library` is non-runtime |
| Deployment unit | One Coolify resource per project | Approved architecture decision |
| Host ports | Forbidden | Security-approved, time-bounded registry entry |
| Deployment registry | Local registration plus central uniqueness | None in production |
| Identity | Access Layer | Security-approved non-user-facing exception |
| Target auth | Access Layer OAuth/OIDC (`unguess-oauth-oidc-v1`) | Temporary legacy mode |
| Existing consumers | Frozen legacy compatibility | No forced migration |
| API | OpenAPI 3.1 contract | Documented non-networked repository profile |
| MCP | Gateway-ready capability manifest | Time-bounded platform exception |
| Monitoring | Health, traces, metrics, logs and synthetic checks | None for runtime production |
| Product analytics | Versioned capability events | Privacy-approved minimisation |
| Observatory | Registration, query and export | Time-bounded onboarding exception |
| Language | `en-GB` UI and English technical contracts | Capability-specific output locale |
| AI governance | Assessment for AI and non-AI projects | None |
| UI | Garden tokens and WCAG 2.2 AA | Not applicable to non-UI repositories |

## Project categories

- **Tool** — user- or agent-facing product, independently deployed on Coolify.
- **Platform service** — central runtime API/service, independently deployed on Coolify.
- **Infrastructure stack** — operational multi-container stack on Coolify, private by default.
- **SDK library** — reusable versioned packages; no domain, port, database or Coolify runtime.

See `docs/platform/PROJECT_TYPES.md`.

## Coolify deployment contract

Every runtime project owns one local `deployment.registration.yaml` and one
entry per environment in the central Git deployment registry.

The registry enforces uniqueness for:

- registration IDs;
- Coolify resource names on the same server;
- unshared public hostnames/routes;
- approved published host ports.

Internal container ports are deliberately excluded from global uniqueness.
They may repeat across independent resources.

A Coolify resource may contain multiple containers. Only intended web/API
services receive public routes. Database, cache, worker and collector services
remain private unless an explicit approved contract says otherwise.

## Capability as the unit of interoperability

A capability is a stable, authorised and observable action or resource. The
same `capability_id` must identify:

- a permission and OAuth scope;
- an OpenAPI operation;
- an MCP tool, resource or prompt;
- a product feature;
- technical spans and product events;
- an owner and risk classification;
- an AI use case, when applicable.

A capability is not ready when only one representation exists.

## Shared components and their boundaries

Runtime projects consume, but do not reimplement, these platform components:

- **Access Layer** (`platform_service`) — identity, entitlement, OAuth/OIDC,
  sessions, clients, scopes and audit;
- **Agent Gateway** (`platform_service`) — MCP transport, discovery, protocol
  compatibility, rate limits and tool routing;
- **UNGUESS Observability Stack** (`infrastructure_stack`) — central OTLP
  collection and technical metrics/trace/log storage;
- **Tool Observatory** (`tool`) — catalogue, product usage, management views,
  technical summaries and exports;
- **UNGUESS Platform SDK** (`sdk_library`) — reusable auth, RequestContext,
  telemetry, health, MCP and Garden packages; no central runtime.

The initial **deployment registry** is Git-versioned data, not a separate
runtime service. Tool Observatory may ingest it later.

The Agent Gateway is not the authorization authority. Access Layer is. Tool
Observatory is not the raw telemetry collector. The Observability Stack is.

## Safe rollout defaults

Platform capability code may be present before a central service is available.
New authentication, MCP, analytics and AI paths remain protected by server-side
feature flags and are enabled progressively after conformance testing.

The safe initial state for an existing project is:

- current Coolify resource, domain and container port recorded before change;
- current web path unchanged;
- legacy Access Layer enabled;
- OAuth resource-server path deployed but disabled;
- MCP registration prepared but disabled;
- telemetry emitted best-effort;
- no new host-port publication;
- rollback possible without a database restore.

## Release evidence

Production releases produce:

- a strict platform-check report with central registry validation;
- route, service, health, storage and backup evidence;
- API/MCP schema validation;
- auth and compatibility test results;
- synthetic readiness result;
- AI assessment status;
- accessibility result where UI applies;
- migration and rollback evidence when deployment or auth behavior changes.
