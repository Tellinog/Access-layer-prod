# Reference examples

All examples contain synthetic or redacted values. They are executable contract fixtures, not production credentials or real user records.

| Directory | Purpose |
|---|---|
| `access-layer/` | Frozen legacy Access Layer registration, exchange and introspection examples based on the currently deployed contract. |
| `oauth/` | Frozen P0 target metadata, registrations, authorization response, token profile, token/introspection/error responses and protected-resource metadata. Runtime remains disabled. |
| `auth/` | Shared `RequestContext` created by the legacy and OAuth adapters. |
| `api/` | Project API success, error and asynchronous-job patterns. |
| `mcp/` | MCP `2026-07-28` per-request metadata, tool discovery and tool invocation. |
| `telemetry/` | Privacy-safe capability event for Tool Observatory. |
| `ai/` | AI provenance and review event examples. |
| `ui/` | Static Garden design-system implementation reference. |
| `manifests/` | Full schema-valid v2.1 examples for greenfield and legacy-migration tools. |
| `registry/` | Example central Coolify deployment registry; `.invalid` domains are illustrative only. |

Canonical OAuth capability identifiers use exactly `project:domain:action`, for example `example-project:records:read`. Legacy permissions retain their frozen broader colon grammar; an OAuth scope must be explicitly registered and bridged to the effective entitlement, never rewritten implicitly. OpenAPI `operationId` and future MCP names use explicit transport mappings.
