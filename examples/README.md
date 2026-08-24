# Reference examples

All examples contain synthetic or redacted values. They are executable contract fixtures, not production credentials or real user records.

| Directory | Purpose |
|---|---|
| `access-layer/` | Frozen legacy Access Layer registration, exchange and introspection examples based on the currently deployed contract. |
| `oauth/` | Proposal B authorization-server/resource registration, metadata and audience-bound access-token claims. |
| `auth/` | Shared `RequestContext` created by the legacy and OAuth adapters. |
| `api/` | Project API success, error and asynchronous-job patterns. |
| `mcp/` | MCP `2026-07-28` per-request metadata, tool discovery and tool invocation. |
| `telemetry/` | Privacy-safe capability event for Tool Observatory. |
| `ai/` | AI provenance and review event examples. |
| `ui/` | Static Garden design-system implementation reference. |
| `manifests/` | Full schema-valid v2.1 examples for greenfield and legacy-migration tools. |
| `registry/` | Example central Coolify deployment registry; `.invalid` domains are illustrative only. |

Canonical capability identifiers use the same colon-separated form already accepted by Access Layer permissions, for example `template-project:example:read`. The `capability_id`, legacy permission and OAuth scope are identical; OpenAPI `operationId` and MCP names are explicit transport mappings. `specs/permissions.v1.yml` also provides an empty-by-default alias registry for the exceptional case in which a deployed permission key must remain unchanged while the canonical capability name differs.
