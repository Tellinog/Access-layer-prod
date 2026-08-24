# Platform reference adapters

This directory contains transport-neutral reference contracts. It is **not** a
production OAuth/JWT/session implementation and is not a substitute for the
versioned **UNGUESS Platform SDK** packages.

The Platform SDK is an `sdk_library`: it has no domain, port, database or
Coolify deployment. Its code is imported and pinned by each project.

```text
verified legacy identity ----+
                             +--> RequestContext --> capability policy --> application core
verified OAuth identity -----+
```

Existing Access Layer permission keys are already hierarchical, colon-separated
capability identifiers. The legacy adapter preserves them exactly; it does not
rename permissions, modify Access Layer records or rewrite token claims. OAuth
scopes use the same identifier. OpenAPI `operationId` and MCP tool names remain
explicit transport mappings.

Authentication profile selection is explicit. An invalid OAuth bearer token
must never fall back to a legacy cookie or session, and requests carrying
ambiguous credentials are rejected. Web, API and MCP call the same application
service after a verified `RequestContext` is created.

Telemetry reference code emits to the central UNGUESS Observability Stack and
Tool Observatory through non-blocking adapters. It does not make those central
systems a synchronous dependency of the business request.
