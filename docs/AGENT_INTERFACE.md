# Agent Interface

## Default deployment

Expose remote MCP through Agent Gateway. The project owns the canonical API and capability manifest. A native MCP server is allowed only through an accepted architecture/security decision.

## Capability selection

Do not convert every REST endpoint into a tool. Classify each stable capability as:

- **tool** — model-controlled action or bounded query;
- **resource** — application-controlled content or state;
- **prompt** — user-controlled reusable workflow.

Never expose arbitrary SQL, shell, filesystem, unrestricted URL fetching or raw provider APIs.

## Required capability metadata

- canonical capability ID;
- title and model-oriented description in English;
- input and output schemas;
- required scope;
- read-only/destructive classification;
- idempotency requirement;
- human-confirmation policy;
- timeout and maximum payload;
- data classification;
- AI use and provenance behavior;
- owner and telemetry feature.

## Protocol and security profile

Target protocol version: `2026-07-28`.

For Streamable HTTP:

- each JSON-RPC message is sent by HTTP POST to the MCP endpoint;
- authorization is supplied and validated per request;
- the server validates `Origin` when present;
- protocol-level sessions are not used;
- requests include protocol/client metadata;
- cross-request state uses explicit application identifiers;
- tool lists may be filtered by the caller’s scopes;
- input and structured output are validated against JSON Schema;
- access tokens never appear in URIs.

## Human oversight for agents

A web confirmation screen alone is insufficient. The capability contract and gateway policy must prevent an agent from bypassing required approval.

Recommended split:

```text
generate_draft
review_draft
approve_draft
publish_or_export
```

Avoid a single `generate_and_publish` capability.

## Error behavior

- unauthenticated or invalid token: OAuth `401` challenge;
- valid token, missing scope: `403 insufficient_scope` with required scope;
- invalid tool input: MCP tool error with safe field errors;
- domain rejection: stable application error code;
- long-running timeout: return/retain job handle rather than duplicate work.

See `examples/mcp/`.
