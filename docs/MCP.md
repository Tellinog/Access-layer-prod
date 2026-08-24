# MCP profile

## Baseline

The template targets MCP protocol version `2026-07-28`, as declared in `template_manifest.yml`. Revalidate the profile against the official specification before every production rollout because MCP is versioned independently from this template.

The default deployment is through Agent Gateway. A project may expose a native MCP endpoint only when a documented need justifies the additional protocol and security ownership.

## One application capability, multiple transports

MCP tools, resources and prompts are adapters over the same application services used by the web and OpenAPI interfaces. They must not contain a second implementation of authorization or business logic.

The mapping is explicit:

```text
capability_id: template-project:example:read
legacy permission: template-project:example:read
OAuth scope: template-project:example:read
OpenAPI operationId: getExample
MCP tool name: example_read
telemetry feature: example_read
```

## Per-request metadata and results

For the `2026-07-28` protocol profile:

- every request includes `params._meta` with the protocol version, client information and client capabilities;
- OpenTelemetry `traceparent`, `tracestate` and `baggage` may be propagated in `_meta` using their reserved names;
- every successful result includes `resultType`;
- server information should be present in result `_meta` unless deliberately disabled;
- a server must not rely on a previous request or connection to recover client identity, protocol version or capabilities.

Examples are under `examples/mcp/`.

## HTTP authorization

For remote HTTP MCP access:

- Access Layer is the OAuth authorization server selected in Proposal B;
- Agent Gateway or the native MCP endpoint is the protected resource;
- the protected resource publishes RFC 9728 metadata;
- authorization-server discovery follows the advertised metadata;
- human delegation uses authorization code with PKCE;
- the client includes the exact `resource` identifier during authorization and token requests;
- bearer tokens are sent only in the `Authorization` header and on every HTTP request;
- the resource server validates issuer, signature, token type, expiry, exact audience and scope;
- a token issued for another resource is rejected and never passed through;
- invalid or absent authentication returns `401` with a useful challenge;
- insufficient scope returns `403` and scope guidance;
- browser-originated requests validate `Origin` against an exact allowlist.

## Stateless transport and durable work

The target Streamable HTTP transport uses a single POST endpoint and no protocol-level session. Do not use a connection, process or transport session as an application state boundary.

Long-running or multi-step work returns explicit, opaque handles:

```text
create_job(...) -> job_id
get_job_status(job_id)
get_job_result(job_id)
cancel_job(job_id)
```

Every operation re-authorizes access to the handle. The handle itself is not proof of authorization.

When more user input is required, use the protocol's input-required/multi-round-trip pattern where supported; do not create an implicit server-side conversational session.

## Tool design

Every tool provides:

- unique `name` and English `title`/`description`;
- valid JSON Schema `inputSchema`;
- `outputSchema` when structured output is returned;
- the required capability/scope and risk in the project manifest;
- timeout, idempotency and confirmation policy;
- sanitised text content and validated `structuredContent`;
- actionable tool-execution errors without secret or internal stack disclosure.

A tool with no parameters still declares a valid object schema, preferably with `additionalProperties: false`.

## Scope minimisation and step-up

Initial authorization requests use the minimum useful read scope. Write, export, administrative and sensitive scopes are requested only when the operation requires them. Scope implication must be declared in `specs/permissions.v1.yml`; it must not be inferred from string prefixes.

The gateway may filter discovery, but the project remains responsible for final authorization. Gateway approval is not a substitute for application policy.

## Mutations and human oversight

A mutating MCP capability requires:

- an idempotency strategy;
- explicit side-effect and destructive-action classification;
- confirmation policy;
- audit and product events;
- application-level authorization;
- human approval when the same effect requires approval in the web interface.

AI-assisted actions cannot bypass the human-oversight boundary through MCP.

## Gateway registration

The project supplies:

- canonical MCP resource URL;
- Access Layer issuer/authorization-server URL;
- protected-resource metadata URL;
- capability manifest and OpenAPI location;
- owner and support contact;
- scopes and risk classifications;
- rate, size and timeout limits;
- health endpoint;
- environment, release and deprecation policy.

## Conformance

Test at least one real MCP client in staging, including:

- protected-resource and authorization-server discovery;
- PKCE login;
- exact resource/audience validation;
- least-privilege scope request and step-up;
- denied tool visibility and denied tool call;
- successful `tools/list` and `tools/call` with required `_meta`;
- structured output validation and `resultType`;
- explicit long-running handle behavior;
- revocation;
- Origin denial;
- Agent Gateway outage isolation from the existing web path.
