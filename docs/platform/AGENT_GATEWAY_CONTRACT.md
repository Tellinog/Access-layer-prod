# Agent Gateway Contract

## Role

Agent Gateway is the default shared remote MCP server. It translates platform capability registrations into MCP primitives and calls project APIs. It does not own project business logic.

## Responsibilities

- MCP protocol versioning and backward compatibility;
- Streamable HTTP endpoint;
- protected-resource metadata and OAuth discovery;
- bearer-token, issuer, audience and scope validation;
- Origin validation;
- rate limits, body/time limits and abuse controls;
- deterministic tool ordering and schema validation;
- tool visibility filtered by granted scope;
- correlation, trace and gateway audit;
- controlled downstream token exchange or service assertion;
- standard errors and retry policy.

## Project responsibilities

- application-level authorization remains enforced in the project;
- capability input/output schemas remain authoritative;
- business validation and idempotency remain in the project;
- dangerous or irreversible actions require the declared confirmation policy;
- the project does not trust gateway headers from public traffic without authenticated integrity.

## Availability isolation

Gateway outage affects MCP access only. Existing web and approved direct API traffic remain available.
