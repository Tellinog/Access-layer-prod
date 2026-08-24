# UNGUESS Platform SDK

## Definition

The UNGUESS Platform SDK is a shared repository of versioned packages. It is
not a tool, platform service or central runtime. It has no domain, port,
database or Coolify deployment.

The name replaces the ambiguous term "Platform Core".

## Intended packages

```text
@unguess/platform-contracts
@unguess/platform-request-context
@unguess/platform-auth-legacy
@unguess/platform-auth-oauth-resource-server
@unguess/platform-permissions
@unguess/platform-telemetry
@unguess/platform-product-events
@unguess/platform-health
@unguess/platform-mcp-adapter
@unguess/garden-ui
@unguess/platform-testkit
```

The repository may be a monorepo, but each package is independently versioned
or released through a documented coordinated-version policy.

## Responsibilities

The SDK provides reusable implementations and test fixtures for:

- mapping verified legacy and OAuth identities into `RequestContext`;
- capability and permission enforcement primitives;
- non-blocking OpenTelemetry export;
- product-event envelopes;
- liveness/readiness helpers;
- Agent Gateway registration/adapters;
- Garden tokens and UI primitives;
- platform conformance tests.

It must not contain project business logic, deployment state or central user
data.

## Consumption and compatibility

Projects pin exact or approved version ranges. An SDK release cannot force an
upgrade of Nancy, Petyr, Goodman, Test Generator or any other tool.

Every SDK upgrade in a consuming project requires:

1. changelog and compatibility review;
2. project tests and platform conformance;
3. legacy Access Layer regression checks when auth packages change;
4. an independent Coolify release and rollback plan.

The SDK is therefore a means of reducing duplicated implementations without
creating a shared runtime single point of failure.
