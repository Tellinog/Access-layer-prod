# Platform conformance tests

The executable repository checker validates static contracts. The YAML
catalogues in this directory define integration and end-to-end acceptance
scenarios that must be implemented in the project's chosen test stack.

## Required layers

1. **Static contract checks** — manifest, local deployment registration,
   central-registry agreement, schemas, OpenAPI, capability mapping, Garden
   tokens, AI governance files and placeholders.
2. **Project integration tests** — request-context adapters, policy enforcement,
   health, non-blocking telemetry, product events and application services.
3. **Coolify deployment tests** — build, internal service ports, public HTTPS
   routes, private dependencies, persistent volumes, backups and rollback.
4. **Platform staging tests** — Access Layer legacy and OAuth/OIDC, Agent
   Gateway, MCP client interoperability, Observability Stack export,
   Observatory ingestion and synthetic checks.
5. **Release migration tests** — pre-upgrade sessions and tokens used after
   deployment, rollback, canary isolation and no data/access loss.

## Registry evidence

Runtime production candidates run the checker with the Git-versioned central
registry. The suite must demonstrate that:

- container port reuse across different Coolify resources is allowed;
- exact hostname/path collisions are rejected;
- resource-registration collisions are rejected;
- overlapping direct host-port mappings are rejected;
- the local registration and central entry are identical.

A passing static check is necessary but is not sufficient evidence that the
central Access Layer implementation preserves all deployed sessions or that a
backup can be restored. Those guarantees require staging/release evidence.
