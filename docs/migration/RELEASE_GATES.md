# Migration release gates

## Gate 0 - evidence exists

- current protocol and functional snapshots are stored;
- owners and rollback operator are named;
- backup/restore is verified;
- deployment and database versions are recorded;
- Coolify server, project, environment, resource, routes, services and internal ports are recorded;
- persistent volumes, backups and rollback are verified;
- local and central deployment registrations match.

## Gate 1 - Coolify deployment conformance

- the communicated HTTPS route targets the declared service and internal port;
- public HTTP services bind to `0.0.0.0` and pass liveness/readiness;
- databases and caches remain private;
- no unapproved direct host-port mapping exists;
- container-port reuse is not treated as a collision;
- strict conformance passes against the central registry.

## Gate 2 - additive compatibility

- schema migration is backward compatible;
- all legacy contract tests pass against the new build;
- pre-upgrade sessions and refresh tokens survive;
- legacy signing and encryption material is preserved;
- OAuth/OIDC can be disabled without data changes.

## Gate 3 - OAuth/OIDC conformance

- metadata is correct;
- PKCE `S256` is required;
- exact redirect matching is enforced;
- token audience and scope are validated;
- refresh-token replay revokes the token family;
- revocation and introspection are protected and audited;
- key rotation is tested;
- public clients do not require embedded secrets.

## Gate 4 - first consumer

- consumer is allowlisted and has an owner;
- resource and scopes are registered;
- user/service identity is distinguishable;
- the new path is observable;
- blast radius and rollback are documented;
- the legacy path remains healthy.

## Gate 5 - project migration

- project conformance passes;
- legacy and OAuth request contexts are equivalent for matching entitlements;
- capability permissions/scopes match the manifest;
- API/MCP policy is enforced server-side;
- support and incident runbooks are updated;
- management and technical dashboards are available.

A failed gate blocks progression but does not require rollback of a healthy legacy path.
