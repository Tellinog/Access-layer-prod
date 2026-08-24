# Template migration: v2.0 to v2.1

## Scope

Version 2.1 adds a Coolify deployment contract and clarifies the difference
between deployable tools/services/infrastructure and the non-deployable UNGUESS
Platform SDK. It does not change authentication runtime behavior, Access Layer
legacy contracts, sessions, grants, OAuth rollout state, product capabilities
or application data.

## Required merge

1. add `project.kind`;
2. add the `deployment` section to `project.platform.yaml`;
3. add `deployment.registration.yaml`;
4. add `specs/deployment.v1.yml`;
5. add the deployment and registry schemas;
6. update the platform checker and tests;
7. register the project in the central deployment registry before production.

## Existing Coolify projects

Inventory the deployed resource before editing configuration:

- Coolify server, project, environment and resource name;
- application/service type and build strategy;
- canonical domains and path routes;
- target service and internal container ports;
- any direct host-port mappings;
- networks and cross-resource dependencies;
- persistent volumes and databases;
- health check, backup and rollback behavior.

Record the current state without changing it. A direct host-port mapping found
in production is not removed incidentally; record it as a migration question,
protect it with the existing firewall, and plan a separate approved change.

## Compatibility

This template migration is documentation, schema and conformance work. Runtime
changes require their own roadmap phase, tests and Coolify release. Existing
Access Layer behavior remains governed by `docs/LEGACY_COMPATIBILITY.md`.
