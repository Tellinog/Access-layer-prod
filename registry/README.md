# Deployment registry integration

This project does not own the central deployment registry. It owns one local,
non-secret registration file: `deployment.registration.yaml`.

The platform team maintains one Git-versioned central registry containing the
registrations for all Coolify runtime resources. The initial registry may be a
YAML file validated by `schemas/deployment-registry.schema.json`; it is not a
new runtime service. Tool Observatory may ingest this registry later, but it
must not become the source of deployment truth by silently modifying entries.

Before a production release:

1. complete `deployment.registration.yaml`;
2. submit or update the same entry in the central registry;
3. verify exact route/path, Coolify resource and any approved host-port uniqueness, including wildcard bind overlap and exception expiry;
4. run `python scripts/platform_check.py --strict --registry <path>`.

`examples/registry/deployments.yml` is illustrative only. Never treat its
`.invalid` domains as deployable configuration.
