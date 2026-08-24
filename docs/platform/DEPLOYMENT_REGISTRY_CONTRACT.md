# Deployment Registry Contract

## Purpose

The deployment registry is the shared inventory of Coolify runtime resources.
Its initial implementation is a Git-versioned YAML dataset, not a new deployed
tool.

Each project owns `deployment.registration.yaml`. The central registry contains
one equivalent entry per environment.

## Required uniqueness

The registry rejects collisions in:

- `registration_id`;
- Coolify `server_name + resource_name`;
- non-shared public hostnames;
- overlapping published host-port bindings on the same server/protocol/port. A wildcard bind such as `0.0.0.0` or `::` conflicts with every specific address for that port.

Container ports are intentionally excluded because they are isolated inside
containers and can be reused across resources.

A hostname may be shared only when every involved route explicitly sets
`shared_hostname: true` and uses non-overlapping path prefixes. For example,
`/alpha` and `/beta` may coexist; `/api` and `/api/v2` overlap and are rejected.
This is an exception, not the default.

## Registration lifecycle

```text
pending_registration
  -> registry pull request
  -> automated uniqueness validation
  -> platform review
  -> registered
  -> production deploy
```

Changes to domain, server, Coolify resource name, public route, host-port
exception or ownership require a registry update before deployment.

## CI verification

A production project runs:

```bash
python scripts/platform_check.py --strict --registry <central-registry-path>
```

The checker validates the local registration, the central registry, global
uniqueness, unexpired host-port exceptions and exact agreement between the two
entries, including registration status and verification timestamp.

## Tool Observatory relationship

Tool Observatory may ingest the registry to display ownership, routes, health
checks and deployment metadata. The Git registry remains the deployment source
of truth until a separate approved decision changes that ownership model.
