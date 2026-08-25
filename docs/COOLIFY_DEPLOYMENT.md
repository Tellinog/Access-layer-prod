# Coolify Deployment Contract

## Scope

Every runtime project based on this template is deployed as its own Coolify
resource. A project may contain several containers, but it remains one
operational deployment unit unless an approved architecture decision says
otherwise.

The only project kind with no Coolify runtime is `sdk_library`.

| Project kind | Runtime | Coolify resource | Public domain |
|---|---:|---:|---:|
| `tool` | Yes | Required | Required by default |
| `platform_service` | Yes | Required | Required only when externally reachable |
| `infrastructure_stack` | Yes | Required | Not required by default |
| `sdk_library` | No | Forbidden | Forbidden |

The canonical machine-readable rules are in:

- `project.platform.yaml`;
- `deployment.registration.yaml`;
- `specs/deployment.v1.yml`;
- `schemas/deployment-registration.schema.json`.

## One tool, one Coolify resource

A tool may still be a multi-container Docker Compose stack:

```text
Tool Observatory - one Coolify resource
|- web
|- api
|- event worker
|- synthetic runner
`- PostgreSQL
```

Only the intended web/API services receive public routes. Workers, databases,
caches and internal collectors remain private inside the resource network.

## Domains and container ports

A public route is identified by:

```text
hostname + path -> target service + target container port
```

Container ports are local to their containers and may be reused by unrelated
Coolify resources. It is valid for Nancy, Petyr, Goodman and Tool Observatory
to each listen on container port `3000`.

For a service listening on container port `3000`, the Coolify domain field is
configured with the target port, for example:

```text
https://tool.example.com:3000
```

The `:3000` suffix tells the Coolify proxy which port to reach inside the
container. Users still access the product over normal HTTPS at:

```text
https://tool.example.com
```

The application must listen on `0.0.0.0`, not only `127.0.0.1`, when Coolify's
proxy must reach it.

## Host-port policy

Direct host-port publication is forbidden by default:

```yaml
ports:
  - "3000:3000"
```

A published host port bypasses normal domain-based proxy routing and can expose
an internal service on a server interface. It is allowed only through a
security-approved, time-bounded exception recorded in both the project
registration and the central deployment registry.

Every exception must include:

- target service and container port;
- host port and protocol;
- bind address;
- business/technical reason;
- approver;
- firewall scope;
- expiry date.

Container ports are never checked for global uniqueness. Host ports are checked for overlapping bindings per server, protocol and port. A wildcard bind such as `0.0.0.0` or `::` conflicts with a specific address on the same port.

## Coolify networking

Docker Compose resources use a resource-specific network by default. Components
inside the same resource communicate through service names and internal ports.

Cross-resource connectivity must be explicit. Use one of these approved models:

1. HTTPS through an authenticated private/public route; or
2. Coolify's predefined shared network when both resources are on the same
   server and the dependency is documented.

Enabling a shared network is not a substitute for authentication or
application-layer authorization. Databases and caches must not receive public
domains or host-port mappings by default.

## Health checks

Every public runtime service provides:

- `/health/live` for process liveness;
- `/health/ready` for readiness and required dependency state.

Checks are lightweight, do not mutate data and reveal no credentials. Coolify
health checks must target the internal container port. Docker Compose projects
must carry health-check configuration in the Dockerfile or Compose definition
when the check is expected to travel with the deployment.

## Persistent storage and backups

Every persistent path, named volume and database must be declared. A stateful
runtime cannot be marked production-ready until it has:

- a backup owner;
- schedule and retention;
- off-container/off-resource storage where appropriate;
- a documented restore procedure;
- a periodic restore test;
- rollback compatibility for schema changes.

Database services remain private. Public database exposure requires a separate
security decision and is not represented by the default template.

## Deployment registry

Each repository owns `deployment.registration.yaml`. The platform team owns one
central Git-versioned registry. The registry prevents accidental collisions in:

- exact hostname/path routes, including overlap rules for intentionally shared hostnames;
- Coolify resource names on the same server;
- approved, unexpired published host-port bindings;
- registration identifiers.

It deliberately does not reserve container ports.

Before production, run:

```bash
python scripts/platform_check.py --strict \
  --registry /path/to/platform-deployment-registry/deployments.yml
```

The initial registry is a file contract, not a new runtime tool. Tool
Observatory may ingest it later for catalogue and monitoring views.

## Rollout and rollback

1. create or update the Coolify resource with feature flags disabled;
2. apply additive database migrations;
3. deploy and wait for health checks;
4. verify the public route and private dependencies;
5. run legacy-auth compatibility smoke tests where applicable;
6. enable new capabilities progressively;
7. retain the previous application/database compatibility window until
   rollback evidence is complete.

Rollback uses the previous Coolify deployment, image tag or Git revision. It
must not require deleting new tables or invalidating existing Access Layer
sessions.

## Official implementation references

- Coolify Docker Compose: <https://coolify.io/docs/knowledge-base/docker/compose>
- Coolify networking: <https://next.coolify.io/docs/services/configuration/networking>
- Coolify domains: <https://next.coolify.io/docs/core/networking/domains>
- Coolify health checks: <https://next.coolify.io/docs/applications/configuration/health-checks>
# Access Layer Step 2 status

This deployment contract is adopted, and live Coolify evidence resolves the source declaration to the already-running logical volume `access_layer_postgres_data_v2`. JWT storage `access_layer_jwt_secrets` is also proven to be a named volume. Do not add explicit physical names or rename either logical/live volume. Deployment remains blocked until backup/restore, registry, ownership and remaining continuity evidence are complete.
