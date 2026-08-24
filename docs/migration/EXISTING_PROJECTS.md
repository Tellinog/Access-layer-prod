# Applying the template to an existing project

## Goal

Adopt the platform contract without a big-bang rewrite. Existing product functionality and access remain authoritative while adapters, manifests and evidence are introduced incrementally.

## Bootstrap

```bash
python scripts/bootstrap.py \
  --project-name "Existing Tool" \
  --project-slug existing-tool \
  --project-kind tool \
  --description "Describe the existing tool and its intended users." \
  --owner-team owner-team \
  --technical-owner technical-owner \
  --product-owner product-owner \
  --base-url "https://communicated-domain.example.com" \
  --container-port 3000 \
  --coolify-server main-server \
  --coolify-project internal-tools \
  --mode legacy-migration
```

The command keeps `access-layer-legacy-v1` as the default web profile and leaves OAuth disabled until the project is registered as a resource. The domain and internal port must describe the deployed Coolify route; do not invent a new port merely because another resource uses the same container port.

## Discovery inventory

Before modifying runtime code, record:

- current login, callback, exchange, refresh, introspection and logout behavior;
- tool slug, client ID, callback allowlist and permissions;
- session and token storage;
- JWT validation and introspection policy;
- single-replica assumptions, in-memory locks and background refresh behavior;
- externally consumed routes and payloads;
- long-running jobs and side effects;
- AI providers, models, data categories and output approval path;
- health checks, logs, metrics and analytics already emitted;
- user-visible strings and non-Garden styling;
- Coolify server/project/environment/resource and build strategy;
- current domain routes, target services and internal container ports;
- any direct host-port mapping and its actual exposure;
- cross-resource networks, persistent volumes, databases, backups and rollback.

Do not silently normalise differences. Record them in `CURRENT_STATE.md` and create migration decisions in `DECISIONS.md`. First record the deployed state; changing a host port, domain, volume or network is a separate runtime change.

## Adapter sequence

### 1. Introduce a shared request context

Map the existing authenticated session to `schemas/request-context.schema.json`. Preserve the existing identity and permission semantics.

### 2. Move policy into the application core

Web handlers, API handlers and MCP adapters call the same capability/service function. The core authorises using the request context rather than relying only on route placement.

### 3. Add observability without changing outcomes

Add trace/correlation IDs, technical telemetry and product events. Telemetry remains non-blocking and excludes tokens, secrets and unrestricted payloads.

### 4. Add the API contract

Describe only stable, supportable capabilities in OpenAPI. Do not publish internal database or generic execution endpoints.

### 5. Register with Agent Gateway

Start with read-only or low-risk capabilities. Keep the existing web interface independent from Gateway availability.

### 6. Add OAuth resource-server support

Accept OAuth tokens only after Access Layer vNext registration, audience/scopes are configured and conformance tests pass. Legacy and OAuth adapters coexist.

### 7. Consider web-login migration separately

Migrating the browser-facing login is optional and must not be bundled with the first API/MCP exposure.

## Existing-tool acceptance criteria

- all pre-migration functional tests pass;
- current users retain access and grants;
- an active pre-deploy session survives the release;
- legacy payload and claim snapshots are unchanged;
- OAuth traffic can be disabled independently;
- telemetry failure does not fail product requests;
- API/MCP calls and web calls reach the same domain policy;
- no new AI data leaves the system without an approved provider/data record;
- Garden and English-first changes do not alter user data or business rules;
- the communicated domain reaches the declared service/internal port through Coolify;
- local deployment registration matches the central registry and actual resource;
- no unapproved host-port mapping is introduced;
- persistent data and rollback survive a deployment rehearsal.
