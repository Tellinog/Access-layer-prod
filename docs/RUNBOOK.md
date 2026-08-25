# Operational Runbook

## Required incident identifiers

Always capture:

- project, project kind and release;
- environment and Coolify server/project/resource;
- affected domain, route, service and internal container port;
- capability;
- correlation and trace IDs;
- invocation channel;
- impact start and end;
- affected users or grants as aggregates unless identifiable access is required.

Never place secrets, access tokens, refresh tokens, session cookies, database
credentials or unredacted customer payloads in an incident ticket.

## Coolify route or reachability incident

1. Check `/health/live` and `/health/ready` through the service network and then
   through the communicated HTTPS domain.
2. Confirm that the application listens on `0.0.0.0` and on the container port
   declared in `project.platform.yaml`.
3. Confirm that the Coolify domain routes to the declared target service and
   internal container port.
4. Check the latest Coolify deployment status and proxy logs.
5. Do not allocate a new host port as a shortcut. Host-port publication remains
   an approved exception only.
6. Compare `deployment.registration.yaml` with the central registry before
   changing a domain or resource name.
7. Roll back to the previous healthy Coolify deployment when the new release
   cannot be repaired inside the incident window.

## Host-port collision or exposure incident

1. Identify the server, bind address, protocol and host port.
2. Stop or isolate only the unapproved/conflicting mapping when safe.
3. Preserve normal proxy-routed traffic where possible.
4. Verify firewall scope and whether `0.0.0.0` or `::` expanded exposure beyond
   the intended interface.
5. Record the exception or removal in both the local deployment registration
   and central registry.
6. Run the registry uniqueness check before redeployment.

## Persistent storage or database incident

1. Stop destructive migrations and automated cleanup jobs.
2. Identify the declared volume/database and its backup owner.
3. Preserve the current volume before attempting repair where feasible.
4. Follow the documented restore procedure; never assume a backup is usable
   without verification.
5. Restore into an isolated environment first when the incident allows it.
6. Verify application schema compatibility and Access Layer/session continuity.
7. Record recovery point, recovery time and evidence of the restore test.

## Authentication outage

1. Determine whether legacy, OAuth/OIDC or both paths are affected.
2. Do not rotate or delete legacy signing/encryption keys as a first response.
3. Existing valid JWTs may remain usable according to local validation policy.
4. High-risk operations that require online introspection fail closed.
5. Disable only the affected new feature flag when possible.
6. Verify legacy login, refresh, introspection and active sessions after recovery.

## OAuth rollout incident

1. Disable OAuth for the affected client/resource.
2. Preserve legacy traffic.
3. Stop new schema contractions.
4. Compare token audience, scopes, redirect URI and key IDs.
5. Roll back application or Access Layer while additive schema remains compatible.

## Agent Gateway outage

MCP access may be unavailable. Web and direct approved API paths remain
operational. Communicate the channel-specific impact. Do not route agents around
Access Layer or directly to project databases.

## UNGUESS Observability Stack outage

Business operations continue. Technical traces, metrics or logs may be delayed
or dropped according to bounded-buffer policy. Check Collector health, exporter
queues, storage pressure and failed batches. Restore exporters without replaying
sensitive or duplicate data blindly.

## Tool Observatory outage

Management dashboards, catalogue views, product analytics and exports may be
unavailable. Tool business operations and the technical Observability Stack
continue independently. Preserve product-event buffers within their declared
bounds and reconcile idempotently after recovery.

## AI provider outage

Disable or degrade only AI assistance. Preserve deterministic/manual
functionality. Do not switch to an unapproved provider or model.

## Key compromise

Follow the central Access Layer key-compromise plan. Publish/activate replacement
keys, revoke affected credentials and preserve validation of uncompromised
still-valid legacy tokens only when security approves.

## Post-incident requirements

- update `DEVLOG.md`, `CURRENT_STATE.md` and `BACKLOG.md`;
- update deployment registration when domain, resource, route, port, storage or
  ownership changed;
- attach test and rollback evidence;
- add or update a synthetic check when the incident was externally observable;
- record a decision when the remediation changes a platform contract.
# Access Layer Step 2 release gate

No deployment or rollback rehearsal is authorized. The logical named-volume mismatch is resolved from live evidence, but a verified backup/restore point, central registry, named owners and remaining continuity proof are still required. Preserve `access_layer_postgres_data_v2`, `access_layer_jwt_secrets` and their UUID-prefixed live volumes exactly. The procedures above are target runbook guidance, not evidence of an executed deployment.
