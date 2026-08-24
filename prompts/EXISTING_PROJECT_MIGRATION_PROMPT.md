# Existing project migration prompt

Apply the v2.1 platform contract to this existing project without changing current access, deployment or product behavior.

First create an evidence-based inventory of:

- current Coolify server, project, environment and resource;
- domains and path routes;
- services and internal container ports;
- any direct host-port mappings;
- Docker networks and cross-resource dependencies;
- volumes, databases, backups, health checks and rollback behavior;
- Access Layer endpoints, payloads, JWT validation, introspection, sessions, refresh coordination, grants and callbacks.

Record the current deployment in `project.platform.yaml` and `deployment.registration.yaml` before making runtime changes. Preserve differences rather than silently replacing them. A current host-port mapping is recorded and reviewed; it is not removed incidentally in the template-adoption commit.

Then implement only the next reversible step:

1. deployment and legacy golden-contract evidence;
2. shared RequestContext from the current legacy path;
3. application-core capability policy;
4. non-blocking instrumentation through the UNGUESS Platform SDK;
5. OpenAPI capability contract;
6. Agent Gateway registration for a low-risk capability;
7. OAuth resource-server adapter after Access Layer registration;
8. optional web-login migration as a separate release.

Every step includes pre-upgrade session survival, feature flag, tests, Coolify health evidence, registry alignment and rollback plan. Never require another existing tool to migrate at the same time.
