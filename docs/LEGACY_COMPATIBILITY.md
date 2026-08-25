# Legacy Compatibility

> Step 2 status: the current legacy-only surface remains frozen in `../specs/legacy-contract-baseline.v1.json`. The additive OAuth P0 contract is frozen in `../specs/oauth-p0.v1.yml`, but no OAuth endpoint, table, migration, flag or adapter has been introduced. All dual-run material below remains a future constraint, not current behavior or a passed migration result.

## Objective

Introduce OAuth/OIDC, MCP and platform monitoring without loss of access, sessions, grants, features or rollback capability for Nancy, Test Generator, Goodman, Petyr and other current consumers.

Continuity is not assumed. It is enforced through explicit invariants, golden contracts, upgrade tests and staged rollout.

## P0 invariants

Until a consumer is explicitly migrated, the Access Layer release must not change:

- `/v1/auth/start`;
- `/v1/auth/google/callback`;
- `/v1/auth/exchange`;
- `/v1/auth/refresh`;
- `/v1/auth/introspect`;
- `/v1/auth/logout`;
- `/v1/.well-known/jwks.json`;
- request or response field names and meanings;
- Basic client authentication behavior;
- exact callback/return URL comparison;
- current legacy JWT issuer, audience and claim semantics;
- tool slug and registered permission behavior;
- current session and refresh lifetimes;
- active session IDs and refresh-token hashes;
- signing and encryption material needed to read current state;
- existing users, tools, grants and permissions.

## Additive data model

Do not transform existing tables in place as the first step. Add independent OAuth entities while legacy entities remain authoritative during transition.

```text
Existing
  users
  tools
  tool_permissions
  authorization_grants
  sessions
  refresh_tokens

Additive
  oauth_clients
  oauth_resources
  oauth_scopes
  oauth_grants
  oauth_authorization_codes
  oauth_refresh_token_families
  service_principals
  signing_keys
```

Use expand–migrate–verify–contract. The contract/removal phase occurs only after measured zero usage and explicit approval.

## Dual adapter pattern

```text
Legacy session/token --> LegacyAuthAdapter --+
                                               +--> RequestContext --> Application core
OAuth token ----------> OAuthAuthAdapter -----+
```

The application core never branches on `legacy` versus `oauth`. Differences remain at the adapter and audit layers. Canonical capability IDs use the Access Layer-compatible colon syntax. A legacy permission that cannot be adopted unchanged is mapped only through the versioned `legacy_permission_aliases` catalogue; the deployed permission and grant remain untouched until explicit migration.

## Session continuity test

Required scenario:

1. create a valid legacy login/session/refresh token on release N-1;
2. deploy release N containing the OAuth additions;
3. use the existing session without a new login;
4. refresh with the existing refresh token;
5. introspect the existing access token;
6. perform the same authorized operation;
7. log out and revoke successfully;
8. verify the same legacy audit behavior;
9. repeat across every registered legacy consumer contract.

## Rollback test

1. enable OAuth only for a canary client;
2. confirm legacy traffic is unchanged;
3. disable OAuth feature flags;
4. roll Access Layer back to N-1 when schema compatibility permits;
5. verify no user, grant, legacy session or refresh token is lost.

Database migrations must therefore be backward-compatible during the rollback window.

## Feature flags

All new paths are independently controlled:

- OAuth authorization server;
- OIDC provider;
- OAuth resource-server adapter per project;
- MCP per project/client;
- service principals;
- token exchange;
- telemetry exporters.

Disabling them restores the pre-change traffic path.

## Migration order for an existing tool

1. Freeze legacy behavior with golden contract tests.
2. Add the manifest and common capability IDs without changing runtime behavior.
3. Convert the local legacy session into `RequestContext`.
4. Add health and non-blocking telemetry.
5. Extract transport-neutral application services.
6. Add OpenAPI capability behind the current auth path if needed.
7. Add OAuth as a second adapter.
8. Canary one client/resource/scope combination.
9. Register the API in Agent Gateway.
10. Migrate web login only as a separate, reversible change.
11. Retire legacy only after usage is zero and retention/rollback windows have passed.

## Evidence

The release must retain:

- compatibility test results;
- count of active legacy sessions before/after deploy;
- login, refresh, introspection and authorization success/error rates;
- consumer version matrix;
- feature-flag changes;
- migration and rollback timestamps;
- owner approval.

See `specs/legacy-compatibility.v1.yml` and `tests/platform-conformance/legacy/`.
