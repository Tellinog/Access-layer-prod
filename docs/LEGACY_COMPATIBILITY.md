# Legacy Compatibility

## Approved temporary Microsoft exception

`specs/legacy-contract-baseline.v1.json` remains the immutable historical Google baseline. D-045 adds `specs/legacy-microsoft-bridge.v1.yml` as a reversible exception without rewriting that evidence: selected tools may choose Microsoft at `/v1/auth/start`, and a conditional `/v1/auth/microsoft/callback` normalizes a verified Entra identity into the existing legacy identity shape.

The exception does not change exchange/JWT/refresh/introspection/logout contracts, TTLs, cookies, grants, database schema or consumers. All post-identity work uses the same code path. Google remains direct for non-allowlisted tools and for every tool when the bridge flag is false. Provider-prefixed state prevents a Microsoft request from being completed on the Google callback or vice versa.

Rollback requires only `LEGACY_MICROSOFT_ENABLED=false` and restart. Existing synthetic users are retained as inert audit/history records; no destructive data rollback or migration is required.

> Current status: the legacy runtime surface remains frozen in `../specs/legacy-contract-baseline.v1.json`. Step 3E adds the complete default-off OAuth P0 HTTP adapter outside `src/app.ts`; absent/false retains the exact legacy route inventory. Step 4A extends only the encrypted version-1 backup data sections while retaining legacy-only import compatibility. No production/pilot action exists. Dual-run material below remains a future constraint, not a passed N→N+1 result.

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

## Step 4A backup compatibility

The seven legacy version-1 backup sections remain mandatory and unchanged. Existing legacy-only backups still import and return only their original seven count keys. With merge semantics they leave OAuth rows untouched; with replace semantics they intentionally remove OAuth dependants before the existing legacy deletion sequence, then restore the older snapshot with zero OAuth rows.

A current full backup adds exactly all 17 `oauth_*` sections permitted by the existing additive data object. Export reads all 24 sections through one transaction-bound `REPEATABLE READ, READ ONLY` PostgreSQL snapshot. Partial OAuth section sets fail before writes. Full import remains one transaction and restores legacy parents before OAuth records, including two-pass credential rotation links whose owner-local chains must be acyclic and terminate at `NULL`, plus refresh generations that must equal exactly `0..current_generation`. Deterministic malformed-backup failures retain legacy `VALIDATION_ERROR`/400 classification through the unchanged global handler. `src/app.ts`, `/v1/*`, successful response shapes, the encrypted envelope/version, the historical OpenAPI and migrations 001–005 are unchanged.

This is repository-level import/export evidence, not the real PostgreSQL restore or N→N+1 evidence required by Step 4B and later gates.

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
