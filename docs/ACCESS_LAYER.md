# Access Layer integration

## Decision

Access Layer is mandatory. The target architecture is **Proposal B**: Access Layer itself evolves additively into the OAuth authorization server while continuing to broker upstream Google OIDC. Downstream OpenID Provider functionality is P1. The current legacy protocol remains available side by side.

## Supported profiles

### `access-layer-legacy-v1`

Used by existing tools. The frozen endpoints are:

- `GET /v1/auth/start`;
- `GET /v1/auth/google/callback`;
- `POST /v1/auth/exchange`;
- `POST /v1/auth/refresh`;
- `POST /v1/auth/introspect`;
- `POST /v1/auth/logout`;
- `GET /v1/.well-known/jwks.json`.

The project must preserve the current behavior of callback allowlisting, one-time code exchange, tool client Basic authentication, tool-scoped JWTs, rotating refresh tokens, local server-side sessions and grant permissions.

### `unguess-oauth-oidc-v1`

The target standard profile includes:

- OAuth authorization-server metadata;
- authorization code with PKCE `S256`;
- confidential clients plus a public-client contract whose rollout is disabled;
- resource indicators and audience binding;
- JWT access tokens following the selected platform profile;
- refresh rotation and replay detection;
- revocation and introspection;
- active introspection only for RFC 9068 access tokens presented by separately authorised resource servers;
- protected-resource metadata for MCP/API resources;
- client credentials for service principals after the core release;
- token exchange only after explicit platform approval.

The frozen P0 contract is `OAUTH_P0_CONTRACT.md`. OpenID Provider discovery, ID Tokens and UserInfo are P1/deferred and must not appear in P0 metadata.

Every P0 resource requires exactly one legacy-tool entitlement-only binding while OAuth client and resource identities remain separate. The future internal Google callback is `/oauth/upstream/google/callback`, additive to and distinct from the frozen legacy callback. Neither it nor any OAuth runtime path is implemented in Step 2.

## Legacy compatibility invariant

Introducing OAuth/OIDC must not alter, before an explicit consumer migration:

- endpoint paths or HTTP methods;
- request and response field names;
- legacy JWT claims or audience rules;
- session and idle-expiry behavior;
- refresh-token validity and rotation behavior;
- grant evaluation;
- callback matching;
- tool client IDs/secrets;
- signing and encryption keys needed by existing consumers;
- existing database records.

## Existing session survival

A required acceptance scenario is:

1. create a legacy tool session on Access Layer version N;
2. deploy Access Layer vNext with OAuth disabled;
3. use the existing local session;
4. introspect the existing token;
5. refresh with the existing refresh token;
6. logout;
7. verify no re-grant or data migration was required.

Rollback to the previous release must also remain possible during the additive phase.

## Project integration requirement

Projects do not implement Access Layer protocol logic independently when approved UNGUESS Platform SDK authentication packages exist. Existing Access Layer permission keys remain canonical by default. When a deployed key cannot match the new capability ID, define an explicit, versioned source-to-target mapping in `specs/permissions.v1.yml`; do not rewrite the live grant or token during the compatibility phase.

They integrate one or both adapters:

```text
LegacyAuthAdapter ----+
                      +--> RequestContext --> Application core
OAuthResourceAdapter -+
```

## Risk-based introspection

Default policy:

| Operation | Local validation | Online introspection |
|---|---:|---:|
| Normal read | Required | Cached, short maximum age |
| Low-risk write | Required | Cached or immediate by project policy |
| Admin/security/export-sensitive | Required | Immediate |
| Irreversible/high-risk | Required | Immediate and confirmation where applicable |

The revocation window must be explicit in `project.platform.yaml`.

## Registration data

Every project registers:

- project/tool slug;
- owner;
- exact callback URLs;
- resource identifier;
- OAuth client metadata where applicable;
- capability scopes;
- data classification;
- status and environment.

## Forbidden patterns

- client secrets in browser bundles;
- wildcard redirect URLs;
- access or refresh tokens in query strings;
- accepting a token without checking audience;
- forwarding a received token to a different resource;
- background refreshes that keep inactive sessions alive;
- in-memory-only refresh locks in a multi-replica deployment;
- deleting legacy tables or keys during the OAuth introduction release.
