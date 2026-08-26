# Authentication and Authorization

## Selected target: additive OAuth authority, with OIDC provider functionality deferred

The frozen P0 target evolves Access Layer into:

- an OAuth authorization server;
- an identity broker to the approved upstream identity provider;
- the separate registry for OAuth clients, resource servers and scopes;
- the token, refresh, revocation and introspection authority.

Downstream OpenID Provider features (ID Token, UserInfo and OIDC discovery), service principals and token exchange are P1. Google OIDC remains the internal upstream human authentication mechanism and is not exposed as P0 downstream OIDC.

This is implemented **additively**. The current Access Layer remains available to existing tools while the new standard interface is introduced.

## Roles

```text
Natural person       resource owner / authenticated subject
Web BFF or agent      OAuth client
Project API or MCP    resource server
Access Layer          OAuth authorization server (future P1 OpenID Provider)
Upstream Google OIDC  external identity provider
```

A current Access Layer `tool` must not continue to represent all of these roles in the new model. Client and resource registration are separate.

Every P0 resource has exactly one `legacy_tool` entitlement-only binding so the current grant model remains authoritative. The bound tool is not implicitly the OAuth client or resource. Native OAuth entitlement domains are deferred beyond P0.

## New project defaults

### Web

P0 target: OAuth Authorization Code flow through a backend-for-frontend.

- PKCE `S256` required;
- verifier syntax is 43–128 RFC 7636 unreserved characters and the S256 challenge is exactly 43 unpadded base64url characters;
- state and nonce required;
- exact redirect URI matching;
- tokens remain server-side;
- browser receives only an opaque, `HttpOnly`, `Secure`, `SameSite=Lax` local session cookie;
- session and refresh material is encrypted at rest;
- CSRF protection is required for mutations.
- the human OAuth `sub` is the stable Google `sub`;
- OAuth tokens exclude email/profile claims by default.
- the exact downstream client state uses short-lived reversible protected storage and is never logged; upstream Google state/nonce remain separately hashed.

During transition, web may continue using the current legacy flow.

### API and MCP

Target: OAuth resource server.

- bearer token only in `Authorization` header;
- issuer, signature, expiry, resource/audience, client and scope validated;
- `401` for absent/invalid/expired token;
- `403` and `insufficient_scope` for a valid token without the required scope;
- tokens for another resource are rejected;
- received tokens are not forwarded to downstream services;
- high-risk capabilities force online policy/introspection according to policy.

### Machine identity (P1)

Use client credentials only for a registered service principal. A service principal never impersonates a human or uses a synthetic email.

### Delegated agents (P1)

When Agent Gateway calls a downstream project on behalf of a human, the final token must be audience-bound to the downstream project and preserve subject and actor separately. Direct forwarding of a gateway-audience token is forbidden. Token exchange is a later central capability, not project-specific code.

## Canonical capability and scope

The common identifier is hierarchical and colon-separated:

```text
project:domain:action
```

Example:

```text
test-generator:test:generate
```

It is used as:

- `capability_id`;
- Access Layer permission key;
- OAuth scope;
- telemetry dimension;
- audit subject.

OpenAPI `operationId` and MCP tool names map explicitly to it because their naming conventions differ.

The normative P0 contract, token transport, errors, registrations, refresh-family replay and key rotation are in `OAUTH_P0_CONTRACT.md` and `../specs/oauth-p0.v1.yml`.

## Introspection policy

Default: local JWT validation plus a bounded introspection cache. P0 introspection uses `client_secret_basic` with a separately authorised credential owned by one OAuth resource, not an OAuth client or legacy tool client. It discloses an RFC 9068 access token as active only when the token's exact `aud` equals that credential's resource; audience mismatches, refresh tokens and other non-disclosable tokens return exactly `{"active":false}`. Online introspection is mandatory for:

- administrative mutations;
- sensitive data export;
- permission or security changes;
- irreversible writes;
- capabilities classified `high` or `critical`;
- anomalous or revoked sessions.

The revocation window must be documented. Failure behavior is deny-by-default for operations requiring online policy.

## Refresh policy

- refresh only while processing authenticated user activity;
- never refresh through a timer, cron, hidden browser heartbeat or inactive page;
- rotate refresh tokens atomically;
- serialize concurrent refreshes across all replicas through database compare-and-swap, a database lock or equivalent distributed coordination;
- replay of a used refresh token revokes the token family;
- refresh cannot expand scope, change resource, change client or change subject;
- refresh failure destroys the local session and requires login; never retry the same rejected token.

## Required server-side request context

Authentication adapters produce one context before application services run. See `schemas/request-context.schema.json`.

## Registration artefacts

Examples are available in `examples/access-layer/` for:

- current legacy tool registration;
- OAuth client registration;
- OAuth resource registration;
- protected-resource metadata;
- token claims.

## Do not implement protocol handlers independently in every project

Use the official UNGUESS Platform SDK authentication packages when they are available. Until then, keep project code behind the contracts in `platform/reference/typescript/` and do not copy one project’s concrete session code into another project without a shared package and compatibility tests.
