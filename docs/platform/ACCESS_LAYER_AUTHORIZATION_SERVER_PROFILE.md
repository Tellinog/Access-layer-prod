# Access Layer OAuth/OIDC Authorization Server Profile

Status: P0 contract frozen; runtime not implemented
Version: 1
Last reviewed: 2026-08-17

## Scope

This document defines the central service assumed by the template. It is not implemented by each project.

## Required additive surfaces

The legacy `/v1/auth/*` interface remains operational. New standard surfaces are added:

```text
/.well-known/oauth-authorization-server
/oauth/authorize
/oauth/token
/oauth/revoke
/oauth/introspect
/oauth/jwks
```

Resource servers publish RFC 9728 protected-resource metadata.

## P0 protocol profile

- stable RFC contract aligned with the OAuth 2.1 work-in-progress draft, using Authorization Code and Refresh Token grants;
- PKCE `S256` for all authorization-code clients;
- RFC 7636 verifier grammar and an exact 43-character unpadded base64url S256 challenge;
- exact redirect URI matching;
- confidential clients and a public-client code-flow contract whose production rollout is disabled;
- RFC 8414 discovery;
- RFC 8707 resource indicators and audience-bound access tokens;
- RFC 9068 JWT access-token profile;
- RFC 7009 revocation;
- RFC 7662 introspection;
- access-token-only active introspection through separate resource-owned `client_secret_basic` credentials, with exact token-audience matching;
- RFC 9700 security BCP controls;
- refresh-token rotation and token-family replay detection;
- pre-registered first-party clients and resources;
- exactly one legacy-tool entitlement-only binding for every P0 resource;
- exactly one explicit legacy permission mapping for every registered resource scope, with no inferred rewriting;
- key rotation without invalidating still-valid tokens.

The Access Layer-specific normative profile is `../../specs/oauth-p0.v1.yml`; `../OAUTH_P0_CONTRACT.md` is its human-readable design. Human token `sub` is Google `sub`, OAuth signing keys are isolated from legacy keys, and browser applications retain BFF/server-side token storage. The internal upstream Google callback is `/oauth/upstream/google/callback`; it is not advertised as a protocol endpoint and never reuses the frozen legacy callback.

## P1 profile

- client credentials and governed service-principal lifecycle;
- OpenID Connect login and UserInfo;
- `private_key_jwt` for strategic confidential clients;
- Client ID Metadata Documents for compatible remote MCP clients;
- token exchange for Agent Gateway delegation, with subject and actor separation and downscoping only.
- OpenID Provider discovery, ID Tokens and UserInfo.

## Explicit exclusions from the initial release

- implicit grant;
- resource owner password grant;
- wildcard redirect URIs;
- bearer token in query strings;
- PKCE `plain`;
- automatic Dynamic Client Registration unless a real interoperability need is approved;
- multi-audience access tokens by default;
- forwarding a token to a different resource.

## Compatibility gate

No OAuth/OIDC release may be deployed unless the legacy compatibility suite passes against current consumer contracts and pre-upgrade sessions.
