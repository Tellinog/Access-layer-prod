# Access Layer OAuth/OIDC Authorization Server Profile

Status: target platform contract
Version: 1
Last reviewed: 2026-08-17

## Scope

This document defines the central service assumed by the template. It is not implemented by each project.

## Required additive surfaces

The legacy `/v1/auth/*` interface remains operational. New standard surfaces are added:

```text
/.well-known/oauth-authorization-server
/.well-known/openid-configuration          when OIDC is enabled
/oauth/authorize
/oauth/token
/oauth/revoke
/oauth/introspect
/oauth/jwks
/oauth/userinfo                             when OIDC is enabled
```

Resource servers publish RFC 9728 protected-resource metadata.

## P0 protocol profile

- OAuth 2.1 draft profile with Authorization Code and Refresh Token grants;
- PKCE `S256` for all authorization-code clients;
- exact redirect URI matching;
- public and confidential clients;
- RFC 8414 discovery;
- RFC 8707 resource indicators and audience-bound access tokens;
- RFC 9068 JWT access-token profile;
- RFC 7009 revocation;
- RFC 7662 introspection;
- RFC 9700 security BCP controls;
- refresh-token rotation and token-family replay detection;
- pre-registered first-party clients and resources;
- key rotation without invalidating still-valid tokens.

## P1 profile

- client credentials and governed service-principal lifecycle;
- OpenID Connect login and UserInfo;
- `private_key_jwt` for strategic confidential clients;
- Client ID Metadata Documents for compatible remote MCP clients;
- token exchange for Agent Gateway delegation, with subject and actor separation and downscoping only.

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
