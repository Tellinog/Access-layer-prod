# OAuth vNext P0 contract

Status: frozen target contract; not implemented or enabled
Machine source: `../specs/oauth-p0.v1.yml`
Target OpenAPI: `../schemas/access-layer-oauth-v1.openapi.yaml`

## Boundary and compatibility

P0 is an additive OAuth authorization-server contract. It creates no runtime endpoint, table, migration, dependency, client registration or production configuration in Step 2. The frozen `access-layer-legacy-v1` contract remains authoritative for `/v1/*`, Google callback, JWT/JWKS, sessions, refresh tokens, grants, permissions, cookies, tool clients, Admin UI and current consumers. OAuth failure must never silently fall back to legacy credentials, and no consumer is forced to migrate.

Stable RFCs are normative: RFC 6749 where applicable, RFC 6750, RFC 7636, RFC 7009, RFC 7662, RFC 8414, RFC 8707, RFC 9068, RFC 9207, RFC 9700, RFC 9728 and RFC 10017. OAuth 2.1 is an aligned work-in-progress draft profile, not a published RFC.

## P0 and deferred capabilities

| Area | P0 frozen contract | P1/deferred |
|---|---|---|
| Grants | Authorization Code, Refresh Token | `client_credentials`, RFC 8693 token exchange |
| PKCE | Required for every code flow; `S256` only | `plain` is forbidden |
| Clients | Controlled confidential registration; public code-client contract with rollout disabled | dynamic registration, Client ID Metadata Documents, `private_key_jwt` |
| Browser | BFF/server-side tokens and opaque local session cookie | SPA/browser bearer-token model |
| Identity | Human authorization; Google `sub` is OAuth `sub` | service principals, OIDC ID Token/UserInfo |
| Extensions | RFC 8707 resource and exact single audience | PAR, JAR, DPoP, multi-audience tokens |

## Authorization request and response

`GET /oauth/authorize` accepts only `response_type=code`. It requires a registered `client_id`, an exact registered `redirect_uri`, client `state`, a space-delimited capability `scope`, one registered HTTPS `resource`, and PKCE `code_challenge` with `code_challenge_method=S256`. The verifier grammar is exactly 43–128 RFC 7636 unreserved characters (`[A-Za-z0-9._~-]`); the stored S256 challenge is exactly 43 unpadded base64url characters (`[A-Za-z0-9_-]`). `plain`, padding `=`, whitespace and other characters are invalid.

The authorization code is high entropy, hashed at rest, single-use, valid for 60 seconds, and atomically bound to client, redirect URI, resource, granted scopes, human subject and PKCE challenge. The Access Layer-to-Google transaction uses separate server-side state and nonce; downstream client state is never reused as Google state. The exact downstream state is retained only in short-lived reversible protected storage until the authorization response is emitted, with an optional lookup hash; it is never logged. Upstream Google state and nonce remain hash-only.

Google returns OAuth vNext upstream transactions to the separate internal path `/oauth/upstream/google/callback`. This path is not an advertised OAuth protocol endpoint and is not implemented in Step 2. It must not reuse or extend the frozen `/v1/auth/google/callback`. Before a future OAuth rollout, production Google configuration adds the new URI while retaining the existing legacy URI.

A successful redirect contains only `code`, the original `state`, and RFC 9207 `iss=https://access-layer.unguess-internal.net`. A redirectable OAuth error preserves safe `state` and includes `iss`. If the client or redirect URI cannot be trusted, Access Layer returns a local error and does not redirect. Access and refresh tokens never appear in browser URLs.

## Token endpoint and client authentication

`POST /oauth/token` accepts only `application/x-www-form-urlencoded`.

- `authorization_code` requires the code, exact redirect URI, `client_id`, PKCE verifier and the same single `resource`.
- `refresh_token` requires the rotating refresh credential, `client_id` and the original resource; requested scope may only stay equal or narrow.
- Confidential first-party clients authenticate with `client_secret_basic`.
- Public clients use method `none` only when explicitly registered. Public-client production rollout remains disabled until a concrete consumer is approved.

Token responses use `Cache-Control: no-store` and `Pragma: no-cache`. The first-party browser architecture remains a BFF: OAuth tokens and refresh material stay server-side; the browser receives only an opaque `HttpOnly`, `Secure`, `SameSite=Lax` or stricter local session cookie.

## Resource, audience, scope and entitlement

The RFC 8707 `resource` value is a canonical registered HTTPS URI. P0 accepts exactly one resource at authorization and token endpoints. The RFC 9068 JWT `aud` claim is one string exactly equal to that resource. A resource server rejects tokens for any other audience.

Business scopes have exactly three colon-separated identifiers:

```text
project:domain:action
```

A scope is granted only when it is registered for the resource, allowed for the client/resource relationship, present in the human's effective existing grant/permission entitlement, and allowed by central policy. The result is the intersection of those sets. Unknown or unauthorized scope fails closed as `invalid_scope`; aliases require an explicit versioned mapping.

OAuth client identity and resource identity are separate. Every P0 resource registration requires exactly one `legacy_tool` entitlement binding so existing grants and registered permissions remain authoritative. The bridge is entitlement-only: the legacy `tool` is never implicitly the OAuth client or the OAuth resource, and no legacy record changes. Native OAuth entitlement domains are deferred beyond P0.

P0 is an internal, centrally administered first-party service. Existing admin-managed grants determine entitlement; Step 2 introduces no user-consent product model.

## Human JWT access token

P0 uses the RFC 9068 JWT access-token profile and a dedicated OAuth key ring.

- JOSE header: `alg=RS256`, required unique `kid`, `typ=at+jwt`.
- Required claims: `iss`, `sub`, `aud`, `client_id`, `iat`, `exp`, `jti`, `scope`, `principal_type=human`.
- `sub` is the stable Google `sub` from `users.google_sub`, preserving D-004. It is never email or local UUID.
- `aud` is the exact single resource URI; `scope` is a space-delimited string.
- `nbf` and `sid` are optional profile claims.
- Default lifetime is 900 seconds.

OAuth access tokens exclude `email`, `hd`, display/profile data, legacy `role` and legacy `permissions` by default. A future resource-specific identity attribute requires a separate privacy/security contract. Scopes carry business authorization.

Protected resources accept bearer access tokens only in `Authorization: Bearer`. Bearer tokens in query parameters, form bodies or application cookies are forbidden. Standard token, revocation and introspection form parameters are endpoint credentials, not protected-resource bearer transport. A missing/invalid token returns HTTP 401 with a Bearer `WWW-Authenticate` challenge and `invalid_token`; a valid token lacking scope returns HTTP 403 with `insufficient_scope`. Challenges include the applicable RFC 9728 `resource_metadata` URL.

RFC 9700 controls are explicit: implicit and password grants, authorization-server/client open redirects, token forwarding, privilege expansion and multi-audience tokens are forbidden; PKCE plus RFC 9207 issuer identification mitigate code injection/mix-up; TLS is mandatory except an explicitly registered loopback development redirect; refresh rotation/replay detection and least-privilege resource/scope binding are mandatory.

## Refresh-token family and replay

OAuth refresh tokens are opaque and stored only as non-reversible hashes. Every valid use is an atomic compare-and-rotate operation in shared transactional storage. Families record lineage, current/consumed state, client, subject, resource, authorization and session.

Refresh occurs only while processing authenticated user activity. Timers, cron jobs, hidden heartbeats and inactive pages may not keep a session alive. The idle timeout is 28,800 seconds, matching D-029. Refresh cannot change subject, client or resource and cannot expand scope.

Use of an already-consumed family member is replay: deny the request with `invalid_grant`, revoke the complete family and linked OAuth session, and emit the replay audit event. Online introspection becomes inactive immediately; already-issued self-contained access tokens remain cryptographically valid until expiry unless the resource's risk policy requires online state.

## Revocation and introspection

`POST /oauth/revoke` follows RFC 7009. It is authenticated according to the registered client method and is idempotent from the caller's perspective: unknown, expired and already-revoked tokens return the same successful external response. Revoking an access token records its `jti` as inactive for online state. Revoking a refresh token revokes its complete family and linked OAuth session. Offline validation of a self-contained access token can continue only until its original expiry unless resource risk policy requires online introspection.

`POST /oauth/introspect` follows RFC 7662 and requires separately authorised resource-server credentials. P0 discloses only audience-authorised RFC 9068 Bearer access tokens as active. An OAuth refresh token is never returned as active through this surface; refresh-token lifecycle remains available only through token refresh and RFC 7009 revocation. For an unknown, inactive, refresh or otherwise non-disclosable token, an authenticated caller receives exactly `{"active":false}` with no reason or other fields. Invalid caller credentials use HTTP 401. Active responses use `Cache-Control: no-store`.

## Metadata and key rotation

RFC 8414 metadata is at `/.well-known/oauth-authorization-server` and advertises only P0 protocol endpoints. The internal Google callback is not advertised. RFC 9728 protected-resource metadata identifies the exact resource, Access Layer issuer, registered scopes and header-only bearer method. OIDC discovery and UserInfo are not advertised.

OAuth keys are isolated behind `/oauth/jwks`; legacy `/v1/.well-known/jwks.json` and its key material remain untouched. Rotation rules are:

1. publish a new public key at least 300 seconds before activation;
2. never reuse a `kid` for different key material;
3. serve OAuth JWKS with a 300-second maximum cache age;
4. allow at most 60 seconds verifier clock skew;
5. keep an old verification key for at least 1,260 seconds after its last signature (900-second token lifetime + 300-second JWKS cache + 60-second skew);
6. keep all private key material out of Git, logs and evidence.

## Errors

OAuth endpoints use interoperable OAuth fields: `error`, optional safe `error_description`, optional `error_uri`, and optional `correlation_id`. Supported names are `invalid_request`, `invalid_client`, `invalid_grant`, `unauthorized_client`, `unsupported_grant_type`, `invalid_scope`, RFC 8707 `invalid_target`, `access_denied`, `unsupported_response_type`, RFC 7009 `unsupported_token_type`, `server_error` and `temporarily_unavailable`. `invalid_client` uses HTTP 401 and an appropriate `WWW-Authenticate` challenge; other token endpoint protocol failures use HTTP 400.

The legacy `/v1/*` error envelope and status mapping remain unchanged.

## Audit and secret handling

Authorization requests/decisions, code issue/exchange/denial, refresh, replay, revocation, introspection, registration changes and signing-key lifecycle changes require structured audit events with correlation ID, outcome, client ID, resource ID, scope identifiers and stable human subject when known.

Never log or persist in audit metadata raw authorization codes, access tokens, refresh tokens, client secrets, cookies, private keys, PKCE verifiers, downstream client state, raw secret-bearing request bodies or reusable secret verifiers. Inactive-token reasons and secret hashes are not audit-facing identifiers.

## Future dark rollout and rollback

The first OAuth-capable binary must start with legacy `/v1/*` enabled, OAuth globally disabled, no enabled client, no legacy key/secret rotation and only backward-compatible additive schema. It must roll back immediately to the previous image without losing legacy or new rows. OAuth is then enabled for an explicit reviewed client/resource/scope pilot only. Invalid OAuth credentials are rejected as OAuth; the service never tries legacy credentials as fallback. Any per-client disable restores the pre-change traffic path without deleting OAuth state.
