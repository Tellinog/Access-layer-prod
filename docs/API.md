# API.md

## API principles

- Versioned under `/v1`.
- JSON payloads for API endpoints.
- Redirect endpoints may return HTTP redirects or error pages.
- Server-to-server endpoints require tool client authentication.
- Admin endpoints require Access Layer admin session/token.
- Every endpoint that makes an access decision writes an audit event.

## Authentication requirements

| API area | Required auth |
|---|---|
| `/health` | None |
| `/v1/auth/start` | None, but tool and return URL must be valid |
| `/v1/auth/google/callback` | Google OAuth callback plus server-side state validation |
| `/v1/auth/exchange` | Tool client credentials |
| `/v1/auth/refresh` | Tool client credentials |
| `/v1/auth/introspect` | Tool client credentials |
| `/v1/auth/logout` | Tool token or admin/user session |
| `/v1/me` | Access Layer JWT or admin session |
| `/v1/admin/*` | Platform admin role, or delegated tool admin where explicitly allowed |
| `/v1/.well-known/jwks.json` | Public |
| OAuth metadata/JWKS | Public, only when `OAUTH_P0_ENABLED=true` |
| `/oauth/authorize` and OAuth upstream callback | Validated OAuth/Google transaction, only when enabled |
| `/oauth/token`, `/oauth/revoke` | Registered OAuth client Basic or registered public `none` method, only when enabled |
| `/oauth/introspect` | Resource-owned OAuth Basic credential, only when enabled |

## Step 3B default-off read-only OAuth routes

These routes exist only when `OAUTH_P0_ENABLED=true`; absent/false returns 404 and leaves the legacy inventory unchanged.

| Method | Path | Result |
|---|---|---|
| GET | `/oauth/jwks` | Dedicated validated OAuth public verification keys; `Cache-Control: public, max-age=300`. Returns sanitized HTTP 503 `{ "error": "temporarily_unavailable" }` when no safe key exists. |
| GET | `/.well-known/oauth-protected-resource/v1` | RFC 9728 metadata for `https://access-layer.unguess-internal.net/v1` and header-only Bearer transport; with no pilot scopes, `scopes_supported` is omitted. |

Both Step 3B paths are GET-only; Fastify's automatic `HEAD` siblings are disabled and return 404. At the Step 3B boundary, RFC 8414 remained unregistered. Step 3E now mounts it only alongside every endpoint it advertises. The legacy `/v1/.well-known/jwks.json` endpoint is a separate unchanged key domain.

## Step 3C default-off authorization issuance routes

These additional routes exist only when `OAUTH_P0_ENABLED=true` and are also GET-only with explicit HEAD 404:

| Method | Path | Result |
|---|---|---|
| GET | `/oauth/authorize` | Validates the frozen code/PKCE/resource/scope request, persists a protected 600-second transaction and redirects to the separate Google flow. |
| GET | `/oauth/upstream/google/callback` | Atomically claims Google state, validates identity/nonce and current exact entitlement, then redirects an opaque 60-second code, exact state and `iss` to the stored redirect. |

Untrusted client or redirect input receives a local OAuth JSON error and is never redirected. After exact redirect trust, protocol errors use only `error`, exact safely retained `state` and exact `iss`; no verbose description is added. Success adds only `code`, exact state and issuer to any safe pre-registered query parameters. Automatic request logging is disabled for both paths.

At the Step 3C boundary, `/oauth/token`, `/oauth/revoke`, `/oauth/introspect` and RFC 8414 remained 404. Step 3E supersedes only that historical mounting state; Step 3C authorization semantics are unchanged.

## Step 3D unmounted token-lifecycle core

Step 3D implements the internal repository/service behavior for code exchange, OAuth client/resource credential verification, dedicated-key access-token signing, refresh rotation/replay, revocation and introspection. Revocation and introspection `token_type_hint` values are advisory: a wrong or unknown revocation hint cannot prevent lookup of the other supported token class, and introspection ignores the hint without widening its access-token-only active disclosure. Access-token jti revocation is retained through `exp` plus the frozen 60-second verifier clock-skew window. Step 3D itself added no Fastify registration; Step 3E mounts this unchanged core.

## Step 3E strict default-off OAuth HTTP surface

All Step 3E routes remain absent/404 when `OAUTH_P0_ENABLED` is absent/false. When true, they are added to the existing Step 3B/3C surface:

| Method | Path | Result |
|---|---|---|
| GET | `/.well-known/oauth-authorization-server` | Exact issuer-preserving RFC 8414 metadata; `Cache-Control: public, max-age=300`; no automatic HEAD. |
| POST | `/oauth/token` | Authorization-code exchange or activity-driven refresh; exact token wire fields, `Cache-Control: no-store`, `Pragma: no-cache`. |
| POST | `/oauth/revoke` | RFC 7009 idempotent non-disclosing revocation; `Cache-Control: no-store`. |
| POST | `/oauth/introspect` | RFC 7662 access-token-only exact-audience disclosure; inactive output is exactly `{"active":false}`; `Cache-Control: no-store`. |

The POST routes accept only `application/x-www-form-urlencoded`, bounded to 16 KiB. Malformed percent/UTF-8 encoding, duplicates, unsupported fields, missing/empty required fields and other media types return sanitized OAuth errors. OAuth Basic uses canonical Base64 and form-decoded credential components. The form body never accepts `client_secret`; Bearer and legacy tool credentials are never fallback authentication.

Confidential token/revocation callers use registered OAuth client Basic credentials and the Basic username must match token-form `client_id` when both are present. Registered public clients may use only their frozen `none` method with form `client_id`. Introspection always requires resource-owned Basic credentials whose username is `credential_id`.

`invalid_client` returns 401 with `WWW-Authenticate: Basic realm="oauth"`; `invalid_request`, `unsupported_grant_type`, `invalid_grant`, `invalid_scope` and `invalid_target` return 400; `temporarily_unavailable` returns 503. Every OAuth error is sanitized and `no-store`. Code exchange, refresh, revocation and introspection have separate bounded rate limits; raw codes/tokens never enter their keys.

## Endpoints

| Method | Path | Purpose | Auth required | Notes |
|---|---|---|---:|---|
| GET | `/health` | Health check | No | Includes DB status in non-public detail mode |
| GET | `/v1/auth/start` | Start login for a tool | No | Requires `tool_slug`, `return_url`, `state` |
| GET | `/v1/auth/google/callback` | Receive Google callback | Google state | Internal endpoint for OAuth redirect |
| POST | `/v1/auth/exchange` | Exchange one-time code for identity/token | Tool client | Consumes code once |
| POST | `/v1/auth/refresh` | Rotate refresh token and renew access/session | Tool client | Sliding renewal on authenticated activity |
| POST | `/v1/auth/introspect` | Validate token online | Tool client | Returns active/inactive and identity |
| POST | `/v1/auth/logout` | Revoke Access Layer session/token | Tool client or user | Clears central session state |
| GET | `/v1/me` | Return current identity | User token | Tool-scoped view |
| GET | `/v1/.well-known/jwks.json` | Public signing keys | No | Used for JWT verification |
| GET | `/v1/admin/tools` | List tools | Admin | Filter by search/status/owner; includes registered permission keys |
| POST | `/v1/admin/tools` | Create tool | Admin | Generates client credentials once; returns registered permission keys |
| PATCH | `/v1/admin/tools/{tool_id}` | Update tool | Admin | Includes description, return URLs, status and permission keys |
| DELETE | `/v1/admin/tools/{tool_id}` | Delete tool | Platform admin | Deletes non-reserved tool registration and cascades linked grants/sessions/requests; audit logs are preserved |
| POST | `/v1/admin/tools/{tool_id}/rotate-secret` | Rotate tool secret | Admin | Overlap old/new if configured |
| GET | `/v1/admin/users` | List users | Admin | Search by email/sub/status |
| PATCH | `/v1/admin/users/{user_id}` | Update user status | Admin | Disable/suspend/reactivate; non-active status revokes active sessions |
| GET | `/v1/admin/grants` | List grants | Admin | Filter by tool/user/email/status |
| GET | `/v1/admin/grants/export` | Export grants CSV | Admin/tool admin | Export current grant rows scoped by actor |
| GET | `/v1/admin/grants/bulk/template` | Download grant bulk CSV template | Admin/tool admin | Template for operational bulk import |
| POST | `/v1/admin/grants/bulk/preview` | Preview grant bulk CSV | Admin/tool admin | Validates rows without writing data |
| POST | `/v1/admin/grants/bulk/commit` | Commit grant bulk CSV | Admin/tool admin | Applies only when preview has no errors; writes audit events |
| GET | `/v1/admin/tools/permissions/export` | Export tool permission catalog CSV | Admin/tool admin | Shows tool slugs and registered permission keys scoped by actor |
| GET | `/v1/admin/access-requests` | List access requests | Admin/tool admin | Filter by status/tool/email/date |
| POST | `/v1/admin/grants` | Create grant | Admin | User ID or email required |
| PATCH | `/v1/admin/grants/{grant_id}` | Update/revoke grant | Admin | Writes audit event |
| POST | `/v1/admin/access-requests/{request_id}/approve` | Approve access request | Admin/tool admin | Creates grant and marks request approved |
| POST | `/v1/admin/access-requests/{request_id}/reject` | Reject access request | Admin/tool admin | Stores optional note and marks request rejected |
| POST | `/v1/admin/access-requests/{request_id}/close` | Close access request | Admin/tool admin | For duplicates/tests without creating grant |
| GET | `/v1/admin/audit-logs` | Query logs | Admin/auditor | Filter by date, tool, email, Google sub, outcome, reason code or correlation ID |
| GET | `/v1/admin/backup/export` | Export encrypted backup | Admin or backup API token | Requires `admin:backup:read` for admin sessions |
| GET | `/v1/admin/backup/secret-material` | Export restore secret material | Platform admin | Requires `admin:backup:secrets`; does not include per-tool plaintext client secrets |
| POST | `/v1/admin/backup/import` | Import encrypted backup | Platform admin | Requires `admin:backup:write`; destructive replace requires confirmation |

## Error model

All JSON API errors use this shape:

```json
{
  "error": {
    "code": "AUTH_NOT_AUTHORIZED_FOR_TOOL",
    "message": "Utente non autorizzato per il tool richiesto.",
    "correlation_id": "01HY...",
    "details": {}
  }
}
```

See:

- `docs/ERROR_CODES.md`
- `docs/ERROR_MESSAGES.md`

## Versioning

- Current API version: `v1`.
- Breaking changes require a new major path, e.g. `/v2`.
- Additive fields are allowed if documented in `schemas/openapi.yaml` and examples.
- Deprecations require documentation in `CURRENT_STATE.md` and `DEVLOG.md`.

## Additive OAuth P0 target

The complete OAuth surface is documented separately in `../schemas/access-layer-oauth-v1.openapi.yaml` and `OAUTH_P0_CONTRACT.md`. With the optional flag true, the current dark runtime registers the two Step 3B reads, two Step 3C issuance paths and four Step 3E routes above; absent/false remains fully dark. Step 3A's zero-route, Step 3B's read-only state and Step 3D's unmounted state are historical phase boundaries. The historical `../schemas/openapi.yaml` and frozen `/v1/auth/google/callback` remain unchanged.
# Step 1 machine baseline

The exhaustive repository-observed route and wire-contract freeze is `../specs/legacy-contract-baseline.v1.json`. It records one known documentation drift: runtime registers `GET /v1/admin/backup/secret-material`, while the historical `../schemas/openapi.yaml` omits it. Step 1 changes neither side.
