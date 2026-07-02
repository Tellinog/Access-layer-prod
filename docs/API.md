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
| `/v1/auth/introspect` | Tool client credentials |
| `/v1/auth/logout` | Tool token or admin/user session |
| `/v1/me` | Access Layer JWT or admin session |
| `/v1/admin/*` | Platform admin role, or delegated tool admin where explicitly allowed |
| `/v1/.well-known/jwks.json` | Public |

## Endpoints

| Method | Path | Purpose | Auth required | Notes |
|---|---|---|---:|---|
| GET | `/health` | Health check | No | Includes DB status in non-public detail mode |
| GET | `/v1/auth/start` | Start login for a tool | No | Requires `tool_slug`, `return_url`, `state` |
| GET | `/v1/auth/google/callback` | Receive Google callback | Google state | Internal endpoint for OAuth redirect |
| POST | `/v1/auth/exchange` | Exchange one-time code for identity/token | Tool client | Consumes code once |
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
