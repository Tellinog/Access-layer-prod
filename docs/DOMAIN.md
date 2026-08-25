# DOMAIN.md

## Domain language

| Term | Meaning |
|---|---|
| Access Layer | Central service responsible for Google login, tool authorization, token issuing and audit logs |
| Tool | Internal web application that delegates access to Access Layer |
| Tool slug | Stable unique identifier for a tool, e.g. `crm`, `reporting`, `intranet-admin` |
| Tool client | Server-side credential pair used by a tool backend to call Access Layer |
| User | Google account recognized by Access Layer after ID token validation |
| Google sub | Stable Google Account subject claim, used as primary identity key |
| Hosted domain / hd | Google ID token claim indicating Workspace/Cloud organization domain |
| Grant | Authorization that allows a user or pending email to access a tool with roles/permissions |
| One-time code | Short-lived code sent to the tool callback and exchanged server-to-server |
| Access token | Short-lived JWT issued by Access Layer for a specific user/tool/session |
| Refresh token | Opaque, single-use server-side credential used to rotate the access token and extend an active session |
| Introspection | API call by a tool backend to check whether an Access Layer token is still active |
| Audit event | Structured log entry for access attempts, decisions and admin actions |
| OAuth client | Software registered to request tokens; distinct from a legacy tool and from the resource |
| OAuth resource | Canonical HTTPS API/MCP audience receiving a token; may explicitly bind to a legacy tool entitlement domain |
| OAuth scope | Canonical `project:domain:action` capability granted by the fail-closed intersection policy |
| Refresh family | Lineage of rotating OAuth refresh tokens; replay revokes the family and linked OAuth session |

## Core entities

### User

Represents a verified Google account.

Required fields:

- `id`: internal UUID
- `google_sub`: stable Google subject
- `email`: current email from Google
- `email_normalized`: lowercase email
- `email_verified`: boolean
- `hd`: hosted domain claim
- `display_name`: optional
- `picture_url`: optional
- `status`: `active`, `suspended`, `disabled`
- `first_seen_at`, `last_seen_at`

### Tool

Represents an internal application.

Required fields:

- `id`: internal UUID
- `slug`: unique stable identifier
- `display_name`
- `status`: `active`, `disabled`, `maintenance`
- `allowed_return_urls`: exact URLs or strict patterns approved by admins
- `client_id`: public identifier for tool backend
- `client_secret_hash`: hashed secret for server-to-server authentication
- `created_at`, `updated_at`

### Grant

Allows a user or pending email to access a tool.

Required fields:

- `id`
- `tool_id`
- `user_id`: nullable until first Google login if created by email
- `email_normalized`: nullable but required for pending grants
- `role`: primary role label for the tool
- `permissions`: JSON array of permission keys
- `status`: `active`, `revoked`, `expired`, `pending_user_link`
- `valid_from`, `valid_until`
- `created_by_user_id`, `created_at`

### Session

Represents an Access Layer session for a user and tool.

Required fields:

- `id`
- `user_id`
- `tool_id`
- `grant_id`
- `status`: `active`, `revoked`, `expired`
- `issued_at`, `expires_at`, `revoked_at`
- `last_seen_at`

`expires_at` is an idle deadline. A valid refresh performed during authenticated user activity moves it forward by the configured refresh/session TTL. No activity beyond that deadline requires a new login.

### Audit event

Records security-relevant behavior.

Required fields:

- `event_id`
- `event_type`
- `created_at`
- `correlation_id`
- `outcome`: `success`, `denied`, `error`, `info`
- `tool_slug` when applicable
- `actor_google_sub` and `actor_email` when known
- `request_ip_hash`, `user_agent_hash` when available
- `reason_code`
- `metadata` with non-sensitive details only

## Invariants

- `google_sub` is the only stable user identity key from Google.
- `email` may change and must not be used as primary key.
- A grant is evaluated against both user identity and tool.
- A one-time code can be consumed once only.
- Access tokens are tool-scoped: a token issued for `tool_a` is invalid for `tool_b`.
- Admin changes are themselves audited.
