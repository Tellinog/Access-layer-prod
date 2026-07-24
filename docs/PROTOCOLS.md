# PROTOCOLS.md

## Access Layer JWT claims

Recommended claims:

```json
{
  "iss": "https://access-layer.unguess-internal.net",
  "sub": "110000000000000000000",
  "aud": "crm",
  "exp": 1760000000,
  "iat": 1759999100,
  "jti": "01HYTOKEN",
  "sid": "01HYSESSION",
  "tool_slug": "crm",
  "email": "mario.rossi@unguess.io",
  "hd": "unguess.io",
  "permissions": ["crm:read", "crm:write"],
  "role": "tool_user"
}
```

## Tool client authentication

Use HTTP Basic Auth for server-to-server endpoints:

```http
Authorization: Basic base64(client_id:client_secret)
```

Accepted endpoints:

- `POST /v1/auth/exchange`
- `POST /v1/auth/refresh`
- `POST /v1/auth/introspect`
- `POST /v1/auth/logout` when called by tool backend

## One-time code rules

- Random value at least 128 bits entropy.
- Prefix optional, e.g. `otc_`.
- Store only hash.
- TTL 60 seconds by default.
- Atomic consume by hash and tool.
- Bind to tool, return URL, user, grant and correlation ID.

## Refresh token rules

- Opaque value stored only as a hash by Access Layer and only server-side by the tool.
- Single-use and atomically consumed.
- Rotate on every successful refresh.
- Bind indirectly to the originating tool through the Access Layer session.
- Revalidate active tool, user, session and grant on refresh.
- Extend the session idle deadline only for authenticated user activity.
- Do not refresh on background timers without user activity.

## Return URL matching

Default v1 rule: exact match.

Allowed pattern mode can be added only if:

- pattern syntax is documented;
- wildcard does not cross domain boundary;
- tests cover malicious URLs.

Examples denied:

- `https://crm.draftapps.it.evil.com/auth/callback`
- `https://evil.com/auth/callback`
- `javascript:alert(1)`
- `https://crm.draftapps.it/auth/callback?next=https://evil.com` unless exact URL was registered
