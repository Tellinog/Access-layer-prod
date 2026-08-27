# ARCHITECTURE.md

## Overview

Access Layer is a centralized web service used by internal tools for authentication, authorization and access audit.

It sits between internal tools and Google Auth Platform:

- Tools send users to Access Layer.
- Access Layer authenticates with Google OpenID Connect.
- Access Layer verifies company domain and user grants.
- Access Layer returns a short-lived, tool-scoped identity to the tool backend.
- Tools create local sessions and call introspection/JWKS as needed.

## Components

| Component | Responsibility | Technology | Notes |
|---|---|---|---|
| Public Auth API | Start login, handle Google callback, exchange one-time code | Node.js/TypeScript reference | Must be HTTPS in production |
| Google OIDC Adapter | Build authorization URL, exchange code, validate ID token | Google auth library | Must validate `aud`, `iss`, `exp`, `hd` |
| Permission Service | Resolve grants for user/tool | DB-backed service | Must handle pending email grants |
| Token Service | Issue Access Layer JWT and refresh tokens | JOSE/JWT | Tool-scoped, short TTL |
| JWKS Endpoint | Publish public signing keys | HTTP endpoint | Used by tools for offline validation |
| Introspection API | Online token status check | Tool-authenticated API | Useful for revocation |
| Admin API/UI | Manage users, tools, grants, logs | Same service in v1 | Admin itself protected by Access Layer |
| Audit Logger | Persist structured security events | DB table + optional SIEM | Must not log tokens/secrets |
| Database | Store users, tools, grants, sessions, audit logs | PostgreSQL reference | See `docs/DB.md` |

## Data flow

### Auth flow

1. Tool redirects browser to `/v1/auth/start` in production, or the configured local base path plus `/v1/auth/start`, with `tool_slug`, `return_url` and `state`.
2. Access Layer validates tool and return URL, creates a correlation record and redirects to Google.
3. Google redirects back to `/v1/auth/google/callback` in production with authorization code.
4. Access Layer exchanges code server-side and validates ID token.
5. Access Layer upserts user by `google_sub`.
6. Access Layer checks active grant for requested tool.
7. Access Layer creates session and one-time code.
8. Browser is redirected to tool callback with code and original state.
9. Tool backend calls `/v1/auth/exchange` using tool client credentials.
10. Access Layer returns identity, permissions, session ID and JWT.

### Activity-driven session renewal

1. The tool backend handles an authenticated user request.
2. If the Access Layer JWT is expired or close to expiration, the backend calls `/v1/auth/refresh` with its tool client credentials and current opaque refresh token.
3. Access Layer atomically consumes the refresh token and revalidates tool, user, session and grant.
4. Access Layer issues a new 15-minute JWT, rotates the refresh token and moves the session idle deadline forward by 8 hours.
5. If refresh is denied, the tool clears its local session and starts login again.

Tools must not refresh on an unconditional background timer: remaining logged in depends on user activity.

### Authorization decision

A request is allowed only if all checks pass:

- tool exists and is active;
- return URL is allowed for that tool;
- Google ID token is valid;
- `email_verified` is true;
- `hd` is present and allowed;
- user status is active;
- active grant exists for user/email and tool;
- grant validity dates are satisfied.

## Invariants

- Google callback can only resume a known auth request through server-side `state`.
- Access Layer never returns Google tokens to tools.
- One-time code is single-use, short-lived and stored hashed.
- Access token audience is the requested `tool_slug` or tool client ID.
- All sensitive state transitions write audit events.

## Integration points

| Integration | Purpose | Auth | Notes |
|---|---|---|---|
| Google Auth Platform | User login and ID token | OAuth client ID/secret | Configured in Google Cloud |
| Internal tools | Login start, exchange, refresh, introspection | Tool client credentials | Each tool must be registered |
| Admin users | Manage access | Google login + platform admin role | Bootstrap through env for first deploy |
| SIEM/log export | Optional audit export | API token or managed identity | Deferred scope |

## Operational constraints

- Production must run behind HTTPS.
- Redirect URIs must exactly match Google OAuth client configuration.
- System time must be synchronized for token expiration checks.
- DB write path for audit logs must be available before accepting auth traffic.
- Avoid browser-delivered long-lived tokens.

## Additive OAuth vNext target and Step 3B boundary

P0 adds a future authorization-server adapter beside, not inside, the legacy flow. OAuth clients and resources are separate identities. Every P0 resource requires exactly one existing legacy tool/grant entitlement-only binding; each canonical resource scope maps explicitly one-to-one to an exact permission registered for that tool, with no inferred conversion. The bound tool never becomes the OAuth client or resource, and native OAuth entitlement domains are deferred. Introspection uses separate resource-owned credentials and discloses active state only for an exact matching token audience; it never reuses OAuth client or legacy tool credentials. The future Google return path is the separate internal `/oauth/upstream/google/callback`, never the frozen `/v1/auth/google/callback`, and is not advertised as a protocol endpoint. Exact downstream client state uses short-lived reversible protected storage; upstream Google state/nonce remain separately hashed.

Step 3A implements only the dark foundation below:

```text
src/oauth/ pure validation + read repository
                    |
                    v
oauth_* foundation tables ----read-only----> tools + tool_permissions

buildApp / legacy /v1/* --------------------> unchanged legacy repositories
```

Step 3B adds composition around, not inside, the frozen legacy builder:

```text
server -> buildApplication -> buildApp (unchanged legacy routes)
                           -> flag=true only -> OAuth read-only HTTP
                                                  |-> RFC 9728 pure builder
                                                  `-> public metadata repository -> JWKS selector
```

At the Step 3B boundary, `OAUTH_P0_ENABLED=true` registered only the dedicated OAuth JWKS and protected-resource metadata GET routes. The RFC 8414 builder remains intentionally unmounted until its advertised protocol routes exist. Metadata preserves the configured issuer identifier exactly while using a separately trailing-slash-normalized base only for endpoint construction. The repository query exposes public/lifecycle metadata but never the protected private-key reference.

Step 3C extends only the true-flag branch with a separate authorization-issuance boundary:

```text
/oauth/authorize -> exact registration + PKCE -> protected 600s transaction -> OAuth Google adapter
                                                                              |
/oauth/upstream/google/callback <- atomic state claim <- Google identity ------+
            -> legacy user upsert + pending-grant link only
            -> current exact entitlement mapping/grant decision
            -> atomic OAuth authorization + SHA-256 code + completion/audits
            -> exact client redirect (code, state, iss)
```

The external Google exchange occurs after the state-claim query completes and outside a database transaction. Token exchange/signing and every OAuth session/refresh/revocation component remain absent. `src/app.ts` and the legacy Google adapter remain unchanged.

## Risks

| Risk | Mitigation |
|---|---|
| External Google users try login | Google internal audience plus backend `hd` validation |
| Email domain spoofing or stale email | Use `sub` and validate `hd`, do not trust email domain alone |
| Token leakage in URL | Use one-time code, not access token, in callback URL |
| Replay of one-time code | Store hash, consume atomically, TTL 60 seconds |
| Tool secret leaked | Secret rotation, hashing, audit, per-tool credentials |
| Missing logs on failure paths | Audit middleware and required tests for denial cases |
