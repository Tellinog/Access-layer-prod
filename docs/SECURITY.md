# SECURITY.md

## Production continuity evidence safety

Continuity evidence may contain operational identifiers, safe effective configuration, environment state enums, and public JWT key metadata, but never tokens, cookies, authorization codes, client secrets, private keys, passwords, database connection strings, session secrets, peppers, backup encryption keys, reusable secret verifiers, or personal rows. Operator artifacts stay outside the repository or in ignored local evidence paths; committed evidence must be redacted and reviewed.

## Authentication

Access Layer authenticates users through Google OpenID Connect.

Required Google ID token checks:

- signature valid with Google public keys or Google auth library;
- `aud` equals the configured Google OAuth Client ID;
- `iss` equals `accounts.google.com` or `https://accounts.google.com`;
- `exp` not expired;
- `email_verified` is true;
- `hd` exists and is in `GOOGLE_ALLOWED_HD`.

Do not trust the email domain alone.

## OAuth vNext P0 target security

The additive OAuth protocol target is frozen but not implemented. `OAUTH_P0_CONTRACT.md` and `../specs/oauth-p0.v1.yml` require Authorization Code plus Refresh Token only, PKCE `S256` for every code flow, RFC 7636 verifier grammar and exact unpadded S256 challenge grammar, exact redirects, one RFC 8707 resource, exact single audience, RFC 9068 `typ=at+jwt`, RFC 9207 response issuer, header-only bearer transport, OAuth-standard errors, refresh-family replay revocation and a dedicated OAuth key ring. Human OAuth `sub` remains Google `sub`; email, hosted domain, role and legacy permission arrays are excluded from OAuth access tokens by default.

Step 3B implements only a read-only, default-off metadata/JWKS surface over the Step 3A foundation; the authorization protocol remains unimplemented. `OAUTH_P0_ENABLED` defaults to `false`, requires no additional OAuth secret/key input, and leaves every new route at 404 when false/absent. When true, only GET OAuth JWKS and GET RFC 9728 protected-resource metadata are registered outside the unchanged legacy builder; automatic `HEAD` siblings are disabled.

Foundation credential tables contain only `secret_hash` plus lifecycle metadata. Repository metadata queries deliberately do not select credential hashes. Controlled client-registration validation carries only non-secret `secretPresent`, rotation and expiry metadata: confidential `client_secret_basic` requires presence, while public `none` forbids it. Plaintext credentials and credential hashes are not members of that validation model.

Redirect, resource and protected-resource metadata URI helpers reject raw whitespace/control characters, raw backslashes, malformed percent escapes, userinfo, fragments and wildcards before exact scheme/localhost checks. They validate the original string and do not normalize the value used for registration or comparison.

`oauth_signing_keys` accepts a public RSA JWK with private members constrained out, a public SHA-256 fingerprint, lifecycle metadata and a protected private-key reference; it has no private-key byte/PEM column, and the repository never returns the protected reference. Required public JWK members are explicit non-empty strings and the database constraint fails false rather than UNKNOWN for missing/null members. Database and pure-domain lifecycle validation enforce the frozen 300-second publication lead, 1,260-second verification retention and retirement ordering. No real credential, private key, token or pilot data is seeded or used in fixtures.

The Step 3B JWKS selector treats persisted rows as untrusted: it revalidates lifecycle and public JWK shape. RSA `n` and `e` must be canonical unpadded RFC 7518 Base64urlUInt values using the minimum unsigned big-endian octet sequence; padding, whitespace, non-base64url characters and redundant leading-zero octets fail closed. For RS256, `n` must be positive with bit length at least 2048, while `e` must be at least 3, odd and less than `n`. It publishes only deliberate pre-activation `published` and `active` records, sorts by `kid`, and serializes only the allow-listed public members `kty`, `kid`, `alg`, `use`, `n` and `e`. Staged, disabled, retired and invalid rows are excluded. Empty/failed selection returns a sanitized 503 without row diagnostics or legacy-key fallback. Future private-key reference loading is blocked until traversal, safe-root and scheme allow-list checks are defined and tested; no loader exists in Step 3B.

Every P0 resource requires exactly one legacy-tool entitlement-only binding and one explicit legacy permission mapping for every declared OAuth scope. Mappings cover the scope set exactly; prefix/segment/alias inference is forbidden. The mapped permission must be registered for the bound tool and present in the effective active grant, or authorization fails closed. Client, resource and legacy-tool identities remain separate; native OAuth entitlement domains are deferred.

P0 introspection uses `client_secret_basic` credentials owned by one OAuth resource and stored only as non-reversible hashes with lifecycle/rotation metadata. These credentials are neither OAuth client credentials nor legacy tool clients. It discloses only RFC 9068 access tokens whose exact `aud` equals the credential's resource as active. Audience mismatches, refresh, inactive, unknown and otherwise non-disclosable tokens receive exactly `{"active":false}`; invalid caller credentials fail authentication.

OAuth vNext uses the future internal Google callback `/oauth/upstream/google/callback`; it never extends the frozen legacy callback and remains unimplemented and unregistered after Step 3B. Exact downstream client state is kept only in future short-lived reversible protected storage until returned and is never logged. Upstream Google state and nonce may remain hash-only.

First-party browser clients remain BFF/server-side-token applications. Public-client rollout, SPA bearer-token storage, downstream OIDC, service principals, `client_credentials`, token exchange, `private_key_jwt` and dynamic registration are disabled/deferred.

## Authorization / permissions

Authentication and authorization are separate.

A user can access a tool only if:

- Google identity is valid;
- user status is `active`;
- tool status is `active`;
- return URL is allowed for that tool;
- grant exists and is active;
- grant is within validity dates.

See also:

- `specs/policy.v1.yml`
- `specs/permissions.v1.yml`
- `specs/visibility.v1.yml`

## Session management

- One-time codes expire after `ONE_TIME_CODE_TTL_SECONDS` and are single-use.
- Store one-time codes hashed only.
- Access Layer access tokens expire after `ACCESS_TOKEN_TTL_SECONDS`.
- Refresh tokens, if enabled, are opaque, hashed at rest, single-use, rotated on every successful refresh and revocable.
- A successful authenticated refresh extends both the refresh-token expiry and Access Layer session expiry by `REFRESH_TOKEN_TTL_SECONDS`.
- Sliding renewal represents authenticated user activity. Tools must refresh while handling a user request; unconditional background timers or refreshes without user activity are forbidden.
- If no valid refresh occurs within `REFRESH_TOKEN_TTL_SECONDS`, the session cannot be renewed and the tool must restart login.
- Refresh validates the active tool, user, session and grant before issuing a new access token.
- Tool local sessions must not outlive Access Layer grant/session rules unless the tool uses introspection or refresh checks.
- Admin session cookies must be `HttpOnly`, `Secure`, `SameSite=Lax` or stricter.
- Admin cookie-authenticated write requests must pass same-origin validation. Bearer-token admin API clients do not use browser cookies and are not subject to the CSRF browser threat model.

## CSRF and replay protection

- Tool generates its own callback `state`.
- Access Layer generates its own Google OAuth `state` and `nonce`.
- Callback must match server-side state.
- Authorization code/one-time code exchange must be atomic.
- Reject replayed code.

## Tool client authentication

- Tool exchange and introspection endpoints require tool client credentials.
- Use HTTPS only.
- Store only hashed tool secrets in DB.
- Show tool secret only once at creation/rotation.
- Support rotation and revocation. The rotate endpoint accepts `revoke_existing=true` to disable existing active clients before issuing the replacement credential.
- Backup and restore permissions are separate from secret rotation. `admin:secrets:rotate` must not imply backup read/write access.

## Input validation

Validate:

- `tool_slug`: lowercase slug format;
- `return_url`: exact allow-list match or strict configured pattern;
- `state`: max length, allowed characters, entropy generated by tool;
- email: normalized lowercase for lookup, preserve original for display;
- pending grant email: well-formed company email whose domain is allowed by `GOOGLE_ALLOWED_HD`;
- permissions: known registered keys using colon-separated lowercase segments, for example `tool:read` or `petyr:read:all`;
- dates: ISO-8601 UTC.

## Uploads and files

No file upload is in scope for v1.

## Secrets and environment variables

- Never hardcode secrets.
- Document variables in `.env.example` and `DEPLOY.md`.
- Use secret manager in production.
- Do not commit `.env`.

Secrets:

- `GOOGLE_CLIENT_SECRET`
- `JWT_PRIVATE_KEY_PEM_PATH` content
- `JWT_PRIVATE_KEY_PEM` content when PEM is injected directly
- `SESSION_SECRET`
- `TOOL_CLIENT_SECRET_PEPPER`
- `BACKUP_ENCRYPTION_KEY`
- `LOG_IP_SALT`
- per-tool client secrets

`JWT_PRIVATE_KEY_PEM_PATH` and `JWT_PRIVATE_KEY_PEM` are alternatives. Do not set both unless the deployment platform intentionally overrides file-based keys with injected PEM content.

Encrypted backup exports use `BACKUP_ENCRYPTION_KEY`. Admin-only restore secret material export may return `TOOL_CLIENT_SECRET_PEPPER` and `BACKUP_ENCRYPTION_KEY`, but cannot return existing per-tool client secrets because those are stored only as hashes.

## Logging and privacy

Allowed audit identity fields:

- Google `sub`;
- email;
- `hd`;
- tool slug;
- outcome/reason;
- correlation ID;
- salted IP/user-agent hash.

Forbidden in logs:

- tokens;
- authorization codes;
- secrets;
- cookies;
- raw sensitive payloads.

See `docs/LOGGING.md`.

## Rate limiting

Apply rate limits to:

- `/v1/auth/start` by IP hash and tool;
- `/v1/auth/exchange` by tool client and code;
- `/v1/auth/refresh` by tool client and refresh-token hash;
- `/v1/auth/introspect` by tool client;
- admin write endpoints by admin user.

## HTTP security headers

V1 responses set baseline browser hardening headers:

- `X-Content-Type-Options: nosniff`;
- `Referrer-Policy: no-referrer`;
- `X-Frame-Options: DENY`;
- `Permissions-Policy` disabling camera, microphone and geolocation;
- `Content-Security-Policy` restricted to same-origin resources, with inline script/style allowed only for the minimal same-service Admin UI.

## CORS

Browser CORS is disabled by default unless `CORS_ALLOWED_ORIGINS` contains an exact origin. When an allowed origin is present, v1 returns CORS headers for `Authorization` and `Content-Type` on `GET`, `POST`, `PATCH` and `OPTIONS`.

## Reverse proxy trust

`TRUST_PROXY_HOPS` controls how many proxy hops are trusted for client IP resolution. Use `1` for the expected Coolify reverse-proxy path and `0` for direct local development. Do not use unlimited proxy trust.

## Security-sensitive areas

- Google callback handling.
- ID token validation.
- Return URL validation.
- Tool client secret handling.
- JWT signing key management.
- Grant creation/revocation.
- Audit log integrity.

## Failure behavior

- Deny by default.
- On audit log write failure during access decision, fail closed unless explicitly configured otherwise for emergency mode.
- Never expose low-level Google errors to end users; show generic denial and correlation ID.

## Access request security

Access requests must be created only after a successful Google login for an allowed hosted domain. Do not create admin queue items for external accounts, invalid Google tokens, invalid return URLs or unknown tools.

To prevent spam and enumeration:

- deduplicate pending requests by `tool_id + email_normalized`;
- increment `attempts_count` instead of creating duplicate rows;
- rate limit repeated login attempts;
- expose requests only to `platform_admin` or assigned `tool_admin`;
- keep raw IP disabled by default and store only hashes unless approved.
# Step 1 compatibility freeze

As of 2026-08-24, the repository-observed security contract is frozen in `../specs/legacy-contract-baseline.v1.json`. Step 1 adds no OAuth/OIDC surface, secret rotation, permission, token, cookie or session change. Copied template OAuth and SDK material is reference-only. Never log or store raw golden tokens; all new fixtures use synthetic `.invalid` identities and non-secret token strings.

## Step 1.5B continuity evidence safety

The production-continuity bundle records secret-bearing environment inputs only as `ABSENT`, `PRESENT_EMPTY`, or `PRESENT_NON_EMPTY`. Presence does not establish continuity: equality of `SESSION_SECRET`, `TOOL_CLIENT_SECRET_PEPPER`, `BACKUP_ENCRYPTION_KEY`, `GOOGLE_CLIENT_SECRET`, `LOG_IP_SALT`, and JWT signing material must be attested through access-controlled external evidence. Secret values, low-entropy hashes, HMACs, private-key fingerprints, and other reusable verifiers are forbidden in Git.

For file-backed JWT signing, the public JWKS `kid`/fingerprint and the actual persistent `/run/secrets` mount identity are separate required observations. The runtime helper may stat the configured key file but never reads it. An absent file is continuity-sensitive because the current entrypoint can generate a new private key at startup.

The intermediate `ready_for_isolated_restore` gate never authorises production changes. Final N→N+1 readiness additionally requires a proven `PASSED` isolated restore.
