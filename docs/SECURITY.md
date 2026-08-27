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

That paragraph records the completed Step 3B boundary. Step 3C now adds only dark Authorization Code issuance when the same flag is true. The authorize and separate upstream-Google callback routes disable automatic request logging and HEAD exposure. They validate singleton requests, exact registered redirect trust, active client/resource state, canonical scopes, explicit allowances and PKCE S256 before creating a transaction. Untrusted client/redirect failures are local; only a previously trusted exact redirect receives OAuth response parameters and exact RFC 9207 issuer identity.

`OAUTH_TRANSACTION_PROTECTION_KEY` is a dedicated canonical unpadded base64url encoding of exactly 32 random bytes. It is absent/optional when OAuth is false and mandatory when true; it is never derived from or replaced by a legacy secret. Exact downstream state is encrypted with AES-256-GCM using a fresh 96-bit IV, versioned envelope and AAD bound to version plus transaction UUID. Upstream Google state and nonce are independently random and stored only as SHA-256 hashes. The 600-second transaction is claimed atomically once before any Google network exchange.

Protected downstream-state ciphertext exists only while a transaction is `pending` or `claimed`. Successful completion and denial erase the envelope atomically with the terminal status update; bounded opportunistic cleanup erases expired pending/claimed envelopes while marking those rows `expired`. Cleanup processes at most 100 lock-safe rows per OAuth activity, is idempotent and has no cron, timer or background worker. State is decrypted before terminal commit and kept only in request memory for the immediate redirect. A crash after terminal commit requires a new authorization attempt; plaintext is never persisted to support retries.

After verified Google identity, Step 3C may upsert the legacy user and link existing pending-email grants through the frozen methods. It creates no legacy grant, access request, session or one-time code. Client/resource/allowances/mappings and the active grant are re-read; each exact mapped permission must still be registered and present case-sensitively in that grant. Authorization, a SHA-256-only code row, transaction completion and sanitized success audits are committed atomically. Raw 32-byte authorization codes exist only for the response, expire after 60 seconds and never enter persistence or logs.

Foundation credential tables contain only `secret_hash` plus lifecycle metadata. Repository metadata queries deliberately do not select credential hashes. Controlled client-registration validation carries only non-secret `secretPresent`, rotation and expiry metadata: confidential `client_secret_basic` requires presence, while public `none` forbids it. Plaintext credentials and credential hashes are not members of that validation model.

Redirect, resource and protected-resource metadata URI helpers reject raw whitespace/control characters, raw backslashes, malformed percent escapes, userinfo, fragments and wildcards before exact scheme/localhost checks. They validate the original string and do not normalize the value used for registration or comparison.

`oauth_signing_keys` accepts a public RSA JWK with private members constrained out, a public SHA-256 fingerprint, lifecycle metadata and a protected private-key reference; it has no private-key byte/PEM column, and the repository never returns the protected reference. Required public JWK members are explicit non-empty strings and the database constraint fails false rather than UNKNOWN for missing/null members. Database and pure-domain lifecycle validation enforce the frozen 300-second publication lead, 1,260-second verification retention and retirement ordering. No real credential, private key, token or pilot data is seeded or used in fixtures.

The Step 3B JWKS selector treats persisted rows as untrusted: it revalidates lifecycle and public JWK shape. RSA `n` and `e` must be canonical unpadded RFC 7518 Base64urlUInt values using the minimum unsigned big-endian octet sequence; padding, whitespace, non-base64url characters and redundant leading-zero octets fail closed. For RS256, `n` must be positive with bit length at least 2048, while `e` must be at least 3, odd and less than `n`. It publishes only deliberate pre-activation `published` and `active` records, sorts by `kid`, and serializes only the allow-listed public members `kty`, `kid`, `alg`, `use`, `n` and `e`. Staged, disabled, retired and invalid rows are excluded. Empty/failed selection returns a sanitized 503 without row diagnostics or legacy-key fallback. Future private-key reference loading is blocked until traversal, safe-root and scheme allow-list checks are defined and tested; no loader exists in Step 3B.

Every P0 resource requires exactly one legacy-tool entitlement-only binding and one explicit legacy permission mapping for every declared OAuth scope. Mappings cover the scope set exactly; prefix/segment/alias inference is forbidden. The mapped permission must be registered for the bound tool and present in the effective active grant, or authorization fails closed. Client, resource and legacy-tool identities remain separate; native OAuth entitlement domains are deferred.

P0 introspection uses `client_secret_basic` credentials owned by one OAuth resource and stored only as non-reversible hashes with lifecycle/rotation metadata. These credentials are neither OAuth client credentials nor legacy tool clients. It discloses only RFC 9068 access tokens whose exact `aud` equals the credential's resource as active. Audience mismatches, refresh, inactive, unknown and otherwise non-disclosable tokens receive exactly `{"active":false}`; invalid caller credentials fail authentication.

OAuth vNext uses the internal Google callback `/oauth/upstream/google/callback`; it never extends the frozen legacy callback. Step 3C registers it only under the default-false flag. Exact downstream client state is kept only in short-lived authenticated-encrypted storage until returned and is never logged. Upstream Google state and nonce are hash-only.

Step 3D now implements that exchange re-check in an unmounted core. It hashes the raw code before lookup, UPDATE-locks only the mutable code row and SHARE-locks the current OAuth identities, human, exact legacy grant, entitlement binding/mappings/allowances and registered permissions before a compare-and-set consume. Code scopes must exactly equal the active authorization scope set. Code consumption, OAuth session/family/refresh-hash persistence, sanitized success audit and OAuth signing-key usage update are one transaction. Failed exchange state rolls back before a separate bounded sanitized denial-audit transaction; denial-audit failure returns only `temporarily_unavailable`. It never creates or changes a legacy session, refresh token, grant or code.

OAuth client and resource credential verification uses only `OAUTH_CREDENTIAL_SECRET_PEPPER` with the existing salted scrypt verifier format. Configuration and the invoked core fail closed if it equals `TOOL_CLIENT_SECRET_PEPPER`; neither value is logged. It never uses the tool pepper or queries `tool_clients`. Confidential clients authenticate against current `oauth_client_credentials`; registered public clients use `none`; introspection authenticates only current `oauth_resource_credentials`.

The Step 3D signer accepts only absolute local paths or local `file:` references that resolve to regular, non-empty files no larger than 64 KiB inside the realpath of `OAUTH_SIGNING_KEY_ROOT`. Relative/unsupported references, encoded traversal, symlink escape, public/private/fingerprint mismatch, and equality between the candidate RSA public `n`/`e` and the actual configured legacy key fail as a sanitized unavailable condition regardless of copied filename or inline legacy PEM. Exactly one active OAuth key without a retirement deadline may sign; old active overlap keys verify only while `retire_after > now`. Verification also requires finite integer `iat`/`exp`, bounds `iat` to the existing 60-second skew and preserves exact 900-second TTL. Successful persisted issuance alone updates `last_signed_at`.

Refresh tokens contain at least 32 random bytes and remain SHA-256-only at rest. Refresh UPDATE-locks token/family/session and SHARE-locks all related read-only rows. Before signing it requires token generation/current scopes to match family state, current scopes to remain inside the family ceiling, and ceiling/current/requested scopes to remain inside the active authorization. Each valid user-activity refresh preserves human/client/resource, narrows scopes monotonically if requested and sets the OAuth session and replacement token deadline to exactly `now + 28,800 seconds`. Consumed-member reuse commits family/session revocation and the replay audit before returning `invalid_grant`; no timer, cron or heartbeat exists.

Revocation/introspection remain unmounted core methods in Step 3D. Access-token revocation resolves only the exact existing OAuth audience, without requiring the resource to remain active and without legacy fallback, then persists the OAuth `jti` through original expiry; refresh revocation revokes its family/session. Resource introspection verifies only OAuth `RS256`/`at+jwt` keys and exact audience, then checks jti, OAuth session, authorization and current entitlement state. Unknown, legacy, malformed, expired, wrong-audience and inactive candidates expose only `active:false`.

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
- `OAUTH_TRANSACTION_PROTECTION_KEY` when dark OAuth is enabled
- `OAUTH_CREDENTIAL_SECRET_PEPPER` before Step 3D credential verification is invoked
- private key files beneath `OAUTH_SIGNING_KEY_ROOT`; the root/path is not logged
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
