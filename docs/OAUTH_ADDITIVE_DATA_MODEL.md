# Proposed additive OAuth data model

Status: Step 3A foundation, Step 3C authorization issuance and Step 3D unmounted token/session/refresh/revocation core implemented; HTTP protocol mounting remains deferred.

## Migration boundary

Step 3A implements the first OAuth migration as `../migrations/003_oauth_dark_foundation.sql`. It is expand-only and readable by the currently deployed legacy binary. It adds only the ten foundation `oauth_*` tables and the read-only entitlement bridge; it does not rename, drop, reinterpret or reuse legacy `users`, `tools`, `tool_clients`, `tool_permissions`, `authorization_grants`, `auth_requests`, `one_time_codes`, `sessions` or `refresh_tokens`. Legacy rows remain authoritative for legacy traffic.

Step 3C implements the three authorization transaction/authorization/code rows shown below through additive migration 004. Step 3D implements the four token-lifecycle rows through additive migration 005 without mounting protocol routes.

Step 3D joined reads use mixed row-lock strength without upgrades: only code or refresh token/family/session rows receive UPDATE locks; authorization/client/resource/user/grant rows and entitlement mappings receive SHARE locks. The service additionally cross-checks authorization `granted_scopes` against code scopes and every refresh token/family generation, current-scope and ceiling field before mutating state.

For `oauth_revocations` rows whose target is `access_token_jti`, `expires_at` is the revocation-retention deadline: JWT `exp` plus the frozen 60-second verifier skew. It is not the token's nominal expiry. Conflict handling may only extend that deadline. OAuth signing metadata similarly treats `last_signed_at` as a monotonic maximum so retirement decisions use the latest recorded signing instant.

## Proposed entities

| Proposed table | Purpose and minimum contract |
|---|---|
| `oauth_clients` | Stable `client_id`, display name, type, status, allowed P0 grants, token auth method, owner metadata, created/updated timestamps. It is not a `tools` alias. |
| `oauth_client_credentials` | Client FK, non-reversible secret hash or future key metadata, status, created/activated/expires/retired timestamps and rotation lineage. Never stores plaintext secrets. |
| `oauth_client_redirect_uris` | Client FK and exact normalized-for-storage-but-exactly-compared redirect URI; unique per client. No wildcard/pattern column. |
| `oauth_resources` | Canonical HTTPS `resource_id`, display name, status, owner, protected-resource metadata URL and `exact_single_resource` audience policy. It is not an OAuth client. |
| `oauth_resource_credentials` | Resource FK, stable `credential_id` used as the HTTP Basic username, non-reversible secret hash, status, created/activated/rotated/expires/retired timestamps and rotation-parent lineage. P0 supports only `client_secret_basic`. The credential belongs to one OAuth resource and is neither an OAuth client credential nor a legacy `tool_clients` row. |
| `oauth_resource_entitlement_bindings` | Resource FK plus the mandatory P0 legacy `tool_id`/slug bridge. Exactly one active `legacy_tool` entitlement domain exists per P0 resource. It may read legacy grants/permissions without changing their meaning and never identifies the OAuth client or resource. Native OAuth entitlement domains are deferred beyond P0. |
| `oauth_scopes` | Canonical `project:domain:action`, description, status and audit metadata. Scope aliases, if ever approved, are separate versioned records. |
| `oauth_resource_scopes` | Resource/scope registration, required exact `legacy_permission_key` and status. Each resource scope has exactly one explicit mapping to a legacy permission registered for the resource's bound tool. Only these scopes may appear in that resource's metadata or tokens. |
| `oauth_client_resource_scopes` | Client/resource/scope allow-list. Prevents a client registration from implying access to every resource or scope. |
| `oauth_authorization_transactions` | Exact downstream client state in a versioned AES-256-GCM envelope with transaction-bound AAD; separate SHA-256 Google state/nonce hashes; client, exact redirect, resource/scopes, PKCE, correlation, fixed 600-second expiry and claim/completion timestamps. |
| `oauth_authorizations` | Human `user_id`, client, resource, effective scope set, exact legacy grant reference used for the decision, status and timestamps. P0 introduces no consent row. |
| `oauth_authorization_codes` | Unique SHA-256 code hash; transaction/authorization/client/resource/redirect/subject/PKCE/scope bindings; exact 60-second expiry and future atomic consumption timestamp. Raw code is never persisted. |
| `oauth_sessions` | Human, client, resource, authorization, status, issued/activity/idle-expiry/revoked timestamps and correlation. Separate from legacy `sessions`; idle expiry is exactly activity plus 28,800 seconds. |
| `oauth_refresh_token_families` | Authorization/session/client/resource/subject invariants, immutable scope ceiling, current monotonically narrowed scopes/generation, status, replay timestamp and revocation reason. |
| `oauth_refresh_tokens` | Family FK, SHA-256 token hash, generation/same-family parent, scope snapshot, status and issued/expires/consumed/revoked timestamps. A partial unique index permits one current member per family. |
| `oauth_signing_keys` | Public `kid`, algorithm, public-JWK fingerprint/reference, lifecycle state, publish/activate/retire timestamps and protected private-key reference only. No private key bytes. |
| `oauth_revocations` | Idempotent access-jti/family/session/authorization target type and opaque internal target ID, client/resource context, reason and timestamp. Access jti records retain original token expiry. |

OAuth audit events continue through the append-only legacy `audit_logs` facility initially, using only non-secret OAuth identifiers and event names. A separate audit table is unnecessary unless later scale or retention evidence requires it.

## Required constraints

- Client and resource identities are separate foreign-key domains.
- Every P0 resource has exactly one active `legacy_tool` entitlement binding; the bound tool is entitlement-only and never becomes the OAuth client or resource.
- Every registered P0 resource scope has exactly one explicit `legacy_permission_key`. The resource-scope mapping set covers the declared scopes exactly, with no missing, extra or duplicate scope, and never derives a permission by prefix, segment rewriting or alias inference.
- Each mapped permission key must exist for the bound legacy tool and be present in the human's effective active grant. A missing, stale, unknown or ungranted mapping fails closed as `invalid_scope`/deny; legacy permissions and grants are not changed.
- Resource introspection credentials are separate from OAuth client credentials and legacy tool clients. An authenticated resource credential may receive `active=true` only when the token's exact `aud` equals that credential's resource; every audience mismatch receives exactly `{"active":false}`.
- Resource IDs and client IDs are immutable after activation.
- Redirect comparison is exact; wildcard redirect records are impossible.
- Every authorization transaction contains exactly one resource and `S256` PKCE.
- Every authorization transaction can return the exact original downstream client state after the Google round trip; only upstream Google state and nonce may be hash-only.
- Codes and refresh tokens are hashed, unique, single-use and transactionally consumed.
- Granted scopes are the fail-closed intersection of resource registration, client/resource allowance, legacy human entitlement and central policy.
- Human OAuth subject is obtained from the linked legacy user's `google_sub`; email and local UUID are not token subjects.
- Refresh replay revokes the whole family and linked OAuth session in the same transaction.
- OAuth key records cannot point at legacy private-key material; key namespaces and JWKS remain isolated.
- Deleting/disabling a client, resource, scope, entitlement or human grant cannot erase audit history.

## Future migration sequence

1. Add the tables and constraints without changing existing tables or runtime reads.
2. Seed reviewed client/resource/scope/mapping registrations and resource credentials through a controlled administrative path.
3. Verify the frozen legacy suite and rollback with OAuth globally disabled.
4. Enable OAuth for an explicit pilot client/resource only.
5. Observe compatibility, replay, key, audit and rollback gates.
6. Consider any contract/removal phase only after measured zero legacy use, retention windows and explicit approval.
