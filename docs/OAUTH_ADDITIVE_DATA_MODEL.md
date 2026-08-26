# Proposed additive OAuth data model

Status: Step 3A foundation partially implemented; protocol transaction model remains a proposal.

## Migration boundary

Step 3A implements the first OAuth migration as `../migrations/003_oauth_dark_foundation.sql`. It is expand-only and readable by the currently deployed legacy binary. It adds only the ten foundation `oauth_*` tables and the read-only entitlement bridge; it does not rename, drop, reinterpret or reuse legacy `users`, `tools`, `tool_clients`, `tool_permissions`, `authorization_grants`, `auth_requests`, `one_time_codes`, `sessions` or `refresh_tokens`. Legacy rows remain authoritative for legacy traffic.

The implemented subset ends at `oauth_signing_keys` in the table below. Every later authorization transaction, authorization, code, session, refresh and revocation entity remains unimplemented and must not be inferred from the presence of foundation tables.

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
| `oauth_authorization_transactions` *(not implemented)* | Exact downstream client state in short-lived reversible protected storage (for example, an encrypted-at-rest value) until the response is emitted, plus an optional lookup hash; separate upstream Google state/nonce hashes; client, exact redirect, requested resource/scopes, PKCE challenge/method, correlation, expiry and consumed/decision timestamps. Downstream state is never logged. |
| `oauth_authorizations` *(not implemented)* | Human `user_id`, client, resource, effective scope set, explicit legacy grant references used for the decision, status and timestamps. P0 has no newly invented consent row. |
| `oauth_authorization_codes` *(not implemented)* | Non-reversible code hash; transaction/authorization/client/resource/redirect/subject/PKCE/scope bindings; issued, expires and consumed timestamps. Single-use with atomic consumption. |
| `oauth_sessions` *(not implemented)* | Human, client, resource, authorization, status, issued/idle-expiry/revoked timestamps and correlation. Separate from legacy `sessions`. |
| `oauth_refresh_token_families` *(not implemented)* | Authorization/session/client/resource/subject invariants, original/current scope ceiling, status, replay timestamp and revocation reason. |
| `oauth_refresh_tokens` *(not implemented)* | Family FK, non-reversible token hash, generation/parent, status, issued/expires/consumed/revoked timestamps. One atomic current member per active family. |
| `oauth_signing_keys` | Public `kid`, algorithm, public-JWK fingerprint/reference, lifecycle state, publish/activate/retire timestamps and protected private-key reference only. No private key bytes. |
| `oauth_revocations` *(not implemented)* | Token/family/session/authorization target type and opaque internal target ID, client/resource context, reason code, actor and timestamp. |

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
