# DB.md

## Production continuity metadata

Step 1.5 permits only read-only database/schema evidence without application row contents. `scripts/continuity/collect-postgres-metadata.mjs` uses a read-only transaction and emits PostgreSQL version, database name, a deterministic schema fingerprint, migration identifiers from `schema_migrations`, and metadata counts. It does not emit connection details or driver messages on failure.

The actual live storage identity, backup policy and isolated restore outcome remain unverified. Schema-v2 evidence separates readiness to begin a separately authorised isolated restore from readiness to begin N→N+1; the latter requires a recorded `PASSED` isolated restore. No migration or production restore is authorised by this workflow.

## Data storage overview

Reference persistence layer: PostgreSQL.

Main data categories:

- users and Google identity;
- tools and tool clients;
- grants and permissions;
- sessions and one-time codes;
- audit logs.
- disabled OAuth P0 registration/signing foundation metadata in additive `oauth_*` tables.

## Tables / collections

| Name | Purpose | Key fields | Notes |
|---|---|---|---|
| `users` | Verified Google users | `google_sub`, `email`, `hd`, `status` | `google_sub` unique |
| `tools` | Registered internal tools | `slug`, `status`, `allowed_return_urls` | `slug` unique |
| `tool_clients` | Server-to-server credentials | `client_id`, `secret_hash`, `tool_id` | Secret shown once only |
| `tool_permissions` | Known permission keys | `tool_id`, `permission_key` | Optional but recommended |
| `authorization_grants` | User/tool grants | `user_id`, `email_normalized`, `tool_id`, `role`, `permissions` | Supports pending email grants |
| `admin_tool_assignments` | Delegated admin scope | `user_id`, `tool_id` | Used for `tool_admin` assigned-tool visibility |
| `auth_requests` | Pending OAuth state | `state_hash`, `tool_id`, `return_url`, `tool_state`, `correlation_id` | Short TTL; `tool_state` is never logged and must not contain secrets |
| `access_requests` | Admin queue for valid internal users without grant | `tool_id`, `email_normalized`, `status`, `attempts_count` | Created only after valid company Google login and no active grant |
| `one_time_codes` | Callback code for tool exchange | `code_hash`, `user_id`, `tool_id`, `expires_at`, `consumed_at` | Consume atomically |
| `sessions` | Access Layer sessions | `user_id`, `tool_id`, `grant_id`, `status` | Revocable |
| `refresh_tokens` | Optional central refresh tokens | `token_hash`, `session_id`, `status`, `expires_at` | Opaque, hashed and single-use; rotated on refresh |
| `audit_logs` | Central audit trail | `event_type`, `outcome`, `tool_slug`, `actor_email`, `correlation_id` | Append-only by application rule |

## Invariants

- `users.google_sub` unique and not nullable.
- `tools.slug` unique and immutable after creation except through explicit admin migration.
- A grant must refer to either `user_id` or `email_normalized`.
- Non-empty grant permissions must reference registered permission keys for the target tool.
- Active grants cannot duplicate same user/email + tool + role unless validity windows do not overlap.
- Bulk `upsert` uses the earliest `active` or `pending_user_link` row for an email/tool as a no-op guard, independent of role; it does not mutate that grant.
- One-time code is stored hashed and consumed at most once.
- Audit log rows are never updated or deleted by normal app code.

## Migration strategy

- Use SQL migrations or Prisma migrations.
- Run migrations before app starts accepting traffic.
- Back up database before destructive changes.
- Add indexes for log queries by timestamp, tool, actor email, actor sub, outcome and correlation ID.
- For local Docker development, `docker-compose.yml` starts PostgreSQL and the app entrypoint runs migrations after the PostgreSQL health check passes.

## Local Docker PostgreSQL

The local compose stack starts a `postgres` service and exposes it on `localhost:5432` for developer tools. Inside the compose network the application must use:

```env
DATABASE_URL=postgresql://access_layer:<password>@postgres:5432/access_layer
```

The database files live in the Docker volume `access_layer_postgres_data_v2`. Removing the volume destroys local data and should only be done intentionally.

## Seeds order

Recommended order:

1. `seeds/000_schema_delta.sql`
2. `seeds/010_reference_data.sql`
3. `seeds/020_default_configs.sql`
4. `seeds/030_example_entities.sql`

## Data retention

Default retention:

- audit logs: 365 days;
- auth requests: delete after expiration + 24 hours;
- access requests: keep while pending; archive approved/rejected/closed after audit retention or company policy;
- one-time codes: delete after expiration + 24 hours;
- revoked sessions: keep 90 days unless compliance requires longer;
- users: keep while account or logs require linkage, then pseudonymize if needed.

## Step 3A OAuth dark foundation

D-047 adds no migration and reuses these tables. OAuth Admin writes registration, credential and signing lifecycle changes together with one sanitized `audit_logs` row in a transaction. Secret hashes and protected key references are never selected by the Admin list API. Private key bytes remain filesystem-only and are absent from PostgreSQL and encrypted DB backup data.

`migrations/003_oauth_dark_foundation.sql` is expand-only and creates exactly these independent tables:

| Table | Step 3A purpose |
|---|---|
| `oauth_clients` | Separate stable OAuth client identity, P0 grants/auth method, owner and lifecycle status |
| `oauth_client_credentials` | Confidential-client non-reversible secret hashes and rotation lifecycle only |
| `oauth_client_redirect_uris` | Exact per-client redirect strings; wildcard and fragment records are constrained out |
| `oauth_resources` | Separate canonical HTTPS resource/audience identity and protected-resource metadata URL |
| `oauth_resource_credentials` | Resource-owned `client_secret_basic` introspection credential ID, hash and lifecycle |
| `oauth_resource_entitlement_bindings` | Entitlement-only FK to one existing legacy tool, with at most one active binding per resource |
| `oauth_scopes` | Canonical exact `project:domain:action` scope registry |
| `oauth_resource_scopes` | Exactly one explicit legacy permission key per resource/scope mapping |
| `oauth_client_resource_scopes` | Explicit client/resource/scope allow-list constrained to a registered resource mapping |
| `oauth_signing_keys` | Dedicated OAuth namespace, public JWK/fingerprint/lifecycle and protected private-key reference only |

The migration contains no legacy `ALTER`, rename, drop, data rewrite, trigger or seed. Its only legacy FK is the entitlement bridge to `tools`, using `ON DELETE RESTRICT`; application repository access to `tools`/`tool_permissions` is read-only. No authorization transaction, authorization, code, OAuth session, refresh family/token or revocation table exists yet.

PostgreSQL constraints prevent ambiguous active bindings, duplicate mappings/allowances, wildcard redirects, non-canonical scopes, plaintext-oriented secret columns, private JWK members and legacy/OAuth key-namespace reuse. The signing-key constraints require at least 300 seconds from publication to activation, at least 1,260 seconds from the last signature to `retire_after`, retirement no earlier than `retire_after`, and coherent lifecycle timestamps for staged, published, active and retired rows. The public-JWK constraint uses an explicit false fallback so missing/JSON-null members cannot pass through PostgreSQL `CHECK` UNKNOWN semantics; `kty`, `kid`, `alg`, `use`, `n` and `e` must be present, non-empty strings with the frozen RSA/RS256/signing values and row-matching `kid`.

Exact mapping coverage, proof that every mapped permission is registered for the bound tool, URI-schema parity and confidential/public credential-presence rules are additionally enforced by `src/oauth/validation.ts` fail closed without inferred rewriting or URI normalization. Registration lifecycle metadata contains presence/timestamps only, never a plaintext credential or credential hash.

`OAUTH_ADDITIVE_DATA_MODEL.md` continues to define the later transaction entities as a frozen proposal. Step 3A implements only the ten foundation tables above and does not rename, reuse or reinterpret any legacy table.

Step 4A later closes the repository-level backup gap for all 17 current `oauth_*` tables and makes replace deletion dependency-safe around `oauth_resource_entitlement_bindings` and legacy `tools`. A real encrypted export/replace restore on disposable PostgreSQL 16 remains required in Step 4B before any non-empty production OAuth registration or pilot.

## Step 3C OAuth authorization issuance

`migrations/004_oauth_authorization_code_flow.sql` is expand-only and creates exactly:

| Table | Step 3C purpose |
|---|---|
| `oauth_authorization_transactions` | One validated client/resource/redirect/scope/PKCE request, short-lived AEAD-protected downstream state, independent Google state/nonce hashes, correlation, 600-second expiry and pending/claimed/completed/denied/expired lifecycle |
| `oauth_authorizations` | The exact user, client, resource, granted scopes and legacy authorization grant used by a successful current entitlement decision |
| `oauth_authorization_codes` | Unique SHA-256 code hash plus transaction/authorization/client/resource/user/redirect/scope/PKCE bindings, fixed 60-second expiry and future single-use consumption timestamp |

The migration contains no legacy DDL or data write and adds no OAuth session, refresh or revocation entity. References to `users` and `authorization_grants` use `ON DELETE RESTRICT` to preserve authorization history. Runtime writes to legacy domain data are limited to the existing user upsert and pending-grant linking methods; entitlement lookups remain read-only and OAuth audits continue through `audit_logs`.

`protected_downstream_state` is present as a JSON object only for `pending`/`claimed` rows and must be SQL `NULL` for `completed`/`denied`/`expired`. Completion and denial erase it in the same status compare-and-set. OAuth activity opportunistically cleans at most 100 expired pending/claimed rows using `FOR UPDATE SKIP LOCKED`; cleanup sets `expired`, terminal time and null state atomically, is safe to repeat and has no timer/background worker. Raw downstream state never enters the database.

The original Step 3C candidate migration SHA-256 was `96c37fe2a043a1aae6f813ca36db36cb1aa7ce67f2abfbff42c4883e35f72772`; hardened undeployed migration 004 supersedes it with SHA-256 `407b0fe9b3c9e053e22fac7e9640e0b4d02fe341ea6b3e7f05bb32eeaa8efede`. Live PostgreSQL 16 application and previous-binary smoke evidence must not be claimed unless actually run against a disposable database. Docker/API, `psql` and a local port-5432 server were unavailable for this run, so deterministic migration-shape tests remain the local evidence.

## Step 3D OAuth token lifecycle

`migrations/005_oauth_token_lifecycle.sql` is expand-only and creates exactly:

| Table | Step 3D purpose |
|---|---|
| `oauth_sessions` | OAuth-only human/client/resource/authorization online state with an exact 28,800-second activity/idle deadline |
| `oauth_refresh_token_families` | Immutable subject/client/resource/authorization/session binding, scope ceiling/current scopes, generation, replay and revocation state |
| `oauth_refresh_tokens` | SHA-256-only opaque credential hashes, generation/same-family parent lineage, current/consumed/revoked/expired lifecycle and one partial-unique current member per family |
| `oauth_revocations` | Idempotent opaque target records, including access-token jti expiry and durable family/session/authorization targets |

The migration performs no `ALTER`, seed or data write and does not change migrations 001–004. References to legacy `users` remain identity-only and legacy grant state remains read-only. The Step 3D repository writes only the four lifecycle tables, `oauth_authorization_codes.consumed_at`, `oauth_signing_keys.last_signed_at` and append-only sanitized `audit_logs`; it never writes legacy sessions, refresh tokens, grants or codes.

Code exchange first authenticates with SHARE locks, then UPDATE-locks only the matching authorization-code row and SHARE-locks authorization/client/resource/user/grant rows. Refresh UPDATE-locks only the refresh-token/family/session rows and SHARE-locks the related authorization/client/resource/user/grant rows. Entitlement rows remain SHARE-locked in canonical scope order. This avoids SHARE-to-UPDATE upgrades on read-only rows and preserves the required loser path where same-token concurrency observes `consumed`, commits family/session replay revocation and returns `invalid_grant`.

For `oauth_revocations.target_type = 'access_token_jti'`, `expires_at` is the online revocation-retention deadline (`JWT exp + 60-second verifier skew`), not a rewrite of the JWT expiry. Repeated inserts retain the greatest deadline. `oauth_signing_keys.last_signed_at` updates also use a guarded SQL maximum, preventing clock rollback from shortening the signing-key retirement grace.

Live application of 001→005 remains required on disposable PostgreSQL 16 when available. Deterministic shape and repository/service race tests are not a claim that PostgreSQL accepted the migration.

## Step 4A OAuth backup/import ordering

The existing version-1 encrypted backup now carries explicit, deterministically ordered persisted columns for all ten Step 3A, three Step 3C and four Step 3D OAuth tables. All seven legacy plus 17 OAuth reads use one transaction-bound connection after `REPEATABLE READ, READ ONLY` is established, producing one consistent PostgreSQL snapshot. The seven legacy arrays remain mandatory; the OAuth arrays are optional only as a complete 17-section set. Partial sets fail before an import transaction begins.

Replace deletes OAuth dependants before the existing legacy deletion sequence, including removing the entitlement bridge before `tools`. Full import restores legacy parents, then OAuth clients/resources/scopes/signing metadata, credentials/redirects/entitlement mappings, authorization state, sessions/families/tokens and revocations in one transaction. Credential rotation parents are linked after every credential row exists, but their same-owner chains must first prove acyclic and terminate at `NULL`. Refresh-token parents are validated and inserted by family/generation order; the generation set must equal exactly `0..current_generation`, and missing, extra, cross-family or non-immediate lineage fails closed before writes.

This repository behavior preserves hash/protected/reference forms only and introduces no migration. External OAuth peppers, transaction protection, signing-key files/root and runtime secrets remain outside the database backup. Step 4B must still execute the real isolated PostgreSQL restore.
# Step 2 continuity note

Live Coolify evidence proves that logical volume `access_layer_postgres_data_v2` backs `/var/lib/postgresql/data` and resolves to the recorded UUID-prefixed physical volume. The source top-level declaration now matches the unchanged service mount. Do not add an explicit physical name, rename the logical/live volume, migrate data or deploy. Backup/restore evidence and the other release gates remain open. The machine database baseline is `../specs/legacy-contract-baseline.v1.json`.
