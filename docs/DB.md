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

PostgreSQL constraints prevent ambiguous active bindings, duplicate mappings/allowances, wildcard redirects, non-canonical scopes, plaintext-oriented secret columns, private JWK members and legacy/OAuth key-namespace reuse. Exact mapping coverage and proof that every mapped permission is registered for the bound tool cross multiple tables, so `src/oauth/validation.ts` enforces those rules fail closed without inferred rewriting.

`OAUTH_ADDITIVE_DATA_MODEL.md` continues to define the later transaction entities as a frozen proposal. Step 3A implements only the ten foundation tables above and does not rename, reuse or reinterpret any legacy table.
# Step 2 continuity note

Live Coolify evidence proves that logical volume `access_layer_postgres_data_v2` backs `/var/lib/postgresql/data` and resolves to the recorded UUID-prefixed physical volume. The source top-level declaration now matches the unchanged service mount. Do not add an explicit physical name, rename the logical/live volume, migrate data or deploy. Backup/restore evidence and the other release gates remain open. The machine database baseline is `../specs/legacy-contract-baseline.v1.json`.
