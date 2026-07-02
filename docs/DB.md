# DB.md

## Data storage overview

Reference persistence layer: PostgreSQL.

Main data categories:

- users and Google identity;
- tools and tool clients;
- grants and permissions;
- sessions and one-time codes;
- audit logs.

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
| `refresh_tokens` | Optional central refresh tokens | `token_hash`, `session_id`, `expires_at` | Opaque and hashed |
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

The database files live in the Docker volume `access_layer_postgres_data`. Removing the volume destroys local data and should only be done intentionally.

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
