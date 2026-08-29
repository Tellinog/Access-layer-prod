# Access Layer backup and restore

Access Layer stores durable identity and authorization data in Postgres. This feature adds a portable encrypted JSON backup for disaster recovery and scheduled external backups.

## What the backup includes

The JSON export includes:

- `users`
- `tools`
- `tool_clients`
- `tool_permissions`
- `authorization_grants`
- `admin_tool_assignments`
- `access_requests`

Step 4A adds all 17 current OAuth tables to the same version-1 payload:

- `oauth_clients`
- `oauth_client_credentials`
- `oauth_client_redirect_uris`
- `oauth_resources`
- `oauth_resource_credentials`
- `oauth_resource_entitlement_bindings`
- `oauth_scopes`
- `oauth_resource_scopes`
- `oauth_client_resource_scopes`
- `oauth_signing_keys`
- `oauth_authorization_transactions`
- `oauth_authorizations`
- `oauth_authorization_codes`
- `oauth_sessions`
- `oauth_refresh_token_families`
- `oauth_refresh_tokens`
- `oauth_revocations`

OAuth credential, authorization-code and refresh-token material is included only in its already stored non-reversible hash form. Pending/claimed downstream state remains only as its authenticated-encrypted database envelope. Signing records include the public JWK, public fingerprint and protected private-key reference, never the private key contents.

The encrypted backup plaintext includes `client_id` and `client_secret_hash` in the `tool_clients` section. Access Layer intentionally does not store tool client secrets in plaintext, so existing plaintext `tls_...` values cannot be recovered from the database or the backup.

All seven legacy and 17 OAuth table reads execute through one transaction-bound PostgreSQL connection. The transaction establishes `REPEATABLE READ, READ ONLY` before the first table `SELECT`, so one export represents one consistent MVCC snapshot without a write lock or `SERIALIZABLE` isolation.

Existing tool client secrets continue to work after restore only if the restored environment uses the same `TOOL_CLIENT_SECRET_PEPPER` that was used when the secrets were created. If that pepper is lost or changed, restore still imports the tool clients and client IDs, but clients must be rotated and downstream tools must receive new secrets.

OAuth client and resource credentials likewise remain usable only with the same external `OAUTH_CREDENTIAL_SECRET_PEPPER`. A restored pending/claimed OAuth transaction can be decrypted only with the same external `OAUTH_TRANSACTION_PROTECTION_KEY`. The referenced OAuth private signing-key files and their `OAUTH_SIGNING_KEY_ROOT` storage remain external continuity material.

The API and Admin UI export an encrypted envelope with:

- `schema=access-layer-encrypted-backup`
- `alg=AES-256-GCM`
- random IV and authentication tag
- ciphertext containing the backup payload

Production requires `BACKUP_ENCRYPTION_KEY`. Keep that key outside the backup.

## What the backup does not include

The export does not include these legacy ephemeral or high-churn tables:

- legacy `sessions`
- legacy `refresh_tokens`
- legacy `one_time_codes`
- legacy `auth_requests`
- audit logs
- raw Google OAuth secrets
- legacy JWT private/public key material
- `.env` files or Coolify secrets

The OAuth tables listed above are included even when they contain active OAuth sessions or hash-only token lifecycle rows. No export query recovers or synthesizes a raw OAuth client/resource secret, authorization code, access token, refresh token or private signing key.

The frozen top-level `contents.sessions` and `contents.refresh_tokens` flags are legacy-oriented metadata describing the excluded legacy tables. They do not negate the explicit `data.oauth_sessions`, `data.oauth_refresh_token_families` or `data.oauth_refresh_tokens` sections in a current full Step 4A backup. The metadata is not changed because `src/app.ts` and the legacy backup envelope remain frozen.

Keep these runtime secrets in your password manager / Coolify secrets backup:

- `TOOL_CLIENT_SECRET_PEPPER`
- `BACKUP_ENCRYPTION_KEY`
- `SESSION_SECRET`
- `JWT_PRIVATE_KEY_PEM` or the content referenced by `JWT_PRIVATE_KEY_PEM_PATH`
- `JWT_PUBLIC_KEY_ID`
- `GOOGLE_CLIENT_ID`
- `GOOGLE_CLIENT_SECRET`
- `GOOGLE_REDIRECT_URI`
- `POSTGRES_PASSWORD`
- `BACKUP_API_TOKEN` if enabled
- `OAUTH_CREDENTIAL_SECRET_PEPPER`
- `OAUTH_TRANSACTION_PROTECTION_KEY`
- `OAUTH_SIGNING_KEY_ROOT` and every referenced OAuth private signing-key file
- other runtime secrets required by the restored environment

## Admin UI download

Log in as a platform admin and open:

```text
/admin -> Backup
```

Use **Scarica backup cifrato** to download the encrypted backup manually.

Use **Scarica secret restore** only as a platform admin to download the restore secret material containing `TOOL_CLIENT_SECRET_PEPPER` and `BACKUP_ENCRYPTION_KEY`. This file is highly sensitive. It still cannot include existing per-tool `tls_...` client secrets, because those are never stored in plaintext after creation or rotation.

The UI also exposes an import/restore form. For a disaster restore into a newly migrated database, enable `replace_existing` and confirm the destructive restore.

## API export for N8n

Set a long random token in the Access Layer environment:

```env
BACKUP_API_TOKEN=replace-with-at-least-32-random-characters
```

Then call:

```bash
curl -fsS \
  -H "Authorization: Bearer $BACKUP_API_TOKEN" \
  -o access-layer-backup.json \
  https://access-layer.example.com/v1/admin/backup/export
```

In N8n, use an HTTP Request node:

- Method: `GET`
- URL: `https://access-layer.example.com/v1/admin/backup/export`
- Header: `Authorization: Bearer <BACKUP_API_TOKEN>`
- Response: file/binary data or JSON, depending on the workflow

Store the resulting encrypted JSON in Google Drive, S3, Backblaze, or your chosen backup destination.

## API import/restore

Import requires an authenticated admin session with `admin:backup:write`. It is intentionally not enabled through `BACKUP_API_TOKEN` by default, because import is destructive when `replace_existing=true`.

Endpoint:

```text
POST /v1/admin/backup/import
```

Payload:

```json
{
  "backup": { "schema": "access-layer-backup", "version": 1, "data": {} },
  "replace_existing": true,
  "confirm_replace": true
}
```

For most disaster-recovery scenarios:

1. Redeploy Access Layer.
2. Restore the same external secrets, especially `TOOL_CLIENT_SECRET_PEPPER` and JWT key material.
3. Run migrations.
4. Import the encrypted JSON backup with `replace_existing=true`.
5. Restart the application.
6. Rotate any tool client secrets if the pepper was not preserved.

## Version-1 import compatibility

The encrypted envelope, endpoint and plaintext backup identity remain `access-layer-backup` version `1`. The seven legacy data sections remain mandatory. The 17 OAuth sections are optional only as one complete set:

- zero OAuth sections is a valid legacy-only backup;
- one or more but fewer than all 17 OAuth sections is rejected before database writes;
- a legacy-only merge (`replace_existing=false`) does not touch existing OAuth rows;
- every replace (`replace_existing=true`) deletes OAuth dependants before legacy parents, so restoring a legacy-only snapshot intentionally leaves zero OAuth rows and cannot be blocked by the entitlement binding's `tools` foreign key;
- a full backup restores legacy parents first, then OAuth parents and dependants in one transaction. Credential rotation parents use a second linking pass, and refresh tokens are validated and inserted by family/generation order.

Before the import transaction opens, client and resource credential parent chains must resolve within the same owner and terminate at `NULL`; missing, cross-owner, self-parent and multi-row cycles are rejected. Every refresh family must contain exactly one token generation for each integer in `0..current_generation`, no generation above the marker, a null parent at generation zero and an immediate same-family generation-minus-one parent thereafter. Repository-detected structural or lineage failures carry sanitized HTTP 400 validation semantics and do not expose backup rows or protected material.

Import count responses keep the original seven keys for a legacy-only backup. A full OAuth backup adds the 17 OAuth count keys.

Step 4A provides deterministic repository/test evidence only. A real encrypted export and replace restore against disposable PostgreSQL 16 is Step 4B and has not been claimed here.

## Security notes

- Treat the encrypted backup as sensitive data. After decryption, it contains users, grants, tool metadata, client IDs and client secret hashes.
- Treat the restore secret material export as secret-manager data.
- Do not commit backups to Git.
- Store backup envelopes and restore secret material encrypted at rest.
- Restrict `BACKUP_API_TOKEN` to N8n or backup automation only.
- Rotate `BACKUP_API_TOKEN` if it is exposed.
- Keep the N8n workflow logs from printing the backup body.
