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

The encrypted backup plaintext includes `client_id` and `client_secret_hash` in the `tool_clients` section. Access Layer intentionally does not store tool client secrets in plaintext, so existing plaintext `tls_...` values cannot be recovered from the database or the backup.

Existing tool client secrets continue to work after restore only if the restored environment uses the same `TOOL_CLIENT_SECRET_PEPPER` that was used when the secrets were created. If that pepper is lost or changed, restore still imports the tool clients and client IDs, but clients must be rotated and downstream tools must receive new secrets.

The API and Admin UI export an encrypted envelope with:

- `schema=access-layer-encrypted-backup`
- `alg=AES-256-GCM`
- random IV and authentication tag
- ciphertext containing the backup payload

Production requires `BACKUP_ENCRYPTION_KEY`. Keep that key outside the backup.

## What the backup does not include

The export does not include ephemeral or high-churn runtime data:

- active sessions
- refresh tokens
- one-time auth codes
- OAuth auth requests
- audit logs
- raw Google OAuth secrets
- JWT private/public key material
- `.env` files or Coolify secrets

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

## Security notes

- Treat the encrypted backup as sensitive data. After decryption, it contains users, grants, tool metadata, client IDs and client secret hashes.
- Treat the restore secret material export as secret-manager data.
- Do not commit backups to Git.
- Store backup envelopes and restore secret material encrypted at rest.
- Restrict `BACKUP_API_TOKEN` to N8n or backup automation only.
- Rotate `BACKUP_API_TOKEN` if it is exposed.
- Keep the N8n workflow logs from printing the backup body.
