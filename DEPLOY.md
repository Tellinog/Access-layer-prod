# DEPLOY.md

## Deployment target

The service must be deployed as an HTTPS-only backend reachable by all internal tools.

Recommended production URL pattern:

- `https://access-layer.unguess-internal.net`

Recommended environments:

- local: `http://localhost:8080/access-control`
- production: `https://access-layer.unguess-internal.net`

No separate staging environment is required for v1 unless specified later.

## Required external setup

Before production deploy:

1. Create Google Cloud/Auth Platform app and OAuth Web client.
2. Configure internal audience for the company Google Workspace organization.
3. Configure redirect URIs for each environment.
4. Store Google client secret and JWT private key in a secret manager.
   - Set either `JWT_PRIVATE_KEY_PEM_PATH` or `JWT_PRIVATE_KEY_PEM`.
   - Store `TOOL_CLIENT_SECRET_PEPPER` and `BACKUP_ENCRYPTION_KEY` with the same secret-management controls.
5. Configure database and run migrations.
6. Bootstrap first platform admin.
7. Register first pilot tool.

## Coolify production

Use `docker-compose.yml` as the Coolify compose application. Do not commit or upload real `.env` files. Configure production variables in Coolify from `.env.production.example`. The canonical production values are:

```env
PUBLIC_BASE_PATH=
APP_BASE_URL=https://access-layer.unguess-internal.net
AUTH_ISSUER=https://access-layer.unguess-internal.net
GOOGLE_REDIRECT_URI=https://access-layer.unguess-internal.net/v1/auth/google/callback
GOOGLE_ALLOWED_HD=unguess.io,nuotounostiledivita.it
TRUST_PROXY_HOPS=1
```

The dashboard is at `/admin`; admin and tool-management APIs are under `/v1/admin/*`.

`OAUTH_P0_ENABLED` is optional and defaults to `false`; absent/false preserves the exact legacy route inventory and requires no OAuth-only input. True mounts the complete Step 3E dark surface: Step 3B metadata/JWKS, Step 3C authorization/Google callback, token, revoke, introspect and RFC 8414, with no implicit HEAD on GET routes. It then requires a dedicated canonical 32-byte `OAUTH_TRANSACTION_PROTECTION_KEY`, distinct `OAUTH_CREDENTIAL_SECRET_PEPPER` and absolute dedicated `OAUTH_SIGNING_KEY_ROOT`. Never reuse the tool-client pepper or legacy JWT key/root, and never record real values or key paths in Git.

Do not set or enable those OAuth values in production under this step. No callback registration, pilot/key provisioning, controlled registration, backup expansion or production action is authorised; Step 3E does not modify Compose/Coolify or production secrets.

### Optional temporary legacy Microsoft bridge

The bridge is absent by default. Enabling it requires all of the following runtime values:

```env
LEGACY_MICROSOFT_ENABLED=true
MICROSOFT_TENANT_ID=<testbirds-directory-tenant-guid>
MICROSOFT_CLIENT_ID=<entra-web-app-client-guid>
MICROSOFT_CLIENT_SECRET=<secret-manager-reference-value>
MICROSOFT_REDIRECT_URI=https://access-layer.unguess-internal.net/v1/auth/microsoft/callback
MICROSOFT_OIDC_SCOPE=openid profile email
MICROSOFT_ALLOWED_EMAIL_DOMAINS=testbirds.com,testbirds.de
LEGACY_MICROSOFT_TOOL_SLUGS=<comma-separated-pilot-slugs>
```

Do not commit real identifiers or secret values. The redirect must exactly match the configured public origin/base path and the Entra Web redirect. The client secret must use approved secret storage/rotation and continuity evidence. Roll back by setting `LEGACY_MICROSOFT_ENABLED=false` and restarting; no migration or consumer change is involved. This repository task does not authorize deployment, Coolify changes or tenant registration changes.

## Local Docker Compose

For local development, Docker Compose can start both PostgreSQL and the Access Layer service.

1. Copy `.env.docker.example` to `.env.docker`.
2. Replace all placeholder secrets in `.env.docker`; keep `GOOGLE_ALLOWED_HD=unguess.io,nuotounostiledivita.it`.
3. Ensure `DATABASE_URL` points to the compose service host `postgres`, not `localhost`.
4. Run `npm run docker:up`; the script passes `.env.docker` to Docker Compose.
5. Verify `GET http://localhost:8080/health`.

The app container waits for the PostgreSQL health check, runs SQL migrations, optionally seeds local reference data through `RUN_SEED_ON_START=true`, then starts `node dist/src/server.js`.

This local compose profile is not a production secret-management pattern. Production must inject secrets through the target platform or a secret manager, and should run migrations as a controlled deploy step before exposing traffic.

## Runtime checks

- `GET /health` returns service and DB health.
- `GET /v1/.well-known/jwks.json` returns current public signing keys.
- OAuth redirect URI matches Google Cloud configuration exactly.
- If the legacy Microsoft bridge is enabled, its exact redirect, single tenant, allowed domains and tool-slug allowlist match the approved registration/configuration.
- `GOOGLE_ALLOWED_HD` matches the Workspace domain.
- `GOOGLE_ALLOWED_HD` contains only Google Workspace hosted domains from the ID token `hd` claim, never local runtime hosts such as `localhost`.
- Audit log write path is available before accepting login traffic.
- Backup export returns an encrypted JSON envelope and restore secret material is accessible only to admins with explicit backup-secret permission.

## Secret rotation

- Google client secret: rotate using Google Auth Platform, deploy new secret, verify no old secret use, then disable old secret.
- Microsoft client secret: create/rotate in Entra and the approved secret store, update runtime configuration without versioning the value, verify the pilot, then retire the old credential.
- JWT signing key: add new key with new `kid`, publish JWKS, issue new tokens, wait for old TTL, then retire old key.
- Tool client secrets: support per-tool rotation with overlapping old/new secret during migration.
- Backup encryption key: rotate by exporting a fresh encrypted backup after deploying the new `BACKUP_ENCRYPTION_KEY`; preserve the previous key until older backup files expire.

## Production readiness gate

Do not expose production until tests in `docs/TESTING.md` pass for:

- internal user allowed;
- external user denied;
- internal user without grant denied;
- one-time code replay denied;
- invalid return URL denied;
- invalid tool client secret denied;
- token introspection success and revocation behavior;
- audit events generated for every path above.
# Step 2 deployment block

The source Compose mismatch is resolved from live Coolify evidence: both the PostgreSQL service mount and top-level declaration use `access_layer_postgres_data_v2`, while JWT storage remains `access_layer_jwt_secrets`. Do not add explicit physical volume names or rename either logical/live volume. Deployment is still prohibited until the backup/restore, ownership, registry and remaining continuity gates in `BACKLOG.md` are complete.

The observed non-secret Coolify IDs are server `wx513ojqd80kdicevubog7`, project `xdihnb979tvyh9gdk72zfy7y`, environment `rd3mt4dkpqyghxlx9h96sdlo` and resource `u3cyw3y1obp88to9la0w8c75`; destination remains unresolved. Coolify visibly reported `Changes pending`, which must be reviewed and resolved or explicitly accepted before any future production deploy. This record does not apply those changes or authorise deployment.
