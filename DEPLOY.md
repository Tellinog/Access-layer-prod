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
- `GOOGLE_ALLOWED_HD` matches the Workspace domain.
- `GOOGLE_ALLOWED_HD` contains only Google Workspace hosted domains from the ID token `hd` claim, never local runtime hosts such as `localhost`.
- Audit log write path is available before accepting login traffic.
- Backup export returns an encrypted JSON envelope and restore secret material is accessible only to admins with explicit backup-secret permission.

## Secret rotation

- Google client secret: rotate using Google Auth Platform, deploy new secret, verify no old secret use, then disable old secret.
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
# Step 1 deployment block

Deployment is prohibited while the Compose PostgreSQL volume reference/declaration mismatch remains unresolved. See `PLATFORM_ADOPTION_REPORT.md` and `BACKLOG.md`. Do not normalize the volume names without live Coolify mapping evidence and a verified backup.
