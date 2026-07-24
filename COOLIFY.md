# COOLIFY.md

## Production target

Canonical production origin:

```text
https://access-layer.unguess-internal.net
```

All Access Layer API endpoints are mounted at the production root:

```text
/v1/auth/start
/v1/auth/google/callback
/v1/auth/exchange
/v1/auth/introspect
/v1/admin/tools
/v1/admin/grants
/v1/admin/access-requests
/v1/admin/audit-logs
```

`/` redirects to `/admin`. The production health endpoint is exposed at `/health`.

## Coolify import

Use this repository/package as a Docker Compose application.

Do not upload real `.env`, `.env.docker`, generated `.tmp` or `.local` keys, `node_modules` or `dist` folders. The production package intentionally contains only examples and source files.

The Docker builder stage must include `scripts/copy-assets.mjs` and `assets/` before `npm run build`; the build script compiles TypeScript and copies UI assets into `dist/assets`. A Coolify warning about `APP_ENV=production` is informational for this Node.js multi-stage image and is not by itself a build failure.

## Environment variables

Create the variables in the Coolify resource Environment Variables section. Start from `.env.production.example` and replace all placeholder values.

Minimum production values:

```env
APP_ENV=production
PUBLIC_BASE_PATH=
APP_BASE_URL=https://access-layer.unguess-internal.net
AUTH_ISSUER=https://access-layer.unguess-internal.net
PORT=8080

POSTGRES_USER=access_layer
POSTGRES_PASSWORD=<long random password>
POSTGRES_DB=access_layer
DATABASE_URL=postgresql://access_layer:<same password>@postgres:5432/access_layer

GOOGLE_CLIENT_ID=<google web oauth client id>
GOOGLE_CLIENT_SECRET=<google web oauth client secret>
GOOGLE_REDIRECT_URI=https://access-layer.unguess-internal.net/v1/auth/google/callback
GOOGLE_ALLOWED_HD=unguess.io,nuotounostiledivita.it
GOOGLE_OIDC_SCOPE=openid email profile

JWT_PRIVATE_KEY_PEM=<private key PEM from secret manager>
JWT_PRIVATE_KEY_PEM_PATH=
JWT_PUBLIC_KEY_ID=prod-key-1
SESSION_SECRET=<long random secret>
TOOL_CLIENT_SECRET_PEPPER=<long random secret>
LOG_IP_SALT=<long random secret>

CORS_ALLOWED_ORIGINS=https://access-layer.unguess-internal.net
RETURN_URL_ALLOWED_SCHEMES=https
ADMIN_BOOTSTRAP_EMAILS=lorenzo.prandi@unguess.io,lorenzo@nuotounostiledivita.it

RUN_MIGRATIONS_ON_START=true
RUN_SEED_ON_START=true
SEED_EXAMPLE_TOOLS=false
```

For production, prefer `JWT_PRIVATE_KEY_PEM` as a Coolify secret/environment variable. `JWT_PRIVATE_KEY_PEM_PATH` can remain empty.

## Google OAuth

The authorized redirect URI in Google Cloud must exactly match the production root-path callback:

```text
https://access-layer.unguess-internal.net/v1/auth/google/callback
```

For local tests:

```text
http://localhost:8080/access-control/v1/auth/google/callback
```

`GOOGLE_ALLOWED_HD` must be the Google Workspace hosted domain only:

```env
GOOGLE_ALLOWED_HD=unguess.io,nuotounostiledivita.it
```

Do not put `localhost`, URLs, ports, `draftapps.it` or `access-layer.unguess-internal.net` in `GOOGLE_ALLOWED_HD` unless that is also the actual Google Workspace hosted domain in the Google ID token `hd` claim.

## First login

After deploy:

1. open `https://access-layer.unguess-internal.net`;
2. click Login;
3. login with an email listed in `ADMIN_BOOTSTRAP_EMAILS`;
4. verify the dashboard loads;
5. open Tools and create managed tools from the UI.

The `access-admin` tool is seeded automatically. Example/demo tools are not seeded unless `SEED_EXAMPLE_TOOLS=true`.

## Tool management

Use the UI, not seed files, for v1 tool onboarding:

1. open Tools;
2. click New tool;
3. enter slug, display name, exact return URLs and permission keys;
4. copy the one-time client secret immediately;
5. store that secret only in the target tool backend environment variables.

The cleartext tool client secret is shown only once. If lost, rotate the secret from the Tool detail screen.

## Smoke tests

After deploy, verify:

```text
GET https://access-layer.unguess-internal.net/health
GET https://access-layer.unguess-internal.net/v1/.well-known/jwks.json
GET https://access-layer.unguess-internal.net/admin
```

Then test:

- admin bootstrap login succeeds;
- non-admin user cannot access `/admin`;
- Tools section loads;
- a new tool can be created and its secret copied;
- a company user without grant creates an access request;
- an external Google account is denied without creating an approvable access request.
