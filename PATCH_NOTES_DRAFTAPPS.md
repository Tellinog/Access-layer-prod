# UNGUESS internal deployment patch

Target deployment origin:

- `https://access-layer.unguess-internal.net`

Runtime/auth changes:

- `APP_BASE_URL=https://access-layer.unguess-internal.net`
- `AUTH_ISSUER=https://access-layer.unguess-internal.net`
- `GOOGLE_REDIRECT_URI=https://access-layer.unguess-internal.net/v1/auth/google/callback`
- `CORS_ALLOWED_ORIGINS=https://access-layer.unguess-internal.net`
- `GOOGLE_ALLOWED_HD=unguess.io,nuotounostiledivita.it`
- `ADMIN_BOOTSTRAP_EMAILS=lorenzo.prandi@unguess.io,lorenzo@nuotounostiledivita.it`

Important Google OAuth note:

`GOOGLE_ALLOWED_HD` checks the Google ID token `hd` claim. `nuotounostiledivita.it` will work only if Google returns `hd=nuotounostiledivita.it` for those users. If `unguess.io` and `nuotounostiledivita.it` are in different Google Workspace organizations, do not rely on an Internal-only OAuth audience for one organization; use an OAuth configuration that can reach both domains and keep the backend HD allow-list as the final guard.

Verification performed:

- `npm.cmd run lint` passed.
- `npm.cmd run build` passed.
- `npm.cmd test` passed: 95 tests.
