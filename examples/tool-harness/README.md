# Tool integration harness

This minimal Node.js harness demonstrates how an internal tool integrates with Access Layer Google SSO without adding framework dependencies.

It implements:

- protected home route;
- redirect to `GET /v1/auth/start`;
- callback state validation;
- server-to-server `POST /v1/auth/exchange` with Basic Auth;
- local tool session creation;
- logout with `POST /v1/auth/logout`.

## Environment

```env
ACCESS_LAYER_BASE_URL=http://localhost:8080
ACCESS_LAYER_TOOL_SLUG=crm
ACCESS_LAYER_CLIENT_ID=tlc_...
ACCESS_LAYER_CLIENT_SECRET=tls_...
ACCESS_LAYER_CALLBACK_URL=http://localhost:3000/auth/callback
PORT=3000
```

Run:

```sh
node examples/tool-harness/server.mjs
```

The harness intentionally keeps state and sessions in memory. It is for integration testing and documentation only, not production.

It never logs one-time codes, access tokens, refresh tokens, cookies or client secrets.

The harness shows only the login link until it is configured with a valid Access Layer tool client ID/secret and the logged-in user has an active grant for `ACCESS_LAYER_TOOL_SLUG`. Without a grant, Access Layer denies the login and creates a pending access request for admins.
