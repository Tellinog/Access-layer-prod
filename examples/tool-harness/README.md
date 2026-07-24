# Tool integration harness

This minimal Node.js harness demonstrates how an internal tool integrates with Access Layer Google SSO without adding framework dependencies.

It implements:

- protected home route;
- redirect to `GET /v1/auth/start`;
- callback state validation;
- server-to-server `POST /v1/auth/exchange` with Basic Auth;
- activity-driven `POST /v1/auth/refresh` with single-use token rotation;
- local tool session creation;
- logout with `POST /v1/auth/logout`.

## Environment

```env
ACCESS_LAYER_PUBLIC_BASE_URL=http://localhost:8080/access-control
ACCESS_LAYER_INTERNAL_BASE_URL=http://localhost:8080/access-control
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

Refresh is attempted only while handling an authenticated browser request and only when the current access token is close to expiration. It is not performed by a background timer. The harness uses an in-memory single-flight promise so concurrent requests share one refresh. A production tool must provide equivalent coordination and persist session state in an appropriate protected server-side store.

It never logs one-time codes, access tokens, refresh tokens, cookies or client secrets.

The harness shows only the login link until it is configured with a valid Access Layer tool client ID/secret and the logged-in user has an active grant for `ACCESS_LAYER_TOOL_SLUG`. Without a grant, Access Layer denies the login and creates a pending access request for admins.
