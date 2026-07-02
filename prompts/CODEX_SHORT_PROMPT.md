Implement Access Layer Google SSO from this repository. First read `AGENTS.md`, `CURRENT_STATE.md`, `BACKLOG.md`, `DECISIONS.md`, `README.md`, `docs/SCOPE.md`, `docs/DOMAIN.md`, `docs/ARCHITECTURE.md`, `docs/SECURITY.md`, `docs/API.md`, `docs/GOOGLE_CLOUD_SETUP.md`, `docs/INTEGRATION_GUIDE.md`, `docs/IMPLEMENTATION_PLAN.md`, and `docs/TESTING.md`.

Use the reference stack in `DECISIONS.md` unless explicitly changed: Node.js 22, TypeScript, PostgreSQL, OpenAPI, Google auth library, JOSE/JWT. Build backend API, DB migrations, admin UI minimal, Google OIDC flow, tool registration, grants, one-time code exchange, JWT/JWKS, introspection, logout and audit logs.

Do not log tokens/secrets. Validate Google ID token, `aud`, `iss`, `exp`, `email_verified` and `hd`. Use Google `sub` as user key. Deny by default. Update docs/specs/schemas/devlog/current state and run tests before final summary.
