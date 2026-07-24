# IMPLEMENTATION_PLAN.md

## Goal

Implement a production-ready v1 of Access Layer Google SSO according to this repository.

## Milestone 1 - Project bootstrap

- Create Node.js/TypeScript service.
- Add lint, test, typecheck.
- Add config loader with validation against `.env.example` and `schemas/config.schema.json`.
- Add health endpoint.
- Add structured logger with secret redaction.

Acceptance:

- App starts locally.
- `GET /health` works.
- Config validation fails closed for missing secrets.

## Milestone 2 - Database

- Implement PostgreSQL migrations from `seeds/000_schema_delta.sql` or equivalent.
- Add repositories for tools, users, grants, sessions, auth requests, access requests, one-time codes and audit logs.
- Add seed for local dev.

Acceptance:

- Migrations run cleanly.
- Tests can create/read/update core records.

## Milestone 3 - Google OIDC

- Implement `/v1/auth/start`.
- Implement Google authorization URL generation.
- Implement `/v1/auth/google/callback`.
- Exchange code server-side.
- Validate ID token using Google library.
- Enforce `hd` and `email_verified`.

Acceptance:

- Mocked Google tests cover valid and invalid cases.
- External/missing `hd` denied.

## Milestone 4 - Authorization and exchange

- Implement grant resolution.
- Implement one-time code creation and atomic consumption.
- Implement `/v1/auth/exchange` with tool client auth.
- Implement `/v1/auth/refresh` with single-use rotation, active authorization revalidation and activity-driven sliding session expiry.
- Issue Access Layer JWT.
- Publish `/v1/.well-known/jwks.json`.
- Implement `/v1/auth/introspect`.

Acceptance:

- Authorized user gets token and identity.
- No grant denied.
- Valid internal no-grant denial creates or updates an access request.
- Code replay denied.
- JWT can be verified by test tool.

## Milestone 5 - Admin API/UI

- Implement admin auth for platform admin.
- CRUD tools.
- Create/modify/revoke grants.
- List users.
- List, approve, reject and close access requests.
- Query audit logs.
- Add minimal admin UI pages.

Acceptance:

- Bootstrap admin can create pilot tool and grant.
- Admin can approve a pending access request and create a grant in one transaction.
- Admin changes produce audit events.

## Milestone 6 - Tool integration sample

- Add example integration app or documented test harness.
- Demonstrate login, callback, exchange, local session and logout.

Acceptance:

- One pilot flow works end-to-end in the configured v1 environment.

## Milestone 7 - Hardening

- Rate limiting.
- Secret rotation paths.
- Log redaction tests.
- Security headers.
- Deployment docs updated.

Acceptance:

- Security test checklist passes.
- Production readiness gate in `DEPLOY.md` passes.

## Implementation rules

- Do not log tokens or secrets.
- Do not use email as primary key.
- Do not skip `hd` validation.
- Do not issue tokens without active grant.
- Do not accept unregistered return URLs.
- Update docs/specs/schemas if implementation changes behavior.
