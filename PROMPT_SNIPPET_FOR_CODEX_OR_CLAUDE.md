# Prompt snippet for Codex, Claude Code or similar agents

Copy and paste this block at the beginning of tasks sent to Codex, Claude Code or other coding agents.

```text
You are working inside an agent-ready, source-of-truth driven repository for Access Layer Google SSO.

Before making code changes, read and follow:

1. AGENTS.md
2. CURRENT_STATE.md
3. BACKLOG.md
4. DECISIONS.md
5. README.md
6. docs/SCOPE.md
7. docs/DOMAIN.md
8. docs/ARCHITECTURE.md
9. docs/SECURITY.md
10. docs/API.md
11. docs/GOOGLE_CLOUD_SETUP.md
12. docs/INTEGRATION_GUIDE.md
13. docs/IMPLEMENTATION_PLAN.md
14. docs/TESTING.md

Task:
Implement the complete v1 Access Layer Google SSO service.

Expected outcome:
Backend API, DB migrations, Google OIDC flow, admin UI minimal, tool registry, grants, one-time code exchange, Access Layer JWT/JWKS, introspection, logout, audit logs and tests.

Constraints:
Use the reference stack in DECISIONS.md unless explicitly changed. Never log tokens, authorization codes, cookies or secrets. Validate Google ID token including aud, iss, exp, email_verified and hd. Use Google sub as primary user key. Deny by default. Every access decision and admin change must write an audit event.

At the end, return files changed, behavior changed, docs/specs/schemas updated, tests run, decisions made, blockers/open questions and recommended next step.
```
