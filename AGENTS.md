# AGENTS.md

This repository is agent-ready and source-of-truth driven.

AI agents, coding assistants and human contributors must use this file as the operational entry point before making changes.

## Core principle

Do not infer missing product, domain, architecture, UX, security, API, data or deployment rules.

If something is not documented, ambiguous or contradictory:

1. do not invent;
2. add the issue to `BACKLOG.md`;
3. classify it as `BLOCKER`, `QUESTION`, `ASSUMPTION_TO_VALIDATE` or `DEFERRED_SCOPE`;
4. continue only on the parts that are not affected by the ambiguity;
5. report the issue in the final task summary.

## Required reading order

Before working on any task, read these files in this order:

1. `AGENTS.md`
2. `ACCESS_LAYER_INTEGRATION_URL_SPEC.md`
3. `CURRENT_STATE.md`
4. `BACKLOG.md`
5. `DECISIONS.md`
6. `README.md`
7. `docs/SCOPE.md`
8. `docs/DOMAIN.md`
9. `docs/ARCHITECTURE.md`
10. `docs/SECURITY.md`
11. `docs/API.md`
12. `docs/TESTING.md`

Then read task-specific documents:

- Google/OAuth work: `docs/GOOGLE_CLOUD_SETUP.md`, `docs/SECURITY.md`, `specs/policy.v1.yml`
- Tool integration work: `docs/INTEGRATION_GUIDE.md`, `docs/API_PAYLOADS.md`, `schemas/openapi.yaml`, `examples/api/`
- Admin work: `docs/ADMIN_GUIDE.md`, `docs/UX.md`, `docs/UI_SYSTEM.md`, `docs/COPY.md`, `specs/permissions.v1.yml`
- Database/data work: `docs/DB.md`, `seeds/`, `schemas/`
- Logging/audit work: `docs/LOGGING.md`, `docs/ANALYTICS.md`, `schemas/events.schema.json`, `examples/events/`
- Deployment/devops work: `DEPLOY.md`, `docs/DEPLOYMENT.md`, `.env.example`, `scripts/`
- Implementation planning: `docs/IMPLEMENTATION_PLAN.md`, `prompts/CODEX_SHORT_PROMPT.md`

## Source of truth hierarchy

When sources conflict, use this hierarchy:

1. `specs/` for machine-readable rules and policies
2. `schemas/` for formal data/API/event/config shapes
3. `docs/` for human-readable product, domain, UX, architecture and operational rules
4. `DECISIONS.md` for accepted decisions and rationale
5. `CURRENT_STATE.md` for current status and known constraints
6. `BACKLOG.md` for open questions and unresolved items
7. code comments and implementation details only after the above

If there is a conflict between these sources, stop on the conflicting part and add an item to `BACKLOG.md`.

## Required updates

When a task changes behavior, update:

- `DEVLOG.md`
- `CURRENT_STATE.md`
- relevant files in `docs/`
- relevant files in `specs/` or `schemas/`, if rules or shapes changed
- `DECISIONS.md`, if a decision was made
- `BACKLOG.md`, if something remains unresolved

## Security rule

Security-sensitive changes must consult:

- `docs/SECURITY.md`
- `specs/policy.v1.yml`
- `specs/permissions.v1.yml`
- `specs/visibility.v1.yml`

Do not log secrets, authorization codes, ID tokens, access tokens, refresh tokens, cookies, raw request bodies containing secrets, private user data beyond the explicitly allowed audit fields, or sensitive payloads.

## Environment variables

All required environment variables must be documented in `.env.example` and `docs/DEPLOYMENT.md` or `DEPLOY.md`.

Never hardcode secrets.

## Definition of Done

A task is complete only when:

- implementation is complete for the defined scope;
- relevant checks/tests were run, or the reason they were not run is documented;
- behavior changes are documented in `DEVLOG.md`;
- current progress is reflected in `CURRENT_STATE.md`;
- architectural/product decisions are documented in `DECISIONS.md`;
- unresolved issues are documented in `BACKLOG.md`;
- specs/schemas/docs are updated if the task changed rules, payloads, permissions, UX, copy, analytics or data behavior.

## Task closing summary

At the end of every task, provide a concise summary with:

- files changed;
- behavior changed;
- docs/specs/schemas updated;
- tests/checks run;
- decisions made;
- blockers or open questions;
- recommended next step.
