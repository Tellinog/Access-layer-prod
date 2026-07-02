# AGENT_TASK_PROMPT.md

```text
Task:
{{describe the implementation or fix}}

Expected outcome:
{{describe observable result}}

Relevant docs:
- AGENTS.md
- docs/API.md
- docs/SECURITY.md
- docs/INTEGRATION_GUIDE.md
- docs/IMPLEMENTATION_PLAN.md

Constraints:
- Do not log secrets/tokens/codes.
- Preserve API contract unless docs/schemas are updated.
- Deny by default on auth uncertainty.
- Add or update tests.

Closing summary required:
files changed, behavior changed, docs/specs/schemas updated, tests run, decisions, blockers, next step.
```
