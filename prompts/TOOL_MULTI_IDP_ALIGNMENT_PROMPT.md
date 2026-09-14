Status: deferred long-term provider-neutral migration prompt. Do not apply it to the D-045 temporary legacy bridge: that bridge deliberately requires no consumer/tool change and preserves the current v1 contract.

Align this tool with a future separately approved Access Layer provider-neutral login contract. Do not add Google or Microsoft SDKs, provider credentials, provider callbacks or ID-token validation to the tool: Access Layer remains the only identity broker and token authority.

First read this tool's `AGENTS.md` and repository source-of-truth files, then read the Access Layer integration contract supplied with the task, including the approved v2 endpoint/payload schemas. Inspect the current login, callback, one-time-code exchange, server-side session, refresh, introspection, logout, JWT validation, authorization and logging paths before changing anything. Record contradictions or missing contract details instead of inventing them.

Required outcome:

- change only the browser login entrypoint from the frozen Google-only Access Layer v1 start URL to the approved multi-provider Access Layer entrypoint;
- preserve a high-entropy tool-generated `state`, store it server-side with a short expiry and verify it exactly on callback;
- keep the callback and one-time-code exchange server-side, using `ACCESS_LAYER_INTERNAL_BASE_URL` and the existing tool client credentials;
- keep Access Layer access and refresh tokens exclusively in protected server-side storage;
- preserve activity-driven refresh, atomic refresh-token replacement, same-session concurrency control, introspection and logout behavior;
- consume the approved provider-neutral user fields such as stable Access Layer subject, `identity_provider`, `email`, `email_verified`, `organization_domain` and display name;
- stop treating `google_sub`, `hd`, email or UPN as a provider-independent primary key; retain Google-only fields only where the approved compatibility schema explicitly includes them;
- key local authorization/session identity by the approved stable Access Layer subject, not by email;
- apply exactly the existing tool roles and permissions from Access Layer; do not infer authorization from provider, tenant or email domain;
- log only the approved stable subject, identity-provider name, tool slug, Access Layer session ID, correlation ID, action and outcome; never log provider authorization codes, ID/access/refresh tokens, cookies, client secrets, PKCE material or raw callback bodies;
- keep the frozen v1 integration available behind the approved rollback/configuration switch until the pilot exit criteria are met;
- update environment templates and deployment documentation without committing real secrets.

Add meaningful tests for both `google` and `microsoft_entra` v2 exchange/introspection fixtures, state mismatch, absent required provider-neutral fields, refresh-token rotation, concurrent refresh serialization, invalid session cleanup, logout and rollback to the existing v1 login entrypoint. The tool must not need to know the Testbirds tenant ID or validate Microsoft tokens; those checks belong to Access Layer.

Before implementation, list any place where this tool persists, queries, logs or authorizes by `google_sub`, `hd` or email. If changing that identity key requires a data migration or could merge two existing people, stop on that part, add a blocker and propose a reversible migration plan. Never auto-link Google and Microsoft accounts by email.

Acceptance criteria:

1. An UNGUESS Google user and a Testbirds Microsoft user can complete the same Access Layer callback/exchange/session flow using synthetic fixtures.
2. The tool makes no direct request to Google or Microsoft and contains no provider credential.
3. Provider choice does not change tool permissions or bypass an Access Layer grant.
4. Existing v1 Google login remains available for rollback during the approved compatibility window.
5. Refresh, introspection, logout, secure cookie attributes and secret redaction remain at least as strict as before.
6. Relevant lint, build, unit/integration and contract tests pass, and documentation/current-state/devlog files are updated according to the repository rules.

In the final summary report files changed, behavior changed, contracts/docs updated, tests run, decisions, blockers and the recommended next rollout step.
