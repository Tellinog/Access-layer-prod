# Multi-provider authentication discovery plan

Status: historical long-term planning. D-045 and the approved 2026-09-14 hand-off supersede this document only for the narrow temporary legacy bridge. Its provider-neutral recommendations remain deferred and do not describe the implemented bridge.

## Requested outcome

Access Layer should eventually authenticate two workforce populations:

- UNGUESS users through Google Workspace/OpenID Connect;
- Testbirds users through Microsoft Entra/OpenID Connect.

After upstream authentication, both populations use the same Access Layer tool grants, sessions, one-time-code exchange, refresh, introspection, logout and audit authority.

## Current constraints

The live legacy profile is Google-specific and frozen:

- `/v1/auth/start` immediately starts Google login;
- `/v1/auth/google/callback` is the only legacy upstream callback;
- `users.google_sub` and `users.hd` are non-null database fields;
- legacy JWT `sub`, exchange/introspection payloads, admin filters and audit fields explicitly mean Google `sub` and Google hosted domain;
- OAuth vNext P0 also freezes the human subject as Google `sub`, although that runtime remains default-off and has no production pilot.

For a durable multi-provider architecture, Microsoft support still requires a provider-neutral identity model. D-045 is the explicit temporary exception: only the legacy bridge may represent `(tid, oid)` as `msft:<tid>:<oid>` in the frozen Google-named field without treating email as identity.

## Recommended target architecture

This is the recommended direction for review; it is not yet an accepted decision.

```text
tool -> versioned Access Layer login entrypoint -> provider chooser
                                              |-> Google OIDC adapter
                                              `-> Microsoft Entra OIDC adapter
                                                       |
                                               verified canonical identity
                                                       |
                                     Access Layer user + grant + session
                                                       |
                              one-time code -> tool backend exchange
```

Principles:

- tools integrate only with Access Layer and never with Google or Microsoft directly;
- preserve the complete `/v1` Google flow for existing consumers;
- add a versioned multi-provider entrypoint instead of silently changing `/v1/auth/start`;
- use separate provider callbacks and independent state/nonce values;
- normalize verified identities at one boundary before grant evaluation;
- keep email as a mutable lookup/display and pending-grant attribute, never the stable principal key;
- use exact Google `sub` for Google identities and exact Entra `(tid, oid)` for Microsoft identities;
- issue a provider-neutral v2 user/token contract to upgraded tools;
- keep all provider tokens and credentials inside Access Layer.

## Proposed user experience

An upgraded tool sends the browser to the new Access Layer login entrypoint with the existing `tool_slug`, exact callback URL and tool-generated state.

Access Layer validates those values before showing a small page with two actions:

- `Continue with UNGUESS (Google)`;
- `Continue with Testbirds (Microsoft)`.

The page must also show the target tool name, keyboard focus, accessible labels and a generic support path. Provider selection must reference only an opaque, short-lived, single-use Access Layer transaction identifier. It must not copy return URLs, downstream state, provider tokens or secrets into the button URL.

The provider choice is stored and audited before redirecting to the upstream provider. Each provider callback can resume only a transaction created for that same provider.

Existing `/v1/auth/start` continues to redirect directly to Google. Tools move to the chooser only when they adopt the new contract.

## Proposed canonical identity contract

Provider adapters should return an internal structure equivalent to:

```json
{
  "provider": "google|microsoft_entra",
  "issuer": "provider issuer",
  "subject": "provider subject",
  "tenant_id": "Entra tenant GUID or null",
  "provider_object_id": "Entra oid or null",
  "email": "current address",
  "email_verified": true,
  "organization_domain": "unguess.io|nuotounostiledivita.it|testbirds.com",
  "display_name": "optional",
  "picture_url": "optional"
}
```

Stable keys:

- Google: `(provider, issuer, sub)`;
- Microsoft Entra: `(provider, tid, oid)` with issuer/tenant consistency validation.

The proposed downstream v2 identity should expose a provider-neutral stable Access Layer subject plus `identity_provider`, `organization_domain` and current display attributes. Raw upstream access/refresh tokens remain forbidden. Whether downstream tools need the provider-specific subject is an open privacy/API decision.

## Data-model migration problem

The current `users.google_sub NOT NULL UNIQUE` and `users.hd NOT NULL` constraints prevent a truthful Microsoft user row. The safe migration should be staged across releases:

1. **Compatibility preparation release**: add an identity table and provider-neutral read/write types; backfill every existing Google user; dual-read/dual-write Google identity; keep Microsoft disabled and preserve all `/v1` output.
2. **Generic-user release**: update every runtime/admin/backup path to tolerate a user without Google-specific fields, add provider-neutral uniqueness and audit fields, and prove old Google sessions and backups still work.
3. **Contract/enablement release**: only after the rollback window no longer targets a binary that assumes non-null Google fields, relax or retire the Google-only columns, enable one Microsoft pilot and emit only the v2 identity contract for Microsoft users.

Outside D-045, do not fabricate provider identities in `google_sub`. The approved legacy exception uses exactly `msft:<tid>:<oid>`. Never auto-link a Google and Microsoft identity by matching email; cross-provider account linking requires a separate explicit, audited decision.

The exact schema and rollback sequence require a new accepted decision before any migration is written.

## API and compatibility proposal

Recommended boundaries:

- keep `/v1/auth/start`, `/v1/auth/google/callback`, `/v1/auth/exchange`, legacy JWT/JWKS and legacy user payloads unchanged;
- add a new multi-provider login entrypoint and provider callbacks under a new versioned namespace;
- decide whether v2 reuses the current exchange/refresh/introspection paths with content negotiation or introduces `/v2/auth/*`; a separate `/v2/auth/*` family is easier to test and reason about;
- keep one-time-code, tool Basic authentication, exact return URL, activity-driven refresh and logout semantics unchanged unless the contract explicitly says otherwise;
- update the default-off OAuth P0 specification before it is ever enabled, because it currently requires Google `sub` for all humans.

All route names, payloads, claims and migration shapes are proposals until recorded in `DECISIONS.md` and the relevant specs/schemas.

## Work packages

### WP0 — close discovery decisions

Inputs:

- completed Entra handoff from `MICROSOFT_ENTRA_SETUP.md`;
- provider/tenant/guest and email-claim decisions;
- accepted callback namespace and versioning strategy;
- accepted canonical user subject and downstream payload;
- accepted credential/storage/rotation mechanism;
- pilot tool, owner, callback and test users;
- production continuity and independent Step 4B gates resolved or an explicitly separate non-production environment approved.

Output: accepted decisions, revised backlog and implementation acceptance criteria. No code.

### WP1 — contract and compatibility freeze

- add a provider-neutral identity specification and JSON/OpenAPI schemas;
- update security, domain, API, UX, copy, logging, backup and deployment contracts;
- define v1/v2 route and claim matrices;
- define provider-selection, callback and error/audit events;
- amend OAuth P0 human-subject rules or explicitly defer OAuth P0 multi-provider support;
- add synthetic golden fixtures for both providers;
- write the N/N+1/N+2 rollback plan for identity-schema expansion.

### WP2 — dark identity foundation

- add provider-neutral identity types and repositories;
- add an expand-only identity migration and Google backfill;
- keep all Microsoft routes disabled/absent;
- dual-read/dual-write Google without changing `/v1`;
- extend encrypted backup/export/import and restore validation;
- prove old-binary/schema compatibility on PostgreSQL 16.

### WP3 — dark Microsoft adapter and chooser

- add a vetted OIDC/MSAL-compatible server library rather than hand-crafting JWT validation;
- implement tenant-specific discovery, authorization-code exchange and ID-token validation;
- add short-lived provider-selection transactions and separate callbacks;
- add accessible chooser UI and safe errors;
- add provider-specific rate limits and sanitized audit events;
- add all configuration names to environment templates, schemas and deployment docs;
- keep the feature globally default-off and unregistered in production.

### WP4 — tool-contract v2 and reference harness

- implement provider-neutral exchange/introspection/JWT claims;
- update the reference tool harness;
- publish the per-tool Codex prompt;
- test Google and Microsoft identities against the same grant/session behavior;
- prove `/v1` golden compatibility unchanged.

### WP5 — non-production pilot

- configure the separate Entra development registration;
- register one pilot tool and exact callback;
- test assigned member, no-grant member, guest, wrong tenant, invalid claims and Google regression;
- run database backup/restore and session/refresh concurrency checks;
- collect redacted evidence and owner approval.

### WP6 — production rollout

- close the existing deployment/continuity blockers;
- provision the production credential and rotation monitoring;
- deploy dark, then enable one tool/provider pilot;
- monitor success/denial/error/audit metrics by provider without identity in metric labels;
- preserve an immediate server-side disable switch;
- expand to tools individually after their v2 compatibility evidence passes.

## Required test matrix

At minimum:

- existing Google `/v1` golden route, payload, claim, cookie, session and refresh tests;
- chooser input, exact callback and state/nonce replay tests;
- Google v2 happy/denial paths;
- Entra exact tenant/issuer/audience/time/nonce/object/member/domain checks;
- guest, personal account, other tenant, missing email and wrong-domain denial;
- same email at two providers creates separate identities unless explicitly linked;
- pending email grant links only after the approved provider/domain checks;
- tool grant, session, one-time-code, refresh rotation, introspection and logout parity;
- audit redaction for both upstream code/token/credential families;
- backup/restore with Google-only and mixed identities;
- N-to-N+1 and staged rollback evidence before production enablement.

## Decisions required before implementation

1. Is the Testbirds app definitely single-tenant in the authoritative Testbirds workforce tenant?
2. Are B2B guest accounts forbidden? The recommendation is yes, enforced by `acct=0` plus assignment.
3. Is `email` + `xms_edov=true` available for every intended Testbirds member, or is Microsoft Graph required?
4. What is the canonical v2 downstream subject: Access Layer principal ID or a provider-scoped identifier?
5. May a person link Google and Microsoft identities? The recommendation for P0 is no automatic linking.
6. Which exact versioned login/callback/exchange paths are approved?
7. Which credential method and protected storage/rotation owner are approved for production?
8. Which tool is the first pilot, and does it currently rely on `google_sub` or `hd` as a database key?
9. Must the same-service Admin UI support Testbirds administrators in the first pilot?
10. Does Microsoft support apply only to the legacy tool broker, also to the default-off OAuth vNext server, or to both in the same programme?
