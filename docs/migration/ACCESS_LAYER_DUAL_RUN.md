# Access Layer dual-run migration

## Purpose

This runbook introduces the Access Layer OAuth/OIDC target profile without changing the behaviour of the existing Access Layer contract. It applies to both the central Access Layer and every project that adopts this template.

## Non-negotiable invariants

1. **Zero forced migration.** A current consumer is not modified merely because Access Layer vNext is deployed.
2. **Zero access loss.** Existing users, tool registrations, grants, sessions, refresh tokens, callbacks and permissions remain valid.
3. **Independent migration.** Web, API and MCP interfaces may migrate separately, one project at a time.
4. **Full rollback.** The new surfaces can be disabled without rewriting or deleting legacy data.
5. **No silent semantic change.** Legacy endpoint paths, request/response fields, JWT claims, audience rules and session lifecycle remain frozen until the consumer opts into a versioned migration.

## Target topology

```text
                         Access Layer
                +-------------+-------------+
                |                           |
      legacy /v1/auth/*             OAuth/OIDC /oauth/*
                |                           |
     existing web tools             new clients and APIs
                |                           |
                +-------------+-------------+
                              |
                  shared identity and entitlement data
                  isolated protocol state and token profiles
```

The two protocol surfaces may share stable user identity, tool/resource metadata, entitlement evaluation and audit infrastructure. They do not share mutable protocol records such as authorization codes, token families or client sessions unless the record is explicitly designed for both protocols.

## Database migration rule

Use expand-migrate-verify-contract:

1. **Expand:** add OAuth/OIDC tables, columns and indexes without removing or reinterpreting legacy fields.
2. **Migrate:** populate derived resource/scope records and enable shadow reads.
3. **Verify:** compare entitlement decisions and run current-consumer contract tests.
4. **Contract:** remove a legacy field only after every consumer is migrated, its active records have expired or been transformed, rollback is no longer required, and a separate removal decision is approved.

The first OAuth/OIDC release must stop after `verify`. Contracting the legacy model is outside its scope.

## Release sequence

### Phase 0 - baseline capture

- record the deployed Access Layer version and Coolify resource;
- record its domains, target services/internal ports, networks, volumes and backups;
- confirm the local deployment registration matches the central registry;
- export non-secret client/tool configuration;
- capture endpoint golden contracts;
- inventory active sessions and refresh-token families by count, not token value;
- record signing-key IDs and maximum token lifetimes;
- run login, exchange, refresh, introspection and logout tests for each existing tool;
- confirm database backup and restore.

### Phase 1 - additive deploy, dark

- deploy new tables and code paths with OAuth/OIDC feature flags off;
- serve no new endpoint to production traffic;
- verify that pre-deploy sessions still work;
- verify that rollback to the previous application version remains possible;
- compare legacy latency and error rate to the baseline.

### Phase 2 - discovery and test clients

- expose metadata and OAuth endpoints to an allowlisted staging client only;
- keep all existing consumers on the legacy profile;
- validate PKCE, resource indicators, audience binding, refresh rotation, revocation, key rotation and error semantics;
- test at least one real MCP client through Agent Gateway;
- exercise failure modes with the OAuth feature disabled.

### Phase 3 - first production consumer

Use a new consumer, preferably Agent Gateway, rather than an existing web tool. Restrict access by client allowlist, environment and resource. Observe token issuance, denials, latency and audit completeness.

### Phase 4 - project-by-project adoption

For each project:

1. add an OAuth resource-server adapter;
2. map both adapters to the same `RequestContext`;
3. keep the current web session path unchanged;
4. expose a read-only or low-risk API capability first;
5. compare legacy and OAuth policy outcomes;
6. expand to mutating capabilities after review;
7. migrate the web login only in a separate change.

### Phase 5 - optional legacy retirement

Legacy retirement is not a template requirement. It requires a separate inventory showing zero active consumers, zero active legacy sessions/tokens beyond the agreed window, completed data migration, tested rollback alternative and explicit product/security approval.

## Session-survival test

A release candidate must prove:

```text
old Access Layer creates session and refresh token
-> deploy new Access Layer
-> old session remains usable
-> old refresh token rotates successfully
-> old access token introspects correctly
-> logout/revocation still works
```

The same sequence is run across rollback where the database migration is declared backward compatible.

## Key continuity

- do not delete a legacy signing key while a token signed by it may still be valid;
- preserve cookie-signing and encryption keys across deploys;
- publish overlapping keys during rotation;
- introduce a distinct OAuth key ring or explicit token type/profile when required;
- validate key compromise procedures separately from routine migration.

## Failure and rollback trigger

Disable the new profile when any of the following is observed:

- legacy login, exchange, refresh, introspection or logout regression;
- active-session invalidation;
- grant or permission divergence;
- token accepted by the wrong audience;
- unexplained increase in legacy authentication errors or latency;
- audit gaps;
- database migration that prevents application rollback.

Disabling OAuth/OIDC must not disable legacy authentication.
