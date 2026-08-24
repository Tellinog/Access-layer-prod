# N→N+1 Session and Refresh Survival Harness

## Status

`DOCUMENTED_NOT_RUN`. Step 1 did not receive two real Access Layer versions or immutable deployable images and therefore cannot claim session or refresh survival.

## Preconditions

1. Identify immutable version N and N+1 image digests built from reviewed commits.
2. Restore a sanitized production-shaped PostgreSQL backup into an isolated test environment.
3. Use the same JWT signing key, `JWT_PUBLIC_KEY_ID`, `SESSION_SECRET`, token pepper, encryption configuration and schema state for the controlled transition.
4. Verify the Compose/Coolify volume mapping and take a restorable backup before any upgrade exercise.
5. Register a synthetic tool/client and synthetic Workspace identity; never copy live credentials or tokens.
6. Capture config, migration and image digests in the test report.

## Harness sequence

1. Start N against the isolated database and issue a tool session through start/callback/exchange.
2. Save only encrypted harness credentials; record JWT claims, session ID, grant, expiry timestamps and refresh-token lineage without logging raw tokens.
3. On N, verify `/v1/me`, local JWT validation, JWKS validation and introspection active state.
4. Rotate refresh once on N and verify the old refresh token is rejected as single-use.
5. Keep a second active N-issued refresh token unconsumed for the transition.
6. Stop N cleanly and start N+1 against the same database and key material, with no destructive migration.
7. Verify the N-issued access JWT still validates until its original expiry and that `/v1/me`/introspection remain consistent.
8. Refresh the preserved N-issued token on N+1; verify one successful rotation, stable session ID, unchanged user/tool/grant shape and rejection of replay.
9. Confirm logout on N+1 revokes the transitioned session and all associated refresh tokens.
10. Roll back to N using the documented deployment strategy and verify that data written during the compatible window remains readable, or document why rollback is intentionally one-way.

## Required assertions

- No endpoint, payload member, claim, status, TTL default, cookie attribute or permission changes.
- N JWT `iss`, `aud`, `sub`, `sid`, `tool_slug`, `permissions`, `role`, `kid` and RS256 validation survive on N+1.
- N refresh token can be consumed exactly once on N+1 and rotates atomically.
- Session/grant/user/tool disable and revocation checks remain effective.
- No raw tokens, cookies, authorization codes, client secrets or personal payloads appear in logs or reports.
- Database row counts and relevant constraints remain consistent.

## Evidence bundle

The completed report must include both image digests, both commit IDs, sanitized request/response hashes, database migration list, config-name diff, test timestamps, rollback outcome and operator approval. A pass requires all assertions and a real N→N+1 transition; mocks or two tags pointing at one image are insufficient.
