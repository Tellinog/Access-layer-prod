# N→N+1 Session and Refresh Survival Harness

## Status

`DOCUMENTED_NOT_RUN`. Step 1.5 did not receive two real Access Layer versions or immutable deployable images, a verified production backup, or an isolated restored database and therefore cannot claim session or refresh survival.

## Step 1.5 evidence gate

Before selecting N or executing this harness, an authorised operator must complete `operations/production-continuity.evidence.yml` according to `operations/PRODUCTION_CONTINUITY_COLLECTION.md` and obtain a `READY` result from:

```sh
python scripts/validate_production_continuity.py <reviewed-redacted-evidence.yml>
```

The gate supplies the observed live topology, immutable N identity, real PostgreSQL storage mapping, backup/restore proof, schema and migration metadata, continuity-sensitive environment presence, public JWT `kid`/fingerprint, deployment settings, owners, and registry record. Repository expectations cannot substitute for observed fields. The validator does not start the harness or update platform manifests.

## Preconditions

1. Require a reviewed production-continuity evidence bundle with status `READY`; preserve its hash in the test report.
2. Identify immutable version N and N+1 image digests built from reviewed commits. N must match the reviewed live identity where observable.
3. Restore the evidence bundle's identified, verified PostgreSQL backup into an isolated test environment.
4. Use the same JWT signing key, `JWT_PUBLIC_KEY_ID`, `SESSION_SECRET`, token pepper, encryption configuration and schema state for the controlled transition.
5. Verify the Compose/Coolify volume mapping and take a restorable backup before any upgrade exercise.
6. Register a synthetic tool/client and synthetic Workspace identity; never copy live credentials or tokens.
7. Capture evidence-bundle, config, migration and image digests in the test report.

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
