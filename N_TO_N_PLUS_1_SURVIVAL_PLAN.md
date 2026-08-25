# N→N+1 Session and Refresh Survival Harness

## Status

`DOCUMENTED_NOT_RUN`. Step 1.5B did not receive two real Access Layer versions or immutable deployable images, a verified production backup, or an isolated restored database. It cannot claim restore, session, or refresh survival.

## Staged evidence gates

Validate the reviewed, redacted working evidence bundle according to `operations/PRODUCTION_CONTINUITY_COLLECTION.md`:

```sh
python scripts/validate_production_continuity.py <reviewed-redacted-evidence.yml> --json
```

The first gate, `gates.ready_for_isolated_restore`, must be true before a separately authorised isolated restore exercise starts. It requires observed live topology and immutable N identity, real PostgreSQL and file-backed JWT-key storage mappings, backup metadata, schema/migration metadata, complete source-derived configuration states/effective safe values, external proof of continuity-secret sameness, public JWT identity, registry/ownership records, and pre-restore approvals. It does not claim that a restore passed.

After that authorised exercise, record the isolated result and proof. The second gate, `gates.ready_for_n_to_n_plus_1`, remains false until `backup.restore_test.status` is `PASSED`, the target is proven isolated, the restore evidence and approval are present, and all final approvals are recorded. Repository expectations never substitute for observations, and the validator does not start either exercise.

## Preconditions for N→N+1 execution

1. Require a reviewed bundle for which `ready_for_n_to_n_plus_1` is true; preserve its hash in the test report.
2. Identify immutable version N and N+1 image digests built from reviewed commits. N must match the reviewed live identity where observable.
3. Use the already proven isolated restored database; never restore over production.
4. Bind the same JWT signing material, `JWT_PUBLIC_KEY_ID`, `SESSION_SECRET`, `TOOL_CLIENT_SECRET_PEPPER`, relevant encryption/OAuth secrets, and behavior-sensitive configuration. Reference external sameness proof without copying secrets or reusable verifiers.
5. Preserve the verified PostgreSQL and file-backed `/run/secrets` persistence mappings. Do not rename or create production volumes.
6. Register a synthetic tool/client and synthetic Workspace identity; never copy live credentials or tokens.
7. Capture evidence-bundle, safe config, migration, and image digests in the test report.

## Harness sequence

1. Start N against the isolated database and issue a tool session through start/callback/exchange.
2. Save only encrypted harness credentials; record JWT claims, session ID, grant, expiry timestamps and refresh-token lineage without logging raw tokens.
3. On N, verify `/v1/me`, local JWT validation, JWKS validation and introspection active state.
4. Rotate refresh once on N and verify the old refresh token is rejected as single-use.
5. Keep a second active N-issued refresh token unconsumed for the transition.
6. Stop N cleanly and start N+1 against the same database, signing material, continuity secrets, and configuration, with no destructive migration.
7. Verify the N-issued access JWT still validates until its original expiry and that `/v1/me`/introspection remain consistent.
8. Refresh the preserved N-issued token on N+1; verify one successful rotation, stable session ID, unchanged user/tool/grant shape and rejection of replay.
9. Confirm logout on N+1 revokes the transitioned session and all associated refresh tokens.
10. Roll back to N using the documented deployment strategy and verify that data written during the compatible window remains readable, or document why rollback is intentionally one-way.

## Required assertions

- No endpoint, payload member, claim, status, TTL default, cookie attribute or permission changes.
- N JWT `iss`, `aud`, `sub`, `sid`, `tool_slug`, `permissions`, `role`, `kid` and RS256 validation survive on N+1.
- N refresh token can be consumed exactly once on N+1 and rotates atomically.
- Session/grant/user/tool disable and revocation checks remain effective.
- Signing-key source/persistence, secret bindings, and behavior-sensitive effective configuration remain continuous.
- No raw tokens, cookies, authorization codes, client secrets, private keys, secret digests/verifiers, or personal payloads appear in logs or reports.
- Database row counts and relevant constraints remain consistent.

## Evidence bundle

The completed report must include both image digests, both commit IDs, sanitized request/response hashes, database migration list, safe config-name/value diff, signing-key source and public fingerprint evidence, external continuity-secret references, test timestamps, rollback outcome, and operator approval. A pass requires all assertions and a real N→N+1 transition; mocks or two tags pointing at one image are insufficient.
