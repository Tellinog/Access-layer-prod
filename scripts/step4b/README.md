# Step 4B real PostgreSQL qualification

Phase 9A.2 extends this same guarded runner to migrations 001–006 and a synthetic native resource with two scopes and linked grants. It retains the full P0 flow, eight same-token refresh races, repeatable-read backup snapshot, encrypted replace restore and old legacy-binary smoke. Native checks cover source/provenance, missing/duplicate writer links, grant state and scope/allowance denials, callback/exchange/refresh/introspection/revocation, post-lock grant mutation ordering and restored native lineage. Run only against a clean committed worktree; the final evidence is attributable to that commit.

`run-qualification.ps1` is a local-only qualification entry point. It creates two distinct, loopback-only PostgreSQL 16 containers with synthetic Step4B database names, applies the existing migrations, runs the real HTTP/database qualification harness, and removes both containers in `finally` cleanup.

Run from the repository root:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/step4b/run-qualification.ps1
```

The harness generates only temporary synthetic credentials and RSA material. It keeps raw OAuth and backup material in memory, removes temporary key and legacy-baseline checkout files automatically, and prints sanitized evidence containing only assertions, counts, migration hashes, and non-secret fingerprints.

This is a disposable qualification tool. It must not be pointed at production, Coolify, a remotely hosted database, or a database without a synthetic Step4B name.
