# Continuity evidence helpers

These tools collect narrow, read-only metadata for the production continuity evidence bundle:

- `collect-runtime-metadata.mjs`: allowlisted runtime identity, the complete source-derived environment inventory, `ABSENT`/`PRESENT_EMPTY`/`PRESENT_NON_EMPTY` states, safe effective configuration, and file-backed JWT key state without reading key material;
- `fingerprint-public-jwks.mjs`: public JWKS `kid` values and RFC 7638 SHA-256 fingerprints;
- `collect-postgres-metadata.mjs`: PostgreSQL version, database name, schema fingerprint, migration identifiers, and metadata counts in a read-only transaction.

They do not modify production or the evidence YAML. They fail closed when required observations are unavailable. The runtime collector treats an empty required secret differently from absence, requires only state presence for the OAuth transaction protection key when the OAuth flag is true, permits an observed empty `PUBLIC_BASE_PATH`, and screens credential-bearing URLs. Do not change the helpers to print process environments, secret values or reusable verifiers, connection strings, response bodies, private/symmetric JWK members, personal values, SQL row contents, or driver error messages.

The operator workflow and safe invocation rules are in `operations/PRODUCTION_CONTINUITY_COLLECTION.md`.
