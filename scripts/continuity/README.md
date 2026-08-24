# Continuity evidence helpers

These tools collect narrow, read-only metadata for the production continuity evidence bundle:

- `collect-runtime-metadata.mjs`: allowlisted runtime identity and sensitive environment-variable presence booleans;
- `fingerprint-public-jwks.mjs`: public JWKS `kid` values and RFC 7638 SHA-256 fingerprints;
- `collect-postgres-metadata.mjs`: PostgreSQL version, database name, schema fingerprint, migration identifiers, and metadata counts in a read-only transaction.

They do not modify production or the evidence YAML. They fail closed when required observations are unavailable. Do not change them to print process environments, connection strings, response bodies, private/symmetric JWK members, SQL row contents, or driver error messages.

The operator workflow and safe invocation rules are in `operations/PRODUCTION_CONTINUITY_COLLECTION.md`.
