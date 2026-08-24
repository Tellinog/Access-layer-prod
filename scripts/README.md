# scripts

## Production continuity (Step 1.5)

- `validate_production_continuity.py` validates the versioned evidence schema and returns `0` for `READY`, `2` for `VALID_BUT_NOT_READY`, or `1` for invalid/unsafe evidence. It is read-only and never updates platform manifests.
- `continuity/` contains allowlisted, read-only production metadata helpers. See `continuity/README.md` and `operations/PRODUCTION_CONTINUITY_COLLECTION.md` before use.

These scripts wrap the Node.js/TypeScript implementation commands.

- `setup.sh`: install npm dependencies.
- `migrate.sh`: run SQL migrations through the TypeScript migration runner. Only `DATABASE_URL` is required for migration execution.
- `seed.sh`: load local development reference data.
- `test.sh`: run Vitest.
- `lint.sh`: run TypeScript typecheck.
- `export.sh`: run the production build.

Scripts must not print secrets.
