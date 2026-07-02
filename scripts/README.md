# scripts

These scripts wrap the Node.js/TypeScript implementation commands.

- `setup.sh`: install npm dependencies.
- `migrate.sh`: run SQL migrations through the TypeScript migration runner. Only `DATABASE_URL` is required for migration execution.
- `seed.sh`: load local development reference data.
- `test.sh`: run Vitest.
- `lint.sh`: run TypeScript typecheck.
- `export.sh`: run the production build.

Scripts must not print secrets.
