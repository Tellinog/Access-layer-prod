#!/usr/bin/env sh
set -eu

is_enabled() {
  case "${1:-}" in
    1|true|TRUE|yes|YES|on|ON) return 0 ;;
    *) return 1 ;;
  esac
}

if [ -z "${JWT_PRIVATE_KEY_PEM:-}" ] && [ -n "${JWT_PRIVATE_KEY_PEM_PATH:-}" ] && [ ! -s "$JWT_PRIVATE_KEY_PEM_PATH" ]; then
  mkdir -p "$(dirname "$JWT_PRIVATE_KEY_PEM_PATH")"
  openssl genrsa -out "$JWT_PRIVATE_KEY_PEM_PATH" 2048 >/dev/null 2>&1
  chmod 600 "$JWT_PRIVATE_KEY_PEM_PATH"
  echo "Generated local JWT signing key at configured path."
fi

if is_enabled "${RUN_MIGRATIONS_ON_START:-true}"; then
  node dist/src/cli/migrate.js
fi

if is_enabled "${RUN_SEED_ON_START:-false}"; then
  node dist/src/cli/seed.js
fi

exec "$@"
