#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
python3 scripts/preflight.py
docker compose --env-file /dev/null -f deploy/compose.yaml config --quiet
docker compose --env-file /dev/null -f deploy/compose.yaml pull
docker compose --env-file /dev/null -f deploy/compose.yaml run --rm --no-deps caddy \
  caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
docker compose --env-file /dev/null -f deploy/compose.yaml up -d --no-build
before=$(python3 scripts/verify-running.py)
curl --fail --silent --show-error --retry 20 --retry-delay 1 --retry-connrefused \
  http://127.0.0.1:8081/readyz
curl --fail --silent --show-error --retry 20 --retry-delay 1 --retry-connrefused \
  http://127.0.0.1:2019/config/ >/dev/null
after=$(python3 scripts/verify-running.py)
test "$before" = "$after" || {
  echo "runtime verification: a container restarted during readiness checks" >&2
  exit 1
}
