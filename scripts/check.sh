#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
unformatted=$(gofmt -l .)
test -z "$unformatted" || {
  printf 'Unformatted Go files:\n%s\n' "$unformatted" >&2
  exit 1
}
go vet ./...
go test -race ./...
for file in scripts/*.sh; do bash -n "$file"; done
shellcheck scripts/*.sh
shfmt -d -i 2 scripts
python3 -m unittest discover -s tests/integration -p test_deploy.py -v
caddy_image=caddy:2.11.7-alpine@sha256:eb4d35b7452d1ab6171fbdbe8d9275b2301dad6dad92115d91e19fb9b24d510f
docker run --rm -v "$PWD/deploy/Caddyfile:/Caddyfile:ro" "$caddy_image" \
  caddy fmt /Caddyfile | cmp deploy/Caddyfile -
docker run --rm -v "$PWD/deploy/Caddyfile:/Caddyfile:ro" "$caddy_image" \
  caddy validate --config /Caddyfile --adapter caddyfile
# Render only; deliberately synthetic values never start services or request certs.
SERVICE_PUBLIC_IPS=93.184.216.34 ACME_EMAIL=ci@example.invalid \
  ALLOWED_DOMAINS=example.com APEX_DATA_DIR="$PWD/data" \
  docker compose --env-file /dev/null -f deploy/compose.yaml config --quiet
