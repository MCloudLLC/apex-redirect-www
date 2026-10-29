#!/usr/bin/env bash
# Persistent block first, full Caddy process restart second. Never erase certs.
# Environment is identical to release.sh. Args: DOMAIN REASON OPERATOR.
set -euo pipefail
cd "$(dirname "$0")/.."
test "$#" -eq 3 || {
  echo "usage: $0 DOMAIN REASON OPERATOR" >&2
  exit 2
}
domain=$1
case "$domain" in
'' | *[!a-z0-9.-]*)
  echo "use a normalized ASCII apex" >&2
  exit 2
  ;;
esac
compose=(docker compose --env-file /dev/null -f deploy/compose.yaml)
case "${RUNTIME:-compose}" in
compose)
  python3 scripts/preflight.py
  "${compose[@]}" exec -T app /apex-redirect block add --kind domain \
    --value "$domain" --reason "$2" --operator "$3"
  ;;
systemd)
  runuser -u apex-redirect -- env "STATE_PATH=${STATE_PATH:-/var/lib/apex-redirect/state.db}" \
    /usr/local/bin/apex-redirect block add --kind domain \
    --value "$domain" --reason "$2" --operator "$3"
  ;;
*)
  echo "RUNTIME must be compose or systemd" >&2
  exit 2
  ;;
esac
status=$(curl --silent --show-error --output /dev/null --write-out '%{http_code}' \
  --get --data-urlencode "domain=$domain" http://127.0.0.1:8081/ask)
test "$status" = 403 || {
  echo "permission must deny with 403; Caddy unchanged" >&2
  exit 1
}
# Reload retains in-memory certificates. Restart discards the entire TLS cache.
case "${RUNTIME:-compose}" in
compose) "${compose[@]}" restart caddy ;;
systemd) systemctl restart caddy.service ;;
esac
curl --fail --silent --show-error --retry 20 --retry-delay 1 --retry-connrefused \
  http://127.0.0.1:2019/config/ >/dev/null
result=0
if curl --insecure --silent --show-error --noproxy '*' --max-time 10 \
  --resolve "$domain:443:127.0.0.1" "https://$domain/" >/dev/null 2>&1; then
  result=0
else
  result=$?
fi
if test "$result" -ne 35; then
  echo "retirement verification FAILED: expected TLS handshake denial (curl35), got $result" >&2
  exit 1
fi
echo "Persistent block installed; post-restart TLS denied. Certificate storage preserved."
