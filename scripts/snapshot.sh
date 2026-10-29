#!/usr/bin/env bash
# backup ARCHIVE: stop both writers, archive protected data, resume existing release.
# restore ARCHIVE NEW_DIRECTORY: offline extraction only; never overwrite active data.
# Rollback: stop both services, select the archived release version/configuration,
# restore only if needed into a NEW directory, then run release.sh explicitly.
# Retain original directories and certificates; never compose down -v.
set -euo pipefail
umask 077
cd "$(dirname "$0")/.."
command -v age >/dev/null || {
  echo "age is required; plaintext backups and restore are forbidden" >&2
  exit 1
}
test "$#" -ge 2 || {
  echo "usage: $0 backup ARCHIVE | restore ARCHIVE NEW_DIRECTORY" >&2
  exit 2
}
case "$1" in
backup)
  test "$#" -eq 2
  : "${AGE_RECIPIENT:?Set the offline backup public age recipient}"
  python3 scripts/preflight.py
  if test -e "$2" || test -L "$2" || test -e "$2.sha256" || test -L "$2.sha256"; then
    echo "archive already exists" >&2
    exit 1
  fi
  archive=$(realpath -m "$2")
  case "$archive" in "$APEX_DATA_DIR"/*)
    echo "archive must be outside data directory" >&2
    exit 1
    ;;
  esac
  compose=(docker compose --env-file /dev/null -f deploy/compose.yaml)
  # Only resume a release that was already running; never start a stopped one.
  python3 scripts/verify-running.py >/dev/null
  metadata="$PWD/.integration-snapshot-$(python3 -c 'import uuid; print(uuid.uuid4().hex)')"
  mkdir -m 0700 "$metadata"
  trap 'rm -rf "$metadata"' EXIT
  "${compose[@]}" config --format json >"$metadata/compose.rendered.json"
  trap 'rm -rf "$metadata"; "${compose[@]}" start app caddy' EXIT
  "${compose[@]}" stop caddy app
  tar -cpf - -C "$APEX_DATA_DIR" app caddy \
    -C "$PWD" deploy/Caddyfile deploy/compose.yaml \
    -C "$metadata" compose.rendered.json |
    age --recipient "$AGE_RECIPIENT" --output "$archive"
  checksum=$(sha256sum "$archive")
  printf '%s\n' "${checksum%% *}" >"$archive.sha256"
  ;;
restore)
  test "$#" -eq 3
  : "${AGE_IDENTITY_FILE:?Set the protected age identity FILE path, never a secret value}"
  if test -e "$3" || test -L "$3"; then
    echo "restore target must not exist" >&2
    exit 1
  fi
  read -r expected <"$2.sha256"
  checksum=$(sha256sum "$2")
  test "${checksum%% *}" = "$expected" || {
    echo "encrypted archive checksum mismatch" >&2
    exit 1
  }
  # Validate archive paths and links before writing any file.
  age --decrypt --identity "$AGE_IDENTITY_FILE" "$2" |
    python3 scripts/validate-snapshot.py
  mkdir -m 0700 "$3"
  age --decrypt --identity "$AGE_IDENTITY_FILE" "$2" |
    tar --same-owner -xpf - -C "$3"
  echo "Restored offline. Review ownership, accepted release images and config; start explicitly."
  ;;
*)
  echo "unknown action" >&2
  exit 2
  ;;
esac
