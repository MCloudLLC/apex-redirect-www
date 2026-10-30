#!/usr/bin/env bash
# Offline rollback preparation only. Never redeploy or erase current volumes.
set -euo pipefail
cd "$(dirname "$0")/.."
test "$#" -eq 2 || {
  echo "usage: $0 ACCEPTED_ARCHIVE NEW_DIRECTORY" >&2
  exit 2
}
bash scripts/snapshot.sh restore "$1" "$2"
echo "Review archived deploy/ and compose.rendered.json against accepted release evidence."
echo "Stop current services before selecting restored data. Verify the accepted release"
echo "version and scan evidence, then run release.sh with reviewed archived configuration."
