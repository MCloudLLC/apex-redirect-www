#!/usr/bin/env bash
set -euo pipefail
test "$#" -gt 0 || {
  echo "usage: $0 IMAGE [IMAGE ...]" >&2
  exit 2
}
scanner=aquasec/trivy:0.69.3@sha256:bcc376de8d77cfe086a917230e818dc9f8528e3c852f7b1aff648949b6258d1c
for image in "$@"; do
  docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
    "$scanner" image --no-progress --scanners vuln --severity HIGH,CRITICAL --exit-code 1 "$image"
done
