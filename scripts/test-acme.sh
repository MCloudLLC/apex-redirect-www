#!/usr/bin/env bash
# A shared container network namespace also works with Docker Desktop, where
# --network host does not share the CLI machine's loopback interface.
set -euo pipefail
cd "$(dirname "$0")/.."
name="apex-acme-test-$(python3 -c 'import uuid; print(uuid.uuid4().hex[:12])')"
binary="$PWD/.integration-bin-$name"
h2binary="$PWD/.integration-h2-$name"
trap 'rm -f "$binary" "$h2binary"' EXIT
CGO_ENABLED=0 go build -o "$binary" .
CGO_ENABLED=0 go build -o "$h2binary" ./tests/integration/h2probe
docker run --rm --name "$name" \
  --user "$(id -u):$(id -g)" --group-add "$(stat -c %g /var/run/docker.sock)" \
  -e "TEST_DOCKER_NETWORK=container:$name" -e "APEX_TEST_BINARY=$binary" \
  -e "APEX_H2_BINARY=$h2binary" \
  -e "ACME_TEST_LOGS=${ACME_TEST_LOGS:-}" \
  -v "$PWD:$PWD" -w "$PWD" \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$(readlink -f "$(command -v docker)"):/usr/local/bin/docker:ro" \
  python:3.13-alpine@sha256:8bcfa47b04b853a17aaf909362b847b2112fd6ec4105ea553ef9a43bafbb5916 \
  python3 -m unittest discover -s tests/integration -p test_local_acme.py -v
