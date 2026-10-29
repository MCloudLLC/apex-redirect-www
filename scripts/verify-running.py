#!/usr/bin/env python3
"""Verify exactly the expected running Compose containers; print a restart fingerprint."""
import json
import os
import subprocess
import sys

COMPOSE = ["docker", "compose", "--env-file", "/dev/null", "-f", "deploy/compose.yaml"]
FORMAT = '{"state":{{json .State}},"image":{{json .Config.Image}},"restarts":{{json .RestartCount}}}'


def verify():
    fingerprint = {}
    version = os.environ.get("RELEASE_VERSION", "latest")
    expected_images = {
        "app": f"ghcr.io/mcloudllc/apex-redirect-www:{version}",
        "caddy": f"ghcr.io/mcloudllc/apex-redirect-www-caddy:{version}",
    }
    for service in ("app", "caddy"):
        ids = subprocess.check_output(COMPOSE + ["ps", "--all", "--quiet", service],
                                      text=True).split()
        if len(ids) != 1:
            raise ValueError(f"{service}: expected exactly one existing container")
        info = json.loads(subprocess.check_output(
            ["docker", "inspect", "--format", FORMAT, ids[0]], text=True))
        state = info["state"]
        if not state["Running"] or state["Restarting"] or state["Status"] != "running":
            raise ValueError(f"{service}: container is not running normally")
        if info["image"] != expected_images[service]:
            raise ValueError(f"{service}: running image does not match RELEASE_VERSION")
        fingerprint[service] = [ids[0], state["StartedAt"], info["restarts"]]
    return fingerprint


if __name__ == "__main__":
    try:
        print(json.dumps(verify(), sort_keys=True))
    except (ValueError, KeyError, OSError, subprocess.CalledProcessError) as exc:
        sys.exit(f"runtime verification: {exc}")
