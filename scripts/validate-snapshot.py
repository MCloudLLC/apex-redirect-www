#!/usr/bin/env python3
"""Validate decrypted tar metadata in a stream; never persist plaintext keys."""
import sys
import tarfile

with tarfile.open(fileobj=sys.stdin.buffer, mode="r|*") as archive:
    for member in archive:
        parts = member.name.split("/")
        if parts[0] not in ("app", "caddy", "deploy", "compose.rendered.json") or ".." in parts:
            raise SystemExit("unsafe archive path")
        if not (member.isfile() or member.isdir()):
            raise SystemExit("only regular files and directories may be restored")
        if member.mode & 0o7000:
            raise SystemExit("special permission bits are forbidden")
