#!/usr/bin/env python3
"""Read environment only; never load dotenv files. No CA requests are made."""
import ipaddress
import os
import pathlib
import re
import sys


def validate_image(image, name="APP_IMAGE"):
    match = re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._:/-]*@sha256:([a-f0-9]{64})", image)
    if not match or match[1] == "0" * 64 or ":latest@" in image:
        raise ValueError(f"{name} must be a complete, nonzero immutable digest reference")


def check():
    if sys.platform != "linux":
        raise ValueError("host-network Compose requires Linux")
    validate_image(os.environ.get("APP_IMAGE", ""))
    validate_image(os.environ.get("CADDY_IMAGE", ""), "CADDY_IMAGE")
    for name in ("SERVICE_PUBLIC_IPS", "ACME_EMAIL", "APEX_DATA_DIR"):
        if not os.environ.get(name):
            raise ValueError(f"{name} is required")
    for value in os.environ["SERVICE_PUBLIC_IPS"].split(","):
        if not ipaddress.ip_address(value.strip()).is_global:
            raise ValueError("SERVICE_PUBLIC_IPS must contain only real public IPs")
    mode = os.environ.get("MODE", "selfhost")
    if mode not in ("selfhost", "public"):
        raise ValueError("MODE must be selfhost or public")
    if mode == "selfhost" and not os.environ.get("ALLOWED_DOMAINS", "").strip():
        raise ValueError("selfhost requires ALLOWED_DOMAINS")
    if os.environ.get("ADMISSION_ENABLED", "true") != "true":
        raise ValueError("release startup requires ADMISSION_ENABLED=true")
    ca = os.environ.get("ACME_CA", "https://acme-staging-v02.api.letsencrypt.org/directory")
    if ca not in (
        "https://acme-staging-v02.api.letsencrypt.org/directory",
        "https://acme-v02.api.letsencrypt.org/directory",
    ):
        raise ValueError("release issuer must be Let's Encrypt")
    if ca == "https://acme-v02.api.letsencrypt.org/directory" and os.environ.get(
        "PRODUCTION_ACME_APPROVED"
    ) != "yes":
        raise ValueError("production ACME requires explicit PRODUCTION_ACME_APPROVED=yes")
    root = pathlib.Path(os.environ["APEX_DATA_DIR"])
    if not root.is_absolute() or root.is_symlink() or not root.is_dir():
        raise ValueError("APEX_DATA_DIR must be an existing absolute non-symlink directory")
    if root.stat().st_mode & 0o077:
        raise ValueError("APEX_DATA_DIR must have private mode 0700")
    for name, uid in (("app", 10001), ("caddy", 10002)):
        path = root / name
        if path.is_symlink() or not path.is_dir():
            raise ValueError(f"provision {path} without symlinks before startup")
        stat = path.stat()
        if stat.st_uid != uid or stat.st_mode & 0o077:
            raise ValueError(f"{path} requires owner {uid} and private mode 0700")


if __name__ == "__main__":
    try:
        check()
    except (ValueError, OSError) as exc:
        sys.exit(f"preflight: {exc}")
    print("Release configuration passed; this is not production-readiness approval.")
