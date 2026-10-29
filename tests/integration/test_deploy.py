import importlib.util
import hashlib
import io
import os
from pathlib import Path
import shutil
import shlex
import subprocess
import tarfile
import unittest
from unittest.mock import patch
import uuid
import sys

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("preflight", ROOT / "scripts/preflight.py")
preflight = importlib.util.module_from_spec(spec)
spec.loader.exec_module(preflight)


class ReleaseGate(unittest.TestCase):
    def test_digest_references_fail_closed(self):
        preflight.validate_image("ghcr.io/owner/apex@sha256:" + "1" * 64)
        for value in ("", "apex", "apex:latest", "apex:v1", "apex@sha256:" + "0" * 64,
                      "apex:latest@sha256:" + "1" * 64, "apex@sha256:123", "@sha256:" + "1" * 64):
            with self.subTest(value=value), self.assertRaises(ValueError):
                preflight.validate_image(value)

    def test_private_service_address_and_launch_gates(self):
        baseline = {"APP_IMAGE": "example.invalid/apex@sha256:" + "1" * 64,
                    "CADDY_IMAGE": "example.invalid/caddy@sha256:" + "2" * 64,
                    "SERVICE_PUBLIC_IPS": "93.184.216.34", "ACME_EMAIL": "ops@example.com",
                    "APEX_DATA_DIR": str(ROOT / "nonexistent-data")}
        for changes, message in (
            ({"CADDY_IMAGE": "caddy:latest"}, "CADDY_IMAGE"),
            ({"SERVICE_PUBLIC_IPS": "127.0.0.1"}, "real public"),
            ({}, "ALLOWED_DOMAINS"),
            ({"MODE": "public"}, "PUBLIC_LAUNCH_GATES_APPROVED"),
            ({"ALLOWED_DOMAINS": "example.com", "ADMISSION_ENABLED": "false"}, "ADMISSION_ENABLED"),
            ({"ALLOWED_DOMAINS": "example.com", "ACME_CA": "https://unintended.invalid"}, "Let's Encrypt"),
            ({"ALLOWED_DOMAINS": "example.com",
              "ACME_CA": "https://acme-v02.api.letsencrypt.org/directory"}, "PRODUCTION_ACME_APPROVED"),
        ):
            with self.subTest(changes=changes), patch.dict(os.environ, baseline | changes, clear=True):
                with self.assertRaisesRegex(ValueError, message):
                    preflight.check()


class EncryptedRecovery(unittest.TestCase):
    def setUp(self):
        self.work = ROOT / (".integration-recovery-" + uuid.uuid4().hex)
        self.work.mkdir(mode=0o700)
        self.addCleanup(shutil.rmtree, self.work)
        self.identity = self.work / "test-only-age-identity"
        subprocess.run(["age-keygen", "-o", str(self.identity)], check=True, capture_output=True)
        self.recipient = subprocess.run(["age-keygen", "-y", str(self.identity)], check=True,
                                        capture_output=True, text=True).stdout.strip()
        self.archive = self.work / "snapshot.tar.age"
        self.target = self.work / "restored"

    def create_archive(self, unsafe=False, plaintext=False):
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w") as archive:
            for name, value in (("app/state.db", b"test policy state"),
                                ("caddy/test-only.key", b"test certificate key material"),
                                ("deploy/Caddyfile", b"test release manifest")):
                info = tarfile.TarInfo("../escape" if unsafe else name)
                info.mode = 0o600
                info.uid = os.getuid()
                info.gid = os.getgid()
                info.size = len(value)
                archive.addfile(info, io.BytesIO(value))
        if plaintext:
            self.archive.write_bytes(buffer.getvalue())
        else:
            subprocess.run(["age", "--recipient", self.recipient, "--output", str(self.archive)],
                           input=buffer.getvalue(), check=True, capture_output=True)
        digest = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        Path(str(self.archive) + ".sha256").write_text(f"{digest}\n")

    def restore(self):
        return subprocess.run(["bash", "scripts/snapshot.sh", "restore", str(self.archive),
                               str(self.target)], cwd=ROOT, capture_output=True, text=True,
                              env=dict(os.environ, AGE_IDENTITY_FILE=str(self.identity)))

    def test_encrypted_restore_preserves_state_and_refuses_overwrite(self):
        self.create_archive()
        self.assertNotIn(b"test certificate key material", self.archive.read_bytes())
        result = self.restore()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.target / "app/state.db").read_bytes(), b"test policy state")
        self.assertEqual((self.target / "caddy/test-only.key").read_bytes(), b"test certificate key material")
        self.assertEqual((self.target / "caddy/test-only.key").stat().st_mode & 0o777, 0o600)
        self.assertNotEqual(self.restore().returncode, 0)

    def test_restore_rejects_plaintext_and_checksum_corruption(self):
        self.create_archive(plaintext=True)
        self.assertNotEqual(self.restore().returncode, 0)
        self.assertFalse(self.target.exists())
        self.archive.write_bytes(b"corrupted")
        self.assertNotEqual(self.restore().returncode, 0)
        self.assertFalse(self.target.exists())

    def test_restore_rejects_encrypted_path_traversal_before_writing(self):
        self.create_archive(unsafe=True)
        self.assertNotEqual(self.restore().returncode, 0)
        self.assertFalse(self.target.exists())
        self.assertFalse((self.work / "escape").exists())


class RuntimeScriptChecks(unittest.TestCase):
    def setUp(self):
        self.work = ROOT / (".integration-runtime-" + uuid.uuid4().hex)
        self.work.mkdir(mode=0o700)
        self.addCleanup(shutil.rmtree, self.work)
        self.trace = self.work / "commands"
        self.env = dict(os.environ, PATH=str(self.work) + os.pathsep + os.environ["PATH"],
                        APP_IMAGE="example.invalid/app@sha256:" + "1" * 64,
                        CADDY_IMAGE="example.invalid/caddy@sha256:" + "2" * 64,
                        RELEASE_CERTIFICATE_IDENTITY="https://example.invalid/release",
                        APEX_DATA_DIR=str(self.work / "data"), AGE_RECIPIENT="test-public-recipient",
                        MOCK_TRACE=str(self.trace))
        self.helper("python3", "#!/usr/bin/env bash\n"
                    'if test "$1" = scripts/preflight.py; then exit 0; fi\n'
                    f'exec {shlex.quote(sys.executable)} "$@"\n')
        self.helper("cosign", "#!/usr/bin/env bash\nexit 0\n")
        self.helper("age", "#!/usr/bin/env bash\nexit 0\n")
        self.helper("curl", "#!/usr/bin/env bash\n"
                    'printf "curl %s\\n" "$*" >>"$MOCK_TRACE"\n'
                    'case "$*" in *127.0.0.1:2019*) test "${MOCK_ADMIN_DOWN:-0}" != 1 ;;'
                    ' *) exit 0 ;; esac\n')
        self.helper("docker", f"#!{sys.executable}\n" + '''
import json, os, sys
args = sys.argv[1:]
with open(os.environ["MOCK_TRACE"], "a") as log:
    log.write("docker " + " ".join(args) + "\\n")
if "ps" in args:
    print(args[-1])
elif args[0] == "inspect":
    service = args[-1]
    mode = os.environ.get("MOCK_CADDY" if service == "caddy" else "MOCK_APP", "running")
    started = "2026-10-28T00:00:00Z"
    if service == "caddy" and os.environ.get("MOCK_RESTART_DURING_READY"):
        from pathlib import Path
        counter = Path(os.environ["MOCK_TRACE"] + ".inspections")
        count = int(counter.read_text()) + 1 if counter.exists() else 1
        counter.write_text(str(count))
        started = str(count)
    print(json.dumps({"image": os.environ["APP_IMAGE" if service == "app" else "CADDY_IMAGE"],
                      "restarts": 0, "state": {"Running": mode != "exited",
                      "Restarting": mode == "restarting", "Status": mode,
                      "StartedAt": started}}))
''')

    def helper(self, name, content):
        path = self.work / name
        path.write_text(content)
        path.chmod(0o700)

    def invoke(self, script, *args, **changes):
        return subprocess.run(["bash", "scripts/" + script, *map(str, args)], cwd=ROOT,
                              env=self.env | changes, capture_output=True, text=True)

    def test_release_requires_caddy_running_and_admin_responsive(self):
        for state in ("exited", "restarting"):
            with self.subTest(state=state):
                result = self.invoke("release.sh", MOCK_CADDY=state)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("caddy: container is not running normally", result.stderr)
        self.assertNotEqual(self.invoke("release.sh", MOCK_ADMIN_DOWN="1").returncode, 0)
        self.assertNotEqual(self.invoke("release.sh", MOCK_APP="exited").returncode, 0)
        restarted = self.invoke("release.sh", MOCK_RESTART_DURING_READY="1")
        self.assertNotEqual(restarted.returncode, 0)
        self.assertIn("container restarted during readiness", restarted.stderr)
        result = self.invoke("release.sh")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("127.0.0.1:2019/config/", self.trace.read_text())

    def test_backup_of_stopped_release_neither_quiesces_nor_starts_services(self):
        result = self.invoke("snapshot.sh", "backup", self.work / "backup.age",
                             MOCK_CADDY="exited")
        self.assertNotEqual(result.returncode, 0)
        commands = self.trace.read_text()
        self.assertNotIn(" stop ", commands)
        self.assertNotIn(" start ", commands)
        self.assertFalse((self.work / "backup.age").exists())
