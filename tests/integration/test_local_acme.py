#!/usr/bin/env python3
"""Real Caddy + Pebble + Go, local DNS only; never contacts a public CA.

Run: python3 -m unittest discover -s tests/integration -p 'test_local_acme.py' -v
Requires Linux, Docker, Python 3 and Go. Scratch artifacts stay under this repo.
"""
import concurrent.futures
import hashlib
import http.client
import json
import os
from pathlib import Path
import shutil
import socket
import socketserver
import ssl
import struct
import subprocess
import threading
import time
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[2]
CADDY = os.environ.get(
    "ACME_CADDY_IMAGE",
    "caddy:2.11.7-alpine@sha256:eb4d35b7452d1ab6171fbdbe8d9275b2301dad6dad92115d91e19fb9b24d510f",
)
PEBBLE = "ghcr.io/letsencrypt/pebble:2.8.0@sha256:d9080f68f6cb6af8d82134ab26de0aaaf312ac9cba42aecc6d3aede6cb63007b"


def run(*args, **kwargs):
    return subprocess.run(args, cwd=ROOT, check=True, text=True, capture_output=True, **kwargs).stdout


def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class DNS(socketserver.ThreadingUDPServer):
    def __init__(self, validation=False):
        self.validation = validation
        self.withdrawn = set()
        super().__init__(("127.0.0.1", 0), DNSHandler)
        threading.Thread(target=self.serve_forever, daemon=True).start()


class DNSHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        offset, labels = 12, []
        while data[offset]:
            length = data[offset]
            labels.append(data[offset + 1:offset + 1 + length].decode("ascii"))
            offset += length + 1
        name = ".".join(labels)
        end = offset + 5
        qtype = struct.unpack("!H", data[offset + 1:offset + 3])[0]
        ip = "127.0.0.1" if self.server.validation else (
            "1.0.0.1" if name.startswith("www.") else "93.184.216.34"
        )
        answer = b""
        if qtype == 1 and name not in self.server.withdrawn:
            answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 1, 4) + socket.inet_aton(ip)
        response = data[:2] + struct.pack("!HHHHH", 0x8180, 1, bool(answer), 0, 0)
        sock.sendto(response + data[12:end] + answer, self.client_address)


class LocalACME(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work = ROOT / (".integration-" + uuid.uuid4().hex)
        cls.work.mkdir(mode=0o700)
        cls.containers = []
        cls.process = None
        cls.policy_dns = DNS()
        cls.va_dns = DNS(validation=True)
        cls.addClassCleanup(cls.cleanup)
        cls.http, cls.https, cls.app, cls.ask, cls.ca, cls.management, cls.admin = [port() for _ in range(7)]
        cls.env = os.environ.copy()
        cls.env.update({
            "HTTP_ADDR": f"127.0.0.1:{cls.app}", "ASK_ADDR": f"127.0.0.1:{cls.ask}",
            "STATE_PATH": str(cls.work / "state.db"), "SERVICE_PUBLIC_IPS": "93.184.216.34",
            "MODE": "selfhost", "ALLOWED_DOMAINS": "example.com,example.net,example.org",
            "DNS_RESOLVERS": f"127.0.0.1:{cls.policy_dns.server_address[1]}",
            "DNS_CACHE_TTL": "1s", "DNS_NEGATIVE_TTL": "1s",
        })
        if os.environ.get("APEX_TEST_BINARY"):
            shutil.copyfile(os.environ["APEX_TEST_BINARY"], cls.work / "apex-redirect")
            (cls.work / "apex-redirect").chmod(0o700)
        else:
            run("go", "build", "-o", str(cls.work / "apex-redirect"), ".")
        cls.h2binary = os.environ.get("APEX_H2_BINARY", str(cls.work / "h2probe"))
        if not os.environ.get("APEX_H2_BINARY"):
            run("go", "build", "-o", cls.h2binary, "./tests/integration/h2probe")
        cls.log = (cls.work / "app.log").open("w")
        cls.process = subprocess.Popen([str(cls.work / "apex-redirect")], cwd=ROOT,
                                       env=cls.env, stdout=cls.log, stderr=cls.log)
        cls.wait_url(cls.ask, "/readyz")
        # Extract only public CA trust material from the local test CA image.
        carrier = "apex-pebble-files-" + uuid.uuid4().hex[:12]
        run("docker", "create", "--name", carrier, PEBBLE)
        cls.containers.append(carrier)
        run("docker", "cp", carrier + ":/test/certs/pebble.minica.pem", str(cls.work / "root.pem"))
        config = {"pebble": {
            "listenAddress": f"127.0.0.1:{cls.ca}",
            "managementListenAddress": f"127.0.0.1:{cls.management}",
            "certificate": "/test/certs/localhost/cert.pem",
            "privateKey": "/test/certs/localhost/key.pem",
            "httpPort": cls.http, "tlsPort": cls.https,
            "retryAfter": {"authz": 1, "order": 1},
            "profiles": {"default": {"description": "local lifecycle test", "validityPeriod": 120}},
        }}
        (cls.work / "pebble.json").write_text(json.dumps(config))
        cls.pebble = "apex-pebble-" + uuid.uuid4().hex[:12]
        cls.containers.append(cls.pebble)
        network = os.environ.get("TEST_DOCKER_NETWORK", "host")
        run("docker", "run", "-d", "--name", cls.pebble, "--network", network,
            "-e", "PEBBLE_VA_NOSLEEP=1", "-e", "PEBBLE_WFE_NONCEREJECT=0",
            "-e", "PEBBLE_AUTHZREUSE=0", "-v", f"{cls.work}:/fixture:ro",
            PEBBLE, "-config", "/fixture/pebble.json",
            "-dnsserver", f"127.0.0.1:{cls.va_dns.server_address[1]}")
        cls.wait_url(cls.ca, "/dir", tls=True)
        adapt_env = dict(cls.env, CADDY_HTTP_PORT=str(cls.http), CADDY_HTTPS_PORT=str(cls.https),
                         CADDY_STORAGE="/fixture/caddy", ACME_EMAIL="local@example.com",
                         ACME_CA=f"https://localhost:{cls.ca}/dir")
        env_args = [arg for key in ("HTTP_ADDR", "ASK_ADDR", "CADDY_HTTP_PORT", "CADDY_HTTPS_PORT",
                                   "CADDY_STORAGE", "ACME_EMAIL", "ACME_CA")
                    for arg in ("-e", key + "=" + adapt_env[key])]
        adapted = json.loads(run("docker", "run", "--rm", *env_args,
                                 "--entrypoint", "/usr/bin/caddy",
                                 "-v", f"{ROOT / 'deploy/Caddyfile'}:/Caddyfile:ro",
                                 CADDY, "adapt", "--config", "/Caddyfile"))
        adapted["admin"]["listen"] = f"127.0.0.1:{cls.admin}"
        policy = adapted["apps"]["tls"]["automation"]["policies"][0]
        issuer = policy["issuers"][0]
        issuer["trusted_roots_pem_files"] = ["/fixture/root.pem"]
        issuer["challenges"] = {"tls-alpn": {"disabled": True}}
        # Short-lived local certificates exercise actual renewal, not a mock API.
        policy["renewal_window_ratio"] = 0.8
        (cls.work / "caddy.json").write_text(json.dumps(adapted))
        (cls.work / "caddy").mkdir(mode=0o700)
        cls.caddy = "apex-caddy-" + uuid.uuid4().hex[:12]
        cls.containers.append(cls.caddy)
        run("docker", "run", "-d", "--name", cls.caddy, "--network", network,
            "--user", f"{os.getuid()}:{os.getgid()}", "--cap-drop", "ALL",
            "--cap-add", "NET_BIND_SERVICE",
            "--read-only", "--memory", "512m", "--pids-limit", "256",
            "-e", "XDG_DATA_HOME=/fixture/caddy", "-e", "XDG_CONFIG_HOME=/fixture/caddy/config",
            "--security-opt", "no-new-privileges:true",
            "--entrypoint", "/usr/bin/caddy",
            "-v", f"{cls.work}:/fixture", CADDY, "run", "--config", "/fixture/caddy.json")
        cls.wait_url(cls.admin, "/config/")

    @classmethod
    def wait_url(cls, number, path, tls=False):
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            try:
                conn = (http.client.HTTPSConnection("127.0.0.1", number, timeout=1,
                        context=ssl._create_unverified_context()) if tls else
                        http.client.HTTPConnection("127.0.0.1", number, timeout=1))
                conn.request("GET", path)
                response = conn.getresponse()
                response.read()
                conn.close()
                if response.status == 200:
                    return
            except (OSError, http.client.HTTPException):
                pass
            time.sleep(0.1)
        raise AssertionError(f"listener {number}{path} did not become ready")

    @classmethod
    def cleanup(cls):
        if cls.process:
            cls.process.terminate()
            cls.process.wait(timeout=15)
        if hasattr(cls, "log"):
            cls.log.close()
        for name in reversed(cls.containers):
            logs = subprocess.run(["docker", "logs", name], capture_output=True, text=True)
            if logs.returncode == 0 and os.environ.get("ACME_TEST_LOGS"):
                print(name, logs.stdout, logs.stderr)
            subprocess.run(["docker", "rm", "-f", name], check=True, capture_output=True)
        for dns in (cls.policy_dns, cls.va_dns):
            dns.shutdown()
            dns.server_close()
        # This is isolated test material, never a deployment's durable storage.
        shutil.rmtree(cls.work)

    @classmethod
    def request(cls, domain, path="/", host=None, tls=True, headers=""):
        sock = socket.create_connection(("127.0.0.1", cls.https if tls else cls.http), timeout=35)
        fingerprint = None
        if tls:
            sock = ssl._create_unverified_context().wrap_socket(sock, server_hostname=domain)
            fingerprint = hashlib.sha256(sock.getpeercert(binary_form=True)).hexdigest()
        try:
            sock.sendall((f"GET {path} HTTP/1.1\r\nHost: {host or domain}\r\n"
                          f"Connection: close\r\n{headers}\r\n").encode())
            response = http.client.HTTPResponse(sock)
            response.begin()
            body = response.read()
            return response.status, dict(response.getheaders()), body, fingerprint
        finally:
            sock.close()

    def test_complete_lifecycle(self):
        status, headers, _, _ = self.request("example.com", "/a%2Fb?q=%2f&x=1", tls=False)
        self.assertEqual(status, 301)
        self.assertEqual(headers["Location"], "https://www.example.com/a%2Fb?q=%2f&x=1")
        # No public health exception, no initial certificate for a disallowed name.
        self.assertEqual(self.request("denied.com", "/healthz", tls=False)[0], 403)
        with self.assertRaises((ssl.SSLError, ConnectionError)):
            self.request("denied.com")
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda _: self.request("example.com"), range(8)))
        self.assertTrue(all(result[0] == 301 for result in results))
        self.assertEqual(len({result[3] for result in results}), 1)
        first = results[0][3]
        logs = subprocess.run(["docker", "logs", self.caddy], capture_output=True, text=True)
        logtext = logs.stdout + logs.stderr
        self.assertIn('"challenge":"http-01"', logtext)
        self.assertEqual(logtext.count('"certificate obtained successfully"'), 1)
        self.assertEqual(self.request("example.com", host="example.net")[0], 421)
        run(self.h2binary, f"127.0.0.1:{self.https}")
        self.assertEqual(self.request("example.com", headers="X-Forwarded-Host: evil.com\r\n"
                         "X-Apex-Client-IP: 192.0.2.1\r\n")[0], 301)
        # Restart reloads the same certificate from disk, with ask authorization.
        run("docker", "restart", self.caddy)
        self.wait_url(self.admin, "/config/")
        self.assertEqual(self.request("example.com")[3], first)
        # Handshake-triggered real renewal must produce a distinct certificate.
        deadline = time.monotonic() + 105
        renewed = False
        while time.monotonic() < deadline:
            if self.request("example.com")[3] != first:
                renewed = True
                break
            time.sleep(2)
        self.assertTrue(renewed, "local short-lived certificate did not renew")
        renewal_logs = subprocess.run(["docker", "logs", self.caddy], capture_output=True, text=True)
        self.assertIn('"certificate renewed successfully"', renewal_logs.stdout + renewal_logs.stderr)
        # DNS withdrawal denies requests even when TLS certificate remains cached.
        self.policy_dns.withdrawn.add("example.com")
        time.sleep(1.2)
        self.assertEqual(self.request("example.com")[0], 421)
        run("docker", "restart", self.caddy)
        self.wait_url(self.admin, "/config/")
        with self.assertRaises((ssl.SSLError, ConnectionError)):
            self.request("example.com")
        self.policy_dns.withdrawn.clear()
        time.sleep(1.2)
        self.assertEqual(self.request("example.com")[0], 301)
        cert_files = list((self.work / "caddy").rglob("example.com.crt"))
        self.assertTrue(cert_files)
        saved = {str(path): path.read_bytes() for path in cert_files}
        run(str(self.work / "apex-redirect"), "block", "add", "--kind", "domain",
            "--value", "example.com", "--reason", "local lifecycle test",
            "--operator", "integration", env=self.env)
        # Cached TLS still succeeds, but redirect authorization MUST fail now.
        self.assertEqual(self.request("example.com")[0], 403)
        run("docker", "restart", self.caddy)
        self.wait_url(self.admin, "/config/")
        issuance_before = self.issued_count()
        self.assertGreater(issuance_before, 0)
        with self.assertRaises((ssl.SSLError, ConnectionError)):
            self.request("example.com")
        time.sleep(2)
        self.assertEqual(self.issued_count(), issuance_before,
                         "retired name must not obtain or renew after cold-start denial")
        self.assertEqual(saved, {str(path): path.read_bytes() for path in cert_files})
        # A second permitted domain remains available after full-cache retirement.
        self.assertEqual(self.request("example.net")[0], 301)

    def issued_count(self):
        logs = subprocess.run(["docker", "logs", self.pebble], capture_output=True, text=True)
        return (logs.stdout + logs.stderr).count("Issued certificate")


if __name__ == "__main__":
    unittest.main()
