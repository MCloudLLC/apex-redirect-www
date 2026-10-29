# Deployment and Operations

This runbook summarizes the operator contract for the apex-to-www redirect
service. It does **not** assert that a public instance is deployed or that the
service is production-ready.

See the [runtime architecture](assets/runtime-architecture.svg) and
[release operations](assets/release-operations.svg) diagrams.

## Ubuntu VM quick start

This is the recommended path for a first private deployment. It targets a fresh
Ubuntu 24.04 LTS VM and uses Docker Compose. Ubuntu 22.04 or 26.04 can use the
same Docker repository instructions, but test the complete flow before relying
on a different image or distribution.

> **Current release status:** the repository does not currently have an
> accepted deployable two-image release because the stock Caddy image is blocked
> by the vulnerability described under
> [Current release blocker](#current-release-blocker). You can prepare the VM
> now, but do not invent image digests, suppress the scan, or use the deployment
> publicly until a clean signed release is published.

### 1. Create the VM and firewall rules

A practical starting size for the single-host beta is 2 vCPUs, 2 GB RAM, and
20 GB of persistent disk. Reserve a stable public IPv4 address. Add IPv6 only
after verifying that the provider, VM, firewall, DNS, ACME, and monitoring paths
all support it.

At the cloud/provider firewall, allow:

| Direction | Protocol/port | Source or destination | Purpose |
| --- | --- | --- | --- |
| Inbound | TCP 22 | Your administration addresses only | SSH |
| Inbound | TCP 80 | Internet | HTTP and ACME HTTP-01 |
| Inbound | TCP 443 | Internet | HTTPS |
| Outbound | TCP 443 | Internet | Images, signatures, ACME, and updates |
| Outbound | TCP/UDP 53 | Configured DNS resolvers | Domain-policy DNS checks |

Do not expose TCP 8080, 8081, or 2019. They must remain on loopback. Apply
operating-system security updates before installing the service:

```bash
sudo apt update
sudo apt upgrade -y
sudo reboot
```

Reconnect after the VM restarts.

### 2. Install base requirements and Docker

Install the base runtime and operations tools:

```bash
sudo apt update
sudo apt install -y ca-certificates curl git python3 age
```

Install Docker Engine and the Compose plugin from Docker's official Ubuntu
repository:

```bash
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
  -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc

sudo tee /etc/apt/sources.list.d/docker.sources >/dev/null <<EOF
Types: deb
URIs: https://download.docker.com/linux/ubuntu
Suites: $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}")
Components: stable
Architectures: $(dpkg --print-architecture)
Signed-By: /etc/apt/keyrings/docker.asc
EOF

sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io \
  docker-buildx-plugin docker-compose-plugin
sudo systemctl enable --now docker
sudo docker version
sudo docker compose version
```

Use `sudo` or a root login shell for Docker administration. Do not add routine
users to the `docker` group merely for convenience.

### 3. Install the pinned Cosign verifier

The release helper uses Cosign to verify both runtime images. Install the same
v2.6.1 release used by this repository's release workflow, with a checksum
selected for the VM architecture:

```bash
case "$(dpkg --print-architecture)" in
  amd64)
    COSIGN_SHA256=5a31765dec30bcf73bd16a055945575396a723b91ee7f1514540603e452ce31b
    ;;
  arm64)
    COSIGN_SHA256=21d2963a0899f82a4461faa3e3783827a73fe37c712505ea2db01ccfa9a5a77b
    ;;
  *)
    echo "Use an officially supported Cosign package for this architecture." >&2
    exit 1
    ;;
esac

curl -fL -o /tmp/cosign.deb \
  "https://github.com/sigstore/cosign/releases/download/v2.6.1/cosign_2.6.1_$(dpkg --print-architecture).deb"
printf '%s  %s\n' "$COSIGN_SHA256" /tmp/cosign.deb | sha256sum --check -
sudo apt install -y /tmp/cosign.deb
rm /tmp/cosign.deb
cosign version
age --version
```

### 4. Install the deployment files

Clone the repository into a predictable operator-owned location:

```bash
sudo git clone https://github.com/MCloudLLC/apex-redirect-www.git \
  /opt/apex-redirect-www
sudo chown -R root:root /opt/apex-redirect-www
cd /opt/apex-redirect-www
```

For a real deployment, check out the exact published release tag supplied with
the accepted images, not a moving branch:

```bash
sudo git fetch --tags --force
sudo git checkout --detach vX.Y.Z
```

Create the protected state directories required by the container users:

```bash
sudo install -d -m 0700 /srv/apex-redirect
sudo install -d -m 0700 -o 10001 -g 10001 /srv/apex-redirect/app
sudo install -d -m 0700 -o 10002 -g 10002 /srv/apex-redirect/caddy
```

These directories contain the SQLite policy database, ACME account, private
keys, and certificates. Put them on persistent storage, include them in
encrypted backups, and never run `docker compose down -v`.

### 5. Create the deployment configuration

Create one root-owned configuration file from the supplied example:

```bash
sudo install -d -m 0700 /etc/apex-redirect
sudo install -m 0600 deploy/config.env.example \
  /etc/apex-redirect/config.env
sudoedit /etc/apex-redirect/config.env
```

Replace every `REPLACE_...` value. Use:

- the exact app and Caddy digest references from the accepted GitHub release;
- the release's exact signing identity, including its `refs/tags/vX.Y.Z`;
- the VM's actual stable public address in `SERVICE_PUBLIC_IPS`;
- an operator-controlled contact address in `ACME_EMAIL`;
- `MODE=selfhost` and one or more owned domains in `ALLOWED_DOMAINS` for the
  first deployment; and
- the staging ACME URL until end-to-end tests pass.

The configuration file contains no private key, but keep it root-controlled to
prevent unauthorized operational changes. Shell scripts do not load it
automatically.

### 6. Run preflight and deploy to staging

Load the configuration into a root shell, run the fail-closed checks, and start
the accepted images:

```bash
sudo -i
cd /opt/apex-redirect-www
set -a
. /etc/apex-redirect/config.env
set +a

python3 scripts/preflight.py
bash scripts/release.sh
```

`release.sh` verifies immutable digests and signatures, scans both images for
HIGH/CRITICAL vulnerabilities, validates Compose and Caddy, starts the
containers, and checks for restarts. Do not replace it with a direct
`docker compose up` command.

### 7. Verify the VM locally

Still in the configured root shell, run:

```bash
python3 scripts/verify-running.py
curl --fail http://127.0.0.1:8081/healthz
curl --fail http://127.0.0.1:8081/readyz
curl --fail http://127.0.0.1:8081/metrics
curl --fail http://127.0.0.1:2019/config/ >/dev/null
docker compose --env-file /dev/null -f deploy/compose.yaml ps
docker compose --env-file /dev/null -f deploy/compose.yaml logs --tail=100
```

All containers must be running without a restart loop. The local checks do not
prove that public DNS, firewall rules, or certificate issuance work.

### 8. Configure an owned test domain

For a domain listed in `ALLOWED_DOMAINS`, configure:

| Type | Name | Value |
| --- | --- | --- |
| `A` | `@` | The VM's stable public IPv4 address |
| `AAAA` | `@` | The VM's public IPv6 address, only if fully supported |
| `CNAME` | `www` | The existing website's public hostname |

Remove conflicting apex A/AAAA records, preserve unrelated MX/TXT records, and
ensure `www` does not resolve back to this redirect VM. If CAA records exist,
permit Let's Encrypt.

After DNS propagates, test from another network:

```bash
curl --include "http://example.com/test/path?source=vm"
curl --insecure --include "https://example.com/test/path?source=vm"
```

Expect `301` and a `Location` header for the same path and query on
`https://www.example.com`. `--insecure` is expected only during staging because
staging certificates are not browser-trusted.

### 9. Enable production certificates

Only after staging DNS, redirects, monitoring, backups, and recovery have been
reviewed, edit `/etc/apex-redirect/config.env`:

```bash
ACME_CA=https://acme-v02.api.letsencrypt.org/directory
PRODUCTION_ACME_APPROVED=yes
```

Reload the file and run the same release command:

```bash
set -a
. /etc/apex-redirect/config.env
set +a
python3 scripts/preflight.py
bash scripts/release.sh
```

Test HTTPS again without `--insecure` and inspect the certificate presented to
the owned test domain.

### 10. Routine commands

Run these from `/opt/apex-redirect-www` after loading the configuration:

```bash
# Status and recent logs
docker compose --env-file /dev/null -f deploy/compose.yaml ps
docker compose --env-file /dev/null -f deploy/compose.yaml logs --tail=200

# Follow logs
docker compose --env-file /dev/null -f deploy/compose.yaml logs --follow

# Re-run exact runtime checks
python3 scripts/verify-running.py

# Stop without deleting persistent state
docker compose --env-file /dev/null -f deploy/compose.yaml stop

# Start through the verified release path
bash scripts/release.sh
```

Before an upgrade, create an encrypted backup. Then check out the new release
tag, update both image digests and the exact signing identity in
`config.env`, reload it, and run `scripts/release.sh`. Never update only one
image or use mutable tags such as `latest`.

## Deployed components and request flow

A single Linux host runs two services:

- `app`: the Go policy and redirect service, listening only on
  `127.0.0.1:8080`, with private control endpoints on `127.0.0.1:8081`.
- `caddy`: the stock Caddy TLS/ACME edge, exposing TCP 80 and 443 and keeping
  its administration API on `127.0.0.1:2019`.

The request path is:

1. Customer apex DNS resolves to the operator's stable service addresses.
2. Caddy terminates TLS, obtains certificates only after `/ask` authorization,
   and overwrites `X-Apex-Client-IP` from the actual peer address.
3. Go validates the apex, block policy, admission capacity, apex DNS, and the
   generated `www` destination.
4. Valid GET/HEAD requests receive a permanent redirect to the same escaped
   path and query on `https://www.<domain>`. The service never fetches or
   proxies the destination website.

This is a single-host beta design, not an HA deployment. HTTP/1.1 and HTTP/2
are enabled; HTTP/3 is deferred.

## Host, networking, and customer DNS

Use a reserved, stable public IPv4 address. Publish IPv6 only after the host,
provider firewall, local firewall, ACME validation, routing, and external
traffic have all been tested end to end. Allow inbound TCP 80/443; keep ports
8080, 8081, and 2019 loopback-only.

Customers configure:

| Type | Name | Value |
| --- | --- | --- |
| `A` | apex (`@`) | Operator-published stable IPv4 |
| `AAAA` | apex (`@`) | Operator-published stable IPv6, only if supported |
| `CNAME` | `www` | Customer's existing public website target |

The apex must resolve directly and exclusively to the approved
`SERVICE_PUBLIC_IPS`. Replace conflicting apex A/AAAA records but preserve
unrelated MX/TXT records. `www` must not resolve back to this service. The
supported setup does not place a DNS-provider HTTP proxy in front of the apex.
CAA must permit the selected ACME issuer.

## Recommended beta deployment: Linux Compose

Use [deploy/compose.yaml](../deploy/compose.yaml) on Linux with host networking.
The [Ubuntu VM quick start](#ubuntu-vm-quick-start) is the complete installation
and first-deployment procedure. The details below define the operational
invariants that the quick start preserves.

Provision persistent storage before release:

```bash
install -d -m 0700 /srv/apex-redirect
install -d -m 0700 -o 10001 -g 10001 /srv/apex-redirect/app
install -d -m 0700 -o 10002 -g 10002 /srv/apex-redirect/caddy
```

`app` contains SQLite policy/admission state; `caddy` contains ACME account,
certificate, and key material. Keep both across updates. Do not use symlinks,
weaken mode `0700`, change the required owners, or delete these directories.
Never run `docker compose down -v`.

Export reviewed non-secret settings explicitly; scripts do not load dotenv
files. Start from [deploy/config.env.example](../deploy/config.env.example):

- `APEX_DATA_DIR`, `SERVICE_PUBLIC_IPS`, `ACME_EMAIL`
- immutable `APP_IMAGE` and `CADDY_IMAGE` digest references
- exact `RELEASE_CERTIFICATE_IDENTITY`
- `MODE=selfhost` plus `ALLOWED_DOMAINS`, or approved `MODE=public`
- ACME issuer, DNS resolvers, and admission limits

Do not commit runtime configuration, private state, certificate material, age
identities, or other secrets.

### Native systemd alternative

For a native installation, install the verified Go binary at
`/usr/local/bin/apex-redirect`, verified Caddy at `/usr/bin/caddy`, and the
reviewed [Caddyfile](../deploy/Caddyfile). Create dedicated `apex-redirect` and
`caddy` users, then install and review
[apex-redirect.service](../deploy/apex-redirect.service) and
[caddy.service](../deploy/caddy.service).

Place non-secret runtime settings in root-controlled
`/etc/default/apex-redirect`. The units create private
`/var/lib/apex-redirect` and `/var/lib/caddy` state directories. Do not replace
operator-managed units without review. Compose remains the recommended beta
path because the release and recovery automation targets it.

## Release gates and startup

Run from the repository root with the reviewed environment exported:

```bash
python3 scripts/preflight.py
bash scripts/release.sh
```

Preflight fails closed unless the host is Linux, both image references are
nonzero SHA-256 digests, public service IPs are real global addresses, required
directories and ownership are correct, admission is enabled, and mode/issuer
approvals are present.

`release.sh` then requires **both** images to:

1. match immutable digest references;
2. pass keyless Cosign verification against the exact approved GitHub workflow
   identity; and
3. pass the pinned Trivy HIGH/CRITICAL vulnerability gate.

It also renders Compose, pulls images, validates the Caddy configuration,
starts without building, verifies the exact running images, checks app
readiness and Caddy administration, and rejects a restart during those checks.
Do not waive a signature, digest, or scanner failure.

### Current release blocker

Release is currently blocked by **HIGH `CVE-2026-116587`** in stock Caddy's
`github.com/go-jose/go-jose/v3` v3.0.5 dependency. No published v3 fix is
available. The source-build candidate in
[deploy/Caddy.source.Dockerfile](../deploy/Caddy.source.Dockerfile) is an audit
candidate, not an accepted release. Do not suppress the finding, use an
unreviewed crypto fork, or describe the current TLS image as releasable.

## ACME environments

The example configuration uses Let's Encrypt staging. Staging certificates are
untrusted by browsers and are appropriate for deployment rehearsal.

Switching `ACME_CA` to the Let's Encrypt production directory also requires
`PRODUCTION_ACME_APPROVED=yes` after DNS, CAA, contact, rate-limit, and recovery
review. A public-mode release separately requires
`PUBLIC_LAUNCH_GATES_APPROVED=yes`. These flags record completed review; they
must not be used to bypass it.

## Verification and monitoring

After release, verify:

```bash
python3 scripts/verify-running.py
curl --fail http://127.0.0.1:8081/healthz
curl --fail http://127.0.0.1:8081/readyz
curl --fail http://127.0.0.1:8081/metrics
curl --fail http://127.0.0.1:2019/config/ >/dev/null
```

Readiness confirms local policy state only. It does not prove public DNS,
certificate validity, renewal, routing, or end-to-end redirect availability.
Continuously monitor an operator-owned synthetic apex domain through public
IPv4 and, when offered, IPv6. Test HTTP and HTTPS redirects, escaped
path/query preservation, certificate expiry/renewal, and alert delivery.
There is no public customer-host health-path exemption.

## Blocking and certificate retirement

Run `apex-redirect block` and `admissions` commands as the service user against
the same `STATE_PATH`; with Compose, execute `/apex-redirect` in the `app`
container. Exact/wildcard domain blocks and IP/CIDR blocks affect subsequent
requests. Use provider or host firewall controls when a connection must be
stopped before TLS.

A Caddy reload does not remove an already loaded certificate. Retire an exact
domain with:

```bash
bash scripts/retire-domain.sh example.com "reason" operator
```

The script persists the block, verifies `/ask` denial, fully restarts Caddy,
and verifies TLS handshake denial while preserving certificate storage. For
systemd export `RUNTIME=systemd`. Wildcard retirement requires blocking the
pattern, restarting Caddy, and checking each affected enrolled domain. The
restart briefly interrupts the shared edge.

## Encrypted backup, restore, and rollback

Backups are age-encrypted and include app state, Caddy state, deployment files,
and rendered Compose metadata. The online backup requires the accepted release
already running, stops both writers while archiving, then resumes that release.
Set only the offline recipient public key:

```bash
export AGE_RECIPIENT='age1...'
bash scripts/snapshot.sh backup /secure/backups/release.tar.age
```

Keep the archive with its `.sha256` sidecar. Store the age private identity
offline and pass only its protected file path during restore:

```bash
export AGE_IDENTITY_FILE=/secure/keys/backup-identity.txt
bash scripts/snapshot.sh restore /secure/backups/release.tar.age /srv/apex-restored-new
```

Restore is offline, verifies the encrypted checksum and archive members, and
requires a new nonexistent target directory. It never overwrites or starts the
active deployment.

For rollback:

```bash
bash scripts/rollback.sh /secure/backups/accepted-release.tar.age /srv/apex-rollback-new
```

Review the archived configuration, ownership, image digests, signatures, and
scan evidence. Stop current writers, explicitly select the accepted restored
data and configuration, then run `scripts/release.sh`. Rollback never
automatically redeploys or deletes current durable data.

## Public launch gates and current state

Local implementation and validation are complete enough for continued private
deployment work, but the release is blocked by the Caddy HIGH vulnerability
above. No public deployment, production readiness, or authorization to spend
is established.

Before public launch, the operator must obtain explicit approval for:

- provider selection, reserved addresses, firewall/DDoS posture, and budget;
- service-information domain, public DNS instructions, and external monitoring;
- legal review of terms, acceptable use, privacy, retention, and the customer
  notice/acceptance approach;
- abuse, privacy, security, and operational contacts and response procedures;
- a clean, accepted, signed, digest-pinned, scanned two-image release;
- successful encrypted restore rehearsal and rollback evidence; and
- real public IPv4/IPv6 reachability, production issuance, and renewal evidence.

CI and local ACME tests do not provision public infrastructure, authorize
production CA use, change customer DNS, or satisfy these external gates.
