# Deployment and Operations

This runbook summarizes the operator contract for the apex-to-www redirect
service. It does **not** assert that a public instance is deployed or that the
service is production-ready.

See the [runtime architecture](assets/runtime-architecture.svg) and
[release operations](assets/release-operations.svg) diagrams.

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
