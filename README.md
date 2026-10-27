# Apex-to-www redirect service

This service permanently redirects requests for a verified apex domain to
`https://www.<domain>`, preserving the escaped path and query string. It only
redirects GET and HEAD requests. It does not host the `www` site.

## Beta deployment

Start with one Linux VM and stable, reserved public IP addresses. This is a
single-instance beta, not a highly available deployment. Add IPv6 only when
the VM, Caddy, cloud firewall, and host firewall all accept IPv6 traffic.

The Go service has two listeners:

- `HTTP_ADDR` (default `127.0.0.1:8080`) handles redirects and `GET /healthz`.
- `ASK_ADDR` (default `127.0.0.1:8081`) is the loopback-only Caddy TLS
  admission endpoint. Do not expose it publicly.

`SERVICE_PUBLIC_IPS` is required to serve redirects or approve certificates.
Set it to a comma-separated list of the service's public IPs, for example
`203.0.113.10,2001:db8::10` (replace these documentation-only addresses with
your actual addresses). A domain is accepted only when its DNS resolves
exclusively to configured service IPs. The current service accepts ASCII
registrable apex names only; it does not support IDNs, subdomains, wildcards,
custom destinations, or automatic account management.

Build and install the binary and systemd unit:

```sh
sudo useradd --system --no-create-home --shell /usr/sbin/nologin apex-redirect
go build -o apex-redirect .
sudo install -o root -g root -m 0755 apex-redirect /usr/local/bin/apex-redirect
sudo install -m 0644 deploy/apex-redirect.service /etc/systemd/system/
```

Create `/etc/default/apex-redirect` readable by the service with the real
addresses and loopback listener configuration:

```sh
HTTP_ADDR=127.0.0.1:8080
ASK_ADDR=127.0.0.1:8081
SERVICE_PUBLIC_IPS=YOUR_PUBLIC_IPV4,YOUR_PUBLIC_IPV6
```

Omit the IPv6 address if IPv6 is not configured. Install Caddy and
[`deploy/Caddyfile`](deploy/Caddyfile) as `/etc/caddy/Caddyfile`; replace the
example ACME contact address. Permit inbound TCP ports **80 and 443** in both
the cloud network rules and VM firewall. Keep the Go listeners private. Then
start the services:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now apex-redirect
sudo systemctl enable --now caddy
sudo systemctl reload caddy
```

The sample Caddyfile uses on-demand TLS and asks the Go service at
`http://127.0.0.1:8081/ask?domain=<apex>`. Only verified apex DNS resolving
exclusively to the configured public service IPs is approved. The check is
performed when issuing a certificate and on redirect requests, with a short
in-memory cache; it is not a persistent customer registry or a DNSSEC ownership
verifier.

## Customer DNS and TLS

For each domain:

1. Point the apex **A** record to the service's stable public IPv4 address.
   Add **AAAA** only if the service has stable, reachable IPv6.
2. Point **www separately** to the customer's web host (commonly a CNAME).
   Do not point `www` at this redirect service unless the customer intends to
   host their site here; this service only handles apex redirects.
3. Ensure any CAA records permit the certificate authority configured in
   Caddy. Caddy validates the apex via ACME before HTTPS redirects can work.

Caddy stores ACME account state, certificates, and keys under `/var/lib/caddy`.
Keep this storage writable by Caddy and persistent across restarts and
redeployments; back it up securely. For development, uncomment the staging
`acme_ca` setting in the Caddyfile. Staging certificates are not trusted by
browsers. Do not test repeatedly against the production CA.

## Operational limits

This is a minimal, single-VM beta: there is no HA/failover, customer database,
metrics, rate limiting, or automatic lifecycle cleanup. Certificate issuance
depends on correct public DNS and reachable ports 80/443. A DNS change away
from the service stops redirects and prevents new certificate approval. Keep
the published IPs stable: customers must update DNS if they change.
