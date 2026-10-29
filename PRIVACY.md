# Hosted Redirect Service Privacy Disclosure

Draft for legal and operational review. Not approved for public launch.

The operator must publish its identity, contact channels, applicable rights and
lawful bases, infrastructure providers and processing locations, and concrete
retention periods before opening the public service. This draft must be adapted
to the actual deployment and applicable law.

## Scope and processing

We operate only the apex-to-www redirect. We do not host or fetch the destination
website. That website and your DNS provider have their own privacy practices.

To provide the service we process the requested hostname, URL path and query,
connection metadata, and client IP address. We use the validated hostname to
build a redirect and preserve the path and query in its Location header. URL
fragments are not sent to our server.

Requests may contain personal or confidential information in URLs. Do not put
sensitive information in a URL unnecessarily. The application does not
deliberately log query strings or request bodies, and its deployment does not
enable customer request access logging by default. Infrastructure and TLS error
logs can still contain domains, addresses, or connection metadata; the operator
must review and configure those logs rather than promise that none exist.

The redirect application does not set cookies, run analytics scripts, or create
visitor accounts. A separately operated information/status website must disclose
its own behavior if that differs.

## Stored operational information

We store domain admission reservations and timestamps to manage capacity and
certificate issuance. We store operator blocks, which may contain domains,
wildcard patterns, client IP addresses or ranges, reasons, timestamps, expiry,
and operator identifiers. Block changes have private audit records. We use
bounded temporary DNS caches and aggregate, non-domain-labelled request
counters.

TLS certificates, private keys, and certificate authority account state are
stored in protected persistent storage. These are not published as repository
content or included in application images. Authorized operators and encrypted
backups may have access as necessary to run and recover the service.

Before launch, publish retention schedules for each class of records, error
logs, audit history, and backups, and configure deletion/expiry accordingly.
The software's default operational state is not a complete legal retention
policy. Do not claim that deleting an active block also deletes its audit trail
or all backups.

## External systems

Domain eligibility checks send DNS questions to the configured resolvers.
Certificate authorities process domain names and ACME validation traffic to
issue and renew certificates. Public certificate names appear in Certificate
Transparency logs and generally cannot be removed by us.

The infrastructure provider necessarily processes network traffic to operate
the service. Publish the actual provider, resolver, certificate authority, and
relevant data-transfer disclosures for the hosted instance. Follow-up requests
to the redirected `www` website go to that website's operator.

## Contact and rights

Publish a working privacy contact for questions and requests, and an abuse
contact for misuse and block review. Describe legally applicable access,
correction, deletion, objection, complaint, and verification procedures after
legal review. Do not request unnecessary personal information in public issue
reports; sensitive block or privacy reports should use the private contact.
