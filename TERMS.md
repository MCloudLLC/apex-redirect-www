# Hosted Redirect Service Terms and Acceptable Use

Draft for legal review. Not approved for public launch.

Before publication, the operator must identify its legal entity, service domain,
effective date, abuse and privacy contacts, applicable jurisdiction, and the
appropriate notice and acceptance mechanism. These are launch requirements, not
claims that an agreement is already enforceable.

## What we provide

The hosted service is an open, free, signup-free apex-to-www redirect service,
subject to eligibility, capacity, and these terms. We provide only the redirect
and the apex TLS certificate handling needed to deliver it. We do not acquire
your domain, manage your DNS, host your destination website, or endorse its
content. There is no affiliation requirement with another hosting platform.

You remain responsible for your domain, DNS configuration, destination website,
content, and compliance with applicable law. You must have authority to direct
each domain you configure to the service. Your `www` destination must work
independently and must not loop back to the redirect service.

## Acceptable use

Do not use the hosted service for phishing, malware distribution, spam
infrastructure, fraud, denial-of-service activity, infringement of others'
rights, or unlawful activity. Do not circumvent blocks, spoof client identity,
attempt unauthorized access, or exhaust DNS, certificate authority, network,
storage, or compute resources.

We may apply fair-use limits, including admission, connection, traffic, and
capacity limits. Free and open access does not mean unlimited usage or a right
to continued access.

## Blocking and suspension

We may refuse, limit, suspend, or terminate access to the hosted redirect service
for any domain, wildcard domain pattern, IP address, or IP range to address
suspected abuse, protect the service or others, enforce these terms, manage
capacity, or comply with applicable law. Where permitted by law, we may take
these actions without prior notice.

Blocks may apply to an exact apex, its `www` destination, a wildcard such as
`*.example.com`, an individual IPv4 or IPv6 client address, or an entire network
range. Blocking patterns are an operator control, not a feature for wildcard
certificate enrollment or arbitrary URL forwarding.

Contact the published abuse/review address to report abuse or request review of
a block. A review request does not guarantee reinstatement. We may withhold
details where disclosure would harm security, privacy, an investigation, or
compliance with law.

Blocking stops service-controlled future requests; it cannot recall redirects
already cached by browsers, reverse DNS changes, or disable an independently
operated destination website.

## Availability and changes

The service is provided on an as-available basis. There is no initial SLA,
guarantee of uninterrupted operation, or promise of permanent availability.
Certificate issuance depends on DNS, certificate authorities, and network
reachability outside our control. The first HTTPS connection may fail or be
delayed while a certificate is issued.

We may change, restrict, or discontinue the hosted service. Material changes
and updated terms will be published through the service information site;
planned withdrawal will be announced where practical. Urgent security or abuse
action may happen sooner, subject to applicable law. You remain responsible for
changing your DNS if you stop using the service.

Final warranty, liability, governing-law, dispute, and legally required consumer
provisions must be supplied through legal review. Nothing in this draft purports
to waive rights that cannot lawfully be waived.

## Privacy and certificates

See [PRIVACY.md](PRIVACY.md) for the draft privacy disclosure. We process domain
names, request metadata, and client addresses as needed to provide and protect
the redirect. Public certificate issuance publishes domain names in Certificate
Transparency logs maintained outside our control.

## Separate open-source rights

The source code is licensed under [Apache-2.0](LICENSE). These hosted-service
terms do not restrict rights granted by that license or require independent
self-hosters to use our hosted service or blocklist. Self-hosters operate their
own service and are responsible for its policies, legal notices, and users.
