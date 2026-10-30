// Package policy checks time-bounded DNS evidence without contacting websites.
package policy

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"mc-apex-redirect/internal/domain"

	"github.com/miekg/dns"
)

var (
	ErrIneligible  = errors.New("domain is ineligible")
	ErrUnavailable = errors.New("DNS policy unavailable")
)

type Config struct {
	ServiceIPs    []netip.Addr
	Resolvers     []string
	Timeout       time.Duration
	CacheTTL      time.Duration
	NegativeTTL   time.Duration
	MaxEntries    int
	MaxConcurrent int
}

type entry struct {
	ready   chan struct{}
	pending bool
	cancel  context.CancelFunc
	waiters int
	err     error
	expires time.Time
}

type Policy struct {
	config Config
	ips    map[netip.Addr]struct{}
	slots  chan struct{}
	mu     sync.Mutex
	cache  map[string]*entry
}

func New(config Config) (*Policy, error) {
	if config.Timeout < 0 || config.CacheTTL < 0 || config.NegativeTTL < 0 ||
		config.MaxEntries < 0 || config.MaxConcurrent < 0 {
		return nil, fmt.Errorf("policy limits must not be negative")
	}
	if config.Timeout == 0 {
		config.Timeout = 3 * time.Second
	}
	if config.CacheTTL == 0 {
		config.CacheTTL = time.Minute
	}
	if config.NegativeTTL == 0 {
		config.NegativeTTL = 5 * time.Second
	}
	config.NegativeTTL = min(config.NegativeTTL, 30*time.Second)
	if config.MaxEntries == 0 {
		config.MaxEntries = 4096
	}
	if config.MaxConcurrent == 0 {
		config.MaxConcurrent = 32
	}
	if len(config.ServiceIPs) == 0 || len(config.Resolvers) == 0 {
		return nil, fmt.Errorf("public service IPs and trusted DNS resolvers are required")
	}
	ips := make(map[netip.Addr]struct{}, len(config.ServiceIPs))
	for _, ip := range config.ServiceIPs {
		if !IsPublicIP(ip) {
			return nil, fmt.Errorf("service address is not public")
		}
		ips[ip.Unmap()] = struct{}{}
	}
	for _, resolver := range config.Resolvers {
		address, err := netip.ParseAddrPort(resolver)
		if err != nil || address.Port() == 0 || address.Addr().Zone() != "" ||
			address.Addr().IsUnspecified() || address.Addr().IsMulticast() {
			return nil, fmt.Errorf("trusted resolver must be an explicit IP:port")
		}
	}
	config.ServiceIPs = slices.Clone(config.ServiceIPs)
	config.Resolvers = slices.Clone(config.Resolvers)
	return &Policy{
		config: config, ips: ips, slots: make(chan struct{}, config.MaxConcurrent),
		cache: make(map[string]*entry),
	}, nil
}

// Check deduplicates active checks and never serves a stale positive decision.
// The shared check is canceled once all of its callers have disconnected.
func (p *Policy) Check(ctx context.Context, apex string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	apex, err := domain.Apex(apex)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrIneligible, err)
	}
	p.mu.Lock()
	now := time.Now()
	current := p.cache[apex]
	if current != nil && !current.pending {
		if now.Before(current.expires) {
			p.mu.Unlock()
			return current.err
		}
		delete(p.cache, apex)
		current = nil
	}
	if current == nil {
		if len(p.cache) >= p.config.MaxEntries {
			var oldest string
			var expiration time.Time
			for key, candidate := range p.cache {
				if !candidate.pending && (oldest == "" || candidate.expires.Before(expiration)) {
					oldest, expiration = key, candidate.expires
				}
			}
			if oldest == "" {
				p.mu.Unlock()
				return fmt.Errorf("%w: DNS check capacity reached", ErrUnavailable)
			}
			delete(p.cache, oldest)
		}
		work, cancel := context.WithTimeout(context.Background(), p.config.Timeout)
		current = &entry{ready: make(chan struct{}), pending: true, cancel: cancel}
		p.cache[apex] = current
		go p.run(work, apex, current)
	}
	current.waiters++
	p.mu.Unlock()
	select {
	case <-ctx.Done():
		p.mu.Lock()
		current.waiters--
		if current.pending && current.waiters == 0 {
			current.cancel()
			if p.cache[apex] == current {
				delete(p.cache, apex)
			}
		}
		p.mu.Unlock()
		return ctx.Err()
	case <-current.ready:
		if err := ctx.Err(); err != nil {
			return err
		}
		return current.err
	}
}

func (p *Policy) run(ctx context.Context, apex string, current *entry) {
	started := time.Now()
	ttl, err := p.checkDNS(ctx, apex)
	p.mu.Lock()
	defer p.mu.Unlock()
	current.err, current.pending = err, false
	// Cancellation and an exhausted shared deadline must never install a
	// lasting decision on behalf of a disconnected caller.
	if ctx.Err() != nil || p.cache[apex] != current {
		if p.cache[apex] == current {
			delete(p.cache, apex)
		}
	} else {
		if err != nil {
			ttl = p.config.NegativeTTL
		}
		current.expires = started.Add(ttl)
		if !time.Now().Before(current.expires) {
			delete(p.cache, apex)
		}
	}
	current.cancel()
	close(current.ready)
}

func (p *Policy) checkDNS(ctx context.Context, apex string) (time.Duration, error) {
	ttl := p.config.CacheTTL
	for _, host := range []string{apex, "www." + apex} {
		for _, resolver := range p.config.Resolvers {
			var reference []string
			count := 0
			for _, family := range []uint16{dns.TypeA, dns.TypeAAAA} {
				result, err := p.lookup(ctx, resolver, host, family)
				if err != nil {
					return 0, err
				}
				ttl = min(ttl, result.ttl)
				if reference == nil {
					reference = result.chain
				} else if !slices.Equal(reference, result.chain) {
					return 0, fmt.Errorf("%w: inconsistent DNS alias chains", ErrIneligible)
				}
				for _, ip := range result.addresses {
					if !IsPublicIP(ip) {
						return 0, fmt.Errorf("%w: nonpublic DNS address", ErrIneligible)
					}
					_, service := p.ips[ip.Unmap()]
					if host == apex && !service || host != apex && service {
						return 0, fmt.Errorf("%w: address does not match routing policy", ErrIneligible)
					}
					count++
				}
			}
			if count == 0 {
				return 0, fmt.Errorf("%w: hostname has no addresses", ErrIneligible)
			}
		}
	}
	return ttl, nil
}

type lookupResult struct {
	addresses []netip.Addr
	chain     []string
	ttl       time.Duration
}

const maxCNAMEHops = 8

func (p *Policy) lookup(ctx context.Context, resolver, host string, family uint16) (lookupResult, error) {
	result := lookupResult{chain: []string{host}, ttl: p.config.CacheTTL}
	seen := map[string]bool{host: true}
	for {
		response, err := p.exchange(ctx, resolver, host, family)
		if err != nil {
			return result, err
		}
		if response.Rcode == dns.RcodeNameError {
			return result, fmt.Errorf("%w: DNS name does not exist", ErrIneligible)
		}
		if response.Rcode != dns.RcodeSuccess {
			return result, fmt.Errorf("%w: DNS response %s", ErrUnavailable, dns.RcodeToString[response.Rcode])
		}
		if len(response.Answer) > 128 {
			return result, fmt.Errorf("%w: oversized DNS answer", ErrUnavailable)
		}
		aliases := make(map[string]*dns.CNAME)
		addresses := make(map[string][]dns.RR)
		for _, record := range response.Answer {
			owner, err := normalizeDNSName(record.Header().Name)
			if err != nil || record.Header().Class != dns.ClassINET {
				return result, fmt.Errorf("%w: malformed DNS answer", ErrIneligible)
			}
			switch value := record.(type) {
			case *dns.CNAME:
				if aliases[owner] != nil {
					return result, fmt.Errorf("%w: multiple DNS aliases", ErrIneligible)
				}
				aliases[owner] = value
			case *dns.A, *dns.AAAA:
				if record.Header().Rrtype != family {
					return result, fmt.Errorf("%w: unexpected DNS address family", ErrIneligible)
				}
				addresses[owner] = append(addresses[owner], record)
			}
		}
		followed := false
		for {
			alias := aliases[host]
			records := addresses[host]
			if alias != nil && len(records) != 0 {
				return result, fmt.Errorf("%w: alias and address coexist", ErrIneligible)
			}
			if alias == nil {
				for _, record := range records {
					var ip netip.Addr
					switch record := record.(type) {
					case *dns.A:
						ip, _ = netip.AddrFromSlice(record.A)
					case *dns.AAAA:
						ip, _ = netip.AddrFromSlice(record.AAAA)
						if ip.Is4In6() {
							return result, fmt.Errorf("%w: IPv4-mapped AAAA record", ErrIneligible)
						}
					}
					result.addresses = append(result.addresses, ip.Unmap())
					result.ttl = min(result.ttl, time.Duration(record.Header().Ttl)*time.Second)
				}
				delete(addresses, host)
				break
			}
			next, err := normalizeDNSName(alias.Target)
			if err != nil || seen[next] || len(result.chain) > maxCNAMEHops {
				return result, fmt.Errorf("%w: invalid or excessive DNS alias chain", ErrIneligible)
			}
			result.ttl = min(result.ttl, time.Duration(alias.Hdr.Ttl)*time.Second)
			delete(aliases, host)
			host = next
			seen[host] = true
			result.chain = append(result.chain, host)
			followed = true
		}
		if len(aliases) != 0 || len(addresses) != 0 {
			return result, fmt.Errorf("%w: unrelated DNS answers", ErrIneligible)
		}
		if len(result.addresses) > 0 {
			return result, nil
		}
		if followed {
			continue
		}
		// Absence of one family is evidence too: do not outlive its RFC 2308
		// negative TTL. Without an SOA there is no cacheable absence evidence.
		negativeTTL := time.Duration(0)
		foundSOA := false
		for _, record := range response.Ns {
			if soa, ok := record.(*dns.SOA); ok && soa.Hdr.Class == dns.ClassINET {
				zone := strings.ToLower(strings.TrimSuffix(soa.Hdr.Name, "."))
				if zone != "" && host != zone && !strings.HasSuffix(host, "."+zone) {
					continue
				}
				value := time.Duration(min(soa.Hdr.Ttl, soa.Minttl)) * time.Second
				if !foundSOA || value < negativeTTL {
					negativeTTL = value
				}
				foundSOA = true
			}
		}
		result.ttl = min(result.ttl, negativeTTL)
		return result, nil
	}
}

func normalizeDNSName(name string) (string, error) {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if len(name) == 0 || len(name) > 253 {
		return "", errors.New("invalid DNS name length")
	}
	labels := strings.Split(name, ".")
	if len(labels) < 2 {
		return "", errors.New("DNS name requires a suffix")
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("invalid DNS label")
		}
		for _, char := range label {
			if !(char >= 'a' && char <= 'z' || char >= '0' && char <= '9' ||
				char == '-' || char == '_') {
				return "", errors.New("invalid DNS label character")
			}
		}
	}
	return name, nil
}

func (p *Policy) exchange(ctx context.Context, resolver, host string, family uint16) (*dns.Msg, error) {
	select {
	case p.slots <- struct{}{}:
		defer func() { <-p.slots }()
	case <-ctx.Done():
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, ctx.Err())
	}
	query := new(dns.Msg)
	query.SetQuestion(dns.Fqdn(host), family)
	client := &dns.Client{Net: "udp", Timeout: p.config.Timeout}
	response, _, err := client.ExchangeContext(ctx, query, resolver)
	if err == nil && response.Truncated {
		client.Net = "tcp"
		response, _, err = client.ExchangeContext(ctx, query, resolver)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: DNS exchange failed: %v", ErrUnavailable, err)
	}
	if !response.Response || response.Truncated || response.Opcode != dns.OpcodeQuery ||
		len(response.Question) != 1 || response.Question[0] != query.Question[0] {
		return nil, fmt.Errorf("%w: invalid DNS response", ErrUnavailable)
	}
	return response, nil
}

var nonpublic = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"), netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"), netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("3fff::/20"),
}

// IsPublicIP conservatively permits globally routable unicast addresses only.
// IPv6 is restricted to allocated global unicast space, excluding special-use
// assignments, documentation, and transition mechanisms.
func IsPublicIP(ip netip.Addr) bool {
	if !ip.IsValid() || ip.Zone() != "" {
		return false
	}
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	if ip.Is6() && !netip.MustParsePrefix("2000::/3").Contains(ip) {
		return false
	}
	for _, prefix := range nonpublic {
		if prefix.Contains(ip) {
			return false
		}
	}
	return true
}
