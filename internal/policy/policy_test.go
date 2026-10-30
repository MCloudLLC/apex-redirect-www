package policy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

type responder func(*dns.Msg) *dns.Msg

func dnsServer(t *testing.T, answer responder) string {
	t.Helper()
	var packet net.PacketConn
	var stream net.Listener
	var err error
	for range 20 {
		stream, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		packet, err = net.ListenPacket("udp", stream.Addr().String())
		if err == nil {
			break
		}
		stream.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, query *dns.Msg) {
		if response := answer(query); response != nil {
			_ = w.WriteMsg(response)
		}
	})
	for _, server := range []*dns.Server{
		{PacketConn: packet, Handler: handler}, {Listener: stream, Handler: handler},
	} {
		ready := make(chan struct{})
		server.NotifyStartedFunc = func() { close(ready) }
		go func() { _ = server.ActivateAndServe() }()
		<-ready
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := server.ShutdownContext(ctx); err != nil {
				t.Errorf("DNS shutdown: %v", err)
			}
		})
	}
	return packet.LocalAddr().String()
}

func record(text string) dns.RR {
	rr, err := dns.NewRR(text)
	if err != nil {
		panic(err)
	}
	return rr
}

func reply(query *dns.Msg) *dns.Msg {
	response := new(dns.Msg)
	response.SetReply(query)
	response.Authoritative = true
	name := query.Question[0].Name
	if query.Question[0].Qtype == dns.TypeA {
		ip := "1.1.1.1"
		if strings.HasPrefix(name, "www.") {
			ip = "8.8.8.8"
		}
		response.Answer = []dns.RR{record(name + " 60 IN A " + ip)}
	} else {
		response.Ns = []dns.RR{record(name + " 60 IN SOA ns.example.com. hostmaster.example.com. 1 60 60 60 60")}
	}
	return response
}

func newPolicy(t *testing.T, answer responder, configure ...func(*Config)) *Policy {
	t.Helper()
	config := Config{
		ServiceIPs: []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("2606:4700:4700::1111")},
		Resolvers:  []string{dnsServer(t, answer)}, Timeout: time.Second,
		CacheTTL: time.Minute, NegativeTTL: time.Millisecond * 20,
	}
	for _, change := range configure {
		change(&config)
	}
	policy, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func TestPublicAddressPolicy(t *testing.T) {
	for _, value := range []string{"1.1.1.1", "8.8.8.8", "2606:4700:4700::1111", "::ffff:8.8.8.8"} {
		if !IsPublicIP(netip.MustParseAddr(value)) {
			t.Errorf("public address rejected: %s", value)
		}
	}
	for _, value := range []string{
		"0.0.0.0", "0.1.2.3", "10.0.0.1", "100.64.0.1", "127.0.0.1", "169.254.1.1",
		"172.16.0.1", "192.168.1.1", "192.0.0.9", "192.0.2.1", "192.88.99.1",
		"198.18.0.1", "198.51.100.1", "203.0.113.1", "224.0.0.1", "240.0.0.1",
		"::", "::1", "fc00::1", "fe80::1", "ff02::1", "2001:db8::1", "2001::1",
		"2001:20::1", "2002:0808:0808::1", "3fff::1", "4000::1", "64:ff9b::808:808",
		"100::1", "::ffff:127.0.0.1", "2606:4700::1%eth0",
	} {
		if IsPublicIP(netip.MustParseAddr(value)) {
			t.Errorf("nonpublic address accepted: %s", value)
		}
	}
	if IsPublicIP(netip.Addr{}) {
		t.Fatal("invalid address accepted")
	}
}

func TestAddressEligibilityAndFamilyErrors(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*dns.Msg, *dns.Msg) *dns.Msg
		want   error
	}{
		{"NODATA AAAA", func(_ *dns.Msg, response *dns.Msg) *dns.Msg { return response }, nil},
		{"IPv6 only", func(q, r *dns.Msg) *dns.Msg {
			r.Answer = nil
			r.Ns = []dns.RR{record(q.Question[0].Name + " 60 IN SOA ns.example.com. hostmaster.example.com. 1 60 60 60 60")}
			if q.Question[0].Qtype == dns.TypeAAAA {
				ip := "2606:4700:4700::1111"
				if strings.HasPrefix(q.Question[0].Name, "www.") {
					ip = "2001:4860:4860::8888"
				}
				r.Answer = []dns.RR{record(q.Question[0].Name + " 60 IN AAAA " + ip)}
			}
			return r
		}, nil},
		{"mixed apex", func(q, r *dns.Msg) *dns.Msg {
			if q.Question[0].Name == "example.com." && q.Question[0].Qtype == dns.TypeA {
				r.Answer = append(r.Answer, record("example.com. 60 IN A 8.8.8.8"))
			}
			return r
		}, ErrIneligible},
		{"nonpublic apex", func(q, r *dns.Msg) *dns.Msg {
			if q.Question[0].Name == "example.com." && q.Question[0].Qtype == dns.TypeAAAA {
				r.Answer = []dns.RR{record("example.com. 60 IN AAAA 2001:db8::1")}
			}
			return r
		}, ErrIneligible},
		{"IPv6 apex third party", func(q, r *dns.Msg) *dns.Msg {
			if q.Question[0].Name == "example.com." && q.Question[0].Qtype == dns.TypeAAAA {
				r.Answer = []dns.RR{record("example.com. 60 IN AAAA 2001:4860:4860::8888")}
			}
			return r
		}, ErrIneligible},
		{"mapped AAAA", func(q, r *dns.Msg) *dns.Msg {
			if q.Question[0].Name == "example.com." && q.Question[0].Qtype == dns.TypeAAAA {
				r.Answer = []dns.RR{record("example.com. 60 IN AAAA ::ffff:1.1.1.1")}
			}
			return r
		}, ErrIneligible},
		{"www loop", func(q, r *dns.Msg) *dns.Msg {
			if q.Question[0].Name == "www.example.com." && q.Question[0].Qtype == dns.TypeA {
				r.Answer = append(r.Answer, record("www.example.com. 60 IN A 1.1.1.1"))
			}
			return r
		}, ErrIneligible},
		{"www IPv6 loop", func(q, r *dns.Msg) *dns.Msg {
			if q.Question[0].Name == "www.example.com." && q.Question[0].Qtype == dns.TypeAAAA {
				r.Answer = []dns.RR{record("www.example.com. 60 IN AAAA 2606:4700:4700::1111")}
			}
			return r
		}, ErrIneligible},
		{"www private", func(q, r *dns.Msg) *dns.Msg {
			if q.Question[0].Name == "www.example.com." && q.Question[0].Qtype == dns.TypeA {
				r.Answer = []dns.RR{record("www.example.com. 60 IN A 10.0.0.1")}
			}
			return r
		}, ErrIneligible},
		{"www empty", func(q, r *dns.Msg) *dns.Msg {
			if q.Question[0].Name == "www.example.com." {
				r.Answer = nil
			}
			return r
		}, ErrIneligible},
		{"AAAA SERVFAIL", func(q, r *dns.Msg) *dns.Msg {
			if q.Question[0].Qtype == dns.TypeAAAA {
				r.Rcode = dns.RcodeServerFailure
			}
			return r
		}, ErrUnavailable},
		{"www AAAA SERVFAIL", func(q, r *dns.Msg) *dns.Msg {
			if q.Question[0].Name == "www.example.com." && q.Question[0].Qtype == dns.TypeAAAA {
				r.Rcode = dns.RcodeServerFailure
			}
			return r
		}, ErrUnavailable},
		{"AAAA timeout", func(q, r *dns.Msg) *dns.Msg {
			if q.Question[0].Qtype == dns.TypeAAAA {
				return nil
			}
			return r
		}, ErrUnavailable},
		{"NXDOMAIN", func(_ *dns.Msg, r *dns.Msg) *dns.Msg {
			r.Rcode = dns.RcodeNameError
			return r
		}, ErrIneligible},
	} {
		t.Run(test.name, func(t *testing.T) {
			p := newPolicy(t, func(q *dns.Msg) *dns.Msg { return test.change(q, reply(q)) },
				func(c *Config) { c.Timeout = 100 * time.Millisecond })
			err := p.Check(context.Background(), "EXAMPLE.COM.")
			if test.want == nil && err != nil || test.want != nil && !errors.Is(err, test.want) {
				t.Fatalf("Check = %v; want %v", err, test.want)
			}
		})
	}
}

func TestCNAMERouting(t *testing.T) {
	for _, mode := range []string{"valid inline", "valid separate", "valid underscored www", "loop", "cross-response loop", "too deep", "family mismatch", "coexist", "www loop"} {
		t.Run(mode, func(t *testing.T) {
			p := newPolicy(t, func(q *dns.Msg) *dns.Msg {
				r := reply(q)
				name, family := q.Question[0].Name, q.Question[0].Qtype
				if mode == "valid underscored www" && name == "www.example.com." {
					target := "_aiw_svc.example.net."
					r.Answer = []dns.RR{record(name + " 60 IN CNAME " + target)}
					if family == dns.TypeA {
						r.Answer = append(r.Answer, record(target+" 60 IN A 8.8.8.8"))
					} else {
						r.Answer = append(r.Answer, record(target+" 60 IN AAAA 2001:4860:4860::8888"))
					}
					return r
				}
				if mode == "www loop" {
					if name == "www.example.com." {
						r.Answer = []dns.RR{record(name + " 60 IN CNAME example.com.")}
					}
					return r
				}
				if strings.HasPrefix(name, "www.") {
					return r
				}
				if mode == "cross-response loop" && name == "alias.example.net." {
					r.Answer = []dns.RR{record(name + " 60 IN CNAME example.com.")}
					return r
				}
				if mode == "too deep" {
					r.Answer = []dns.RR{record(name + " 60 IN CNAME x." + name)}
					return r
				}
				if name == "example.com." {
					target := "alias.example.net."
					if mode == "loop" {
						target = name
					}
					if mode == "family mismatch" && family == dns.TypeAAAA {
						return r
					}
					r.Answer = []dns.RR{record(name + " 60 IN CNAME " + target)}
					if mode == "coexist" && family == dns.TypeA {
						r.Answer = append(r.Answer, record(name+" 60 IN A 1.1.1.1"))
					}
					if mode == "valid inline" && family == dns.TypeA {
						r.Answer = append(r.Answer, record(target+" 60 IN A 1.1.1.1"))
					}
				}
				return r
			})
			err := p.Check(context.Background(), "example.com")
			if strings.HasPrefix(mode, "valid") {
				if err != nil {
					t.Fatal(err)
				}
			} else if !errors.Is(err, ErrIneligible) {
				t.Fatalf("Check = %v, want ineligible", err)
			}
		})
	}
}

func TestCacheTTLAndNoStalePositives(t *testing.T) {
	for _, mode := range []string{"answer", "CNAME", "NODATA", "mixed SOA TTLs", "unrelated SOA", "configured cap"} {
		t.Run(mode, func(t *testing.T) {
			var calls atomic.Int32
			var unavailable atomic.Bool
			p := newPolicy(t, func(q *dns.Msg) *dns.Msg {
				calls.Add(1)
				r := reply(q)
				if unavailable.Load() {
					r.Rcode = dns.RcodeServerFailure
					return r
				}
				switch mode {
				case "answer":
					for _, rr := range r.Answer {
						rr.Header().Ttl = 1
					}
				case "CNAME":
					if q.Question[0].Name == "example.com." {
						r.Answer = []dns.RR{record("example.com. 0 IN CNAME alias.example.net.")}
					}
				case "NODATA":
					for _, rr := range r.Ns {
						rr.Header().Ttl = 0
					}
				case "mixed SOA TTLs":
					if len(r.Ns) != 0 {
						r.Ns[0].Header().Ttl = 0
						r.Ns = append(r.Ns, record(q.Question[0].Name+" 60 IN SOA ns.example.com. hostmaster.example.com. 1 60 60 60 60"))
					}
				case "unrelated SOA":
					for _, rr := range r.Ns {
						rr.Header().Name = "unrelated.com."
					}
				}
				return r
			}, func(c *Config) {
				if mode == "configured cap" {
					c.CacheTTL = 25 * time.Millisecond
				}
			})
			if err := p.Check(context.Background(), "example.com"); err != nil {
				t.Fatal(err)
			}
			before := calls.Load()
			if err := p.Check(context.Background(), "example.com"); err != nil {
				t.Fatal(err)
			}
			zero := mode == "CNAME" || mode == "NODATA" || mode == "mixed SOA TTLs" || mode == "unrelated SOA"
			if zero == (calls.Load() == before) {
				t.Fatalf("unexpected cache behavior: before=%d after=%d", before, calls.Load())
			}
			unavailable.Store(true)
			if mode == "answer" {
				time.Sleep(1050 * time.Millisecond)
			} else if mode == "configured cap" {
				time.Sleep(35 * time.Millisecond)
			}
			if err := p.Check(context.Background(), "example.com"); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("stale positive served: %v", err)
			}
		})
	}
}

func TestZeroAddressTTLAndNegativeCache(t *testing.T) {
	var calls atomic.Int32
	var fail atomic.Bool
	p := newPolicy(t, func(q *dns.Msg) *dns.Msg {
		calls.Add(1)
		r := reply(q)
		for _, rr := range r.Answer {
			rr.Header().Ttl = 0
		}
		if fail.Load() {
			r.Rcode = dns.RcodeServerFailure
		}
		return r
	})
	for range 2 {
		if err := p.Check(context.Background(), "example.com"); err != nil {
			t.Fatal(err)
		}
	}
	if calls.Load() != 8 {
		t.Fatalf("zero TTL cached: %d DNS calls", calls.Load())
	}
	fail.Store(true)
	for range 2 {
		if err := p.Check(context.Background(), "example.com"); !errors.Is(err, ErrUnavailable) {
			t.Fatal(err)
		}
	}
	if calls.Load() != 9 {
		t.Fatalf("negative decision not deduplicated: %d", calls.Load())
	}
	time.Sleep(30 * time.Millisecond)
	_ = p.Check(context.Background(), "example.com")
	if calls.Load() != 10 {
		t.Fatal("negative decision did not expire")
	}
}

func TestConcurrentChecksDeduplicate(t *testing.T) {
	gate, started := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	p := newPolicy(t, func(q *dns.Msg) *dns.Msg {
		if calls.Add(1) == 1 {
			close(started)
			<-gate
		}
		return reply(q)
	})
	const callers = 24
	results := make(chan error, callers)
	for range callers {
		go func() { results <- p.Check(context.Background(), "example.com") }()
	}
	<-started
	deadline := time.Now().Add(time.Second)
	for {
		p.mu.Lock()
		waiters := p.cache["example.com"].waiters
		p.mu.Unlock()
		if waiters == callers || time.Now().After(deadline) {
			break
		}
		time.Sleep(time.Millisecond)
	}
	close(gate)
	for range callers {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	if calls.Load() != 4 {
		t.Fatalf("same-name work was not deduplicated: %d calls", calls.Load())
	}
}

func TestCancellationDoesNotPoisonOtherWaitersOrCache(t *testing.T) {
	for _, survivor := range []bool{false, true} {
		t.Run(fmt.Sprint(survivor), func(t *testing.T) {
			gate, started := make(chan struct{}), make(chan struct{})
			var once sync.Once
			p := newPolicy(t, func(q *dns.Msg) *dns.Msg {
				once.Do(func() {
					close(started)
					<-gate
				})
				return reply(q)
			})
			ctx, cancel := context.WithCancel(context.Background())
			result := make(chan error, 1)
			go func() { result <- p.Check(ctx, "example.com") }()
			<-started
			var other chan error
			if survivor {
				other = make(chan error, 1)
				go func() { other <- p.Check(context.Background(), "example.com") }()
				for {
					p.mu.Lock()
					waiters := p.cache["example.com"].waiters
					p.mu.Unlock()
					if waiters == 2 {
						break
					}
					time.Sleep(time.Millisecond)
				}
			}
			cancel()
			if err := <-result; !errors.Is(err, context.Canceled) {
				t.Fatalf("canceled caller: %v", err)
			}
			close(gate)
			if survivor {
				if err := <-other; err != nil {
					t.Fatalf("surviving waiter: %v", err)
				}
			}
			if err := p.Check(context.Background(), "example.com"); err != nil {
				t.Fatalf("cancellation poisoned next check: %v", err)
			}
		})
	}
}

func TestBoundedCacheAndDNSConcurrency(t *testing.T) {
	var active, maximum atomic.Int32
	gate, started := make(chan struct{}), make(chan struct{}, 10)
	p := newPolicy(t, func(q *dns.Msg) *dns.Msg {
		n := active.Add(1)
		for old := maximum.Load(); n > old && !maximum.CompareAndSwap(old, n); old = maximum.Load() {
		}
		select {
		case started <- struct{}{}:
		default:
		}
		<-gate
		active.Add(-1)
		return reply(q)
	}, func(c *Config) { c.MaxConcurrent, c.MaxEntries = 2, 3 })
	results := make(chan error, 3)
	for _, host := range []string{"one.com", "two.com", "three.com"} {
		go func() { results <- p.Check(context.Background(), host) }()
	}
	<-started
	<-started
	deadline := time.Now().Add(time.Second)
	for {
		p.mu.Lock()
		size := len(p.cache)
		p.mu.Unlock()
		if size == 3 || time.Now().After(deadline) {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if err := p.Check(context.Background(), "four.com"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("full active cache did unbounded fallback: %v", err)
	}
	close(gate)
	for range 3 {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	if maximum.Load() > 2 {
		t.Fatalf("DNS concurrency = %d, want <= 2", maximum.Load())
	}
	for _, host := range []string{"four.com", "five.com", "six.com"} {
		if err := p.Check(context.Background(), host); err != nil {
			t.Fatal(err)
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.cache) > 3 {
		t.Fatalf("cache grew to %d", len(p.cache))
	}
}

func TestAllTrustedResolversMustApprove(t *testing.T) {
	first := dnsServer(t, reply)
	second := dnsServer(t, func(q *dns.Msg) *dns.Msg {
		r := reply(q)
		r.Rcode = dns.RcodeServerFailure
		return r
	})
	p, err := New(Config{ServiceIPs: []netip.Addr{netip.MustParseAddr("1.1.1.1")}, Resolvers: []string{first, second}})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Check(context.Background(), "example.com"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("partial resolver failure accepted: %v", err)
	}
}

func TestResolverSpecificDestinationAliases(t *testing.T) {
	for _, mode := range []string{"eligible", "mixed", "loop", "family failure"} {
		t.Run(mode, func(t *testing.T) {
			var resolvers []string
			for index, target := range []string{"west.cdn.example.net.", "east.cdn.example.net."} {
				resolvers = append(resolvers, dnsServer(t, func(q *dns.Msg) *dns.Msg {
					r := reply(q)
					if q.Question[0].Name != "www.example.com." {
						return r
					}
					r.Answer = []dns.RR{record("www.example.com. 60 IN CNAME " + target)}
					if q.Question[0].Qtype == dns.TypeA {
						ip := []string{"8.8.8.8", "9.9.9.9"}[index]
						r.Answer = append(r.Answer, record(target+" 60 IN A "+ip))
						if index == 1 && (mode == "mixed" || mode == "loop") {
							if mode == "loop" {
								r.Answer = r.Answer[:1]
							}
							r.Answer = append(r.Answer, record(target+" 60 IN A 1.1.1.1"))
						}
					} else if index == 1 && mode == "family failure" {
						r.Rcode = dns.RcodeServerFailure
					}
					return r
				}))
			}
			p, err := New(Config{
				ServiceIPs: []netip.Addr{netip.MustParseAddr("1.1.1.1")},
				Resolvers:  resolvers,
			})
			if err != nil {
				t.Fatal(err)
			}
			err = p.Check(context.Background(), "example.com")
			switch mode {
			case "eligible":
				if err != nil {
					t.Fatalf("eligible resolver-specific CDN aliases denied: %v", err)
				}
			case "family failure":
				if !errors.Is(err, ErrUnavailable) {
					t.Fatalf("family error accepted: %v", err)
				}
			default:
				if !errors.Is(err, ErrIneligible) {
					t.Fatalf("invalid destination accepted: %v", err)
				}
			}
		})
	}
}

func TestTruncatedUDPUsesTCP(t *testing.T) {
	var calls atomic.Int32
	p := newPolicy(t, func(q *dns.Msg) *dns.Msg {
		r := reply(q)
		if calls.Add(1)%2 == 1 {
			r.Truncated, r.Answer = true, nil
		}
		return r
	})
	if err := p.Check(context.Background(), "example.com"); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 8 {
		t.Fatalf("TCP retries = %d calls, want 8", calls.Load())
	}
}

func TestInvalidConfigAndNamesFailBeforeDNS(t *testing.T) {
	for _, config := range []Config{
		{}, {ServiceIPs: []netip.Addr{netip.MustParseAddr("10.0.0.1")}, Resolvers: []string{"127.0.0.1:53"}},
		{ServiceIPs: []netip.Addr{netip.MustParseAddr("1.1.1.1")}, Resolvers: []string{"dns.example.com:53"}},
		{ServiceIPs: []netip.Addr{netip.MustParseAddr("1.1.1.1")}, Resolvers: []string{"127.0.0.1:0"}},
		{Timeout: -time.Second}, {MaxConcurrent: -1}, {MaxEntries: -1},
	} {
		if _, err := New(config); err == nil {
			t.Fatalf("invalid config accepted: %+v", config)
		}
	}
	var calls atomic.Int32
	p := newPolicy(t, func(q *dns.Msg) *dns.Msg { calls.Add(1); return reply(q) })
	for _, host := range []string{"www.example.com", "blog.example.com", "example.invalid", "127.0.0.1", "example.com:443"} {
		if err := p.Check(context.Background(), host); !errors.Is(err, ErrIneligible) {
			t.Fatalf("%q: %v", host, err)
		}
	}
	if calls.Load() != 0 {
		t.Fatal("invalid names reached DNS")
	}
}
