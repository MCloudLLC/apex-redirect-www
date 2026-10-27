package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/publicsuffix"
)

const (
	defaultHTTPAddr = "127.0.0.1:8080"
	// Caddy is expected to run on the same host and call this loopback-only
	// endpoint. It must not be exposed through a separately public listener.
	defaultAskAddr = "127.0.0.1:8081"

	dnsCacheTTL         = 30 * time.Second
	negativeDNSCacheTTL = 5 * time.Second
	maxDNSCacheEntries  = 4096
)

type ipLookup interface {
	LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
}

type dnsCacheEntry struct {
	checkedAt time.Time
	allowed   bool
	inFlight  bool
	done      chan struct{}
}

type redirectService struct {
	serviceIPs map[netip.Addr]struct{}
	resolver   ipLookup
	cacheMu    sync.Mutex
	dnsCache   map[string]*dnsCacheEntry
}

func main() {
	serviceIPs, err := configuredServiceIPs(os.Getenv("SERVICE_PUBLIC_IPS"))
	if err != nil {
		log.Fatalf("invalid SERVICE_PUBLIC_IPS: %v", err)
	}

	httpAddr := envOrDefault("HTTP_ADDR", defaultHTTPAddr)
	askAddr := envOrDefault("ASK_ADDR", defaultAskAddr)
	if err := validatePrivateListenAddr(askAddr); err != nil {
		log.Fatalf("invalid ASK_ADDR: %v", err)
	}

	publicListener, err := net.Listen("tcp", httpAddr)
	if err != nil {
		log.Fatalf("listen on %s: %v", httpAddr, err)
	}
	askListener, err := net.Listen("tcp", askAddr)
	if err != nil {
		_ = publicListener.Close()
		log.Fatalf("listen on private ask endpoint %s: %v", askAddr, err)
	}

	service := &redirectService{
		serviceIPs: serviceIPs,
		resolver:   net.DefaultResolver,
	}
	publicServer := newHTTPServer(http.HandlerFunc(service.redirectHandler))
	askMux := http.NewServeMux()
	askMux.HandleFunc("/ask", service.askHandler)
	askServer := newHTTPServer(askMux)

	errs := make(chan error, 2)
	go func() { errs <- publicServer.Serve(publicListener) }()
	go func() { errs <- askServer.Serve(askListener) }()

	log.Printf("HTTP redirect server listening on %s", publicListener.Addr())
	log.Printf("private Caddy ask endpoint listening on %s", askListener.Addr())
	if len(serviceIPs) == 0 {
		log.Print("SERVICE_PUBLIC_IPS is unset; redirects and TLS approvals are disabled")
	}

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	select {
	case sig := <-signals:
		log.Printf("received %s; shutting down", sig)
	case err := <-errs:
		if !errors.Is(err, http.ErrServerClosed) {
			log.Printf("server stopped: %v", err)
		}
	}
	signal.Stop(signals)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = publicServer.Shutdown(ctx)
	_ = askServer.Shutdown(ctx)
	_ = publicListener.Close()
	_ = askListener.Close()
}

func newHTTPServer(handler http.Handler) *http.Server {
	return &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
}

func (s *redirectService) redirectHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/healthz" {
		if !allowGetHead(w, r) {
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
		return
	}
	if !allowGetHead(w, r) {
		return
	}

	apex, ok := validateApex(r.Host)
	if !ok || !s.isConfiguredPublicApex(r.Context(), apex) {
		http.Error(w, "unrecognized host", http.StatusMisdirectedRequest)
		return
	}

	// apex is a validated DNS name (no port, path, userinfo, or URL delimiters),
	// and RequestURI preserves the original escaped path and raw query.
	target := "https://www." + apex + r.URL.RequestURI()
	w.Header().Set("Location", target)
	w.WriteHeader(http.StatusMovedPermanently)
}

func (s *redirectService) askHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	values := r.URL.Query()["domain"]
	if len(values) != 1 {
		http.Error(w, "domain must be specified once", http.StatusBadRequest)
		return
	}
	apex, ok := validateApex(values[0])
	if !ok || !s.isConfiguredPublicApex(r.Context(), apex) {
		http.Error(w, "domain not approved", http.StatusForbidden)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("approved\n"))
}

func allowGetHead(w http.ResponseWriter, r *http.Request) bool {
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		return true
	}
	w.Header().Set("Allow", "GET, HEAD")
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	return false
}

func (s *redirectService) isConfiguredPublicApex(ctx context.Context, apex string) bool {
	if len(s.serviceIPs) == 0 || s.resolver == nil {
		return false
	}

	for {
		now := time.Now()
		s.cacheMu.Lock()
		entry, exists := s.dnsCache[apex]
		if exists && entry.inFlight {
			done := entry.done
			s.cacheMu.Unlock()
			select {
			case <-done:
				continue
			case <-ctx.Done():
				return false
			}
		}
		if exists && now.Sub(entry.checkedAt) < dnsCacheEntryTTL(entry.allowed) {
			s.cacheMu.Unlock()
			return entry.allowed
		}

		if !exists && len(s.dnsCache) >= maxDNSCacheEntries {
			s.evictOldestDNSCacheEntry(now)
		}
		if s.dnsCache == nil {
			s.dnsCache = make(map[string]*dnsCacheEntry)
		}
		if len(s.dnsCache) >= maxDNSCacheEntries {
			s.cacheMu.Unlock()
			return s.lookupConfiguredPublicApex(ctx, apex)
		}

		entry = &dnsCacheEntry{inFlight: true, done: make(chan struct{})}
		s.dnsCache[apex] = entry
		s.cacheMu.Unlock()

		allowed := s.lookupConfiguredPublicApex(ctx, apex)

		s.cacheMu.Lock()
		entry.allowed = allowed
		entry.checkedAt = time.Now()
		entry.inFlight = false
		close(entry.done)
		s.cacheMu.Unlock()
		return allowed
	}
}

func dnsCacheEntryTTL(allowed bool) time.Duration {
	if allowed {
		return dnsCacheTTL
	}
	return negativeDNSCacheTTL
}

func (s *redirectService) evictOldestDNSCacheEntry(now time.Time) {
	var oldestKey string
	var oldest time.Time
	for key, entry := range s.dnsCache {
		if entry.inFlight {
			continue
		}
		if now.Sub(entry.checkedAt) >= dnsCacheEntryTTL(entry.allowed) {
			delete(s.dnsCache, key)
			continue
		}
		if oldestKey == "" || entry.checkedAt.Before(oldest) {
			oldestKey, oldest = key, entry.checkedAt
		}
	}
	if oldestKey != "" && len(s.dnsCache) >= maxDNSCacheEntries {
		delete(s.dnsCache, oldestKey)
	}
}

func (s *redirectService) lookupConfiguredPublicApex(ctx context.Context, apex string) bool {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	addresses, err := s.resolver.LookupIPAddr(ctx, apex)
	if err != nil || len(addresses) == 0 {
		return false
	}
	for _, address := range addresses {
		ip, ok := netip.AddrFromSlice(address.IP)
		if !ok {
			return false
		}
		ip = ip.Unmap()
		if !isPublicIP(ip) {
			return false
		}
		if _, ok := s.serviceIPs[ip]; !ok {
			return false
		}
	}
	return true
}

func validateApex(host string) (string, bool) {
	if host == "" || strings.ContainsAny(host, ":/%\\@[]") {
		return "", false
	}
	host = strings.ToLower(host)
	if len(host) > 253 || strings.HasSuffix(host, ".") || net.ParseIP(host) != nil {
		return "", false
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return "", false
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", false
		}
		for _, ch := range label {
			if (ch < 'a' || ch > 'z') && (ch < '0' || ch > '9') && ch != '-' {
				return "", false
			}
		}
	}

	registered, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil || registered != host {
		return "", false
	}
	return host, true
}

func configuredServiceIPs(value string) (map[netip.Addr]struct{}, error) {
	result := make(map[netip.Addr]struct{})
	if strings.TrimSpace(value) == "" {
		return result, nil
	}
	for _, part := range strings.Split(value, ",") {
		ip, err := netip.ParseAddr(strings.TrimSpace(part))
		if err != nil {
			return nil, fmt.Errorf("%q is not an IP address", part)
		}
		ip = ip.Unmap()
		if !isPublicIP(ip) {
			return nil, fmt.Errorf("%s is not a public IP address", ip)
		}
		result[ip] = struct{}{}
	}
	return result, nil
}

func isPublicIP(ip netip.Addr) bool {
	if !ip.IsValid() || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return false
	}
	if ip.Is4() {
		return !inPrefixes(ip,
			"0.0.0.0/8",
			"100.64.0.0/10",
			"192.0.0.0/24",
			"192.0.2.0/24",
			"192.88.99.0/24",
			"198.18.0.0/15",
			"198.51.100.0/24",
			"203.0.113.0/24",
			"224.0.0.0/4",
			"240.0.0.0/4",
		)
	}
	return ip.Is6() && ip.IsGlobalUnicast() && !inPrefixes(ip, "2001:db8::/32")
}

func inPrefixes(ip netip.Addr, prefixes ...string) bool {
	for _, text := range prefixes {
		if netip.MustParsePrefix(text).Contains(ip) {
			return true
		}
	}
	return false
}

func validatePrivateListenAddr(address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("ASK_ADDR must be a loopback IP and port: %w", err)
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || !ip.IsLoopback() {
		return fmt.Errorf("ASK_ADDR must bind to a loopback IP")
	}
	return nil
}

func envOrDefault(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}
