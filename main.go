package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"mc-apex-redirect/internal/domain"
	"mc-apex-redirect/internal/policy"
	"mc-apex-redirect/internal/state"
)

const clientIPHeader = "X-Apex-Client-IP"

type eligibilityPolicy interface {
	Check(context.Context, string) error
}

type abuseState interface {
	CheckBlocked(context.Context, string, netip.Addr) (bool, error)
	ReserveAdmission(context.Context, string) error
	Ping(context.Context) error
}

type serviceMetrics struct {
	redirects atomic.Uint64
	denied    atomic.Uint64
	failures  atomic.Uint64
	admitted  atomic.Uint64
}

type redirectService struct {
	policy           eligibilityPolicy
	store            abuseState
	publicMode       bool
	allowedDomains   map[string]struct{}
	trustedProxies   []netip.Prefix
	admissionEnabled bool
	metrics          serviceMetrics
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		log.Printf("apex-redirect: %v", err)
		os.Exit(1)
	}
}

func run(args []string, out io.Writer) error {
	if len(args) > 0 {
		switch args[0] {
		case "block", "admissions":
			return runOperator(args, out)
		case "help", "-h", "--help":
			_, err := fmt.Fprintln(out, "Usage: apex-redirect [serve | block add/list/remove | admissions list/forget]\nConfigure the service through environment variables; see deploy/config.env.example.")
			return err
		case "serve":
			if len(args) != 1 {
				return errors.New("serve accepts no arguments")
			}
		default:
			return fmt.Errorf("unknown command %q; use help", args[0])
		}
	}
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	store, err := state.Open(cfg.statePath, cfg.limits)
	if err != nil {
		return fmt.Errorf("open policy state: %w", err)
	}
	defer store.Close()
	dnsPolicy, err := policy.New(cfg.dns)
	if err != nil {
		return fmt.Errorf("configure DNS policy: %w", err)
	}
	service := &redirectService{
		policy: dnsPolicy, store: store, publicMode: cfg.publicMode,
		allowedDomains: cfg.allowedDomains, trustedProxies: cfg.trustedProxies,
		admissionEnabled: cfg.admissionEnabled,
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return serve(ctx, cfg, service)
}

func serve(ctx context.Context, cfg config, service *redirectService) error {
	redirectListener, err := net.Listen("tcp", cfg.httpAddr)
	if err != nil {
		return fmt.Errorf("listen for private proxied requests: %w", err)
	}
	defer redirectListener.Close()
	controlListener, err := net.Listen("tcp", cfg.askAddr)
	if err != nil {
		return fmt.Errorf("listen for private control requests: %w", err)
	}
	defer controlListener.Close()
	redirectServer := newHTTPServer(http.HandlerFunc(service.redirectHandler))
	controlServer := newHTTPServer(service.controlHandler())
	errs := make(chan error, 2)
	go func() { errs <- redirectServer.Serve(redirectListener) }()
	go func() { errs <- controlServer.Serve(controlListener) }()
	log.Printf("private redirect listener=%s control listener=%s public_mode=%t", redirectListener.Addr(), controlListener.Addr(), cfg.publicMode)
	var serveErr error
	select {
	case <-ctx.Done():
	case err := <-errs:
		if !errors.Is(err, http.ErrServerClosed) {
			serveErr = fmt.Errorf("HTTP server stopped: %w", err)
		}
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, server := range []*http.Server{redirectServer, controlServer} {
		if err := server.Shutdown(shutdownCtx); err != nil {
			serveErr = errors.Join(serveErr, fmt.Errorf("graceful shutdown: %w", err))
			if closeErr := server.Close(); closeErr != nil {
				serveErr = errors.Join(serveErr, closeErr)
			}
		}
	}
	return serveErr
}

func newHTTPServer(handler http.Handler) *http.Server {
	return &http.Server{
		Handler: handler, ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second,
		IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10,
	}
}

func (s *redirectService) redirectHandler(w http.ResponseWriter, r *http.Request) {
	if !allowGetHead(w, r) {
		return
	}
	apex, err := domain.Apex(r.Host)
	if err != nil {
		s.reject(w, http.StatusMisdirectedRequest, "unrecognized host")
		return
	}
	if r.TLS != nil {
		sni, err := domain.Normalize(r.TLS.ServerName)
		if err != nil || sni != apex {
			s.reject(w, http.StatusMisdirectedRequest, "TLS server name does not match host")
			return
		}
	}
	client, err := s.clientIP(r)
	if err != nil {
		s.reject(w, http.StatusMisdirectedRequest, "invalid client address")
		return
	}
	if !s.authorize(w, r, apex, client, false) {
		return
	}
	// EscapedPath and RawQuery must not be decoded and re-escaped.
	target := "https://www." + apex + r.URL.RequestURI()
	w.Header().Set("Location", target)
	w.WriteHeader(http.StatusMovedPermanently)
	s.metrics.redirects.Add(1)
}

func (s *redirectService) askHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	query, err := parseAskQuery(r.URL.RawQuery)
	if err != nil {
		s.reject(w, http.StatusBadRequest, "specify domain exactly once")
		return
	}
	apex, err := domain.Apex(query)
	if err != nil {
		s.reject(w, http.StatusForbidden, "domain not approved")
		return
	}
	if !s.authorize(w, r, apex, netip.Addr{}, true) {
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, "approved\n")
	s.metrics.admitted.Add(1)
}

func (s *redirectService) authorize(w http.ResponseWriter, r *http.Request, apex string, client netip.Addr, admission bool) bool {
	if s.store == nil || s.policy == nil {
		s.reject(w, http.StatusServiceUnavailable, "policy unavailable")
		return false
	}
	blocked, err := s.store.CheckBlocked(r.Context(), apex, client)
	if err != nil {
		log.Printf("block policy lookup failed: %v", err)
		s.reject(w, http.StatusServiceUnavailable, "policy unavailable")
		return false
	}
	if blocked {
		s.reject(w, http.StatusForbidden, "access blocked")
		return false
	}
	if !s.publicMode {
		if _, ok := s.allowedDomains[apex]; !ok {
			s.reject(w, http.StatusForbidden, "domain not allowed")
			return false
		}
	}
	if err := s.policy.Check(r.Context(), apex); err != nil {
		if errors.Is(err, policy.ErrIneligible) {
			status := http.StatusMisdirectedRequest
			if admission {
				status = http.StatusForbidden
			}
			s.reject(w, status, "domain does not meet DNS policy")
		} else {
			s.reject(w, http.StatusServiceUnavailable, "DNS policy unavailable")
		}
		return false
	}
	if admission {
		if !s.admissionEnabled {
			s.reject(w, http.StatusServiceUnavailable, "certificate admission disabled")
			return false
		}
		if err := s.store.ReserveAdmission(r.Context(), apex); err != nil {
			switch {
			case errors.Is(err, state.ErrBlocked):
				s.reject(w, http.StatusForbidden, "access blocked")
			case errors.Is(err, state.ErrCapacity), errors.Is(err, state.ErrRateLimited):
				w.Header().Set("Retry-After", "300")
				s.reject(w, http.StatusServiceUnavailable, "certificate admission capacity unavailable")
			default:
				log.Printf("certificate admission state failed: %v", err)
				s.reject(w, http.StatusServiceUnavailable, "admission state unavailable")
			}
			return false
		}
	}
	return true
}

func (s *redirectService) clientIP(r *http.Request) (netip.Addr, error) {
	peer, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}, err
	}
	ip := peer.Addr().Unmap()
	for _, prefix := range s.trustedProxies {
		if prefix.Contains(ip) {
			values := r.Header.Values(clientIPHeader)
			if len(values) != 1 {
				return netip.Addr{}, errors.New("trusted proxy must supply one client address")
			}
			forwarded, err := netip.ParseAddr(values[0])
			if err != nil || forwarded.Zone() != "" {
				return netip.Addr{}, errors.New("invalid trusted proxy client address")
			}
			return forwarded.Unmap(), nil
		}
	}
	return ip, nil
}

func (s *redirectService) controlHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/ask", s.askHandler)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if allowGetHead(w, r) {
			w.WriteHeader(http.StatusOK)
			if r.Method != http.MethodHead {
				_, _ = io.WriteString(w, "ok\n")
			}
		}
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		if !allowGetHead(w, r) {
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), time.Second)
		defer cancel()
		if s.store == nil || s.policy == nil {
			http.Error(w, "policy unavailable", http.StatusServiceUnavailable)
		} else if err := s.store.Ping(ctx); err != nil {
			http.Error(w, "state unavailable", http.StatusServiceUnavailable)
		} else {
			w.WriteHeader(http.StatusOK)
			if r.Method != http.MethodHead {
				_, _ = io.WriteString(w, "ready\n")
			}
		}
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		if !allowGetHead(w, r) {
			return
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		if r.Method != http.MethodHead {
			_, _ = fmt.Fprintf(w, "# TYPE apex_redirects_total counter\napex_redirects_total %d\n# TYPE apex_denied_total counter\napex_denied_total %d\n# TYPE apex_failures_total counter\napex_failures_total %d\n# TYPE apex_admissions_total counter\napex_admissions_total %d\n",
				s.metrics.redirects.Load(), s.metrics.denied.Load(), s.metrics.failures.Load(), s.metrics.admitted.Load())
		}
	})
	return mux
}

func (s *redirectService) reject(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Cache-Control", "no-store")
	if status >= 500 {
		s.metrics.failures.Add(1)
	} else {
		s.metrics.denied.Add(1)
	}
	http.Error(w, message, status)
}

func allowGetHead(w http.ResponseWriter, r *http.Request) bool {
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		return true
	}
	w.Header().Set("Allow", "GET, HEAD")
	w.Header().Set("Cache-Control", "no-store")
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	return false
}

func validatePrivateListenAddr(address string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil || port == "" {
		return errors.New("listener must use a loopback IP and port")
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || ip.Zone() != "" || !ip.IsLoopback() {
		return errors.New("listener must bind to a loopback IP")
	}
	return nil
}

func envOrDefault(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}
