package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"mc-apex-redirect/internal/policy"
	"mc-apex-redirect/internal/state"
)

type fakePolicy struct{ err error }

func (p fakePolicy) Check(context.Context, string) error { return p.err }

type failedState struct{ err error }

func (s failedState) CheckBlocked(context.Context, string, netip.Addr) (bool, error) {
	return false, s.err
}
func (s failedState) ReserveAdmission(context.Context, string) error { return s.err }
func (s failedState) Ping(context.Context) error                     { return s.err }

type admissionFailureState struct {
	abuseState
	err error
}

func (s admissionFailureState) ReserveAdmission(context.Context, string) error { return s.err }

func testService(t *testing.T) (*redirectService, *state.Store) {
	t.Helper()
	store, err := state.Open(filepath.Join(t.TempDir(), "private", "state.db"), state.Limits{
		MaxDomains: 10, AdmissionsPerWindow: 10, Window: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return &redirectService{
		policy: fakePolicy{}, store: store, publicMode: true, admissionEnabled: true,
		trustedProxies: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")},
	}, store
}

func TestRedirectPreservesEscapedPathAndQuery(t *testing.T) {
	service, _ := testService(t)
	for _, path := range []string{
		"/a%2Fb%3Fc?next=%2Fother+path&x=a%26b", "//elsewhere.test/a", "/?", "/healthz",
	} {
		for _, method := range []string{http.MethodGet, http.MethodHead} {
			t.Run(method+path, func(t *testing.T) {
				request := httptest.NewRequest(method, "http://example.com"+path, nil)
				response := httptest.NewRecorder()
				service.redirectHandler(response, request)
				if response.Code != http.StatusMovedPermanently {
					t.Fatalf("status = %d", response.Code)
				}
				if got, want := response.Header().Get("Location"), "https://www.example.com"+path; got != want {
					t.Fatalf("Location = %q, want %q", got, want)
				}
			})
		}
	}
}

func TestRedirectRejectsInvalidOrUnrecognizedHosts(t *testing.T) {
	service, _ := testService(t)
	for _, host := range []string{"example.com:443", "www.example.com", "127.0.0.1", "com", "bad..example.com", "example.com@evil.com"} {
		t.Run(host, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "http://example.com/path", nil)
			request.Host = host
			response := httptest.NewRecorder()
			service.redirectHandler(response, request)
			assertDenied(t, response, http.StatusMisdirectedRequest)
		})
	}
}

func TestRedirectNormalizesIDNAAndRejectsMismatchedSNI(t *testing.T) {
	service, _ := testService(t)
	request := httptest.NewRequest(http.MethodGet, "http://example.com/path", nil)
	request.Host = "BÜCHER.DE."
	response := httptest.NewRecorder()
	service.redirectHandler(response, request)
	if response.Code != 301 || response.Header().Get("Location") != "https://www.xn--bcher-kva.de/path" {
		t.Fatalf("IDNA redirect = %d %q", response.Code, response.Header().Get("Location"))
	}
	request.Host = "example.com"
	request.TLS = &tls.ConnectionState{ServerName: "other.com"}
	response = httptest.NewRecorder()
	service.redirectHandler(response, request)
	assertDenied(t, response, http.StatusMisdirectedRequest)
}

func TestDNSFailuresAreNotSuccessOrCachedRedirects(t *testing.T) {
	for _, check := range []struct {
		err    error
		status int
	}{
		{policy.ErrIneligible, http.StatusMisdirectedRequest},
		{policy.ErrUnavailable, http.StatusServiceUnavailable},
		{context.DeadlineExceeded, http.StatusServiceUnavailable},
	} {
		service, _ := testService(t)
		service.policy = fakePolicy{err: check.err}
		response := httptest.NewRecorder()
		service.redirectHandler(response, httptest.NewRequest("GET", "http://example.com/", nil))
		assertDenied(t, response, check.status)
		if response.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("failure lacks no-store")
		}
	}
}

func TestBlocksApplyToRedirectsAndTLSAdmissionImmediately(t *testing.T) {
	for _, check := range []struct{ kind, value string }{
		{"domain", "example.com"}, {"domain", "www.example.com"},
		{"wildcard", "*.example.com"}, {"ip", "192.0.2.1"}, {"cidr", "192.0.2.0/24"},
	} {
		t.Run(check.kind+check.value, func(t *testing.T) {
			service, store := testService(t)
			request := httptest.NewRequest("GET", "http://example.com/", nil)
			request.RemoteAddr = "192.0.2.1:1234"
			service.redirectHandler(httptest.NewRecorder(), request)
			id, err := store.AddBlock(context.Background(), state.Block{
				Kind: check.kind, Value: check.value, Reason: "test", Operator: "test",
			})
			if err != nil {
				t.Fatal(err)
			}
			response := httptest.NewRecorder()
			service.redirectHandler(response, request)
			assertDenied(t, response, http.StatusForbidden)
			if check.kind == "domain" || check.kind == "wildcard" {
				response = httptest.NewRecorder()
				service.askHandler(response, httptest.NewRequest("GET", "/ask?domain=example.com", nil))
				assertDenied(t, response, http.StatusForbidden)
			}
			if err := store.RemoveBlock(context.Background(), id); err != nil {
				t.Fatal(err)
			}
			response = httptest.NewRecorder()
			service.redirectHandler(response, request)
			if response.Code != 301 {
				t.Fatalf("block removal did not restore redirect: %d", response.Code)
			}
		})
	}
}

func TestUntrustedForwardingHeadersCannotEvadeIPBlock(t *testing.T) {
	service, store := testService(t)
	_, err := store.AddBlock(context.Background(), state.Block{
		Kind: "ip", Value: "192.0.2.1", Reason: "test", Operator: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, peer := range []string{"192.0.2.1:1234", "127.0.0.1:1234"} {
		request := httptest.NewRequest("GET", "http://example.com/", nil)
		request.RemoteAddr = peer
		request.Header.Set("X-Forwarded-For", "192.0.2.2")
		request.Header.Set("X-Forwarded-Host", "other.com")
		request.Header.Set(clientIPHeader, "192.0.2.2")
		if strings.HasPrefix(peer, "127.") {
			request.Header.Set(clientIPHeader, "192.0.2.1")
		}
		response := httptest.NewRecorder()
		service.redirectHandler(response, request)
		assertDenied(t, response, http.StatusForbidden)
	}
	for _, values := range [][]string{nil, {"bad"}, {"192.0.2.1", "192.0.2.2"}, {"fe80::1%lo"}} {
		request := httptest.NewRequest("GET", "http://example.com/", nil)
		request.RemoteAddr = "127.0.0.1:1234"
		request.Header[clientIPHeader] = values
		response := httptest.NewRecorder()
		service.redirectHandler(response, request)
		assertDenied(t, response, http.StatusMisdirectedRequest)
	}
}

func TestAskValidationAdmissionAndSelfhostMode(t *testing.T) {
	service, _ := testService(t)
	for _, query := range []string{"", "domain=", "domain=example.com&domain=other.com", "domain=%ZZ", "domain=example.com;bad"} {
		response := httptest.NewRecorder()
		service.askHandler(response, httptest.NewRequest("GET", "/ask?"+query, nil))
		assertDenied(t, response, http.StatusBadRequest)
	}
	response := httptest.NewRecorder()
	service.askHandler(response, httptest.NewRequest("GET", "/ask?domain=example.com", nil))
	if response.Code != 200 {
		t.Fatalf("valid admission denied: %d", response.Code)
	}
	service.admissionEnabled = false
	response = httptest.NewRecorder()
	service.askHandler(response, httptest.NewRequest("GET", "/ask?domain=example.com", nil))
	assertDenied(t, response, 503)
	response = httptest.NewRecorder()
	service.redirectHandler(response, httptest.NewRequest("GET", "http://example.com/", nil))
	if response.Code != 301 {
		t.Fatalf("disabling admissions should not disable redirects: %d", response.Code)
	}
	service.publicMode = false
	response = httptest.NewRecorder()
	service.redirectHandler(response, httptest.NewRequest("GET", "http://example.com/", nil))
	assertDenied(t, response, 403)
	service.allowedDomains = map[string]struct{}{"example.com": {}}
	response = httptest.NewRecorder()
	service.redirectHandler(response, httptest.NewRequest("GET", "http://example.com/", nil))
	if response.Code != 301 {
		t.Fatalf("selfhost allowlist domain denied: %d", response.Code)
	}
}

func TestStateFailuresAndAdmissionBudgetsFailClosed(t *testing.T) {
	service, _ := testService(t)
	service.store = failedState{err: errors.New("state inaccessible")}
	for _, path := range []string{"http://example.com/", "/ask?domain=example.com"} {
		response := httptest.NewRecorder()
		if strings.HasPrefix(path, "/ask") {
			service.askHandler(response, httptest.NewRequest("GET", path, nil))
		} else {
			service.redirectHandler(response, httptest.NewRequest("GET", path, nil))
		}
		assertDenied(t, response, 503)
	}
	for _, check := range []struct {
		err    error
		status int
	}{
		{state.ErrBlocked, 403}, {state.ErrCapacity, 503}, {state.ErrRateLimited, 503},
		{errors.New("state write failed"), 503},
	} {
		service, _ := testService(t)
		service.store = admissionFailureState{abuseState: service.store, err: check.err}
		response := httptest.NewRecorder()
		service.askHandler(response, httptest.NewRequest("GET", "/ask?domain=example.com", nil))
		assertDenied(t, response, check.status)
		if errors.Is(check.err, state.ErrCapacity) || errors.Is(check.err, state.ErrRateLimited) {
			if response.Header().Get("Retry-After") == "" {
				t.Fatal("admission exhaustion missing retry guidance")
			}
		}
	}
}

func TestPrivateHealthReadinessAndMethods(t *testing.T) {
	service, store := testService(t)
	for _, path := range []string{"/healthz", "/readyz", "/metrics"} {
		response := httptest.NewRecorder()
		service.controlHandler().ServeHTTP(response, httptest.NewRequest("GET", path, nil))
		if response.Code != 200 {
			t.Errorf("%s = %d", path, response.Code)
		}
		response = httptest.NewRecorder()
		service.controlHandler().ServeHTTP(response, httptest.NewRequest("POST", path, nil))
		assertDenied(t, response, 405)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	service.controlHandler().ServeHTTP(response, httptest.NewRequest("GET", "/readyz", nil))
	assertDenied(t, response, 503)
	for _, method := range []string{"POST", "OPTIONS"} {
		response = httptest.NewRecorder()
		service.redirectHandler(response, httptest.NewRequest(method, "http://example.com/", nil))
		assertDenied(t, response, 405)
	}
}

func TestConfigFailsClosed(t *testing.T) {
	t.Setenv("SERVICE_PUBLIC_IPS", "1.1.1.1,2606:4700:4700::1111")
	t.Setenv("STATE_PATH", filepath.Join(t.TempDir(), "private", "state.db"))
	t.Setenv("MODE", "selfhost")
	t.Setenv("ALLOWED_DOMAINS", "")
	if _, err := loadConfig(); err == nil {
		t.Fatal("missing allowlist accepted")
	}
	t.Setenv("ALLOWED_DOMAINS", "Example.COM")
	cfg, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cfg.allowedDomains["example.com"]; !ok {
		t.Fatal("allowlist not normalized")
	}
	for _, check := range []struct{ key, value string }{
		{"HTTP_ADDR", "0.0.0.0:8080"}, {"ASK_ADDR", ":8081"},
		{"SERVICE_PUBLIC_IPS", "192.0.2.1"}, {"MODE", "invalid"},
		{"STATE_PATH", "relative.db"}, {"ADMISSION_ENABLED", "sometimes"},
		{"MAX_DOMAINS", "0"}, {"DNS_TIMEOUT", "-1s"}, {"TRUSTED_PROXIES", "0.0.0.0/0"},
	} {
		t.Run(check.key, func(t *testing.T) {
			t.Setenv(check.key, check.value)
			if _, err := loadConfig(); err == nil {
				t.Fatalf("%s=%s accepted", check.key, check.value)
			}
		})
	}
}

func TestOperatorCommandsPersistAndValidate(t *testing.T) {
	t.Setenv("STATE_PATH", filepath.Join(t.TempDir(), "private", "state.db"))
	var out bytes.Buffer
	if err := runOperator([]string{"block", "add", "--kind", "wildcard", "--value", "*.example.com", "--reason", "test", "--operator", "test"}, &out); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := runOperator([]string{"block", "list"}, &out); err != nil || !strings.Contains(out.String(), "*.example.com") {
		t.Fatalf("persisted block missing: %s %v", out.String(), err)
	}
	if err := runOperator([]string{"block", "remove", "--id", "1"}, &out); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"block", "add", "--expires", "-1h"}, {"block", "remove", "--id", "0"},
		{"block", "list", "unexpected"}, {"block", "unknown"}, {"admissions", "forget", "--domain", "www.example.com"},
	} {
		if err := runOperator(args, &out); err == nil {
			t.Errorf("invalid command accepted: %v", args)
		}
	}
}

func TestServeStopsGracefully(t *testing.T) {
	service, _ := testService(t)
	httpAddr, controlAddr := availableAddress(t), availableAddress(t)
	for controlAddr == httpAddr {
		controlAddr = availableAddress(t)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serve(ctx, config{httpAddr: httpAddr, askAddr: controlAddr}, service) }()
	client := &http.Client{Timeout: time.Second}
	deadline := time.Now().Add(5 * time.Second)
	ready := false
	for time.Now().Before(deadline) {
		response, err := client.Get("http://" + controlAddr + "/healthz")
		if err == nil {
			_ = response.Body.Close()
			ready = response.StatusCode == 200
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !ready {
		t.Fatal("server never became responsive")
	}
}

func TestPrivateListenAddress(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:8080", "[::1]:8081"} {
		if err := validatePrivateListenAddr(addr); err != nil {
			t.Fatal(err)
		}
	}
	for _, addr := range []string{":8080", "0.0.0.0:8080", "localhost:8080", "127.0.0.1", "[::1%lo]:8080"} {
		if err := validatePrivateListenAddr(addr); err == nil {
			t.Errorf("unsafe listener accepted: %s", addr)
		}
	}
}

func availableAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}

func assertDenied(t *testing.T, response *httptest.ResponseRecorder, status int) {
	t.Helper()
	if response.Code != status || response.Header().Get("Location") != "" {
		t.Fatalf("response = %d Location=%q body=%q; want %d without redirect",
			response.Code, response.Header().Get("Location"), response.Body.String(), status)
	}
}
