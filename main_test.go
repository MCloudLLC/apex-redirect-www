package main

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"
)

type fakeIPLookup map[string][]string

func (f fakeIPLookup) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	var result []net.IPAddr
	for _, value := range f[host] {
		result = append(result, net.IPAddr{IP: net.ParseIP(value)})
	}
	return result, nil
}

type countingIPLookup struct {
	mu    sync.Mutex
	calls int
}

func (f *countingIPLookup) LookupIPAddr(_ context.Context, _ string) ([]net.IPAddr, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return []net.IPAddr{{IP: net.ParseIP("1.1.1.1")}}, nil
}

func testService(answers fakeIPLookup, ips ...string) *redirectService {
	configured := make(map[netip.Addr]struct{}, len(ips))
	for _, value := range ips {
		configured[netip.MustParseAddr(value)] = struct{}{}
	}
	return &redirectService{serviceIPs: configured, resolver: answers}
}

func TestPublicApexDNSCheckUsesShortCache(t *testing.T) {
	resolver := &countingIPLookup{}
	service := testService(nil, "1.1.1.1")
	service.resolver = resolver

	for range 2 {
		if !service.isConfiguredPublicApex(context.Background(), "example.com") {
			t.Fatal("configured public apex was rejected")
		}
	}

	resolver.mu.Lock()
	defer resolver.mu.Unlock()
	if resolver.calls != 1 {
		t.Fatalf("DNS lookup count = %d, want 1", resolver.calls)
	}
}

func TestRedirectPreservesEscapedPathAndQuery(t *testing.T) {
	service := testService(fakeIPLookup{
		"example.com": {"1.1.1.1"},
	}, "1.1.1.1")
	request := httptest.NewRequest(http.MethodGet,
		"http://example.com/a%2Fb%3Fc?next=%2Fother+path&x=a%26b", nil)
	response := httptest.NewRecorder()

	service.redirectHandler(response, request)

	if response.Code != http.StatusMovedPermanently {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusMovedPermanently)
	}
	const want = "https://www.example.com/a%2Fb%3Fc?next=%2Fother+path&x=a%26b"
	if got := response.Header().Get("Location"); got != want {
		t.Fatalf("Location = %q, want %q", got, want)
	}
}

func TestRedirectRejectsInvalidOrUnrecognizedHosts(t *testing.T) {
	service := testService(fakeIPLookup{
		"example.com": {"1.1.1.1"},
		"other.com":   {"8.8.8.8"},
	}, "1.1.1.1")
	for _, host := range []string{
		"example.com:443",
		"www.example.com",
		"127.0.0.1",
		"com",
		"bad..example.com",
		"other.com",
	} {
		t.Run(host, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "http://"+host+"/path", nil)
			response := httptest.NewRecorder()
			service.redirectHandler(response, request)
			if response.Code != http.StatusMisdirectedRequest {
				t.Fatalf("status = %d, want %d", response.Code, http.StatusMisdirectedRequest)
			}
			if response.Header().Get("Location") != "" {
				t.Fatalf("unexpected redirect location %q", response.Header().Get("Location"))
			}
		})
	}
}

func TestRedirectFailsClosedWithoutConfiguredIPs(t *testing.T) {
	service := testService(fakeIPLookup{"example.com": {"1.1.1.1"}})
	request := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	response := httptest.NewRecorder()

	service.redirectHandler(response, request)

	if response.Code != http.StatusMisdirectedRequest {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusMisdirectedRequest)
	}
}

func TestAskApprovesOnlyConfiguredPublicApex(t *testing.T) {
	service := testService(fakeIPLookup{
		"example.com": {"1.1.1.1"},
		"mixed.com":   {"1.1.1.1", "8.8.8.8"},
		"private.com": {"10.0.0.1"},
	}, "1.1.1.1")

	for _, test := range []struct {
		domain string
		status int
	}{
		{"example.com", http.StatusOK},
		{"www.example.com", http.StatusForbidden},
		{"mixed.com", http.StatusForbidden},
		{"private.com", http.StatusForbidden},
		{"", http.StatusForbidden},
	} {
		t.Run(test.domain, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/ask?domain="+test.domain, nil)
			response := httptest.NewRecorder()
			service.askHandler(response, request)
			if response.Code != test.status {
				t.Fatalf("status = %d, want %d", response.Code, test.status)
			}
		})
	}
}

func TestMethodHandlingAndHealthEndpoint(t *testing.T) {
	service := testService(nil, "1.1.1.1")
	for _, method := range []string{http.MethodPost, http.MethodOptions} {
		request := httptest.NewRequest(method, "http://example.com/", nil)
		response := httptest.NewRecorder()
		service.redirectHandler(response, request)
		if response.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s status = %d, want %d", method, response.Code, http.StatusMethodNotAllowed)
		}
	}

	request := httptest.NewRequest(http.MethodGet, "http://example.com/healthz", nil)
	response := httptest.NewRecorder()
	service.redirectHandler(response, request)
	if response.Code != http.StatusOK || response.Body.String() != "ok\n" {
		t.Fatalf("health response = %d %q", response.Code, response.Body.String())
	}
}

func TestConfiguredServiceIPsMustBePublic(t *testing.T) {
	if _, err := configuredServiceIPs("10.0.0.1"); err == nil {
		t.Fatal("private service IP accepted")
	}
	ips, err := configuredServiceIPs("1.1.1.1, 2606:4700:4700::1111")
	if err != nil {
		t.Fatalf("public IPs rejected: %v", err)
	}
	if len(ips) != 2 {
		t.Fatalf("configured IP count = %d, want 2", len(ips))
	}
}

func TestAskAddressMustBeLoopback(t *testing.T) {
	for _, address := range []string{"127.0.0.1:8081", "[::1]:8081"} {
		if err := validatePrivateListenAddr(address); err != nil {
			t.Errorf("%s rejected: %v", address, err)
		}
	}
	for _, address := range []string{":8081", "0.0.0.0:8081", "192.0.2.1:8081"} {
		if err := validatePrivateListenAddr(address); err == nil {
			t.Errorf("%s accepted", address)
		}
	}
}
