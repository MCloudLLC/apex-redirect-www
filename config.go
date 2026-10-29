package main

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"mc-apex-redirect/internal/domain"
	"mc-apex-redirect/internal/policy"
	"mc-apex-redirect/internal/state"
)

type config struct {
	httpAddr         string
	askAddr          string
	statePath        string
	publicMode       bool
	allowedDomains   map[string]struct{}
	trustedProxies   []netip.Prefix
	admissionEnabled bool
	dns              policy.Config
	limits           state.Limits
}

func loadConfig() (config, error) {
	cfg := config{
		httpAddr: envOrDefault("HTTP_ADDR", "127.0.0.1:8080"),
		askAddr:  envOrDefault("ASK_ADDR", "127.0.0.1:8081"),
	}
	for _, addr := range []string{cfg.httpAddr, cfg.askAddr} {
		if err := validatePrivateListenAddr(addr); err != nil {
			return cfg, err
		}
	}
	if cfg.httpAddr == cfg.askAddr {
		return cfg, errors.New("HTTP_ADDR and ASK_ADDR must be different")
	}
	var err error
	cfg.statePath, cfg.limits, err = loadStateConfig()
	if err != nil {
		return cfg, err
	}
	switch envOrDefault("MODE", "selfhost") {
	case "public":
		cfg.publicMode = true
	case "selfhost":
	default:
		return cfg, errors.New("MODE must be public or selfhost")
	}
	cfg.allowedDomains = make(map[string]struct{})
	for _, name := range splitValues(os.Getenv("ALLOWED_DOMAINS")) {
		apex, err := domain.Apex(name)
		if err != nil {
			return cfg, fmt.Errorf("invalid ALLOWED_DOMAINS entry: %w", err)
		}
		cfg.allowedDomains[apex] = struct{}{}
	}
	if !cfg.publicMode && len(cfg.allowedDomains) == 0 {
		return cfg, errors.New("selfhost mode requires ALLOWED_DOMAINS; use MODE=public for open DNS-based enrollment")
	}
	for _, text := range splitValues(envOrDefault("TRUSTED_PROXIES", "127.0.0.1/32,::1/128")) {
		prefix, err := netip.ParsePrefix(text)
		if err != nil || prefix.Bits() == 0 || prefix.Addr().Zone() != "" || prefix.Addr().Is4In6() {
			return cfg, errors.New("TRUSTED_PROXIES must contain explicit, nonzero IPv4/IPv6 CIDRs")
		}
		cfg.trustedProxies = append(cfg.trustedProxies, prefix.Masked())
	}
	cfg.admissionEnabled, err = strconv.ParseBool(envOrDefault("ADMISSION_ENABLED", "true"))
	if err != nil {
		return cfg, fmt.Errorf("ADMISSION_ENABLED: %w", err)
	}
	ips, err := configuredServiceIPs(os.Getenv("SERVICE_PUBLIC_IPS"))
	if err != nil {
		return cfg, err
	}
	if len(ips) == 0 {
		return cfg, errors.New("SERVICE_PUBLIC_IPS requires at least one reachable public address")
	}
	cfg.dns = policy.Config{
		ServiceIPs: ips, Resolvers: splitValues(envOrDefault("DNS_RESOLVERS", "1.1.1.1:53,8.8.8.8:53")),
		MaxEntries: 4096, MaxConcurrent: 32,
	}
	for _, item := range []struct {
		key      string
		fallback string
		target   *time.Duration
	}{
		{"DNS_TIMEOUT", "3s", &cfg.dns.Timeout},
		{"DNS_CACHE_TTL", "30s", &cfg.dns.CacheTTL},
		{"DNS_NEGATIVE_TTL", "5s", &cfg.dns.NegativeTTL},
	} {
		duration, err := positiveDuration(item.key, item.fallback)
		if err != nil {
			return cfg, err
		}
		*item.target = duration
	}
	return cfg, nil
}

func loadStateConfig() (string, state.Limits, error) {
	path := envOrDefault("STATE_PATH", "/var/lib/apex-redirect/state.db")
	limits := state.Limits{}
	if !filepath.IsAbs(path) {
		return "", limits, errors.New("STATE_PATH must be an absolute path")
	}
	for _, item := range []struct {
		key      string
		fallback string
		target   *int
	}{
		{"MAX_DOMAINS", "1000", &limits.MaxDomains},
		{"ADMISSIONS_PER_WINDOW", "100", &limits.AdmissionsPerWindow},
	} {
		value, err := strconv.Atoi(envOrDefault(item.key, item.fallback))
		if err != nil || value < 1 {
			return "", limits, fmt.Errorf("%s must be a positive integer", item.key)
		}
		*item.target = value
	}
	window, err := positiveDuration("ADMISSION_WINDOW", "24h")
	if err != nil {
		return "", limits, err
	}
	limits.Window = window
	return path, limits, nil
}

func configuredServiceIPs(value string) ([]netip.Addr, error) {
	var result []netip.Addr
	seen := make(map[netip.Addr]bool)
	for _, part := range splitValues(value) {
		ip, err := netip.ParseAddr(part)
		if err != nil || ip.Zone() != "" || !policy.IsPublicIP(ip.Unmap()) {
			return nil, errors.New("SERVICE_PUBLIC_IPS must contain only public IPv4/IPv6 addresses")
		}
		ip = ip.Unmap()
		if !seen[ip] {
			result = append(result, ip)
			seen[ip] = true
		}
	}
	return result, nil
}

func splitValues(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

func positiveDuration(key, fallback string) (time.Duration, error) {
	value, err := time.ParseDuration(envOrDefault(key, fallback))
	if err != nil || value <= 0 {
		return 0, fmt.Errorf("%s must be a positive duration", key)
	}
	return value, nil
}

func parseAskQuery(raw string) (string, error) {
	values, err := url.ParseQuery(raw)
	if err != nil {
		return "", err
	}
	domains := values["domain"]
	if len(domains) != 1 || domains[0] == "" {
		return "", errors.New("domain must be specified once")
	}
	return domains[0], nil
}
