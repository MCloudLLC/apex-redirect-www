// Package domain provides the shared hostname and enrollment boundary.
package domain

import (
	"fmt"
	"net/netip"
	"strings"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

var profile = idna.New(
	idna.MapForLookup(), idna.Transitional(false), idna.StrictDomainName(true),
	idna.ValidateLabels(true), idna.CheckHyphens(true), idna.CheckJoiners(true),
	idna.VerifyDNSLength(true), idna.BidiRule(),
)

// Normalize returns an ASCII DNS hostname, without its optional terminal dot.
// Authorities, URLs, IP literals, and single-label local names are not hostnames.
func Normalize(host string) (string, error) {
	if host == "" || strings.ContainsAny(host, ":/%\\@[]?# \t\r\n") {
		return "", fmt.Errorf("invalid hostname")
	}
	host = strings.NewReplacer("\u3002", ".", "\uff0e", ".", "\uff61", ".").Replace(host)
	host = strings.TrimSuffix(host, ".")
	ascii, err := profile.ToASCII(host)
	if err != nil {
		return "", fmt.Errorf("invalid IDNA hostname: %w", err)
	}
	ascii = strings.ToLower(strings.TrimSuffix(ascii, "."))
	if len(ascii) > 253 {
		return "", fmt.Errorf("hostname exceeds DNS length")
	}
	if _, err := netip.ParseAddr(ascii); err == nil {
		return "", fmt.Errorf("IP literals are not hostnames")
	}
	labels := strings.Split(ascii, ".")
	if len(labels) < 2 {
		return "", fmt.Errorf("hostname requires a DNS suffix")
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("invalid DNS label")
		}
		for _, ch := range label {
			if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-') {
				return "", fmt.Errorf("invalid DNS label character")
			}
		}
		if strings.HasPrefix(label, "xn--") {
			unicode, err := profile.ToUnicode(label)
			if err != nil {
				return "", fmt.Errorf("invalid punycode label: %w", err)
			}
			encoded, err := profile.ToASCII(unicode)
			if err != nil || encoded != label || unicode == label {
				return "", fmt.Errorf("noncanonical punycode label")
			}
		}
	}
	return ascii, nil
}

// Apex accepts exactly registrable PSL names, including private PSL boundaries.
func Apex(host string) (string, error) {
	host, err := Normalize(host)
	if err != nil {
		return "", err
	}
	if strings.HasPrefix(host, "www.") {
		return "", fmt.Errorf("www hostnames are destinations, not enrolled apexes")
	}
	suffix, icann := publicsuffix.PublicSuffix(host)
	// Unknown TLDs receive the PSL implicit "*" rule. Private rules have a
	// multi-label suffix, unlike that fallback, and are deliberately supported.
	if !icann && !strings.Contains(suffix, ".") {
		return "", fmt.Errorf("unknown DNS suffix")
	}
	registered, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil || registered != host {
		return "", fmt.Errorf("hostname is not a registrable apex")
	}
	return host, nil
}
