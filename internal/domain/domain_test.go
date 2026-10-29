package domain

import (
	"strings"
	"testing"
)

func TestNormalize(t *testing.T) {
	for input, want := range map[string]string{
		"EXAMPLE.COM.": "example.com", "BÜCHER.de": "xn--bcher-kva.de",
		"xn--bcher-kva.de": "xn--bcher-kva.de", "www.Example.com": "www.example.com",
		"example。com。": "example.com",
	} {
		got, err := Normalize(input)
		if err != nil || got != want {
			t.Errorf("Normalize(%q) = %q, %v; want %q", input, got, err, want)
		}
	}
	for _, input := range []string{
		"", "example.com..", "example.com:443", "https://example.com", "user@example.com",
		"example.com/a", "example.com?x", "example.com#x", "127.0.0.1", "[::1]", "::1",
		"*.example.com", "bad..com", "-bad.com", "bad-.com", "bad_name.com", " localhost",
		"xn--.com", "xn--a.com", "xn--abc-.com", "\u200d.com", "\x00.com",
		strings.Repeat("x", 64) + ".com", strings.Repeat(strings.Repeat("x", 63)+".", 4) + "com",
	} {
		if got, err := Normalize(input); err == nil {
			t.Errorf("Normalize(%q) accepted as %q", input, got)
		}
	}
}

func TestApexUsesPrivateAndICANNSuffixes(t *testing.T) {
	for _, input := range []string{"example.com", "EXAMPLE.CO.UK.", "bücher.de", "tenant.blogspot.com", "tenant.github.io"} {
		if _, err := Apex(input); err != nil {
			t.Errorf("Apex(%q): %v", input, err)
		}
	}
	for _, input := range []string{
		"com", "co.uk", "blogspot.com", "github.io", "www.example.com", "blog.example.com",
		"www.tenant.github.io", "sub.tenant.github.io", "example.local", "example.invalid", "example.unknown-tld",
	} {
		if got, err := Apex(input); err == nil {
			t.Errorf("Apex(%q) accepted as %q", input, got)
		}
	}
}
