package idp

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
)

// TestEgressPolicyBuiltin: one case per special-purpose range and per IPv6 form (T-21). The policy here has no
// configured prefix: the built-in ranges alone refuse every internal address.
func TestEgressPolicyBuiltin(t *testing.T) {
	pol, err := NewEgressPolicy(nil)
	if err != nil {
		t.Fatal(err)
	}
	refused := map[string]string{
		// IPv4
		"0.0.0.0":         ReasonUnspecified,
		"0.1.2.3":         ReasonUnspecified,
		"10.0.0.1":        ReasonPrivate,
		"10.255.255.254":  ReasonPrivate,
		"100.64.0.1":      ReasonCGNAT,
		"100.127.255.254": ReasonCGNAT,
		"127.0.0.1":       ReasonLoopback,
		"127.255.255.254": ReasonLoopback,
		"169.254.0.1":     ReasonLinkLocal,
		"169.254.169.254": ReasonLinkLocal, // cloud metadata
		"172.16.0.1":      ReasonPrivate,
		"172.31.255.254":  ReasonPrivate,
		"192.0.0.8":       ReasonSpecial,
		"192.0.2.1":       ReasonDocumentation,
		"192.88.99.1":     ReasonSpecial,
		"192.168.0.1":     ReasonPrivate,
		"192.168.255.254": ReasonPrivate,
		"198.18.0.1":      ReasonSpecial,
		"198.51.100.1":    ReasonDocumentation,
		"203.0.113.1":     ReasonDocumentation,
		"224.0.0.1":       ReasonMulticast,
		"239.255.255.250": ReasonMulticast,
		"240.0.0.1":       ReasonReserved,
		"255.255.255.255": ReasonReserved,
		// IPv6 outside 2000::/3
		"::":                 ReasonUnspecified,
		"::1":                ReasonLoopback,
		"fe80::1":            ReasonLinkLocal,
		"fe80::1%eth0":       ReasonLinkLocal,
		"fc00::1":            ReasonULA,
		"fd7a:115c:a1e0::1":  ReasonULA, // tailnet range of Headscale
		"fec0::1":            ReasonSiteLocal,
		"ff02::1":            ReasonMulticast,
		"ff05::1:3":          ReasonMulticast,
		"100::1":             ReasonSpecial,
		"64:ff9b::a9fe:a9fe": ReasonNAT64, // NAT64 of 169.254.169.254
		"64:ff9b::808:808":   ReasonNAT64, // NAT64 of a public address: refused too
		"64:ff9b:1::1":       ReasonNAT64,
		"::127.0.0.1":        ReasonIPv4Compat, // IPv4-compatible forms
		"::a9fe:a9fe":        ReasonIPv4Compat,
		"::10.249.2.2":       ReasonIPv4Compat,
		"4000::1":            ReasonNotGlobal,
		// IPv6 special blocks inside 2000::/3
		"2001::1":           ReasonSpecial, // Teredo
		"2001:db8::1":       ReasonDocumentation,
		"2002:a9fe:a9fe::1": Reason6to4, // 6to4 of 169.254.169.254
		"2002:808:808::1":   Reason6to4,
		"3fff::1":           ReasonDocumentation,
		// IPv4-mapped forms of internal IPv4 addresses
		"::ffff:127.0.0.1":       "ipv4_mapped_" + ReasonLoopback,
		"::ffff:10.249.2.2":      "ipv4_mapped_" + ReasonPrivate,
		"::ffff:169.254.169.254": "ipv4_mapped_" + ReasonLinkLocal,
		"::ffff:100.64.0.1":      "ipv4_mapped_" + ReasonCGNAT,
		"::ffff:172.24.0.1":      "ipv4_mapped_" + ReasonPrivate,
		"::ffff:192.168.1.8":     "ipv4_mapped_" + ReasonPrivate,
		"::ffff:0.0.0.0":         "ipv4_mapped_" + ReasonUnspecified,
		"::ffff:224.0.0.1":       "ipv4_mapped_" + ReasonMulticast,
	}
	for s, want := range refused {
		a := netip.MustParseAddr(s)
		if got := pol.Reason(a); got != want {
			t.Errorf("%s: reason %q, want %q", s, got, want)
		}
		err := pol.Check(a)
		var e *Error
		if !errors.As(err, &e) || e.Code != CodeDestinationRefused || e.Reason != "address_"+want {
			t.Errorf("%s: Check = %v", s, err)
		}
	}
	for _, s := range []string{"8.8.8.8", "1.1.1.1", "9.9.9.9", "93.184.215.14", "::ffff:8.8.8.8",
		"2606:4700:4700::1111", "2001:4860:4860::8888", "2a00:1450:4001::1"} {
		if r := pol.Reason(netip.MustParseAddr(s)); r != "" {
			t.Errorf("%s: refused (%s), want allowed", s, r)
		}
	}
	if pol.Reason(netip.Addr{}) != ReasonInvalid {
		t.Error("the zero address must be refused")
	}
}

// TestEgressPolicyConfigured: configured prefixes refuse addresses the built-in ranges allow, in both IPv4 and
// IPv4-mapped forms; an IPv4-mapped configured prefix is stored as IPv4.
func TestEgressPolicyConfigured(t *testing.T) {
	deny, err := ParsePrefixes("9.9.9.0/24, 2a00:1450::/32,::ffff:1.1.1.0/120, 8.8.4.4")
	if err != nil {
		t.Fatal(err)
	}
	pol, err := NewEgressPolicy(deny)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"9.9.9.9", "::ffff:9.9.9.9", "2a00:1450:4001::1", "1.1.1.1", "::ffff:1.1.1.1", "8.8.4.4"} {
		if r := pol.Reason(netip.MustParseAddr(s)); r != ReasonConfigured && r != "ipv4_mapped_"+ReasonConfigured {
			t.Errorf("%s: reason %q, want configured_deny", s, r)
		}
	}
	for _, s := range []string{"8.8.8.8", "9.9.10.1", "2606:4700:4700::1111"} {
		if r := pol.Reason(netip.MustParseAddr(s)); r != "" {
			t.Errorf("%s: refused (%s)", s, r)
		}
	}
	for _, bad := range []string{"docker", "10.0.0.0/33", "1.2.3"} {
		if _, err := ParsePrefixes(bad); err == nil {
			t.Errorf("ParsePrefixes(%q) accepted", bad)
		}
	}
	if _, err := NewEgressPolicy([]netip.Prefix{{}}); err == nil || !strings.Contains(err.Error(), "invalid") {
		t.Errorf("an invalid prefix must be refused: %v", err)
	}
}
