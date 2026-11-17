package idp

import (
	"fmt"
	"net/netip"
	"strings"
)

// EgressPolicy decides which IP addresses a tenant-influenced URL may reach (§8.2 "SSRF — URL do tenant cung cấp",
// T-21). An address is refused when it is in one of the built-in special-purpose ranges below — never a legitimate
// IdP endpoint — or in one of the configured prefixes (MG_EGRESS_DENY_CIDRS: every Docker address pool of the
// platform, the LAN, the tunnel, the public entry…). Because api and worker are also members of mg-admin/mg-data
// (§14.3), the network is not the boundary: this check is.
//
// Embedded IPv4 forms are resolved before the decision: an IPv4-mapped address (::ffff:a.b.c.d) is judged as its
// IPv4 address; IPv4-compatible (::a.b.c.d), NAT64 (64:ff9b::/96, 64:ff9b:1::/48) and 6to4 (2002::/16) addresses are
// refused outright (each embeds an IPv4 address that a translator may forward to). IPv6 is otherwise limited to
// global unicast (2000::/3) minus its special-purpose blocks.
type EgressPolicy struct {
	deny []denyEntry
}

type denyEntry struct {
	prefix netip.Prefix
	reason string
}

// Reasons of a refused address (Error.Reason is "address_" + reason, or "address_ipv4_mapped_" + reason).
const (
	ReasonLoopback      = "loopback"
	ReasonPrivate       = "private"
	ReasonLinkLocal     = "link_local"
	ReasonCGNAT         = "cgnat"
	ReasonULA           = "ula"
	ReasonMulticast     = "multicast"
	ReasonUnspecified   = "unspecified"
	ReasonReserved      = "reserved"
	ReasonDocumentation = "documentation"
	ReasonSpecial       = "special_purpose"
	ReasonIPv4Compat    = "ipv4_compatible"
	ReasonNAT64         = "nat64"
	Reason6to4          = "6to4"
	ReasonSiteLocal     = "site_local"
	ReasonNotGlobal     = "not_global_unicast"
	ReasonConfigured    = "configured_deny"
	ReasonInvalid       = "invalid"
)

func mustPrefix(s string) netip.Prefix { return netip.MustParsePrefix(s) }

// builtinDeny4: the IANA IPv4 Special-Purpose Address Registry (RFC 6890 and updates) entries that are not globally
// reachable, plus multicast, the reserved block and the deprecated 6to4 relay anycast.
var builtinDeny4 = []denyEntry{
	{mustPrefix("0.0.0.0/8"), ReasonUnspecified},         // "this network" (RFC 791, RFC 1122)
	{mustPrefix("10.0.0.0/8"), ReasonPrivate},            // RFC 1918 — incl. 10.249.0.0/16 (platform), 10.250.0.0/16 (tenants)
	{mustPrefix("100.64.0.0/10"), ReasonCGNAT},           // RFC 6598 shared address space — also the tailnet range
	{mustPrefix("127.0.0.0/8"), ReasonLoopback},          // RFC 1122
	{mustPrefix("169.254.0.0/16"), ReasonLinkLocal},      // RFC 3927 — cloud metadata 169.254.169.254
	{mustPrefix("172.16.0.0/12"), ReasonPrivate},         // RFC 1918 — incl. the Docker pool 172.24.0.0/13
	{mustPrefix("192.0.0.0/24"), ReasonSpecial},          // IETF protocol assignments (RFC 6890)
	{mustPrefix("192.0.2.0/24"), ReasonDocumentation},    // TEST-NET-1 (RFC 5737)
	{mustPrefix("192.88.99.0/24"), ReasonSpecial},        // 6to4 relay anycast (RFC 7526, deprecated)
	{mustPrefix("192.168.0.0/16"), ReasonPrivate},        // RFC 1918
	{mustPrefix("198.18.0.0/15"), ReasonSpecial},         // benchmarking (RFC 2544)
	{mustPrefix("198.51.100.0/24"), ReasonDocumentation}, // TEST-NET-2
	{mustPrefix("203.0.113.0/24"), ReasonDocumentation},  // TEST-NET-3
	{mustPrefix("224.0.0.0/4"), ReasonMulticast},         // RFC 5771
	{mustPrefix("240.0.0.0/4"), ReasonReserved},          // RFC 1112 — incl. 255.255.255.255 (limited broadcast)
}

var globalUnicast6 = mustPrefix("2000::/3")

// builtinDeny6: special-purpose blocks inside 2000::/3 (IANA IPv6 Special-Purpose Address Registry).
var builtinDeny6 = []denyEntry{
	{mustPrefix("2001::/23"), ReasonSpecial},           // IETF protocol assignments: Teredo 2001::/32, benchmarking, ORCHID
	{mustPrefix("2001:db8::/32"), ReasonDocumentation}, // RFC 3849
	{mustPrefix("2002::/16"), Reason6to4},              // 6to4 (RFC 3056): embeds an IPv4 address
	{mustPrefix("3fff::/20"), ReasonDocumentation},     // RFC 9637
}

// outside6 names the IPv6 ranges outside 2000::/3 (all refused) for the reason of a refusal.
var outside6 = []denyEntry{
	{mustPrefix("::/128"), ReasonUnspecified},
	{mustPrefix("::1/128"), ReasonLoopback},
	{mustPrefix("::/96"), ReasonIPv4Compat},     // IPv4-compatible (RFC 4291 §2.5.5.1, deprecated)
	{mustPrefix("64:ff9b::/96"), ReasonNAT64},   // NAT64 well-known prefix (RFC 6052)
	{mustPrefix("64:ff9b:1::/48"), ReasonNAT64}, // local-use NAT64 (RFC 8215)
	{mustPrefix("100::/64"), ReasonSpecial},     // discard-only (RFC 6666)
	{mustPrefix("fc00::/7"), ReasonULA},         // RFC 4193 — incl. fd7a:115c:a1e0::/48 (tailnet)
	{mustPrefix("fe80::/10"), ReasonLinkLocal},  // RFC 4291
	{mustPrefix("fec0::/10"), ReasonSiteLocal},  // RFC 3879 (deprecated)
	{mustPrefix("ff00::/8"), ReasonMulticast},   // RFC 4291
}

// NewEgressPolicy returns the policy with the built-in ranges plus deny (the configured prefixes). An IPv4-mapped
// IPv6 prefix (::ffff:a.b.c.d/n — after masking only possible with n ≥ 96) is stored as its IPv4 prefix, so it
// matches both forms (addresses are unmapped before matching).
func NewEgressPolicy(deny []netip.Prefix) (*EgressPolicy, error) {
	p := &EgressPolicy{}
	p.deny = append(p.deny, builtinDeny4...)
	p.deny = append(p.deny, builtinDeny6...)
	for _, d := range deny {
		if !d.IsValid() {
			return nil, fmt.Errorf("idp: invalid deny prefix %v", d)
		}
		d = d.Masked()
		if a := d.Addr(); a.Is4In6() {
			d = netip.PrefixFrom(a.Unmap(), d.Bits()-96)
		}
		p.deny = append(p.deny, denyEntry{d, ReasonConfigured})
	}
	return p, nil
}

// Reason returns why a is refused ("" when allowed). It never resolves names.
func (p *EgressPolicy) Reason(a netip.Addr) string {
	if !a.IsValid() {
		return ReasonInvalid
	}
	a = a.WithZone("")
	if a.Is4In6() {
		if r := p.Reason(a.Unmap()); r != "" {
			return "ipv4_mapped_" + r
		}
		return ""
	}
	if a.Is6() {
		if !globalUnicast6.Contains(a) {
			for _, e := range outside6 {
				if e.prefix.Contains(a) {
					return e.reason
				}
			}
			return ReasonNotGlobal
		}
	}
	for _, e := range p.deny {
		if e.prefix.Contains(a) {
			return e.reason
		}
	}
	return ""
}

// Check returns nil when a may be dialled, else an *Error with code CodeDestinationRefused.
func (p *EgressPolicy) Check(a netip.Addr) error {
	if r := p.Reason(a); r != "" {
		return &Error{Code: CodeDestinationRefused, Op: "egress", Reason: "address_" + r}
	}
	return nil
}

// ParsePrefixes reads a comma-separated list of CIDRs and IP addresses (a single address is a host prefix) — the
// format of MG_EGRESS_DENY_CIDRS.
func ParsePrefixes(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, item := range strings.Split(s, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if strings.Contains(item, "/") {
			p, err := netip.ParsePrefix(item)
			if err != nil {
				return nil, fmt.Errorf("%q is not a CIDR", item)
			}
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(item)
		if err != nil {
			return nil, fmt.Errorf("%q is not an IP address", item)
		}
		a = a.WithZone("")
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out, nil
}
