package prober

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// ParsePrefixes parses an allow-list: comma- or space-separated IP addresses (one host) and CIDR prefixes, IPv4 or
// IPv6 (IPv4-mapped IPv6 is read as IPv4). An empty list is an error: an allow-list must name what it allows.
func ParsePrefixes(list string) ([]netip.Prefix, error) {
	fields := strings.FieldsFunc(list, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' })
	if len(fields) == 0 {
		return nil, errors.New("empty allow-list")
	}
	out := make([]netip.Prefix, 0, len(fields))
	for _, f := range fields {
		var p netip.Prefix
		if strings.Contains(f, "/") {
			q, err := netip.ParsePrefix(f)
			if err != nil {
				return nil, fmt.Errorf("allow-list entry %q: %w", f, err)
			}
			p = q
			if a := q.Addr(); a.Is4In6() && q.Bits() >= 96 {
				p = netip.PrefixFrom(a.Unmap(), q.Bits()-96)
			}
		} else {
			a, err := netip.ParseAddr(f)
			if err != nil {
				return nil, fmt.Errorf("allow-list entry %q: %w", f, err)
			}
			if a.Zone() != "" {
				return nil, fmt.Errorf("allow-list entry %q: zones are not allowed", f)
			}
			a = a.Unmap()
			p = netip.PrefixFrom(a, a.BitLen())
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

// allowed reports whether a is inside one of the prefixes.
func allowed(prefixes []netip.Prefix, a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range prefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// parseTarget parses an ip:port target (an IP literal, never a name; port 1–65535).
func parseTarget(field, s string) (netip.AddrPort, error) {
	ap, err := netip.ParseAddrPort(strings.TrimSpace(s))
	if err != nil {
		return netip.AddrPort{}, newError(CodeInvalidRequest, field+" must be an ip:port with an IP literal (no name is resolved)")
	}
	if ap.Port() == 0 {
		return netip.AddrPort{}, newError(CodeInvalidRequest, field+": port must be 1-65535")
	}
	a := ap.Addr()
	if a.Zone() != "" || a.IsUnspecified() || a.IsMulticast() {
		return netip.AddrPort{}, newError(CodeInvalidRequest, field+": not a unicast address")
	}
	return netip.AddrPortFrom(a.Unmap(), ap.Port()), nil
}

// checkTarget refuses a target outside the allow-list, before anything is sent.
func checkTarget(prefixes []netip.Prefix, field string, ap netip.AddrPort) error {
	if !allowed(prefixes, ap.Addr()) {
		return newError(CodeTargetNotAllowed, field+" "+ap.Addr().String()+" is outside the prober's allow-list")
	}
	return nil
}
