package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"time"
)

// Resolver is the DNSChecker of step 4 in wildcard mode (§11.3, §15.4: *.mesh.<domain> → the public entry): it only
// checks that the control hostname resolves to the expected address — it creates nothing. Server ("" = the system
// resolver of the container) is an ip:port the worker can reach when its own resolver cannot see public DNS.
type Resolver struct {
	Server  string
	Timeout time.Duration // per lookup; 0 = 5 s
}

var _ DNSChecker = Resolver{}

// Check implements DNSChecker.
func (r Resolver) Check(ctx context.Context, hostname string, want netip.Addr) (DNSResult, error) {
	if !want.IsValid() {
		return DNSResult{}, errors.New("no expected address")
	}
	timeout := r.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	res := &net.Resolver{}
	if r.Server != "" {
		if _, err := netip.ParseAddrPort(r.Server); err != nil {
			return DNSResult{}, fmt.Errorf("DNS server must be ip:port: %w", err)
		}
		server := r.Server
		res = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: timeout}
			return d.DialContext(ctx, network, server)
		}}
	}
	lctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	addrs, err := res.LookupNetIP(lctx, "ip4", hostname)
	if err != nil {
		return DNSResult{}, err
	}
	out := DNSResult{Addresses: make([]netip.Addr, 0, len(addrs))}
	for _, a := range addrs {
		out.Addresses = append(out.Addresses, a.Unmap())
	}
	out.OK = slices.Contains(out.Addresses, want.Unmap())
	return out, nil
}

// StaticDNS is a DNSChecker answering from a fixed table (dev/CI stacks without public DNS — and the tests).
type StaticDNS map[string][]netip.Addr

// Check implements DNSChecker.
func (s StaticDNS) Check(_ context.Context, hostname string, want netip.Addr) (DNSResult, error) {
	addrs, ok := s[hostname]
	if !ok {
		return DNSResult{}, &net.DNSError{Err: "no such host", Name: hostname, IsNotFound: true}
	}
	return DNSResult{Addresses: addrs, OK: slices.Contains(addrs, want)}, nil
}
