package audit

import (
	"net/netip"
	"testing"
	"time"

	"github.com/google/uuid"
)

// TestAnonymousAggregation — G2 F2, the in-memory part of RecordAnonymousDenial: rows only at the 1st, 10th, 100th…
// occurrence of a key in its window (⌊log10 n⌋+1 rows for n events), a new window after AnonymousWindow, IPv6 grouped
// by /64, and at most AnonymousKeys keys at once — further sources share the overflow key "*" of their
// (tenant, action, reason) until a window ends and frees room. The database part is TestAnonymousRejectionsAreBounded
// (internal/httpapi/auditapi).
func TestAnonymousAggregation(t *testing.T) {
	written := map[int64]bool{}
	for n := int64(1); n <= 100000; n++ {
		if checkpoint(n) {
			written[n] = true
		}
	}
	if len(written) != 6 || !written[1] || !written[10] || !written[100] || !written[1000] || !written[10000] || !written[100000] {
		t.Fatalf("checkpoints of 1…100 000: %v", written)
	}
	for addr, want := range map[string]string{
		"198.51.100.7": "198.51.100.7/32", "::ffff:198.51.100.7": "198.51.100.7/32", "2001:db8:42:7::1": "2001:db8:42:7::/64",
		"2001:db8:42:7:ffff:ffff:ffff:ffff": "2001:db8:42:7::/64", "fe80::1%eth0": "fe80::/64",
	} {
		if got := ClientPrefix(netip.MustParseAddr(addr)); got != want {
			t.Errorf("ClientPrefix(%s) = %s, want %s", addr, got, want)
		}
	}
	if got := ClientPrefix(netip.Addr{}); got != prefixUnknown {
		t.Errorf("ClientPrefix(invalid) = %s", got)
	}

	now := time.Date(2026, 11, 17, 10, 0, 0, 0, time.UTC)
	a := &anonymous{entries: map[anonKey]*anonEntry{}, window: 10 * time.Minute, limit: 3, now: func() time.Time { return now }}
	k := anonKey{prefix: "198.51.100.7/32", action: "auth.login", reason: "state_malformed"}
	for i := int64(1); i <= 1000; i++ {
		if n, got := a.hit(k); n != i || got != k {
			t.Fatalf("hit %d = %d %+v", i, n, got)
		}
	}
	now = now.Add(10 * time.Minute)
	if n, _ := a.hit(k); n != 1 {
		t.Fatalf("first hit of a new window = %d, want 1", n)
	}
	// limit 3: two more sources fit, the next ones share the overflow key of their (tenant, action, reason)
	tenant := uuid.New()
	for i, p := range []string{"192.0.2.1/32", "192.0.2.2/32"} {
		if n, got := a.hit(anonKey{prefix: p, action: k.action, reason: k.reason}); n != 1 || got.prefix != p {
			t.Fatalf("source %d: %d %+v", i, n, got)
		}
	}
	for i := int64(1); i <= 5; i++ {
		n, got := a.hit(anonKey{prefix: "192.0.2." + string(rune('a'+i)), tenant: tenant, action: k.action, reason: k.reason})
		if n != i || got.prefix != prefixOverflow || got.tenant != tenant {
			t.Fatalf("overflow %d: %d %+v", i, n, got)
		}
	}
	if len(a.entries) != 4 {
		t.Fatalf("%d keys tracked, want 3 sources + 1 overflow key", len(a.entries))
	}
	// once the windows have ended, a new source gets its own key again
	now = now.Add(10 * time.Minute)
	if n, got := a.hit(anonKey{prefix: "192.0.2.9/32", action: k.action, reason: k.reason}); n != 1 || got.prefix != "192.0.2.9/32" {
		t.Fatalf("after the windows: %d %+v", n, got)
	}
	if len(a.entries) != 1 {
		t.Fatalf("%d keys tracked after the sweep, want 1", len(a.entries))
	}
}
