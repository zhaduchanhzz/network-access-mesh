package audit

import (
	"context"
	"net/netip"
	"regexp"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Defaults of Config.AnonymousWindow and Config.AnonymousKeys.
const (
	DefaultAnonymousWindow = 10 * time.Minute
	DefaultAnonymousKeys   = 256
)

// Client prefixes of the aggregation key that are not an address.
const (
	prefixUnknown  = "unknown" // no valid client address
	prefixOverflow = "*"       // Config.AnonymousKeys sources already tracked in the window
)

// reasonLabelRE bounds the values of the reason label of meshguard_audit_anonymous_denials_total to stable codes.
var reasonLabelRE = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// ClientPrefix is the unit anonymous denials are aggregated by: the address itself for IPv4 (/32), its /64 for IPv6 —
// what one client controls, as for the per-address rate limit of the HTTP chain — and "unknown" without an address.
func ClientPrefix(a netip.Addr) string {
	if !a.IsValid() {
		return prefixUnknown
	}
	a = a.Unmap().WithZone("")
	bits := 32
	if a.Is6() {
		bits = 64
	}
	p, err := a.Prefix(bits)
	if err != nil {
		return prefixUnknown
	}
	return p.String()
}

// anonKey groups the anonymous denials one row stands for.
type anonKey struct {
	prefix string
	tenant uuid.UUID // uuid.Nil = a platform event
	action string
	reason string
}

type anonEntry struct {
	start time.Time
	count int64
}

// anonymous counts the anonymous denials of each key within its window (from the first occurrence). At most limit
// keys are tracked; a new source beyond that shares the overflow key of its (tenant, action, reason).
type anonymous struct {
	mu      sync.Mutex
	entries map[anonKey]*anonEntry
	window  time.Duration
	limit   int
	now     func() time.Time
}

// hit records one occurrence and returns its rank n within the window of its key, and the key it was counted under.
func (a *anonymous) hit(k anonKey) (int64, anonKey) {
	now := a.now()
	a.mu.Lock()
	defer a.mu.Unlock()
	e := a.entries[k]
	if e == nil && len(a.entries) >= a.limit {
		a.sweep(now)
		if len(a.entries) >= a.limit {
			k.prefix = prefixOverflow
			e = a.entries[k]
		}
	}
	switch {
	case e == nil:
		a.entries[k] = &anonEntry{start: now, count: 1}
		return 1, k
	case now.Sub(e.start) >= a.window:
		e.start, e.count = now, 1
		return 1, k
	}
	e.count++
	return e.count, k
}

// sweep drops the keys whose window has ended.
func (a *anonymous) sweep(now time.Time) {
	for k, e := range a.entries {
		if now.Sub(e.start) >= a.window {
			delete(a.entries, k)
		}
	}
}

// checkpoint reports whether the n-th occurrence of a key in its window is written: the 1st, 10th, 100th, 1 000th…
func checkpoint(n int64) bool {
	for n >= 10 && n%10 == 0 {
		n /= 10
	}
	return n == 1
}

// RecordAnonymousDenial records a denied or failure event of a request refused before any identity exists — no actor
// to attribute: a foreign Origin on a state-changing request, a cross-site or invalid login start, a broken callback
// (G2 F2). Such requests cost an attacker nothing, and one append-only row each — kept ≥ 400 days — would let any
// client grow the shared database without bound; the HTTP audit middleware therefore leaves anonymous 401s to the
// access log, and the identity module's anonymous refusals come here. Every event is counted in
// meshguard_audit_anonymous_denials_total{action, reason}. Within Config.AnonymousWindow from the first occurrence of
// its key — client prefix (ClientPrefix), tenant, action, details["reason"] — the n-th event is written (detached path,
// as RecordDetached) only when n is 1 or a power of ten, with details count = n, client_prefix and window_seconds: at
// most ⌊log10 n⌋+1 rows per key and window — 4 for 1 000 events, 5 for the 30 300 the per-address rate limit admits
// in ten minutes. At most Config.AnonymousKeys keys are tracked at once; new sources beyond share the key with client
// prefix "*". An event with an actor is not anonymous: it is written by RecordDetached, one row per event (§8.8).
func (l *Logger) RecordAnonymousDenial(ctx context.Context, ev Event) error {
	if ev.ActorIdentityID != nil || ev.Outcome == OutcomeSuccess || ev.Outcome == "" {
		return l.RecordDetached(ctx, ev)
	}
	reason, _ := ev.Details["reason"].(string)
	action, label := ev.Action, reason
	if len(action) > maxAction || !actionRE.MatchString(action) {
		action = "invalid"
	}
	if !reasonLabelRE.MatchString(label) {
		label = "other"
	}
	l.m.anonymous.WithLabelValues(action, label).Inc()
	k := anonKey{prefix: ClientPrefix(ev.ActorIP), action: ev.Action, reason: reason}
	if ev.TenantID != nil {
		k.tenant = *ev.TenantID
	}
	n, k := l.anon.hit(k)
	if !checkpoint(n) {
		return nil
	}
	d := make(Details, len(ev.Details)+3)
	for key, v := range ev.Details {
		d[key] = v
	}
	d["client_prefix"], d["count"], d["window_seconds"] = k.prefix, n, int64(l.cfg.AnonymousWindow.Seconds())
	ev.Details = d
	return l.RecordDetached(ctx, ev)
}
