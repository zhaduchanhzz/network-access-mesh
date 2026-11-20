package httpapi

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/gen"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/problem"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/ratelimit"
)

// Class groups the requests that share bucket sizes (§13.1: "hạn mức riêng, chặt hơn cho auth/*, enrollment/*,
// devices/sync"). It is decided from the request path before routing, segment by segment like the ServeMux, so a
// path the router would not match cannot pick a laxer class for a route it does match.
type Class string

const (
	ClassDefault    Class = "default"
	ClassAuth       Class = "auth"       // /api/v1/auth/*
	ClassEnrollment Class = "enrollment" // /api/v1/tenants/{t}/enrollment/* (Phase 4)
	ClassSync       Class = "sync"       // POST …/devices/sync and GET …/devices?fresh=true (a bounded sync, §13.1)
	// ClassDiagnostics: POST …/diagnostics/connectivity (P5-T08) — each call reads the register, routes, relays and
	// evaluates the applied policy; a person runs a few, a script must not run it in a loop.
	ClassDiagnostics Class = "diagnostics"
)

// Classes lists every class.
var Classes = []Class{ClassDefault, ClassAuth, ClassEnrollment, ClassSync, ClassDiagnostics}

// ClassLimits are the two buckets of a class: per client IP (always) and per identity (when the session hook has
// called SetIdentity). A request must pass both.
type ClassLimits struct {
	PerIP       ratelimit.Limit
	PerIdentity ratelimit.Limit
}

// RateLimits configures every class; a class missing from the map gets its DefaultRateLimits entry.
type RateLimits map[Class]ClassLimits

// DefaultRateLimits are starting values, to be tuned with real traffic together with the edge limits (P6-T07).
// An office behind one NAT address shares the per-IP buckets, hence their size.
func DefaultRateLimits() RateLimits {
	return RateLimits{
		ClassDefault: {
			PerIP:       ratelimit.Limit{Every: 20 * time.Millisecond, Burst: 300},  // 50/s
			PerIdentity: ratelimit.Limit{Every: 100 * time.Millisecond, Burst: 100}, // 10/s
		},
		ClassAuth: {
			PerIP:       ratelimit.Limit{Every: 500 * time.Millisecond, Burst: 30}, // 2/s
			PerIdentity: ratelimit.Limit{Every: time.Second, Burst: 20},
		},
		ClassEnrollment: {
			PerIP:       ratelimit.Limit{Every: time.Second, Burst: 10},
			PerIdentity: ratelimit.Limit{Every: 5 * time.Second, Burst: 5},
		},
		ClassSync: {
			PerIP:       ratelimit.Limit{Every: 2 * time.Second, Burst: 10},
			PerIdentity: ratelimit.Limit{Every: 10 * time.Second, Burst: 3},
		},
		ClassDiagnostics: {
			PerIP:       ratelimit.Limit{Every: time.Second, Burst: 30},     // 60/min
			PerIdentity: ratelimit.Limit{Every: 3 * time.Second, Burst: 10}, // 20/min
		},
	}
}

type classLimiters struct{ ip, identity *ratelimit.Limiter }

func newLimiters(cfg RateLimits, maxKeys int) (map[Class]classLimiters, error) {
	def := DefaultRateLimits()
	out := map[Class]classLimiters{}
	for _, c := range Classes {
		l, ok := cfg[c]
		if !ok {
			l = def[c]
		}
		if err := l.PerIP.Validate(); err != nil {
			return nil, fmt.Errorf("rate limit %s per IP: %w", c, err)
		}
		if err := l.PerIdentity.Validate(); err != nil {
			return nil, fmt.Errorf("rate limit %s per identity: %w", c, err)
		}
		out[c] = classLimiters{ratelimit.New(l.PerIP, maxKeys), ratelimit.New(l.PerIdentity, maxKeys)}
	}
	for c := range cfg {
		if _, ok := out[c]; !ok {
			return nil, fmt.Errorf("rate limit: unknown class %q", c)
		}
	}
	return out, nil
}

// classify maps a request to its class from the path below BaseURL.
func classify(r *http.Request) Class {
	seg := segments(r.URL.EscapedPath())
	if len(seg) < 3 || seg[0] != "api" || seg[1] != "v1" {
		return ClassDefault
	}
	seg = seg[2:]
	switch {
	case seg[0] == "auth":
		return ClassAuth
	case seg[0] != "tenants" || len(seg) < 3:
		return ClassDefault
	case seg[2] == "enrollment":
		return ClassEnrollment
	case seg[2] == "devices" && len(seg) == 4 && seg[3] == "sync":
		return ClassSync
	case seg[2] == "devices" && len(seg) == 3 && freshRequested(r):
		return ClassSync
	case seg[2] == "diagnostics" && len(seg) == 4 && seg[3] == "connectivity":
		return ClassDiagnostics
	}
	return ClassDefault
}

func freshRequested(r *http.Request) bool {
	for _, v := range r.URL.Query()["fresh"] {
		if b, err := strconv.ParseBool(v); err == nil && b {
			return true
		}
	}
	return false
}

// segments splits an escaped path on "/" and unescapes each segment, as the ServeMux matches patterns.
func segments(escaped string) []string {
	parts := strings.Split(strings.Trim(escaped, "/"), "/")
	for i, p := range parts {
		if u, err := url.PathUnescape(p); err == nil {
			parts[i] = u
		}
	}
	return parts
}

// clientIP is the address the per-IP buckets use: the peer address, or — when the peer is a trusted proxy (the edge)
// — the right-most X-Forwarded-For entry that is not a trusted proxy. Entries left of it are client-supplied and
// ignored, so a spoofed X-Forwarded-For never picks another client's bucket.
func clientIP(r *http.Request, trusted []netip.Prefix) netip.Addr {
	peer := parseAddr(r.RemoteAddr)
	if !peer.IsValid() || !isTrusted(peer, trusted) {
		return peer
	}
	hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		a := parseAddr(strings.TrimSpace(hops[i]))
		if !a.IsValid() {
			return peer // a hop the trusted proxy appended is malformed: count the request against the proxy
		}
		if !isTrusted(a, trusted) {
			return a
		}
	}
	return peer
}

// parseAddr accepts "ip", "ip:port" and "[ipv6]:port"; IPv4-mapped IPv6 addresses become IPv4, zones are dropped.
func parseAddr(s string) netip.Addr {
	if s == "" {
		return netip.Addr{}
	}
	if host, _, err := net.SplitHostPort(s); err == nil {
		s = host
	}
	a, err := netip.ParseAddr(strings.Trim(s, "[]"))
	if err != nil {
		return netip.Addr{}
	}
	return a.Unmap().WithZone("")
}

func isTrusted(a netip.Addr, trusted []netip.Prefix) bool {
	for _, p := range trusted {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// ipKey is the bucket key of an address; IPv6 clients are grouped by /64 (one subscriber's prefix), so rotating
// addresses inside a prefix does not multiply the allowance.
func ipKey(a netip.Addr) string {
	switch {
	case !a.IsValid():
		return "ip:unknown"
	case a.Is6():
		return "ip6:" + netip.PrefixFrom(a, 64).Masked().String()
	}
	return "ip:" + a.String()
}

// dimension selects which bucket of the class a stage of the chain checks.
type dimension int

const (
	byIP dimension = iota
	byIdentity
)

// limit is one stage of rate limiting. The per-IP stage runs before the session hook (cheap rejection, protects the
// session lookup); the per-identity stage runs after it. Every response that passed a stage carries the RateLimit-*
// headers of the most restrictive bucket seen; a denial answers 429 rate_limited with Retry-After.
func (s *server) limit(dim dimension) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			info := infoFrom(r.Context())
			class := classify(r)
			lims := s.limiters[class]
			var d ratelimit.Decision
			switch dim {
			case byIP:
				d = lims.ip.Allow(ipKey(info.clientIP), s.now())
			case byIdentity:
				info.mu.Lock()
				id := info.identity
				info.mu.Unlock()
				if id == "" {
					next.ServeHTTP(w, r)
					return
				}
				d = lims.identity.Allow("id:"+id, s.now())
			}
			shown := d
			info.set(func(i *requestInfo) {
				if d.Allowed && i.limit != nil && (i.limit.Remaining < d.Remaining ||
					(i.limit.Remaining == d.Remaining && i.limit.Reset > d.Reset)) {
					shown = *i.limit // an earlier stage is closer to exhaustion
				}
				i.limit = &shown
				if !d.Allowed {
					i.denied = string(class) + "/" + [...]string{"ip", "identity"}[dim]
				}
			})
			h := w.Header()
			h.Set("RateLimit-Limit", strconv.Itoa(shown.Limit))
			h.Set("RateLimit-Remaining", strconv.FormatInt(shown.Remaining, 10))
			h.Set("RateLimit-Reset", strconv.FormatInt(problem.Seconds(shown.Reset), 10))
			if !d.Allowed {
				WriteProblem(w, r, &problem.Error{
					Code:       gen.ProblemCodeRateLimited,
					Detail:     "Too many requests; retry after the delay given in Retry-After.",
					RetryAfter: max(d.RetryAfter, time.Second),
				})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
