package headscale

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// TestProbe: the probe of an instance through the adapter (§16.2) — healthy, database unreachable, unsupported
// version, instance not answering (bare 502 of the edge), breaker open, API key refused, edge token refused, no
// instance located, any other answer — each with its stable reason, the version and database reported when reached,
// the breaker state after the calls, and never the upstream text.
func TestProbe(t *testing.T) {
	healthy := func(h *harness) {
		h.edge.on(http.MethodGet, "/api/v1/health", 200, `{"databaseConnectivity":true}`)
	}
	cases := []struct {
		name    string
		prepare func(h *harness)
		reason  string
		version string
		db      *bool
		breaker BreakerState
	}{
		{"healthy", healthy, "", "v0.29.7", probeBool(true), BreakerClosed},
		{"database unreachable", func(h *harness) {
			h.edge.on(http.MethodGet, "/api/v1/health", 200, `{"databaseConnectivity":false}`)
		}, ProbeDatabaseUnreachable, "v0.29.7", probeBool(false), BreakerClosed},
		{"unsupported version", func(h *harness) {
			healthy(h)
			h.edge.set(func(f *fakeEdge) { f.version = "v0.30.0" })
		}, ProbeUnsupportedVersion, "v0.30.0", nil, BreakerClosed},
		{"pre-release version", func(h *harness) {
			healthy(h)
			h.edge.set(func(f *fakeEdge) { f.version = "v0.29.7-dirty" })
		}, ProbeUnsupportedVersion, "v0.29.7-dirty", nil, BreakerClosed},
		{"instance not answering", func(h *harness) {
			h.edge.set(func(f *fakeEdge) { f.slug = "another" }) // the edge cannot route: bare 404, as for a stopped instance
		}, ProbeInstanceUnavailable, "", nil, BreakerClosed},
		{"health endpoint unavailable", func(h *harness) {
			h.edge.on(http.MethodGet, "/api/v1/health", http.StatusServiceUnavailable, ``)
		}, ProbeInstanceUnavailable, "v0.29.7", nil, BreakerClosed},
		{"api key refused", func(h *harness) {
			healthy(h)
			h.loc.setKey(testAPIKey("wrongprefix1"))
		}, ProbeAPIKeyRejected, "v0.29.7", nil, BreakerClosed},
		{"edge token refused", func(h *harness) {
			h.edge.set(func(f *fakeEdge) { f.token = strings.Repeat("X", 40) })
		}, ProbeEdgeRejected, "", nil, BreakerClosed},
		{"not located", func(h *harness) {
			h.loc.err = fmt.Errorf("tenant: %w", ErrNoInstance)
		}, ProbeNotLocated, "", nil, ""},
		{"locator failure", func(h *harness) {
			h.loc.err = errors.New("secret store unavailable")
		}, ProbeInternal, "", nil, ""},
		{"other answer", func(h *harness) {
			h.edge.on(http.MethodGet, "/api/v1/health", 500, gw(2, "fake headscale says no "+testAPIKey("leakprefix12")))
		}, ProbeUpstreamRejected, "v0.29.7", nil, BreakerClosed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t, Options{Retry: RetryPolicy{Attempts: 1}})
			c.prepare(h)
			p := h.reg.Probe(context.Background(), testTenant)
			if p.Reason() != c.reason || p.Healthy() != (c.reason == "") || p.Version != c.version || !sameProbeBool(p.Database, c.db) ||
				p.Breaker != c.breaker {
				t.Fatalf("probe = {instance %s version %q db %v breaker %q reason %q err %v}, want version %q db %v breaker %q reason %q",
					p.InstanceID, p.Version, showBool(p.Database), p.Breaker, p.Reason(), p.Err, c.version, showBool(c.db), c.breaker, c.reason)
			}
			if c.breaker != "" && p.InstanceID != testInstance {
				t.Errorf("instance %s, want %s", p.InstanceID, testInstance)
			}
			if strings.Contains(p.Reason(), "says no") || strings.Contains(p.Reason(), "hskey") {
				t.Errorf("reason leaks the upstream text: %q", p.Reason())
			}
		})
	}
}

// TestProbeBreakerAndCache: failures of the probe count on the instance's breaker like any other call — once it is
// open the probe reports circuit_open without calling the instance; a probe neither fills nor needs the registry's
// cache, but uses a fresh cached target; a nil tenant is refused locally.
func TestProbeBreakerAndCache(t *testing.T) {
	h := newHarness(t, Options{Retry: RetryPolicy{Attempts: 1}, Breaker: BreakerConfig{FailureThreshold: 2, OpenFor: time.Minute}})
	h.edge.on(http.MethodGet, "/api/v1/health", 200, `{"databaseConnectivity":true}`)
	h.edge.set(func(f *fakeEdge) { f.slug = "stopped" })
	for i, want := range []BreakerState{BreakerClosed, BreakerOpen} {
		if p := h.reg.Probe(context.Background(), testTenant); p.Reason() != ProbeInstanceUnavailable || p.Breaker != want {
			t.Fatalf("probe %d: reason %q breaker %q, want instance_unavailable %q", i+1, p.Reason(), p.Breaker, want)
		}
	}
	h.edge.set(func(f *fakeEdge) { f.slug = "tenant-a" })
	h.edge.reset()
	if p := h.reg.Probe(context.Background(), testTenant); p.Reason() != ProbeCircuitOpen || p.Breaker != BreakerOpen ||
		len(h.edge.requests()) != 0 {
		t.Fatalf("open breaker: reason %q breaker %q, %d requests sent", p.Reason(), p.Breaker, len(h.edge.requests()))
	}
	if s := h.reg.BreakerState(testInstance); s != BreakerOpen {
		t.Errorf("registry breaker %q, want open (the probe's failures are the instance's)", s)
	}
	h.clk.advance(time.Minute)
	if p := h.reg.Probe(context.Background(), testTenant); !p.Healthy() || p.Breaker != BreakerClosed {
		t.Fatalf("trial after OpenFor: reason %q breaker %q", p.Reason(), p.Breaker)
	}

	// Cache: a probe does not fill it; a fresh entry (from ForTenant) is used without asking the locator again.
	if _, ok := h.reg.CachedVersion(testTenant); ok {
		t.Error("the probes filled the registry cache")
	}
	h.instance(t)
	before := h.loc.count()
	if p := h.reg.Probe(context.Background(), testTenant); !p.Healthy() || h.loc.count() != before {
		t.Errorf("probe with a fresh cache entry: reason %q, locator calls %d → %d", p.Reason(), before, h.loc.count())
	}
	if p := h.reg.Probe(context.Background(), uuid.Nil); p.Reason() != ProbeInternal {
		t.Errorf("nil tenant: %q", p.Reason())
	}
	// A probe cut short by its caller says nothing about the instance: the context error is in Err.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if p := h.reg.Probe(ctx, testTenant); p.Healthy() || !errors.Is(p.Err, context.Canceled) {
		t.Errorf("cancelled probe: reason %q err %v", p.Reason(), p.Err)
	}
}

func probeBool(v bool) *bool { return &v }

func sameProbeBool(a, b *bool) bool { return (a == nil) == (b == nil) && (a == nil || *a == *b) }

func showBool(b *bool) any {
	if b == nil {
		return nil
	}
	return *b
}
