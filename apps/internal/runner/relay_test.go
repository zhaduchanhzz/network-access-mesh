package runner

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"strings"
	"testing"
	"time"

	probe "github.com/zhaduchanhzz/network-access-mesh/apps/probe/prober"
	"github.com/zhaduchanhzz/network-access-mesh/apps/probe/stub"
	"github.com/zhaduchanhzz/network-access-mesh/internal/config"
	"github.com/zhaduchanhzz/network-access-mesh/internal/relay"
)

// TestRelayProber: the RelayService's prober over the real prober (apps/probe — prober.Local, the code the prober
// service runs) against the stubs of the public entry on loopback — the edge with its strict SNI and allow-listed paths,
// the STUN responder of stund's rules: a tenant's DERP probe answers 200 and STUN a mapped address; an unknown tenant
// hostname is the edge's uniform 404 (expectation_failed with the status); a silent STUN responder is timeout; a target
// outside the prober's allow-list is an error (the probe could not run), not a failed check.
func TestRelayProber(t *testing.T) {
	edge, err := stub.NewEdge("127.0.0.1:0", "mesh.example.test", "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = edge.Close() })
	stun, err := stub.NewSTUN("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stun.Close() })
	p := RelayProber(probe.New(probe.Options{Allow: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, RootCAs: edge.CA}))
	req := relay.ProbeRequest{Address: edge.Addr().String(), Host: edge.Host("tenant-a"), STUN: stun.Addr().String()}
	r, err := p.Relay(t.Context(), req)
	if err != nil || !r.DERP.OK || r.DERP.Status != 200 || r.DERP.Code != "" || !r.STUN.OK || r.STUN.Code != "" || r.DERP.Duration <= 0 {
		t.Fatalf("healthy relay: %+v %v", r, err)
	}
	r, err = p.Relay(t.Context(), relay.ProbeRequest{Address: req.Address, Host: edge.Host("nope"), STUN: req.STUN})
	if err != nil || r.DERP.OK || r.DERP.Status != 404 || r.DERP.Code != "expectation_failed" || !r.STUN.OK {
		t.Errorf("unknown hostname: %+v %v", r, err)
	}
	stun.SetSilent(true)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	r, err = p.Relay(ctx, req)
	if err != nil || !r.DERP.OK || r.STUN.OK || r.STUN.Code != probe.CodeTimeout {
		t.Errorf("silent STUN: %+v %v", r, err)
	}
	if _, err = p.Relay(t.Context(), relay.ProbeRequest{Address: req.Address, Host: req.Host, STUN: "192.0.2.1:3478"}); err == nil ||
		probe.CodeOf(err) != probe.CodeTargetNotAllowed {
		t.Errorf("target outside the allow-list: %v, want the prober's refusal as an error", err)
	}
}

// TestNewRelayProbe: without MG_PROBER_URL the worker runs no relay.probe (nil, a warning naming the variable, no
// schedule); with it, the service probes towards MG_PROVISION_EDGE_ADDR.
func TestNewRelayProbe(t *testing.T) {
	var logs strings.Builder
	log := slog.New(slog.NewTextHandler(&logs, nil))
	svc, err := NewRelayProbe(config.Config{}, nil, log, nil)
	if err != nil || svc != nil || !strings.Contains(logs.String(), "MG_PROBER_URL") {
		t.Fatalf("without a prober: %v %v %q", svc, err, logs.String())
	}
	if err := relaySchedule(nil)(t.Context()); err != nil {
		t.Errorf("the schedule of a worker without a prober: %v", err)
	}
	cfg := config.Config{Provisioning: config.Provisioning{ProberURL: "http://prober:8080", EdgeAddr: "10.249.0.2:443"}}
	if _, err := NewRelayProbe(cfg, nil, slog.New(slog.NewTextHandler(io.Discard, nil)), nil); err == nil {
		t.Error("a relay service without a store was built") // relay.New refuses a nil store
	}
	cfg.Provisioning.ProberURL = "ftp://prober"
	if _, err := NewRelayProbe(cfg, nil, log, nil); err == nil {
		t.Error("a prober URL that is not http(s) was accepted")
	}
}
