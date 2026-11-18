package faultinject

import (
	"context"
	"errors"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	agentv1 "github.com/zhaduchanhzz/network-access-mesh/api/agent/v1"
	"github.com/zhaduchanhzz/network-access-mesh/internal/agentclient"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/idp"
	"github.com/zhaduchanhzz/network-access-mesh/internal/platform"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/orchestrator"
	"github.com/zhaduchanhzz/network-access-mesh/internal/secrets"
)

// fakeAgent answers every RPC and counts the calls that reached it.
type fakeAgent struct{ calls map[string]int }

func (f *fakeAgent) hit(n string) { f.calls[n]++ }

func (f *fakeAgent) ValidateConfig(context.Context, *agentv1.ValidateConfigRequest, ...grpc.CallOption) (*agentv1.ValidateConfigResponse, error) {
	f.hit("ValidateConfig")
	return &agentv1.ValidateConfigResponse{Valid: true}, nil
}

func (f *fakeAgent) EnsureInstance(_ context.Context, r *agentv1.EnsureInstanceRequest, _ ...grpc.CallOption) (*agentv1.EnsureInstanceResponse, error) {
	f.hit("EnsureInstance:" + r.GetTargetPhase().String())
	return &agentv1.EnsureInstanceResponse{}, nil
}

func (f *fakeAgent) GetInstanceStatus(context.Context, *agentv1.GetInstanceStatusRequest, ...grpc.CallOption) (*agentv1.GetInstanceStatusResponse, error) {
	f.hit("GetInstanceStatus")
	return &agentv1.GetInstanceStatusResponse{}, nil
}

func (f *fakeAgent) RemoveInstance(context.Context, *agentv1.RemoveInstanceRequest, ...grpc.CallOption) (*agentv1.RemoveInstanceResponse, error) {
	f.hit("RemoveInstance")
	return &agentv1.RemoveInstanceResponse{}, nil
}

func (f *fakeAgent) BootstrapPolicy(context.Context, *agentv1.BootstrapPolicyRequest, ...grpc.CallOption) (*agentv1.BootstrapPolicyResponse, error) {
	f.hit("BootstrapPolicy")
	return &agentv1.BootstrapPolicyResponse{}, nil
}

func (f *fakeAgent) BootstrapApiKey(context.Context, *agentv1.BootstrapApiKeyRequest, ...grpc.CallOption) (*agentv1.BootstrapApiKeyResponse, error) { //nolint:revive // generated name
	f.hit("BootstrapApiKey")
	return &agentv1.BootstrapApiKeyResponse{Created: true, Prefix: "abcdefghijkl"}, nil
}

func (f *fakeAgent) EnsureEdgeAttachment(context.Context, *agentv1.EnsureEdgeAttachmentRequest, ...grpc.CallOption) (*agentv1.EnsureEdgeAttachmentResponse, error) {
	f.hit("EnsureEdgeAttachment")
	return &agentv1.EnsureEdgeAttachmentResponse{Attached: true}, nil
}

func (f *fakeAgent) RemoveEdgeAttachment(context.Context, *agentv1.RemoveEdgeAttachmentRequest, ...grpc.CallOption) (*agentv1.RemoveEdgeAttachmentResponse, error) {
	f.hit("RemoveEdgeAttachment")
	return &agentv1.RemoveEdgeAttachmentResponse{}, nil
}

func TestPlanValidation(t *testing.T) {
	good := Plan{{Call: "agent.BootstrapApiKey", Mode: Kill, Times: 1}, {Call: "store.Configure", Mode: Permanent, After: true},
		{Call: "prober.Relay", Mode: Transient, Times: 6, Skip: 1}}
	p, err := ParsePlan(good.Encode())
	if err != nil || len(p) != 3 || p[2].Skip != 1 {
		t.Fatalf("round trip: %v %+v", err, p)
	}
	if p, err := ParsePlan(""); err != nil || p != nil {
		t.Fatalf("empty plan: %v %v", p, err)
	}
	for name, bad := range map[string]string{
		"unknown call":             `[{"call":"agent.Nope","mode":"permanent"}]`,
		"unknown mode":             `[{"call":"store.Configure","mode":"flaky"}]`,
		"negative times":           `[{"call":"store.Configure","mode":"transient","times":-1}]`,
		"permanent relay probe":    `[{"call":"prober.Relay","mode":"permanent"}]`,
		"kill more than once":      `[{"call":"agent.BootstrapApiKey","mode":"kill"}]`,
		"unknown field":            `[{"call":"store.Configure","mode":"transient","when":"later"}]`,
		"not a list":               `{"call":"store.Configure"}`,
		"every call is documented": `[{"call":"","mode":"permanent"}]`,
	} {
		if _, err := ParsePlan(bad); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	for call, step := range Calls {
		if step == "" || !strings.Contains(call, ".") {
			t.Errorf("call %q: step %q", call, step)
		}
	}
}

// TestAgentFaults: before ⇒ the real RPC is not made; after ⇒ it is made and its answer replaced; Times and Skip count
// matching calls deterministically; the errors are what the state machine classifies as permanent / transient.
func TestAgentFaults(t *testing.T) {
	ctx := context.Background()
	fa := &fakeAgent{calls: map[string]int{}}
	in, err := New(Plan{
		{Call: "agent.BootstrapPolicy", Mode: Transient, Times: 2},
		{Call: "agent.BootstrapApiKey", Mode: Permanent, After: true, Skip: 1, Times: 1},
		{Call: "agent.EnsureInstance:NETWORK", Mode: Permanent},
	}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	a := &Agent{Next: fa, In: in}

	for i := range 3 {
		_, err := a.BootstrapPolicy(ctx, &agentv1.BootstrapPolicyRequest{})
		if wantFail := i < 2; (err != nil) != wantFail || (err != nil && (!agentclient.Retryable(err) || !IsInjected(err))) {
			t.Fatalf("policy call %d: %v", i+1, err)
		}
	}
	if fa.calls["BootstrapPolicy"] != 1 {
		t.Fatalf("a fault before the call made the call: %d", fa.calls["BootstrapPolicy"])
	}

	// skip 1: the first call goes through; the second is made and its answer dropped; the third goes through again.
	for i := range 3 {
		r, err := a.BootstrapApiKey(ctx, &agentv1.BootstrapApiKeyRequest{})
		switch i {
		case 1:
			ref, ok := agentclient.RefusalOf(err)
			if r != nil || !ok || ref.GetReason() != agentv1.RefusalReason_REFUSAL_REASON_STATE || agentclient.Retryable(err) ||
				status.Code(err) != codes.FailedPrecondition {
				t.Fatalf("key call 2: %v %v", r, err)
			}
		default:
			if err != nil || !r.GetCreated() {
				t.Fatalf("key call %d: %v %v", i+1, r, err)
			}
		}
	}
	if fa.calls["BootstrapApiKey"] != 3 {
		t.Fatalf("a fault after the call did not make it: %d", fa.calls["BootstrapApiKey"])
	}

	// Times 0: every matching call; other phases of the same RPC are not matched.
	for range 2 {
		if _, err := a.EnsureInstance(ctx, &agentv1.EnsureInstanceRequest{TargetPhase: agentv1.TargetPhase_TARGET_PHASE_NETWORK}); err == nil {
			t.Fatal("network phase passed")
		}
	}
	if _, err := a.EnsureInstance(ctx, &agentv1.EnsureInstanceRequest{TargetPhase: agentv1.TargetPhase_TARGET_PHASE_STORAGE}); err != nil {
		t.Fatalf("storage phase: %v", err)
	}
	if got := in.Fired(); got[0] != 2 || got[1] != 1 || got[2] != 2 {
		t.Fatalf("fired %v", got)
	}
	if c := in.Calls(); c["agent.BootstrapPolicy"] != 3 || c["agent.BootstrapApiKey"] != 3 || c["agent.EnsureInstance:STORAGE"] != 1 {
		t.Fatalf("calls %v", c)
	}
	if s := in.Summary(); !strings.Contains(s, "agent.BootstrapApiKey×3") || !strings.Contains(s, "fired 2") {
		t.Fatalf("summary %s", s)
	}
}

func TestKillAfterTheCall(t *testing.T) {
	fa := &fakeAgent{calls: map[string]int{}}
	killed := 0
	var events []Event
	in, err := New(Plan{{Call: "agent.BootstrapApiKey", Mode: Kill, Times: 1}},
		Options{Kill: func() { killed++ }, Notify: func(e Event) { events = append(events, e) }})
	if err != nil {
		t.Fatal(err)
	}
	a := &Agent{Next: fa, In: in}
	if _, err := a.BootstrapApiKey(context.Background(), &agentv1.BootstrapApiKeyRequest{}); err == nil || !agentclient.Retryable(err) {
		t.Fatalf("after a kill that returned: %v", err)
	}
	if killed != 1 || fa.calls["BootstrapApiKey"] != 1 || len(events) != 1 || !events[0].Fired || !events[0].After {
		t.Fatalf("killed %d, calls %v, events %+v", killed, fa.calls, events)
	}
	if _, err := a.BootstrapApiKey(context.Background(), &agentv1.BootstrapApiKeyRequest{}); err != nil || killed != 1 {
		t.Fatalf("the kill fired twice: %v %d", err, killed)
	}
}

type fakeStore struct {
	orchestrator.Store
	configured int
}

func (f *fakeStore) Configure(context.Context, orchestrator.ConfigureRequest) (uuid.UUID, error) {
	f.configured++
	return uuid.New(), nil
}

func (f *fakeStore) AssignRelay(context.Context, orchestrator.RelayRequest) error { return nil }

type fakeRegistry struct{ headscale.Instance }

func (f fakeRegistry) ForTenant(context.Context, uuid.UUID) (headscale.Instance, error) {
	return f, nil
}
func (fakeRegistry) GetPolicy(context.Context) (headscale.Policy, error) {
	return headscale.Policy{Data: "{}"}, nil
}

type fakeProber struct{ edge int }

func (*fakeProber) Relay(context.Context, orchestrator.RelayProbe) (orchestrator.ProbeResult, error) {
	return orchestrator.ProbeResult{OK: true}, nil
}

func (f *fakeProber) Edge(context.Context, orchestrator.EdgeProbe) (orchestrator.ProbeResult, error) {
	f.edge++
	return orchestrator.ProbeResult{OK: true}, nil
}

type fakePlacer struct{}

func (fakePlacer) Allocate(context.Context, platform.AllocationRequest) (platform.Allocation, error) {
	return platform.Allocation{}, nil
}
func (fakePlacer) Release(context.Context, uuid.UUID, uuid.UUID) (bool, error) { return true, nil }

type fakeSecrets struct{ orchestrator.SecretStore }

func (fakeSecrets) EnsureDEK(context.Context, secrets.Owner) (int32, error) { return 1, nil }

type fakeDrivers struct{}

func (fakeDrivers) Driver(string) (idp.IdPDriver, error) { return fakeIdP{}, nil }

type fakeIdP struct{ idp.IdPDriver }

func (fakeIdP) EnsureIssuer(context.Context, idp.IssuerSpec) (idp.IssuerResult, error) {
	return idp.IssuerResult{}, nil
}

// TestOtherLayers: every layer's errors carry ErrInjected and the classification of the real collaborator.
func TestOtherLayers(t *testing.T) {
	ctx := context.Background()
	in, err := New(Plan{
		{Call: "store.Configure", Mode: Permanent, After: true, Times: 1},
		{Call: "store.AssignRelay", Mode: Transient, Times: 1},
		{Call: "headscale.GetPolicy", Mode: Permanent, Times: 1},
		{Call: "headscale.GetPolicy", Mode: Transient, Times: 1},
		{Call: "prober.Edge", Mode: Permanent, After: true, Times: 1},
		{Call: "prober.Relay", Mode: Transient, Times: 1},
		{Call: "placer.Allocate", Mode: Permanent, Times: 1},
		{Call: "secrets.EnsureDEK", Mode: Permanent, Times: 1},
		{Call: "idp.EnsureIssuer", Mode: Transient, Times: 1},
	}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	fs := &fakeStore{}
	s := &Store{Store: fs, In: in}
	if _, err := s.Configure(ctx, orchestrator.ConfigureRequest{}); !errors.Is(err, orchestrator.ErrState) || !errors.Is(err, ErrInjected) || fs.configured != 1 {
		t.Fatalf("configure after: %v (%d)", err, fs.configured)
	}
	if err := s.AssignRelay(ctx, orchestrator.RelayRequest{}); err == nil || errors.Is(err, orchestrator.ErrState) || !IsInjected(err) {
		t.Fatalf("relay rows transient: %v", err)
	}

	h := &Headscale{Next: fakeRegistry{}, In: in}
	inst, err := h.ForTenant(ctx, uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	var he *headscale.Error
	if _, err := inst.GetPolicy(ctx); !errors.As(err, &he) || he.Kind != headscale.KindUpstreamRejected || !errors.Is(err, ErrInjected) {
		t.Fatalf("policy permanent: %v", err)
	}
	if _, err := inst.GetPolicy(ctx); !errors.As(err, &he) || he.Kind != headscale.KindUnavailable {
		t.Fatalf("policy transient: %v", err)
	}
	if p, err := inst.GetPolicy(ctx); err != nil || p.Data != "{}" {
		t.Fatalf("policy third call: %v", err)
	}

	fp := &fakeProber{}
	p := &Prober{Next: fp, In: in}
	if r, err := p.Edge(ctx, orchestrator.EdgeProbe{}); err != nil || r.OK || len(r.Exposed) != 1 || fp.edge != 1 {
		t.Fatalf("edge probe permanent after: %+v %v (%d)", r, err, fp.edge)
	}
	if r, err := p.Edge(ctx, orchestrator.EdgeProbe{}); err != nil || !r.OK {
		t.Fatalf("edge probe again: %+v %v", r, err)
	}
	if _, err := p.Relay(ctx, orchestrator.RelayProbe{}); !IsInjected(err) {
		t.Fatalf("relay probe: %v", err)
	}

	if _, err := (&Placer{Next: fakePlacer{}, In: in}).Allocate(ctx, platform.AllocationRequest{}); !errors.Is(err, platform.ErrConflict) {
		t.Fatalf("placement: %v", err)
	}
	if _, err := (&Secrets{SecretStore: fakeSecrets{}, In: in}).EnsureDEK(ctx, secrets.TenantOwner(uuid.New())); !errors.Is(err, secrets.ErrKeyDestroyed) {
		t.Fatalf("DEK: %v", err)
	}
	drv, err := (&IdP{Next: fakeDrivers{}, In: in}).Driver("keycloak")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := drv.EnsureIssuer(ctx, idp.IssuerSpec{}); idp.CodeOf(err) != idp.CodeUnavailable || !errors.Is(err, ErrInjected) {
		t.Fatalf("issuer: %v", err)
	}
}

// TestNotImportedByProduction: no production package (apps/, internal/) imports the fault injection — it exists only in
// the harness's process.
func TestNotImportedByProduction(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	const self = "github.com/zhaduchanhzz/network-access-mesh/tests/"
	checked := 0
	for _, top := range []string{"apps", "internal"} {
		err := filepath.WalkDir(filepath.Join(root, top), func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if d.Name() == "testdata" || d.Name() == "node_modules" || strings.HasPrefix(d.Name(), ".") {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return nil
			}
			f, err := parser.ParseFile(token.NewFileSet(), p, nil, parser.ImportsOnly)
			if err != nil {
				return err
			}
			checked++
			for _, imp := range f.Imports {
				if v, _ := strconv.Unquote(imp.Path.Value); strings.HasPrefix(v, self) {
					t.Errorf("%s imports %s", p, v)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if checked < 100 {
		t.Fatalf("only %d files checked — wrong root %s?", checked, root)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatal(err)
	}
}
