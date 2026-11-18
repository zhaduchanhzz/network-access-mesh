package orchestrator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "github.com/zhaduchanhzz/network-access-mesh/api/agent/v1"
	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
)

// paramSHAOf is the fake agent's rendering: a sha256 of the parameters (the real one renders config.yaml).
func paramSHAOf(spec *agentv1.InstanceSpec) string {
	raw, _ := json.Marshal(paramsOf(spec))
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// bfAgent is a host with one instance built by hand: running, healthy, the edge attached without the flag, no
// activation; its config.yaml is the rendering of `onDisk`.
type bfAgent struct {
	st        *agentv1.InstanceStatus
	onDisk    string
	invalid   bool
	calls     []string
	validated []*agentv1.InstanceSpec
	attachJob string
	// restartOnAttach: EnsureEdgeAttachment "restarts" the container (a host that misbehaves)
	restartOnAttach bool
}

func (a *bfAgent) GetHostInfo(context.Context, *agentv1.GetHostInfoRequest, ...grpc.CallOption) (*agentv1.GetHostInfoResponse, error) {
	a.calls = append(a.calls, "GetHostInfo")
	return &agentv1.GetHostInfoResponse{TemplateVersion: 1}, nil
}

func (a *bfAgent) GetInstanceStatus(context.Context, *agentv1.GetInstanceStatusRequest, ...grpc.CallOption) (*agentv1.GetInstanceStatusResponse, error) {
	a.calls = append(a.calls, "GetInstanceStatus")
	s, _ := proto.Clone(a.st).(*agentv1.InstanceStatus) // a fresh RPC answer
	s.ConfigSha256 = a.onDisk
	return &agentv1.GetInstanceStatusResponse{Status: s}, nil
}

func (a *bfAgent) ValidateConfig(_ context.Context, in *agentv1.ValidateConfigRequest, _ ...grpc.CallOption) (*agentv1.ValidateConfigResponse, error) {
	a.calls = append(a.calls, "ValidateConfig")
	a.validated = append(a.validated, in.GetSpec())
	if a.invalid {
		return &agentv1.ValidateConfigResponse{Valid: false, ExitCode: 1}, nil
	}
	return &agentv1.ValidateConfigResponse{Valid: true, ConfigSha256: paramSHAOf(in.GetSpec())}, nil
}

func (a *bfAgent) EnsureEdgeAttachment(_ context.Context, in *agentv1.EnsureEdgeAttachmentRequest, _ ...grpc.CallOption) (*agentv1.EnsureEdgeAttachmentResponse, error) {
	a.calls = append(a.calls, "EnsureEdgeAttachment")
	a.attachJob = in.GetJobId()
	a.st.Activated, a.st.EdgeAttachFlag = true, true
	if a.restartOnAttach {
		a.st.StartedAt = timestamppb.New(a.st.GetStartedAt().AsTime().Add(time.Minute))
	}
	return &agentv1.EnsureEdgeAttachmentResponse{Attached: true, AlreadyAttached: true, NetworkMembers: 2}, nil
}

// bfStore is the registry of the backfill.
type bfStore struct {
	t        BackfillTarget
	begun    []audit.Event
	recorded []BackfillRecord
	failed   []string
	recErr   error
}

func (s *bfStore) BackfillTarget(context.Context, uuid.UUID) (BackfillTarget, error) { return s.t, nil }

func (s *bfStore) BeginBackfill(_ context.Context, ev audit.Event) (audit.Operation, error) {
	s.begun = append(s.begun, ev)
	return audit.Operation{ID: uuid.New(), Action: ev.Action}, nil
}

func (s *bfStore) RecordBackfill(_ context.Context, r BackfillRecord) error {
	if s.recErr != nil {
		return s.recErr
	}
	s.recorded = append(s.recorded, r)
	// the registry after the write
	if r.Config != nil {
		raw, _ := json.Marshal(r.Config.Params)
		s.t.Current = &ConfigVersion{ID: r.Config.ID, Version: 1, Status: "applied", ConfigSHA256: r.Config.ConfigSHA256, Params: raw}
		s.t.Instance.DERPRegionID = r.DERPRegionID
	}
	if r.Fingerprint != "" {
		s.t.Instance.NoiseFingerprint = r.Fingerprint
	}
	if r.Relay != nil {
		s.t.RelayRegion, s.t.RelayAssigned = true, true
	}
	return nil
}

func (s *bfStore) FailBackfill(_ context.Context, _ audit.Operation, reason string, _ audit.Details) error {
	s.failed = append(s.failed, reason)
	return nil
}

const bfFP = "1111111111111111111111111111111111111111111111111111111111111111"

// bfWorld is tenant-a of staging as adopted: registry rows of adopt-instance, a host built from the Phase-1 parameter
// file (= the orchestrator's defaults, 512 MiB / 1000 mCPU / 256 PIDs).
func bfWorld(t *testing.T) (*Backfiller, *bfStore, *bfAgent) {
	t.Helper()
	tid, iid := uuid.New(), uuid.New()
	img := "sha256:" + strings.Repeat("a", 64)
	st := &bfStore{t: BackfillTarget{
		Tenant: TenantRecord{ID: tid, Slug: "tenant-a", Status: tenants.StatusActive},
		Instance: InstanceRecord{ID: iid, TenantID: tid, HostID: uuid.New(), Status: tenants.InstanceRunning, ImageDigest: img,
			ControlHostname: "tenant-a.mesh.mg.test", RunUID: 30001, NetCIDR: netip.MustParsePrefix("10.250.0.0/29"),
			PublicEntryIPv4: netip.MustParseAddr("192.0.2.10")},
		DesiredPolicy: true,
	}}
	b := &Backfiller{Store: st, Defaults: BackfillDefaults{Nameservers: []netip.Addr{netip.MustParseAddr("1.1.1.1"),
		netip.MustParseAddr("9.9.9.9")}}}
	want := configParams{ImageDigest: img, RunUID: 30001, NetCIDR: "10.250.0.0/29", MemoryMiB: 512, CPUMillis: 1000, PIDs: 256,
		NodeExpiryDays: 90, Nameservers: []string{"1.1.1.1", "9.9.9.9"}, DERPRegionID: 901, PublicEntryIPv4: "192.0.2.10",
		LogLevel: "LOG_LEVEL_INFO"}
	spec, err := want.spec(&agentv1.InstanceRef{})
	if err != nil {
		t.Fatal(err)
	}
	ag := &bfAgent{onDisk: paramSHAOf(spec), st: &agentv1.InstanceStatus{
		ContainerState: agentv1.ContainerState_CONTAINER_STATE_RUNNING, Health: agentv1.HealthState_HEALTH_STATE_HEALTHY,
		ContainerId: "c1", StartedAt: timestamppb.New(time.Date(2026, 11, 16, 10, 0, 0, 0, time.UTC)), ImageDigest: img,
		NoiseKeyFingerprint: bfFP, TemplateVersion: 1,
		Network: &agentv1.NetworkState{Exists: true, Internal: true, Subnet: "10.250.0.0/29", EdgeAttached: true,
			Members: []string{"mg-edge", "mg-hs-tenant-a"}}}}
	b.Agent = ag
	return b, st, ag
}

func items(p BackfillPlan) map[string]string {
	out := map[string]string{}
	for _, it := range p.Items {
		out[it.Name] = it.State
	}
	return out
}

// TestBackfillAdoptedInstance: the dry run validates everything and writes nothing; the run activates through the agent
// (job id = the audit operation, no restart) and records the version (params of tenant.provision, sha256 of the host),
// the fingerprint and the relay in one store call; a second run finds everything and changes nothing — no audit event,
// no ValidateConfig, no agent write.
func TestBackfillAdoptedInstance(t *testing.T) {
	b, st, ag := bfWorld(t)
	ctx := t.Context()
	req := BackfillRequest{TenantID: st.t.Tenant.ID, DryRun: true, Actor: "test"}
	plan, err := b.Backfill(ctx, req)
	if err != nil || !plan.Changed || plan.OperationID != nil {
		t.Fatalf("dry run: %+v, %v", plan, err)
	}
	for n, s := range items(plan) {
		if s != ItemWouldWrite {
			t.Errorf("dry run: %s %s", n, s)
		}
	}
	if len(st.begun) != 0 || len(st.recorded) != 0 || slices.Contains(ag.calls, "EnsureEdgeAttachment") {
		t.Fatalf("dry run wrote: begun %d recorded %d calls %v", len(st.begun), len(st.recorded), ag.calls)
	}
	if plan.ConfigSHA256 != ag.onDisk || plan.RenderedSHA256 != ag.onDisk || plan.NoiseKeyFingerprint != bfFP {
		t.Fatalf("dry run plan: %+v", plan)
	}

	ag.calls = nil
	req.DryRun = false
	plan, err = b.Backfill(ctx, req)
	if err != nil || !plan.Changed || plan.OperationID == nil {
		t.Fatalf("run: %+v, %v", plan, err)
	}
	for n, s := range items(plan) {
		if s != ItemWritten {
			t.Errorf("run: %s %s", n, s)
		}
	}
	if want := []string{"GetInstanceStatus", "GetHostInfo", "ValidateConfig", "EnsureEdgeAttachment", "GetInstanceStatus"}; !slices.Equal(ag.calls, want) {
		t.Fatalf("agent calls %v, want %v", ag.calls, want)
	}
	if ag.attachJob != plan.OperationID.String() {
		t.Fatalf("activation job %s, operation %s", ag.attachJob, plan.OperationID)
	}
	if len(st.begun) != 1 || st.begun[0].Action != ActionInstanceBackfill || st.begun[0].ActorType != audit.ActorSystem ||
		len(st.recorded) != 1 || len(st.failed) != 0 {
		t.Fatalf("store: begun %+v recorded %d failed %v", st.begun, len(st.recorded), st.failed)
	}
	r := st.recorded[0]
	if r.Config == nil || r.Config.ConfigSHA256 != ag.onDisk || r.Config.TemplateVersion != 1 || r.Fingerprint != bfFP ||
		r.Relay == nil || r.Relay.Code != "mg-tenant-a" || r.Relay.DERPRegionID != 901 || r.Relay.STUNPort != DefaultSTUNPort ||
		r.DERPRegionID != 901 || r.Operation.ID != *plan.OperationID {
		t.Fatalf("record: %+v", r)
	}
	if p := r.Config.Params; p.MemoryMiB != 512 || p.CPUMillis != 1000 || p.PIDs != 256 || p.NodeExpiryDays != 90 ||
		p.LogLevel != "LOG_LEVEL_INFO" || p.StunPort != nil {
		t.Fatalf("params %+v", p)
	}
	// the recorded parameters re-render the configuration on the host — what reconfigure, upgrade and their rollback do
	spec, err := r.Config.Params.spec(&agentv1.InstanceRef{})
	if err != nil || paramSHAOf(spec) != ag.onDisk {
		t.Fatalf("recorded parameters render %v, %v", paramSHAOf(spec), err)
	}

	ag.calls = nil
	plan, err = b.Backfill(ctx, req)
	if err != nil || plan.Changed || plan.OperationID != nil {
		t.Fatalf("second run: %+v, %v", plan, err)
	}
	for n, s := range items(plan) {
		if s != ItemPresent {
			t.Errorf("second run: %s %s", n, s)
		}
	}
	if len(st.begun) != 1 || len(st.recorded) != 1 || !slices.Equal(ag.calls, []string{"GetInstanceStatus"}) {
		t.Fatalf("second run changed something: begun %d recorded %d calls %v", len(st.begun), len(st.recorded), ag.calls)
	}
}

// TestBackfillOverridesAndPlanLimits: the plan's limits replace the defaults (as in tenant.provision), the operator's
// overrides replace both; out-of-range values are refused before any agent call.
func TestBackfillOverridesAndPlanLimits(t *testing.T) {
	b, st, ag := bfWorld(t)
	st.t.Tenant.Instance = InstanceLimits{CPUs: 0.5, MemoryMB: 256, PIDs: 128}
	ag.onDisk = strings.Repeat("e", 64)
	_, err := b.Backfill(t.Context(), BackfillRequest{TenantID: st.t.Tenant.ID, DryRun: true})
	var be *BackfillError
	if !errors.As(err, &be) || be.Code != BackfillConfigDiffers {
		t.Fatalf("mismatch: %v", err)
	}
	p := paramsOf(ag.validated[0])
	if p.MemoryMiB != 256 || p.CPUMillis != 500 || p.PIDs != 128 {
		t.Fatalf("plan limits not applied: %+v", p)
	}
	exp, derp, mem := uint32(30), uint32(950), uint32(1024)
	_, _ = b.Backfill(t.Context(), BackfillRequest{TenantID: st.t.Tenant.ID, DryRun: true, Overrides: BackfillOverrides{
		NodeExpiryDays: &exp, DERPRegionID: &derp, MemoryMiB: &mem, LogLevel: "warn", Nameservers: []string{"2606:4700:4700:0::1111"}}})
	p = paramsOf(ag.validated[1])
	if p.NodeExpiryDays != 30 || p.DERPRegionID != 950 || p.MemoryMiB != 1024 || p.LogLevel != "LOG_LEVEL_WARN" ||
		!slices.Equal(p.Nameservers, []string{"2606:4700:4700::1111"}) {
		t.Fatalf("overrides not applied: %+v", p)
	}
	n := len(ag.calls)
	for name, o := range map[string]BackfillOverrides{
		"pids":      {PIDs: new(uint32(5))},
		"log level": {LogLevel: "debug"},
		"derp":      {DERPRegionID: new(uint32(5))},
		"dns":       {Nameservers: []string{"127.0.0.1"}},
	} {
		_, err := b.Backfill(t.Context(), BackfillRequest{TenantID: st.t.Tenant.ID, Overrides: o})
		if !errors.As(err, &be) || be.Code != BackfillParams {
			t.Errorf("%s: %v", name, err)
		}
	}
	if slices.Contains(ag.calls[n:], "ValidateConfig") || len(st.begun) != 0 {
		t.Fatal("refused overrides reached the agent or the audit")
	}
}

// TestBackfillRefusals: every state the backfill may not record is refused before anything is written (no audit
// operation, no agent write, no registry write).
func TestBackfillRefusals(t *testing.T) {
	for name, c := range map[string]struct {
		mod  func(*bfStore, *bfAgent)
		code string
	}{
		"instance quarantined in the registry": {func(s *bfStore, _ *bfAgent) { s.t.Instance.Status = tenants.InstanceQuarantined }, BackfillNotRunning},
		"instance stopped":                     {func(s *bfStore, _ *bfAgent) { s.t.Instance.Status = tenants.InstanceStopped }, BackfillNotRunning},
		"tenant provisioning":                  {func(s *bfStore, _ *bfAgent) { s.t.Tenant.Status = "provisioning" }, BackfillTenantState},
		"lifecycle job running":                {func(s *bfStore, _ *bfAgent) { s.t.LockHolder = uuid.New() }, BackfillLifecycleBusy},
		"no public entry":                      {func(s *bfStore, _ *bfAgent) { s.t.Instance.PublicEntryIPv4 = netip.Addr{} }, BackfillRegistryState},
		"quarantined on the host":              {func(_ *bfStore, a *bfAgent) { a.st.Quarantined = true }, BackfillQuarantined},
		"container stopped": {func(_ *bfStore, a *bfAgent) {
			a.st.ContainerState = agentv1.ContainerState_CONTAINER_STATE_EXITED
		}, BackfillHostState},
		"unhealthy":            {func(_ *bfStore, a *bfAgent) { a.st.Health = agentv1.HealthState_HEALTH_STATE_UNHEALTHY }, BackfillHostState},
		"another image":        {func(_ *bfStore, a *bfAgent) { a.st.ImageDigest = "sha256:" + strings.Repeat("c", 64) }, BackfillHostState},
		"network not internal": {func(_ *bfStore, a *bfAgent) { a.st.Network.Internal = false }, BackfillHostState},
		"another subnet":       {func(_ *bfStore, a *bfAgent) { a.st.Network.Subnet = "10.250.0.8/29" }, BackfillHostState},
		"no config.yaml":       {func(_ *bfStore, a *bfAgent) { a.onDisk = "" }, BackfillHostState},
		"no fingerprint":       {func(_ *bfStore, a *bfAgent) { a.st.NoiseKeyFingerprint = "" }, BackfillNoFingerprint},
		"fingerprint mismatch": {func(s *bfStore, _ *bfAgent) { s.t.Instance.NoiseFingerprint = strings.Repeat("2", 64) }, BackfillFingerprintDiff},
		"render ≠ host":        {func(_ *bfStore, a *bfAgent) { a.onDisk = strings.Repeat("e", 64) }, BackfillConfigDiffers},
		"configtest refuses":   {func(_ *bfStore, a *bfAgent) { a.invalid = true }, BackfillConfigInvalid},
		"version ≠ host config": {func(s *bfStore, _ *bfAgent) {
			s.t.Current = &ConfigVersion{Version: 3, ConfigSHA256: strings.Repeat("f", 64)}
		}, BackfillConfigVersionAt},
		"no nameservers": {func(*bfStore, *bfAgent) {}, BackfillParams},
	} {
		t.Run(name, func(t *testing.T) {
			b, st, ag := bfWorld(t)
			c.mod(st, ag)
			if name == "no nameservers" {
				b.Defaults.Nameservers = nil
			}
			plan, err := b.Backfill(t.Context(), BackfillRequest{TenantID: st.t.Tenant.ID})
			var be *BackfillError
			if !errors.As(err, &be) || be.Code != c.code {
				t.Fatalf("err %v, want %s", err, c.code)
			}
			if plan.OperationID != nil || len(st.begun) != 0 || len(st.recorded) != 0 || slices.Contains(ag.calls, "EnsureEdgeAttachment") {
				t.Fatalf("a refusal wrote: %+v begun %d recorded %d calls %v", plan, len(st.begun), len(st.recorded), ag.calls)
			}
		})
	}
}

// TestBackfillFailuresAfterTheOperationOpened: a container restarted by the activation (never expected — the backfill
// only verifies it) and a registry write that fails both close the audit operation .failed with a stable code; a run
// after a failed registry write finds the activation done and writes the registry only.
func TestBackfillFailuresAfterTheOperationOpened(t *testing.T) {
	b, st, ag := bfWorld(t)
	ag.restartOnAttach = true
	_, err := b.Backfill(t.Context(), BackfillRequest{TenantID: st.t.Tenant.ID})
	var be *BackfillError
	if !errors.As(err, &be) || be.Code != BackfillHostState || !slices.Equal(st.failed, []string{BackfillHostState}) || len(st.recorded) != 0 {
		t.Fatalf("restart during activation: %v failed %v recorded %d", err, st.failed, len(st.recorded))
	}

	b, st, ag = bfWorld(t)
	st.recErr = errors.New("connection reset")
	if _, err := b.Backfill(t.Context(), BackfillRequest{TenantID: st.t.Tenant.ID}); err == nil ||
		!slices.Equal(st.failed, []string{"registry_write_failed"}) {
		t.Fatalf("registry failure: %v failed %v", err, st.failed)
	}
	st.recErr = nil
	ag.calls = nil
	plan, err := b.Backfill(t.Context(), BackfillRequest{TenantID: st.t.Tenant.ID})
	if err != nil || items(plan)[BackfillActivation] != ItemPresent || items(plan)[BackfillConfigVersion] != ItemWritten ||
		slices.Contains(ag.calls, "EnsureEdgeAttachment") || len(st.recorded) != 1 {
		t.Fatalf("rerun: %+v %v calls %v", plan, err, ag.calls)
	}
}

// TestBackfillOrchestratorBuiltInstanceIsNoop: an instance provisioned by tenant.provision has every item: nothing to
// do, and no ValidateConfig (the version in force is the host's configuration).
func TestBackfillOrchestratorBuiltInstanceIsNoop(t *testing.T) {
	b, st, ag := bfWorld(t)
	st.t.Current = &ConfigVersion{Version: 1, Status: "applied", ConfigSHA256: ag.onDisk}
	st.t.Instance.NoiseFingerprint = bfFP
	st.t.RelayRegion, st.t.RelayAssigned = true, true
	ag.st.Activated, ag.st.EdgeAttachFlag = true, true
	plan, err := b.Backfill(t.Context(), BackfillRequest{TenantID: st.t.Tenant.ID})
	if err != nil || plan.Changed || !slices.Equal(ag.calls, []string{"GetInstanceStatus"}) || len(st.begun) != 0 {
		t.Fatalf("%+v %v calls %v", plan, err, ag.calls)
	}
	st.t.DesiredPolicy = false
	plan, _ = b.Backfill(t.Context(), BackfillRequest{TenantID: st.t.Tenant.ID})
	if len(plan.Notes) != 1 || !strings.Contains(plan.Notes[0], "policy-apply --tenant tenant-a") {
		t.Fatalf("notes %v", plan.Notes)
	}
}

// TestBackfillRefusedRestoreDoesNotBlock: the staging restore drill of tenant-a before P3-T14b — an instance.restore of
// this instance refused by the agent (agent_state: not activated) waits failed_resumable holding the tenant's lifecycle
// lock; the backfill proceeds (and says to /retry it). The same job with another code, another instance, another kind
// or another status still blocks.
func TestBackfillRefusedRestoreDoesNotBlock(t *testing.T) {
	b, st, _ := bfWorld(t)
	job := uuid.New()
	st.t.LockHolder, st.t.LockHolderKind, st.t.LockHolderStatus, st.t.LockHolderCode, st.t.LockHolderInstance =
		job, "instance.restore", "failed_resumable", "agent_state", st.t.Instance.ID
	plan, err := b.Backfill(t.Context(), BackfillRequest{TenantID: st.t.Tenant.ID, DryRun: true})
	if err != nil || !plan.Changed || len(plan.Notes) != 1 || !strings.Contains(plan.Notes[0], job.String()+"/retry") {
		t.Fatalf("refused restore: %+v %v", plan, err)
	}
	for name, mod := range map[string]func(*BackfillTarget){
		"other code":     func(x *BackfillTarget) { x.LockHolderCode = "restore_check_failed" },
		"other instance": func(x *BackfillTarget) { x.LockHolderInstance = uuid.New() },
		"other kind":     func(x *BackfillTarget) { x.LockHolderKind = "instance.restart" },
		"running":        func(x *BackfillTarget) { x.LockHolderStatus = "running" },
	} {
		b, st, _ := bfWorld(t)
		st.t.LockHolder, st.t.LockHolderKind, st.t.LockHolderStatus, st.t.LockHolderCode, st.t.LockHolderInstance =
			job, "instance.restore", "failed_resumable", "agent_state", st.t.Instance.ID
		mod(&st.t)
		_, err := b.Backfill(t.Context(), BackfillRequest{TenantID: st.t.Tenant.ID, DryRun: true})
		var be *BackfillError
		if !errors.As(err, &be) || be.Code != BackfillLifecycleBusy {
			t.Errorf("%s: %v", name, err)
		}
	}
}
