package orchestrator

// Unit tests of instance.reconfigure (P3-T13) with in-memory fakes: a host model that renders a sha256 from the typed
// parameters and keeps apart the configuration on disk and the one the running container loaded (a configuration can
// pass configtest and still fail at runtime), a registry of versions, a Headscale (CheckPolicy, GetPolicy, health).
// Every failure point after the write ⇒ the previous version back on disk AND running, healthy, the new version
// failed, the registry on the previous version, audit .failed + config_rollback; a rollback that fails ⇒ Critical
// security event, the operation left open, and a later /rollback completes it.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "github.com/zhaduchanhzz/network-access-mesh/api/agent/v1"
	"github.com/zhaduchanhzz/network-access-mesh/infrastructure/headscale/templates"
	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
)

// ---------------------------------------------------------------------------------------------------- host model

// paramSHA is the fake agent's rendering: sha256 of the typed parameters (the real agent hashes config.yaml).
func paramSHA(p configParams) string {
	b, _ := json.Marshal(p)
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

type rcAgent struct {
	mu         sync.Mutex
	calls      []string
	errs       map[string][]error
	fileParams configParams // config/ on the host
	runParams  configParams // what the running container loaded at its last start
	started    time.Time
	restarts   int
	writes     int
	invalid    func(configParams) bool // configtest refuses it
	crash      func(configParams) bool // passes configtest, fails at runtime (never healthy)
	guard      bool                    // the start guard refuses every start
	fp         string
	tmpl       uint32
	detached   bool
	stopped    bool
}

func newRCAgent(p configParams) *rcAgent {
	return &rcAgent{errs: map[string][]error{}, fileParams: p, runParams: p, started: time.Unix(1_800_000_000, 0),
		fp: strings.Repeat("ab", 32), tmpl: 2, invalid: func(configParams) bool { return false },
		crash: func(configParams) bool { return false }}
}

func (a *rcAgent) enter(m string) error {
	a.mu.Lock()
	a.calls = append(a.calls, m)
	if q := a.errs[m]; len(q) > 0 {
		a.errs[m] = q[1:]
		return q[0]
	}
	return nil
}

func (a *rcAgent) fail(m string, errs ...error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.errs[m] = append(a.errs[m], errs...)
}

func (a *rcAgent) GetHostInfo(context.Context, *agentv1.GetHostInfoRequest, ...grpc.CallOption) (*agentv1.GetHostInfoResponse, error) {
	err := a.enter("GetHostInfo")
	defer a.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return &agentv1.GetHostInfoResponse{TemplateVersion: a.tmpl}, nil
}

func (a *rcAgent) ValidateConfig(_ context.Context, in *agentv1.ValidateConfigRequest, _ ...grpc.CallOption) (*agentv1.ValidateConfigResponse, error) {
	err := a.enter("ValidateConfig")
	defer a.mu.Unlock()
	if err != nil {
		return nil, err
	}
	p := paramsOf(in.GetSpec())
	if a.invalid(p) {
		return &agentv1.ValidateConfigResponse{Valid: false, ExitCode: 1, ConfigSha256: paramSHA(p), Detail: "configtest: invalid"}, nil
	}
	return &agentv1.ValidateConfigResponse{Valid: true, ConfigSha256: paramSHA(p)}, nil
}

func (a *rcAgent) EnsureInstance(_ context.Context, in *agentv1.EnsureInstanceRequest, _ ...grpc.CallOption) (*agentv1.EnsureInstanceResponse, error) {
	err := a.enter("EnsureInstance:" + in.GetTargetPhase().String())
	defer a.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if in.GetTargetPhase() != agentv1.TargetPhase_TARGET_PHASE_CONFIG {
		return nil, errors.New("unexpected phase")
	}
	p := paramsOf(in.GetSpec())
	if p.ImageDigest != a.fileParams.ImageDigest {
		return nil, refused(codes.FailedPrecondition, agentv1.RefusalReason_REFUSAL_REASON_CONFLICT, "image changes only through UpgradeInstance")
	}
	if paramSHA(p) != paramSHA(a.fileParams) {
		a.writes++
	}
	a.fileParams = p
	return &agentv1.EnsureInstanceResponse{ConfigSha256: paramSHA(p), TemplateVersion: a.tmpl, Status: a.statusLocked()}, nil
}

func (a *rcAgent) statusLocked() *agentv1.InstanceStatus {
	st := &agentv1.InstanceStatus{ContainerState: agentv1.ContainerState_CONTAINER_STATE_RUNNING,
		Health: agentv1.HealthState_HEALTH_STATE_HEALTHY, ConfigSha256: paramSHA(a.fileParams),
		StartedAt: timestamppb.New(a.started), NoiseKeyFingerprint: a.fp}
	switch {
	case a.stopped:
		st.ContainerState, st.Health = agentv1.ContainerState_CONTAINER_STATE_EXITED, agentv1.HealthState_HEALTH_STATE_NONE
	case a.crash(a.runParams):
		st.ContainerState, st.Health = agentv1.ContainerState_CONTAINER_STATE_RESTARTING, agentv1.HealthState_HEALTH_STATE_UNHEALTHY
	}
	return st
}

func (a *rcAgent) GetInstanceStatus(context.Context, *agentv1.GetInstanceStatusRequest, ...grpc.CallOption) (*agentv1.GetInstanceStatusResponse, error) {
	err := a.enter("GetInstanceStatus")
	defer a.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return &agentv1.GetInstanceStatusResponse{Status: a.statusLocked()}, nil
}

func (a *rcAgent) RestartInstance(context.Context, *agentv1.RestartInstanceRequest, ...grpc.CallOption) (*agentv1.RestartInstanceResponse, error) {
	err := a.enter("RestartInstance")
	defer a.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if a.guard {
		a.stopped = true // the agent contains the instance: stopped, edge detached, Critical event (P3-T03)
		return nil, refused(codes.FailedPrecondition, agentv1.RefusalReason_REFUSAL_REASON_STATE, "start guard: noise key fingerprint differs")
	}
	a.runParams, a.stopped = a.fileParams, false
	a.started = a.started.Add(time.Second)
	a.restarts++
	return &agentv1.RestartInstanceResponse{Status: a.statusLocked()}, nil
}

func (a *rcAgent) RemoveEdgeAttachment(context.Context, *agentv1.RemoveEdgeAttachmentRequest, ...grpc.CallOption) (*agentv1.RemoveEdgeAttachmentResponse, error) {
	err := a.enter("RemoveEdgeAttachment")
	defer a.mu.Unlock()
	if err != nil {
		return nil, err
	}
	a.detached = true
	return &agentv1.RemoveEdgeAttachmentResponse{Detached: true, WasAttached: true}, nil
}

func (a *rcAgent) snapshot() (file, run string, restarts, writes int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return paramSHA(a.fileParams), paramSHA(a.runParams), a.restarts, a.writes
}

func (a *rcAgent) callList() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.Clone(a.calls)
}

// ---------------------------------------------------------------------------------------------------- registry

type rcStore struct {
	mu       sync.Mutex
	inst     InstanceRecord
	slug     string
	tstatus  string
	versions map[uuid.UUID]*ConfigVersion
	current  uuid.UUID
	policy   *AppliedPolicy
	audit    []string // "<action> <outcome> <reason>"
	finished map[uuid.UUID]bool
	failErr  map[string][]error
}

func (m *rcStore) err(op string) error {
	if q := m.failErr[op]; len(q) > 0 {
		m.failErr[op] = q[1:]
		return q[0]
	}
	return nil
}

func (m *rcStore) ReconfigureTarget(_ context.Context, _, id uuid.UUID) (ReconfigureTarget, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.err("ReconfigureTarget"); err != nil {
		return ReconfigureTarget{}, err
	}
	if id != m.inst.ID {
		return ReconfigureTarget{}, ErrNotFound
	}
	t := ReconfigureTarget{Instance: m.inst, TenantSlug: m.slug, TenantStatus: m.tstatus}
	if v, ok := m.versions[m.current]; ok {
		cv := *v
		t.Current = &cv
	}
	return t, nil
}

func (m *rcStore) ConfigVersion(_ context.Context, _, _, id uuid.UUID) (ConfigVersion, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.versions[id]
	if !ok {
		return ConfigVersion{}, ErrNotFound
	}
	return *v, nil
}

func (m *rcStore) InsertConfigVersion(_ context.Context, _, _ uuid.UUID, nv NewConfigVersion) (ConfigVersion, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.err("InsertConfigVersion"); err != nil {
		return ConfigVersion{}, err
	}
	if v, ok := m.versions[nv.ID]; ok {
		return *v, nil
	}
	params, _ := json.Marshal(nv.Params)
	v := &ConfigVersion{ID: nv.ID, Version: int32(len(m.versions) + 1), Status: ConfigPending, //nolint:gosec // test
		TemplateVersion: fmt.Sprint(nv.TemplateVersion), ConfigSHA256: nv.ConfigSHA256, Params: params}
	m.versions[nv.ID] = v
	return *v, nil
}

func (m *rcStore) CurrentPolicy(context.Context, uuid.UUID, uuid.UUID) (AppliedPolicy, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.policy == nil {
		return AppliedPolicy{}, false, nil
	}
	return *m.policy, true, nil
}

func (m *rcStore) close(op audit.Operation, suffix, outcome, reason string) {
	if m.finished[op.ID] {
		return
	}
	m.finished[op.ID] = true
	m.audit = append(m.audit, strings.TrimSpace(op.Action+suffix+" "+outcome+" "+reason))
}

func (m *rcStore) ApplyConfig(_ context.Context, r ApplyConfigRequest) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.err("ApplyConfig"); err != nil {
		return err
	}
	switch m.current {
	case r.VersionID:
	case r.PreviousVersionID:
		m.current = r.VersionID
		m.inst.DERPRegionID = r.DERPRegionID
	default:
		return ErrState
	}
	m.versions[r.VersionID].Status = ConfigApplied
	if r.PreviousVersionID != r.VersionID && m.versions[r.PreviousVersionID].Status == ConfigApplied {
		m.versions[r.PreviousVersionID].Status = ConfigSuperseded
	}
	m.close(r.Operation, ".succeeded", "success", "")
	return nil
}

func (m *rcStore) RevertConfig(_ context.Context, _, _, version, previous uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.err("RevertConfig"); err != nil {
		return err
	}
	if m.current == version && previous != version {
		m.current = previous
		if m.versions[previous].Status == ConfigSuperseded {
			m.versions[previous].Status = ConfigApplied
		}
	}
	if v := m.versions[version]; v != nil && previous != version && (v.Status == ConfigPending || v.Status == ConfigApplied) {
		v.Status = ConfigFailed
	}
	return nil
}

func (m *rcStore) RecordUnchanged(_ context.Context, op audit.Operation, _ audit.Details) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.close(op, ".succeeded", "success", "unchanged")
	return nil
}

func (m *rcStore) RecordRollback(_ context.Context, r RollbackRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r.Failed {
		m.audit = append(m.audit, ActionConfigRollback+" failure "+r.Reason)
		return nil
	}
	if m.finished[r.Operation.ID] {
		return nil
	}
	m.close(r.Operation, ".failed", "failure", r.Reason)
	if w, _ := r.Details["config_written"].(bool); w {
		m.audit = append(m.audit, ActionConfigRollback+" success")
	}
	return nil
}

func (m *rcStore) statuses() map[uuid.UUID]string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[uuid.UUID]string{}
	for id, v := range m.versions {
		out[id] = v.Status
	}
	return out
}

// ---------------------------------------------------------------------------------------------------- Headscale

type rcHS struct {
	headscale.Instance // methods the job never calls panic
	mu                 sync.Mutex
	policy             string
	noPolicy           bool
	checkErr           error
	healthy            bool
	healthFn           func() bool // when set, decides the database connectivity reported
	healthErrs         []error
	calls              []string
	checked            []string // documents given to CheckPolicy
}

func (h *rcHS) CheckPolicy(_ context.Context, p string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.calls = append(h.calls, "CheckPolicy")
	h.checked = append(h.checked, p)
	if p == "" {
		return errors.New("empty policy checked")
	}
	return h.checkErr
}

func (h *rcHS) GetPolicy(context.Context) (headscale.Policy, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.calls = append(h.calls, "GetPolicy")
	if h.noPolicy {
		return headscale.Policy{}, &headscale.Error{Op: headscale.OpGetPolicy, Kind: headscale.KindNoPolicy, Err: headscale.ErrNoPolicy}
	}
	return headscale.Policy{Data: h.policy}, nil
}

func (h *rcHS) Health(context.Context) (headscale.Health, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.calls = append(h.calls, "Health")
	if len(h.healthErrs) > 0 {
		e := h.healthErrs[0]
		h.healthErrs = h.healthErrs[1:]
		return headscale.Health{}, e
	}
	if h.healthFn != nil {
		fn := h.healthFn
		h.mu.Unlock()
		ok := fn()
		h.mu.Lock()
		return headscale.Health{DatabaseConnectivity: ok}, nil
	}
	return headscale.Health{DatabaseConnectivity: h.healthy}, nil
}

type rcRegistry struct{ hs *rcHS }

func (r rcRegistry) ForTenant(context.Context, uuid.UUID) (headscale.Instance, error) {
	return r.hs, nil
}

// ---------------------------------------------------------------------------------------------------- rig

type rcRig struct {
	c      *InstanceReconfigurer
	r      *fakeRunner
	in     ReconfigureInput
	st     *rcStore
	agent  *rcAgent
	hs     *rcHS
	prober *fakeProber
	sec    *recSecurity
	logs   *bytes.Buffer
	base   configParams
	v1     uuid.UUID
}

func baseParams() configParams {
	return configParams{ImageDigest: "sha256:" + strings.Repeat("d", 64), RunUID: 30001, NetCIDR: "10.250.1.0/29",
		MemoryMiB: 512, CPUMillis: 1000, PIDs: 256, NodeExpiryDays: 90, Nameservers: []string{"1.1.1.1"}, DERPRegionID: 901,
		PublicEntryIPv4: "192.0.2.10", LogLevel: "LOG_LEVEL_INFO"}
}

func newRCRig(t *testing.T, change ConfigChange, mut ...func(*ReconfigureConfig, *rcRig)) *rcRig {
	t.Helper()
	g := &rcRig{base: baseParams(), v1: uuid.New(), sec: &recSecurity{}, logs: &bytes.Buffer{},
		hs: &rcHS{policy: templates.BootstrapPolicy, healthy: true}, prober: &fakeProber{edge: ProbeResult{OK: true}}}
	g.agent = newRCAgent(g.base)
	params, _ := json.Marshal(g.base)
	tenant, inst := uuid.New(), uuid.New()
	g.st = &rcStore{slug: "acme", tstatus: tenants.StatusActive, finished: map[uuid.UUID]bool{}, failErr: map[string][]error{},
		inst: InstanceRecord{ID: inst, TenantID: tenant, HostID: uuid.New(), HostName: "host-1", Status: tenants.InstanceRunning,
			ImageDigest: g.base.ImageDigest, HeadscaleVersion: "v0.29.7", ControlHostname: "acme.mesh.example.test",
			RunUID: 30001, NetCIDR: netip.MustParsePrefix("10.250.1.0/29"), DERPRegionID: 901,
			PublicEntryIPv4: netip.MustParseAddr("192.0.2.10"), NoiseFingerprint: strings.Repeat("ab", 32)},
		versions: map[uuid.UUID]*ConfigVersion{g.v1: {ID: g.v1, Version: 1, Status: ConfigApplied, TemplateVersion: "2",
			ConfigSHA256: paramSHA(g.base), Params: params}},
		current: g.v1, policy: &AppliedPolicy{HuJSON: templates.BootstrapPolicy, SHA256: BaselineSHA256}}
	actor := uuid.New()
	g.in = ReconfigureInput{TenantID: tenant, InstanceID: inst, Change: change, Source: SourcePlatform, RequestedBy: &actor,
		Operation: audit.Operation{ID: uuid.New(), Action: ActionInstanceReconfigure, ActorType: audit.ActorIdentity,
			ResourceType: "instance", ResourceID: inst.String()}}
	cfg := ReconfigureConfig{Store: g.st, Agent: g.agent, Headscale: rcRegistry{hs: g.hs}, Prober: g.prober, Security: g.sec,
		Logger: slog.New(slog.NewJSONHandler(g.logs, nil)), EdgeAddress: "10.249.0.2:443", RetryBase: time.Millisecond,
		RetryMax: 4 * time.Millisecond, HealthPoll: time.Millisecond, HealthTimeout: 40 * time.Millisecond}
	for _, m := range mut {
		m(&cfg, g)
	}
	c, err := NewReconfigurer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	g.c = c
	b, _ := json.Marshal(g.in)
	g.r = &fakeRunner{id: uuid.New(), input: b}
	return g
}

// run is one delivery as the worker makes it: the handler, then — after a permanent error — the compensation.
func (g *rcRig) run() (runErr, compErr error) {
	ctx := context.Background()
	runErr = g.c.run(ctx, g.r)
	if jobs.IsPermanent(runErr) {
		compErr = g.c.compensate(ctx, g.r, runErr)
	}
	return runErr, compErr
}

func (g *rcRig) steps() []string {
	var out []string
	for _, s := range g.r.steps {
		out = append(out, s.name+":"+s.status)
	}
	return out
}

func (g *rcRig) newVersion(t *testing.T) (uuid.UUID, *ConfigVersion) {
	t.Helper()
	g.st.mu.Lock()
	defer g.st.mu.Unlock()
	for id, v := range g.st.versions {
		if id != g.v1 {
			cv := *v
			return id, &cv
		}
	}
	return uuid.Nil, nil
}

func (g *rcRig) events(kind string) []audit.SecurityEvent {
	var out []audit.SecurityEvent
	for _, e := range g.sec.events {
		if e.Kind == kind {
			out = append(out, e)
		}
	}
	return out
}

func u32p(v uint32) *uint32 { return &v }

// ---------------------------------------------------------------------------------------------------- tests

func TestReconfigureStepTable(t *testing.T) {
	want := "config.validate,config.record,policy.check,config.write,instance.restart,instance.health,edge.verify,config.apply"
	if got := strings.Join(ReconfigureSteps, ","); got != want {
		t.Fatalf("steps %s", got)
	}
	k := jobs.DefaultKinds()[ReconfigureKind]
	if !k.Compensable || k.Lock != jobs.LockHold || k.Dedupe != "instance:{instance}:{kind}" {
		t.Fatalf("kind %+v", k)
	}
}

// TestParamsMatchProvisioning: the parameters config.validate decodes are exactly what provisioning step 8 stores
// (specParams) — same keys, same values — so a version recorded by the provisioning renders the same spec again.
func TestParamsMatchProvisioning(t *testing.T) {
	sp := uint32(3478)
	for _, spec := range []*agentv1.InstanceSpec{
		mustSpec(t, baseParams()),
		{Instance: &agentv1.InstanceRef{InstanceId: uuid.NewString(), TenantId: uuid.NewString(), Slug: "x"},
			ImageDigest: "sha256:" + strings.Repeat("e", 64), RunUid: 30002, NetCidr: "10.250.1.8/29",
			Limits: &agentv1.ResourceLimits{MemoryMib: 64, CpuMillis: 100, Pids: 32},
			Headscale: &agentv1.HeadscaleParams{NodeExpiryDays: 1, Nameservers: []string{"9.9.9.9", "2001:db8::53"},
				DerpRegionId: 999, PublicEntryIpv4: "192.0.2.11", LogLevel: agentv1.LogLevel_LOG_LEVEL_ERROR, StunPort: &sp}},
	} {
		a, _ := json.Marshal(specParams(spec))
		b, _ := json.Marshal(paramsOf(spec))
		var ma, mb map[string]any
		_ = json.Unmarshal(a, &ma)
		_ = json.Unmarshal(b, &mb)
		if fmt.Sprint(ma) != fmt.Sprint(mb) {
			t.Fatalf("specParams %s\nparamsOf   %s", a, b)
		}
		p, err := decodeParams(a)
		if err != nil {
			t.Fatal(err)
		}
		back, err := p.spec(spec.GetInstance())
		if err != nil || paramSHA(paramsOf(back)) != paramSHA(paramsOf(spec)) {
			t.Fatalf("round trip %v %v", back, err)
		}
	}
}

func mustSpec(t *testing.T, p configParams) *agentv1.InstanceSpec {
	t.Helper()
	s, err := p.spec(&agentv1.InstanceRef{InstanceId: uuid.NewString(), TenantId: uuid.NewString(), Slug: "acme"})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestConfigChangeNormalize(t *testing.T) {
	ok := []ConfigChange{
		{},
		{LogLevel: "warn"}, {LogLevel: "error"}, {LogLevel: "info"},
		{NodeExpiryDays: u32p(1)}, {NodeExpiryDays: u32p(3650)},
		{DERPRegionID: u32p(900)}, {DERPRegionID: u32p(999)},
		{Nameservers: []string{"9.9.9.9", "2001:db8::53", "10.0.0.53"}},
	}
	for _, c := range ok {
		if err := c.Normalize(); err != nil {
			t.Errorf("%+v: %v", c, err)
		}
	}
	bad := map[string]ConfigChange{
		"log_level":        {LogLevel: "debug"},
		"node_expiry_days": {NodeExpiryDays: u32p(0)},
		"derp_region_id":   {DERPRegionID: u32p(1000)},
	}
	for field, c := range bad {
		var ce *CreateError
		if err := c.Normalize(); !errors.As(err, &ce) || ce.Field != field || !errors.Is(err, ErrInvalid) {
			t.Errorf("%+v: %v", c, err)
		}
	}
	for _, ns := range [][]string{{}, {"1.1.1.1", "1.1.1.1"}, {"127.0.0.1"}, {"0.0.0.0"}, {"fe80::1"}, {"224.0.0.1"},
		{"::ffff:1.1.1.1"}, {"not-an-ip"}, {"1.1.1.1%eth0"}, {"1", "2", "3", "4", "5", "6", "7", "8", "9"}} {
		c := ConfigChange{Nameservers: ns}
		if err := c.Normalize(); !errors.Is(err, ErrInvalid) {
			t.Errorf("nameservers %v: %v", ns, err)
		}
	}
	c := ConfigChange{Nameservers: []string{"2001:DB8:0:0::53"}}
	if err := c.Normalize(); err != nil || c.Nameservers[0] != "2001:db8::53" {
		t.Fatalf("canonical form: %v %v", c.Nameservers, err)
	}
	if !(ConfigChange{LogLevel: "warn", NodeExpiryDays: u32p(3)}).Equal(ConfigChange{LogLevel: "warn", NodeExpiryDays: u32p(3)}) ||
		(ConfigChange{NodeExpiryDays: u32p(3)}).Equal(ConfigChange{NodeExpiryDays: u32p(4)}) ||
		(ConfigChange{}).Equal(ConfigChange{Nameservers: []string{"1.1.1.1"}}) {
		t.Fatal("Equal")
	}
}

func TestReconfigureHappyPath(t *testing.T) {
	g := newRCRig(t, ConfigChange{LogLevel: "warn", NodeExpiryDays: u32p(30), Nameservers: []string{"9.9.9.9"}, DERPRegionID: u32p(950)})
	oldSHA := paramSHA(g.base)
	if runErr, _ := g.run(); runErr != nil {
		t.Fatalf("run: %v\n%s", runErr, g.logs)
	}
	for _, s := range g.r.steps {
		if s.status != jobs.StepSucceeded || s.attempt != 1 {
			t.Errorf("step %s %s attempt %d", s.name, s.status, s.attempt)
		}
	}
	var names []string
	for _, s := range g.r.steps {
		names = append(names, s.name)
	}
	if strings.Join(names, ",") != strings.Join(ReconfigureSteps, ",") {
		t.Fatalf("steps %v", names)
	}
	// Agent: host info + configtest, write, the status before the restart, the restart, then the health gate.
	want := []string{"GetHostInfo", "ValidateConfig", "EnsureInstance:TARGET_PHASE_CONFIG", "GetInstanceStatus", "RestartInstance", "GetInstanceStatus"}
	if got := g.agent.callList(); !slices.Equal(got, want) {
		t.Fatalf("agent calls %v, want %v", got, want)
	}
	if got := strings.Join(g.hs.calls, ","); got != "CheckPolicy,Health,GetPolicy" {
		t.Fatalf("headscale calls %s", got)
	}
	// CheckPolicy gets plain JSON (the adapter refuses HuJSON comments — V-06), the applied baseline without them.
	if len(g.hs.checked) != 1 || strings.Contains(g.hs.checked[0], "//") || !json.Valid([]byte(g.hs.checked[0])) ||
		!strings.Contains(templates.BootstrapPolicy, "//") {
		t.Fatalf("checked %q", g.hs.checked)
	}
	file, run, restarts, writes := g.agent.snapshot()
	np := g.base
	np.LogLevel, np.NodeExpiryDays, np.Nameservers, np.DERPRegionID = "LOG_LEVEL_WARN", 30, []string{"9.9.9.9"}, 950
	if file != paramSHA(np) || run != file || restarts != 1 || writes != 1 || file == oldSHA {
		t.Fatalf("host: file %s run %s restarts %d writes %d", file, run, restarts, writes)
	}
	id, v := g.newVersion(t)
	if v == nil || v.Status != ConfigApplied || v.ConfigSHA256 != file || g.st.current != id || g.st.versions[g.v1].Status != ConfigSuperseded ||
		g.st.inst.DERPRegionID != 950 || v.TemplateVersion != "2" {
		t.Fatalf("registry: current %s new %+v v1 %s derp %d", g.st.current, v, g.st.versions[g.v1].Status, g.st.inst.DERPRegionID)
	}
	if strings.Join(g.st.audit, "|") != "platform.instance.reconfigure.succeeded success" {
		t.Fatalf("audit %v", g.st.audit)
	}
	if g.prober.calls[0] != "edge acme.mesh.example.test mkey:"+strings.Repeat("ab", 32) {
		t.Fatalf("prober %v", g.prober.calls)
	}
	out, _ := json.Marshal(g.r.output)
	if !strings.Contains(string(out), `"changed":true`) || !strings.Contains(string(out), file) {
		t.Fatalf("output %s", out)
	}
	if len(g.sec.events) != 0 {
		t.Fatalf("security events %+v", g.sec.events)
	}
	// The step detail names what changed (public values only).
	if d := string(g.r.step(RStepValidate).detail); !strings.Contains(d, `"param":"log_level"`) || !strings.Contains(d, `"param":"nameservers"`) {
		t.Fatalf("validate detail %s", d)
	}
}

// TestReconfigureUnchanged: the empty change renders the version in force — nothing written, nothing restarted, the
// operation closed .succeeded.
func TestReconfigureUnchanged(t *testing.T) {
	g := newRCRig(t, ConfigChange{})
	if runErr, _ := g.run(); runErr != nil {
		t.Fatal(runErr)
	}
	if got := g.agent.callList(); !slices.Equal(got, []string{"GetHostInfo", "ValidateConfig"}) {
		t.Fatalf("agent calls %v", got)
	}
	if got := strings.Join(g.steps(), ","); got != "config.validate:succeeded,config.apply:succeeded" {
		t.Fatalf("steps %s", got)
	}
	if len(g.st.versions) != 1 || g.st.current != g.v1 || strings.Join(g.st.audit, "|") != "platform.instance.reconfigure.succeeded success unchanged" {
		t.Fatalf("registry %v audit %v", g.st.versions, g.st.audit)
	}
	out, _ := json.Marshal(g.r.output)
	if !strings.Contains(string(out), `"changed":false`) {
		t.Fatalf("output %s", out)
	}
}

// TestReconfigureRollbackAtEveryFailurePoint: a permanent failure at each step ⇒ the job's compensation leaves the
// previous version on disk and running (healthy), the new version failed, the registry on the previous one.
func TestReconfigureRollbackAtEveryFailurePoint(t *testing.T) {
	refusal := refused(codes.InvalidArgument, agentv1.RefusalReason_REFUSAL_REASON_OUT_OF_BOUNDS, "refused")
	cases := []struct {
		name     string
		setup    func(g *rcRig)
		code     string
		written  bool // config.write acted: the rollback writes the previous version back (audit config_rollback)
		recorded bool // a version row was written
		writes   int  // files changed on the host (the new version, then the previous one written back)
		restarts int  // restarts (on the new version, then on the previous one)
		security string
	}{
		{name: "configtest refuses", setup: func(g *rcRig) { g.agent.invalid = func(configParams) bool { return true } }, code: "config_invalid"},
		{name: "agent refuses the spec", setup: func(g *rcRig) { g.agent.fail("ValidateConfig", refusal) }, code: "agent_out_of_bounds"},
		{name: "version not recordable", setup: func(g *rcRig) { g.st.failErr["InsertConfigVersion"] = []error{ErrState} }, code: "registry_state"},
		{name: "policy check rejected", setup: func(g *rcRig) {
			g.hs.checkErr = &headscale.Error{Op: headscale.OpCheckPolicy, Kind: headscale.KindPolicyRejected, Err: headscale.ErrPolicyRejected}
		}, code: "policy_check_failed", recorded: true, security: SecPolicyCheckFailed},
		{name: "write refused", setup: func(g *rcRig) { g.agent.fail("EnsureInstance:TARGET_PHASE_CONFIG", refusal) },
			code: "agent_out_of_bounds", recorded: true, written: true},
		{name: "restart refused", setup: func(g *rcRig) { g.agent.fail("RestartInstance", refusal) },
			code: "agent_out_of_bounds", recorded: true, written: true, writes: 2, restarts: 1},
		{name: "runtime failure: never healthy", setup: func(g *rcRig) {
			g.agent.crash = func(p configParams) bool { return p.LogLevel == "LOG_LEVEL_WARN" }
		}, code: "instance_unhealthy", recorded: true, written: true, writes: 2, restarts: 2},
		{name: "API health: no database with the new version", setup: func(g *rcRig) {
			g.hs.healthFn = func() bool { _, run, _, _ := g.agent.snapshot(); return run == paramSHA(g.base) }
		}, code: "instance_unhealthy", recorded: true, written: true, writes: 2, restarts: 2},
		{name: "Noise key changed", setup: func(g *rcRig) { g.agent.fp = strings.Repeat("cd", 32) }, code: "noise_key_changed",
			recorded: true, written: true, writes: 2, restarts: 2, security: SecNoiseKeyChanged},
		{name: "no policy after restart", setup: func(g *rcRig) { g.hs.noPolicy = true }, code: "no_policy",
			recorded: true, written: true, writes: 2, restarts: 2, security: SecPolicyMissing},
		{name: "edge exposes paths", setup: func(g *rcRig) { g.prober.edge = ProbeResult{Exposed: []string{"/api/v1/node"}} },
			code: "edge_exposes_paths", recorded: true, written: true, writes: 2, restarts: 2},
		{name: "edge key mismatch", setup: func(g *rcRig) { g.prober.edge = ProbeResult{KeyMismatch: true} },
			code: "edge_key_mismatch", recorded: true, written: true, writes: 2, restarts: 2},
		{name: "apply refused by the registry", setup: func(g *rcRig) { g.st.failErr["ApplyConfig"] = []error{ErrState} },
			code: "registry_state", recorded: true, written: true, writes: 2, restarts: 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := newRCRig(t, ConfigChange{LogLevel: "warn"})
			tc.setup(g)
			oldSHA := paramSHA(g.base)
			runErr, compErr := g.run()
			if !jobs.IsPermanent(runErr) || jobs.CodeOf(runErr) != tc.code {
				t.Fatalf("run: %v (code %s), want %s\n%s", runErr, jobs.CodeOf(runErr), tc.code, g.logs)
			}
			if compErr != nil {
				t.Fatalf("compensation: %v\n%s", compErr, g.logs)
			}
			file, run, restarts, writes := g.agent.snapshot()
			if file != oldSHA || run != oldSHA {
				t.Fatalf("host after rollback: file %s run %s, want %s", file, run, oldSHA)
			}
			if restarts != tc.restarts || writes != tc.writes {
				t.Fatalf("restarts %d writes %d, want %d %d (calls %v)", restarts, writes, tc.restarts, tc.writes, g.agent.callList())
			}
			if g.st.current != g.v1 || g.st.versions[g.v1].Status != ConfigApplied {
				t.Fatalf("registry: current %s v1 %s", g.st.current, g.st.versions[g.v1].Status)
			}
			id, v := g.newVersion(t)
			switch {
			case tc.recorded && (v == nil || v.Status != ConfigFailed):
				t.Fatalf("new version %s %+v", id, v)
			case !tc.recorded && v != nil:
				t.Fatalf("a version was recorded: %+v", v)
			}
			wantAudit := "platform.instance.reconfigure.failed failure " + tc.code
			if tc.written {
				wantAudit += "|" + ActionConfigRollback + " success"
			}
			if got := strings.Join(g.st.audit, "|"); got != wantAudit {
				t.Fatalf("audit %s, want %s", got, wantAudit)
			}
			if tc.security != "" && len(g.events(tc.security)) != 1 {
				t.Fatalf("security events %+v", g.sec.events)
			}
			if len(g.events(SecRollbackFailed)) != 0 {
				t.Fatal("a successful rollback raised rollback_failed")
			}
			if tc.code == "no_policy" && !g.agent.detached {
				t.Fatal("no policy after the restart: the edge was not detached")
			}
			// every step that acted was compensated (or skipped), none left without a status
			for _, s := range g.r.steps {
				if s.comp != jobs.StepSucceeded && s.comp != jobs.StepSkipped {
					t.Errorf("step %s compensation %q", s.name, s.comp)
				}
			}
			// a second compensation (a repeated /rollback) changes nothing
			before := strings.Join(g.agent.callList(), ",")
			if err := g.c.compensate(context.Background(), g.r, runErr); err != nil {
				t.Fatal(err)
			}
			if after := strings.Join(g.agent.callList(), ","); after != before || len(g.st.audit) != len(strings.Split(wantAudit, "|")) {
				t.Fatalf("second compensation acted: %s / %v", strings.TrimPrefix(after, before), g.st.audit)
			}
		})
	}
}

// TestReconfigureRollbackFailure: the start guard refuses the restart and then the rollback's restart too ⇒ the
// compensation fails (failed_resumable at the job level) with a Critical security event, the operation stays open;
// once the operator fixed the host, /rollback (the compensation again) completes it.
func TestReconfigureRollbackFailure(t *testing.T) {
	g := newRCRig(t, ConfigChange{LogLevel: "warn"})
	g.agent.guard = true
	runErr, compErr := g.run()
	if jobs.CodeOf(runErr) != "agent_state" || compErr == nil {
		t.Fatalf("run %v, compensation %v", runErr, compErr)
	}
	if len(g.events("instance.start_guard_failed")) == 0 || len(g.events(SecRollbackFailed)) != 1 ||
		g.events(SecRollbackFailed)[0].Severity != audit.SeverityCritical {
		t.Fatalf("security events %+v", g.sec.events)
	}
	if got := strings.Join(g.st.audit, "|"); got != ActionConfigRollback+" failure agent_state" {
		t.Fatalf("audit %s", got)
	}
	if g.r.step(RStepRestart).comp != jobs.StepFailed {
		t.Fatalf("restart compensation %q", g.r.step(RStepRestart).comp)
	}
	// The files are back already (written before the refused restart); the operator restores the key, /rollback.
	g.agent.mu.Lock()
	g.agent.guard = false
	g.agent.mu.Unlock()
	if err := g.c.compensate(context.Background(), g.r, runErr); err != nil {
		t.Fatalf("second /rollback: %v", err)
	}
	file, run, _, _ := g.agent.snapshot()
	if file != paramSHA(g.base) || run != paramSHA(g.base) || g.st.current != g.v1 {
		t.Fatalf("host %s %s registry %s", file, run, g.st.current)
	}
	if got := strings.Join(g.st.audit, "|"); got != ActionConfigRollback+" failure agent_state|platform.instance.reconfigure.failed failure agent_state|"+ActionConfigRollback+" success" {
		t.Fatalf("audit %s", got)
	}
}

// TestReconfigureTransientResumable: the agent unavailable at the restart beyond the retries ⇒ Resumable (no
// compensation, the job keeps the lock); a second run (/retry) resumes at the restart.
func TestReconfigureTransientResumable(t *testing.T) {
	g := newRCRig(t, ConfigChange{LogLevel: "warn"})
	unavailable := status.Error(codes.Unavailable, "agent down")
	for range DefaultStepRetries + 1 {
		g.agent.fail("RestartInstance", unavailable)
	}
	runErr, compErr := g.run()
	if !jobs.IsResumable(runErr) || jobs.CodeOf(runErr) != "agent_unavailable" || compErr != nil {
		t.Fatalf("run %v compensation %v", runErr, compErr)
	}
	if g.r.step(RStepRestart).attempt != DefaultStepRetries+1 || g.r.step(RStepHealth) != nil {
		t.Fatalf("steps %v", g.steps())
	}
	if runErr, _ := g.run(); runErr != nil {
		t.Fatal(runErr)
	}
	if g.r.step(RStepWrite).attempt != 1 || g.r.step(RStepRestart).attempt != DefaultStepRetries+2 {
		t.Fatalf("steps %v", g.steps())
	}
	_, v := g.newVersion(t)
	if v.Status != ConfigApplied {
		t.Fatal(v.Status)
	}
}

// TestReconfigureIdempotentReexecution: every step run again after it succeeded (a worker that died before recording
// it) leaves the registry and the audit unchanged and the host on the new version.
func TestReconfigureIdempotentReexecution(t *testing.T) {
	for _, name := range ReconfigureSteps {
		t.Run(name, func(t *testing.T) {
			g := newRCRig(t, ConfigChange{LogLevel: "warn"})
			if runErr, _ := g.run(); runErr != nil {
				t.Fatal(runErr)
			}
			id, _ := g.newVersion(t)
			snap := fmt.Sprint(g.st.statuses(), g.st.current, g.st.audit)
			g.r.reset(name)
			if runErr, _ := g.run(); runErr != nil {
				t.Fatalf("re-run: %v", runErr)
			}
			if got := fmt.Sprint(g.st.statuses(), g.st.current, g.st.audit); got != snap || len(g.st.versions) != 2 || g.st.current != id {
				t.Fatalf("registry changed:\n%s\n%s", snap, got)
			}
			file, run, _, _ := g.agent.snapshot()
			if file != run || file == paramSHA(g.base) {
				t.Fatal("host not on the new version")
			}
		})
	}
}

// TestReconfigureQuarantine: a quarantined instance is never touched; quarantined during the job ⇒ never restarted —
// the rollback restores its files only.
func TestReconfigureQuarantine(t *testing.T) {
	g := newRCRig(t, ConfigChange{LogLevel: "warn"})
	g.st.inst.Status = tenants.InstanceQuarantined
	runErr, compErr := g.run()
	if jobs.CodeOf(runErr) != "instance_quarantined" || compErr != nil || len(g.agent.callList()) != 0 {
		t.Fatalf("run %v comp %v calls %v", runErr, compErr, g.agent.callList())
	}

	g = newRCRig(t, ConfigChange{LogLevel: "warn"})
	// quarantined right after the write (before the restart): EnsureInstance(config) succeeds, then the status flips
	g.c.cfg.Agent = &quarantineAfterWrite{rcAgent: g.agent, st: g.st}
	runErr, compErr = g.run()
	if jobs.CodeOf(runErr) != "instance_quarantined" || compErr != nil {
		t.Fatalf("run %v comp %v", runErr, compErr)
	}
	file, _, restarts, _ := g.agent.snapshot()
	if restarts != 0 || file != paramSHA(g.base) {
		t.Fatalf("quarantined instance: restarts %d, file %s", restarts, file)
	}
}

type quarantineAfterWrite struct {
	*rcAgent
	st *rcStore
}

func (q *quarantineAfterWrite) EnsureInstance(ctx context.Context, in *agentv1.EnsureInstanceRequest, o ...grpc.CallOption) (*agentv1.EnsureInstanceResponse, error) {
	r, err := q.rcAgent.EnsureInstance(ctx, in, o...)
	q.st.mu.Lock()
	q.st.inst.Status = tenants.InstanceQuarantined
	q.st.mu.Unlock()
	return r, err
}

// TestReconfigurePolicyGate: no recorded application ⇒ neither checked nor gated; a policy read back that differs ⇒ a
// High security event, the reconfiguration still succeeds (the repair is policy.apply's).
func TestReconfigurePolicyGate(t *testing.T) {
	g := newRCRig(t, ConfigChange{LogLevel: "warn"})
	g.st.policy = nil
	if runErr, _ := g.run(); runErr != nil {
		t.Fatal(runErr)
	}
	if len(g.hs.calls) != 1 || g.hs.calls[0] != "Health" {
		t.Fatalf("headscale calls %v", g.hs.calls)
	}
	if d := string(g.r.step(RStepPolicy).detail); !strings.Contains(d, "no_applied_policy") {
		t.Fatal(d)
	}
	g = newRCRig(t, ConfigChange{LogLevel: "warn"})
	g.hs.policy = `{"acls":[]}`
	if runErr, _ := g.run(); runErr != nil {
		t.Fatal(runErr)
	}
	if ev := g.events(SecPolicyDrift); len(ev) != 1 || ev[0].Severity != audit.SeverityHigh {
		t.Fatalf("security events %+v", g.sec.events)
	}
	if d := string(g.r.step(RStepHealth).detail); !strings.Contains(d, `"post_start_gate":"drift"`) {
		t.Fatal(d)
	}
}

// TestReconfigureNoProber: without a prober the short edge.verify is recorded skipped.
func TestReconfigureNoProber(t *testing.T) {
	g := newRCRig(t, ConfigChange{LogLevel: "warn"}, func(c *ReconfigureConfig, _ *rcRig) { c.Prober = nil })
	if runErr, _ := g.run(); runErr != nil {
		t.Fatal(runErr)
	}
	if d := string(g.r.step(RStepEdge).detail); !strings.Contains(d, "prober_not_configured") {
		t.Fatal(d)
	}
}

// TestReconfigureRegistryRefusals: no configuration version, a tenant neither active nor suspended, an instance that is
// not running — refused before anything is touched; an unreadable input never runs.
func TestReconfigureRegistryRefusals(t *testing.T) {
	for code, mut := range map[string]func(g *rcRig){
		"no_config_version":    func(g *rcRig) { g.st.current = uuid.Nil },
		"tenant_state":         func(g *rcRig) { g.st.tstatus = tenants.StatusDeprovisioning },
		"instance_not_running": func(g *rcRig) { g.st.inst.Status = tenants.InstanceStopped },
	} {
		g := newRCRig(t, ConfigChange{LogLevel: "warn"})
		mut(g)
		runErr, compErr := g.run()
		if jobs.CodeOf(runErr) != code || compErr != nil || len(g.agent.callList()) != 0 {
			t.Errorf("%s: run %v comp %v calls %v", code, runErr, compErr, g.agent.callList())
		}
	}
	g := newRCRig(t, ConfigChange{})
	g.r.input = []byte(`{"tenant_id":"x"}`)
	if err := g.c.run(context.Background(), g.r); jobs.CodeOf(err) != "invalid_input" {
		t.Fatal(err)
	}
	if _, err := NewReconfigurer(ReconfigureConfig{}); err == nil {
		t.Fatal("empty configuration accepted")
	}
}
