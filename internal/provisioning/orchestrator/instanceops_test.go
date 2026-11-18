package orchestrator

// Unit tests of instance.restart and instance.upgrade (P3-T13a) with in-memory fakes: a host model (image in meta and
// of the container, running or not, the data the instance holds — "orig", or "migrated:<image>" once a target binary
// started on it), the backup subsystem (cold backup of the data, rollback by restore), a Headscale (policy, health, API
// key, version of the running image, the reads of the contract smoke) and the policy core. Every failure point: before
// the switch ⇒ the previous image runs on the untouched data; after it ⇒ rollback by restore; the audit, the security
// events and the notification of the platform staff.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
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
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "github.com/zhaduchanhzz/network-access-mesh/api/agent/v1"
	"github.com/zhaduchanhzz/network-access-mesh/infrastructure/headscale/templates"
	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/policies"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/backup"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/backupfmt"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
)

var (
	imgOld = "sha256:" + strings.Repeat("d", 64)
	imgNew = "sha256:" + strings.Repeat("e", 64)
)

// ---------------------------------------------------------------------------------------------------- host model

type opsHost struct {
	mu        sync.Mutex
	calls     []string
	errs      map[string][]error
	meta      string // image in meta/instance.json
	ctrImage  string // image of the container
	running   bool
	healthyOn map[string]bool // image → becomes healthy when running (default true)
	started   time.Time
	data      string // what data/ holds
	cfgSHA    string // config sha256 on disk
	renderSHA string // what the agent renders for the configuration in force (drift when it differs)
	fp        string
	versions  map[string]string // image → version its binary reports
	allowed   []string
	guard     bool // the start guard refuses every start
	cfgValid  bool
	preflight func() (*agentv1.PreflightUpgradeResponse, error)
	detached  bool
}

func newOpsHost() *opsHost {
	return &opsHost{errs: map[string][]error{}, meta: imgOld, ctrImage: imgOld, running: true, healthyOn: map[string]bool{},
		started: time.Unix(1_800_000_000, 0), data: "orig", cfgSHA: strings.Repeat("c", 64), renderSHA: strings.Repeat("c", 64),
		fp: strings.Repeat("ab", 32), versions: map[string]string{imgOld: "v0.29.7", imgNew: "v0.29.7"},
		allowed: []string{imgOld, imgNew}, cfgValid: true}
}

func (h *opsHost) enter(m string) error {
	h.mu.Lock()
	h.calls = append(h.calls, m)
	if q := h.errs[m]; len(q) > 0 {
		h.errs[m] = q[1:]
		return q[0]
	}
	return nil
}

func (h *opsHost) fail(m string, errs ...error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.errs[m] = append(h.errs[m], errs...)
}

func (h *opsHost) statusLocked() *agentv1.InstanceStatus {
	st := &agentv1.InstanceStatus{ContainerState: agentv1.ContainerState_CONTAINER_STATE_EXITED, Health: agentv1.HealthState_HEALTH_STATE_NONE,
		ConfigSha256: h.cfgSHA, ImageDigest: h.ctrImage, StartedAt: timestamppb.New(h.started), NoiseKeyFingerprint: h.fp}
	if h.running {
		st.ContainerState, st.Health = agentv1.ContainerState_CONTAINER_STATE_RUNNING, agentv1.HealthState_HEALTH_STATE_HEALTHY
		if ok, set := h.healthyOn[h.ctrImage]; set && !ok {
			st.ContainerState, st.Health = agentv1.ContainerState_CONTAINER_STATE_RESTARTING, agentv1.HealthState_HEALTH_STATE_UNHEALTHY
		}
	}
	return st
}

func (h *opsHost) start() error {
	if h.guard {
		h.running = false
		return refused(codes.FailedPrecondition, agentv1.RefusalReason_REFUSAL_REASON_STATE, "start guard: data/db.sqlite is missing")
	}
	h.running, h.started = true, h.started.Add(time.Second)
	if h.ctrImage != imgOld && !strings.HasPrefix(h.data, "migrated") {
		h.data = "migrated:" + h.ctrImage // the target binary opened (and migrated) the live data
	}
	return nil
}

func (h *opsHost) GetHostInfo(context.Context, *agentv1.GetHostInfoRequest, ...grpc.CallOption) (*agentv1.GetHostInfoResponse, error) {
	err := h.enter("GetHostInfo")
	defer h.mu.Unlock()
	if err != nil {
		return nil, err
	}
	out := &agentv1.GetHostInfoResponse{TemplateVersion: 2}
	for _, d := range h.allowed {
		out.AllowedImages = append(out.AllowedImages, &agentv1.AllowedImage{Repository: "r", Digest: d})
	}
	return out, nil
}

func (h *opsHost) ValidateConfig(_ context.Context, in *agentv1.ValidateConfigRequest, _ ...grpc.CallOption) (*agentv1.ValidateConfigResponse, error) {
	err := h.enter("ValidateConfig:" + in.GetSpec().GetImageDigest()[7:9])
	defer h.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if !h.cfgValid {
		return &agentv1.ValidateConfigResponse{Valid: false, ExitCode: 1, ConfigSha256: h.renderSHA, Detail: "configtest: invalid"}, nil
	}
	return &agentv1.ValidateConfigResponse{Valid: true, ConfigSha256: h.renderSHA}, nil
}

func (h *opsHost) GetInstanceStatus(context.Context, *agentv1.GetInstanceStatusRequest, ...grpc.CallOption) (*agentv1.GetInstanceStatusResponse, error) {
	err := h.enter("GetInstanceStatus")
	defer h.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return &agentv1.GetInstanceStatusResponse{Status: h.statusLocked()}, nil
}

func (h *opsHost) StartInstance(context.Context, *agentv1.StartInstanceRequest, ...grpc.CallOption) (*agentv1.StartInstanceResponse, error) {
	err := h.enter("StartInstance")
	defer h.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if err := h.start(); err != nil {
		return nil, err
	}
	return &agentv1.StartInstanceResponse{Status: h.statusLocked()}, nil
}

func (h *opsHost) StopInstance(context.Context, *agentv1.StopInstanceRequest, ...grpc.CallOption) (*agentv1.StopInstanceResponse, error) {
	err := h.enter("StopInstance")
	defer h.mu.Unlock()
	if err != nil {
		return nil, err
	}
	h.running = false
	return &agentv1.StopInstanceResponse{Status: h.statusLocked()}, nil
}

func (h *opsHost) RestartInstance(context.Context, *agentv1.RestartInstanceRequest, ...grpc.CallOption) (*agentv1.RestartInstanceResponse, error) {
	err := h.enter("RestartInstance")
	defer h.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if err := h.start(); err != nil {
		return nil, err
	}
	return &agentv1.RestartInstanceResponse{Status: h.statusLocked()}, nil
}

func (h *opsHost) UpgradeInstance(_ context.Context, in *agentv1.UpgradeInstanceRequest, _ ...grpc.CallOption) (*agentv1.UpgradeInstanceResponse, error) {
	err := h.enter("UpgradeInstance:" + in.GetToImageDigest()[7:9])
	defer h.mu.Unlock()
	if err != nil {
		return nil, err
	}
	switch {
	case h.running:
		return nil, refused(codes.FailedPrecondition, agentv1.RefusalReason_REFUSAL_REASON_STATE, "the instance must be stopped first")
	case in.GetSpec().GetImageDigest() != in.GetToImageDigest():
		return nil, errors.New("spec of another image")
	case h.meta != in.GetFromImageDigest() && h.meta != in.GetToImageDigest():
		return nil, refused(codes.FailedPrecondition, agentv1.RefusalReason_REFUSAL_REASON_CONFLICT, "compare-and-swap")
	}
	h.meta, h.ctrImage = in.GetToImageDigest(), in.GetToImageDigest()
	st := h.statusLocked()
	st.ContainerState = agentv1.ContainerState_CONTAINER_STATE_CREATED
	return &agentv1.UpgradeInstanceResponse{Status: st}, nil
}

func (h *opsHost) InspectImage(_ context.Context, in *agentv1.InspectImageRequest, _ ...grpc.CallOption) (*agentv1.InspectImageResponse, error) {
	err := h.enter("InspectImage:" + in.GetImageDigest()[7:9])
	defer h.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return &agentv1.InspectImageResponse{ImageDigest: in.GetImageDigest(), HeadscaleVersion: h.versions[in.GetImageDigest()]}, nil
}

func (h *opsHost) PreflightUpgrade(_ context.Context, in *agentv1.PreflightUpgradeRequest, _ ...grpc.CallOption) (*agentv1.PreflightUpgradeResponse, error) {
	err := h.enter("PreflightUpgrade")
	defer h.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if h.running || len(in.GetDataKey()) != 32 || in.GetArtifact().GetSequence() == 0 {
		return nil, errors.New("preflight on a running instance or without its backup")
	}
	if h.preflight != nil {
		return h.preflight()
	}
	return &agentv1.PreflightUpgradeResponse{Valid: true, ConfigSha256: h.cfgSHA, BackupHeadscaleVersion: "0.29.7",
		TargetHeadscaleVersion: h.versions[in.GetSpec().GetImageDigest()]}, nil
}

func (h *opsHost) RemoveEdgeAttachment(context.Context, *agentv1.RemoveEdgeAttachmentRequest, ...grpc.CallOption) (*agentv1.RemoveEdgeAttachmentResponse, error) {
	err := h.enter("RemoveEdgeAttachment")
	defer h.mu.Unlock()
	if err != nil {
		return nil, err
	}
	h.detached = true
	return &agentv1.RemoveEdgeAttachmentResponse{Detached: true, WasAttached: true}, nil
}

func (h *opsHost) list() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.Clone(h.calls)
}

func (h *opsHost) state() (meta, ctr, data string, running bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.meta, h.ctrImage, h.data, h.running
}

// ---------------------------------------------------------------------------------------------------- backups

type opsBackups struct {
	h        *opsHost
	mu       sync.Mutex
	taken    map[uuid.UUID]string // backup → the data it holds
	calls    []string
	errs     map[string][]error
	restored int
}

func (b *opsBackups) err(m string) error {
	b.calls = append(b.calls, m)
	if q := b.errs[m]; len(q) > 0 {
		b.errs[m] = q[1:]
		return q[0]
	}
	return nil
}

func (b *opsBackups) Ready() error { return nil }

func (b *opsBackups) ColdBackup(_ context.Context, _, _, _ uuid.UUID) (backup.BackupResult, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.err("ColdBackup"); err != nil {
		return backup.BackupResult{}, err
	}
	b.h.mu.Lock()
	running, data := b.h.running, b.h.data
	b.h.mu.Unlock()
	if running {
		return backup.BackupResult{}, jobs.Permanent("backup_not_cold", errors.New("running"))
	}
	id := uuid.New()
	b.taken[id] = data
	return backup.BackupResult{BackupID: id, Sequence: uint64(len(b.taken)), Method: backupfmt.MethodColdCopy, //nolint:gosec // test
		ArchiveSHA256: strings.Repeat("1", 64), ManifestSHA256: strings.Repeat("2", 64)}, nil
}

func (b *opsBackups) OpenBackup(_ context.Context, _, _, _, id uuid.UUID) (backup.OpenedBackup, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.err("OpenBackup"); err != nil {
		return backup.OpenedBackup{}, err
	}
	if _, ok := b.taken[id]; !ok {
		return backup.OpenedBackup{}, jobs.Permanent("backup_not_found", errors.New("no such backup"))
	}
	return backup.OpenedBackup{Artifact: &agentv1.ArtifactRef{Sequence: 1, ArchiveSha256: strings.Repeat("1", 64),
		ManifestSha256: strings.Repeat("2", 64)}, DataKey: make([]byte, 32), HeadscaleVersion: "0.29.7", Image: imgOld}, nil
}

func (b *opsBackups) RollbackRestore(_ context.Context, _, _, _, id uuid.UUID) (map[string]any, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.err("RollbackRestore"); err != nil {
		return nil, err
	}
	b.h.mu.Lock()
	defer b.h.mu.Unlock()
	if b.h.running || b.h.meta != imgOld {
		return nil, errors.New("restore: the instance must be stopped on the previous image")
	}
	b.h.data = b.taken[id]
	b.h.detached = false
	if err := b.h.start(); err != nil {
		return nil, err
	}
	b.restored++
	return map[string]any{"restored": true}, nil
}

// ---------------------------------------------------------------------------------------------------- Headscale

type opsHS struct {
	headscale.Instance // methods the jobs never call panic
	h                  *opsHost
	mu                 sync.Mutex
	policy             string
	noPolicy           bool
	keyRejected        bool // the instance does not know the platform's API key (its database was replaced)
	dbDown             bool
	usersErr           error
	keys               []headscale.APIKey
	versionOverride    string
	checkErr           error
	calls              []string
}

func (s *opsHS) rec(m string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, m)
}

func (s *opsHS) rejected(op headscale.Op) error {
	return &headscale.Error{Op: op, Kind: headscale.KindAPIKeyRejected, Err: headscale.ErrAPIKeyRejected}
}

func (s *opsHS) Health(context.Context) (headscale.Health, error) {
	s.rec("Health")
	if s.keyRejected {
		return headscale.Health{}, s.rejected(headscale.OpHealth)
	}
	return headscale.Health{DatabaseConnectivity: !s.dbDown}, nil
}

func (s *opsHS) GetPolicy(context.Context) (headscale.Policy, error) {
	s.rec("GetPolicy")
	switch {
	case s.keyRejected:
		return headscale.Policy{}, s.rejected(headscale.OpGetPolicy)
	case s.noPolicy:
		return headscale.Policy{}, &headscale.Error{Op: headscale.OpGetPolicy, Kind: headscale.KindNoPolicy, Err: headscale.ErrNoPolicy}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return headscale.Policy{Data: s.policy}, nil
}

func (s *opsHS) CheckPolicy(context.Context, string) error { s.rec("CheckPolicy"); return s.checkErr }

func (s *opsHS) Version(context.Context) (string, error) {
	s.rec("Version")
	if s.versionOverride != "" {
		return s.versionOverride, nil
	}
	s.h.mu.Lock()
	defer s.h.mu.Unlock()
	return s.h.versions[s.h.ctrImage], nil
}

func (s *opsHS) ListUsers(context.Context, headscale.UserFilter) ([]headscale.User, error) {
	s.rec("ListUsers")
	return []headscale.User{{ID: 1, Name: "mg-x"}}, s.usersErr
}

func (s *opsHS) ListNodes(context.Context, string) ([]headscale.Node, error) {
	s.rec("ListNodes")
	return nil, nil
}

func (s *opsHS) ListPreAuthKeys(context.Context) ([]headscale.PreAuthKey, error) {
	s.rec("ListPreAuthKeys")
	return nil, nil
}

func (s *opsHS) ListAPIKeys(context.Context) ([]headscale.APIKey, error) {
	s.rec("ListAPIKeys")
	return s.keys, nil
}

type opsRegistry struct{ hs *opsHS }

func (r opsRegistry) ForTenant(context.Context, uuid.UUID) (headscale.Instance, error) {
	return r.hs, nil
}

// opsPolicies is the policy core: it sets the canonical rendering and reads back.
type opsPolicies struct {
	hs   *opsHS
	err  error
	reqs []policies.ApplyRequest
}

func (p *opsPolicies) Apply(_ context.Context, req policies.ApplyRequest) (policies.Result, error) {
	p.reqs = append(p.reqs, req)
	if p.err != nil {
		return policies.Result{}, p.err
	}
	doc, err := policies.Lint(req.HuJSON)
	if err != nil {
		return policies.Result{}, err
	}
	p.hs.mu.Lock()
	p.hs.policy = doc.Applied
	p.hs.mu.Unlock()
	return policies.Result{State: policies.StateApplied, AppliedSHA256: doc.AppliedSHA256, ApplicationID: uuid.New()}, nil
}

// ---------------------------------------------------------------------------------------------------- registry

type opsStore struct {
	mu       sync.Mutex
	inst     InstanceRecord
	slug     string
	tstatus  string
	current  *ConfigVersion
	policy   *PolicyInForce
	audit    []string
	finished map[uuid.UUID]bool
	upgrades []UpgradeFinish
	failures []OpsFailure
	notified []string
}

func (m *opsStore) OpsTarget(_ context.Context, _, id uuid.UUID) (ReconfigureTarget, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if id != m.inst.ID {
		return ReconfigureTarget{}, ErrNotFound
	}
	t := ReconfigureTarget{Instance: m.inst, TenantSlug: m.slug, TenantStatus: m.tstatus}
	if m.current != nil {
		cv := *m.current
		t.Current = &cv
	}
	return t, nil
}

func (m *opsStore) AppliedPolicy(context.Context, uuid.UUID, uuid.UUID) (PolicyInForce, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.policy == nil {
		return PolicyInForce{}, false, nil
	}
	return *m.policy, true, nil
}

func (m *opsStore) close(op audit.Operation, outcome, reason string) {
	if m.finished[op.ID] {
		return
	}
	m.finished[op.ID] = true
	m.audit = append(m.audit, strings.TrimSpace(op.Action+"."+outcome+" "+reason))
}

func (m *opsStore) FinishOperation(_ context.Context, op audit.Operation, _ audit.Details) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.close(op, "succeeded", "")
	return nil
}

func (m *opsStore) FinishUpgrade(_ context.Context, f UpgradeFinish) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.current.ID != f.PreviousVersionID && m.current.ID != f.Version.ID {
		return ErrState
	}
	if m.current.ID == f.PreviousVersionID {
		params, _ := json.Marshal(f.Version.Params)
		m.current = &ConfigVersion{ID: f.Version.ID, Version: m.current.Version + 1, Status: ConfigApplied,
			TemplateVersion: "2", ConfigSHA256: f.Version.ConfigSHA256, Params: params}
		m.upgrades = append(m.upgrades, f)
	}
	m.inst.ImageDigest, m.inst.HeadscaleVersion = f.ImageDigest, f.HeadscaleVersion
	m.close(f.Operation, "succeeded", "")
	return nil
}

func (m *opsStore) FailOperation(_ context.Context, f OpsFailure) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if f.Outcome != OutcomeRollbackFailed {
		m.close(f.Operation, "failed", f.Reason)
	}
	if f.RollbackEvent != nil {
		out := "success"
		if !*f.RollbackEvent {
			out = "failure"
		}
		m.audit = append(m.audit, ActionUpgradeRollback+" "+out)
	}
	m.failures = append(m.failures, f)
	m.notified = append(m.notified, f.Outcome+":"+f.Reason)
	return nil
}

func (m *opsStore) NotifyFailure(_ context.Context, f OpsFailure) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.notified = append(m.notified, f.Outcome+":"+f.Reason)
	return nil
}

// ---------------------------------------------------------------------------------------------------- rig

type opsRig struct {
	h    *opsHost
	b    *opsBackups
	hs   *opsHS
	pol  *opsPolicies
	st   *opsStore
	sec  *recSecurity
	logs *bytes.Buffer
	in   OpsInput
	r    *fakeRunner
	rs   *InstanceRestarter
	up   *InstanceUpgrader
	v1   uuid.UUID
}

func newOpsRig(t *testing.T, kind string, mut ...func(*InstanceOpsConfig, *opsRig)) *opsRig {
	t.Helper()
	g := &opsRig{h: newOpsHost(), sec: &recSecurity{}, logs: &bytes.Buffer{}, v1: uuid.New()}
	g.b = &opsBackups{h: g.h, taken: map[uuid.UUID]string{}, errs: map[string][]error{}}
	g.hs = &opsHS{h: g.h, policy: templates.BootstrapPolicy, keys: []headscale.APIKey{{Prefix: "abcdefghijkl"}}}
	g.pol = &opsPolicies{hs: g.hs}
	p := baseParams()
	p.ImageDigest = imgOld
	params, _ := json.Marshal(p)
	tenant, inst := uuid.New(), uuid.New()
	g.st = &opsStore{slug: "acme", tstatus: tenants.StatusActive, finished: map[uuid.UUID]bool{},
		inst: InstanceRecord{ID: inst, TenantID: tenant, HostID: uuid.New(), Status: tenants.InstanceRunning, ImageDigest: imgOld,
			HeadscaleVersion: "v0.29.7", ControlHostname: "acme.mesh.example.test", RunUID: 30001,
			NetCIDR: netip.MustParsePrefix("10.250.1.0/29"), PublicEntryIPv4: netip.MustParseAddr("192.0.2.10"),
			NoiseFingerprint: strings.Repeat("ab", 32), APIKeyPrefix: "abcdefghijkl"},
		current: &ConfigVersion{ID: g.v1, Version: 1, Status: ConfigApplied, TemplateVersion: "2", ConfigSHA256: strings.Repeat("c", 64),
			Params: params},
		policy: &PolicyInForce{HuJSON: templates.BootstrapPolicy, SHA256: BaselineSHA256, Kind: policies.KindBaseline}}
	actor := uuid.New()
	action := ActionInstanceRestart
	g.in = OpsInput{TenantID: tenant, InstanceID: inst, Source: SourcePlatform, RequestedBy: &actor}
	if kind == UpgradeKind {
		action, g.in.ImageDigest = ActionInstanceUpgrade, imgNew
	}
	g.in.Operation = audit.Operation{ID: uuid.New(), Action: action, ActorType: audit.ActorIdentity, ResourceType: "instance",
		ResourceID: inst.String()}
	cfg := InstanceOpsConfig{Store: g.st, Agent: g.h, Headscale: opsRegistry{hs: g.hs}, Policies: g.pol, Backups: g.b,
		Security: g.sec, Logger: slog.New(slog.NewJSONHandler(g.logs, nil)), RetryBase: time.Millisecond,
		RetryMax: 4 * time.Millisecond, HealthPoll: time.Millisecond, HealthTimeout: 40 * time.Millisecond}
	for _, m := range mut {
		m(&cfg, g)
	}
	var err error
	if kind == UpgradeKind {
		g.up, err = NewUpgrader(cfg)
	} else {
		g.rs, err = NewRestarter(cfg)
	}
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(g.in)
	g.r = &fakeRunner{id: uuid.New(), input: b}
	return g
}

// run is one delivery as the worker makes it: the handler, then — after a permanent error — the compensation.
func (g *opsRig) run() (runErr, compErr error) {
	ctx := context.Background()
	if g.up != nil {
		runErr = g.up.run(ctx, g.r)
		if jobs.IsPermanent(runErr) {
			compErr = g.up.compensate(ctx, g.r, runErr)
		}
		return runErr, compErr
	}
	runErr = g.rs.run(ctx, g.r)
	if jobs.IsPermanent(runErr) {
		compErr = g.rs.compensate(ctx, g.r, runErr)
	}
	return runErr, compErr
}

func (g *opsRig) steps() []string {
	var out []string
	for _, s := range g.r.steps {
		out = append(out, s.name+":"+s.status)
	}
	return out
}

func (g *opsRig) events(kind string) int {
	n := 0
	for _, e := range g.sec.events {
		if e.Kind == kind {
			n++
		}
	}
	return n
}

func sha(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func count(list []string, prefix string) int {
	n := 0
	for _, c := range list {
		if strings.HasPrefix(c, prefix) {
			n++
		}
	}
	return n
}

// ---------------------------------------------------------------------------------------------------- restart

func TestOpsKindsAndSteps(t *testing.T) {
	for _, name := range []string{RestartKind, UpgradeKind} {
		k := jobs.DefaultKinds()[name]
		if !k.Compensable || k.Lock != jobs.LockHold || k.Dedupe != "instance:{instance}:{kind}" {
			t.Fatalf("%s: %+v", name, k)
		}
	}
	if !slices.Equal(RestartSteps, []string{"instance.restart", "instance.health", "policy.gate", "edge.verify", "restart.finish"}) {
		t.Fatalf("restart steps %v", RestartSteps)
	}
	if len(UpgradeSteps) != 11 || UpgradeSteps[0] != "upgrade.preflight" || UpgradeSteps[4] != "image.switch" {
		t.Fatalf("upgrade steps %v", UpgradeSteps)
	}
}

func TestRestartHappyPath(t *testing.T) {
	g := newOpsRig(t, RestartKind)
	before := g.h.started
	if err, _ := g.run(); err != nil {
		t.Fatalf("restart: %v (%v)", err, g.steps())
	}
	want := []string{"instance.restart:succeeded", "instance.health:succeeded", "policy.gate:succeeded", "edge.verify:succeeded",
		"restart.finish:succeeded"}
	if !slices.Equal(g.steps(), want) {
		t.Fatalf("steps %v", g.steps())
	}
	if c := g.h.list(); count(c, "RestartInstance") != 1 || count(c, "StopInstance") != 0 || !g.h.started.After(before) {
		t.Fatalf("agent calls %v", c)
	}
	if !slices.Equal(g.st.audit, []string{"platform.instance.restart.succeeded"}) || len(g.st.notified) != 0 {
		t.Fatalf("audit %v, notified %v", g.st.audit, g.st.notified)
	}
	if d := string(g.r.step("policy.gate").detail); !strings.Contains(d, `"post_start_gate":"ok"`) {
		t.Fatalf("post-start gate %s", d)
	}
	if d := string(g.r.step("edge.verify").detail); !strings.Contains(d, "prober_not_configured") {
		t.Fatalf("edge.verify %s", d)
	}
}

// TestRestartPostStartGateReappliesDrift — §11.4 verification: a policy changed out of band before the restart is
// applied again (drift_repair) and read back; High event.
func TestRestartPostStartGateReappliesDrift(t *testing.T) {
	g := newOpsRig(t, RestartKind)
	g.hs.policy = `{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}` // changed out of band
	if err, _ := g.run(); err != nil {
		t.Fatalf("restart: %v", err)
	}
	if len(g.pol.reqs) != 1 || g.pol.reqs[0].Trigger != policies.TriggerDriftRepair || g.pol.reqs[0].HuJSON != templates.BootstrapPolicy ||
		g.pol.reqs[0].Kind != policies.KindBaseline {
		t.Fatalf("re-application %+v", g.pol.reqs)
	}
	doc, _ := policies.Lint(templates.BootstrapPolicy)
	if g.hs.policy != doc.Applied || g.events(SecPolicyDrift) != 1 {
		t.Fatalf("policy now %q, drift events %d", g.hs.policy, g.events(SecPolicyDrift))
	}
	if d := string(g.r.step("policy.gate").detail); !strings.Contains(d, `"post_start_gate":"repaired"`) {
		t.Fatalf("post-start gate %s", d)
	}
	// without a policy core (reconfigure's behaviour) the drift is reported, not repaired
	g2 := newOpsRig(t, RestartKind, func(c *InstanceOpsConfig, _ *opsRig) { c.Policies = nil })
	g2.hs.policy = `{"acls":[]}`
	if err, _ := g2.run(); err != nil || g2.events(SecPolicyDrift) != 1 || g2.hs.policy != `{"acls":[]}` {
		t.Fatalf("no core: %v, %d", err, g2.events(SecPolicyDrift))
	}
	// the repair fails ⇒ the job fails (policy_repair_failed), the operation closes .failed, the staff notified
	g3 := newOpsRig(t, RestartKind)
	g3.hs.policy = `{"acls":[]}`
	g3.pol.err = errors.New("instance refused")
	runErr, compErr := g3.run()
	if jobs.CodeOf(runErr) != "policy_repair_failed" || compErr != nil ||
		!slices.Equal(g3.st.audit, []string{"platform.instance.restart.failed policy_repair_failed"}) ||
		!slices.Equal(g3.st.notified, []string{"rolled_back:policy_repair_failed"}) {
		t.Fatalf("failed repair: %v / %v, audit %v, notified %v", runErr, compErr, g3.st.audit, g3.st.notified)
	}
}

// TestRestartReplacedDatabase — §11.4 verification: db.sqlite replaced by an empty database ⇒ after the restart the
// instance refuses the platform's API key: Critical, edge detached, the job fails.
func TestRestartReplacedDatabase(t *testing.T) {
	g := newOpsRig(t, RestartKind)
	g.hs.keyRejected = true
	runErr, compErr := g.run()
	if jobs.CodeOf(runErr) != "database_replaced" || compErr != nil {
		t.Fatalf("run %v, compensation %v", runErr, compErr)
	}
	if !g.h.detached || g.events(SecDatabaseReplaced) != 1 {
		t.Fatalf("detached %v, events %v", g.h.detached, g.sec.events)
	}
	for _, e := range g.sec.events {
		if e.Kind == SecDatabaseReplaced && e.Severity != audit.SeverityCritical {
			t.Fatalf("severity %s", e.Severity)
		}
	}
	if !slices.Equal(g.st.audit, []string{"platform.instance.restart.failed database_replaced"}) ||
		!slices.Equal(g.st.notified, []string{"rolled_back:database_replaced"}) {
		t.Fatalf("audit %v notified %v", g.st.audit, g.st.notified)
	}
	// no policy at all (allow-all) after the restart: the same containment
	g2 := newOpsRig(t, RestartKind)
	g2.hs.noPolicy = true
	if runErr, _ := g2.run(); jobs.CodeOf(runErr) != "no_policy" || !g2.h.detached || g2.events(SecPolicyMissing) != 1 {
		t.Fatalf("no policy: %v detached %v", runErr, g2.h.detached)
	}
}

func TestRestartRefusals(t *testing.T) {
	cases := []struct {
		name  string
		setup func(*opsRig)
		code  string
		event string
	}{
		{"quarantined", func(g *opsRig) { g.st.inst.Status = tenants.InstanceQuarantined }, "instance_quarantined", ""},
		{"stopped", func(g *opsRig) { g.st.inst.Status = tenants.InstanceStopped }, "instance_not_running", ""},
		{"tenant deleted", func(g *opsRig) { g.st.tstatus = tenants.StatusDeleted }, "tenant_state", ""},
		{"start guard", func(g *opsRig) { g.h.guard = true }, "agent_state", SecStartGuardFailed},
		{"never healthy", func(g *opsRig) { g.h.healthyOn[imgOld] = false }, "instance_unhealthy", ""},
		{"no database", func(g *opsRig) { g.hs.dbDown = true }, "instance_unhealthy", ""},
		{"another noise key", func(g *opsRig) { g.h.fp = strings.Repeat("cd", 32) }, "noise_key_changed", SecNoiseKeyChanged},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := newOpsRig(t, RestartKind)
			c.setup(g)
			runErr, compErr := g.run()
			if jobs.CodeOf(runErr) != c.code || compErr != nil {
				t.Fatalf("run %v (%s), compensation %v", runErr, jobs.CodeOf(runErr), compErr)
			}
			if c.event != "" && g.events(c.event) != 1 {
				t.Fatalf("events %v", g.sec.events)
			}
			if c.code == "instance_quarantined" && count(g.h.list(), "RestartInstance") != 0 {
				t.Fatal("a quarantined instance was restarted")
			}
			if !slices.Equal(g.st.audit, []string{"platform.instance.restart.failed " + c.code}) {
				t.Fatalf("audit %v", g.st.audit)
			}
			for _, s := range g.r.steps {
				if s.comp != jobs.StepSkipped {
					t.Fatalf("step %s compensation %q (a restart has nothing to undo)", s.name, s.comp)
				}
			}
		})
	}
}

func TestRestartTransientResumable(t *testing.T) {
	g := newOpsRig(t, RestartKind)
	unavailable := refused(codes.Unavailable, 0, "agent down")
	g.h.fail("RestartInstance", unavailable, unavailable, unavailable, unavailable, unavailable, unavailable)
	runErr, _ := g.run()
	if !jobs.IsResumable(runErr) || !slices.Equal(g.st.notified, []string{"resumable:agent_unavailable"}) || len(g.st.audit) != 0 {
		t.Fatalf("run %v, notified %v, audit %v", runErr, g.st.notified, g.st.audit)
	}
	// /retry: resumes at instance.restart
	if err, _ := g.run(); err != nil || count(g.h.list(), "RestartInstance") != 7 {
		t.Fatalf("retry: %v, %v", err, g.h.list())
	}
}

// ---------------------------------------------------------------------------------------------------- upgrade

func TestUpgradeHappyPath(t *testing.T) {
	g := newOpsRig(t, UpgradeKind)
	if err, _ := g.run(); err != nil {
		t.Fatalf("upgrade: %v (%v)", err, g.steps())
	}
	for i, s := range g.r.steps {
		if s.name != UpgradeSteps[i] || s.status != jobs.StepSucceeded {
			t.Fatalf("steps %v", g.steps())
		}
	}
	calls := g.h.list()
	order := []string{"GetHostInfo", "InspectImage:dd", "InspectImage:ee", "ValidateConfig:ee", "StopInstance", "PreflightUpgrade",
		"UpgradeInstance:ee", "StartInstance"}
	i := 0
	for _, c := range calls {
		if i < len(order) && c == order[i] {
			i++
		}
	}
	if i != len(order) {
		t.Fatalf("agent calls %v, want in order %v", calls, order)
	}
	meta, ctr, data, running := g.h.state()
	if meta != imgNew || ctr != imgNew || !running || data != "migrated:"+imgNew {
		t.Fatalf("host %s %s %s %v", meta, ctr, data, running)
	}
	if len(g.b.taken) != 1 || g.b.restored != 0 || !slices.Equal(g.b.calls, []string{"ColdBackup", "OpenBackup"}) {
		t.Fatalf("backups %v %v", g.b.taken, g.b.calls)
	}
	for _, d := range g.b.taken {
		if d != "orig" {
			t.Fatalf("the cold backup holds %q", d)
		}
	}
	if len(g.st.upgrades) != 1 || g.st.inst.ImageDigest != imgNew || g.st.current.ConfigSHA256 != strings.Repeat("c", 64) {
		t.Fatalf("registry %+v", g.st.upgrades)
	}
	var p configParams
	_ = json.Unmarshal(g.st.current.Params, &p)
	if p.ImageDigest != imgNew || p.NetCIDR != "10.250.1.0/29" {
		t.Fatalf("new configuration version params %+v", p)
	}
	if !slices.Equal(g.st.audit, []string{"platform.instance.upgrade.succeeded"}) || len(g.st.notified) != 0 {
		t.Fatalf("audit %v notified %v", g.st.audit, g.st.notified)
	}
	if d := string(g.r.step("upgrade.smoke").detail); !strings.Contains(d, `"version":"v0.29.7"`) || !strings.Contains(d, `"users":1`) {
		t.Fatalf("smoke %s", d)
	}
	// re-running every step changes nothing more (a retried job)
	for _, s := range UpgradeSteps {
		g.r.reset(s)
	}
	if err, _ := g.run(); err != nil || len(g.b.taken) != 1 || len(g.st.upgrades) != 1 {
		t.Fatalf("re-run: %v, backups %d, upgrades %d", err, len(g.b.taken), len(g.st.upgrades))
	}
}

func TestUpgradeAlreadyOnTarget(t *testing.T) {
	g := newOpsRig(t, UpgradeKind)
	g.st.inst.ImageDigest = imgNew
	if err, _ := g.run(); err != nil {
		t.Fatal(err)
	}
	if len(g.h.list()) != 0 || !slices.Equal(g.steps(), []string{"upgrade.preflight:succeeded", "upgrade.finish:succeeded"}) ||
		!slices.Equal(g.st.audit, []string{"platform.instance.upgrade.succeeded"}) {
		t.Fatalf("calls %v steps %v audit %v", g.h.list(), g.steps(), g.st.audit)
	}
}

// TestUpgradePreflightRefusals: nothing is stopped — the instance keeps running on its image and data.
func TestUpgradePreflightRefusals(t *testing.T) {
	cases := []struct {
		name  string
		setup func(*opsRig)
		code  string
	}{
		{"no configuration version", func(g *opsRig) { g.st.current = nil }, "no_config_version"},
		{"target not allowed", func(g *opsRig) { g.h.allowed = []string{imgOld} }, "image_not_allowed"},
		{"skips a minor", func(g *opsRig) { g.h.versions[imgNew] = "v0.31.0" }, "version_path_refused"},
		{"downgrade", func(g *opsRig) { g.h.versions[imgNew] = "v0.29.6" }, "version_path_refused"},
		{"adapter has no contract", func(g *opsRig) { g.h.versions[imgNew] = "v0.30.0" }, "version_unsupported"},
		{"instance runs another version", func(g *opsRig) { g.hs.versionOverride = "v0.29.6" }, "version_mismatch"},
		{"configtest of the target", func(g *opsRig) { g.h.cfgValid = false }, "config_invalid"},
		{"configuration drift", func(g *opsRig) { g.h.renderSHA = strings.Repeat("f", 64) }, "config_drift"},
		{"policy refused", func(g *opsRig) {
			g.hs.checkErr = &headscale.Error{Op: headscale.OpCheckPolicy, Kind: headscale.KindPolicyRejected}
		}, "policy_check_failed"},
		{"quarantined", func(g *opsRig) { g.st.inst.Status = tenants.InstanceQuarantined }, "instance_quarantined"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := newOpsRig(t, UpgradeKind)
			c.setup(g)
			runErr, compErr := g.run()
			if jobs.CodeOf(runErr) != c.code || compErr != nil {
				t.Fatalf("run %v (%s), compensation %v", runErr, jobs.CodeOf(runErr), compErr)
			}
			meta, _, data, running := g.h.state()
			if count(g.h.list(), "StopInstance") != 0 || !running || meta != imgOld || data != "orig" || len(g.b.calls) != 0 {
				t.Fatalf("something changed: calls %v, backups %v", g.h.list(), g.b.calls)
			}
			if !slices.Equal(g.st.audit, []string{"platform.instance.upgrade.failed " + c.code}) ||
				!slices.Equal(g.st.notified, []string{"rolled_back:" + c.code}) {
				t.Fatalf("audit %v notified %v", g.st.audit, g.st.notified)
			}
		})
	}
}

// TestUpgradeConfigtestOfTargetFails — §11.4 verification: configtest of the target binary refuses a copy of the data
// (a stored policy or a migration it cannot handle) ⇒ the previous image runs again on the untouched data, rolled_back,
// no restore.
func TestUpgradeConfigtestOfTargetFails(t *testing.T) {
	g := newOpsRig(t, UpgradeKind)
	g.h.preflight = func() (*agentv1.PreflightUpgradeResponse, error) {
		return &agentv1.PreflightUpgradeResponse{Valid: false, ExitCode: 1, Detail: "initializing policy manager: parsing policy",
			ConfigSha256: g.h.cfgSHA}, nil
	}
	runErr, compErr := g.run()
	if jobs.CodeOf(runErr) != "preflight_failed" || compErr != nil {
		t.Fatalf("run %v compensation %v", runErr, compErr)
	}
	meta, ctr, data, running := g.h.state()
	if meta != imgOld || ctr != imgOld || !running || data != "orig" || g.b.restored != 0 || count(g.h.list(), "UpgradeInstance") != 0 {
		t.Fatalf("host %s %s %s %v, restores %d, calls %v", meta, ctr, data, running, g.b.restored, g.h.list())
	}
	if !slices.Equal(g.st.audit, []string{"platform.instance.upgrade.failed preflight_failed"}) ||
		!slices.Equal(g.st.notified, []string{"rolled_back:preflight_failed"}) || len(g.st.upgrades) != 0 {
		t.Fatalf("audit %v notified %v", g.st.audit, g.st.notified)
	}
	if d := string(g.r.step(UStepConfigtest).detail); !strings.Contains(d, "parsing policy") {
		t.Fatalf("configtest detail %s", d)
	}
	if s := g.r.step(UStepStop); s.comp != jobs.StepSucceeded {
		t.Fatalf("instance.stop compensation %q", s.comp)
	}
}

// TestUpgradeRollbackByRestore — §11.4 verification "upgrade lỗi ⇒ tự lùi": every failure after the target image
// started ⇒ stop, previous image, the cold backup restored, healthy — the data is the backup's again.
func TestUpgradeRollbackByRestore(t *testing.T) {
	cases := []struct {
		name  string
		setup func(*opsRig)
		code  string
	}{
		{"never healthy", func(g *opsRig) { g.h.healthyOn[imgNew] = false }, "instance_unhealthy"},
		{"contract smoke", func(g *opsRig) {
			g.hs.usersErr = &headscale.Error{Op: headscale.OpListUsers, Kind: headscale.KindUpstreamRejected}
		}, "contract_smoke_failed"},
		{"platform key not valid", func(g *opsRig) { g.hs.keys = nil }, "contract_smoke_failed"},
		{"edge exposes paths", func(g *opsRig) {}, "edge_exposes_paths"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := newOpsRig(t, UpgradeKind, func(cfg *InstanceOpsConfig, g *opsRig) {
				if c.code == "edge_exposes_paths" {
					cfg.Prober = &fakeProber{edge: ProbeResult{OK: false, Exposed: []string{"/api/v1/node"}}}
				}
			})
			c.setup(g)
			runErr, compErr := g.run()
			if jobs.CodeOf(runErr) != c.code || compErr != nil {
				t.Fatalf("run %v (%s), compensation %v", runErr, jobs.CodeOf(runErr), compErr)
			}
			meta, ctr, data, running := g.h.state()
			if meta != imgOld || ctr != imgOld || !running || data != "orig" || g.b.restored != 1 {
				t.Fatalf("host %s %s %s %v, restores %d", meta, ctr, data, running, g.b.restored)
			}
			if !slices.Equal(g.st.audit, []string{"platform.instance.upgrade.failed " + c.code, ActionUpgradeRollback + " success"}) ||
				!slices.Equal(g.st.notified, []string{"rolled_back:" + c.code}) || len(g.st.upgrades) != 0 || g.st.inst.ImageDigest != imgOld {
				t.Fatalf("audit %v notified %v", g.st.audit, g.st.notified)
			}
			calls := g.h.list()
			if count(calls, "UpgradeInstance:dd") != 1 || count(calls, "StopInstance") != 2 {
				t.Fatalf("calls %v", calls)
			}
		})
	}
}

// TestUpgradeSwitchRefused: the switch itself is refused — the target never started: switched back, the previous image
// started on the untouched data, no restore.
func TestUpgradeSwitchRefused(t *testing.T) {
	g := newOpsRig(t, UpgradeKind)
	g.h.fail("UpgradeInstance:ee", refused(codes.FailedPrecondition, agentv1.RefusalReason_REFUSAL_REASON_CONFLICT, "compose failed"))
	runErr, compErr := g.run()
	if jobs.CodeOf(runErr) != "agent_conflict" || compErr != nil {
		t.Fatalf("run %v compensation %v", runErr, compErr)
	}
	meta, ctr, data, running := g.h.state()
	if meta != imgOld || ctr != imgOld || !running || data != "orig" || g.b.restored != 0 {
		t.Fatalf("host %s %s %s %v restores %d", meta, ctr, data, running, g.b.restored)
	}
	if !slices.Equal(g.st.audit, []string{"platform.instance.upgrade.failed agent_conflict", ActionUpgradeRollback + " success"}) {
		t.Fatalf("audit %v", g.st.audit)
	}
}

// TestUpgradeBackupFails: no cold backup ⇒ nothing proceeds; the previous image starts again.
func TestUpgradeBackupFails(t *testing.T) {
	g := newOpsRig(t, UpgradeKind)
	g.b.errs["ColdBackup"] = []error{jobs.Permanent("backup_not_configured", errors.New("no manifest key"))}
	runErr, compErr := g.run()
	meta, _, data, running := g.h.state()
	if jobs.CodeOf(runErr) != "backup_not_configured" || compErr != nil || meta != imgOld || !running || data != "orig" ||
		count(g.h.list(), "PreflightUpgrade") != 0 {
		t.Fatalf("run %v comp %v host %s %s %v calls %v", runErr, compErr, meta, data, running, g.h.list())
	}
}

// TestUpgradeRollbackFailure: the restore fails ⇒ Critical, the operation stays open, compensation_failed; a later
// /rollback (compensation again) completes it and closes the operation once.
func TestUpgradeRollbackFailure(t *testing.T) {
	g := newOpsRig(t, UpgradeKind)
	g.h.healthyOn[imgNew] = false
	g.b.errs["RollbackRestore"] = []error{jobs.Permanent("restore_check_failed", errors.New("api keys")),
		jobs.Permanent("restore_check_failed", errors.New("api keys"))}
	g.up.ops.cfg.StepRetries = 0
	runErr, compErr := g.run()
	if jobs.CodeOf(runErr) != "instance_unhealthy" || jobs.CodeOf(compErr) != "restore_check_failed" {
		t.Fatalf("run %v compensation %v", runErr, compErr)
	}
	if g.events(SecUpgradeRollbackFailed) != 1 || len(g.st.audit) != 1 || g.st.audit[0] != ActionUpgradeRollback+" failure" ||
		!slices.Equal(g.st.notified, []string{"rollback_failed:restore_check_failed"}) {
		t.Fatalf("events %v audit %v notified %v", g.sec.events, g.st.audit, g.st.notified)
	}
	// the host is repaired; /rollback runs the compensation again
	if err := g.up.compensate(context.Background(), g.r, runErr); err == nil {
		t.Fatal("the second injected restore failure was not seen")
	}
	if err := g.up.compensate(context.Background(), g.r, runErr); err != nil {
		t.Fatalf("/rollback: %v", err)
	}
	meta, _, data, running := g.h.state()
	if meta != imgOld || data != "orig" || !running || count(g.st.audit, "platform.instance.upgrade.failed") != 1 {
		t.Fatalf("host %s %s %v audit %v", meta, data, running, g.st.audit)
	}
}

// TestUpgradeQuarantinedMidJob: quarantined between the backup and the switch ⇒ never switched nor started again.
func TestUpgradeQuarantinedMidJob(t *testing.T) {
	g := newOpsRig(t, UpgradeKind)
	quarantine := func() { g.st.mu.Lock(); g.st.inst.Status = tenants.InstanceQuarantined; g.st.mu.Unlock() }
	g.h.preflight = func() (*agentv1.PreflightUpgradeResponse, error) {
		quarantine()
		return &agentv1.PreflightUpgradeResponse{Valid: true, ConfigSha256: g.h.cfgSHA, TargetHeadscaleVersion: "v0.29.7"}, nil
	}
	runErr, compErr := g.run()
	_, _, _, running := g.h.state()
	if jobs.CodeOf(runErr) != "instance_quarantined" || compErr != nil || running || count(g.h.list(), "UpgradeInstance") != 0 ||
		count(g.h.list(), "StartInstance") != 0 {
		t.Fatalf("run %v comp %v running %v calls %v", runErr, compErr, running, g.h.list())
	}
}

func TestUpgradeInputValidation(t *testing.T) {
	in := OpsInput{TenantID: uuid.New(), InstanceID: uuid.New(), Operation: audit.Operation{ID: uuid.New()}}
	if in.validate(UpgradeKind) == nil {
		t.Fatal("an upgrade without a target accepted")
	}
	in.ImageDigest = "latest"
	if in.validate(UpgradeKind) == nil {
		t.Fatal("an upgrade to a tag accepted")
	}
	in.ImageDigest = imgNew
	if in.validate(UpgradeKind) != nil || in.validate(RestartKind) == nil {
		t.Fatal("validation of the kinds")
	}
	if !sameVersion("v0.29.7", "0.29.7+mg.1") || sameVersion("v0.29.7", "v0.29.6") || sameVersion("", "") {
		t.Fatal("sameVersion")
	}
	_ = sha("")
}
