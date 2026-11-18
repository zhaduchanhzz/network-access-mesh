//go:build linux && dockerintegration

package main

// Integration test of instance.reconfigure (P3-T13 — master §20 "Config lỗi ⇒ tự lùi") on a real Docker Engine: the
// orchestrator's state machine (orchestrator.InstanceReconfigurer, the code the worker runs) drives a REAL agent over
// its Unix socket against a real, activated Headscale 0.29.7 instance. No PostgreSQL, no worker, no network here: the
// registry is an in-memory ReconfigureStore, the attempt an in-memory JobRunner, and the adapter side (CheckPolicy,
// GET /api/v1/health, GetPolicy — the instance is not reachable from this container, network none) a fake that
// answers like the instance; the container health, the configuration on disk, the restart and the start guard are
// real. Entry point: tests/integration/agent/run.sh (`make agent-it`).
//
//  1. a valid change (log.level warn, node.expiry 30 days) ⇒ the new version on disk (sha256), the container restarted
//     on it and healthy, Headscale really runs it (no info-level line after the restart), the registry on the new
//     version, data/ untouched (keys byte for byte, the same database file);
//  2. a configuration that passes configtest but fails at runtime ⇒ rolled back: the typed parameter set has no such
//     value by design (the agent refuses the fail-open values configtest misses — §11.3 step 8), so the test plays the
//     fault: right after the agent wrote the new version it moves listen_addr onto the metrics port in config.yaml —
//     configtest never binds, Serve() fails "address already in use" — the health gate times out, the previous
//     version is written back, the instance restarted on it: the previous sha256, healthy, the new version `failed`.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"
	"google.golang.org/grpc"

	agentv1 "github.com/zhaduchanhzz/network-access-mesh/api/agent/v1"
	"github.com/zhaduchanhzz/network-access-mesh/infrastructure/headscale/templates"
	"github.com/zhaduchanhzz/network-access-mesh/internal/agentclient"
	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/orchestrator"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
)

// ---------------------------------------------------------------------------------------------------- in-memory attempt

type itStep struct {
	name, status, comp string
	attempt            int
	resources, detail  []byte
}

type itRunner struct {
	id     uuid.UUID
	input  []byte
	steps  []*itStep
	output any
}

func (r *itRunner) step(name string) *itStep {
	for _, s := range r.steps {
		if s.name == name {
			return s
		}
	}
	return nil
}

func (r *itRunner) JobID() uuid.UUID           { return r.id }
func (r *itRunner) Input(v any) error          { return json.Unmarshal(r.input, v) }
func (r *itRunner) SetOutput(v any) error      { r.output = v; return nil }
func (r *itRunner) SetResource(string, string) {}

func (r *itRunner) Step(ctx context.Context, name string, fn func(ctx context.Context, s orchestrator.StepContext) error) error {
	s := r.step(name)
	if s == nil {
		s = &itStep{name: name}
		r.steps = append(r.steps, s)
	}
	if s.status == jobs.StepSucceeded {
		return nil
	}
	s.status, s.attempt = jobs.StepRunning, s.attempt+1
	sc := &itStepCtx{s: s}
	err := fn(ctx, sc)
	s.detail = sc.detail
	if err != nil {
		s.status = jobs.StepFailed
		return err
	}
	s.status = jobs.StepSucceeded
	return nil
}

func (r *itRunner) StepResources(_ context.Context, name string, v any) (bool, error) {
	s := r.step(name)
	if s == nil || len(s.resources) == 0 {
		return false, nil
	}
	return true, json.Unmarshal(s.resources, v)
}

func (r *itRunner) CompensateSteps(ctx context.Context, fns map[string]jobs.CompensateFunc) error {
	for i := len(r.steps) - 1; i >= 0; i-- {
		s := r.steps[i]
		if s.comp == jobs.StepSucceeded || s.comp == jobs.StepSkipped {
			continue
		}
		fn := fns[s.name]
		acted := s.status == jobs.StepSucceeded || len(s.resources) > 0
		if fn == nil || !acted {
			s.comp = jobs.StepSkipped
			continue
		}
		if err := fn(ctx, jobs.CompensationStep{Name: s.name, Status: s.status, Resources: s.resources}); err != nil {
			s.comp = jobs.StepFailed
			return err
		}
		s.comp = jobs.StepSucceeded
	}
	return nil
}

type itStepCtx struct {
	s      *itStep
	detail []byte
}

func (c *itStepCtx) RecordCreated(_ context.Context, v any) error {
	b, err := json.Marshal(v)
	c.s.resources = b
	return err
}

func (c *itStepCtx) SetDetail(v any) error {
	b, err := json.Marshal(v)
	c.detail = b
	return err
}

func (c *itStepCtx) Previous(v any) (bool, error) {
	if len(c.s.resources) == 0 {
		return false, nil
	}
	return true, json.Unmarshal(c.s.resources, v)
}

// ---------------------------------------------------------------------------------------------------- in-memory registry

type itStore struct {
	mu       sync.Mutex
	target   orchestrator.ReconfigureTarget
	versions map[uuid.UUID]*orchestrator.ConfigVersion
	order    []uuid.UUID
	current  uuid.UUID
	audit    []string
	finished map[uuid.UUID]bool
}

func (s *itStore) ReconfigureTarget(context.Context, uuid.UUID, uuid.UUID) (orchestrator.ReconfigureTarget, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t := s.target
	cv := *s.versions[s.current]
	t.Current = &cv
	return t, nil
}

func (s *itStore) ConfigVersion(_ context.Context, _, _, id uuid.UUID) (orchestrator.ConfigVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.versions[id]
	if !ok {
		return orchestrator.ConfigVersion{}, orchestrator.ErrNotFound
	}
	return *v, nil
}

func (s *itStore) InsertConfigVersion(_ context.Context, _, _ uuid.UUID, nv orchestrator.NewConfigVersion) (orchestrator.ConfigVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if v, ok := s.versions[nv.ID]; ok {
		return *v, nil
	}
	params, err := json.Marshal(nv.Params)
	if err != nil {
		return orchestrator.ConfigVersion{}, err
	}
	v := &orchestrator.ConfigVersion{ID: nv.ID, Version: int32(len(s.order) + 1), Status: orchestrator.ConfigPending, //nolint:gosec // test
		TemplateVersion: fmt.Sprint(nv.TemplateVersion), ConfigSHA256: nv.ConfigSHA256, Params: params}
	s.versions[nv.ID], s.order = v, append(s.order, nv.ID)
	return *v, nil
}

func (s *itStore) CurrentPolicy(context.Context, uuid.UUID, uuid.UUID) (orchestrator.AppliedPolicy, bool, error) {
	return orchestrator.AppliedPolicy{HuJSON: templates.BootstrapPolicy, SHA256: orchestrator.BaselineSHA256}, true, nil
}

func (s *itStore) ApplyConfig(_ context.Context, r orchestrator.ApplyConfigRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.current == r.PreviousVersionID {
		s.versions[r.PreviousVersionID].Status = orchestrator.ConfigSuperseded
		s.current = r.VersionID
	}
	s.versions[r.VersionID].Status = orchestrator.ConfigApplied
	if !s.finished[r.Operation.ID] {
		s.finished[r.Operation.ID] = true
		s.audit = append(s.audit, r.Operation.Action+".succeeded")
	}
	return nil
}

func (s *itStore) RevertConfig(_ context.Context, _, _, version, previous uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.current == version {
		s.current = previous
		s.versions[previous].Status = orchestrator.ConfigApplied
	}
	if v := s.versions[version]; v != nil {
		v.Status = orchestrator.ConfigFailed
	}
	return nil
}

func (s *itStore) RecordUnchanged(_ context.Context, op audit.Operation, _ audit.Details) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.audit = append(s.audit, op.Action+".succeeded")
	return nil
}

func (s *itStore) RecordRollback(_ context.Context, r orchestrator.RollbackRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.Failed {
		s.audit = append(s.audit, orchestrator.ActionConfigRollback+" failure")
		return nil
	}
	if !s.finished[r.Operation.ID] {
		s.finished[r.Operation.ID] = true
		s.audit = append(s.audit, r.Operation.Action+".failed "+r.Reason, orchestrator.ActionConfigRollback+" success")
	}
	return nil
}

func (s *itStore) statusOf(id uuid.UUID) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.versions[id].Status
}

// ---------------------------------------------------------------------------------------------------- adapter side

// itHS answers like the instance does through the adapter: it holds the baseline the agent set, is healthy; the
// documents given to CheckPolicy must be plain JSON (the real adapter refuses HuJSON comments).
type itHS struct {
	headscale.Instance
	checked []string
}

func (h *itHS) CheckPolicy(_ context.Context, p string) error {
	h.checked = append(h.checked, p)
	if !json.Valid([]byte(p)) {
		return &headscale.Error{Op: headscale.OpCheckPolicy, Kind: headscale.KindValidation, Err: errors.New("not plain JSON")}
	}
	return nil
}

func (h *itHS) GetPolicy(context.Context) (headscale.Policy, error) {
	return headscale.Policy{Data: templates.BootstrapPolicy}, nil
}

func (h *itHS) Health(context.Context) (headscale.Health, error) {
	return headscale.Health{DatabaseConnectivity: true}, nil
}

type itRegistry struct{ hs *itHS }

func (r itRegistry) ForTenant(context.Context, uuid.UUID) (headscale.Instance, error) {
	return r.hs, nil
}

// faultAgent is the real agent client; armed, it plays a runtime fault right after the agent wrote a configuration with
// log level `error`: listen_addr moved onto the metrics port (configtest never binds a port, Serve() does).
type faultAgent struct {
	*agentclient.Client
	t        *testing.T
	file     string
	armed    bool
	injected bool
}

func (f *faultAgent) EnsureInstance(ctx context.Context, in *agentv1.EnsureInstanceRequest, o ...grpc.CallOption) (*agentv1.EnsureInstanceResponse, error) {
	r, err := f.Client.EnsureInstance(ctx, in, o...)
	if err != nil || !f.armed || in.GetTargetPhase() != agentv1.TargetPhase_TARGET_PHASE_CONFIG ||
		in.GetSpec().GetHeadscale().GetLogLevel() != agentv1.LogLevel_LOG_LEVEL_ERROR {
		return r, err
	}
	b, rerr := os.ReadFile(f.file) //nolint:gosec // G304: test
	if rerr != nil || !bytes.Contains(b, []byte("listen_addr: 0.0.0.0:8080\n")) {
		f.t.Errorf("fault injection: config.yaml unreadable or without listen_addr 0.0.0.0:8080: %v", rerr)
		return r, err
	}
	b = bytes.Replace(b, []byte("listen_addr: 0.0.0.0:8080\n"), []byte("listen_addr: 0.0.0.0:9090\n"), 1)
	// the file exists: rewritten in place — same inode, owner and mode (root:run_uid 0440); perm is not applied
	if werr := os.WriteFile(f.file, b, 0o440); werr != nil { //nolint:gosec // G306: existing agent-owned file, mode kept
		f.t.Errorf("fault injection: %v", werr)
	}
	f.armed, f.injected = false, true
	return r, err
}

// ---------------------------------------------------------------------------------------------------- the test

func TestReconfigureEndToEnd(t *testing.T) {
	e := itConfig(t)
	ctx := context.Background()
	dc, err := client.New(client.WithHost("unix:///var/run/docker.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = dc.Close() }()
	edgeName, edgeNet := e.prefix+"-rcedge", e.prefix+"-rcedgenet"
	a := startIT(ctx, t, e, map[string]string{"MG_AGENT_EDGE_CONTAINER": edgeName, "MG_AGENT_EDGE_NETWORK": edgeNet})
	ac := a.client
	job := func() string { return uuid.NewString() }

	// ---- the fake edge (an alpine container on a bridge network with gw_priority 1, like mg-edge)
	enr, err := dc.NetworkCreate(ctx, edgeNet, client.NetworkCreateOptions{Driver: "bridge",
		IPAM: &network.IPAM{Config: []network.IPAMConfig{{Subnet: netip.MustParsePrefix(e.nets[7])}}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = dc.NetworkRemove(context.Background(), enr.ID, client.NetworkRemoveOptions{}) })
	cr, err := dc.ContainerCreate(ctx, client.ContainerCreateOptions{Name: edgeName,
		Config: &container.Config{Image: e.alpine, Cmd: []string{"sleep", "3600"}, User: "10001:10001", Labels: map[string]string{"meshguard.it": e.prefix}},
		HostConfig: &container.HostConfig{NetworkMode: container.NetworkMode(edgeNet), ReadonlyRootfs: true, CapDrop: []string{"ALL"},
			SecurityOpt: []string{"no-new-privileges:true"}},
		NetworkingConfig: &network.NetworkingConfig{EndpointsConfig: map[string]*network.EndpointSettings{edgeNet: {GwPriority: 1}}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = dc.ContainerRemove(context.Background(), edgeName, client.ContainerRemoveOptions{Force: true})
	})
	if _, err := dc.ContainerStart(ctx, cr.ID, client.ContainerStartOptions{}); err != nil {
		t.Fatal(err)
	}

	// ---- a throwaway tenant, provisioned the way steps 7–14 of §11.3 do it, activated (start guard armed)
	_, digest, _ := strings.Cut(e.image, "@")
	ref := &agentv1.InstanceRef{InstanceId: uuid.NewString(), TenantId: uuid.NewString(), Slug: e.prefix + "-rc"}
	const uid = 39921
	params := map[string]any{"image_digest": digest, "run_uid": uid, "net_cidr": e.nets[4], "memory_mib": 256, "cpu_millis": 500,
		"pids": 128, "node_expiry_days": 90, "nameservers": []string{"192.0.2.53"}, "derp_region_id": 990,
		"public_entry_ipv4": "192.0.2.10", "log_level": "LOG_LEVEL_INFO"}
	spec := &agentv1.InstanceSpec{Instance: ref, ImageDigest: digest, RunUid: uid, NetCidr: e.nets[4],
		Limits: &agentv1.ResourceLimits{MemoryMib: 256, CpuMillis: 500, Pids: 128},
		Headscale: &agentv1.HeadscaleParams{NodeExpiryDays: 90, Nameservers: []string{"192.0.2.53"}, DerpRegionId: 990,
			PublicEntryIpv4: "192.0.2.10", LogLevel: agentv1.LogLevel_LOG_LEVEL_INFO}}
	dir := filepath.Join(a.cfg.Host.TenantsDir, ref.GetInstanceId())
	t.Cleanup(func() {
		_, _ = ac.RemoveEdgeAttachment(context.Background(), &agentv1.RemoveEdgeAttachmentRequest{Instance: ref, JobId: job(),
			Reason: agentv1.EdgeDetachReason_EDGE_DETACH_REASON_DEPROVISION})
		_, _ = ac.RemoveInstance(context.Background(), &agentv1.RemoveInstanceRequest{Instance: ref, JobId: job(),
			Data: agentv1.DataDisposition_DATA_DISPOSITION_KEEP})
		_ = os.RemoveAll(dir) // activated: the agent never deletes it — the test does
	})
	for _, ph := range []agentv1.TargetPhase{agentv1.TargetPhase_TARGET_PHASE_STORAGE, agentv1.TargetPhase_TARGET_PHASE_CONFIG,
		agentv1.TargetPhase_TARGET_PHASE_NETWORK, agentv1.TargetPhase_TARGET_PHASE_CONTAINER} {
		c, cancel := context.WithTimeout(ctx, 6*time.Minute)
		_, err := ac.EnsureInstance(c, &agentv1.EnsureInstanceRequest{Spec: spec, TargetPhase: ph, JobId: job()})
		cancel()
		if err != nil {
			t.Fatalf("EnsureInstance(%s): %v", ph, err)
		}
	}
	status := func() *agentv1.InstanceStatus {
		t.Helper()
		r, err := ac.GetInstanceStatus(ctx, &agentv1.GetInstanceStatusRequest{Instance: ref})
		if err != nil {
			t.Fatal(err)
		}
		return r.GetStatus()
	}
	for start := time.Now(); status().GetHealth() != agentv1.HealthState_HEALTH_STATE_HEALTHY; time.Sleep(time.Second) {
		if time.Since(start) > 90*time.Second {
			t.Fatal("the tenant is not healthy after 90 s")
		}
	}
	if _, err := ac.BootstrapPolicy(ctx, &agentv1.BootstrapPolicyRequest{Instance: ref, JobId: job(),
		Policy: agentv1.PolicyKind_POLICY_KIND_BASELINE_DENY_ALL}); err != nil {
		t.Fatal(err)
	}
	if r, err := ac.EnsureEdgeAttachment(ctx, &agentv1.EnsureEdgeAttachmentRequest{Instance: ref, JobId: job()}); err != nil || !r.GetAttached() {
		t.Fatalf("EnsureEdgeAttachment: %v %v", r, err)
	}
	st0 := status()
	if !st0.GetActivated() || len(st0.GetNoiseKeyFingerprint()) != 64 || len(st0.GetConfigSha256()) != 64 {
		t.Fatalf("the tenant is not activated: %v", st0)
	}
	// data/: the keys byte for byte and the identity of the database file — the reconfiguration never touches them
	dataID := func() string {
		t.Helper()
		fi, err := os.Lstat(filepath.Join(dir, "data", "db.sqlite"))
		if err != nil {
			t.Fatal(err)
		}
		return fmt.Sprintf("noise=%s derp=%s db.ino=%d", fileSum(t, filepath.Join(dir, "data", "noise_private.key")),
			fileSum(t, filepath.Join(dir, "data", "derp_server_private.key")), fi.Sys().(*syscall.Stat_t).Ino)
	}
	data0 := dataID()
	// log lines of the container since a moment, by level
	levels := func(since time.Time) (map[string]int, string) {
		t.Helper()
		rc, err := dc.ContainerLogs(ctx, "mg-hs-"+ref.GetSlug(), client.ContainerLogsOptions{ShowStdout: true, ShowStderr: true,
			Since: since.Format(time.RFC3339Nano)})
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = rc.Close() }()
		var raw bytes.Buffer
		if _, err := io.Copy(&raw, rc); err != nil {
			t.Fatal(err)
		}
		out := map[string]int{}
		sc := bufio.NewScanner(bytes.NewReader(raw.Bytes()))
		for sc.Scan() {
			line := sc.Bytes()
			if i := bytes.IndexByte(line, '{'); i >= 0 { // the multiplexed stream header precedes the JSON
				var l struct {
					Level string `json:"level"`
				}
				if json.Unmarshal(line[i:], &l) == nil && l.Level != "" {
					out[l.Level]++
				}
			}
		}
		return out, raw.String()
	}
	if lv, _ := levels(time.Unix(0, 0)); lv["info"] == 0 {
		t.Fatalf("no info-level log line at the first start (log.level info): %v", lv)
	}

	// ---- the registry and the reconfiguration, as the worker builds them
	pj, _ := json.Marshal(params)
	v1 := uuid.New()
	instID, _ := uuid.Parse(ref.GetInstanceId())
	tenID, _ := uuid.Parse(ref.GetTenantId())
	store := &itStore{finished: map[uuid.UUID]bool{}, current: v1, order: []uuid.UUID{v1},
		versions: map[uuid.UUID]*orchestrator.ConfigVersion{v1: {ID: v1, Version: 1, Status: orchestrator.ConfigApplied,
			TemplateVersion: fmt.Sprint(st0.GetTemplateVersion()), ConfigSHA256: st0.GetConfigSha256(), Params: pj}},
		target: orchestrator.ReconfigureTarget{TenantSlug: ref.GetSlug(), TenantStatus: tenants.StatusActive,
			Instance: orchestrator.InstanceRecord{ID: instID, TenantID: tenID, Status: tenants.InstanceRunning, ImageDigest: digest,
				ControlHostname: ref.GetSlug() + ".mesh.agentit.test", RunUID: uid, NetCIDR: netip.MustParsePrefix(e.nets[4]),
				PublicEntryIPv4: netip.MustParseAddr("192.0.2.10"), NoiseFingerprint: st0.GetNoiseKeyFingerprint()}}}
	hs := &itHS{}
	fa := &faultAgent{Client: ac, t: t, file: filepath.Join(dir, "config", "config.yaml")}
	logs := &syncBuffer{}
	rc, err := orchestrator.NewReconfigurer(orchestrator.ReconfigureConfig{Store: store, Agent: fa, Headscale: itRegistry{hs},
		Logger: slog.New(slog.NewJSONHandler(logs, nil)), RetryBase: 200 * time.Millisecond, RetryMax: time.Second,
		HealthPoll: time.Second, HealthTimeout: 60 * time.Second, CallTimeout: 4 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	attempt := func(change orchestrator.ConfigChange) *itRunner {
		in := orchestrator.ReconfigureInput{TenantID: tenID, InstanceID: instID, Change: change, Source: orchestrator.SourcePlatform,
			Operation: audit.Operation{ID: uuid.New(), Action: orchestrator.ActionInstanceReconfigure, ActorType: audit.ActorSystem,
				ResourceType: "instance", ResourceID: ref.GetInstanceId()}}
		b, _ := json.Marshal(in)
		return &itRunner{id: uuid.New(), input: b}
	}
	stepLine := func(r *itRunner) string {
		var out []string
		for _, s := range r.steps {
			out = append(out, s.name+":"+s.status)
		}
		return strings.Join(out, ",")
	}
	configFile := func() string {
		t.Helper()
		b, err := os.ReadFile(fa.file) //nolint:gosec // G304: test
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}

	// ---- 1. a valid change: the new version on disk, running, healthy; Headscale really runs it
	days := uint32(30)
	r1 := attempt(orchestrator.ConfigChange{LogLevel: "warn", NodeExpiryDays: &days})
	start1 := time.Now()
	if err := rc.RunAttempt(ctx, r1); err != nil {
		t.Fatalf("valid change: %v (steps %s)\n%s", err, stepLine(r1), logs.String())
	}
	st1 := status()
	v2 := store.current
	sha1 := store.versions[v2].ConfigSHA256
	switch {
	case v2 == v1 || store.statusOf(v2) != orchestrator.ConfigApplied || store.statusOf(v1) != orchestrator.ConfigSuperseded:
		t.Fatalf("registry: current %s, v1 %s", v2, store.statusOf(v1))
	case st1.GetConfigSha256() != sha1 || sha1 == st0.GetConfigSha256():
		t.Fatalf("config on disk %s, version %s, before %s", st1.GetConfigSha256(), sha1, st0.GetConfigSha256())
	case st1.GetContainerState() != agentv1.ContainerState_CONTAINER_STATE_RUNNING || st1.GetHealth() != agentv1.HealthState_HEALTH_STATE_HEALTHY:
		t.Fatalf("after the change: %s %s", st1.GetContainerState(), st1.GetHealth())
	case !st1.GetStartedAt().AsTime().After(st0.GetStartedAt().AsTime()):
		t.Fatal("the container was not restarted")
	case st1.GetNoiseKeyFingerprint() != st0.GetNoiseKeyFingerprint() || dataID() != data0:
		t.Fatalf("data/ touched: %s → %s", data0, dataID())
	case !strings.Contains(configFile(), "  level: warn\n") || !strings.Contains(configFile(), "  expiry: 720h\n"):
		t.Fatalf("config.yaml:\n%s", configFile())
	case len(hs.checked) != 1 || strings.Contains(hs.checked[0], "//"):
		t.Fatalf("CheckPolicy got %q", hs.checked)
	}
	if lv, _ := levels(st1.GetStartedAt().AsTime()); lv["info"] != 0 {
		t.Fatalf("log.level warn is not live: %v info-level lines since the restart", lv)
	}
	t.Logf("valid change in %v: steps %s; sha256 %s… → %s…, restarted at %s, healthy, no info-level line since", time.Since(start1).Round(time.Second),
		stepLine(r1), st0.GetConfigSha256()[:12], sha1[:12], st1.GetStartedAt().AsTime().Format(time.RFC3339))

	// ---- 2. a configuration that passes configtest but fails at runtime ⇒ rolled back to the previous version
	fa.armed = true
	r2 := attempt(orchestrator.ConfigChange{LogLevel: "error"})
	start2 := time.Now()
	runErr := rc.RunAttempt(ctx, r2)
	if !jobs.IsPermanent(runErr) || jobs.CodeOf(runErr) != "instance_unhealthy" || !fa.injected {
		t.Fatalf("faulty configuration: %v (code %s, injected %v, steps %s)\n%s", runErr, jobs.CodeOf(runErr), fa.injected, stepLine(r2), logs.String())
	}
	_, failLogs := levels(start2)
	if !strings.Contains(failLogs, "address already in use") {
		t.Fatalf("Headscale did not fail at runtime as expected; container log since the restart:\n%s", failLogs)
	}
	healthDetail := string(r2.step(orchestrator.RStepHealth).detail)
	if err := rc.CompensateAttempt(ctx, r2, runErr); err != nil {
		t.Fatalf("rollback: %v\n%s", err, logs.String())
	}
	st2 := status()
	var failed uuid.UUID
	for id, v := range store.versions {
		if id != v1 && id != v2 {
			failed = id
			if v.Status != orchestrator.ConfigFailed {
				t.Fatalf("the faulty version is %s", v.Status)
			}
		}
	}
	switch {
	case failed == uuid.Nil || store.current != v2 || store.statusOf(v2) != orchestrator.ConfigApplied:
		t.Fatalf("registry after the rollback: current %s (want %s)", store.current, v2)
	case st2.GetConfigSha256() != sha1:
		t.Fatalf("config on disk after the rollback %s, want the previous version %s", st2.GetConfigSha256(), sha1)
	case st2.GetContainerState() != agentv1.ContainerState_CONTAINER_STATE_RUNNING || st2.GetHealth() != agentv1.HealthState_HEALTH_STATE_HEALTHY:
		t.Fatalf("after the rollback: %s %s", st2.GetContainerState(), st2.GetHealth())
	case !strings.Contains(configFile(), "listen_addr: 0.0.0.0:8080\n") || !strings.Contains(configFile(), "  level: warn\n"):
		t.Fatalf("config.yaml after the rollback:\n%s", configFile())
	case st2.GetNoiseKeyFingerprint() != st0.GetNoiseKeyFingerprint() || dataID() != data0:
		t.Fatalf("data/ touched: %s → %s", data0, dataID())
	case strings.Join(store.audit, "|") != "platform.instance.reconfigure.succeeded|platform.instance.reconfigure.failed instance_unhealthy|"+orchestrator.ActionConfigRollback+" success":
		t.Fatalf("audit %v", store.audit)
	}
	for _, s := range r2.steps {
		if s.comp != jobs.StepSucceeded && s.comp != jobs.StepSkipped {
			t.Errorf("step %s compensation %q", s.name, s.comp)
		}
	}
	t.Logf("faulty configuration (listen_addr on the metrics port — configtest passed, Serve: address already in use): steps %s; "+
		"health gate %s; rolled back in %v total: sha256 %s… again, running, healthy; data/ untouched (%s)",
		stepLine(r2), healthDetail, time.Since(start2).Round(time.Second), st2.GetConfigSha256()[:12], data0[:24])
}
