package orchestrator

// instance.restart, instance.upgrade and the upgrade wave against PostgreSQL 18 (storetest) with the real job framework
// (River worker), the real registry (DBStore), the API side (InstanceOpsService, Control) with the api's roles, the real
// policy core (drift_repair) and the real Headscale adapter path (locator + registry → the fake edge admin listener of
// headscaletest): tenants are provisioned by tenant.provision first (same worker). The Host Agent (a host model per
// instance: image, running, the data it holds), the backup subsystem (cold backup of that data, restore) and the prober
// are fakes — the real ones run in agent-it (TestUpgradeEndToEnd).

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "github.com/zhaduchanhzz/network-access-mesh/api/agent/v1"
	"github.com/zhaduchanhzz/network-access-mesh/infrastructure/headscale/templates"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale/headscaletest"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale/locator"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/platform"
	"github.com/zhaduchanhzz/network-access-mesh/internal/policies"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/backup"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/backupfmt"
	"github.com/zhaduchanhzz/network-access-mesh/internal/secrets"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/storetest"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
	"github.com/zhaduchanhzz/network-access-mesh/internal/usage"
)

var dbImgOld, dbImgNew = "sha256:" + strings.Repeat("d", 64), "sha256:" + strings.Repeat("e", 64)

// opsInst is what the host model keeps of one instance.
type opsInst struct {
	image   string
	running bool
	started time.Time
	sha     string
	data    string
}

// opsDBAgent is the agent of the provisioning DB tests plus the operations of restart and upgrade, one host model per
// instance. The configuration sha256 does not depend on the image (as config.yaml — the real agent).
type opsDBAgent struct {
	*edgeAgent
	mu        sync.Mutex
	inst      map[string]*opsInst
	failPre   map[string]bool // slug → configtest of the target refuses the copy
	unhealthy map[string]bool // image → never healthy
	detaches  int
}

func cfgSHA(spec *agentv1.InstanceSpec) string {
	p := paramsOf(spec)
	p.ImageDigest = ""
	return paramSHA(p)
}

func (a *opsDBAgent) get(id string) *opsInst {
	i := a.inst[id]
	if i == nil {
		i = &opsInst{data: "orig"}
		a.inst[id] = i
	}
	return i
}

func (a *opsDBAgent) GetHostInfo(context.Context, *agentv1.GetHostInfoRequest, ...grpc.CallOption) (*agentv1.GetHostInfoResponse, error) {
	return &agentv1.GetHostInfoResponse{TemplateVersion: 2, AllowedImages: []*agentv1.AllowedImage{{Digest: dbImgOld}, {Digest: dbImgNew}}}, nil
}

func (a *opsDBAgent) ValidateConfig(ctx context.Context, in *agentv1.ValidateConfigRequest, o ...grpc.CallOption) (*agentv1.ValidateConfigResponse, error) {
	r, err := a.edgeAgent.ValidateConfig(ctx, in, o...)
	if err != nil {
		return nil, err
	}
	r.ConfigSha256 = cfgSHA(in.GetSpec())
	return r, nil
}

func (a *opsDBAgent) EnsureInstance(ctx context.Context, in *agentv1.EnsureInstanceRequest, o ...grpc.CallOption) (*agentv1.EnsureInstanceResponse, error) {
	r, err := a.edgeAgent.EnsureInstance(ctx, in, o...)
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	i := a.get(in.GetSpec().GetInstance().GetInstanceId())
	switch in.GetTargetPhase() {
	case agentv1.TargetPhase_TARGET_PHASE_CONFIG:
		i.sha = cfgSHA(in.GetSpec())
		r.ConfigSha256, r.TemplateVersion = i.sha, 2
	case agentv1.TargetPhase_TARGET_PHASE_CONTAINER:
		i.image, i.running, i.started = in.GetSpec().GetImageDigest(), true, time.Now().UTC()
	}
	return r, nil
}

func (a *opsDBAgent) GetInstanceStatus(ctx context.Context, in *agentv1.GetInstanceStatusRequest, o ...grpc.CallOption) (*agentv1.GetInstanceStatusResponse, error) {
	r, err := a.edgeAgent.GetInstanceStatus(ctx, in, o...)
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	i := a.get(in.GetInstance().GetInstanceId())
	st := r.GetStatus()
	st.ConfigSha256, st.StartedAt, st.ImageDigest, st.Activated = i.sha, timestamppb.New(i.started), i.image, true
	if !i.running {
		st.ContainerState, st.Health = agentv1.ContainerState_CONTAINER_STATE_EXITED, agentv1.HealthState_HEALTH_STATE_NONE
	} else if a.unhealthy[i.image] {
		st.ContainerState, st.Health = agentv1.ContainerState_CONTAINER_STATE_RESTARTING, agentv1.HealthState_HEALTH_STATE_UNHEALTHY
	}
	return r, nil
}

func (a *opsDBAgent) start(id string) {
	i := a.get(id)
	i.running, i.started = true, i.started.Add(time.Second)
	if i.image != dbImgOld && !strings.HasPrefix(i.data, "migrated") {
		i.data = "migrated"
	}
}

func (a *opsDBAgent) RestartInstance(_ context.Context, in *agentv1.RestartInstanceRequest, _ ...grpc.CallOption) (*agentv1.RestartInstanceResponse, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.start(in.GetInstance().GetInstanceId())
	return &agentv1.RestartInstanceResponse{Status: &agentv1.InstanceStatus{ContainerState: agentv1.ContainerState_CONTAINER_STATE_RUNNING}}, nil
}

func (a *opsDBAgent) StartInstance(_ context.Context, in *agentv1.StartInstanceRequest, _ ...grpc.CallOption) (*agentv1.StartInstanceResponse, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.start(in.GetInstance().GetInstanceId())
	return &agentv1.StartInstanceResponse{Status: &agentv1.InstanceStatus{ContainerState: agentv1.ContainerState_CONTAINER_STATE_RUNNING}}, nil
}

func (a *opsDBAgent) StopInstance(_ context.Context, in *agentv1.StopInstanceRequest, _ ...grpc.CallOption) (*agentv1.StopInstanceResponse, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.get(in.GetInstance().GetInstanceId()).running = false
	return &agentv1.StopInstanceResponse{Status: &agentv1.InstanceStatus{ContainerState: agentv1.ContainerState_CONTAINER_STATE_EXITED}}, nil
}

func (a *opsDBAgent) UpgradeInstance(_ context.Context, in *agentv1.UpgradeInstanceRequest, _ ...grpc.CallOption) (*agentv1.UpgradeInstanceResponse, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	i := a.get(in.GetInstance().GetInstanceId())
	if i.running || (i.image != in.GetFromImageDigest() && i.image != in.GetToImageDigest()) || cfgSHA(in.GetSpec()) != i.sha {
		return nil, refused(codes.FailedPrecondition, agentv1.RefusalReason_REFUSAL_REASON_STATE, "switch refused")
	}
	i.image = in.GetToImageDigest()
	return &agentv1.UpgradeInstanceResponse{Status: &agentv1.InstanceStatus{ContainerState: agentv1.ContainerState_CONTAINER_STATE_CREATED,
		ImageDigest: i.image}}, nil
}

func (a *opsDBAgent) InspectImage(_ context.Context, in *agentv1.InspectImageRequest, _ ...grpc.CallOption) (*agentv1.InspectImageResponse, error) {
	return &agentv1.InspectImageResponse{ImageDigest: in.GetImageDigest(), HeadscaleVersion: "v0.29.7"}, nil
}

func (a *opsDBAgent) PreflightUpgrade(_ context.Context, in *agentv1.PreflightUpgradeRequest, _ ...grpc.CallOption) (*agentv1.PreflightUpgradeResponse, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	i := a.get(in.GetSpec().GetInstance().GetInstanceId())
	if i.running || len(in.GetDataKey()) != 32 {
		return nil, errors.New("preflight of a running instance or without a data key")
	}
	if a.failPre[in.GetSpec().GetInstance().GetSlug()] {
		return &agentv1.PreflightUpgradeResponse{Valid: false, ExitCode: 1, Detail: "initializing policy manager", ConfigSha256: i.sha}, nil
	}
	return &agentv1.PreflightUpgradeResponse{Valid: true, ConfigSha256: i.sha, TargetHeadscaleVersion: "v0.29.7", BackupHeadscaleVersion: "0.29.7"}, nil
}

func (a *opsDBAgent) RemoveEdgeAttachment(ctx context.Context, in *agentv1.RemoveEdgeAttachmentRequest, o ...grpc.CallOption) (*agentv1.RemoveEdgeAttachmentResponse, error) {
	a.mu.Lock()
	a.detaches++
	a.mu.Unlock()
	return a.edgeAgent.RemoveEdgeAttachment(ctx, in, o...)
}

func (a *opsDBAgent) state(id uuid.UUID) opsInst {
	a.mu.Lock()
	defer a.mu.Unlock()
	return *a.get(id.String())
}

// dbBackups is the backup subsystem over the host model.
type dbBackups struct {
	a     *opsDBAgent
	mu    sync.Mutex
	taken map[uuid.UUID][2]string // backup → instance, data
}

func (b *dbBackups) Ready() error { return nil }

func (b *dbBackups) ColdBackup(_ context.Context, _, _, inst uuid.UUID) (backup.BackupResult, error) {
	s := b.a.state(inst)
	if s.running {
		return backup.BackupResult{}, jobs.Permanent("backup_not_cold", errors.New("running"))
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	id := uuid.New()
	b.taken[id] = [2]string{inst.String(), s.data}
	return backup.BackupResult{BackupID: id, Sequence: uint64(len(b.taken)), Method: backupfmt.MethodColdCopy}, nil //nolint:gosec // test
}

func (b *dbBackups) OpenBackup(_ context.Context, _, _, _, id uuid.UUID) (backup.OpenedBackup, error) {
	return backup.OpenedBackup{Artifact: &agentv1.ArtifactRef{Sequence: 1, ArchiveSha256: strings.Repeat("1", 64),
		ManifestSha256: strings.Repeat("2", 64)}, DataKey: make([]byte, 32)}, nil
}

func (b *dbBackups) RollbackRestore(_ context.Context, _, _, inst, id uuid.UUID) (map[string]any, error) {
	b.mu.Lock()
	taken := b.taken[id]
	b.mu.Unlock()
	b.a.mu.Lock()
	defer b.a.mu.Unlock()
	i := b.a.get(inst.String())
	if i.running || i.image != dbImgOld || taken[0] != inst.String() {
		return nil, errors.New("restore: stopped on the previous image, a backup of this instance")
	}
	i.data = taken[1]
	b.a.start(inst.String())
	return map[string]any{"restored": true}, nil
}

type opsDBRig struct {
	*dbRig
	ag     *opsDBAgent
	svc    *InstanceOpsService
	reject map[string]bool // slug → the instance refuses the platform's API key (database replaced)
}

func newOpsDBRig(t *testing.T) *opsDBRig {
	t.Helper()
	env := storetest.Require(t)
	db := env.NewDatabase(t)
	g := &dbRig{su: env.Admin(t, db), api: env.OpenStore(t, db, "mg_api_tenant", "mg_api_platform", 6),
		wrk: env.OpenStore(t, db, "mg_worker_tenant", "mg_worker_platform", 10), actor: uuid.New(), host: uuid.New(),
		policy: map[string]string{}}
	g.exec(t, `INSERT INTO hosts (id, name, region, run_uid_range, tenant_net_pool, public_entry)
		VALUES ($1, 'host-1', 'lab', int4range(30000, 30100), '10.250.0.0/24', '{"ipv4": "192.0.2.10", "mode": "direct"}')`, g.host)
	// the platform staff who receive instance.operation_failed (super_admin, verified e-mail)
	pidp, ident := uuid.New(), uuid.New()
	g.exec(t, `INSERT INTO identity_providers (id, scope, issuer, client_id, driver, status)
		VALUES ($1, 'platform', 'https://idp.invalid/realms/platform-ops', 'mg-admin', 'keycloak', 'active')`, pidp)
	g.exec(t, `INSERT INTO identities (id, idp_id, scope, subject, email, email_verified, display_name)
		VALUES ($1, $2, 'platform', 'sa-ops', 'sa@platform.test', true, 'SA')`, ident, pidp)
	g.exec(t, `INSERT INTO platform_users (identity_id, role_id, status)
		SELECT $1, id, 'active' FROM roles WHERE scope = 'platform' AND key = 'super_admin'`, ident)
	dir := t.TempDir()
	k := make([]byte, 32)
	_, _ = rand.Read(k)
	writeFile(t, filepath.Join(dir, "kek-1"), hex.EncodeToString(k)+"\n")
	writeFile(t, filepath.Join(dir, secrets.ActiveFile), "kek-1\n")
	kr, err := secrets.LoadKeyring(secrets.KEKApp, dir)
	if err != nil {
		t.Fatal(err)
	}
	apiSec, err := secrets.New(g.api, secrets.Options{App: kr})
	if err != nil {
		t.Fatal(err)
	}
	wrkSec, err := secrets.New(g.wrk, secrets.Options{App: kr})
	if err != nil {
		t.Fatal(err)
	}
	r := &opsDBRig{dbRig: g, reject: map[string]bool{}}
	canonical, err := policies.Lint(templates.BootstrapPolicy)
	if err != nil {
		t.Fatal(err)
	}
	tok := headscaletest.NewToken()
	g.edge = headscaletest.NewEdge(t, tok)
	g.edge.SetHook(func(rq headscaletest.Request, _ int) (int, string, bool) {
		g.mu.Lock()
		defer g.mu.Unlock()
		if r.reject[rq.Slug] && strings.HasPrefix(rq.Path, "/api/v1/") {
			return 401, "Unauthorized", true
		}
		switch {
		case rq.Method == "GET" && rq.Path == "/api/v1/policy":
			b, _ := json.Marshal(map[string]string{"policy": g.policy[rq.Slug], "updatedAt": time.Now().UTC().Format(time.RFC3339)})
			return 200, string(b), true
		case rq.Method == "POST" && rq.Path == "/api/v1/policy/check":
			return 200, `{}`, true
		case rq.Method == "PUT" && rq.Path == "/api/v1/policy": // the policy core sets the canonical baseline
			g.policy[rq.Slug] = canonical.Applied
			b, _ := json.Marshal(map[string]string{"policy": canonical.Applied, "updatedAt": time.Now().UTC().Format(time.RFC3339)})
			return 200, string(b), true
		case rq.Method == "GET" && rq.Path == "/api/v1/user":
			return 200, `{"users": []}`, true
		case rq.Method == "GET" && rq.Path == "/api/v1/node":
			return 200, `{"nodes": []}`, true
		case rq.Method == "GET" && rq.Path == "/api/v1/preauthkey":
			return 200, `{"preAuthKeys": []}`, true
		}
		return 0, "", false
	})
	tokenFile := filepath.Join(t.TempDir(), "edge_admin_token")
	writeFile(t, tokenFile, tok+"\n")
	ten := tenants.New(g.wrk, tenants.Options{BaseDomain: testDomain})
	loc, err := locator.New(ten, wrkSec, locator.Options{AdminURL: g.edge.URL(), EdgeTokenFile: tokenFile})
	if err != nil {
		t.Fatal(err)
	}
	reg := headscale.NewRegistry(loc, headscale.Options{Retry: headscale.RetryPolicy{Attempts: 1}})
	placer, err := platform.NewPlacer(g.wrk, platform.PlacerOptions{BaseDomain: testDomain})
	if err != nil {
		t.Fatal(err)
	}
	g.agent = &edgeAgent{fakeAgent: newFakeAgent(), edge: g.edge, insts: map[string]*headscaletest.Instance{}}
	r.ag = &opsDBAgent{edgeAgent: g.agent, inst: map[string]*opsInst{}, failPre: map[string]bool{}, unhealthy: map[string]bool{}}
	g.prober = &fakeProber{relay: ProbeResult{OK: true}, edge: ProbeResult{OK: true}}
	g.kc = &fakeIdP{name: DriverKeycloak, realms: map[string]string{}}
	dns := dnsFunc(func(_ context.Context, _ string, want netip.Addr) (DNSResult, error) {
		return DNSResult{Addresses: []netip.Addr{want}, OK: true}, nil
	})
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	p, err := New(Config{Store: NewDBStore(g.wrk, nil), Agent: r.ag, Placer: placer, Secrets: wrkSec,
		IdP: fakeDrivers{DriverKeycloak: g.kc}, Headscale: reg, DNS: dns, Prober: g.prober, Logger: log,
		HeadscaleDigest: dbImgOld, HeadscaleVersion: "v0.29.7",
		Nameservers: []netip.Addr{netip.MustParseAddr("1.1.1.1")}, EdgeAddress: "10.249.0.2:443",
		RetryBase: 20 * time.Millisecond, RetryMax: 50 * time.Millisecond, HealthPoll: 10 * time.Millisecond,
		HealthTimeout: 500 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	core, err := policies.New(g.wrk, policies.Config{Registry: reg, Logger: log})
	if err != nil {
		t.Fatal(err)
	}
	oc := InstanceOpsConfig{Store: NewDBStore(g.wrk, nil), Agent: r.ag, Headscale: reg, Policies: core,
		Backups: &dbBackups{a: r.ag, taken: map[uuid.UUID][2]string{}}, Prober: g.prober, Security: dbSecurity{g.wrk}, Logger: log,
		EdgeAddress: "10.249.0.2:443", RetryBase: 20 * time.Millisecond, RetryMax: 50 * time.Millisecond,
		HealthPoll: 10 * time.Millisecond, HealthTimeout: 500 * time.Millisecond}
	rs, err := NewRestarter(oc)
	if err != nil {
		t.Fatal(err)
	}
	up, err := NewUpgrader(oc)
	if err != nil {
		t.Fatal(err)
	}
	cfg := jobs.DefaultConfig()
	cfg.FetchCooldown, cfg.FetchPollInterval = 10*time.Millisecond, 50*time.Millisecond
	cfg.RetryBase, cfg.RetryMax = 50*time.Millisecond, 200*time.Millisecond
	cfg.LockBusySnooze, cfg.LockHeldSnooze = 100*time.Millisecond, 200*time.Millisecond
	cfg.StartJitter, cfg.SoftStopTimeout, cfg.QueuePoolConns = 0, 2*time.Second, 4
	w, err := jobs.NewWorker(g.wrk, cfg, jobs.Options{Registerer: prometheus.NewRegistry()})
	if err != nil {
		t.Fatal(err)
	}
	for _, reg := range []interface{ Register(*jobs.Worker) error }{p, rs, up} {
		if err := reg.Register(w); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = w.Stop(ctx)
	})
	g.worker = w
	if g.creator, err = NewCreator(CreatorConfig{Store: g.api, Secrets: apiSec, Quota: usage.NewChecker(g.api),
		QuotaTx: usage.TenantCreationTx, BaseDomain: testDomain}); err != nil {
		t.Fatal(err)
	}
	g.control = NewControl(g.api)
	r.svc = NewInstanceOpsService(g.api)
	return r
}

// provision creates a tenant with tenant.provision and returns its instance.
func (r *opsDBRig) provision(t *testing.T, slug string) uuid.UUID {
	t.Helper()
	c := r.create(t, slug)
	r.waitJob(t, c.Job.ID, jobs.StatusSucceeded)
	return dbScalar[uuid.UUID](t, r.dbRig, `SELECT id FROM tenant_instances WHERE tenant_id = $1`, c.TenantID)
}

func (r *opsDBRig) restart(t *testing.T, inst uuid.UUID, key string) (Reconfigured, error) {
	t.Helper()
	return r.svc.Restart(r.reqCtx(t, ActionInstanceRestart), r.actor, inst, &Idempotency{Key: key, Hash: []byte(strings.Repeat("s", 32))})
}

func (r *opsDBRig) upgrade(t *testing.T, inst uuid.UUID, digest, key string) (Reconfigured, error) {
	t.Helper()
	return r.svc.Upgrade(r.reqCtx(t, ActionInstanceUpgrade), r.actor, inst, digest,
		&Idempotency{Key: key, Hash: []byte(strings.Repeat("u", 31) + digest[len(digest)-1:])})
}

func (r *opsDBRig) audit(t *testing.T, inst, job uuid.UUID) string {
	t.Helper()
	return dbScalar[string](t, r.dbRig, `SELECT string_agg(action || '/' || outcome, ',' ORDER BY occurred_at) FROM audit_events
		WHERE action LIKE 'platform.instance.%' AND resource_id = $1::text
		AND occurred_at >= (SELECT created_at FROM provisioning_jobs WHERE id = $2)`, inst, job)
}

func TestInstanceOpsDB(t *testing.T) {
	g := newOpsDBRig(t)
	inst := g.provision(t, "acme")

	// ---- 1. restart: 202, replay, the five steps, the audit pair
	r, err := g.restart(t, inst, "rs-key-0001")
	if err != nil || !r.Created || r.Job.Kind != RestartKind {
		t.Fatalf("restart %v %+v", err, r)
	}
	if again, err := g.restart(t, inst, "rs-key-0001"); err != nil || !again.Replayed || again.Job.ID != r.Job.ID {
		t.Fatalf("replay %v %+v", err, again)
	}
	g.waitJob(t, r.Job.ID, jobs.StatusSucceeded)
	if got := dbScalar[string](t, g.dbRig, `SELECT string_agg(name || ':' || status, ',' ORDER BY seq) FROM provisioning_job_steps WHERE job_id = $1`,
		r.Job.ID); got != "instance.restart:succeeded,instance.health:succeeded,policy.gate:succeeded,edge.verify:succeeded,restart.finish:succeeded" {
		t.Fatal(got)
	}
	if got := g.audit(t, inst, r.Job.ID); got != "platform.instance.restart.requested/success,platform.instance.restart.succeeded/success" {
		t.Fatal(got)
	}

	// ---- 2. post-start gate: a policy changed out of band before the restart ⇒ applied again (drift_repair)
	g.setPolicy("acme", `{"grants": [{"src": ["*"], "dst": ["*"], "ip": ["*"]}]}`)
	d, err := g.restart(t, inst, "rs-key-0002")
	if err != nil {
		t.Fatal(err)
	}
	g.waitJob(t, d.Job.ID, jobs.StatusSucceeded)
	canonical, _ := policies.Lint(templates.BootstrapPolicy)
	g.mu.Lock()
	served := g.policy["acme"]
	g.mu.Unlock()
	if served != canonical.Applied {
		t.Fatalf("the instance serves %q after the restart", served)
	}
	for q, want := range map[string]string{
		`SELECT trigger || '/' || state FROM policy_applications WHERE instance_id = $1 AND superseded_at IS NULL`:                                                                                                                       "drift_repair/applied",
		`SELECT count(*)::text FROM security_events WHERE kind = 'instance.policy_drift' AND severity = 'high' AND details->>'instance_id' = $1::text`:                                                                                   "1",
		`SELECT detail->>'post_start_gate' FROM provisioning_job_steps WHERE name = 'policy.gate' AND job_id = (SELECT id FROM provisioning_jobs WHERE instance_id = $1 AND kind = 'instance.restart' ORDER BY created_at DESC LIMIT 1)`: "repaired",
	} {
		if got := dbScalar[string](t, g.dbRig, q, inst); got != want {
			t.Errorf("%s = %q, want %q", q, got, want)
		}
	}

	// ---- 3. db.sqlite replaced by an empty database: the platform's API key refused ⇒ Critical, edge detached, rolled_back,
	// platform staff notified
	g.mu.Lock()
	g.reject["acme"] = true
	g.mu.Unlock()
	x, err := g.restart(t, inst, "rs-key-0003")
	if err != nil {
		t.Fatal(err)
	}
	g.waitJob(t, x.Job.ID, jobs.StatusRolledBack)
	g.mu.Lock()
	g.reject["acme"] = false
	g.mu.Unlock()
	for q, want := range map[string]string{
		`SELECT error->>'code' FROM provisioning_jobs WHERE id = $1`:                                                                                                  "database_replaced",
		`SELECT count(*)::text FROM security_events WHERE kind = 'instance.database_replaced' AND severity = 'critical' AND details->>'job_id' = $1::text`:            "1",
		`SELECT count(*)::text FROM notification_outbox WHERE kind = 'instance.operation_failed' AND tenant_id IS NULL AND payload->>'job_id' = $1::text`:             "1",
		`SELECT payload->>'outcome' || '/' || (payload->>'code') FROM notification_outbox WHERE kind = 'instance.operation_failed' AND payload->>'job_id' = $1::text`: "rolled_back/database_replaced",
	} {
		if got := dbScalar[string](t, g.dbRig, q, x.Job.ID); got != want {
			t.Errorf("%s = %q, want %q", q, got, want)
		}
	}
	if g.ag.detaches != 1 {
		t.Fatalf("%d edge detachments", g.ag.detaches)
	}
	if got := g.audit(t, inst, x.Job.ID); got != "platform.instance.restart.requested/success,platform.instance.restart.failed/failure" {
		t.Fatal(got)
	}

	// ---- 4. upgrade: the registry on the target image with a new configuration version (same sha256)
	v1 := dbScalar[string](t, g.dbRig, `SELECT config_version_id::text FROM tenant_instances WHERE id = $1`, inst)
	sha1 := dbScalar[string](t, g.dbRig, `SELECT c.config_sha256 FROM tenant_instances i JOIN instance_config_versions c ON c.id = i.config_version_id WHERE i.id = $1`, inst)
	u, err := g.upgrade(t, inst, dbImgNew, "up-key-0001")
	if err != nil || !u.Created || u.Job.Kind != UpgradeKind {
		t.Fatalf("upgrade %v %+v", err, u)
	}
	g.waitJob(t, u.Job.ID, jobs.StatusSucceeded)
	for q, want := range map[string]string{
		`SELECT image_digest || '/' || headscale_version FROM tenant_instances WHERE id = $1`:                                                                                                                 dbImgNew + "/v0.29.7",
		`SELECT string_agg(status, ',' ORDER BY version) FROM instance_config_versions WHERE instance_id = $1`:                                                                                                "superseded,applied",
		`SELECT c.params->>'image_digest' FROM tenant_instances i JOIN instance_config_versions c ON c.id = i.config_version_id WHERE i.id = $1`:                                                              dbImgNew,
		`SELECT c.config_sha256 FROM tenant_instances i JOIN instance_config_versions c ON c.id = i.config_version_id WHERE i.id = $1`:                                                                        sha1,
		`SELECT string_agg(s.name || ':' || s.status, ',' ORDER BY s.seq) FROM provisioning_job_steps s JOIN provisioning_jobs j ON j.id = s.job_id WHERE j.instance_id = $1 AND j.kind = 'instance.upgrade'`: "upgrade.preflight:succeeded,instance.stop:succeeded,backup.cold:succeeded,upgrade.configtest:succeeded,image.switch:succeeded,instance.start:succeeded,instance.health:succeeded,policy.gate:succeeded,upgrade.smoke:succeeded,edge.verify:succeeded,upgrade.finish:succeeded",
	} {
		if got := dbScalar[string](t, g.dbRig, q, inst); got != want {
			t.Errorf("%s = %q, want %q", q, got, want)
		}
	}
	if dbScalar[string](t, g.dbRig, `SELECT config_version_id::text FROM tenant_instances WHERE id = $1`, inst) == v1 {
		t.Fatal("the instance still points at the previous configuration version")
	}
	if got := g.audit(t, inst, u.Job.ID); got != "platform.instance.upgrade.requested/success,platform.instance.upgrade.succeeded/success" {
		t.Fatal(got)
	}
	if s := g.ag.state(inst); s.image != dbImgNew || !s.running || s.data != "migrated" {
		t.Fatalf("host %+v", s)
	}

	// ---- 5. API refusals
	var ce *CreateError
	if _, err := g.upgrade(t, inst, dbImgNew, "up-key-0002"); !errors.As(err, &ce) || ce.Reason != "already_on_target" {
		t.Fatalf("already on target: %v", err)
	}
	if _, err := g.upgrade(t, uuid.New(), dbImgOld, "up-key-0003"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown instance: %v", err)
	}
	if _, err := g.svc.Upgrade(g.reqCtx(t, ActionInstanceUpgrade), g.actor, inst, "latest", nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("tag: %v", err)
	}
	g.exec(t, `UPDATE tenant_instances SET status = 'quarantined' WHERE id = $1`, inst)
	if _, err := g.restart(t, inst, "rs-key-0004"); !errors.As(err, &ce) || ce.Reason != "instance_quarantined" {
		t.Fatalf("quarantined restart: %v", err)
	}
	if _, err := g.upgrade(t, inst, dbImgOld, "up-key-0004"); !errors.As(err, &ce) || ce.Reason != "instance_quarantined" {
		t.Fatalf("quarantined upgrade: %v", err)
	}
	g.exec(t, `UPDATE tenant_instances SET status = 'running' WHERE id = $1`, inst)

	// ---- 6. configtest of the target refuses the copy ⇒ the previous image again, registry unchanged, rolled_back
	g.ag.mu.Lock()
	g.ag.failPre["acme"] = true
	g.ag.mu.Unlock()
	f, err := g.upgrade(t, inst, dbImgOld, "up-key-0005") // (back to the old digest: another build of the same version)
	if err != nil {
		t.Fatal(err)
	}
	g.waitJob(t, f.Job.ID, jobs.StatusRolledBack)
	g.ag.mu.Lock()
	g.ag.failPre["acme"] = false
	g.ag.mu.Unlock()
	if s := g.ag.state(inst); s.image != dbImgNew || !s.running || s.data != "migrated" {
		t.Fatalf("host after a refused preflight %+v", s)
	}
	if got := dbScalar[string](t, g.dbRig, `SELECT error->>'code' FROM provisioning_jobs WHERE id = $1`, f.Job.ID); got != "preflight_failed" {
		t.Errorf("code %q", got)
	}
	if got := dbScalar[string](t, g.dbRig, `SELECT image_digest FROM tenant_instances WHERE id = $1`, inst); got != dbImgNew {
		t.Errorf("registry image %q", got)
	}

	// ---- 7. one unfinished upgrade per instance; /cancel closes its operation
	if err := g.worker.Stop(t.Context()); err != nil {
		t.Fatal(err)
	}
	q1, err := g.upgrade(t, inst, dbImgOld, "up-key-0006")
	if err != nil || !q1.Created {
		t.Fatalf("queued %v %+v", err, q1)
	}
	if q2, err := g.upgrade(t, inst, dbImgOld, "up-key-0007"); err != nil || q2.Created || q2.Job.ID != q1.Job.ID {
		t.Fatalf("same target %v %+v", err, q2)
	}
	cr, err := g.control.Cancel(g.reqCtx(t, ActionJobCancel), g.actor, q1.Job.ID, nil)
	if err != nil || cr.Job.Status != jobs.StatusCancelled {
		t.Fatalf("cancel %v %+v", err, cr)
	}
	if got := dbScalar[string](t, g.dbRig, `SELECT details->>'reason' FROM audit_events WHERE action = 'platform.instance.upgrade.failed'
		AND operation_id = (SELECT (input->'operation'->>'id')::uuid FROM provisioning_jobs WHERE id = $1)`, q1.Job.ID); got != "cancelled" {
		t.Fatalf("cancelled audit %q", got)
	}
	if n := dbScalar[int64](t, g.dbRig, `SELECT count(*) FROM audit_events r WHERE r.action IN ('platform.instance.restart.requested', 'platform.instance.upgrade.requested')
		AND NOT EXISTS (SELECT 1 FROM audit_events f WHERE f.operation_id = r.operation_id AND f.action <> r.action)`); n != 0 {
		t.Fatalf("%d open operations", n)
	}
}

// TestUpgradeWaveDB — §11.4 "canary trước, rồi từng nhóm, tự dừng ở lỗi đầu tiên": the canary alone, then the rest
// with at most N unfinished upgrades; the first failure stops the wave (the instances after it are never enqueued); an
// instance already on the target is skipped; a dry run enqueues nothing.
func TestUpgradeWaveDB(t *testing.T) {
	g := newOpsDBRig(t)
	ids := map[string]uuid.UUID{}
	for _, s := range []string{"wave-a", "wave-b", "wave-c", "wave-d", "wave-e"} {
		ids[s] = g.provision(t, s)
	}
	var events []WaveEvent
	run := func(cfg WaveConfig) (WaveReport, error) {
		events = nil
		cfg.Store, cfg.ImageDigest, cfg.Poll = g.wrk, dbImgNew, 50*time.Millisecond
		cfg.Progress = func(e WaveEvent) { events = append(events, e) }
		return RunUpgradeWave(t.Context(), cfg)
	}
	// dry run of --all: the five, nothing enqueued
	rep, err := run(WaveConfig{All: true, Canary: ids["wave-c"], DryRun: true})
	if err != nil || rep.Planned != 5 || rep.Canary != ids["wave-c"] || len(events) != 5 ||
		dbScalar[int64](t, g.dbRig, `SELECT count(*) FROM provisioning_jobs WHERE kind = 'instance.upgrade'`) != 0 {
		t.Fatalf("dry run %v %+v %d", err, rep, len(events))
	}
	// the canary fails ⇒ nothing else is enqueued
	g.ag.mu.Lock()
	g.ag.failPre["wave-a"] = true
	g.ag.mu.Unlock()
	rep, err = run(WaveConfig{Canary: ids["wave-a"], Instances: []uuid.UUID{ids["wave-b"], ids["wave-c"]}})
	if !errors.Is(err, ErrWaveStopped) || !rep.Stopped || len(rep.Failed) != 1 || rep.Failed[0].Code != "preflight_failed" ||
		dbScalar[int64](t, g.dbRig, `SELECT count(*) FROM provisioning_jobs WHERE kind = 'instance.upgrade'`) != 1 {
		t.Fatalf("canary failure %v %+v", err, rep)
	}
	// canary b succeeds; then c, d (max 2 in flight); d fails ⇒ e never enqueued; a skipped? (a still old — failed)
	g.ag.mu.Lock()
	g.ag.failPre["wave-a"], g.ag.failPre["wave-d"] = false, true
	g.ag.mu.Unlock()
	rep, err = run(WaveConfig{Canary: ids["wave-b"], Instances: []uuid.UUID{ids["wave-c"], ids["wave-d"], ids["wave-e"]}, MaxParallel: 2})
	if !errors.Is(err, ErrWaveStopped) || rep.Succeeded < 2 || len(rep.Failed) != 1 || rep.Failed[0].Instance != ids["wave-d"] {
		t.Fatalf("wave %v %+v", err, rep)
	}
	enqueued := dbScalar[int64](t, g.dbRig, `SELECT count(*) FROM provisioning_jobs WHERE kind = 'instance.upgrade' AND instance_id = $1`, ids["wave-e"])
	if rep.Succeeded == 2 && enqueued != 0 {
		t.Fatalf("e was enqueued after the failure of d (%+v)", rep)
	}
	for _, s := range []string{"wave-b", "wave-c"} {
		if got := dbScalar[string](t, g.dbRig, `SELECT image_digest FROM tenant_instances WHERE id = $1`, ids[s]); got != dbImgNew {
			t.Fatalf("%s on %s", s, got)
		}
	}
	// --all, all good now: b and c are skipped (already on the target), a, d, e upgraded
	g.ag.mu.Lock()
	g.ag.failPre["wave-d"] = false
	g.ag.mu.Unlock()
	rep, err = run(WaveConfig{All: true, MaxParallel: 3})
	if err != nil || rep.Stopped || rep.Succeeded+rep.Skipped != rep.Planned {
		t.Fatalf("--all %v %+v", err, rep)
	}
	if n := dbScalar[int64](t, g.dbRig, `SELECT count(*) FROM tenant_instances WHERE image_digest = $1`, dbImgNew); n != 5 {
		t.Fatalf("%d instances on the target", n)
	}
	// the audit of the wave's upgrades: system actor, source admin_wave
	if got := dbScalar[string](t, g.dbRig, `SELECT DISTINCT actor_type || '/' || (details->>'source') FROM audit_events
		WHERE action = 'platform.instance.upgrade.requested'`); got != "system/admin_wave" {
		t.Fatalf("audit of the wave %q", got)
	}
}
