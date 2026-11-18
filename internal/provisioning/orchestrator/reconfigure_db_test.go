package orchestrator

// instance.reconfigure against PostgreSQL 18 (storetest) with the real job framework (River worker), the real registry
// (DBStore), the API side (ReconfigureService, Control) with the api's roles, and the real Headscale adapter path
// (locator + registry → the fake edge admin listener of headscaletest): a tenant is provisioned by tenant.provision
// first (same worker), then reconfigured. Only the Host Agent (a host model whose configuration sha256 follows the
// typed parameters and whose container loads it at each restart) and the prober are fakes.

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
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "github.com/zhaduchanhzz/network-access-mesh/api/agent/v1"
	"github.com/zhaduchanhzz/network-access-mesh/infrastructure/headscale/templates"
	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale/headscaletest"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale/locator"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/platform"
	"github.com/zhaduchanhzz/network-access-mesh/internal/secrets"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/storetest"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
	"github.com/zhaduchanhzz/network-access-mesh/internal/usage"
)

// cfgAgent is the edge agent of the provisioning DB tests plus what a reconfiguration needs: the configuration
// sha256 follows the typed parameters, the container loads the configuration on disk at each restart, a parameter set
// may fail at runtime (passes configtest, never healthy), and RestartInstance may be unavailable.
type cfgAgent struct {
	*edgeAgent
	mu          sync.Mutex
	file, run   configParams
	started     time.Time
	restarts    int
	crash       func(configParams) bool
	unavailable bool // RestartInstance answers UNAVAILABLE
}

func (a *cfgAgent) GetHostInfo(context.Context, *agentv1.GetHostInfoRequest, ...grpc.CallOption) (*agentv1.GetHostInfoResponse, error) {
	return &agentv1.GetHostInfoResponse{TemplateVersion: 2}, nil
}

func (a *cfgAgent) ValidateConfig(ctx context.Context, in *agentv1.ValidateConfigRequest, o ...grpc.CallOption) (*agentv1.ValidateConfigResponse, error) {
	r, err := a.edgeAgent.ValidateConfig(ctx, in, o...)
	if err != nil {
		return nil, err
	}
	r.ConfigSha256 = paramSHA(paramsOf(in.GetSpec()))
	return r, nil
}

func (a *cfgAgent) EnsureInstance(ctx context.Context, in *agentv1.EnsureInstanceRequest, o ...grpc.CallOption) (*agentv1.EnsureInstanceResponse, error) {
	r, err := a.edgeAgent.EnsureInstance(ctx, in, o...)
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	switch in.GetTargetPhase() {
	case agentv1.TargetPhase_TARGET_PHASE_CONFIG:
		a.file = paramsOf(in.GetSpec())
		r.ConfigSha256, r.TemplateVersion = paramSHA(a.file), 2
	case agentv1.TargetPhase_TARGET_PHASE_CONTAINER:
		a.run, a.started = a.file, time.Now().UTC()
	}
	return r, nil
}

func (a *cfgAgent) GetInstanceStatus(ctx context.Context, in *agentv1.GetInstanceStatusRequest, o ...grpc.CallOption) (*agentv1.GetInstanceStatusResponse, error) {
	r, err := a.edgeAgent.GetInstanceStatus(ctx, in, o...)
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	st := r.GetStatus()
	st.ConfigSha256, st.StartedAt = paramSHA(a.file), timestamppb.New(a.started)
	if a.crash != nil && a.crash(a.run) {
		st.ContainerState, st.Health = agentv1.ContainerState_CONTAINER_STATE_RESTARTING, agentv1.HealthState_HEALTH_STATE_UNHEALTHY
	}
	return r, nil
}

func (a *cfgAgent) RestartInstance(context.Context, *agentv1.RestartInstanceRequest, ...grpc.CallOption) (*agentv1.RestartInstanceResponse, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.unavailable {
		return nil, status.Error(codes.Unavailable, "agent unavailable")
	}
	a.run, a.restarts = a.file, a.restarts+1
	a.started = a.started.Add(time.Second)
	return &agentv1.RestartInstanceResponse{Status: &agentv1.InstanceStatus{ContainerState: agentv1.ContainerState_CONTAINER_STATE_RUNNING}}, nil
}

func (a *cfgAgent) host() (file, run string, restarts int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return paramSHA(a.file), paramSHA(a.run), a.restarts
}

func (a *cfgAgent) set(fn func(a *cfgAgent)) {
	a.mu.Lock()
	defer a.mu.Unlock()
	fn(a)
}

type rcDBRig struct {
	*dbRig
	cfg  *cfgAgent
	svc  *ReconfigureService
	tid  uuid.UUID
	inst uuid.UUID
}

// newReconfigureDBRig provisions tenant "acme" with tenant.provision, then returns the rig with instance.reconfigure
// registered on the same worker.
func newReconfigureDBRig(t *testing.T) *rcDBRig {
	t.Helper()
	env := storetest.Require(t)
	db := env.NewDatabase(t)
	g := &dbRig{su: env.Admin(t, db), api: env.OpenStore(t, db, "mg_api_tenant", "mg_api_platform", 6),
		wrk: env.OpenStore(t, db, "mg_worker_tenant", "mg_worker_platform", 10), actor: uuid.New(), host: uuid.New(),
		policy: map[string]string{}}
	g.exec(t, `INSERT INTO hosts (id, name, region, run_uid_range, tenant_net_pool, public_entry)
		VALUES ($1, 'host-1', 'lab', int4range(30000, 30100), '10.250.0.0/24', '{"ipv4": "192.0.2.10", "mode": "direct"}')`, g.host)
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
	tok := headscaletest.NewToken()
	g.edge = headscaletest.NewEdge(t, tok)
	g.edge.SetHook(func(r headscaletest.Request, _ int) (int, string, bool) {
		switch {
		case r.Method == "GET" && r.Path == "/api/v1/policy":
			g.mu.Lock()
			defer g.mu.Unlock()
			b, _ := json.Marshal(map[string]string{"policy": g.policy[r.Slug], "updatedAt": time.Now().UTC().Format(time.RFC3339)})
			return 200, string(b), true
		case r.Method == "POST" && r.Path == "/api/v1/policy/check":
			return 200, `{}`, true
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
	ca := &cfgAgent{edgeAgent: g.agent}
	g.prober = &fakeProber{relay: ProbeResult{OK: true}, edge: ProbeResult{OK: true}}
	g.kc = &fakeIdP{name: DriverKeycloak, realms: map[string]string{}}
	dns := dnsFunc(func(_ context.Context, _ string, want netip.Addr) (DNSResult, error) {
		return DNSResult{Addresses: []netip.Addr{want}, OK: true}, nil
	})
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	p, err := New(Config{Store: NewDBStore(g.wrk, nil), Agent: ca, Placer: placer, Secrets: wrkSec,
		IdP: fakeDrivers{DriverKeycloak: g.kc}, Headscale: reg, DNS: dns, Prober: g.prober, Logger: log,
		HeadscaleDigest: "sha256:" + strings.Repeat("d", 64), HeadscaleVersion: "v0.29.7",
		Nameservers: []netip.Addr{netip.MustParseAddr("1.1.1.1")}, EdgeAddress: "10.249.0.2:443",
		RetryBase: 20 * time.Millisecond, RetryMax: 50 * time.Millisecond, HealthPoll: 10 * time.Millisecond,
		HealthTimeout: 500 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	rc, err := NewReconfigurer(ReconfigureConfig{Store: NewDBStore(g.wrk, nil), Agent: ca, Headscale: reg, Prober: g.prober,
		Security: dbSecurity{g.wrk}, Logger: log, EdgeAddress: "10.249.0.2:443", RetryBase: 20 * time.Millisecond,
		RetryMax: 50 * time.Millisecond, HealthPoll: 10 * time.Millisecond, HealthTimeout: 500 * time.Millisecond})
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
	if err := p.Register(w); err != nil {
		t.Fatal(err)
	}
	if err := rc.Register(w); err != nil {
		t.Fatal(err)
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
	c := g.create(t, "acme")
	g.waitJob(t, c.Job.ID, jobs.StatusSucceeded)
	r := &rcDBRig{dbRig: g, cfg: ca, svc: NewReconfigureService(g.api), tid: c.TenantID}
	r.inst = dbScalar[uuid.UUID](t, g, `SELECT id FROM tenant_instances WHERE tenant_id = $1`, c.TenantID)
	return r
}

// dbSecurity records security events in a platform transaction of the worker's store (platformSecurity of the
// runner in production) — never on the superuser connection the test polls with (a pgx.Conn is not concurrent-safe).
type dbSecurity struct{ st *store.Store }

func (s dbSecurity) RecordSecurityEvent(ctx context.Context, ev audit.SecurityEvent) (bool, error) {
	var ok bool
	err := s.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		var err error
		ok, err = audit.RecordSecurityEvent(ctx, q, ev)
		return err
	})
	return ok, err
}

func (g *rcDBRig) request(t *testing.T, key string, ch ConfigChange) (Reconfigured, error) {
	t.Helper()
	return g.svc.Request(g.reqCtx(t, ActionInstanceReconfigure), g.actor, g.inst, ch,
		&Idempotency{Key: key, Hash: []byte(strings.Repeat("r", 31) + key[len(key)-1:])})
}

func (g *rcDBRig) currentSHA(t *testing.T) string {
	t.Helper()
	return dbScalar[string](t, g.dbRig, `SELECT c.config_sha256 FROM tenant_instances i
		JOIN instance_config_versions c ON c.id = i.config_version_id WHERE i.id = $1`, g.inst)
}

func TestReconfigureDB(t *testing.T) {
	g := newReconfigureDBRig(t)
	v1SHA := g.currentSHA(t)
	if file, run, _ := g.cfg.host(); file != v1SHA || run != v1SHA {
		t.Fatalf("provisioned host %s %s, registry %s", file, run, v1SHA)
	}

	// ---- 1. a valid change: new version applied, the previous superseded, audit pair, the host on it
	r, err := g.request(t, "rc-key-0001", ConfigChange{LogLevel: "warn", NodeExpiryDays: u32p(30)})
	if err != nil || !r.Created || r.Job.Kind != ReconfigureKind || r.Job.Status != jobs.StatusQueued {
		t.Fatalf("request %v %+v", err, r)
	}
	again, err := g.request(t, "rc-key-0001", ConfigChange{LogLevel: "warn", NodeExpiryDays: u32p(30)})
	if err != nil || !again.Replayed || again.Job.ID != r.Job.ID {
		t.Fatalf("replay %v %+v", err, again)
	}
	if _, err := g.svc.Request(g.reqCtx(t, ActionInstanceReconfigure), g.actor, g.inst, ConfigChange{LogLevel: "error"},
		&Idempotency{Key: "rc-key-0001", Hash: []byte(strings.Repeat("x", 32))}); !errors.Is(err, ErrIdempotencyKeyReuse) {
		t.Fatalf("same key, other request: %v", err)
	}
	g.waitJob(t, r.Job.ID, jobs.StatusSucceeded)
	v2SHA := g.currentSHA(t)
	file, run, restarts := g.cfg.host()
	if v2SHA == v1SHA || file != v2SHA || run != v2SHA || restarts != 1 {
		t.Fatalf("host %s %s restarts %d, registry %s (was %s)", file, run, restarts, v2SHA, v1SHA)
	}
	for q, want := range map[string]string{
		`SELECT string_agg(status, ',' ORDER BY version) FROM instance_config_versions WHERE instance_id = $1`:                                                                                                    "superseded,applied",
		`SELECT c.params->>'log_level' FROM tenant_instances i JOIN instance_config_versions c ON c.id = i.config_version_id WHERE i.id = $1`:                                                                     "LOG_LEVEL_WARN",
		`SELECT c.params->>'node_expiry_days' FROM tenant_instances i JOIN instance_config_versions c ON c.id = i.config_version_id WHERE i.id = $1`:                                                              "30",
		`SELECT (c.created_by IS NOT NULL AND c.applied_at IS NOT NULL)::text FROM tenant_instances i JOIN instance_config_versions c ON c.id = i.config_version_id WHERE i.id = $1`:                              "true",
		`SELECT string_agg(s.name || ':' || s.status, ',' ORDER BY s.seq) FROM provisioning_job_steps s JOIN provisioning_jobs j ON j.id = s.job_id WHERE j.instance_id = $1 AND j.kind = 'instance.reconfigure'`: "config.validate:succeeded,config.record:succeeded,policy.check:succeeded,config.write:succeeded,instance.restart:succeeded,instance.health:succeeded,edge.verify:succeeded,config.apply:succeeded",
		`SELECT string_agg(action, ',' ORDER BY occurred_at) FROM audit_events WHERE action LIKE 'platform.instance.%' AND tenant_id IS NULL AND resource_id = $1::text`:                                          "platform.instance.reconfigure.requested,platform.instance.reconfigure.succeeded",
	} {
		if got := dbScalar[string](t, g.dbRig, q, g.inst); got != want {
			t.Errorf("%s = %q, want %q", q, got, want)
		}
	}
	// CheckPolicy, GET /api/v1/health and the post-start gate went through the real adapter path.
	seen := map[string]bool{}
	for _, rq := range g.edge.Requests() {
		if rq.Slug == "acme" && rq.TokenOK {
			seen[rq.Method+" "+rq.Path] = true
		}
	}
	for _, p := range []string{"POST /api/v1/policy/check", "GET /api/v1/health", "GET /api/v1/policy"} {
		if !seen[p] {
			t.Errorf("%s never reached the instance", p)
		}
	}

	// ---- 2. nothing to change: no restart, no version
	u, err := g.request(t, "rc-key-0002", ConfigChange{})
	if err != nil {
		t.Fatal(err)
	}
	g.waitJob(t, u.Job.ID, jobs.StatusSucceeded)
	if n := dbScalar[int64](t, g.dbRig, `SELECT count(*) FROM instance_config_versions WHERE instance_id = $1`, g.inst); n != 2 {
		t.Fatalf("%d versions after an unchanged request", n)
	}
	if _, _, rs := g.cfg.host(); rs != 1 {
		t.Fatalf("restarts %d", rs)
	}
	if got := dbScalar[string](t, g.dbRig, `SELECT output->>'changed' FROM provisioning_jobs WHERE id = $1`, u.Job.ID); got != "false" {
		t.Fatal(got)
	}

	// ---- 3. "Config lỗi ⇒ tự lùi": a version that passes configtest but never comes up healthy ⇒ rolled_back
	g.cfg.set(func(a *cfgAgent) { a.crash = func(p configParams) bool { return p.NodeExpiryDays == 13 } })
	f, err := g.request(t, "rc-key-0003", ConfigChange{NodeExpiryDays: u32p(13)})
	if err != nil {
		t.Fatal(err)
	}
	g.waitJob(t, f.Job.ID, jobs.StatusRolledBack)
	file, run, restarts = g.cfg.host()
	if g.currentSHA(t) != v2SHA || file != v2SHA || run != v2SHA || restarts != 3 {
		t.Fatalf("after rollback: registry %s host %s %s restarts %d, want %s", g.currentSHA(t), file, run, restarts, v2SHA)
	}
	for q, want := range map[string]string{
		`SELECT string_agg(status, ',' ORDER BY version) FROM instance_config_versions WHERE instance_id = $1`:                                       "superseded,applied,failed",
		`SELECT error->>'code' FROM provisioning_jobs WHERE id = $1::uuid`:                                                                           "instance_unhealthy",
		`SELECT string_agg(name || ':' || COALESCE(compensation_status, '-'), ',' ORDER BY seq) FROM provisioning_job_steps WHERE job_id = $1::uuid`: "config.validate:skipped,config.record:succeeded,policy.check:skipped,config.write:succeeded,instance.restart:succeeded,instance.health:skipped",
	} {
		arg := any(g.inst)
		if strings.Contains(q, "$1::uuid") {
			arg = f.Job.ID
		}
		if got := dbScalar[string](t, g.dbRig, q, arg); got != want {
			t.Errorf("%s = %q, want %q", q, got, want)
		}
	}
	if got := dbScalar[string](t, g.dbRig, `SELECT string_agg(action || '/' || outcome, ',' ORDER BY occurred_at) FROM audit_events
		WHERE action LIKE 'platform.instance.%' AND resource_id = $1::text AND occurred_at >= (SELECT created_at FROM provisioning_jobs WHERE id = $2)`,
		g.inst, f.Job.ID); got != "platform.instance.reconfigure.requested/success,platform.instance.reconfigure.failed/failure,platform.instance.config_rollback/success" {
		t.Fatalf("audit %s", got)
	}
	g.cfg.set(func(a *cfgAgent) { a.crash = nil })

	// ---- 4. transient failure ⇒ failed_resumable (lock held: another reconfigure is refused) ⇒ /rollback
	g.cfg.set(func(a *cfgAgent) { a.unavailable = true })
	h, err := g.request(t, "rc-key-0004", ConfigChange{LogLevel: "error"})
	if err != nil {
		t.Fatal(err)
	}
	g.waitJob(t, h.Job.ID, jobs.StatusFailedResumable)
	if got := dbScalar[string](t, g.dbRig, `SELECT error->>'code' FROM provisioning_jobs WHERE id = $1`, h.Job.ID); got != "agent_unavailable" {
		t.Fatal(got)
	}
	if _, err := g.request(t, "rc-key-0005", ConfigChange{LogLevel: "info"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("another reconfigure while one is failed_resumable: %v", err)
	}
	g.cfg.set(func(a *cfgAgent) { a.unavailable = false })
	if _, err := g.control.Rollback(g.reqCtx(t, ActionJobRollback), g.actor, h.Job.ID, nil); err != nil {
		t.Fatal(err)
	}
	g.waitJob(t, h.Job.ID, jobs.StatusRolledBack)
	if file, run, _ := g.cfg.host(); g.currentSHA(t) != v2SHA || file != v2SHA || run != v2SHA {
		t.Fatalf("after /rollback: registry %s host %s %s", g.currentSHA(t), file, run)
	}
	if got := dbScalar[string](t, g.dbRig, `SELECT string_agg(status, ',' ORDER BY version) FROM instance_config_versions WHERE instance_id = $1`, g.inst); got != "superseded,applied,failed,failed" {
		t.Fatal(got)
	}

	// ---- 4b. post-start gate: the policy read back after the restart differs from the applied one ⇒ a High security
	// event in the database; the reconfiguration itself succeeds (repairing the policy is policy.apply's)
	g.setPolicy("acme", `{"grants": [{"src": ["*"], "dst": ["*"], "ip": ["*"]}]}`)
	d, err := g.request(t, "rc-key-0009", ConfigChange{LogLevel: "info"})
	if err != nil {
		t.Fatal(err)
	}
	g.waitJob(t, d.Job.ID, jobs.StatusSucceeded)
	if n := dbScalar[int64](t, g.dbRig, `SELECT count(*) FROM security_events WHERE kind = 'instance.policy_drift'
		AND severity = 'high' AND tenant_id IS NULL AND details->>'instance_id' = $1::text`, g.inst); n != 1 {
		t.Fatalf("%d policy drift events", n)
	}
	g.setPolicy("acme", templates.BootstrapPolicy)

	// ---- 5. API refusals
	if _, err := g.svc.Request(g.reqCtx(t, ActionInstanceReconfigure), g.actor, uuid.New(), ConfigChange{}, nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown instance: %v", err)
	}
	if _, err := g.svc.Request(g.reqCtx(t, ActionInstanceReconfigure), g.actor, g.inst, ConfigChange{LogLevel: "debug"}, nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid change: %v", err)
	}
	g.exec(t, `UPDATE tenant_instances SET status = 'quarantined' WHERE id = $1`, g.inst)
	var ce *CreateError
	if _, err := g.svc.Request(g.reqCtx(t, ActionInstanceReconfigure), g.actor, g.inst, ConfigChange{}, nil); !errors.As(err, &ce) || ce.Reason != "instance_quarantined" {
		t.Fatalf("quarantined: %v", err)
	}
	g.exec(t, `UPDATE tenant_instances SET status = 'running' WHERE id = $1`, g.inst)

	// ---- 6. one unfinished job per instance: the same change ⇒ the same job; another ⇒ 409; /cancel closes the audit
	if err := g.worker.Stop(t.Context()); err != nil {
		t.Fatal(err)
	}
	q1, err := g.request(t, "rc-key-0006", ConfigChange{Nameservers: []string{"9.9.9.9"}})
	if err != nil || !q1.Created {
		t.Fatalf("queued %v %+v", err, q1)
	}
	q2, err := g.request(t, "rc-key-0007", ConfigChange{Nameservers: []string{"9.9.9.9"}})
	if err != nil || q2.Created || q2.Job.ID != q1.Job.ID {
		t.Fatalf("same change %v %+v", err, q2)
	}
	if _, err := g.request(t, "rc-key-0008", ConfigChange{Nameservers: []string{"8.8.8.8"}}); !errors.As(err, &ce) || ce.Reason != "reconfigure_in_progress" {
		t.Fatalf("other change: %v", err)
	}
	cr, err := g.control.Cancel(g.reqCtx(t, ActionJobCancel), g.actor, q1.Job.ID, nil)
	if err != nil || cr.Job.Status != jobs.StatusCancelled {
		t.Fatalf("cancel %v %+v", err, cr)
	}
	if got := dbScalar[string](t, g.dbRig, `SELECT details->>'reason' FROM audit_events WHERE action = 'platform.instance.reconfigure.failed'
		AND operation_id = (SELECT (input->'operation'->>'id')::uuid FROM provisioning_jobs WHERE id = $1)`, q1.Job.ID); got != "cancelled" {
		t.Fatalf("cancelled audit %q", got)
	}
	if _, err := g.control.Retry(g.reqCtx(t, ActionJobRetry), g.actor, q1.Job.ID, nil); !errors.Is(err, jobs.ErrJobState) {
		t.Fatalf("retry cancelled: %v", err)
	}
	// no audit operation left open by any of the above
	if n := dbScalar[int64](t, g.dbRig, `SELECT count(*) FROM audit_events r WHERE r.action = 'platform.instance.reconfigure.requested'
		AND NOT EXISTS (SELECT 1 FROM audit_events f WHERE f.operation_id = r.operation_id AND f.action <> r.action)`); n != 0 {
		t.Fatalf("%d open operations", n)
	}
}
