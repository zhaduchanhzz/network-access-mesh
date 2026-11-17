package reconcile

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	agentv1 "github.com/zhaduchanhzz/network-access-mesh/api/agent/v1"
	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/storetest"
)

// dbSecurity is the recorder of apps/worker (runner.platformSecurity): a platform transaction of the worker's store.
type dbSecurity struct{ st *store.Store }

func (p dbSecurity) RecordSecurityEvent(ctx context.Context, ev audit.SecurityEvent) (bool, error) {
	var wrote bool
	err := p.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		var err error
		wrote, err = audit.RecordSecurityEvent(ctx, q, ev)
		return err
	})
	return wrote, err
}

type dbTenant struct {
	id, instance uuid.UUID
	slug         string
	hs           *fakeHS
}

type dbFixture struct {
	db    string
	mu    sync.Mutex
	su    *pgx.Conn
	host  uuid.UUID
	n     int
	st    *store.Store
	agent *fakeAgent
	reg   fakeRegistry
	svc   *Service
	prom  *prometheus.Registry
	a, b  *dbTenant
}

func newDBFixture(t *testing.T) *dbFixture {
	t.Helper()
	env := storetest.Require(t)
	f := &dbFixture{db: env.NewDatabase(t), host: uuid.New(), agent: newFakeAgent(), reg: fakeRegistry{}, prom: prometheus.NewRegistry()}
	f.su = env.Admin(t, f.db)
	f.exec(t, `INSERT INTO hosts (id, name, region, run_uid_range, tenant_net_pool)
		VALUES ($1, 'host-1', 'lab', int4range(30000, 40000), '10.250.0.0/16')`, f.host)
	f.a, f.b = f.tenant(t, "running"), f.tenant(t, "running")
	f.st = env.OpenStore(t, f.db, "mg_worker_tenant", "mg_worker_platform", 6)
	var err error
	f.svc, err = New(f.st, Config{Agent: f.agent.serve(t), Headscale: f.reg, Security: dbSecurity{f.st}, Registerer: f.prom,
		AgentTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// tenant inserts an active tenant with an instance of the given status, its config version in force, a recorded API
// key prefix, and the matching actual state in the fakes.
func (f *dbFixture) tenant(t *testing.T, status string) *dbTenant {
	t.Helper()
	f.n++
	ten := &dbTenant{id: uuid.New(), instance: uuid.New(), slug: fmt.Sprintf("tenant%02d", f.n), hs: &fakeHS{}}
	f.exec(t, `INSERT INTO tenants (id, slug, name, status) VALUES ($1, $2, $3, 'active')`, ten.id, ten.slug, "Tenant "+ten.slug)
	cidr := fmt.Sprintf("10.250.%d.8/29", f.n)
	f.exec(t, `INSERT INTO tenant_instances (id, tenant_id, host_id, status, headscale_version, image_digest, control_hostname,
			server_url, base_domain, internal_address, run_uid, net_cidr, data_path, api_key_prefix)
		VALUES ($1, $2, $3, $4, '0.29.7', $5, $6, 'https://'||$6, $7, $8, $9, $10::cidr, $11, $12)`,
		ten.instance, ten.id, f.host, status, digestA, ten.slug+".mesh.test", ten.slug+".ts.test", "hs-"+ten.slug+":8080", runUID+f.n,
		cidr, "/opt/meshguard/tenants/"+ten.instance.String(), "curKEY0000"+fmt.Sprintf("%02d", f.n))
	cv := uuid.New()
	f.exec(t, `INSERT INTO instance_config_versions (id, tenant_id, instance_id, version, template_version, rendered_config, config_sha256)
		VALUES ($1, $2, $3, 1, '1', 'server_url: x', $4)`, cv, ten.id, ten.instance, cfgSum)
	f.exec(t, `UPDATE tenant_instances SET config_version_id = $1 WHERE id = $2`, cv, ten.instance)
	d := desired()
	d.InstanceID, d.TenantID, d.Slug, d.RunUID = ten.instance, ten.id, ten.slug, uint32(runUID+f.n) //nolint:gosec // test
	d.NetCIDR = netip.MustParsePrefix(cidr)
	st := goodStatus(d)
	for _, p := range st.Paths {
		if p.Uid == runUID {
			p.Uid = d.RunUID
		}
		if p.Gid == runUID {
			p.Gid = d.RunUID
		}
	}
	f.agent.set(ten.instance, st, nil)
	cur := currentKey()
	cur.Prefix = "curKEY0000" + fmt.Sprintf("%02d", f.n)
	cur.CreatedAt, cur.Expiration = time.Now().Add(-30*24*time.Hour), time.Now().Add(60*24*time.Hour)
	ten.hs.setKeys(cur)
	f.reg[ten.id] = ten.hs
	f.agent.mu.Lock()
	f.agent.inventory.Instances = append(f.agent.inventory.Instances, &agentv1.InventoryEntry{InstanceId: ten.instance.String(),
		TenantId: ten.id.String(), Slug: ten.slug, HasDirectory: true, HasContainer: true, HasNetwork: true})
	f.agent.inventory.EdgeAliases = append(f.agent.inventory.EdgeAliases, &agentv1.EdgeAlias{Network: "mg-t-" + ten.slug,
		Container: "mg-hs-" + ten.slug, Alias: "hs-" + ten.slug})
	f.agent.mu.Unlock()
	return ten
}

func (f *dbFixture) exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, err := f.su.Exec(context.Background(), sql, args...); err != nil {
		t.Fatalf("superuser exec: %v\n%s", err, sql)
	}
}

func (f *dbFixture) count(t *testing.T, sql string, args ...any) int {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	var n int
	if err := f.su.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		t.Fatalf("superuser query: %v\n%s", err, sql)
	}
	return n
}

// registryState is the part of the registry reconcile must never change.
func (f *dbFixture) registryState(t *testing.T) string {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	var s string
	if err := f.su.QueryRow(context.Background(), `SELECT string_agg(concat_ws(' ', id, status, image_digest, version, updated_at,
		last_health_at, api_key_prefix, config_version_id), E'\n' ORDER BY id) FROM tenant_instances`).Scan(&s); err != nil {
		t.Fatal(err)
	}
	return s
}

func (f *dbFixture) worker(t *testing.T) *jobs.Worker {
	t.Helper()
	cfg := jobs.DefaultConfig()
	cfg.FetchCooldown, cfg.FetchPollInterval = 10*time.Millisecond, 50*time.Millisecond
	cfg.StartJitter, cfg.SoftStopTimeout, cfg.QueuePoolConns = 0, 2*time.Second, 4
	w, err := jobs.NewWorker(f.st, cfg, jobs.Options{Registerer: prometheus.NewRegistry()})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Register(w); err != nil {
		t.Fatal(err)
	}
	if err := w.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = w.Stop(c)
	})
	return w
}

func (f *dbFixture) waitSucceeded(t *testing.T, want int) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	q := `SELECT count(*) FROM provisioning_jobs WHERE kind IN ('instance.reconcile', 'host.reconcile') AND status = 'succeeded'`
	for f.count(t, q) < want {
		if time.Now().After(deadline) {
			t.Fatalf("reconcile jobs succeeded: %d, want %d (failed: %d)", f.count(t, q), want,
				f.count(t, `SELECT count(*) FROM provisioning_jobs WHERE kind LIKE '%.reconcile' AND status <> 'succeeded'`))
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// gauge reads one series of a gauge.
func gauge(t *testing.T, g prometheus.Gauge) float64 {
	t.Helper()
	m := &dto.Metric{}
	if err := g.Write(m); err != nil {
		t.Fatal(err)
	}
	return m.GetGauge().GetValue()
}

// TestReconcileThroughWorker runs both jobs under the real job framework (River): the schedule enqueues one
// host.reconcile and one instance.reconcile per instance; each job succeeds with its report as output — drift is a
// result, not a failure —; monitoring reads the latest reports back; every security-relevant drift is ONE platform
// security event, also after a second round (dedupe per subject); the gauge counts the drift by kind; the registry
// is unchanged and the fakes saw reads only.
func TestReconcileThroughWorker(t *testing.T) {
	f := newDBFixture(t)
	ctx := context.Background()
	// A: a foreign API key and a stranger on its network; B: clean; the host: a labelled network nobody registered
	f.a.hs.setKeys(append(f.a.hs.keys, headscale.APIKey{ID: 66, Prefix: "evilKEY00001", CreatedAt: time.Now().Add(-time.Hour)})...)
	f.agent.mu.Lock()
	f.agent.status[f.a.instance.String()].Network.Members = []string{"intruder", "mg-edge", "mg-hs-" + f.a.slug}
	f.agent.inventory.Instances = append(f.agent.inventory.Instances, &agentv1.InventoryEntry{
		InstanceId: "99999999-9999-4999-8999-999999999999", Slug: "ghost", HasNetwork: true})
	f.agent.mu.Unlock()
	before := f.registryState(t)
	f.worker(t)
	sc := f.svc.NewScheduler(SchedulerConfig{Interval: time.Minute, Tick: time.Second})
	t0 := time.Now()
	if n, err := sc.Tick(ctx, t0); err != nil || n != 0 {
		t.Fatalf("first tick: %d %v, want 0 (subjects only noted)", n, err)
	}
	if n, err := sc.Tick(ctx, t0.Add(time.Minute)); err != nil || n != 3 {
		t.Fatalf("tick after one interval: %d %v, want 3 (host, A, B)", n, err)
	}
	if n, err := sc.Tick(ctx, t0.Add(time.Minute)); err != nil || n != 0 {
		t.Fatalf("same period again: %d %v", n, err)
	}
	f.waitSucceeded(t, 3)
	for _, ten := range []*dbTenant{f.a, f.b} {
		slot := sc.slot(KindInstance, ten.instance[:], t0.Add(time.Minute))
		if n := f.count(t, `SELECT count(*) FROM provisioning_jobs WHERE kind = 'instance.reconcile' AND instance_id = $1 AND dedupe_key = $2`,
			ten.instance, fmt.Sprintf("instance:%s:reconcile:%d", ten.instance, slot)); n != 1 {
			t.Errorf("job of %s: %d", ten.slug, n)
		}
	}

	reports, err := f.svc.LatestReports(ctx, t0.Add(-time.Hour))
	if err != nil || len(reports) != 2 {
		t.Fatalf("latest reports: %d %v", len(reports), err)
	}
	for _, r := range reports {
		k := r.Report.Kinds()
		switch *r.Report.InstanceID {
		case f.a.instance:
			if r.Report.Status != StatusDrift || k[DriftAPIKeyForeign] != 1 || k[DriftNetworkExtraMember] != 1 || len(r.Report.Findings) != 2 {
				t.Errorf("A: %+v", r.Report)
			}
		case f.b.instance:
			if r.Report.Status != StatusClean {
				t.Errorf("B: %+v", r.Report)
			}
		}
	}
	host, err := f.svc.LatestHostReport(ctx)
	if err != nil || host == nil || host.Report.Status != StatusDrift || host.Report.Kinds()[DriftUnknownInstance] != 1 ||
		len(host.Report.Findings) != 1 || host.Report.Findings[0].Subject != "99999999-9999-4999-8999-999999999999" {
		t.Fatalf("host report: %+v %v", host, err)
	}
	wantEvents := func(round string) {
		t.Helper()
		for kind, want := range map[string]int{"reconcile.api_key_foreign": 1, "reconcile.network_extra_member": 1,
			"reconcile.unknown_instance": 1} {
			if n := f.count(t, `SELECT count(*) FROM security_events WHERE kind = $1 AND tenant_id IS NULL AND source = 'reconcile'`, kind); n != want {
				t.Errorf("%s: %d events of %s, want %d", round, n, kind, want)
			}
		}
		if n := f.count(t, `SELECT count(*) FROM security_events`); n != 3 {
			t.Errorf("%s: %d security events, want 3", round, n)
		}
		if n := f.count(t, `SELECT count(*) FROM security_events WHERE kind = 'reconcile.api_key_foreign' AND severity = 'high'
				AND details->>'prefix' = 'evilKEY00001' AND details->>'instance_id' = $1`, f.a.instance.String()); n != 1 {
			t.Errorf("%s: the foreign key event does not name the prefix and the instance", round)
		}
	}
	wantEvents("first round")
	if g := gauge(t, f.svc.m.drift.WithLabelValues(DriftAPIKeyForeign)); g != 1 {
		t.Errorf("gauge api_key_foreign %v", g)
	}
	if g := gauge(t, f.svc.m.drift.WithLabelValues(DriftUnknownInstance)); g != 1 {
		t.Errorf("gauge unknown_instance %v", g)
	}

	// second round: same drift ⇒ new reports, no new security event
	if n, err := sc.Tick(ctx, t0.Add(2*time.Minute)); err != nil || n != 3 {
		t.Fatalf("second round: %d %v", n, err)
	}
	f.waitSucceeded(t, 6)
	wantEvents("second round")
	// the intruder leaves: the next report of A no longer has it, the gauge follows
	f.agent.mu.Lock()
	f.agent.status[f.a.instance.String()].Network.Members = []string{"mg-edge", "mg-hs-" + f.a.slug}
	f.agent.mu.Unlock()
	if _, _, err := f.svc.ReconcileInstance(ctx, f.a.id, f.a.instance); err != nil {
		t.Fatal(err)
	}
	if g := gauge(t, f.svc.m.drift.WithLabelValues(DriftNetworkExtraMember)); g != 0 {
		t.Errorf("gauge network_extra_member %v after the intruder left", g)
	}
	if after := f.registryState(t); after != before {
		t.Errorf("reconcile changed the registry:\n%s\n---\n%s", before, after)
	}
	assertReadOnly(t, f.agent, f.a.hs, f.b.hs)
	raw := f.count(t, `SELECT count(*) FROM provisioning_jobs WHERE kind LIKE '%.reconcile' AND output::text LIKE '%hskey%'`)
	if raw != 0 {
		t.Errorf("%d reports hold a key", raw)
	}
	var out string
	f.mu.Lock()
	err = f.su.QueryRow(ctx, `SELECT output::text FROM provisioning_jobs WHERE kind = 'instance.reconcile' AND instance_id = $1
		ORDER BY finished_at DESC LIMIT 1`, f.a.instance).Scan(&out)
	f.mu.Unlock()
	if err != nil || strings.Contains(out, "intruder") || !strings.Contains(out, `"status": "drift"`) {
		t.Errorf("output of A (tenant-visible) %s %v", out, err)
	}
}

// TestReconcileSkips: an unknown instance, a quarantined one and one whose tenant has a lifecycle job running are not
// reconciled (§11.4) — nothing read from the agent or Headscale; the scheduler targets starting/running/stopped only.
func TestReconcileSkips(t *testing.T) {
	f := newDBFixture(t)
	ctx := context.Background()
	if _, skipped, err := f.svc.ReconcileInstance(ctx, f.a.id, uuid.New()); err != nil || skipped != SkipInstanceNotFound {
		t.Fatalf("unknown instance: %q %v", skipped, err)
	}
	f.exec(t, `UPDATE tenant_instances SET status = 'quarantined' WHERE id = $1`, f.a.instance)
	if _, skipped, err := f.svc.ReconcileInstance(ctx, f.a.id, f.a.instance); err != nil || skipped != SkipNotReconciled {
		t.Fatalf("quarantined: %q %v", skipped, err)
	}
	f.exec(t, `INSERT INTO provisioning_jobs (tenant_id, instance_id, kind, dedupe_key, lock_key, status, max_attempts, started_at)
		VALUES ($1, $2, 'instance.upgrade', $3, $4, 'running', 6, now())`,
		f.b.id, f.b.instance, "instance:"+f.b.instance.String()+":instance.upgrade", jobs.LockKey(f.b.id))
	if _, skipped, err := f.svc.ReconcileInstance(ctx, f.b.id, f.b.instance); err != nil || skipped != SkipLifecycleBusy {
		t.Fatalf("lifecycle job running: %q %v", skipped, err)
	}
	if n := len(f.agent.calls()) + len(f.a.hs.called()) + len(f.b.hs.called()); n != 0 {
		t.Errorf("%d calls for skipped reconciles", n)
	}
	sc := f.svc.NewScheduler(SchedulerConfig{Interval: time.Minute, Tick: time.Second})
	t0 := time.Now()
	_, _ = sc.Tick(ctx, t0)
	if n, err := sc.Tick(ctx, t0.Add(time.Minute)); err != nil || n != 2 { // host + B (A quarantined)
		t.Fatalf("scheduled %d %v, want 2", n, err)
	}
	if n := f.count(t, `SELECT count(*) FROM provisioning_jobs WHERE kind = 'instance.reconcile' AND instance_id = $1`, f.a.instance); n != 0 {
		t.Errorf("quarantined instance scheduled")
	}
}

// TestNoAgentReportsUnavailable: without an agent (dev) the jobs succeed with an incomplete report and the API keys
// are still checked.
func TestNoAgentReportsUnavailable(t *testing.T) {
	f := newDBFixture(t)
	svc, err := New(f.st, Config{Headscale: f.reg, Security: dbSecurity{f.st}})
	if err != nil {
		t.Fatal(err)
	}
	f.svc = svc
	f.worker(t)
	ctx := context.Background()
	err = f.st.WithTenantJobTx(ctx, f.b.id, func(tx *store.Tx) error {
		_, err := jobs.Enqueue(ctx, tx, jobs.Spec{Kind: KindInstance, TenantID: &f.b.id, InstanceID: &f.b.instance, Slot: "1"})
		return err
	})
	if err == nil {
		err = f.st.WithPlatformJobTx(ctx, func(tx *store.Tx) error {
			_, err := jobs.Enqueue(ctx, tx, jobs.Spec{Kind: KindHost, Slot: "1"})
			return err
		})
	}
	if err != nil {
		t.Fatal(err)
	}
	f.waitSucceeded(t, 2)
	var out []byte
	f.mu.Lock()
	err = f.su.QueryRow(ctx, `SELECT output FROM provisioning_jobs WHERE kind = 'instance.reconcile'`).Scan(&out)
	f.mu.Unlock()
	var rep Report
	if err != nil || json.Unmarshal(out, &rep) != nil || rep.Status != StatusIncomplete ||
		checkOf(rep, CheckAgent).Reason != ReasonAgentNotConfigured || checkOf(rep, CheckAPIKeys).Outcome != OutcomeOK {
		t.Fatalf("report without agent: %s %v", out, err)
	}
	if !slices.Equal(f.b.hs.called(), []string{"ListAPIKeys"}) || len(f.agent.calls()) != 0 {
		t.Errorf("calls: headscale %v agent %v", f.b.hs.called(), f.agent.calls())
	}
}
