package jobs

// PostgreSQL integration harness of internal/jobs: every test gets its own database (internal/store/storetest:
// bootstrap, goose + River migrations, role passwords) with two tenants, so River clients, leaders and queues of
// parallel tests never meet.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/storetest"
)

func TestMain(m *testing.M) {
	code := m.Run()
	storetest.Cleanup()
	os.Exit(code)
}

// fixture is one test database with two tenants (A, B), each with a running instance.
type fixture struct {
	env          *storetest.Env
	db           string
	su           *pgx.Conn // superuser connection: fixtures and checks (test goroutine only)
	host         uuid.UUID
	tenants      int
	a, b         uuid.UUID // tenants
	instA, instB uuid.UUID
	identity     uuid.UUID // requested_by of API-enqueued jobs
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	env := storetest.Require(t)
	f := &fixture{env: env, db: env.NewDatabase(t), a: uuid.New(), b: uuid.New(), instA: uuid.New(), instB: uuid.New(),
		identity: uuid.New()}
	f.su = env.Admin(t, f.db)
	f.host = uuid.New()
	f.exec(t, `INSERT INTO hosts (id, name, region, run_uid_range, tenant_net_pool)
		VALUES ($1, 'host-1', 'lab', int4range(30000, 40000), '10.250.0.0/16')`, f.host)
	f.insertTenant(t, f.a, f.instA)
	f.insertTenant(t, f.b, f.instB)
	return f
}

// newTenant adds one more tenant with a running instance.
func (f *fixture) newTenant(t *testing.T) (tenant, instance uuid.UUID) {
	t.Helper()
	tenant, instance = uuid.New(), uuid.New()
	f.insertTenant(t, tenant, instance)
	return tenant, instance
}

func (f *fixture) insertTenant(t *testing.T, tenant, instance uuid.UUID) {
	t.Helper()
	f.tenants++
	i := f.tenants
	slug := fmt.Sprintf("tenant%02d", i)
	f.exec(t, `INSERT INTO tenants (id, slug, name, status) VALUES ($1, $2, $3, 'active')`, tenant, slug, "Tenant "+slug)
	f.exec(t, `INSERT INTO tenant_instances (id, tenant_id, host_id, status, headscale_version, image_digest,
			control_hostname, server_url, base_domain, internal_address, run_uid, net_cidr, data_path)
		VALUES ($1, $2, $3, 'running', '0.29.7', 'sha256:'||repeat('a', 64), $4, 'https://'||$4, $5, $6, $7, $8::cidr, $9)`,
		instance, tenant, f.host, slug+".mesh.test", slug+".ts.test", "hs-"+slug+":8080", 30000+i,
		fmt.Sprintf("10.250.%d.0/29", i), "/opt/meshguard/tenants/"+instance.String())
}

func (f *fixture) exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	if _, err := f.su.Exec(t.Context(), sql, args...); err != nil {
		t.Fatalf("superuser exec: %v\n%s", err, sql)
	}
}

// scalar runs a superuser query returning one value.
func scalar[T any](t *testing.T, f *fixture, sql string, args ...any) T {
	t.Helper()
	var v T
	if err := f.su.QueryRow(t.Context(), sql, args...).Scan(&v); err != nil {
		t.Fatalf("query %q: %v", sql, err)
	}
	return v
}

// api is the api process's store (mg_api_tenant / mg_api_platform); worker the worker's (mg_worker_*).
func (f *fixture) api(t *testing.T) *store.Store {
	return f.env.OpenStore(t, f.db, "mg_api_tenant", "mg_api_platform", 4)
}

func (f *fixture) workerStore(t *testing.T) *store.Store {
	return f.env.OpenStore(t, f.db, "mg_worker_tenant", "mg_worker_platform", 6)
}

// job reads a business job (superuser view through the worker's platform pool).
func (f *fixture) job(t *testing.T, st *store.Store, id uuid.UUID) sqlcdb.ProvisioningJob {
	t.Helper()
	var j sqlcdb.ProvisioningJob
	if err := st.WithPlatformTx(t.Context(), func(q *sqlcdb.Queries) error {
		var err error
		j, err = q.GetJob(t.Context(), id)
		return err
	}); err != nil {
		t.Fatalf("job %s: %v", id, err)
	}
	return j
}

// queueState is the state of a job's River job ("" if it no longer exists).
func (f *fixture) queueState(t *testing.T, j sqlcdb.ProvisioningJob) string {
	t.Helper()
	if j.QueueJobID == nil {
		return ""
	}
	var s string
	err := f.su.QueryRow(t.Context(), "SELECT state::text FROM river.river_job WHERE id = $1", *j.QueueJobID).Scan(&s)
	if errors.Is(err, store.ErrNoRows) {
		return ""
	}
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// enqueue writes one job in its own transaction (tenant scope when spec.TenantID is set, platform otherwise).
func enqueue(t *testing.T, st *store.Store, spec Spec) (Enqueued, error) {
	t.Helper()
	var out Enqueued
	run := func(tx *store.Tx) error {
		var err error
		out, err = Enqueue(t.Context(), tx, spec)
		return err
	}
	if spec.TenantID != nil {
		return out, st.WithTenantJobTx(t.Context(), *spec.TenantID, run)
	}
	return out, st.WithPlatformJobTx(t.Context(), run)
}

func mustEnqueue(t *testing.T, st *store.Store, spec Spec) Enqueued {
	t.Helper()
	e, err := enqueue(t, st, spec)
	if err != nil {
		t.Fatalf("enqueue %s: %v", spec.Kind, err)
	}
	return e
}

// testConfig is DefaultConfig made fast: short polls, snoozes and backoff, no start jitter, River's TestOnly.
func testConfig() Config {
	c := DefaultConfig()
	c.testOnly = true
	c.periodicOff = true
	c.FetchCooldown = 10 * time.Millisecond
	c.FetchPollInterval = 50 * time.Millisecond
	c.RetryBase = 50 * time.Millisecond
	c.RetryMax = 200 * time.Millisecond
	c.LockBusySnooze = 100 * time.Millisecond
	c.LockHeldSnooze = 200 * time.Millisecond
	c.NoHandlerSnooze = time.Second
	c.StartJitter = 0
	c.SoftStopTimeout = 2 * time.Second
	c.QueuePoolConns = 5
	return c
}

// setTimeouts gives every kind the same whole-job and worker timeout (and keeps Validate happy).
func setTimeouts(c *Config, timeout, worker time.Duration) {
	for name, k := range c.Kinds {
		k.Timeout, k.WorkerTimeout = timeout, worker
		c.Kinds[name] = k
	}
}

// recAlerter records alerts.
type recAlerter struct {
	mu     sync.Mutex
	alerts []Alert
}

func (r *recAlerter) JobAlert(_ context.Context, a Alert) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.alerts = append(r.alerts, a)
}

func (r *recAlerter) all() []Alert {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Alert(nil), r.alerts...)
}

func (r *recAlerter) find(reason string, job uuid.UUID) (Alert, bool) {
	for _, a := range r.all() {
		if a.Reason == reason && a.JobID == job {
			return a, true
		}
	}
	return Alert{}, false
}

// newWorker builds (but does not start) a worker on st with a recording alerter and its own metrics registry.
func newWorker(t *testing.T, st *store.Store, cfg Config, opts Options) (*Worker, *recAlerter) {
	t.Helper()
	rec := &recAlerter{}
	if opts.Alerter == nil {
		opts.Alerter = rec
	}
	if opts.Registerer == nil {
		opts.Registerer = prometheus.NewRegistry()
	}
	w, err := NewWorker(st, cfg, opts)
	if err != nil {
		t.Fatal(err)
	}
	return w, rec
}

// start starts w and stops it when the test ends.
func start(t *testing.T, w *Worker) {
	t.Helper()
	if err := w.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = w.Stop(ctx)
	})
}

// eventually polls cond every 50 ms until it holds or timeout passes.
func eventually(t *testing.T, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %s waiting for: %s", timeout, what)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// waitStatus waits until the job reaches status.
func (f *fixture) waitStatus(t *testing.T, st *store.Store, id uuid.UUID, status string, timeout time.Duration) sqlcdb.ProvisioningJob {
	t.Helper()
	var j sqlcdb.ProvisioningJob
	eventually(t, timeout, fmt.Sprintf("job %s %s", id, status), func() bool {
		j = f.job(t, st, id)
		return j.Status == status
	})
	return j
}

// counter reads one series of a counter vector.
func counter(t *testing.T, v *prometheus.CounterVec, labels ...string) float64 {
	t.Helper()
	m := &dto.Metric{}
	if err := v.WithLabelValues(labels...).Write(m); err != nil {
		t.Fatal(err)
	}
	return m.GetCounter().GetValue()
}

// errorCode extracts provisioning_jobs.error.code.
func errorCode(j sqlcdb.ProvisioningJob) string {
	if e := decodeError(j.Error); e != nil {
		return e.Code
	}
	return ""
}
