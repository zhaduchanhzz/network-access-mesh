package apikey_test

// Database tests of the rotation: a real PostgreSQL migrated like a deployment (storetest, worker roles), the real
// SecretStore, the production locator over the Tenant Registry, the advisory lock of store.WithTenantLock, the job
// framework (River) — and the fake edge admin listener of headscaletest in front of a fake Headscale. The report-only
// reconcile of P3-T12 runs against the same database to show that its API key check stays quiet during and after a
// rotation. The same flow against Headscale 0.29.7: tests/integration/headscale, phase 13.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale/headscaletest"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale/locator"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/logx"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/apikey"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/reconcile"
	"github.com/zhaduchanhzz/network-access-mesh/internal/secrets"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/storetest"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
)

func TestMain(m *testing.M) {
	code := m.Run()
	storetest.Cleanup()
	os.Exit(code)
}

const day = 24 * time.Hour

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

// pausingSecrets is the worker's SecretStore that can hold the rotation at step 6 — after the new key was created and
// verified, before it is stored and recorded: the window in which the instance has two valid keys.
type pausingSecrets struct {
	*secrets.Store
	mu      sync.Mutex
	armed   bool
	paused  chan struct{}
	release chan struct{}
}

func (p *pausingSecrets) arm() {
	p.mu.Lock()
	p.armed, p.paused, p.release = true, make(chan struct{}), make(chan struct{})
	p.mu.Unlock()
}

func (p *pausingSecrets) Rotate(ctx context.Context, ref secrets.Ref, value []byte, opts ...secrets.Option) (secrets.Ref, error) {
	p.mu.Lock()
	armed, paused, release := p.armed, p.paused, p.release
	p.armed = false
	p.mu.Unlock()
	if armed {
		close(paused)
		<-release
	}
	return p.Store.Rotate(ctx, ref, value, opts...)
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

type dbFix struct {
	t        *testing.T
	pg       *storetest.Env
	db       string
	su       *pgx.Conn
	mu       sync.Mutex
	st       *store.Store
	ss       *secrets.Store
	ps       *pausingSecrets
	ten      *tenants.Service
	edge     *headscaletest.Edge
	inst     *headscaletest.Instance
	token    string
	tokFile  string
	loc      *locator.Locator           // the rotation's locator (apikey.TenantStatuses)
	shared   *headscale.CachingRegistry // the worker's shared registry (default statuses)
	logs     *syncBuffer
	prom     *prometheus.Registry
	svc      *apikey.Service
	tenant   uuid.UUID
	instance uuid.UUID
	k0, p0   string
}

func newDBFix(t *testing.T, ttl time.Duration) *dbFix {
	t.Helper()
	pg := storetest.Require(t)
	f := &dbFix{t: t, pg: pg, db: pg.NewDatabase(t), tenant: uuid.New(), instance: uuid.New(), logs: &syncBuffer{},
		prom: prometheus.NewRegistry(), token: headscaletest.NewToken()}
	f.su = pg.Admin(t, f.db)
	f.st = pg.OpenStore(t, f.db, "mg_worker_tenant", "mg_worker_platform", 8)
	dir := t.TempDir()
	k := make([]byte, 32)
	_, _ = rand.Read(k)
	write(t, filepath.Join(dir, "kek-1"), hex.EncodeToString(k)+"\n")
	write(t, filepath.Join(dir, secrets.ActiveFile), "kek-1\n")
	kr, err := secrets.LoadKeyring(secrets.KEKApp, dir)
	if err != nil {
		t.Fatal(err)
	}
	log := logx.New(f.logs, slog.LevelDebug, "apikey-db")
	if f.ss, err = secrets.New(f.st, secrets.Options{App: kr, Logger: log}); err != nil {
		t.Fatal(err)
	}
	f.ps = &pausingSecrets{Store: f.ss}
	f.ten = tenants.New(f.st, tenants.Options{BaseDomain: "mg.test"})
	f.edge = headscaletest.NewEdge(t, f.token)
	f.inst = f.edge.AddInstance("tenant-a")
	f.tokFile = filepath.Join(t.TempDir(), "edge_admin_token")
	write(t, f.tokFile, f.token+"\n")
	if f.loc, err = locator.New(f.ten, f.ss, locator.Options{AdminURL: f.edge.URL(), EdgeTokenFile: f.tokFile, Logger: log,
		TenantStatuses: apikey.TenantStatuses}); err != nil {
		t.Fatal(err)
	}
	sharedLoc, err := locator.New(f.ten, f.ss, locator.Options{AdminURL: f.edge.URL(), EdgeTokenFile: f.tokFile, Logger: log})
	if err != nil {
		t.Fatal(err)
	}
	f.shared = headscale.NewRegistry(sharedLoc, headscale.Options{Logger: log})
	host := uuid.New()
	f.exec(`INSERT INTO hosts (id, name, region, run_uid_range, tenant_net_pool)
		VALUES ($1, 'host-1', 'lab', int4range(30000, 40000), '10.250.0.0/16')`, host)
	f.exec(`INSERT INTO tenants (id, slug, name, status) VALUES ($1, 'tenant-a', 'Tenant A', 'active')`, f.tenant)
	f.exec(`INSERT INTO tenant_instances (id, tenant_id, host_id, status, headscale_version, image_digest, control_hostname,
			server_url, base_domain, internal_address, run_uid, net_cidr, data_path)
		VALUES ($1, $2, $3, 'running', 'v0.29.7', 'sha256:'||repeat('a', 64), 'tenant-a.mesh.mg.test', 'https://tenant-a.mesh.mg.test',
			'tenant-a.tail.mg.test', 'hs-tenant-a:8080', 30001, '10.250.0.8/29', '/opt/meshguard/tenants/x')`, f.instance, f.tenant, host)
	f.k0, f.p0 = f.inst.NewKey(ttl)
	ref := secrets.TenantRef(f.tenant, apikey.SecretName, 1)
	if err := f.ss.Put(context.Background(), ref, []byte(f.k0)); err != nil {
		t.Fatal(err)
	}
	var exp *time.Time
	for _, key := range f.inst.Keys() {
		if key.Prefix == f.p0 {
			exp = key.Expiration
		}
	}
	f.exec(`UPDATE tenant_instances SET api_key_secret_ref = $1, api_key_prefix = $2, api_key_expires_at = $3 WHERE id = $4`,
		ref.String(), f.p0, exp, f.instance)
	f.svc = f.newService(f.st, f.prom)
	return f
}

// newService is the wiring of runner.newAPIKeyRotation on a store (several stores = several worker processes).
func (f *dbFix) newService(st *store.Store, reg prometheus.Registerer) *apikey.Service {
	f.t.Helper()
	log := logx.New(f.logs, slog.LevelDebug, "apikey-db")
	svc, err := apikey.New(st, apikey.Config{Locator: f.loc, Secrets: f.ps, Security: dbSecurity{st: st},
		Invalidate: []apikey.Invalidator{f.shared}, Headscale: headscale.Options{Logger: log}, Logger: log, Registerer: reg})
	if err != nil {
		f.t.Fatal(err)
	}
	return svc
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func (f *dbFix) exec(sql string, args ...any) {
	f.t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, err := f.su.Exec(context.Background(), sql, args...); err != nil {
		f.t.Fatalf("superuser exec: %v\n%s", err, sql)
	}
}

func (f *dbFix) count(sql string, args ...any) int {
	f.t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	var n int
	if err := f.su.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		f.t.Fatalf("superuser query: %v\n%s", err, sql)
	}
	return n
}

func (f *dbFix) str(sql string, args ...any) string {
	f.t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	var s string
	if err := f.su.QueryRow(context.Background(), sql, args...).Scan(&s); err != nil {
		f.t.Fatalf("superuser query: %v\n%s", err, sql)
	}
	return s
}

func (f *dbFix) row() (ref, prefix string, expires time.Time) {
	f.t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.su.QueryRow(context.Background(), `SELECT api_key_secret_ref, api_key_prefix, api_key_expires_at
		FROM tenant_instances WHERE id = $1`, f.instance).Scan(&ref, &prefix, &expires); err != nil {
		f.t.Fatal(err)
	}
	return ref, prefix, expires
}

func (f *dbFix) valid() []string {
	p := f.inst.ValidPrefixes()
	slices.Sort(p)
	return p
}

func (f *dbFix) rotate(req apikey.Request) (apikey.Result, error) {
	req.TenantID, req.InstanceID = f.tenant, f.instance
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	return f.svc.Rotate(ctx, req)
}

// noSecretInDB: no hskey- text in the audit, security events, job rows or the logs.
func (f *dbFix) noSecretInDB() {
	f.t.Helper()
	n := f.count(`SELECT (SELECT count(*) FROM audit_events WHERE details::text LIKE '%hskey-%')
		+ (SELECT count(*) FROM security_events WHERE details::text LIKE '%hskey-%')
		+ (SELECT count(*) FROM provisioning_jobs WHERE coalesce(output::text, '') || coalesce(error::text, '') || input::text LIKE '%hskey-%')
		+ (SELECT count(*) FROM provisioning_job_steps WHERE coalesce(detail::text, '') LIKE '%hskey-%')`)
	if n != 0 || strings.Contains(f.logs.String(), "hskey-") || strings.Contains(f.logs.String(), f.k0[23:]) {
		f.t.Fatalf("a key reached the database or the logs (%d rows)", n)
	}
}

// TestJobRotatesThroughTheFramework: the schedule enqueues apikey.rotate for the due key (dedupe key
// instance:<id>:apikey:<period>), the worker runs it — new key verified, version 2 stored, row + audit pair in one
// platform transaction, old key expired and its version destroyed — and the worker's shared registry, which had the
// old key cached, uses the new one at once (invalidated). The same period never gets a second job.
func TestJobRotatesThroughTheFramework(t *testing.T) {
	f := newDBFix(t, 10*day)
	ctx := context.Background()
	cached, err := f.shared.ForTenant(ctx, f.tenant)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cached.ListAPIKeys(ctx); err != nil {
		t.Fatal(err)
	}
	cfg := jobs.DefaultConfig()
	cfg.FetchCooldown, cfg.FetchPollInterval = 10*time.Millisecond, 50*time.Millisecond
	cfg.RetryBase, cfg.RetryMax, cfg.StartJitter, cfg.SoftStopTimeout, cfg.QueuePoolConns = 100*time.Millisecond, time.Second, 0, 2*time.Second, 4
	w, err := jobs.NewWorker(f.st, cfg, jobs.Options{Registerer: prometheus.NewRegistry(),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Register(w); err != nil {
		t.Fatal(err)
	}
	if err := w.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = w.Stop(c)
	})
	sc := f.svc.NewScheduler(apikey.SchedulerConfig{})
	now := time.Now()
	if n, err := sc.Tick(ctx, now); err != nil || n != 1 {
		t.Fatalf("schedule: %d %v", n, err)
	}
	deadline := time.Now().Add(60 * time.Second)
	for f.count(`SELECT count(*) FROM provisioning_jobs WHERE kind = 'apikey.rotate' AND status IN ('succeeded', 'failed')`) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("apikey.rotate did not finish")
		}
		time.Sleep(100 * time.Millisecond)
	}
	status := f.str(`SELECT status || '|' || dedupe_key || '|' || coalesce(output->>'outcome', '') || '|' ||
		coalesce(output->>'key_prefix', '') || '|' || coalesce(output->>'trigger', '') || '|' || coalesce(resource_type, '')
		FROM provisioning_jobs WHERE kind = 'apikey.rotate'`)
	parts := strings.Split(status, "|")
	if len(parts) != 6 || parts[0] != "succeeded" || !strings.HasPrefix(parts[1], "instance:"+f.instance.String()+":apikey:") ||
		parts[2] != apikey.OutcomeRotated || len(parts[3]) != 12 || parts[4] != apikey.TriggerSchedule || parts[5] != "instance" {
		t.Fatalf("job: %s", status)
	}
	newPrefix := parts[3]
	ref, prefix, expires := f.row()
	if ref != secrets.TenantRef(f.tenant, apikey.SecretName, 2).String() || prefix != newPrefix ||
		expires.Sub(now.Add(apikey.MaxTTL)).Abs() > time.Minute {
		t.Fatalf("registry: %s %s %s", ref, prefix, expires)
	}
	if !slices.Equal(f.valid(), []string{newPrefix}) {
		t.Fatalf("valid keys: %v", f.valid())
	}
	if n := f.count(`SELECT count(*) FROM secrets WHERE tenant_id = $1 AND name = $2 AND
		((version = 1 AND destroyed_at IS NOT NULL) OR (version = 2 AND destroyed_at IS NULL))`, f.tenant, apikey.SecretName); n != 2 {
		t.Fatalf("secret versions: %d", n)
	}
	// the audit pair: platform events (tenant_id NULL), system actor, same operation id, the tenant in the details
	if n := f.count(`SELECT count(*) FROM audit_events r JOIN audit_events s ON s.operation_id = r.operation_id
		WHERE r.action = 'instance.apikey.rotate.requested' AND s.action = 'instance.apikey.rotate.succeeded'
		AND r.tenant_id IS NULL AND s.tenant_id IS NULL AND r.actor_type = 'system' AND s.resource_type = 'instance'
		AND s.resource_id = $1 AND s.details->>'key_prefix' = $2 AND s.details->>'previous_prefix' = $3
		AND (s.details->>'ref_version')::int = 2 AND s.details->>'tenant_id' = $4`,
		f.instance.String(), newPrefix, f.p0, f.tenant.String()); n != 1 {
		t.Fatalf("audit pair: %d", n)
	}
	// the shared registry was invalidated: the cached Instance reloads on 401, a new ForTenant locates the new key
	if _, err := cached.ListAPIKeys(ctx); err != nil {
		t.Fatalf("cached instance: %v", err)
	}
	if inst, err := f.shared.ForTenant(ctx, f.tenant); err != nil {
		t.Fatal(err)
	} else if _, err := inst.ListAPIKeys(ctx); err != nil {
		t.Fatalf("shared registry: %v", err)
	}
	if n := f.count(`SELECT count(*) FROM security_events`); n != 0 {
		t.Fatalf("security events: %d", n)
	}
	if n, _ := sc.Tick(ctx, now); n != 0 {
		t.Fatalf("same period: %d jobs", n)
	}
	if got := f.svc.Expiries()[f.instance]; got.Sub(expires).Abs() > time.Second {
		t.Fatalf("gauge: %v", got)
	}
	f.noSecretInDB()
}

// TestSkipsAndStrays: a running lifecycle job of the tenant skips the rotation without any call (the skip rule of
// instance.reconcile); a stray valid key is recorded as a platform security event naming its prefix and expired.
func TestSkipsAndStrays(t *testing.T) {
	f := newDBFix(t, 60*day)
	f.exec(`INSERT INTO provisioning_jobs (tenant_id, instance_id, kind, dedupe_key, lock_key, status, max_attempts, started_at)
		VALUES ($1, $2, 'instance.upgrade', $3, $4, 'running', 6, now())`,
		f.tenant, f.instance, "instance:"+f.instance.String()+":instance.upgrade", jobs.LockKey(f.tenant))
	calls := len(f.edge.Requests())
	res, err := f.rotate(apikey.Request{Force: true})
	if err != nil || res.SkipReason != apikey.SkipLifecycleBusy || len(f.edge.Requests()) != calls {
		t.Fatalf("lifecycle busy: %+v %v", res, err)
	}
	f.exec(`UPDATE provisioning_jobs SET status = 'succeeded', finished_at = now() WHERE kind = 'instance.upgrade'`)
	if res, err = f.rotate(apikey.Request{}); err != nil || res.SkipReason != apikey.SkipNotDue {
		t.Fatalf("not due: %+v %v", res, err)
	}
	_, stray := f.inst.NewKey(30 * day)
	res, err = f.rotate(apikey.Request{})
	if err != nil || res.Outcome != apikey.OutcomeRotated || !slices.Equal(f.valid(), []string{res.KeyPrefix}) {
		t.Fatalf("stray: %+v %v valid %v", res, err, f.valid())
	}
	if n := f.count(`SELECT count(*) FROM security_events WHERE tenant_id IS NULL AND kind = 'apikey.stray' AND severity = 'high'
		AND source = 'apikey' AND details->>'prefix' = $1 AND details->>'instance_id' = $2`, stray, f.instance.String()); n != 1 {
		t.Fatalf("stray event: %d", n)
	}
	f.noSecretInDB()
}

// TestSwapIsConditional: when the instance's key reference changes while a rotation runs (another writer), the
// conditional swap writes nothing, the new key is expired and its secret version destroyed, the pair closes .failed.
func TestSwapIsConditional(t *testing.T) {
	f := newDBFix(t, 10*day)
	f.ps.arm()
	type out struct {
		res apikey.Result
		err error
	}
	done := make(chan out, 1)
	go func() {
		res, err := f.rotate(apikey.Request{})
		done <- out{res, err}
	}()
	<-f.ps.paused
	other := secrets.TenantRef(f.tenant, apikey.SecretName, 7).String()
	f.exec(`UPDATE tenant_instances SET api_key_secret_ref = $1 WHERE id = $2`, other, f.instance)
	close(f.ps.release)
	o := <-done
	if code := jobCode(o.err); code != apikey.CodeSwapConflict {
		t.Fatalf("%+v %v", o.res, o.err)
	}
	if ref, _, _ := f.row(); ref != other || !slices.Equal(f.valid(), []string{f.p0}) {
		t.Fatalf("after the conflict: ref %s, valid %v", ref, f.valid())
	}
	if n := f.count(`SELECT count(*) FROM secrets WHERE tenant_id = $1 AND version = 2 AND destroyed_at IS NOT NULL`, f.tenant); n != 1 {
		t.Fatalf("version 2 not destroyed: %d", n)
	}
	if n := f.count(`SELECT count(*) FROM audit_events WHERE action = 'instance.apikey.rotate.failed'
		AND details->>'reason' = 'swap_conflict'`); n != 1 {
		t.Fatalf("failed event: %d", n)
	}
	f.noSecretInDB()
}

// TestTwoProcessesSerialised: two worker processes (two stores) rotating the same instance at once are serialised by
// the advisory lock: every rotation succeeds, the instance ends with one valid key — the recorded one —, no stray was
// ever seen (a stray would mean two rotations interleaved).
func TestTwoProcessesSerialised(t *testing.T) {
	f := newDBFix(t, 10*day)
	second := f.newService(f.pg.OpenStore(t, f.db, "mg_worker_tenant", "mg_worker_platform", 4), nil)
	var wg sync.WaitGroup
	errs := make(chan error, 6)
	for i := range 6 {
		svc := f.svc
		if i%2 == 1 {
			svc = second
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := svc.Rotate(context.Background(), apikey.Request{TenantID: f.tenant, InstanceID: f.instance, Force: true})
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	_, prefix, _ := f.row()
	if !slices.Equal(f.valid(), []string{prefix}) {
		t.Fatalf("valid %v, recorded %s", f.valid(), prefix)
	}
	if n := f.count(`SELECT count(*) FROM audit_events WHERE action = 'instance.apikey.rotate.succeeded'`); n != 6 {
		t.Fatalf("succeeded events: %d", n)
	}
	if n := f.count(`SELECT count(*) FROM security_events`); n != 0 {
		t.Fatalf("security events: %d", n)
	}
	f.noSecretInDB()
}

// TestReconcileQuietDuringAndAfterRotation — the P3-T12 key check during a normal rotation. The rotation is held at
// step 6: the instance has two valid keys and the registry still names the old one. Without the key guard the check
// would report the new key as foreign (negative control); with it (reconcile.New wires store.WithTenantLock on
// apikey.LockName) instance.reconcile waits for the rotation, reads the recorded prefix again and reports nothing — and
// nothing after it either. A guard that cannot get the lock in time reports the check unavailable, never a drift.
func TestReconcileQuietDuringAndAfterRotation(t *testing.T) {
	f := newDBFix(t, 10*day)
	ctx := context.Background()
	rec, err := reconcile.New(f.st, reconcile.Config{Headscale: f.shared, Security: dbSecurity{st: f.st}})
	if err != nil {
		t.Fatal(err)
	}
	keyCheck := func(rep reconcile.Report) (reconcile.Check, []reconcile.Finding) {
		var c reconcile.Check
		for _, x := range rep.Checks {
			if x.Name == reconcile.CheckAPIKeys {
				c = x
			}
		}
		var fs []reconcile.Finding
		for _, x := range rep.Findings {
			if strings.HasPrefix(x.Kind, "api_key") {
				fs = append(fs, x)
			}
		}
		return c, fs
	}
	f.ps.arm()
	type out struct {
		res apikey.Result
		err error
	}
	rotated := make(chan out, 1)
	go func() {
		res, err := f.rotate(apikey.Request{})
		rotated <- out{res, err}
	}()
	<-f.ps.paused
	if len(f.valid()) != 2 {
		t.Fatalf("window: valid keys %v", f.valid())
	}
	// negative control: the same check without the guard, with the prefix the registry holds now
	bare := reconcile.Inspector{Headscale: f.shared, RotationGrace: reconcile.DefaultRotationGrace, EventWindow: day,
		AgentTimeout: time.Second}
	rep, evs := bare.Instance(ctx, reconcile.Desired{InstanceID: f.instance, TenantID: f.tenant, Slug: "tenant-a",
		Status: "running", APIKeyPrefix: f.p0})
	if _, fs := keyCheck(rep); len(fs) != 1 || fs[0].Kind != reconcile.DriftAPIKeyForeign || len(evs) != 1 {
		t.Fatalf("negative control: findings %+v events %d", rep.Findings, len(evs))
	}
	// the guarded check waits for the rotation
	type rout struct {
		rep reconcile.Report
		err error
	}
	recDone := make(chan rout, 1)
	go func() {
		rep, _, err := rec.ReconcileInstance(ctx, f.tenant, f.instance)
		recDone <- rout{rep, err}
	}()
	select {
	case r := <-recDone:
		t.Fatalf("reconcile did not wait for the rotation: %+v %v", r.rep, r.err)
	case <-time.After(500 * time.Millisecond):
	}
	close(f.ps.release)
	o := <-rotated
	if o.err != nil || o.res.Outcome != apikey.OutcomeRotated {
		t.Fatalf("rotation: %+v %v", o.res, o.err)
	}
	r := <-recDone
	c, fs := keyCheck(r.rep)
	if r.err != nil || len(fs) != 0 || c.Outcome != reconcile.OutcomeOK || c.Note != "valid=1" {
		t.Fatalf("reconcile during the rotation: check %+v findings %+v err %v", c, r.rep.Findings, r.err)
	}
	// after the rotation
	rep, _, err = rec.ReconcileInstance(ctx, f.tenant, f.instance)
	if c, fs := keyCheck(rep); err != nil || len(fs) != 0 || c.Outcome != reconcile.OutcomeOK {
		t.Fatalf("reconcile after the rotation: %+v %+v %v", c, rep.Findings, err)
	}
	// a guard that does not get the lock in time: unavailable, no finding
	short, err := reconcile.New(f.st, reconcile.Config{Headscale: f.shared, Security: dbSecurity{st: f.st},
		KeyLockWait: 200 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	f.ps.arm()
	go func() {
		res, err := f.rotate(apikey.Request{Force: true})
		rotated <- out{res, err}
	}()
	<-f.ps.paused
	rep, _, err = short.ReconcileInstance(ctx, f.tenant, f.instance)
	close(f.ps.release)
	if o := <-rotated; o.err != nil {
		t.Fatal(o.err)
	}
	if c, fs := keyCheck(rep); err != nil || len(fs) != 0 || c.Outcome != reconcile.OutcomeUnavailable ||
		c.Reason != reconcile.ReasonKeyLocked {
		t.Fatalf("guard timeout: %+v %+v %v", c, rep.Findings, err)
	}
	if n := f.count(`SELECT count(*) FROM security_events`); n != 0 {
		t.Fatalf("security events: %d", n)
	}
	f.noSecretInDB()
}

// TestSharedNames: the secret name is the one adopt-instance (and §11.3 step 13) writes — apikey does not import its
// parent package, so the constant is checked here.
func TestSharedNames(t *testing.T) {
	if apikey.SecretName != provisioning.APIKeySecretName {
		t.Fatalf("secret name %q, adopt-instance writes %q", apikey.SecretName, provisioning.APIKeySecretName)
	}
	if apikey.Kind != "apikey.rotate" || !slices.Contains(jobs.KindNames(), apikey.Kind) {
		t.Fatalf("job kind %q is not in the registry of §13.5", apikey.Kind)
	}
}

func jobCode(err error) string {
	var je *jobs.Error
	if errors.As(err, &je) {
		return je.Code
	}
	return ""
}
