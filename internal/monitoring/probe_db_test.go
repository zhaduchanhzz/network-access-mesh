package monitoring

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/zhaduchanhzz/network-access-mesh/internal/devices/devicestest"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
)

// TestProbeRecordsHealth: a probe through the real adapter records status, version, database connectivity and breaker
// in tenant_instances.last_health, with last_health_at = the database time when the probe started; the instance's
// version and updated_at (its ETag) do not change; the other tenant's instance and Headscale are untouched.
func TestProbeRecordsHealth(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	before := f.instanceRow(t, f.a.instance)
	var dbBefore, dbAfter time.Time
	f.scan(t, `SELECT clock_timestamp()`, nil, &dbBefore)
	res, err := f.wrk.Probe(ctx, f.a.id, f.a.instance)
	if err != nil {
		t.Fatal(err)
	}
	f.scan(t, `SELECT clock_timestamp()`, nil, &dbAfter)
	row := f.instanceRow(t, f.a.instance)
	if res.Status != StatusHealthy || !res.Recorded || res.Skipped != "" || res.Version != "v0.29.7" || res.Breaker != "closed" ||
		res.CheckedAt == nil {
		t.Fatalf("result %+v", res)
	}
	if !row.hasHealthDoc || row.health.Status != StatusHealthy || row.health.Reason != "" || row.health.Version != "v0.29.7" ||
		row.health.Database == nil || !*row.health.Database || row.health.Breaker != "closed" || row.health.Schema != recordSchema {
		t.Fatalf("last_health %s", row.raw)
	}
	if row.healthAt == nil || !row.healthAt.Equal(*res.CheckedAt) || row.healthAt.Before(dbBefore) || row.healthAt.After(dbAfter) {
		t.Errorf("last_health_at %v, result %v, want the database time of the probe within [%v, %v]", row.healthAt, res.CheckedAt,
			dbBefore, dbAfter)
	}
	if row.version != before.version || !row.updatedAt.Equal(before.updatedAt) {
		t.Errorf("version/updated_at changed: %d→%d %v→%v (the ETag of the instance must not move)", before.version, row.version,
			before.updatedAt, row.updatedAt)
	}
	if other := f.instanceRow(t, f.b.instance); other.hasHealthDoc || other.healthAt != nil {
		t.Errorf("B's instance written by A's probe: %s", other.raw)
	}
	if n := f.a.hs.Calls(devicestest.OpHealth); n != 1 {
		t.Errorf("GET /api/v1/health called %d times, want 1", n)
	}
	if n := f.b.hs.Calls(devicestest.OpHealth) + f.b.hs.Calls(devicestest.OpVersion); n != 0 {
		t.Errorf("B's Headscale called %d times by A's probe", n)
	}
}

// TestProbeFailureModes: with a fake Headscale behind the real adapter — instance down (bare 502 of the edge),
// database unreachable, unsupported version, breaker open after consecutive failures (the probe does not call the
// instance), then the instance back after OpenFor — each probe records an unhealthy result with its stable reason and
// the breaker state, and a later probe overwrites an earlier one.
func TestProbeFailureModes(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	reg := headscale.NewRegistry(headscale.StaticLocator{f.a.id: f.a.hs.Target(f.a.instance)}, headscale.Options{
		Timeout: 2 * time.Second, Retry: headscale.RetryPolicy{Attempts: 1},
		Breaker: headscale.BreakerConfig{FailureThreshold: 2, OpenFor: 300 * time.Millisecond},
	})
	svc := f.service(t, f.wrkSt, f.devWrk, adapterProber(reg))
	probe := func(step string) record {
		t.Helper()
		res, err := svc.Probe(ctx, f.a.id, f.a.instance)
		if err != nil {
			t.Fatalf("%s: %v", step, err)
		}
		row := f.instanceRow(t, f.a.instance)
		if !res.Recorded || row.health.Status != res.Status || row.health.Reason != res.Reason || !row.healthAt.Equal(*res.CheckedAt) {
			t.Fatalf("%s: result %+v not the recorded row %s at %v", step, res, row.raw, row.healthAt)
		}
		return row.health
	}
	check := func(step string, got record, status, reason, breaker string, version string, db *bool) {
		t.Helper()
		if got.Status != status || got.Reason != reason || got.Breaker != breaker || got.Version != version ||
			(got.Database == nil) != (db == nil) || (db != nil && *got.Database != *db) {
			t.Errorf("%s: %+v (database %v), want %s/%s breaker %s version %q database %v", step, got, showBool(got.Database),
				status, reason, breaker, version, showBool(db))
		}
	}
	yes, no := true, false

	check("up", probe("up"), StatusHealthy, "", "closed", "v0.29.7", &yes)
	f.a.hs.SetDatabase(false)
	check("database down", probe("database down"), StatusUnhealthy, headscale.ProbeDatabaseUnreachable, "closed", "v0.29.7", &no)
	f.a.hs.SetDatabase(true)
	f.a.hs.SetVersion("v0.30.0")
	check("unsupported version", probe("unsupported version"), StatusUnhealthy, headscale.ProbeUnsupportedVersion, "closed", "v0.30.0", nil)
	f.a.hs.SetVersion("v0.29.7")
	f.a.hs.SetDown(true)
	check("down 1", probe("down 1"), StatusUnhealthy, headscale.ProbeInstanceUnavailable, "closed", "", nil)
	check("down 2", probe("down 2"), StatusUnhealthy, headscale.ProbeInstanceUnavailable, "open", "", nil)
	f.a.hs.ResetCalls()
	check("breaker open", probe("breaker open"), StatusUnhealthy, headscale.ProbeCircuitOpen, "open", "", nil)
	if n := f.a.hs.Calls(devicestest.OpVersion) + f.a.hs.Calls(devicestest.OpHealth); n != 0 {
		t.Errorf("the probe called the instance %d times while its breaker was open", n)
	}
	f.a.hs.SetDown(false)
	time.Sleep(350 * time.Millisecond) // OpenFor: the next probe is the half-open trial
	check("back", probe("back"), StatusHealthy, "", "closed", "v0.29.7", &yes)
}

// TestProbeKeepsTheNewerResult: a probe that started before the recorded one (a slow probe, a replayed job) records
// nothing; a probe is skipped — nothing recorded, nothing called — for an instance that is not running, unknown for
// the tenant, or replaced by another one in the adapter's view; a probe cut short by its context says nothing.
func TestProbeKeepsTheNewerResult(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	future := time.Now().Add(time.Hour).UTC().Truncate(time.Microsecond)
	f.exec(t, `UPDATE tenant_instances SET last_health = '{"schema":1,"status":"unhealthy","reason":"instance_unavailable","duration_ms":3}',
		last_health_at = $2 WHERE id = $1`, f.a.instance, future)
	res, err := f.wrk.Probe(ctx, f.a.id, f.a.instance)
	if err != nil || res.Recorded || res.Status != StatusHealthy {
		t.Fatalf("probe older than the recorded one: %+v %v", res, err)
	}
	if row := f.instanceRow(t, f.a.instance); row.health.Reason != "instance_unavailable" || !row.healthAt.Equal(future) {
		t.Errorf("the newer result was overwritten: %s at %v", row.raw, row.healthAt)
	}

	f.exec(t, `UPDATE tenant_instances SET status = 'stopped' WHERE id = $1`, f.b.instance)
	f.b.hs.ResetCalls()
	if res, err := f.wrk.Probe(ctx, f.b.id, f.b.instance); err != nil || res.Skipped != SkipInstanceNotRunning || res.Recorded {
		t.Errorf("stopped instance: %+v %v", res, err)
	}
	if res, err := f.wrk.Probe(ctx, f.a.id, f.b.instance); err != nil || res.Skipped != SkipInstanceNotFound {
		t.Errorf("instance of another tenant: %+v %v", res, err)
	}
	if n := f.b.hs.Calls(devicestest.OpVersion); n != 0 || f.instanceRow(t, f.b.instance).hasHealthDoc {
		t.Errorf("skipped probes called Headscale %d times or wrote B's row", n)
	}
	other := uuid.New()
	moved := f.service(t, f.wrkSt, f.devWrk, ProberFunc(func(context.Context, uuid.UUID) InstanceProbe {
		return InstanceProbe{InstanceID: other, Reason: headscale.ProbeInstanceUnavailable}
	}))
	f.exec(t, `UPDATE tenant_instances SET last_health = NULL, last_health_at = NULL WHERE id = $1`, f.a.instance)
	if res, err := moved.Probe(ctx, f.a.id, f.a.instance); err != nil || res.Skipped != SkipInstanceChanged ||
		f.instanceRow(t, f.a.instance).hasHealthDoc {
		t.Errorf("adapter resolved another instance: %+v %v", res, err)
	}
	cctx, cancel := context.WithCancel(ctx)
	cut := f.service(t, f.wrkSt, f.devWrk, ProberFunc(func(context.Context, uuid.UUID) InstanceProbe {
		cancel()
		return InstanceProbe{Reason: headscale.ProbeInstanceUnavailable}
	}))
	if _, err := cut.Probe(cctx, f.a.id, f.a.instance); err == nil || f.instanceRow(t, f.a.instance).hasHealthDoc {
		t.Errorf("probe cut short: err %v, recorded %v", err, f.instanceRow(t, f.a.instance).hasHealthDoc)
	}
	if _, err := f.api.Probe(ctx, f.a.id, f.a.instance); err == nil {
		t.Error("a service without a Prober probed")
	}
}

// TestProbeTimeout: a probe is bounded by ProbeTimeout — an instance that does not answer in time is recorded unhealthy
// (what the adapter reports when its context ends: instance_unavailable) well within the job's own timeout, instead
// of the job running out of time and failing.
func TestProbeTimeout(t *testing.T) {
	f := newFixture(t)
	hung := ProberFunc(func(ctx context.Context, _ uuid.UUID) InstanceProbe {
		<-ctx.Done() // the adapter's call gives up when its context ends
		return InstanceProbe{InstanceID: f.a.instance, Breaker: "closed", Reason: headscale.ProbeInstanceUnavailable}
	})
	svc, err := New(f.wrkSt, Config{Devices: deviceCounter(f.devWrk), Prober: hung, ProbeTimeout: 300 * time.Millisecond,
		Registerer: prometheus.NewRegistry()})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second) // the job's deadline
	defer cancel()
	start := time.Now()
	res, err := svc.Probe(ctx, f.a.id, f.a.instance)
	if err != nil || !res.Recorded || res.Status != StatusUnhealthy || res.Reason != headscale.ProbeInstanceUnavailable {
		t.Fatalf("hung instance: %+v %v", res, err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("the probe took %v with ProbeTimeout 300ms", d)
	}
	if def, _ := New(f.wrkSt, Config{Devices: deviceCounter(f.devWrk)}); def.probeLimit != DefaultProbeTimeout ||
		DefaultProbeTimeout >= jobs.DefaultKinds()[KindProbe].Timeout {
		t.Errorf("default probe bound %v must stay below the job timeout of health.probe (%v)", def.probeLimit,
			jobs.DefaultKinds()[KindProbe].Timeout)
	}
}

// TestScheduler: the first tick only notes the instances; after one interval exactly one health.probe per running
// instance with the dedupe key instance:<id>:health:<slot>; ticking again in the same period enqueues nothing; a
// stopped instance is not scheduled; offsets spread instances over the interval.
func TestScheduler(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	c := f.newTenant(t, "suspended")
	f.exec(t, `UPDATE tenant_instances SET status = 'stopped' WHERE id = $1`, c.instance)
	sc := f.wrk.NewScheduler(SchedulerConfig{Interval: time.Minute, Tick: time.Second})
	t0 := time.Now()
	if n, err := sc.Tick(ctx, t0); err != nil || n != 0 {
		t.Fatalf("first tick: %d %v, want 0 (instances only noted)", n, err)
	}
	if n, err := sc.Tick(ctx, t0.Add(time.Minute)); err != nil || n != 2 {
		t.Fatalf("tick after one interval: %d %v, want 2 (A and B; C is stopped)", n, err)
	}
	if n, err := sc.Tick(ctx, t0.Add(time.Minute)); err != nil || n != 0 {
		t.Errorf("tick again in the same period: %d %v, want 0", n, err)
	}
	for _, ten := range []*tenantFx{f.a, f.b} {
		slot := sc.slot(ten.instance, t0.Add(time.Minute))
		if n := f.count(t, `SELECT count(*) FROM provisioning_jobs WHERE kind = 'health.probe' AND tenant_id = $1 AND instance_id = $2
				AND dedupe_key = $3 AND status = 'queued'`, ten.id, ten.instance, fmt.Sprintf("instance:%s:health:%d", ten.instance, slot)); n != 1 {
			t.Errorf("scheduled probe of %s: %d, want 1", ten.slug, n)
		}
	}
	if n := f.count(t, `SELECT count(*) FROM provisioning_jobs WHERE kind = 'health.probe' AND instance_id = $1`, c.instance); n != 0 {
		t.Errorf("stopped instance scheduled %d times", n)
	}
}

// alerts records the framework's alerts.
type alerts struct {
	mu  sync.Mutex
	got []jobs.Alert
}

func (a *alerts) JobAlert(_ context.Context, al jobs.Alert) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.got = append(a.got, al)
}

func (a *alerts) of(kind string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := 0
	for _, al := range a.got {
		if al.Kind == kind {
			n++
		}
	}
	return n
}

// TestProbeThroughWorker runs health.probe under the real job framework (River, P2-T12): the schedule enqueues one job
// per running instance, each job succeeds with its result as output — also for an instance that is down (the result
// is the health: unhealthy is recorded, no job alert) — and each tenant's row holds its own instance's health.
func TestProbeThroughWorker(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.b.hs.SetDown(true)
	cfg := jobs.DefaultConfig()
	cfg.FetchCooldown, cfg.FetchPollInterval = 10*time.Millisecond, 50*time.Millisecond
	cfg.StartJitter, cfg.SoftStopTimeout, cfg.QueuePoolConns = 0, 2*time.Second, 4
	rec := &alerts{}
	w, err := jobs.NewWorker(f.wrkSt, cfg, jobs.Options{Alerter: rec, Registerer: prometheus.NewRegistry()})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.wrk.Register(w); err != nil {
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
	sc := f.wrk.NewScheduler(SchedulerConfig{Interval: time.Minute, Tick: time.Second})
	t0 := time.Now()
	if _, err := sc.Tick(ctx, t0); err != nil {
		t.Fatal(err)
	}
	if n, err := sc.Tick(ctx, t0.Add(time.Minute)); err != nil || n != 2 {
		t.Fatalf("scheduled %d %v, want 2", n, err)
	}
	deadline := time.Now().Add(30 * time.Second)
	for f.count(t, `SELECT count(*) FROM provisioning_jobs WHERE kind = 'health.probe' AND status = 'succeeded'`) < 2 {
		if time.Now().After(deadline) {
			t.Fatalf("health.probe jobs not succeeded: %d", f.count(t, `SELECT count(*) FROM provisioning_jobs WHERE kind = 'health.probe' AND status = 'succeeded'`))
		}
		time.Sleep(50 * time.Millisecond)
	}
	a, b := f.instanceRow(t, f.a.instance), f.instanceRow(t, f.b.instance)
	if a.health.Status != StatusHealthy || b.health.Status != StatusUnhealthy || b.health.Reason != headscale.ProbeInstanceUnavailable {
		t.Errorf("recorded: A %s, B %s", a.raw, b.raw)
	}
	var out string
	f.scan(t, `SELECT output::text FROM provisioning_jobs WHERE kind = 'health.probe' AND instance_id = $1`, []any{f.b.instance}, &out)
	if !strings.Contains(out, `"reason": "instance_unavailable"`) || !strings.Contains(out, `"recorded": true`) {
		t.Errorf("job output of B: %s", out)
	}
	if n := rec.of(KindProbe); n != 0 {
		t.Errorf("%d job alerts for health.probe: an unhealthy instance is a result, not a failed job", n)
	}
}

func showBool(b *bool) any {
	if b == nil {
		return nil
	}
	return *b
}
