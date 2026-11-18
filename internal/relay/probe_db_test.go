package relay

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// TestProbeRecordsResult: a probe asks the prober for the region's hostname through the configured edge address and
// the region's STUN address (public entry : stun_port — exactly the probe of step 17), and records status, reason and
// both checks in relay_regions.last_probe with last_probe_at = the database time when the probe started; the region's
// version and updated_at (its administrative state) do not change; B's region is untouched and never probed.
func TestProbeRecordsResult(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	before := f.regionRow(t, f.a.region)
	dbBefore := f.dbNow(t)
	res, err := f.wrk.Probe(ctx, f.a.id, f.a.region)
	if err != nil {
		t.Fatal(err)
	}
	dbAfter := f.dbNow(t)
	reqs := f.prober.requests()
	if len(reqs) != 1 || reqs[0] != (ProbeRequest{Address: edgeAddr, Host: f.a.host, STUN: entryIPv4 + ":3478"}) {
		t.Fatalf("prober asked %+v", reqs)
	}
	row := f.regionRow(t, f.a.region)
	if res.Status != StatusHealthy || res.Reason != "" || !res.Recorded || res.Skipped != "" || res.CheckedAt == nil ||
		res.RegionID != f.a.region || res.DERP == nil || res.DERP.Status != 200 || !res.STUN.OK {
		t.Fatalf("result %+v", res)
	}
	if row.rec.Schema != recordSchema || row.rec.Status != StatusHealthy || !row.rec.DERP.OK || row.rec.DERP.Status != 200 ||
		row.rec.DERP.DurationMS != 12 || !row.rec.STUN.OK || row.rec.STUN.DurationMS != 3 {
		t.Fatalf("last_probe %s", row.raw)
	}
	if row.probeAt == nil || !row.probeAt.Equal(*res.CheckedAt) || row.probeAt.Before(dbBefore) || row.probeAt.After(dbAfter) {
		t.Errorf("last_probe_at %v, result %v, want the database time of the probe within [%v, %v]", row.probeAt, res.CheckedAt,
			dbBefore, dbAfter)
	}
	if row.version != before.version || !row.updatedAt.Equal(before.updatedAt) {
		t.Errorf("version/updated_at changed: %d→%d %v→%v", before.version, row.version, before.updatedAt, row.updatedAt)
	}
	if other := f.regionRow(t, f.b.region); other.raw != nil || other.probeAt != nil {
		t.Errorf("B's region written by A's probe: %s", other.raw)
	}
	for _, r := range reqs {
		if r.Host == f.b.host {
			t.Errorf("B probed by A's probe")
		}
	}

	// A failing check is a result: recorded unhealthy with the prober's code — and it replaces the earlier result.
	f.prober.set(f.a.host, ProbeResult{DERP: Check{OK: true, Status: 200}, STUN: Check{Code: "refused", Duration: time.Millisecond}})
	res, err = f.wrk.Probe(ctx, f.a.id, f.a.region)
	row = f.regionRow(t, f.a.region)
	if err != nil || res.Status != StatusUnhealthy || res.Reason != ReasonSTUNProbeFailed || !res.Recorded ||
		row.rec.Reason != ReasonSTUNProbeFailed || row.rec.STUN.Code != "refused" || !row.probeAt.Equal(*res.CheckedAt) {
		t.Errorf("unhealthy probe: %+v %v; row %s at %v", res, err, row.raw, row.probeAt)
	}
}

// TestProbeSkipsAndRefusals: nothing is probed nor recorded for a region of another tenant, an unknown one, a region
// that is not active, one whose instance is not running, one of a kind not probed in this release, or one without a
// STUN address; a probe that could not run (prober error) records nothing and is ErrProbeNotRun; a probe that started
// before the recorded one records nothing; a probe cut short by its context says nothing; the api's service (no
// Prober) neither probes nor registers relay.probe, and a Prober without an edge address is refused.
func TestProbeSkipsAndRefusals(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	skip := func(name string, tenant, region uuid.UUID, want string) {
		t.Helper()
		n := len(f.prober.requests())
		res, err := f.wrk.Probe(ctx, tenant, region)
		if err != nil || res.Skipped != want || res.Recorded || len(f.prober.requests()) != n {
			t.Errorf("%s: %+v %v (prober asked %d times), want skipped %s", name, res, err, len(f.prober.requests())-n, want)
		}
	}
	skip("region of another tenant", f.a.id, f.b.region, SkipRegionNotFound)
	skip("unknown region", f.a.id, uuid.New(), SkipRegionNotFound)
	f.exec(t, `UPDATE relay_regions SET status = 'disabled' WHERE id = $1`, f.a.region)
	skip("disabled region", f.a.id, f.a.region, SkipRegionNotActive)
	f.exec(t, `UPDATE relay_regions SET status = 'active' WHERE id = $1`, f.a.region)
	f.exec(t, `UPDATE relay_assignments SET status = 'pending' WHERE id = $1`, f.a.assignment)
	skip("assignment not active", f.a.id, f.a.region, SkipInstanceNotRunning)
	f.exec(t, `UPDATE relay_assignments SET status = 'active' WHERE id = $1`, f.a.assignment)
	f.exec(t, `UPDATE tenant_instances SET status = 'stopped' WHERE id = $1`, f.b.instance)
	skip("instance stopped", f.b.id, f.b.region, SkipInstanceNotRunning)
	f.exec(t, `UPDATE tenant_instances SET status = 'running' WHERE id = $1`, f.b.instance)
	standalone := uuid.New()
	f.exec(t, `INSERT INTO relay_regions (id, tenant_id, code, name, kind, derp_region_id, hostname, ipv4, stun_port,
			verify_mode, status) VALUES ($1, $2, 'derp-a', 'derper A', 'standalone', 902, 'derp.tenant01.test', '192.0.2.11', 3478,
			'verify_url', 'active')`, standalone, f.a.id)
	f.exec(t, `INSERT INTO relay_assignments (tenant_id, instance_id, relay_region_id, priority, status) VALUES ($1, $2, $3, 1, 'active')`,
		f.a.id, f.a.instance, standalone)
	skip("standalone region", f.a.id, standalone, SkipKindNotProbed)
	f.exec(t, `UPDATE relay_regions SET stun_port = NULL WHERE id = $1`, f.b.region)
	skip("region without STUN address", f.b.id, f.b.region, SkipRegionWithoutSTUN)
	f.exec(t, `UPDATE relay_regions SET stun_port = 3478 WHERE id = $1`, f.b.region)

	// The prober could not run the probe: nothing recorded, ErrProbeNotRun.
	f.prober.mu.Lock()
	f.prober.err = errors.New("prober: target_not_allowed")
	f.prober.mu.Unlock()
	if _, err := f.wrk.Probe(ctx, f.a.id, f.a.region); !errors.Is(err, ErrProbeNotRun) || f.regionRow(t, f.a.region).raw != nil {
		t.Errorf("probe that could not run: %v, recorded %s", err, f.regionRow(t, f.a.region).raw)
	}
	f.prober.mu.Lock()
	f.prober.err = nil
	f.prober.mu.Unlock()

	// A newer result is never overwritten by a probe that started earlier.
	future := time.Now().Add(time.Hour).UTC().Truncate(time.Microsecond)
	f.exec(t, `UPDATE relay_regions SET last_probe = '{"schema":1,"status":"unhealthy","reason":"relay_unreachable",
		"derp":{"ok":false,"code":"timeout","duration_ms":5000},"stun":{"ok":false,"code":"timeout","duration_ms":3000}}',
		last_probe_at = $2 WHERE id = $1`, f.a.region, future)
	res, err := f.wrk.Probe(ctx, f.a.id, f.a.region)
	if row := f.regionRow(t, f.a.region); err != nil || res.Recorded || res.Status != StatusHealthy ||
		row.rec.Reason != ReasonRelayUnreachable || !row.probeAt.Equal(future) {
		t.Errorf("probe older than the recorded one: %+v %v; row %s at %v", res, err, row.raw, row.probeAt)
	}

	// Cut short by its context (the job's deadline): no verdict, nothing recorded.
	f.exec(t, `UPDATE relay_regions SET last_probe = NULL, last_probe_at = NULL WHERE id = $1`, f.a.region)
	cctx, cancel := context.WithCancel(ctx)
	f.prober.mu.Lock()
	f.prober.block = make(chan struct{})
	f.prober.mu.Unlock()
	go func() { time.Sleep(100 * time.Millisecond); cancel() }()
	if _, err := f.wrk.Probe(cctx, f.a.id, f.a.region); err == nil || f.regionRow(t, f.a.region).raw != nil {
		t.Errorf("probe cut short: err %v, recorded %s", err, f.regionRow(t, f.a.region).raw)
	}
	f.prober.mu.Lock()
	f.prober.block = nil
	f.prober.mu.Unlock()

	if _, err := f.api.Probe(ctx, f.a.id, f.a.region); err == nil {
		t.Error("a service without a Prober probed")
	}
	if _, _, err := f.api.ProbeTenant(ctx, f.a.id); err == nil {
		t.Error("a service without a Prober probed a tenant")
	}
	w, err := jobs.NewWorker(f.wrkSt, jobs.DefaultConfig(), jobs.Options{Registerer: prometheus.NewRegistry()})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.api.Register(w); err == nil {
		t.Error("relay.probe registered without a Prober")
	}
	if _, err := New(f.wrkSt, Config{Prober: f.prober, EdgeAddress: "edge:443"}); err == nil {
		t.Error("a Prober without an ip:port edge address was accepted")
	}
}

// TestProbeRecordWriters: only the worker's platform pool may write a probe result — the api's pools and the
// worker's tenant pool are refused by the grants of 0019; the CHECKs of 0019 keep the document and its time together
// and the document an object.
func TestProbeRecordWriters(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	write := func(st *store.Store, platform bool) error {
		at := time.Now().UTC()
		rec := func(q *sqlcdb.Queries) error {
			_, err := q.RecordRelayProbe(ctx, sqlcdb.RecordRelayProbeParams{Probe: []byte(`{"schema":1}`), CheckedAt: &at,
				ID: f.a.region, TenantID: f.a.id})
			return err
		}
		if platform {
			return st.WithPlatformTx(ctx, rec)
		}
		return st.WithTenantTx(ctx, f.a.id, rec)
	}
	for name, err := range map[string]error{
		"api platform pool":    write(f.apiSt, true),
		"api tenant pool":      write(f.apiSt, false),
		"worker tenant pool":   write(f.wrkSt, false),
		"worker platform pool": write(f.wrkSt, true),
	} {
		denied := err != nil && store.SQLState(err) == "42501"
		if (name == "worker platform pool") == denied || (name == "worker platform pool" && err != nil) {
			t.Errorf("%s: %v (sqlstate %q)", name, err, store.SQLState(err))
		}
	}
	for name, sql := range map[string]string{
		"document without time":  `UPDATE relay_regions SET last_probe = '{"schema":1}', last_probe_at = NULL WHERE id = $1`,
		"time without document":  `UPDATE relay_regions SET last_probe = NULL, last_probe_at = now() WHERE id = $1`,
		"document not an object": `UPDATE relay_regions SET last_probe = '[1]', last_probe_at = now() WHERE id = $1`,
	} {
		if err := f.execErr(sql, f.a.region); store.SQLState(err) != "23514" {
			t.Errorf("%s: %v, want a CHECK violation", name, err)
		}
	}
}

// TestScheduler: the first tick probes the regions never probed (a tenant provisioned a moment ago gets a result now,
// not after an interval) and only notes the others; after one interval exactly one relay.probe per probed region with
// the dedupe key relay:<region>:probe:<slot>, the tenant of the region and the region as resource; ticking again in the
// same period enqueues nothing; a disabled region, one whose instance is stopped and a standalone one are not scheduled.
func TestScheduler(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	c := f.newTenant(t)
	f.exec(t, `UPDATE relay_regions SET status = 'disabled' WHERE id = $1`, c.region)
	d := f.newTenant(t)
	f.exec(t, `UPDATE tenant_instances SET status = 'stopped' WHERE id = $1`, d.instance)
	f.exec(t, `UPDATE relay_regions SET last_probe = '{"schema":1}', last_probe_at = now() WHERE id = $1`, f.b.region)
	sc := f.wrk.NewScheduler(SchedulerConfig{Interval: time.Minute, Tick: time.Second})
	t0 := time.Now()
	if n, err := sc.Tick(ctx, t0); err != nil || n != 1 {
		t.Fatalf("first tick: %d %v, want 1 (A never probed; B probed before: only noted)", n, err)
	}
	if n, err := sc.Tick(ctx, t0); err != nil || n != 0 {
		t.Fatalf("same tick again: %d %v, want 0", n, err)
	}
	if n, err := sc.Tick(ctx, t0.Add(time.Minute)); err != nil || n != 2 {
		t.Fatalf("tick after one interval: %d %v, want 2 (A and B; C disabled, D stopped)", n, err)
	}
	if n, err := sc.Tick(ctx, t0.Add(time.Minute)); err != nil || n != 0 {
		t.Errorf("tick again in the same period: %d %v, want 0", n, err)
	}
	for _, ten := range []*tenantFx{f.a, f.b} {
		slot := sc.slot(ten.region, t0.Add(time.Minute))
		if n := f.count(t, `SELECT count(*) FROM provisioning_jobs WHERE kind = 'relay.probe' AND tenant_id = $1 AND instance_id IS NULL
				AND dedupe_key = $2 AND status = 'queued' AND resource_type = 'relay_region' AND resource_id = $3
				AND input->>'region_id' = $3`, ten.id, fmt.Sprintf("relay:%s:probe:%d", ten.region, slot), ten.region.String()); n != 1 {
			t.Errorf("scheduled probe of %s: %d, want 1", ten.slug, n)
		}
	}
	if n := f.count(t, `SELECT count(*) FROM provisioning_jobs WHERE kind = 'relay.probe' AND tenant_id IN ($1, $2)`, c.id, d.id); n != 0 {
		t.Errorf("disabled region / stopped instance scheduled %d times", n)
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

// TestProbeThroughWorker runs relay.probe under the real job framework (River, P2-T12): the schedule enqueues one job
// per region, each job succeeds with its result as output — also for an unhealthy relay (the result is recorded, no
// job alert) — and each tenant's region holds its own result; a probe that could not run fails its job (one attempt,
// code prober_unavailable) and records nothing.
func TestProbeThroughWorker(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.prober.set(f.b.host, ProbeResult{DERP: Check{Status: 502, Code: "expectation_failed"}, STUN: Check{OK: true}})
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
	if n, err := sc.Tick(ctx, time.Now()); err != nil || n != 2 {
		t.Fatalf("scheduled %d %v, want 2 (both regions never probed)", n, err)
	}
	waitJobs := func(status string, want int) {
		t.Helper()
		deadline := time.Now().Add(30 * time.Second)
		for f.count(t, `SELECT count(*) FROM provisioning_jobs WHERE kind = 'relay.probe' AND status = $1`, status) < want {
			if time.Now().After(deadline) {
				t.Fatalf("relay.probe jobs %s: %d, want %d", status,
					f.count(t, `SELECT count(*) FROM provisioning_jobs WHERE kind = 'relay.probe' AND status = $1`, status), want)
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	waitJobs("succeeded", 2)
	a, b := f.regionRow(t, f.a.region), f.regionRow(t, f.b.region)
	if a.rec.Status != StatusHealthy || b.rec.Status != StatusUnhealthy || b.rec.Reason != ReasonDERPProbeFailed || b.rec.DERP.Status != 502 {
		t.Errorf("recorded: A %s, B %s", a.raw, b.raw)
	}
	var out string
	f.scan(t, `SELECT output::text FROM provisioning_jobs WHERE kind = 'relay.probe' AND tenant_id = $1`, []any{f.b.id}, &out)
	if !strings.Contains(out, `"reason": "derp_probe_failed"`) || !strings.Contains(out, `"recorded": true`) ||
		!strings.Contains(out, f.b.region.String()) || strings.Contains(out, entryIPv4) || strings.Contains(out, edgeAddr) {
		t.Errorf("job output of B: %s", out)
	}
	if n := rec.of(KindProbe); n != 0 {
		t.Errorf("%d job alerts for relay.probe: an unhealthy relay is a result, not a failed job", n)
	}

	// The prober is down: the job fails (one attempt), nothing is recorded, the earlier result stays.
	f.prober.mu.Lock()
	f.prober.err = errors.New("dial tcp: connection refused")
	f.prober.mu.Unlock()
	if n, err := sc.Tick(ctx, time.Now().Add(time.Minute)); err != nil || n != 2 {
		t.Fatalf("second round scheduled %d %v", n, err)
	}
	waitJobs("failed", 2)
	var code string
	f.scan(t, `SELECT error->>'code' FROM provisioning_jobs WHERE kind = 'relay.probe' AND status = 'failed' AND tenant_id = $1`,
		[]any{f.a.id}, &code)
	if code != CodeProberUnavailable {
		t.Errorf("failed job code %q, want %s", code, CodeProberUnavailable)
	}
	if again := f.regionRow(t, f.a.region); !again.probeAt.Equal(*a.probeAt) || again.rec.Status != StatusHealthy {
		t.Errorf("a probe that could not run changed A's result: %s at %v", again.raw, again.probeAt)
	}
}
