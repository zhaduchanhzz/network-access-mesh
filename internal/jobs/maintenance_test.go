package jobs

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	dto "github.com/prometheus/client_model/go"

	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/storetest"
)

// helperDB names the database of the child worker process of TestKilledWorkerIsReaped.
const helperDB = "MG_JOBS_HELPER_DB"

// TestHelperWorkerProcess is not a test of its own: TestKilledWorkerIsReaped runs it in a child process — a real worker
// (River client + handler) that hangs inside a step until it is killed with SIGKILL.
func TestHelperWorkerProcess(t *testing.T) {
	db := os.Getenv(helperDB)
	if db == "" {
		t.Skip("helper process of TestKilledWorkerIsReaped")
	}
	env := storetest.Require(t)
	st := env.OpenStore(t, db, "mg_worker_tenant", "mg_worker_platform", 4)
	cfg := testConfig()
	k := cfg.Kinds["instance.restart"]
	k.Timeout = 3 * time.Second
	cfg.Kinds["instance.restart"] = k
	w, err := NewWorker(st, cfg, Options{})
	if err != nil {
		t.Fatal(err)
	}
	never := make(chan struct{}) // never closed: the step hangs, ignoring its context, until the process is killed
	if err := w.Register("instance.restart", HandlerFunc(func(ctx context.Context, run *Run) error {
		return run.Step(ctx, "instance.stop", func(context.Context, *StepRun) error {
			<-never
			return nil
		})
	})); err != nil {
		t.Fatal(err)
	}
	if err := w.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	fmt.Println("helper worker started")
	<-never
}

// TestKilledWorkerIsReaped: P2-T12 "kill worker giữa job ⇒ job.reaper chuyển failed_resumable + cảnh báo". A worker
// process running a lifecycle job is killed with SIGKILL inside a step; once timeout_at has passed, job.reaper moves
// the job to failed_resumable (code worker_lost) — the tenant lock stays held until /retry or /rollback — and raises an
// alert. River's rescuer later re-delivers the stuck River job to a new worker, which must not run the job again.
func TestKilledWorkerIsReaped(t *testing.T) {
	f := newFixture(t)
	st := f.workerStore(t)
	j := mustEnqueue(t, f.api(t), Spec{Kind: "instance.restart", TenantID: &f.a, InstanceID: &f.instA})

	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestHelperWorkerProcess$", "-test.count=1", "-test.v") //nolint:gosec // the test binary itself
	cmd.Env = append(os.Environ(), helperDB+"="+f.db)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	exited := false
	t.Cleanup(func() {
		if !exited {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	})
	eventually(t, 60*time.Second, "the child worker is inside step instance.stop", func() bool {
		return scalar[int64](t, f, `SELECT count(*) FROM provisioning_job_steps
			WHERE job_id = $1 AND name = 'instance.stop' AND status = 'running'`, j.Job.ID) == 1
	})
	if err := cmd.Process.Kill(); err != nil { // SIGKILL: no deferred function, no River shutdown, nothing
		t.Fatal(err)
	}
	_ = cmd.Wait()
	exited = true
	t.Logf("child worker killed; its output:\n%s", out.String())

	mid := f.job(t, st, j.Job.ID)
	if mid.Status != StatusRunning || mid.Attempt != 1 || mid.TimeoutAt == nil || f.queueState(t, mid) != "running" {
		t.Fatalf("after the kill: status %s attempt %d, River %s; want running, 1, running", mid.Status, mid.Attempt, f.queueState(t, mid))
	}
	time.Sleep(time.Until(*mid.TimeoutAt) + 200*time.Millisecond)

	w, alerts := newWorker(t, st, testConfig(), Options{})
	rep, err := w.reap(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	reaped := f.job(t, st, j.Job.ID)
	if rep.WorkerLost != 1 || reaped.Status != StatusFailedResumable || errorCode(reaped) != CodeWorkerLost ||
		reaped.FinishedAt != nil || reaped.Attempt != 1 {
		t.Fatalf("reaped: report %+v, job %s %q finished %v attempt %d; want failed_resumable worker_lost, not finished",
			rep, reaped.Status, errorCode(reaped), reaped.FinishedAt, reaped.Attempt)
	}
	a, ok := alerts.find(AlertReaped, j.Job.ID)
	if !ok || a.Status != StatusFailedResumable || a.Code != CodeWorkerLost || a.Kind != "instance.restart" ||
		a.TenantID == nil || *a.TenantID != f.a {
		t.Errorf("alert = %+v (found %v)", a, ok)
	}
	if got := counter(t, w.metrics.alerts, "instance.restart", AlertReaped); got != 1 {
		t.Errorf("meshguard_job_alerts_total{reason=reaped} = %v, want 1", got)
	}
	// the lock stays with the reaped job: another lifecycle job of the tenant cannot start
	next := f.job(t, st, mustEnqueue(t, f.api(t), Spec{Kind: "instance.reconfigure", TenantID: &f.a, InstanceID: &f.instA}).Job.ID)
	err = st.WithPlatformJobTx(t.Context(), func(tx *store.Tx) error {
		_, err := acquireJob(t.Context(), tx.Q, next.ID, *next.QueueJobID, 60)
		return err
	})
	if store.SQLConstraint(err) != lockIndex {
		t.Errorf("lifecycle job started while the reaped job holds the lock: %v", err)
	}
	if again, err := w.reap(t.Context()); err != nil || again != (ReapReport{}) || len(alerts.all()) != 1 {
		t.Errorf("second reaper run: %+v, %v, %d alerts; want a no-op", again, err, len(alerts.all()))
	}

	// River's rescuer re-delivers the stuck River job (the dead worker's leadership expires first): the new worker
	// finds a failed_resumable job and does nothing — no resurrection without /retry.
	f.exec(t, "UPDATE provisioning_jobs SET status = 'cancelled', finished_at = now() WHERE id = $1", next.ID)
	cfg := testConfig()
	cfg.ReaperInterval = 500 * time.Millisecond
	setTimeouts(&cfg, time.Second, 2*time.Second)
	cfg.JobTimeout = 2 * time.Second
	cfg.RescueStuckJobsAfter = 3 * time.Second
	w2, _ := newWorker(t, st, cfg, Options{})
	var runs atomic.Int32
	if err := w2.Register("instance.restart", HandlerFunc(func(context.Context, *Run) error { runs.Add(1); return nil })); err != nil {
		t.Fatal(err)
	}
	start(t, w2)
	eventually(t, 90*time.Second, "River rescued the stuck job and the new worker settled it", func() bool {
		s := f.queueState(t, reaped)
		return s == "completed" || s == "cancelled"
	})
	if runs.Load() != 0 {
		t.Errorf("the handler ran %d times for a reaped job", runs.Load())
	}
	if final := f.job(t, st, j.Job.ID); final.Status != StatusFailedResumable || final.Attempt != 1 {
		t.Errorf("after the rescue: %s attempt %d, want failed_resumable 1", final.Status, final.Attempt)
	}
}

// TestReaperQueueLost: a job the queue dropped — its River job cancelled, discarded or deleted — is settled by
// job.reaper (queue_lost): failed_resumable for a started lifecycle job, failed for one that never started; healthy jobs
// are left alone; the gauge of unfinished jobs is refreshed.
func TestReaperQueueLost(t *testing.T) {
	f := newFixture(t)
	st := f.workerStore(t)
	api := f.api(t)
	w, alerts := newWorker(t, st, testConfig(), Options{})

	started := f.job(t, st, mustEnqueue(t, api, Spec{Kind: "instance.restart", TenantID: &f.a, InstanceID: &f.instA}).Job.ID)
	if err := st.WithPlatformJobTx(t.Context(), func(tx *store.Tx) error {
		_, err := acquireJob(t.Context(), tx.Q, started.ID, *started.QueueJobID, 600)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	f.exec(t, "UPDATE river.river_job SET state = 'discarded', finalized_at = now() WHERE id = $1", *started.QueueJobID)
	never := f.job(t, st, mustEnqueue(t, api, Spec{Kind: "instance.upgrade", TenantID: &f.b, InstanceID: &f.instB}).Job.ID)
	f.exec(t, "DELETE FROM river.river_job WHERE id = $1", *never.QueueJobID)
	healthy := mustEnqueue(t, api, Spec{Kind: "policy.apply", TenantID: &f.a})
	young := mustEnqueue(t, api, Spec{Kind: "policy.apply", TenantID: &f.b})
	f.exec(t, "UPDATE provisioning_jobs SET created_at = now() - interval '1 minute' WHERE id <> $1", young.Job.ID)
	f.exec(t, "UPDATE river.river_job SET state = 'cancelled', finalized_at = now() WHERE args->>'job_id' = $1", young.Job.ID.String())

	rep, err := w.reap(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if rep.QueueLost != 2 || rep.WorkerLost != 0 {
		t.Errorf("report %+v, want 2 queue_lost", rep)
	}
	for id, want := range map[uuid.UUID]string{started.ID: StatusFailedResumable, never.ID: StatusFailed,
		healthy.Job.ID: StatusQueued, young.Job.ID: StatusQueued} {
		j := f.job(t, st, id)
		if j.Status != want {
			t.Errorf("%s: %s, want %s", j.Kind, j.Status, want)
		}
		if want != StatusQueued {
			if errorCode(j) != CodeQueueLost {
				t.Errorf("%s: code %q", j.Kind, errorCode(j))
			}
			if _, ok := alerts.find(AlertReaped, id); !ok {
				t.Errorf("%s: no alert", j.Kind)
			}
		}
	}
	m := &dto.Metric{}
	if err := w.metrics.unfinished.WithLabelValues(StatusFailedResumable).Write(m); err != nil || m.GetGauge().GetValue() != 1 {
		t.Errorf("meshguard_jobs_unfinished{status=failed_resumable} = %v, want 1", m.GetGauge().GetValue())
	}
}

// TestRetentionSweep: retention.sweep applies §6.4 — finished jobs after 180 days (steps by cascade, the device's
// revocation reference set NULL), expired Idempotency-Keys, security_events after 400 days, device cache rows removed
// more than 90 days ago — and never touches audit_events, which no worker role may delete from.
func TestRetentionSweep(t *testing.T) {
	f := newFixture(t)
	st := f.workerStore(t)
	w, _ := newWorker(t, st, testConfig(), Options{})
	jobAt := func(tenant *uuid.UUID, status, finished string) uuid.UUID {
		id := uuid.New()
		f.exec(t, fmt.Sprintf(`INSERT INTO provisioning_jobs (id, tenant_id, kind, status, created_at, finished_at)
			VALUES ($1, $2, 'policy.apply', $3, now() - interval '500 days', %s)`, finished), id, tenant, status)
		return id
	}
	oldJob := jobAt(&f.a, StatusSucceeded, "now() - interval '181 days'")
	f.exec(t, `INSERT INTO provisioning_job_steps (tenant_id, job_id, seq, name, status) VALUES ($1, $2, 0, 'apply', 'succeeded')`, f.a, oldJob)
	refJob := jobAt(&f.a, StatusFailed, "now() - interval '200 days'")
	platformJob := jobAt(nil, StatusCancelled, "now() - interval '300 days'")
	recentJob := jobAt(&f.a, StatusSucceeded, "now() - interval '179 days'")
	resumable := jobAt(&f.b, StatusFailedResumable, "NULL")
	device := func(node int, removed string) uuid.UUID {
		id := uuid.New()
		f.exec(t, fmt.Sprintf(`INSERT INTO device_inventory_cache (id, tenant_id, instance_id, headscale_node_id, machine_key, removed_at)
			VALUES ($1, $2, $3, $4, $5, %s)`, removed), id, f.a, f.instA, node, fmt.Sprintf("mkey:%d", node))
		return id
	}
	live := device(1, "NULL")
	f.exec(t, "UPDATE device_inventory_cache SET revocation_state = 'failed', revocation_kind = 'expire', revocation_job_id = $1 WHERE id = $2", refJob, live)
	oldDevice := device(2, "now() - interval '91 days'")
	recentDevice := device(3, "now() - interval '89 days'")
	for i, exp := range []string{"now() - interval '1 hour'", "now() + interval '1 hour'"} {
		f.exec(t, fmt.Sprintf(`INSERT INTO idempotency_keys (tenant_id, identity_id, operation_id, key, request_hash, expires_at)
			VALUES ($1, $2, 'expireDevice', $3, sha256(convert_to($3, 'UTF8')), %s)`, exp), f.a, f.identity, fmt.Sprintf("key-%d", i))
	}
	for _, at := range []string{"401 days", "399 days"} {
		f.exec(t, "INSERT INTO security_events (tenant_id, kind, severity, source, occurred_at) VALUES ($1, 'test', 'low', 'test', now() - $2::interval)", f.a, at)
	}
	for _, at := range []string{"800 days", "500 days", "0 days"} {
		f.exec(t, `INSERT INTO audit_events (tenant_id, actor_type, action, resource_type, outcome, occurred_at)
			VALUES ($1, 'system', 'test.retention', 'test', 'success', now() - $2::interval)`, f.a, at)
	}
	audit := func() int64 { return scalar[int64](t, f, "SELECT count(*) FROM audit_events") }
	auditBefore := audit()

	rep, err := w.sweep(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if rep != (SweepReport{Jobs: 3, IdempotencyKeys: 1, SecurityEvents: 1, RemovedDevices: 1}) {
		t.Errorf("sweep report %+v, want 3 jobs, 1 key, 1 security event, 1 device", rep)
	}
	exists := func(table string, id uuid.UUID) bool {
		return scalar[int64](t, f, "SELECT count(*) FROM "+table+" WHERE id = $1", id) == 1
	}
	for id, want := range map[uuid.UUID]bool{oldJob: false, refJob: false, platformJob: false, recentJob: true, resumable: true} {
		if exists("provisioning_jobs", id) != want {
			t.Errorf("job %s: present = %v, want %v", id, !want, want)
		}
	}
	if n := scalar[int64](t, f, "SELECT count(*) FROM provisioning_job_steps WHERE job_id = $1", oldJob); n != 0 {
		t.Error("steps of a deleted job remain")
	}
	if !exists("device_inventory_cache", live) || exists("device_inventory_cache", oldDevice) || !exists("device_inventory_cache", recentDevice) {
		t.Error("device_inventory_cache retention: wrong rows deleted")
	}
	if ref := scalar[*uuid.UUID](t, f, "SELECT revocation_job_id FROM device_inventory_cache WHERE id = $1", live); ref != nil {
		t.Errorf("revocation_job_id of the live device = %v after its job was deleted, want NULL", ref)
	}
	if got := audit(); got != auditBefore || got != 3 {
		t.Errorf("audit_events: %d rows before, %d after the sweep; retention.sweep must never touch them", auditBefore, got)
	}
	for _, role := range []string{"mg_worker_platform", "mg_worker_tenant", "mg_api_platform", "mg_api_tenant"} {
		for _, p := range []string{"DELETE", "TRUNCATE", "UPDATE"} {
			if scalar[bool](t, f, "SELECT has_table_privilege($1, 'audit_events', $2)", role, p) {
				t.Errorf("%s has %s on audit_events", role, p)
			}
		}
	}
	if again, err := w.sweep(t.Context()); err != nil || again != (SweepReport{}) {
		t.Errorf("second sweep: %+v %v, want nothing", again, err)
	}
}

// TestPeriodicJobsRecordTheirRuns: the periodic jobs are enqueued by River's leader — retention.sweep and
// partition.maintain on start (RunOnStart: OSS periodic schedules are not durable), job.reaper every interval — and
// each run records its own provisioning_jobs row (platform job, dedupe key <kind>:<slot>) with its output;
// partition.maintain raises an alert when rows sit in a DEFAULT partition.
func TestPeriodicJobsRecordTheirRuns(t *testing.T) {
	f := newFixture(t)
	st := f.workerStore(t)
	f.exec(t, `INSERT INTO audit_events (tenant_id, actor_type, action, resource_type, outcome, occurred_at)
		VALUES ($1, 'system', 'test.default_partition', 'test', 'success', now() - interval '2 years')`, f.a)
	cfg := testConfig()
	cfg.periodicOff = false
	cfg.ReaperInterval = 500 * time.Millisecond
	w, alerts := newWorker(t, st, cfg, Options{Partitions: f.env.OpenPartitionMaintainer(t, f.db)})
	start(t, w)
	count := func(kind string) int64 {
		return scalar[int64](t, f, "SELECT count(*) FROM provisioning_jobs WHERE kind = $1 AND status = 'succeeded'", kind)
	}
	eventually(t, 30*time.Second, "periodic runs", func() bool {
		return count("job.reaper") >= 2 && count("retention.sweep") == 1 && count("partition.maintain") == 1
	})
	rows, err := f.su.Query(t.Context(), `SELECT kind, dedupe_key, tenant_id IS NULL, requested_by IS NULL, output::text
		FROM provisioning_jobs WHERE status = 'succeeded'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	keys := map[string]bool{}
	for rows.Next() {
		var kind, key, output string
		var platform, system bool
		if err := rows.Scan(&kind, &key, &platform, &system, &output); err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(key, kind+":") || keys[key] || !platform || !system {
			t.Errorf("periodic run %s: dedupe key %q (duplicate %v), platform %v, system %v", kind, key, keys[key], platform, system)
		}
		keys[key] = true
		var out map[string]any
		if json.Unmarshal([]byte(output), &out) != nil {
			t.Errorf("%s: output %s", kind, output)
		}
		if kind == "partition.maintain" && !strings.Contains(output, `"default_rows": 1`) {
			t.Errorf("partition.maintain output = %s, want the DEFAULT row reported", output)
		}
	}
	found := false
	for _, a := range alerts.all() {
		found = found || (a.Reason == AlertPartitionDefaultRows && a.Code == "audit_events")
	}
	if !found {
		t.Errorf("no partition_default_rows alert: %+v", alerts.all())
	}
}
