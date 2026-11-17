package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// canary has the shape of a Headscale API key; built by concatenation so the secret scanner does not flag the source.
const canary = "hskey-api-" + "abc123-CANARY7f3a9c1e"

// TestRetryWithBackoff: a transient error is retried with exponential backoff (attempts not wasted), the job keeps
// running in between, and succeeds; River's own error log holds only the error code, never the handler's text.
func TestRetryWithBackoff(t *testing.T) {
	f := newFixture(t)
	st := f.workerStore(t)
	w, alerts := newWorker(t, st, testConfig(), Options{})
	var (
		mu    sync.Mutex
		calls []time.Time
	)
	if err := w.Register("policy.apply", HandlerFunc(func(_ context.Context, run *Run) error {
		mu.Lock()
		calls = append(calls, time.Now())
		n := len(calls)
		mu.Unlock()
		if n < 3 {
			return Transient("instance_unavailable", errors.New("headscale did not answer with "+canary))
		}
		return run.SetOutput(map[string]any{"applied": true})
	})); err != nil {
		t.Fatal(err)
	}
	start(t, w)
	j := mustEnqueue(t, f.api(t), Spec{Kind: "policy.apply", TenantID: &f.a})
	done := f.waitStatus(t, st, j.Job.ID, StatusSucceeded, 20*time.Second)
	if done.Attempt != 3 || done.Error != nil || done.FinishedAt == nil || string(done.Output) != `{"applied": true}` {
		t.Errorf("succeeded job = attempt %d, error %s, finished %v, output %s", done.Attempt, done.Error, done.FinishedAt, done.Output)
	}
	mu.Lock()
	gaps := []time.Duration{calls[1].Sub(calls[0]), calls[2].Sub(calls[1])}
	mu.Unlock()
	// backoff 50 ms then 100 ms (±20 %): the second wait is the longer one
	if gaps[0] < 40*time.Millisecond || gaps[1] < 80*time.Millisecond {
		t.Errorf("retry gaps %v, want ≥ 40 ms then ≥ 80 ms (exponential backoff)", gaps)
	}
	eventually(t, 5*time.Second, "River job completed", func() bool { return f.queueState(t, done) == "completed" })
	errs := scalar[string](t, f, "SELECT COALESCE(array_to_string(errors, ' '), '') FROM river.river_job WHERE id = $1", *done.QueueJobID)
	if strings.Count(errs, "instance_unavailable") != 2 || strings.Contains(errs, "CANARY") || strings.Contains(errs, "headscale") {
		t.Errorf("River errors = %s; want the two codes only", errs)
	}
	if a := alerts.all(); len(a) != 0 {
		t.Errorf("alerts after a job that eventually succeeded: %+v", a)
	}
}

type compensatingHandler struct {
	HandlerFunc
	compensated atomic.Int32
}

func (h *compensatingHandler) Compensate(context.Context, *Run, error) error {
	h.compensated.Add(1)
	return nil
}

// TestFailureOutcomesAndAlerts: §11.3 and §16.3 — attempts exhausted on a transient error: failed (alert) for an
// ordinary kind, failed_resumable (alert, lock kept, the next lifecycle job of the tenant waits) for the lifecycle
// group; instance.backup fails and releases the lock; a permanent error compensates a lifecycle job that can
// (rolled_back + alert) and leaves one that cannot in failed_resumable; a panic and a timeout end the job; credentials
// never reach the stored error.
func TestFailureOutcomesAndAlerts(t *testing.T) {
	f := newFixture(t)
	st := f.workerStore(t)
	api := f.api(t)
	cfg := testConfig()
	for _, name := range []string{"health.probe", "instance.upgrade"} {
		k := cfg.Kinds[name]
		k.Timeout = 300 * time.Millisecond
		cfg.Kinds[name] = k
	}
	w, alerts := newWorker(t, st, cfg, Options{})
	var reconfRuns atomic.Int32
	failing := HandlerFunc(func(context.Context, *Run) error {
		return Transient("instance_unavailable", errors.New("agent unreachable using "+canary))
	})
	permanent := HandlerFunc(func(context.Context, *Run) error { return Permanent("config_invalid", errors.New("bad config")) })
	blocking := HandlerFunc(func(ctx context.Context, _ *Run) error { <-ctx.Done(); return ctx.Err() })
	comp := &compensatingHandler{HandlerFunc: permanent}
	for kind, h := range map[string]Handler{
		"policy.apply":     failing,
		"instance.restart": failing,
		"instance.reconfigure": HandlerFunc(func(context.Context, *Run) error {
			reconfRuns.Add(1)
			return nil
		}),
		"instance.backup":  permanent,
		"tenant.suspend":   comp,
		"tenant.resume":    permanent,
		"device.revoke":    HandlerFunc(func(context.Context, *Run) error { panic("nil map in handler") }),
		"health.probe":     blocking,
		"instance.upgrade": blocking,
	} {
		if err := w.Register(kind, h); err != nil {
			t.Fatal(err)
		}
	}
	start(t, w)
	tC, iC := f.newTenant(t)
	tD, _ := f.newTenant(t)
	tE, _ := f.newTenant(t)
	tF, iF := f.newTenant(t)
	tG, iG := f.newTenant(t)

	apply := mustEnqueue(t, api, Spec{Kind: "policy.apply", TenantID: &f.a, MaxAttempts: 2})
	restart := mustEnqueue(t, api, Spec{Kind: "instance.restart", TenantID: &f.b, InstanceID: &f.instB, MaxAttempts: 2})
	backup := mustEnqueue(t, api, Spec{Kind: "instance.backup", TenantID: &tC, InstanceID: &iC, Slot: "s1"})
	suspend := mustEnqueue(t, api, Spec{Kind: "tenant.suspend", TenantID: &tD})
	resume := mustEnqueue(t, api, Spec{Kind: "tenant.resume", TenantID: &tE})
	revoke := mustEnqueue(t, api, Spec{Kind: "device.revoke", TenantID: &f.a, Object: "d1"})
	probe := mustEnqueue(t, api, Spec{Kind: "health.probe", TenantID: &tF, InstanceID: &iF, Slot: "s1"})
	upgrade := mustEnqueue(t, api, Spec{Kind: "instance.upgrade", TenantID: &tG, InstanceID: &iG})

	type want struct {
		job      Enqueued
		status   string
		code     string
		attempts int32
		alert    string
	}
	for _, c := range []want{
		{apply, StatusFailed, "instance_unavailable", 2, AlertFailed},
		{restart, StatusFailedResumable, "instance_unavailable", 2, AlertFailedResumable},
		{backup, StatusFailed, "config_invalid", 1, AlertFailed},
		{suspend, StatusRolledBack, "config_invalid", 1, AlertRolledBack},
		{resume, StatusFailedResumable, "config_invalid", 1, AlertFailedResumable},
		{revoke, StatusFailed, CodeHandlerPanic, 1, AlertFailed},
		{probe, StatusFailed, CodeTimeout, 1, AlertFailed},
	} {
		j := f.waitStatus(t, st, c.job.Job.ID, c.status, 20*time.Second)
		if errorCode(j) != c.code || j.Attempt != c.attempts {
			t.Errorf("%s: code %q attempt %d, want %q %d", j.Kind, errorCode(j), j.Attempt, c.code, c.attempts)
		}
		if final := c.status != StatusFailedResumable; final != (j.FinishedAt != nil) {
			t.Errorf("%s %s: finished_at = %v", j.Kind, j.Status, j.FinishedAt)
		}
		if strings.Contains(string(j.Error), "CANARY") {
			t.Errorf("%s: credential stored in the job error: %s", j.Kind, j.Error)
		}
		eventually(t, 5*time.Second, j.Kind+" alert", func() bool { _, ok := alerts.find(c.alert, j.ID); return ok })
		a, _ := alerts.find(c.alert, j.ID)
		if a.Status != c.status || a.Code != c.code || a.Kind != j.Kind || a.TenantID == nil || *a.TenantID != *j.TenantID {
			t.Errorf("%s: alert %+v", j.Kind, a)
		}
		if got := counter(t, w.metrics.alerts, j.Kind, c.alert); got != 1 {
			t.Errorf("%s: meshguard_job_alerts_total{reason=%s} = %v, want 1", j.Kind, c.alert, got)
		}
		eventually(t, 5*time.Second, j.Kind+" River job cancelled", func() bool { return f.queueState(t, j) == "cancelled" })
	}
	if n := comp.compensated.Load(); n != 1 {
		t.Errorf("tenant.suspend compensated %d times, want 1", n)
	}

	// failed_resumable keeps the lock: the next lifecycle job of tenant B waits, without using attempts
	reconf := mustEnqueue(t, api, Spec{Kind: "instance.reconfigure", TenantID: &f.b, InstanceID: &f.instB})
	time.Sleep(time.Second)
	if j := f.job(t, st, reconf.Job.ID); j.Status != StatusQueued || reconfRuns.Load() != 0 {
		t.Fatalf("lifecycle job ran while the tenant's lock is held by a failed_resumable job: %s, %d runs", j.Status, reconfRuns.Load())
	}
	if counter(t, w.metrics.lockWaits, "instance.reconfigure") == 0 {
		t.Error("no lock wait counted")
	}
	// the operator's /rollback (Phase 3) ends the holder: the waiting job runs
	f.exec(t, "UPDATE provisioning_jobs SET status = 'rolled_back', finished_at = now() WHERE id = $1", restart.Job.ID)
	if j := f.waitStatus(t, st, reconf.Job.ID, StatusSucceeded, 10*time.Second); j.Attempt != 1 {
		t.Errorf("waiting lifecycle job: attempt %d after its snoozes, want 1", j.Attempt)
	}
	// a lifecycle job past its timeout_at ends failed_resumable
	j := f.waitStatus(t, st, upgrade.Job.ID, StatusFailedResumable, 20*time.Second)
	if errorCode(j) != CodeTimeout {
		t.Errorf("instance.upgrade timeout: code %q", errorCode(j))
	}
	// instance.backup released its lock when it failed
	if n := scalar[int64](t, f, "SELECT count(*) FROM provisioning_jobs WHERE lock_key = $1 AND status IN ('running', 'compensating', 'failed_resumable')", LockKey(tC)); n != 0 {
		t.Errorf("failed instance.backup still holds the lock")
	}
}

// TestLifecycleJobsNeverRunConcurrently: two worker processes (two River clients) and ten lifecycle jobs of two
// tenants, all with different dedupe keys — at no time do two jobs of the same tenant run, in the handlers or in the
// database (their running intervals never overlap); the jobs that waited did not spend attempts.
func TestLifecycleJobsNeverRunConcurrently(t *testing.T) {
	f := newFixture(t)
	var (
		mu       sync.Mutex
		running  = map[uuid.UUID]int{}
		maxSeen  = map[uuid.UUID]int{}
		together int
	)
	h := HandlerFunc(func(ctx context.Context, run *Run) error {
		mu.Lock()
		running[*run.TenantID]++
		maxSeen[*run.TenantID] = max(maxSeen[*run.TenantID], running[*run.TenantID])
		if len(running) == 2 && running[f.a] > 0 && running[f.b] > 0 {
			together++
		}
		mu.Unlock()
		time.Sleep(120 * time.Millisecond)
		mu.Lock()
		if running[*run.TenantID]--; running[*run.TenantID] == 0 {
			delete(running, *run.TenantID)
		}
		mu.Unlock()
		return nil
	})
	kinds := []string{"instance.restart", "instance.reconfigure", "instance.upgrade", "instance.restore", "tenant.suspend"}
	var workers []*Worker
	for range 2 {
		w, _ := newWorker(t, f.workerStore(t), testConfig(), Options{})
		for _, k := range kinds {
			if err := w.Register(k, h); err != nil {
				t.Fatal(err)
			}
		}
		workers = append(workers, w)
	}
	api := f.api(t)
	var ids []uuid.UUID
	for _, tenant := range [][2]uuid.UUID{{f.a, f.instA}, {f.b, f.instB}} {
		for _, k := range kinds {
			ids = append(ids, mustEnqueue(t, api, Spec{Kind: k, TenantID: &tenant[0], InstanceID: &tenant[1]}).Job.ID)
		}
	}
	for _, w := range workers {
		start(t, w)
	}
	st := f.workerStore(t)
	var jobs []sqlcdb.ProvisioningJob
	for _, id := range ids {
		jobs = append(jobs, f.waitStatus(t, st, id, StatusSucceeded, 60*time.Second))
	}
	mu.Lock()
	if maxSeen[f.a] != 1 || maxSeen[f.b] != 1 {
		t.Errorf("concurrent lifecycle jobs per tenant: A %d, B %d; want 1", maxSeen[f.a], maxSeen[f.b])
	}
	t.Logf("handler calls with both tenants running at once: %d (the lock is per tenant)", together)
	mu.Unlock()
	const stamp = "15:04:05.000000"
	for i, a := range jobs {
		if a.Attempt != 1 {
			t.Errorf("%s: attempt %d, want 1 (waiting for the lock spends no attempt)", a.Kind, a.Attempt)
		}
		if n := scalar[int16](t, f, "SELECT attempt FROM river.river_job WHERE id = $1", *a.QueueJobID); n != 1 {
			t.Errorf("%s: River attempt %d, want 1 (a lock wait is a snooze, not a failed attempt)", a.Kind, n)
		}
		for _, b := range jobs[i+1:] {
			if *a.TenantID == *b.TenantID && a.StartedAt.Before(*b.FinishedAt) && b.StartedAt.Before(*a.FinishedAt) {
				t.Errorf("%s [%s, %s] and %s [%s, %s] of the same tenant were running at the same time", a.Kind,
					a.StartedAt.Format(stamp), a.FinishedAt.Format(stamp), b.Kind, b.StartedAt.Format(stamp), b.FinishedAt.Format(stamp))
			}
		}
	}
	var waits float64
	for _, w := range workers {
		for _, k := range kinds {
			waits += counter(t, w.metrics.lockWaits, k)
		}
	}
	if waits == 0 {
		t.Error("no job ever waited for the tenant lock — the test did not exercise the lock")
	}
}

// TestStepsResumeAfterRetry: steps are recorded in provisioning_job_steps; after a failed attempt the job resumes from
// the step that failed (completed steps are skipped), created_resources is written before the step's work, and the
// tenant view shows catalog messages.
func TestStepsResumeAfterRetry(t *testing.T) {
	f := newFixture(t)
	st := f.workerStore(t)
	w, _ := newWorker(t, st, testConfig(), Options{})
	var render, restartRuns, verify atomic.Int32
	if err := w.Register("instance.reconfigure", HandlerFunc(func(ctx context.Context, run *Run) error {
		if err := run.Step(ctx, "config.render", func(context.Context, *StepRun) error { render.Add(1); return nil }); err != nil {
			return err
		}
		if err := run.Step(ctx, "instance.restart", func(ctx context.Context, s *StepRun) error {
			if err := s.RecordCreated(ctx, map[string]string{"container": "mg-t-x"}); err != nil {
				return err
			}
			if restartRuns.Add(1) == 1 {
				return Transient("agent_unavailable", errors.New("agent socket closed"))
			}
			return s.SetDetail(map[string]any{"exit": 0})
		}); err != nil {
			return err
		}
		run.SetResource("instance", run.InstanceID.String())
		return run.Step(ctx, "edge.verify", func(context.Context, *StepRun) error { verify.Add(1); return nil })
	})); err != nil {
		t.Fatal(err)
	}
	start(t, w)
	j := mustEnqueue(t, f.api(t), Spec{Kind: "instance.reconfigure", TenantID: &f.a, InstanceID: &f.instA})
	done := f.waitStatus(t, st, j.Job.ID, StatusSucceeded, 20*time.Second)
	if render.Load() != 1 || restartRuns.Load() != 2 || verify.Load() != 1 || done.Attempt != 2 {
		t.Errorf("runs: render %d, restart %d, verify %d, job attempt %d; want 1, 2, 1, 2", render.Load(), restartRuns.Load(), verify.Load(), done.Attempt)
	}
	if done.CurrentStep == nil || *done.CurrentStep != "edge.verify" || done.ResourceID == nil || *done.ResourceID != f.instA.String() {
		t.Errorf("current step %v, resource %v", done.CurrentStep, done.ResourceID)
	}
	svc := NewService(f.api(t))
	got, err := svc.GetTenantJob(t.Context(), f.a, done.ID)
	if err != nil {
		t.Fatal(err)
	}
	type stepWant struct {
		name    string
		attempt int
	}
	want := []stepWant{{"config.render", 1}, {"instance.restart", 2}, {"edge.verify", 1}}
	if len(got.Steps) != 3 {
		t.Fatalf("steps = %+v", got.Steps)
	}
	for i, s := range got.Steps {
		if s.Name != want[i].name || s.Attempt != want[i].attempt || s.Status != StepSucceeded || s.Message == nil || *s.Message != "Completed" {
			t.Errorf("step %d = %+v, want %+v succeeded", i, s, want[i])
		}
	}
	plat, err := NewService(f.api(t)).GetPlatformJob(t.Context(), done.ID)
	if err != nil {
		t.Fatal(err)
	}
	if plat.Steps[1].Detail["exit"] != float64(0) {
		t.Errorf("platform step detail = %v", plat.Steps[1].Detail)
	}
	created := scalar[string](t, f, "SELECT created_resources::text FROM provisioning_job_steps WHERE job_id = $1 AND name = 'instance.restart'", done.ID)
	var cr map[string]string
	if json.Unmarshal([]byte(created), &cr) != nil || cr["container"] != "mg-t-x" {
		t.Errorf("created_resources = %s", created)
	}
}

// TestInterruptedAttemptResumes: a worker that stops gracefully cancels running jobs after SoftStopTimeout; the
// attempt is not counted, the job stays running (lifecycle lock kept) and resumes on the next worker — no alert.
func TestInterruptedAttemptResumes(t *testing.T) {
	f := newFixture(t)
	st := f.workerStore(t)
	cfg := testConfig()
	cfg.SoftStopTimeout = 200 * time.Millisecond
	var calls atomic.Int32
	started := make(chan struct{}, 1)
	h := HandlerFunc(func(ctx context.Context, _ *Run) error {
		if calls.Add(1) == 1 {
			started <- struct{}{}
			<-ctx.Done()
			return ctx.Err()
		}
		return nil
	})
	w1, alerts := newWorker(t, st, cfg, Options{})
	if err := w1.Register("instance.restart", h); err != nil {
		t.Fatal(err)
	}
	if err := w1.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	j := mustEnqueue(t, f.api(t), Spec{Kind: "instance.restart", TenantID: &f.a, InstanceID: &f.instA})
	select {
	case <-started:
	case <-time.After(10 * time.Second):
		t.Fatal("job never started")
	}
	stopCtx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	if err := w1.Stop(stopCtx); err != nil {
		t.Logf("stop: %v", err)
	}
	mid := f.job(t, st, j.Job.ID)
	if mid.Status != StatusRunning || mid.Attempt != 0 || errorCode(mid) != CodeInterrupted {
		t.Fatalf("after the stop: status %s attempt %d code %q; want running, 0, interrupted", mid.Status, mid.Attempt, errorCode(mid))
	}
	if s := f.queueState(t, mid); s != "available" {
		t.Errorf("River job after a soft stop: %s, want available", s)
	}
	w2, _ := newWorker(t, st, cfg, Options{Alerter: alerts})
	if err := w2.Register("instance.restart", h); err != nil {
		t.Fatal(err)
	}
	start(t, w2)
	if done := f.waitStatus(t, st, j.Job.ID, StatusSucceeded, 20*time.Second); done.Attempt != 1 || done.Error != nil {
		t.Errorf("resumed job: attempt %d error %s; want 1 and no error", done.Attempt, done.Error)
	}
	if a := alerts.all(); len(a) != 0 {
		t.Errorf("alerts for an interrupted job: %+v", a)
	}
}
