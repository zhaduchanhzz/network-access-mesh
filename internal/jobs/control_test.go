package jobs

// Every transition of the lifecycle state machine (Transitions, §11.3) exercised against PostgreSQL with a real worker:
// a scripted lifecycle handler drives each edge, the operator controls run in the api process's pool (mg_api_platform —
// so their grants are checked too), and the test fails if a row of Transitions is never observed.

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// plan scripts one job of the scripted handler.
type plan struct {
	steps    []string
	fail     map[string][]error       // errors returned by successive executions of a step (then success)
	block    map[string]chan struct{} // the step waits until the channel is closed (or ctx ends)
	started  chan string              // a blocking step announces itself here
	panicAt  string                   // the step panics
	waitCtx  string                   // the step waits for the end of ctx (job deadline / worker stop)
	compFail map[string]int           // the compensation of a step fails this many times
	compWait chan struct{}            // every compensation waits for it (nil = no wait)
	compSeen chan string              // a waiting compensation announces itself here
	mu       sync.Mutex
	ran      map[string]int // executions of each step
	comp     []string       // compensations, in order
}

func (p *plan) inc(name string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.ran == nil {
		p.ran = map[string]int{}
	}
	p.ran[name]++
	return p.ran[name]
}

func (p *plan) runs(name string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.ran[name]
}

func (p *plan) compensated() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.comp)
}

// scripted is a lifecycle handler driven by plans (by job id); a job without a plan succeeds at once.
type scripted struct {
	mu    sync.Mutex
	plans map[uuid.UUID]*plan
}

func (s *scripted) plan(id uuid.UUID) *plan {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p := s.plans[id]; p != nil {
		return p
	}
	return &plan{}
}

func (s *scripted) set(id uuid.UUID, p *plan) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.plans[id] = p
}

func (s *scripted) Run(ctx context.Context, run *Run) error {
	p := s.plan(run.ID)
	for _, name := range p.steps {
		err := run.Step(ctx, name, func(ctx context.Context, st *StepRun) error {
			n := p.inc(name)
			if err := st.RecordCreated(ctx, map[string]string{"step": name}); err != nil {
				return err
			}
			if b := p.block[name]; b != nil {
				p.started <- name
				select {
				case <-b:
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			switch {
			case p.panicAt == name:
				panic("scripted panic")
			case p.waitCtx == name:
				<-ctx.Done()
				return ctx.Err()
			}
			if errs := p.fail[name]; n <= len(errs) {
				return errs[n-1]
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// runOnly is the scripted handler without compensation (instance.restart has no Compensator yet).
type runOnly struct{ s *scripted }

func (r runOnly) Run(ctx context.Context, run *Run) error { return r.s.Run(ctx, run) }

func (s *scripted) Compensate(ctx context.Context, run *Run, _ error) error {
	p := s.plan(run.ID)
	fns := map[string]CompensateFunc{}
	for _, name := range p.steps {
		fns[name] = func(ctx context.Context, cs CompensationStep) error {
			var res map[string]string
			if found, err := cs.Decode(&res); err != nil || !found || res["step"] != name {
				return fmt.Errorf("compensation of %s: resources %v: %w", name, res, err)
			}
			if p.compWait != nil {
				p.compSeen <- name
				select {
				case <-p.compWait:
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			p.mu.Lock()
			defer p.mu.Unlock()
			if p.compFail[name] > 0 {
				p.compFail[name]--
				return Transient("comp_failed", errors.New("compensation failed"))
			}
			p.comp = append(p.comp, name)
			return nil
		}
	}
	return run.CompensateSteps(ctx, fns)
}

// transitionLog records the (from, event) pairs the test observed, checked against Transitions.
type transitionLog struct {
	mu   sync.Mutex
	seen map[[2]string]bool
}

func (l *transitionLog) saw(t *testing.T, from, event, got string) {
	t.Helper()
	want, ok := NextStatus(from, event)
	if !ok {
		t.Fatalf("observed %s --%s--> %s, which Transitions does not list", from, event, got)
	}
	if want != got {
		t.Fatalf("%s --%s--> %s, Transitions says %s", from, event, got, want)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.seen[[2]string{from, event}] = true
}

func TestLifecycleTransitions(t *testing.T) {
	f := newFixture(t)
	wst, api := f.workerStore(t), f.api(t)
	cfg := testConfig()
	k := cfg.Kinds["tenant.provision"]
	k.Timeout, k.WorkerTimeout = 4*time.Second, 6*time.Second
	cfg.Kinds["tenant.provision"] = k
	h := &scripted{plans: map[uuid.UUID]*plan{}}
	newW := func() *Worker {
		w, _ := newWorker(t, wst, cfg, Options{})
		if err := w.Register("tenant.provision", h); err != nil {
			t.Fatal(err)
		}
		if err := w.Register("instance.restart", runOnly{h}); err != nil {
			t.Fatal(err)
		}
		if err := w.Register("instance.restore", runOnly{h}); err != nil {
			t.Fatal(err)
		}
		return w
	}
	w := newW()
	start(t, w)
	log := &transitionLog{seen: map[[2]string]bool{}}

	// enqueue a lifecycle job with its plan registered before the transaction commits.
	enqueueWith := func(t *testing.T, kind string, tenant, instance uuid.UUID, p *plan) uuid.UUID {
		t.Helper()
		spec := Spec{Kind: kind, TenantID: &tenant, RequestedBy: &f.identity}
		if kind == "instance.restart" || kind == "instance.restore" {
			spec.InstanceID = &instance
		}
		var id uuid.UUID
		if err := api.WithTenantJobTx(t.Context(), tenant, func(tx *store.Tx) error {
			e, err := Enqueue(t.Context(), tx, spec)
			if err != nil {
				return err
			}
			id = e.Job.ID
			if p != nil {
				h.set(id, p)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return id
	}
	control := func(t *testing.T, fn func(context.Context, *store.Tx, uuid.UUID) (Controlled, error), id uuid.UUID) (Controlled, error) {
		t.Helper()
		var c Controlled
		err := api.WithPlatformJobTx(t.Context(), func(tx *store.Tx) error {
			var err error
			c, err = fn(t.Context(), tx, id)
			return err
		})
		return c, err
	}
	steps := func(t *testing.T, id uuid.UUID) map[string]sqlcdb.ProvisioningJobStep {
		t.Helper()
		out := map[string]sqlcdb.ProvisioningJobStep{}
		if err := wst.WithPlatformTx(t.Context(), func(q *sqlcdb.Queries) error {
			rows, err := q.ListJobSteps(t.Context(), []uuid.UUID{id})
			for _, r := range rows {
				out[r.Name] = r
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return out
	}
	compStatus := func(s sqlcdb.ProvisioningJobStep) string {
		if s.CompensationStatus == nil {
			return ""
		}
		return *s.CompensationStatus
	}

	t.Run("succeed", func(t *testing.T) {
		tenant, inst := f.newTenant(t)
		p := &plan{steps: []string{"a", "b"}}
		id := enqueueWith(t, "tenant.provision", tenant, inst, p)
		j := f.waitStatus(t, wst, id, StatusSucceeded, 15*time.Second)
		log.saw(t, StatusQueued, EventAcquire, StatusRunning)
		log.saw(t, StatusRunning, EventSucceed, j.Status)
		if j.Attempt != 1 || j.FinishedAt == nil || p.runs("a") != 1 || p.runs("b") != 1 {
			t.Fatalf("attempt %d finished %v runs a=%d b=%d", j.Attempt, j.FinishedAt, p.runs("a"), p.runs("b"))
		}
	})

	t.Run("transient_retry_then_succeed", func(t *testing.T) {
		tenant, inst := f.newTenant(t)
		p := &plan{steps: []string{"a", "b"}, fail: map[string][]error{"b": {Transient("flaky", errors.New("try again"))}}}
		id := enqueueWith(t, "tenant.provision", tenant, inst, p)
		j := f.waitStatus(t, wst, id, StatusSucceeded, 15*time.Second)
		log.saw(t, StatusRunning, EventTransientRetry, StatusRunning)
		st := steps(t, id)
		if j.Attempt != 2 || p.runs("a") != 1 || p.runs("b") != 2 || st["b"].Attempt != 2 || st["a"].Attempt != 1 {
			t.Fatalf("attempt %d, runs a=%d b=%d, step attempts a=%d b=%d", j.Attempt, p.runs("a"), p.runs("b"),
				st["a"].Attempt, st["b"].Attempt)
		}
	})

	t.Run("retries_exhausted_then_retry_resumes_from_failed_step", func(t *testing.T) {
		tenant, inst := f.newTenant(t)
		spent := Resumable("dns_mismatch", errors.New("five retries spent"))
		p := &plan{steps: []string{"a", "b", "c"}, fail: map[string][]error{"b": {spent}}}
		id := enqueueWith(t, "tenant.provision", tenant, inst, p)
		j := f.waitStatus(t, wst, id, StatusFailedResumable, 15*time.Second)
		log.saw(t, StatusRunning, EventRetriesExhausted, j.Status)
		if errorCode(j) != "dns_mismatch" || j.FinishedAt != nil || p.runs("b") != 1 {
			t.Fatalf("code %q finished %v runs b=%d (a Resumable error is not retried by the queue)", errorCode(j), j.FinishedAt, p.runs("b"))
		}
		if c := steps(t, id); compStatus(c["a"]) != "" || compStatus(c["b"]) != "" {
			t.Fatal("failed_resumable must not compensate")
		}
		c, err := control(t, Retry, id)
		if err != nil {
			t.Fatal(err)
		}
		log.saw(t, StatusFailedResumable, EventRetry, c.Record.Status)
		j = f.waitStatus(t, wst, id, StatusSucceeded, 15*time.Second)
		if p.runs("a") != 1 || p.runs("b") != 2 || p.runs("c") != 1 || int(j.MaxAttempts) != 1+cfg.Kinds["tenant.provision"].MaxAttempts {
			t.Fatalf("after /retry: runs a=%d b=%d c=%d, max_attempts %d", p.runs("a"), p.runs("b"), p.runs("c"), j.MaxAttempts)
		}
	})

	t.Run("transient_exhausted_on_last_attempt", func(t *testing.T) {
		tenant, inst := f.newTenant(t)
		errs := make([]error, 10)
		for i := range errs {
			errs[i] = Transient("agent_unavailable", errors.New("down"))
		}
		p := &plan{steps: []string{"a"}, fail: map[string][]error{"a": errs}}
		id := enqueueWith(t, "tenant.provision", tenant, inst, p)
		j := f.waitStatus(t, wst, id, StatusFailedResumable, 30*time.Second)
		if j.Attempt != j.MaxAttempts || errorCode(j) != "agent_unavailable" {
			t.Fatalf("attempt %d/%d code %q", j.Attempt, j.MaxAttempts, errorCode(j))
		}
	})

	t.Run("timeout", func(t *testing.T) {
		tenant, inst := f.newTenant(t)
		p := &plan{steps: []string{"a"}, waitCtx: "a"}
		id := enqueueWith(t, "tenant.provision", tenant, inst, p)
		j := f.waitStatus(t, wst, id, StatusFailedResumable, 15*time.Second)
		log.saw(t, StatusRunning, EventTimeout, j.Status)
		if errorCode(j) != CodeTimeout {
			t.Fatalf("code %q, want timeout", errorCode(j))
		}
	})

	t.Run("panic", func(t *testing.T) {
		tenant, inst := f.newTenant(t)
		p := &plan{steps: []string{"a"}, panicAt: "a"}
		id := enqueueWith(t, "tenant.provision", tenant, inst, p)
		j := f.waitStatus(t, wst, id, StatusFailedResumable, 15*time.Second)
		log.saw(t, StatusRunning, EventPanic, j.Status)
		if errorCode(j) != CodeHandlerPanic || p.runs("a") != 1 {
			t.Fatalf("code %q runs %d", errorCode(j), p.runs("a"))
		}
	})

	t.Run("permanent_compensates_in_reverse_order", func(t *testing.T) {
		tenant, inst := f.newTenant(t)
		p := &plan{steps: []string{"a", "b", "c", "d"}, fail: map[string][]error{"c": {Permanent("config_invalid", errors.New("bad"))}}}
		id := enqueueWith(t, "tenant.provision", tenant, inst, p)
		j := f.waitStatus(t, wst, id, StatusRolledBack, 15*time.Second)
		log.saw(t, StatusRunning, EventPermanent, StatusCompensating)
		log.saw(t, StatusCompensating, EventCompensated, j.Status)
		// c failed after recording its resources: it is undone too, before b and a; d never ran.
		if got := p.compensated(); !slices.Equal(got, []string{"c", "b", "a"}) || errorCode(j) != "config_invalid" || j.FinishedAt == nil {
			t.Fatalf("compensated %v, code %q, finished %v", got, errorCode(j), j.FinishedAt)
		}
		st := steps(t, id)
		for _, n := range []string{"a", "b", "c"} {
			if compStatus(st[n]) != StepSucceeded {
				t.Fatalf("step %s compensation %q", n, compStatus(st[n]))
			}
		}
		if _, ok := st["d"]; ok {
			t.Fatal("step d ran")
		}
	})

	t.Run("compensation_failure_then_rollback_resumes", func(t *testing.T) {
		tenant, inst := f.newTenant(t)
		p := &plan{steps: []string{"a", "b", "c"}, fail: map[string][]error{"c": {Permanent("edge_exposes_paths", errors.New("leak"))}},
			compFail: map[string]int{"b": 1}}
		id := enqueueWith(t, "tenant.provision", tenant, inst, p)
		j := f.waitStatus(t, wst, id, StatusFailedResumable, 15*time.Second)
		log.saw(t, StatusCompensating, EventCompensationFail, j.Status)
		st := steps(t, id)
		if errorCode(j) != CodeCompensationFailed || compStatus(st["c"]) != StepSucceeded || compStatus(st["b"]) != StepFailed ||
			compStatus(st["a"]) != "" {
			t.Fatalf("code %q, compensation c=%q b=%q a=%q", errorCode(j), compStatus(st["c"]), compStatus(st["b"]), compStatus(st["a"]))
		}
		c, err := control(t, Rollback, id)
		if err != nil {
			t.Fatal(err)
		}
		log.saw(t, StatusFailedResumable, EventRollback, c.Record.Status)
		j = f.waitStatus(t, wst, id, StatusRolledBack, 15*time.Second)
		// c is not compensated twice; b is retried, then a.
		if got := p.compensated(); !slices.Equal(got, []string{"c", "b", "a"}) {
			t.Fatalf("compensations %v", got)
		}
	})

	t.Run("cancel_running_stops_after_current_step", func(t *testing.T) {
		tenant, inst := f.newTenant(t)
		gate := make(chan struct{})
		p := &plan{steps: []string{"a", "b"}, block: map[string]chan struct{}{"a": gate}, started: make(chan string, 1)}
		id := enqueueWith(t, "tenant.provision", tenant, inst, p)
		<-p.started
		c, err := control(t, Cancel, id)
		if err != nil {
			t.Fatal(err)
		}
		log.saw(t, StatusRunning, EventCancelRequested, c.Record.Status)
		if c.Record.CancelRequestedAt == nil {
			t.Fatal("cancel_requested_at not set")
		}
		if again, err := control(t, Cancel, id); err != nil || again.Event != "" {
			t.Fatalf("second /cancel: event %q, %v (want no-op)", again.Event, err)
		}
		close(gate)
		j := f.waitStatus(t, wst, id, StatusFailedResumable, 15*time.Second)
		log.saw(t, StatusRunning, EventCancelObserved, j.Status)
		st := steps(t, id)
		if errorCode(j) != CodeCancelled || st["a"].Status != StepSucceeded || p.runs("b") != 0 {
			t.Fatalf("code %q, a %s, b ran %d", errorCode(j), st["a"].Status, p.runs("b"))
		}
		if _, err := control(t, Retry, id); err != nil {
			t.Fatal(err)
		}
		j = f.waitStatus(t, wst, id, StatusSucceeded, 15*time.Second)
		if j.CancelRequestedAt != nil || p.runs("a") != 1 || p.runs("b") != 1 {
			t.Fatalf("after /retry: cancel mark %v, runs a=%d b=%d", j.CancelRequestedAt, p.runs("a"), p.runs("b"))
		}
	})

	t.Run("lock_one_lifecycle_job_per_tenant", func(t *testing.T) {
		tenant, inst := f.newTenant(t)
		holder := enqueueWith(t, "tenant.provision", tenant, inst,
			&plan{steps: []string{"a"}, fail: map[string][]error{"a": {Resumable("no_capacity", errors.New("full"))}}})
		f.waitStatus(t, wst, holder, StatusFailedResumable, 15*time.Second)
		// A second lifecycle job of the same tenant (another dedupe key, same lock) never runs while the holder is
		// failed_resumable: it stays queued, snoozing.
		waiting := enqueueWith(t, "instance.restart", tenant, inst, &plan{steps: []string{"x"}})
		time.Sleep(time.Second)
		if j := f.job(t, wst, waiting); j.Status != StatusQueued || j.Attempt != 0 {
			t.Fatalf("second lifecycle job %s attempt %d while the lock is held", j.Status, j.Attempt)
		}
		if n := scalar[int64](t, f, `SELECT count(*) FROM provisioning_jobs WHERE lock_key = $1
			AND status IN ('running','compensating','failed_resumable')`, LockKey(tenant)); n != 1 {
			t.Fatalf("%d jobs hold the lock", n)
		}
		c, err := control(t, Cancel, waiting)
		if err != nil {
			t.Fatal(err)
		}
		log.saw(t, StatusQueued, EventCancelQueued, c.Record.Status)
		if errorCode(c.Record) != CodeCancelled || c.Record.FinishedAt == nil {
			t.Fatalf("cancelled job: code %q finished %v", errorCode(c.Record), c.Record.FinishedAt)
		}
		next := enqueueWith(t, "instance.restart", tenant, inst, &plan{steps: []string{"x"}})
		if _, err := control(t, Rollback, holder); err != nil {
			t.Fatal(err)
		}
		f.waitStatus(t, wst, holder, StatusRolledBack, 15*time.Second)
		f.waitStatus(t, wst, next, StatusSucceeded, 15*time.Second) // the lock released by rolled_back
	})

	t.Run("controls_refused", func(t *testing.T) {
		tenant, inst := f.newTenant(t)
		done := enqueueWith(t, "tenant.provision", tenant, inst, &plan{steps: []string{"a"}})
		f.waitStatus(t, wst, done, StatusSucceeded, 15*time.Second)
		for name, fn := range map[string]func(context.Context, *store.Tx, uuid.UUID) (Controlled, error){
			"retry": Retry, "rollback": Rollback, "cancel": Cancel} {
			if _, err := control(t, fn, done); !errors.Is(err, ErrJobState) {
				t.Errorf("%s of a succeeded job: %v, want ErrJobState", name, err)
			}
		}
		// /rollback of instance.restore (compensable since the restore lock fix — P3-T11) is accepted; a handler that
		// cannot compensate (runOnly) ends it failed_resumable compensation_failed, the lock still held.
		restore := enqueueWith(t, "instance.restore", tenant, inst,
			&plan{steps: []string{"x"}, fail: map[string][]error{"x": {Permanent("unhealthy", errors.New("no"))}}})
		f.waitStatus(t, wst, restore, StatusFailedResumable, 15*time.Second)
		if _, err := control(t, Rollback, restore); err != nil {
			t.Fatalf("rollback of instance.restore: %v", err)
		}
		eventually(t, 15*time.Second, "rollback by a handler without compensation ends compensation_failed", func() bool {
			j := f.job(t, wst, restore)
			return j.Status == StatusFailedResumable && errorCode(j) == CodeCompensationFailed
		})
		if _, err := control(t, Retry, uuid.New()); !errors.Is(err, ErrNotFound) {
			t.Fatalf("retry of an unknown job: %v", err)
		}
		// Clear the lock for the next case.
		if _, err := control(t, Retry, restore); err != nil {
			t.Fatal(err)
		}
		f.waitStatus(t, wst, restore, StatusSucceeded, 15*time.Second)
	})

	t.Run("reaped_and_interrupted", func(t *testing.T) {
		// running past timeout_at (worker lost) and compensating past timeout_at ⇒ failed_resumable.
		for _, from := range []string{StatusRunning, StatusCompensating} {
			tenant, _ := f.newTenant(t)
			id := uuid.New()
			f.exec(t, `INSERT INTO provisioning_jobs (id, tenant_id, kind, dedupe_key, lock_key, status, attempt, max_attempts,
					started_at, timeout_at) VALUES ($1, $2, 'tenant.provision', $3, $4, $5, 1, 6, now() - interval '20 minutes',
					now() - interval '1 minute')`, id, tenant, "tenant:"+tenant.String()+":lifecycle", LockKey(tenant), from)
			if _, err := w.reap(t.Context()); err != nil {
				t.Fatal(err)
			}
			j := f.job(t, wst, id)
			log.saw(t, from, EventReaped, j.Status)
			if errorCode(j) != CodeWorkerLost {
				t.Fatalf("reaped %s: code %q", from, errorCode(j))
			}
		}
		// A worker that stops gracefully in the middle of a run, then of a compensation: neither attempt is lost — the
		// job stays running / compensating and the next worker resumes it.
		tenant, inst := f.newTenant(t)
		gate := make(chan struct{})
		p := &plan{steps: []string{"a", "b"}, block: map[string]chan struct{}{"a": gate}, started: make(chan string, 2),
			fail:     map[string][]error{"b": {Permanent("bad", errors.New("x"))}},
			compWait: make(chan struct{}), compSeen: make(chan string, 4)}
		id := enqueueWith(t, "tenant.provision", tenant, inst, p)
		<-p.started
		stop := func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_ = w.Stop(ctx)
		}
		stop()
		if j := f.job(t, wst, id); j.Status != StatusRunning {
			t.Fatalf("after a stop mid-run: %s", j.Status)
		}
		log.saw(t, StatusRunning, EventInterrupt, StatusRunning)
		w = newW()
		start(t, w)
		<-p.started // a runs again: its earlier attempt was interrupted
		close(gate)
		<-p.compSeen // b failed permanently; the compensation of b waits
		stop()
		j := f.job(t, wst, id)
		if j.Status != StatusCompensating {
			t.Fatalf("after a stop mid-compensation: %s", j.Status)
		}
		log.saw(t, StatusCompensating, EventInterrupt, j.Status)
		close(p.compWait)
		w = newW()
		start(t, w)
		f.waitStatus(t, wst, id, StatusRolledBack, 20*time.Second)
		if got := p.compensated(); !slices.Equal(got, []string{"b", "a"}) {
			t.Fatalf("compensations %v", got)
		}
	})

	// Every edge of the state machine was observed (retry_new_job is tenant.provision's — orchestrator tests).
	for _, tr := range Transitions {
		if tr.Event == EventRetryNewJob {
			continue
		}
		if !log.seen[[2]string{tr.From, tr.Event}] {
			t.Errorf("transition %s --%s--> %s never exercised", tr.From, tr.Event, tr.To)
		}
	}
}

// TestRollbackRefusal: what the kind and the status alone decide of a /rollback.
func TestRollbackRefusal(t *testing.T) {
	failed := sqlcdb.ProvisioningJob{Kind: "x.y", Status: StatusFailedResumable}
	if se := rollbackRefusal(failed, Kind{Name: "x.y", Lock: LockHold}); se == nil || se.Reason != "kind_not_compensable" {
		t.Fatalf("a kind without compensation: %v", se)
	}
	ok := Kind{Name: "x.y", Lock: LockHold, Compensable: true}
	if se := rollbackRefusal(failed, ok); se != nil {
		t.Fatalf("a failed_resumable job of a compensable kind: %v", se)
	}
	if se := rollbackRefusal(sqlcdb.ProvisioningJob{Kind: "x.y", Status: StatusRunning}, ok); se == nil || se.Reason != "status_not_allowed" {
		t.Fatalf("a running job: %v", se)
	}
	// every lifecycle kind of the registry is compensable; instance.restore only before restore.instance (P3-T11 fix)
	for name, k := range DefaultKinds() {
		if k.Lock == LockHold && !k.Compensable {
			t.Errorf("lifecycle kind %s has no compensation", name)
		}
	}
	if k := DefaultKinds()["instance.restore"]; !k.Compensable || k.PointOfNoReturn != "restore.instance" {
		t.Fatalf("instance.restore: compensable %v, point of no return %q", k.Compensable, k.PointOfNoReturn)
	}
}

// TestPointOfNoReturnPassed: the rule of PastPointOfNoReturn on one step row.
func TestPointOfNoReturnPassed(t *testing.T) {
	for _, c := range []struct {
		status, created string
		want            bool
	}{
		{StepSucceeded, "", true},
		{StepFailed, "", false},
		{StepFailed, "null", false},
		{StepRunning, `{"nodes":3}`, true},
		{StepFailed, `{"point_of_no_return":false,"agent_restore":"not_called"}`, false},
		{StepFailed, `{"point_of_no_return":true,"agent_restore":"called"}`, true},
		{StepSucceeded, `{"point_of_no_return":false}`, true},
		{StepFailed, `[1]`, true},
		{StepFailed, `{"point_of_no_return":"no"}`, true},
	} {
		var raw []byte
		if c.created != "" {
			raw = []byte(c.created)
		}
		if got := PointOfNoReturnPassed(c.status, raw); got != c.want {
			t.Errorf("%s %s: %v, want %v", c.status, c.created, got, c.want)
		}
	}
}

func TestTransitionsTable(t *testing.T) {
	seen := map[[2]string]bool{}
	finished := []string{StatusSucceeded, StatusFailed, StatusCancelled}
	for _, tr := range Transitions {
		k := [2]string{tr.From, tr.Event}
		if seen[k] {
			t.Errorf("duplicate transition %v", k)
		}
		seen[k] = true
		if !slices.Contains(Statuses, tr.From) || !slices.Contains(Statuses, tr.To) {
			t.Errorf("unknown status in %v", tr)
		}
		if slices.Contains(finished, tr.From) {
			t.Errorf("a finished status has an outgoing edge: %v", tr)
		}
	}
	// The operator controls apply exactly where §11.3 says.
	for _, c := range []struct{ from, ev, to string }{
		{StatusFailedResumable, EventRetry, StatusRunning}, {StatusFailedResumable, EventRollback, StatusCompensating},
		{StatusQueued, EventCancelQueued, StatusCancelled}, {StatusRunning, EventCancelRequested, StatusRunning},
		{StatusRolledBack, EventRetryNewJob, StatusQueued},
	} {
		if got, ok := NextStatus(c.from, c.ev); !ok || got != c.to {
			t.Errorf("%s --%s--> %q (%v), want %s", c.from, c.ev, got, ok, c.to)
		}
	}
	for _, c := range []struct{ from, ev string }{
		{StatusSucceeded, EventRetry}, {StatusRunning, EventRetry}, {StatusCompensating, EventRollback},
		{StatusRunning, EventRollback}, {StatusCompensating, EventCancelRequested}, {StatusFailedResumable, EventCancelQueued},
	} {
		if _, ok := NextStatus(c.from, c.ev); ok {
			t.Errorf("%s --%s--> must not exist", c.from, c.ev)
		}
	}
}
