package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// TestEnqueueDedupeAndRequestKey: §13.5 (a), (b) — enqueue writes the business job and its River job in the caller's
// transaction (both or neither); an unfinished job with the same dedupe key is returned instead of a second one (same
// kind) or refused (other kind: one lifecycle job per tenant); the request key returns the job of the first request and
// refuses other parameters; the scope of each kind and tenant isolation (RLS) hold.
func TestEnqueueDedupeAndRequestKey(t *testing.T) {
	f := newFixture(t)
	st := f.api(t)

	first := mustEnqueue(t, st, Spec{Kind: "policy.apply", TenantID: &f.a, Input: map[string]any{"trigger": "manual"}})
	if !first.Created || first.Job.Status != StatusQueued {
		t.Fatalf("first enqueue: %+v", first)
	}
	row := f.job(t, st, first.Job.ID)
	if row.QueueJobID == nil || *row.DedupeKey != "tenant:"+f.a.String()+":policy.apply" || row.LockKey != nil || row.MaxAttempts != 6 {
		t.Fatalf("stored job = %+v", row)
	}
	var args, queue string
	if err := f.su.QueryRow(t.Context(), "SELECT args::text, queue FROM river.river_job WHERE id = $1", *row.QueueJobID).Scan(&args, &queue); err != nil {
		t.Fatal(err)
	}
	var qa map[string]any
	_ = json.Unmarshal([]byte(args), &qa)
	if len(qa) != 2 || qa["job_id"] != row.ID.String() || qa["kind"] != "policy.apply" || queue != QueueDefault {
		t.Errorf("River job args %s queue %s: want only the job ID and kind", args, queue)
	}

	// same dedupe key while unfinished: the same job, no second River job
	again := mustEnqueue(t, st, Spec{Kind: "policy.apply", TenantID: &f.a, Input: map[string]any{"trigger": "group_change"}})
	if again.Created || again.Job.ID != first.Job.ID {
		t.Errorf("second policy.apply: %+v, want the first job back", again)
	}
	if n := scalar[int64](t, f, "SELECT count(*) FROM river.river_job WHERE args->>'kind' = 'policy.apply'"); n != 1 {
		t.Errorf("%d River jobs for policy.apply, want 1", n)
	}
	// other tenant: its own job
	if b := mustEnqueue(t, st, Spec{Kind: "policy.apply", TenantID: &f.b}); !b.Created {
		t.Error("policy.apply of tenant B deduplicated against tenant A")
	}

	// one lifecycle job per tenant: tenant.suspend while tenant.provision is unfinished ⇒ conflict
	prov := mustEnqueue(t, st, Spec{Kind: "tenant.provision", TenantID: &f.a, Resource: &Resource{Type: "tenant", ID: f.a.String()}})
	if p := f.job(t, st, prov.Job.ID); p.LockKey == nil || *p.LockKey != LockKey(f.a) || *p.ResourceID != f.a.String() {
		t.Errorf("tenant.provision stored %+v", p)
	}
	if _, err := enqueue(t, st, Spec{Kind: "tenant.suspend", TenantID: &f.a}); !errors.Is(err, ErrDedupeConflict) {
		t.Errorf("tenant.suspend during tenant.provision: err %v, want ErrDedupeConflict", err)
	}

	// request key (Idempotency-Key): replay returns the same job, other parameters are refused
	dev := uuid.New()
	spec := Spec{Kind: "device.revoke", TenantID: &f.a, InstanceID: &f.instA, Object: dev.String(),
		Input: map[string]any{"device_id": dev, "kind": "expire"}, RequestKey: "req-0001", RequestedBy: &f.identity}
	rev := mustEnqueue(t, st, spec)
	replay := mustEnqueue(t, st, spec)
	if !rev.Created || replay.Created || replay.Job.ID != rev.Job.ID {
		t.Errorf("request key replay: %+v then %+v", rev, replay)
	}
	other := spec
	other.Object, other.Input = uuid.NewString(), map[string]any{"kind": "delete"}
	if _, err := enqueue(t, st, other); !errors.Is(err, ErrRequestKeyReuse) {
		t.Errorf("same request key, other parameters: err %v, want ErrRequestKeyReuse", err)
	}

	// enqueue rolls back with the business transaction
	sentinel := errors.New("rollback")
	var rolled Enqueued
	err := st.WithTenantJobTx(t.Context(), f.b, func(tx *store.Tx) error {
		var err error
		if rolled, err = Enqueue(t.Context(), tx, Spec{Kind: "tenant.suspend", TenantID: &f.b}); err != nil {
			return err
		}
		return sentinel
	})
	if !errors.Is(err, sentinel) || rolled.Job.ID == uuid.Nil {
		t.Fatalf("rolled-back enqueue: %v", err)
	}
	if n := scalar[int64](t, f, "SELECT count(*) FROM provisioning_jobs WHERE id = $1", rolled.Job.ID); n != 0 {
		t.Error("business job of a rolled-back transaction exists")
	}
	if n := scalar[int64](t, f, "SELECT count(*) FROM river.river_job WHERE args->>'job_id' = $1", rolled.Job.ID.String()); n != 0 {
		t.Error("River job of a rolled-back transaction exists")
	}

	// scope rules
	for name, s := range map[string]Spec{
		"instance kind without instance": {Kind: "instance.restart", TenantID: &f.a},
		"tenant kind without tenant":     {Kind: "policy.apply"},
		"platform kind with a tenant":    {Kind: "retention.sweep", TenantID: &f.a, Slot: "x"},
		"non-object input":               {Kind: "policy.apply", TenantID: &f.b, Input: []int{1}},
		"missing slot":                   {Kind: "inventory.sync", TenantID: &f.a, InstanceID: &f.instA},
	} {
		if _, err := enqueue(t, st, s); !errors.Is(err, ErrInvalidSpec) {
			t.Errorf("%s: err %v, want ErrInvalidSpec", name, err)
		}
	}
	if _, err := enqueue(t, st, Spec{Kind: "tenant.explode", TenantID: &f.a}); !errors.Is(err, ErrUnknownKind) {
		t.Errorf("unknown kind: err %v", err)
	}
	// tenant isolation: a job for tenant B written in tenant A's transaction is refused by RLS
	err = st.WithTenantJobTx(t.Context(), f.a, func(tx *store.Tx) error {
		_, err := Enqueue(t.Context(), tx, Spec{Kind: "policy.apply", TenantID: &f.b})
		return err
	})
	if store.SQLState(err) != "42501" {
		t.Errorf("job of tenant B in tenant A's scope: %v, want 42501", err)
	}
	// a lifecycle lock key can only name the job's own tenant (CHECK)
	_, err = f.su.Exec(t.Context(), `INSERT INTO provisioning_jobs (tenant_id, kind, lock_key) VALUES ($1, 'tenant.resume', $2)`,
		f.a, LockKey(f.b))
	if store.SQLState(err) != "23514" {
		t.Errorf("lock key of another tenant: %v, want check_violation", err)
	}
}

// TestFinishedJobDoesNotBlockNewJob: §13.5 (b) — the dedupe key binds only unfinished jobs: a succeeded, failed,
// cancelled or rolled_back job never blocks a new job with the same content, while queued, running, compensating and
// failed_resumable do (failed_resumable keeps it so /retry is never overtaken).
func TestFinishedJobDoesNotBlockNewJob(t *testing.T) {
	f := newFixture(t)
	st := f.api(t)
	spec := Spec{Kind: "instance.restart", TenantID: &f.a, InstanceID: &f.instA}
	for _, status := range []string{StatusQueued, StatusRunning, StatusCompensating, StatusFailedResumable} {
		j := mustEnqueue(t, st, spec)
		f.exec(t, "UPDATE provisioning_jobs SET status = $1 WHERE id = $2", status, j.Job.ID)
		if again := mustEnqueue(t, st, spec); again.Created || again.Job.ID != j.Job.ID {
			t.Errorf("%s job did not block the same dedupe key: %+v", status, again)
		}
		f.exec(t, "UPDATE provisioning_jobs SET status = 'succeeded', finished_at = now() WHERE id = $1", j.Job.ID)
	}
	for _, status := range []string{StatusSucceeded, StatusFailed, StatusCancelled, StatusRolledBack} {
		j := mustEnqueue(t, st, spec)
		f.exec(t, "UPDATE provisioning_jobs SET status = $1, finished_at = now() WHERE id = $2", status, j.Job.ID)
		next := mustEnqueue(t, st, spec)
		if !next.Created || next.Job.ID == j.Job.ID {
			t.Errorf("a %s job blocked a new job with the same dedupe key", status)
		}
		f.exec(t, "UPDATE provisioning_jobs SET status = 'cancelled', finished_at = now() WHERE id = $1", next.Job.ID)
	}
}

// TestLifecycleLockSQL: §13.5 (d) — two lifecycle jobs of one tenant cannot both be running: the second queued →
// running update waits for the first transaction and then fails on the partial unique index (no advisory lock); a
// job of another tenant is unaffected; failed_resumable keeps the lock, a final status releases it.
func TestLifecycleLockSQL(t *testing.T) {
	f := newFixture(t)
	st := f.workerStore(t)
	restart := f.job(t, st, mustEnqueue(t, st, Spec{Kind: "instance.restart", TenantID: &f.a, InstanceID: &f.instA}).Job.ID)
	reconf := f.job(t, st, mustEnqueue(t, st, Spec{Kind: "instance.reconfigure", TenantID: &f.a, InstanceID: &f.instA}).Job.ID)
	other := f.job(t, st, mustEnqueue(t, st, Spec{Kind: "instance.upgrade", TenantID: &f.b, InstanceID: &f.instB}).Job.ID)
	acquire := func(ctx context.Context, j sqlcdb.ProvisioningJob, hold <-chan struct{}) error {
		return st.WithPlatformJobTx(ctx, func(tx *store.Tx) error {
			if _, err := tx.Q.AcquireJob(ctx, sqlcdb.AcquireJobParams{TimeoutSecs: 60, ID: j.ID, QueueJobID: *j.QueueJobID}); err != nil {
				return err
			}
			if hold != nil {
				<-hold
			}
			return nil
		})
	}

	// the first transaction takes the lock and stays open while the second one tries
	release := make(chan struct{})
	var wg sync.WaitGroup
	var firstErr, secondErr error
	wg.Add(1)
	go func() { defer wg.Done(); firstErr = acquire(t.Context(), restart, release) }()
	eventually(t, 5*time.Second, "first acquisition holds the row", func() bool {
		return scalar[int64](t, f, `SELECT count(*) FROM pg_locks l JOIN pg_class c ON c.oid = l.relation
			WHERE c.relname = 'provisioning_jobs' AND l.mode = 'RowExclusiveLock' AND l.granted`) > 0
	})
	wg.Add(1)
	secondStarted := time.Now()
	go func() { defer wg.Done(); secondErr = acquire(t.Context(), reconf, nil) }()
	time.Sleep(300 * time.Millisecond) // the second update now waits for the first transaction
	if err := acquire(t.Context(), other, nil); err != nil {
		t.Errorf("lifecycle job of tenant B blocked by tenant A's lock: %v", err)
	}
	close(release)
	wg.Wait()
	if firstErr != nil {
		t.Fatalf("first acquisition: %v", firstErr)
	}
	if store.SQLState(secondErr) != uniqueViolation || store.SQLConstraint(secondErr) != lockIndex {
		t.Fatalf("second lifecycle job of the tenant: %v, want a violation of %s", secondErr, lockIndex)
	}
	if waited := time.Since(secondStarted); waited < 250*time.Millisecond {
		t.Errorf("second acquisition returned after %s without waiting for the first transaction", waited)
	}
	if n := scalar[int64](t, f, "SELECT count(*) FROM provisioning_jobs WHERE lock_key = $1 AND status = 'running'", LockKey(f.a)); n != 1 {
		t.Errorf("%d running lifecycle jobs for tenant A, want 1", n)
	}

	// failed_resumable keeps the lock; a final status releases it
	f.exec(t, "UPDATE provisioning_jobs SET status = 'failed_resumable' WHERE id = $1", restart.ID)
	if err := acquire(t.Context(), reconf, nil); store.SQLConstraint(err) != lockIndex {
		t.Errorf("acquisition while the holder is failed_resumable: %v, want lock violation", err)
	}
	f.exec(t, "UPDATE provisioning_jobs SET status = 'rolled_back', finished_at = now() WHERE id = $1", restart.ID)
	if err := acquire(t.Context(), reconf, nil); err != nil {
		t.Errorf("acquisition after the holder rolled back: %v", err)
	}
}
