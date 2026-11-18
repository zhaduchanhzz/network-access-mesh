package quarantine

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/authz/approvals"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/notifications"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
)

// TestQuarantineReleaseDB — the flow of §11.4 end to end on PostgreSQL, River and the agent model: the request moves
// the registry at once (Critical event, audit .requested); the job isolates the instance on its host (marker, no flag,
// detached, stopped, data/ untouched), verifies it, tells the staff, closes the audit pair; the reconcile and API-key
// schedules no longer select it; a release without approval does nothing — self-approval refused —, the second Super
// Admin's approval runs instance.release: start guard + health + policy on the agent, starting, edge, post-start gate,
// running, Critical/High events, audit pairs, notifications.
func TestQuarantineReleaseDB(t *testing.T) {
	g := newRig(t, rigOptions{})
	ten, other := g.newTenant(t), g.newTenant(t)
	before := g.agent.host(ten.instance)

	out, err := g.quarantine(t, ten, "k-1")
	if err != nil || !out.Changed {
		t.Fatalf("quarantine: %+v %v", out, err)
	}
	// immediate: the registry, the event, the audit — before the worker did anything on the host
	if s := g.instanceStatus(t, ten); s != tenants.InstanceQuarantined {
		t.Fatalf("registry right after the request: %s", s)
	}
	if g.events(t, EventQuarantined, ten) != 1 {
		t.Fatal("no Critical instance.quarantined event at the request")
	}
	if again, err := g.quarantine(t, ten, "k-1"); err != nil || again.Job.ID != out.Job.ID || again.Changed {
		t.Fatalf("replay of the key: %+v %v", again, err)
	}
	g.wait(t, out.Job.ID, jobs.StatusSucceeded)
	if s := g.steps(t, out.Job.ID); s != "validate:succeeded registry.quarantine:succeeded instance.isolate:succeeded "+
		"instance.verify:succeeded notify:succeeded" {
		t.Fatalf("steps: %s", s)
	}
	h := g.agent.host(ten.instance)
	if !h.marked || h.flag || h.attached || h.running || h.dataSum != before.dataSum {
		t.Fatalf("host after the quarantine: %+v", h)
	}
	if o := g.agent.host(other.instance); o.marked || !o.running || !o.attached {
		t.Fatalf("the other tenant was touched: %+v", o)
	}
	if a := g.auditActions(t, ActionQuarantine, ten); a != ActionQuarantine+".requested:success "+ActionQuarantine+".succeeded:success" {
		t.Fatalf("audit: %s", a)
	}
	if n := g.notified(t, string(notifications.KindInstanceQuarantined), notifications.OutcomeIsolated, ten); n != 3 {
		t.Fatalf("%d quarantine notifications, want 3 (two Super Admins, one Platform Operator)", n)
	}
	// the schedules of reconcile (P3-T12) and API key rotation (P3-T10) skip it; the helper says so
	var targets []sqlcdb.ListReconcileTargetsRow
	var rot sqlcdb.GetInstanceForKeyRotationRow
	if err := g.wrk.WithPlatformTx(t.Context(), func(q *sqlcdb.Queries) error {
		var err error
		if targets, err = q.ListReconcileTargets(t.Context()); err != nil {
			return err
		}
		if rot, err = q.GetInstanceForKeyRotation(t.Context(), sqlcdb.GetInstanceForKeyRotationParams{ID: ten.instance,
			TenantID: ten.id}); err != nil {
			return err
		}
		if ok, err := IsQuarantined(t.Context(), q, ten.instance); err != nil || !ok {
			return errors.Join(err, errors.New("IsQuarantined is false"))
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, x := range targets {
		if x.ID == ten.instance {
			t.Fatal("reconcile still selects the quarantined instance")
		}
	}
	if rot.Status != tenants.InstanceQuarantined {
		t.Fatalf("rotation reads status %s", rot.Status)
	}
	// a second quarantine of a quarantined instance is accepted: a new job isolates again (idempotent on the host)
	out2, err := g.quarantine(t, ten, "")
	if err != nil || !out2.Changed || out2.Job.ID == out.Job.ID {
		t.Fatalf("re-quarantine: %+v %v", out2, err)
	}
	g.wait(t, out2.Job.ID, jobs.StatusSucceeded)

	// ---- release: an approval request only; nothing runs without the second person
	jobsBefore := g.count(t, `SELECT count(*) FROM provisioning_jobs WHERE kind = $1 AND instance_id = $2`, KindRelease, ten.instance)
	r, err := g.requestRelease(t, ten)
	if err != nil || r.Status != approvals.StatusPending {
		t.Fatalf("release request: %+v %v", r, err)
	}
	if _, err := g.approve(t, g.sa1, r); !errors.Is(err, approvals.ErrForbidden) {
		t.Fatalf("self-approval: %v", err)
	}
	if _, err := g.approve(t, g.po, r); err == nil {
		t.Fatal("a Platform Operator (restore_only) approved a release")
	}
	time.Sleep(300 * time.Millisecond)
	if n := g.count(t, `SELECT count(*) FROM provisioning_jobs WHERE kind = $1 AND instance_id = $2`, KindRelease, ten.instance); n != jobsBefore {
		t.Fatalf("a release job exists without approval (%d)", n)
	}
	if s := g.instanceStatus(t, ten); s != tenants.InstanceQuarantined || g.agent.count("ReleaseInstance") != 0 {
		t.Fatalf("released without approval: %s, %d agent releases", s, g.agent.count("ReleaseInstance"))
	}
	done, err := g.approve(t, g.sa2, r)
	if err != nil || done.Status != approvals.StatusExecuted || done.JobID == nil {
		t.Fatalf("approval: %+v %v", done, err)
	}
	g.wait(t, *done.JobID, jobs.StatusSucceeded)
	if s := g.steps(t, *done.JobID); s != "validate:succeeded release.prepare:succeeded instance.release:succeeded "+
		"registry.starting:succeeded edge.attach:succeeded poststart.gate:succeeded registry.release:succeeded notify:succeeded" {
		t.Fatalf("release steps: %s", s)
	}
	if s := g.instanceStatus(t, ten); s != tenants.InstanceRunning {
		t.Fatalf("after the release: %s", s)
	}
	h = g.agent.host(ten.instance)
	if h.marked || !h.flag || !h.attached || !h.running || h.dataSum != before.dataSum {
		t.Fatalf("host after the release: %+v", h)
	}
	if ten.hs.gates == 0 {
		t.Fatal("the post-start gate never called the instance")
	}
	if g.events(t, EventReleased, ten) != 1 || g.notified(t, string(notifications.KindInstanceReleased), notifications.OutcomeReleased, ten) != 3 {
		t.Fatal("release event / notifications")
	}
	if a := g.auditActions(t, ActionRelease, ten); a != ActionRelease+".requested:success "+ActionRelease+".succeeded:success" {
		t.Fatalf("release audit: %s", a)
	}
	// the approval is spent; a release of a running instance is refused before any request
	if _, err := g.approve(t, g.sa2, r); err == nil {
		t.Fatal("the executed approval ran again")
	}
	if _, err := g.requestRelease(t, ten); !errors.Is(err, ErrConflict) {
		t.Fatalf("release of a running instance: %v", err)
	}
}

// TestQuarantineTakesEffectUnderTheLifecycleLock — §11.4 "nhanh và an toàn": a lifecycle job (a stand-in registered
// under instance.reconfigure — lifecycle group, compensable) holds
// the tenant's lock and is between two steps; the quarantine is not delayed by the lock: registry at once, host isolated
// by its job while the lifecycle job still holds the lock; the lifecycle job stops at its next step (instance_quarantined,
// failed_resumable — no compensation, nothing undone); /retry stops again; /rollback's compensation is held too.
func TestQuarantineTakesEffectUnderTheLifecycleLock(t *testing.T) {
	g := newRig(t, rigOptions{})
	ten := g.newTenant(t)
	var restart uuid.UUID
	if err := g.api.WithPlatformJobTx(t.Context(), func(tx *store.Tx) error {
		enq, err := jobs.Enqueue(t.Context(), tx, jobs.Spec{Kind: lifecycleKind, TenantID: &ten.id, InstanceID: &ten.instance})
		restart = enq.Job.ID
		return err
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-g.restartPaused:
	case <-time.After(30 * time.Second):
		t.Fatal("the lifecycle job did not start")
	}
	if g.count(t, `SELECT count(*) FROM provisioning_jobs WHERE lock_key = $1 AND status = 'running'`, jobs.LockKey(ten.id)) != 1 {
		t.Fatal("the lifecycle lock is not held")
	}
	out, err := g.quarantine(t, ten, "")
	if err != nil {
		t.Fatal(err)
	}
	g.wait(t, out.Job.ID, jobs.StatusSucceeded) // while the lifecycle job still holds the lock
	if st := g.str(t, `SELECT status FROM provisioning_jobs WHERE id = $1`, restart); st != jobs.StatusRunning {
		t.Fatalf("the lifecycle job is %s", st)
	}
	if h := g.agent.host(ten.instance); !h.marked || h.running || h.attached {
		t.Fatalf("not isolated under the lock: %+v", h)
	}
	close(g.restartBetween) // the lifecycle job goes on to its next step
	g.wait(t, restart, jobs.StatusFailedResumable)
	if c := g.errCode(t, restart); c != CodeInstanceQuarantined {
		t.Fatalf("lifecycle job code %s", c)
	}
	if s := g.steps(t, restart); s != "instance.stop:succeeded" {
		t.Fatalf("lifecycle steps: %s (instance.start must never run)", s)
	}
	// /retry: stopped again before its step
	if _, err := g.control(t, jobs.Retry, restart); err != nil {
		t.Fatal(err)
	}
	g.wait(t, restart, jobs.StatusFailedResumable)
	if s := g.steps(t, restart); s != "instance.stop:succeeded" {
		t.Fatalf("after /retry: %s", s)
	}
	// /rollback: the compensation is held as well (nothing of a quarantined instance is undone)
	if _, err := g.control(t, jobs.Rollback, restart); err != nil {
		t.Fatal(err)
	}
	g.wait(t, restart, jobs.StatusFailedResumable)
	if c := g.errCode(t, restart); c != jobs.CodeCompensationFailed {
		t.Fatalf("rollback of a quarantined instance's job: %s", c)
	}
	if n := g.count(t, `SELECT count(*) FROM provisioning_job_steps WHERE job_id = $1 AND compensation_status = 'succeeded'`, restart); n != 0 {
		t.Fatal("a compensation step ran on a quarantined instance")
	}
}

// TestReleaseFailuresStayQuarantined — any failure of a release leaves the instance quarantined and isolated: the start
// guard refused (Critical), another policy served (refused by the agent), the post-start gate (API key rejected,
// another policy through the API), no applied policy (refused before the host is touched).
func TestReleaseFailuresStayQuarantined(t *testing.T) {
	g := newRig(t, rigOptions{})
	release := func(ten *tenantFx) uuid.UUID {
		t.Helper()
		r, err := g.requestRelease(t, ten)
		if err != nil {
			t.Fatal(err)
		}
		done, err := g.approve(t, g.sa2, r)
		if err != nil || done.JobID == nil {
			t.Fatalf("approval: %+v %v", done, err)
		}
		return *done.JobID
	}
	stays := func(ten *tenantFx, job uuid.UUID, code string) {
		t.Helper()
		g.wait(t, job, jobs.StatusFailed)
		if c := g.errCode(t, job); c != code {
			t.Fatalf("code %s, want %s (steps %s)", c, code, g.steps(t, job))
		}
		if s := g.instanceStatus(t, ten); s != tenants.InstanceQuarantined {
			t.Fatalf("after a failed release: %s", s)
		}
		if h := g.agent.host(ten.instance); !h.marked || h.running || h.attached || h.flag {
			t.Fatalf("not isolated again: %+v", h)
		}
		if g.events(t, EventReleaseFailed, ten) != 1 || g.notified(t, string(notifications.KindInstanceReleased), notifications.OutcomeRefused, ten) != 3 {
			t.Fatal("release_failed event / refused notifications")
		}
		if a := g.auditActions(t, ActionRelease, ten); a != ActionRelease+".requested:success "+ActionRelease+".failed:failure" {
			t.Fatalf("audit: %s", a)
		}
	}
	// start guard
	a := g.newTenant(t)
	g.quarantined(t, a)
	g.agent.set(func(x *fakeAgent) { x.startGuard = true })
	stays(a, release(a), "agent_state")
	if g.events(t, EventStartGuard, a) != 1 {
		t.Fatal("no start guard event")
	}
	g.agent.set(func(x *fakeAgent) { x.startGuard = false })
	// another policy served (the agent refuses before unmarking)
	b := g.newTenant(t)
	g.quarantined(t, b)
	g.agent.set(func(x *fakeAgent) { x.inst[b.instance].served = sha("another policy") })
	stays(b, release(b), "agent_state")
	// the post-start gate: API key rejected (after starting + edge attached: the registry moves back from starting)
	c := g.newTenant(t)
	g.quarantined(t, c)
	c.hs.set(func(f *fakeHS) { f.keyRejected = true })
	stays(c, release(c), "headscale_api_key_rejected")
	if g.events(t, EventPostStartGate, c) != 1 || g.agent.host(c.instance).quarantines != 2 {
		t.Fatal("post-start gate event / isolation again")
	}
	// the post-start gate: another policy through the API (drift)
	d := g.newTenant(t)
	g.quarantined(t, d)
	d.hs.set(func(f *fakeHS) { f.stored = "{}" })
	stays(d, release(d), "policy_drift")
	// no applied policy: refused at release.prepare — the host is never touched
	e := g.newTenant(t)
	g.quarantined(t, e)
	g.exec(t, `UPDATE policy_applications SET superseded_at = now() WHERE instance_id = $1`, e.instance)
	calls := g.agent.count("ReleaseInstance")
	job := release(e)
	g.wait(t, job, jobs.StatusFailed)
	if c := g.errCode(t, job); c != "no_applied_policy" || g.agent.count("ReleaseInstance") != calls ||
		g.agent.host(e.instance).quarantines != 1 || g.instanceStatus(t, e) != tenants.InstanceQuarantined {
		t.Fatalf("no applied policy: %s, %d releases", c, g.agent.count("ReleaseInstance")-calls)
	}
}

// TestReleaseStopsOnNewQuarantine — a quarantine requested while a release runs (its own dedupe key: never blocked by
// the release) stops the release at its next step (quarantine_requested): isolated again, still quarantined.
func TestReleaseStopsOnNewQuarantine(t *testing.T) {
	g := newRig(t, rigOptions{})
	ten := g.newTenant(t)
	g.quarantined(t, ten)
	block, enter := make(chan struct{}), make(chan struct{})
	g.agent.set(func(a *fakeAgent) { a.releaseBlock, a.releaseEnter = block, enter })
	r, err := g.requestRelease(t, ten)
	if err != nil {
		t.Fatal(err)
	}
	done, err := g.approve(t, g.sa2, r)
	if err != nil || done.JobID == nil {
		t.Fatal(err)
	}
	<-enter // the release is inside ReleaseInstance
	q, err := g.quarantine(t, ten, "")
	if err != nil {
		t.Fatalf("a quarantine during a release: %v", err)
	}
	close(block)
	g.wait(t, *done.JobID, jobs.StatusFailed)
	if c := g.errCode(t, *done.JobID); c != CodeQuarantineRequested {
		t.Fatalf("release code %s (steps %s)", c, g.steps(t, *done.JobID))
	}
	g.wait(t, q.Job.ID, jobs.StatusSucceeded)
	if s := g.instanceStatus(t, ten); s != tenants.InstanceQuarantined {
		t.Fatalf("status %s", s)
	}
	if h := g.agent.host(ten.instance); !h.marked || h.running || h.attached {
		t.Fatalf("host %+v", h)
	}
}

// TestQuarantineIncomplete — the isolation fails (agent busy past the retries, no agent, an instance the agent does not
// manage): the registry stays quarantined, Critical instance.quarantine_incomplete, "incomplete" to the staff, audit
// .failed; an instance never deployed (allocated) has nothing on the host: the quarantine succeeds.
func TestQuarantineIncomplete(t *testing.T) {
	g := newRig(t, rigOptions{isolateRetries: 1})
	incomplete := func(ten *tenantFx, code string) {
		t.Helper()
		out, err := g.quarantine(t, ten, "")
		if err != nil {
			t.Fatal(err)
		}
		g.wait(t, out.Job.ID, jobs.StatusFailed)
		if c := g.errCode(t, out.Job.ID); c != code {
			t.Fatalf("code %s, want %s", c, code)
		}
		if s := g.instanceStatus(t, ten); s != tenants.InstanceQuarantined {
			t.Fatalf("registry %s", s)
		}
		if g.events(t, EventQuarantineIncomplete, ten) != 1 ||
			g.notified(t, string(notifications.KindInstanceQuarantined), notifications.OutcomeIncomplete, ten) != 3 {
			t.Fatal("incomplete event / notifications")
		}
		if a := g.auditActions(t, ActionQuarantine, ten); a != ActionQuarantine+".requested:success "+ActionQuarantine+".failed:failure" {
			t.Fatalf("audit %s", a)
		}
	}
	busy := g.newTenant(t)
	g.agent.set(func(a *fakeAgent) { a.alwaysBusy = true })
	incomplete(busy, "agent_busy")
	g.agent.set(func(a *fakeAgent) { a.alwaysBusy = false })
	// containment that never shows in the status (the supervisor would re-contain; here it never does)
	lying := g.newTenant(t)
	g.agent.set(func(a *fakeAgent) { a.statusRunning = true })
	incomplete(lying, "containment_incomplete")
	g.agent.set(func(a *fakeAgent) { a.statusRunning = false })
	// not managed by the agent (deployed by hand)
	hand := g.newTenant(t)
	g.agent.set(func(a *fakeAgent) { delete(a.inst, hand.instance) })
	incomplete(hand, "instance_not_on_agent")
	// never deployed: nothing on the host
	alloc := g.newTenant(t)
	g.exec(t, `UPDATE tenant_instances SET status = 'allocated' WHERE id = $1`, alloc.instance)
	g.agent.set(func(a *fakeAgent) { delete(a.inst, alloc.instance) })
	out, err := g.quarantine(t, alloc, "")
	if err != nil {
		t.Fatal(err)
	}
	g.wait(t, out.Job.ID, jobs.StatusSucceeded)
}

// TestQuarantineWithoutAgent — no Host Agent configured: the registry is quarantined at once, the job fails
// agent_not_configured with the Critical incomplete event (the operator isolates by hand).
func TestQuarantineWithoutAgent(t *testing.T) {
	g2 := newRig(t, rigOptions{noAgent: true})
	none := g2.newTenant(t)
	out, err := g2.quarantine(t, none, "")
	if err != nil {
		t.Fatal(err)
	}
	g2.wait(t, out.Job.ID, jobs.StatusFailed)
	if c := g2.errCode(t, out.Job.ID); c != "agent_not_configured" || g2.instanceStatus(t, none) != tenants.InstanceQuarantined ||
		g2.events(t, EventQuarantineIncomplete, none) != 1 {
		t.Fatalf("no agent: %s", c)
	}
}

// TestRequestRefusalsDB — the API side: unknown instance 404, removed 409, blank reason 422 (after the lookup),
// release of an instance not quarantined 409, release while the quarantine job runs 409 (quarantine_in_progress), an
// approved payload naming another tenant refused at execution; an unfinished quarantine job is returned as is.
func TestRequestRefusalsDB(t *testing.T) {
	g := newRig(t, rigOptions{noWorker: true})
	ten := g.newTenant(t)
	ctx := g.reqCtx(t, g.sa1.IdentityID, ActionQuarantine)
	if _, err := g.req.Quarantine(ctx, g.sa1.IdentityID, uuid.New(), "x", nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown instance: %v", err)
	}
	if _, err := g.req.Quarantine(ctx, g.sa1.IdentityID, ten.instance, "  ", nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("blank reason: %v", err)
	}
	if s := g.instanceStatus(t, ten); s != tenants.InstanceRunning {
		t.Fatalf("a refused request changed the registry: %s", s)
	}
	if _, err := g.req.ReleasePayload(t.Context(), ten.instance); !errors.Is(err, ErrConflict) {
		t.Fatalf("release of a running instance: %v", err)
	}
	out, err := g.quarantine(t, ten, "")
	if err != nil {
		t.Fatal(err)
	}
	again, err := g.quarantine(t, ten, "")
	if err != nil || again.Job.ID != out.Job.ID || again.Changed {
		t.Fatalf("unfinished quarantine: %+v %v", again, err)
	}
	var re *RequestError
	if _, err := g.req.ReleasePayload(t.Context(), ten.instance); !errors.As(err, &re) || re.Reason != ReasonQuarantineActive {
		t.Fatalf("release during the quarantine job: %v", err)
	}
	// the executor checks again in the approval's transaction: a payload of another tenant is refused
	err = g.api.WithPlatformJobTx(t.Context(), func(tx *store.Tx) error {
		_, err := ExecuteRelease(t.Context(), tx, ReleaseExecution{ApprovalID: uuid.New(), RequestedBy: g.sa1.IdentityID,
			ApprovedBy: g.sa2.IdentityID, Payload: ReleasePayload{InstanceID: ten.instance, TenantID: uuid.New()}})
		return err
	})
	if !errors.As(err, &re) || re.Reason != ReasonTenantMismatch {
		t.Fatalf("tenant mismatch: %v", err)
	}
	removed := g.newTenant(t)
	g.exec(t, `UPDATE tenant_instances SET status = 'removed' WHERE id = $1`, removed.instance)
	if _, err := g.quarantine(t, removed, ""); !errors.As(err, &re) || re.Reason != ReasonRemoved {
		t.Fatalf("removed: %v", err)
	}
}

// TestGateDecisions — the step gate on PostgreSQL: quarantined instance stops every kind but quarantine; release stops
// only on a quarantine of its instance unfinished or newer; a platform job is never stopped; other tenants untouched.
func TestGateDecisions(t *testing.T) {
	g := newRig(t, rigOptions{noWorker: true})
	ten, other := g.newTenant(t), g.newTenant(t)
	gate := func(kind string, tenant, instance *uuid.UUID, job uuid.UUID) error {
		var out error
		if err := g.wrk.WithPlatformTx(t.Context(), func(q *sqlcdb.Queries) error {
			out = Gate(t.Context(), q, jobs.GateRun{ID: job, Kind: kind, TenantID: tenant, InstanceID: instance})
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return out
	}
	if err := gate("tenant.suspend", &ten.id, nil, uuid.New()); err != nil {
		t.Fatalf("running instance gated: %v", err)
	}
	q, err := g.quarantine(t, ten, "") // no worker: the quarantine job stays queued (unfinished)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		kind     string
		instance *uuid.UUID
	}{{"tenant.provision", nil}, {"tenant.suspend", nil}, {"instance.reconfigure", &ten.instance}, {"instance.backup", &ten.instance}} {
		if err := gate(c.kind, &ten.id, c.instance, uuid.New()); jobs.CodeOf(err) != CodeInstanceQuarantined || !jobs.IsResumable(err) {
			t.Errorf("%s not stopped: %v", c.kind, err)
		}
	}
	if err := gate(KindQuarantine, &ten.id, &ten.instance, q.Job.ID); err != nil {
		t.Fatalf("the quarantine job gated: %v", err)
	}
	if err := gate(KindDeprovision, &ten.id, nil, uuid.New()); err != nil {
		t.Fatalf("tenant.deprovision gated: %v", err)
	}
	if err := gate("instance.reconfigure", &other.id, &other.instance, uuid.New()); err != nil {
		t.Fatalf("another tenant gated: %v", err)
	}
	if err := gate("job.reaper", nil, nil, uuid.New()); err != nil {
		t.Fatal("a platform job gated")
	}
	// a release job created while the quarantine is unfinished stops; once it is finished and older, it goes on
	var rel uuid.UUID
	if err := g.api.WithPlatformJobTx(t.Context(), func(tx *store.Tx) error {
		enq, err := jobs.Enqueue(t.Context(), tx, jobs.Spec{Kind: KindRelease, TenantID: &ten.id, InstanceID: &ten.instance})
		rel = enq.Job.ID
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := gate(KindRelease, &ten.id, &ten.instance, rel); jobs.CodeOf(err) != CodeQuarantineRequested {
		t.Fatalf("release with an unfinished quarantine: %v", err)
	}
	g.exec(t, `UPDATE provisioning_jobs SET status = 'succeeded', finished_at = now() WHERE id = $1`, q.Job.ID)
	if err := gate(KindRelease, &ten.id, &ten.instance, rel); err != nil {
		t.Fatalf("release after the quarantine finished: %v", err)
	}
}
