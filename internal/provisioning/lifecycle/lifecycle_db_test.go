package lifecycle

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/infrastructure/headscale/templates"
	"github.com/zhaduchanhzz/network-access-mesh/internal/authz"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/notifications"
	"github.com/zhaduchanhzz/network-access-mesh/internal/policies"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/orchestrator"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
)

// canonical is the string the policy core sends for a HuJSON text (Document.Applied).
func canonical(t *testing.T, text string) string {
	t.Helper()
	d, err := policies.Lint(text)
	if err != nil {
		t.Fatal(err)
	}
	return d.Applied
}

// asMember is the context of a request of the tenant identity (the session on app.).
func asMember(ctx context.Context, identity uuid.UUID) context.Context {
	return authz.WithPrincipal(ctx, authz.Principal{IdentityID: identity, Scope: authz.ScopeTenant, Origin: authz.OriginApp})
}

func wantConflict(t *testing.T, what string, err error, reason string) {
	t.Helper()
	var re *RequestError
	if !errors.Is(err, ErrConflict) || !errors.As(err, &re) || re.Reason != reason {
		t.Errorf("%s: err %v, want conflict %s", what, err, reason)
	}
}

// TestSuspendResumeDB — the verification of §20 at the level of the registry: suspend ⇒ the suspension policy is what
// Headscale enforces (desired version kept), every valid pre-auth key expired (and only those), the tenant `suspended`
// so a Tenant Admin's write (syncDevices) is refused with tenant_suspended while reads go on, the Owner and Admins
// notified, the audit pair closed; a second suspend ⇒ 409; resume ⇒ the desired version enforced again (no new
// version), `active`, writes allowed again; a second resume ⇒ 409. The other tenant is never touched.
func TestSuspendResumeDB(t *testing.T) {
	g := newRig(t, rigOptions{})
	a, b := g.newTenant(t), g.newTenant(t)
	allow, deny := canonical(t, allowFixture(t)), canonical(t, templates.SuspensionPolicy)
	az := authz.New(g.api)
	admin := asMember(t.Context(), a.adminIdentity)
	if _, err := az.RequireOperation(admin, "syncDevices", a.id); err != nil {
		t.Fatalf("Tenant Admin sync before the suspension: %v", err)
	}

	r, err := g.suspend(t, a, "suspend-a-0001")
	if err != nil || !r.Changed || r.Job.Kind != KindSuspend || r.Job.Status != jobs.StatusQueued || len(r.Job.Steps) != 1 ||
		r.Job.Steps[0].Name != StepValidate || r.Job.Steps[0].Status != jobs.StepSucceeded {
		t.Fatalf("suspend: %+v, %v", r, err)
	}
	replay, err := g.suspend(t, a, "suspend-a-0001")
	if err != nil || replay.Changed || replay.Job.ID != r.Job.ID {
		t.Errorf("replay of the same request: %+v, %v (want the same job, nothing written)", replay, err)
	}
	g.wait(t, r.Job.ID, jobs.StatusSucceeded)
	if got, want := g.steps(t, r.Job.ID), "validate:succeeded policy.suspend:succeeded registry.suspend:succeeded "+
		"preauthkeys.expire:succeeded notify:succeeded"; got != want {
		t.Errorf("steps %q, want %q", got, want)
	}
	if g.status(t, a) != "suspended" || g.status(t, b) != "active" {
		t.Errorf("status A %s B %s, want suspended / active", g.status(t, a), g.status(t, b))
	}
	if a.hs.Stored() != deny || b.hs.Stored() != allow {
		t.Errorf("Headscale A %q B %q: want the suspension on A only", a.hs.Stored(), b.hs.Stored())
	}
	if got := g.str(t, `SELECT desired_policy_version_id::text FROM tenants WHERE id = $1`, a.id); got != a.desired.String() {
		t.Errorf("desired version %s, want %s kept (§7.3)", got, a.desired)
	}
	if got := g.str(t, `SELECT v.kind || ':' || p.trigger FROM policy_applications p JOIN policy_versions v ON v.id = p.policy_version_id
		WHERE p.tenant_id = $1 AND p.state = 'applied' AND p.superseded_at IS NULL`, a.id); got != "suspension:suspend" {
		t.Errorf("current application %s, want suspension:suspend", got)
	}
	var expired []string
	for _, c := range a.hs.Calls() {
		if strings.HasPrefix(c, "ExpirePreAuthKey:") {
			expired = append(expired, strings.TrimPrefix(c, "ExpirePreAuthKey:"))
		}
	}
	if !slices.Equal(expired, []string{"1", "2", "5"}) || len(ValidPreAuthKeys(a.hs.Keys(), time.Now())) != 0 {
		t.Errorf("expired keys %v (want 1 2 5: valid, valid unused, reusable used), still valid %v", expired,
			ValidPreAuthKeys(a.hs.Keys(), time.Now()))
	}
	if n := len(ValidPreAuthKeys(b.hs.Keys(), time.Now())); n != 3 || slices.ContainsFunc(b.hs.Calls(), func(c string) bool {
		return strings.HasPrefix(c, "ExpirePreAuthKey") || strings.HasPrefix(c, "ListPreAuthKeys")
	}) {
		t.Errorf("tenant B: %d valid keys, calls %v — must not be touched", n, b.hs.Calls())
	}
	if got := g.str(t, `SELECT string_agg(action || ':' || coalesce(actor_identity_id::text, '-') || ':' ||
			(tenant_id IS NULL)::text, ',' ORDER BY occurred_at, id) FROM audit_events WHERE resource_id = $1
			AND action LIKE 'platform.tenant.suspend%'`, a.id.String()); got != "platform.tenant.suspend.requested:"+g.actor.String()+":true,"+
		"platform.tenant.suspend.succeeded:"+g.actor.String()+":true" {
		t.Errorf("audit %s", got)
	}
	if n := g.count(t, `SELECT count(*) FROM notification_outbox WHERE tenant_id = $1 AND kind = 'tenant.suspended'
			AND recipient_membership_id IN ($2, $3)`, a.id, a.owner, a.admin); n != 2 ||
		g.count(t, `SELECT count(*) FROM notification_outbox WHERE tenant_id = $1 AND kind = 'tenant.suspended'`, a.id) != 2 {
		t.Errorf("tenant.suspended notifications: %d to the Owner and Admin (want exactly those 2)", n)
	}
	// §8.4 invariant 5 — the authorizer of the api reads the new status at the next request
	_, err = az.RequireOperation(admin, "syncDevices", a.id)
	if !errors.Is(err, authz.ErrTenantSuspended) {
		t.Errorf("Tenant Admin sync while suspended: %v, want tenant_suspended", err)
	}
	if _, err := az.RequireOperation(admin, "listDevices", a.id); err != nil {
		t.Errorf("Tenant Admin read while suspended: %v", err)
	}
	if _, err := g.suspend(t, a, "suspend-a-0002"); err == nil {
		t.Error("suspend of a suspended tenant accepted")
	} else {
		wantConflict(t, "suspend again", err, ReasonAlreadySuspended)
	}

	r2, err := g.resume(t, a, "resume-a-0001")
	if err != nil || !r2.Changed || r2.Job.Kind != KindResume {
		t.Fatalf("resume: %+v, %v", r2, err)
	}
	g.wait(t, r2.Job.ID, jobs.StatusSucceeded)
	if got, want := g.steps(t, r2.Job.ID), "validate:succeeded policy.resume:succeeded registry.resume:succeeded notify:succeeded"; got != want {
		t.Errorf("resume steps %q, want %q", got, want)
	}
	if g.status(t, a) != "active" || a.hs.Stored() != allow {
		t.Errorf("after resume: status %s, Headscale %q — want active with the desired policy", g.status(t, a), a.hs.Stored())
	}
	if got := g.str(t, `SELECT p.policy_version_id::text || ':' || p.trigger FROM policy_applications p
		WHERE p.tenant_id = $1 AND p.state = 'applied' AND p.superseded_at IS NULL`, a.id); got != a.desired.String()+":resume" {
		t.Errorf("current application %s, want the desired version with trigger resume", got)
	}
	if n := g.count(t, `SELECT count(*) FROM policy_versions WHERE tenant_id = $1`, a.id); n != 2 {
		t.Errorf("%d policy versions, want 2 (the allow fixture, the suspension) — resume creates none", n)
	}
	if n := g.count(t, `SELECT count(*) FROM audit_events WHERE resource_id = $1 AND action IN
			('platform.tenant.resume.requested', 'platform.tenant.resume.succeeded')`, a.id.String()); n != 2 {
		t.Errorf("resume audit pair: %d events", n)
	}
	if n := g.count(t, `SELECT count(*) FROM notification_outbox WHERE tenant_id = $1 AND kind = 'tenant.resumed'`, a.id); n != 2 {
		t.Errorf("tenant.resumed notifications: %d, want 2", n)
	}
	if _, err := az.RequireOperation(admin, "syncDevices", a.id); err != nil {
		t.Errorf("Tenant Admin sync after resume: %v", err)
	}
	_, err = g.resume(t, a, "resume-a-0002")
	wantConflict(t, "resume of an active tenant", err, ReasonNotSuspended)
	if len(ValidPreAuthKeys(a.hs.Keys(), time.Now())) != 0 {
		t.Error("resume must not bring the expired pre-auth keys back")
	}
}

// TestRequestRefusalsDB — the API side (no worker: jobs stay queued): unknown tenant ⇒ 404; no desired version ⇒ 409;
// a tenant neither active nor suspended ⇒ 409; resume of an active tenant ⇒ 409; the unfinished job of the same kind
// is answered as is (nothing written); another lifecycle job unfinished ⇒ 409; /cancel of a queued suspend closes its
// audit pair and leaves the tenant active.
func TestRequestRefusalsDB(t *testing.T) {
	g := newRig(t, rigOptions{noWorker: true})
	a, c, d := g.newTenant(t), g.newTenant(t), g.newTenant(t)
	if _, err := g.req.Suspend(g.reqCtx(t, ActionSuspend), g.actor, uuid.New(), nil); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown tenant: %v", err)
	}
	g.exec(t, `UPDATE tenants SET desired_policy_version_id = NULL WHERE id = $1`, c.id)
	_, err := g.suspend(t, c, "")
	wantConflict(t, "no desired version", err, ReasonNoPolicy)
	g.exec(t, `UPDATE tenants SET status = 'provisioning' WHERE id = $1`, d.id)
	_, err = g.suspend(t, d, "")
	wantConflict(t, "suspend of a provisioning tenant", err, ReasonNotActive)
	_, err = g.resume(t, d, "")
	wantConflict(t, "resume of a provisioning tenant", err, ReasonNotSuspendable)
	_, err = g.resume(t, a, "")
	wantConflict(t, "resume of an active tenant", err, ReasonNotSuspended)

	first, err := g.suspend(t, a, "refusals-0001")
	if err != nil || !first.Changed {
		t.Fatalf("suspend: %+v, %v", first, err)
	}
	again, err := g.suspend(t, a, "refusals-0002")
	if err != nil || again.Changed || again.Job.ID != first.Job.ID {
		t.Errorf("suspend while the same job is queued: %+v, %v (want that job, nothing written)", again, err)
	}
	_, err = g.resume(t, a, "refusals-0003")
	wantConflict(t, "resume while a suspend is unfinished", err, ReasonLifecycleJobActive)
	if n := g.count(t, `SELECT count(*) FROM audit_events WHERE resource_id = $1 AND action = 'platform.tenant.suspend.requested'`,
		a.id.String()); n != 1 {
		t.Errorf("%d suspend.requested events, want 1", n)
	}
	if got := g.str(t, `SELECT input ->> 'restore_version_id' FROM provisioning_jobs WHERE id = $1`, first.Job.ID); got != a.desired.String() {
		t.Errorf("job input restore_version_id %s, want the desired version %s", got, a.desired)
	}
	// another lifecycle job of the tenant (a tenant.provision left failed_resumable) holds tenant:<id>:lifecycle
	g.exec(t, `UPDATE tenants SET status = 'active' WHERE id = $1`, d.id)
	g.exec(t, `INSERT INTO provisioning_jobs (tenant_id, kind, dedupe_key, lock_key, status, attempt, max_attempts)
		VALUES ($1, 'tenant.provision', $2, $2, 'failed_resumable', 1, 6)`, d.id, jobs.LockKey(d.id))
	_, err = g.suspend(t, d, "")
	wantConflict(t, "suspend while a provision is unfinished", err, ReasonLifecycleJobActive)

	// /cancel of the queued suspend: cancelled, its audit operation closed .failed (cancelled), the tenant untouched
	ctl := orchestrator.NewControl(g.api)
	res, err := ctl.Cancel(g.reqCtx(t, "platform.job.cancel"), g.actor, first.Job.ID, nil)
	if err != nil || res.Job.Status != jobs.StatusCancelled {
		t.Fatalf("cancel: %+v, %v", res, err)
	}
	if got := g.str(t, `SELECT string_agg(action || ':' || coalesce(details ->> 'reason', '-'), ',' ORDER BY occurred_at, id)
			FROM audit_events WHERE resource_id = $1 AND action LIKE 'platform.tenant.suspend%'`, a.id.String()); got !=
		"platform.tenant.suspend.requested:-,platform.tenant.suspend.failed:cancelled" {
		t.Errorf("audit after cancel: %s", got)
	}
	if g.status(t, a) != "active" || a.hs.Stored() != canonical(t, allowFixture(t)) {
		t.Errorf("tenant after a cancelled suspend: %s %q", g.status(t, a), a.hs.Stored())
	}
	if r, err := g.suspend(t, a, "refusals-0004"); err != nil || !r.Changed || r.Job.ID == first.Job.ID {
		t.Errorf("a new suspend after the cancelled one: %+v, %v", r, err)
	}
}

// TestSuspendWaitsForTheLifecycleLock — one lifecycle job per tenant (§13.5 (d)): a running instance.restart of the
// tenant holds tenant:<id>:lifecycle; the suspend job stays queued (snoozed, no attempt used, nothing called) until the
// holder ends, then runs.
func TestSuspendWaitsForTheLifecycleLock(t *testing.T) {
	g := newRig(t, rigOptions{})
	a := g.newTenant(t)
	holder := uuid.New()
	g.exec(t, `INSERT INTO provisioning_jobs (id, tenant_id, instance_id, kind, dedupe_key, lock_key, status, attempt,
			max_attempts, started_at, timeout_at)
		VALUES ($1, $2, $3, 'instance.restart', $4, $5, 'running', 1, 6, now(), now() + interval '10 minutes')`,
		holder, a.id, a.instance, "instance:"+a.instance.String()+":instance.restart", jobs.LockKey(a.id))
	calls := len(a.hs.Calls())
	r, err := g.suspend(t, a, "")
	if err != nil || !r.Changed {
		t.Fatalf("suspend while an instance job holds the lock: %+v, %v (the request is accepted, the job waits)", r, err)
	}
	time.Sleep(1500 * time.Millisecond)
	if st := g.str(t, `SELECT status || ':' || attempt FROM provisioning_jobs WHERE id = $1`, r.Job.ID); st != "queued:0" ||
		g.status(t, a) != "active" || len(a.hs.Calls()) != calls {
		t.Fatalf("while the lock is held: job %s, tenant %s, Headscale calls %v", st, g.status(t, a), a.hs.Calls()[calls:])
	}
	g.exec(t, `UPDATE provisioning_jobs SET status = 'succeeded', finished_at = now() WHERE id = $1`, holder)
	g.wait(t, r.Job.ID, jobs.StatusSucceeded)
	if g.status(t, a) != "suspended" {
		t.Errorf("after the holder ended: tenant %s", g.status(t, a))
	}
}

// TestSuspendTransientFailureResumes — Headscale unreachable for the pre-auth keys: retried in place, then
// failed_resumable holding the lock (a resume ⇒ 409) — the tenant already suspended behind the suspension policy (fail
// closed); /retry resumes from the failed step (the policy is not applied again) and closes the audit pair once.
func TestSuspendTransientFailureResumes(t *testing.T) {
	g := newRig(t, rigOptions{})
	a := g.newTenant(t)
	a.hs.set(func(f *fakeHS) {
		f.listErr = &headscale.Error{Op: headscale.OpListPreAuthKeys, Kind: headscale.KindUnavailable, Code: -1}
	})
	r, err := g.suspend(t, a, "")
	if err != nil {
		t.Fatal(err)
	}
	g.wait(t, r.Job.ID, jobs.StatusFailedResumable)
	if got := g.str(t, `SELECT error ->> 'code' FROM provisioning_jobs WHERE id = $1`, r.Job.ID); got != "instance_unavailable" {
		t.Errorf("error code %s", got)
	}
	if g.status(t, a) != "suspended" || a.hs.Stored() != canonical(t, templates.SuspensionPolicy) {
		t.Errorf("after the failure: %s %q — want suspended behind the suspension policy", g.status(t, a), a.hs.Stored())
	}
	_, err = g.resume(t, a, "")
	wantConflict(t, "resume while the suspend is failed_resumable", err, ReasonLifecycleJobActive)
	sets := strings.Count(strings.Join(a.hs.Calls(), " "), "SetPolicy")
	a.hs.set(func(f *fakeHS) { f.listErr = nil })
	if _, err := g.control(t, jobs.Retry, r.Job.ID); err != nil {
		t.Fatalf("retry: %v", err)
	}
	g.wait(t, r.Job.ID, jobs.StatusSucceeded)
	if n := strings.Count(strings.Join(a.hs.Calls(), " "), "SetPolicy"); n != sets {
		t.Errorf("SetPolicy %d → %d: /retry must resume from preauthkeys.expire", sets, n)
	}
	if got := g.str(t, `SELECT string_agg(name || ':' || attempt, ' ' ORDER BY seq) FROM provisioning_job_steps WHERE job_id = $1`,
		r.Job.ID); got != "validate:1 policy.suspend:1 registry.suspend:1 preauthkeys.expire:4 notify:1" {
		t.Errorf("attempts %s (3 tries before failed_resumable + 1 after /retry)", got)
	}
	if n := g.count(t, `SELECT count(*) FROM audit_events WHERE resource_id = $1 AND action = 'platform.tenant.suspend.succeeded'`,
		a.id.String()); n != 1 {
		t.Errorf("%d suspend.succeeded events", n)
	}
}

// TestSuspendPermanentFailureNeverUnsuspends — a permanent error of tenant.suspend (Headscale refuses the listing)
// stops failed_resumable WITHOUT compensation: the tenant stays suspended behind the suspension policy. Only /rollback
// undoes it, in reverse order: `active` again, then the desired version applied again; the expired keys stay expired
// (no compensation); the audit pair closes .failed.
func TestSuspendPermanentFailureNeverUnsuspends(t *testing.T) {
	g := newRig(t, rigOptions{})
	a := g.newTenant(t)
	a.hs.set(func(f *fakeHS) {
		f.listErr = &headscale.Error{Op: headscale.OpListPreAuthKeys, Kind: headscale.KindUpstreamRejected, Code: -1}
	})
	r, err := g.suspend(t, a, "")
	if err != nil {
		t.Fatal(err)
	}
	g.wait(t, r.Job.ID, jobs.StatusFailedResumable, jobs.StatusRolledBack)
	if st := g.str(t, `SELECT status || ':' || (error ->> 'code') FROM provisioning_jobs WHERE id = $1`, r.Job.ID); st !=
		"failed_resumable:headscale_upstream_rejected" {
		t.Fatalf("job %s, want failed_resumable (never an automatic compensation of a suspension)", st)
	}
	if g.status(t, a) != "suspended" || a.hs.Stored() != canonical(t, templates.SuspensionPolicy) {
		t.Errorf("after the failure: %s — want suspended (fail closed)", g.status(t, a))
	}
	if _, err := g.control(t, jobs.Rollback, r.Job.ID); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	g.wait(t, r.Job.ID, jobs.StatusRolledBack)
	if got := g.compensation(t, r.Job.ID); got != "validate:skipped policy.suspend:succeeded registry.suspend:succeeded "+
		"preauthkeys.expire:skipped" {
		t.Errorf("compensation %s", got)
	}
	if g.status(t, a) != "active" || a.hs.Stored() != canonical(t, allowFixture(t)) {
		t.Errorf("after /rollback: %s %q — want active with the desired policy", g.status(t, a), a.hs.Stored())
	}
	if got := g.str(t, `SELECT string_agg(action || ':' || coalesce(details ->> 'reason', '-'), ',' ORDER BY occurred_at, id)
			FROM audit_events WHERE resource_id = $1 AND action LIKE 'platform.tenant.suspend%'`, a.id.String()); got !=
		"platform.tenant.suspend.requested:-,platform.tenant.suspend.failed:headscale_upstream_rejected" {
		t.Errorf("audit %s", got)
	}
	if got := g.str(t, `SELECT p.policy_version_id::text || ':' || p.trigger FROM policy_applications p
		WHERE p.tenant_id = $1 AND p.state = 'applied' AND p.superseded_at IS NULL`, a.id); got != a.desired.String()+":resume" {
		t.Errorf("current application %s", got)
	}
}

// TestResumeFailureCompensates — a permanent error of tenant.resume is compensated at once: Headscale refuses the
// desired version ⇒ the suspension policy is applied again, the tenant stays suspended, the job ends rolled_back,
// .failed; once the cause is fixed a new resume succeeds.
func TestResumeFailureCompensates(t *testing.T) {
	g := newRig(t, rigOptions{})
	a := g.newTenant(t)
	r, err := g.suspend(t, a, "")
	if err != nil {
		t.Fatal(err)
	}
	g.wait(t, r.Job.ID, jobs.StatusSucceeded)
	allow := canonical(t, allowFixture(t))
	a.hs.set(func(f *fakeHS) {
		f.checkErr, f.checkFor = &headscale.Error{Op: headscale.OpCheckPolicy, Kind: headscale.KindPolicyRejected, Code: -1}, allow
	})
	r2, err := g.resume(t, a, "")
	if err != nil {
		t.Fatal(err)
	}
	g.wait(t, r2.Job.ID, jobs.StatusRolledBack)
	if got := g.compensation(t, r2.Job.ID); got != "validate:skipped policy.resume:succeeded" {
		t.Errorf("compensation %s", got)
	}
	if g.status(t, a) != "suspended" || a.hs.Stored() != canonical(t, templates.SuspensionPolicy) {
		t.Errorf("after the failed resume: %s %q — want suspended behind the suspension policy", g.status(t, a), a.hs.Stored())
	}
	if got := g.str(t, `SELECT string_agg(action || ':' || coalesce(details ->> 'reason', '-'), ',' ORDER BY occurred_at, id)
			FROM audit_events WHERE resource_id = $1 AND action LIKE 'platform.tenant.resume%'`, a.id.String()); got !=
		"platform.tenant.resume.requested:-,platform.tenant.resume.failed:policy_rejected" {
		t.Errorf("audit %s", got)
	}
	a.hs.set(func(f *fakeHS) { f.checkErr = nil })
	r3, err := g.resume(t, a, "")
	if err != nil {
		t.Fatal(err)
	}
	g.wait(t, r3.Job.ID, jobs.StatusSucceeded)
	if g.status(t, a) != "active" || a.hs.Stored() != allow {
		t.Errorf("second resume: %s %q", g.status(t, a), a.hs.Stored())
	}
}

// failingNotifier refuses every event like an invalid one (a permanent error of the last step).
type failingNotifier struct{}

func (failingNotifier) Enqueue(context.Context, *store.Tx, notifications.Event) (notifications.Result, error) {
	return notifications.Result{}, notifications.ErrInvalidEvent
}

// TestResumeCompensationAfterStatusChange — a permanent error in the last step of tenant.resume (after the tenant was
// `active` again) is undone in reverse order: `suspended` again, then the suspension policy again.
func TestResumeCompensationAfterStatusChange(t *testing.T) {
	g := newRig(t, rigOptions{notifier: failingNotifier{}})
	a := g.newTenant(t)
	g.exec(t, `UPDATE tenants SET status = 'suspended' WHERE id = $1`, a.id)
	a.hs.set(func(f *fakeHS) { f.stored = canonical(t, templates.SuspensionPolicy) })
	r, err := g.resume(t, a, "")
	if err != nil {
		t.Fatal(err)
	}
	g.wait(t, r.Job.ID, jobs.StatusRolledBack)
	if got := g.compensation(t, r.Job.ID); got != "validate:skipped policy.resume:succeeded registry.resume:succeeded notify:skipped" {
		t.Errorf("compensation %s", got)
	}
	if g.status(t, a) != "suspended" || a.hs.Stored() != canonical(t, templates.SuspensionPolicy) {
		t.Errorf("after compensation: %s %q", g.status(t, a), a.hs.Stored())
	}
	if got := g.str(t, `SELECT error ->> 'code' FROM provisioning_jobs WHERE id = $1`, r.Job.ID); got != "notification_invalid" {
		t.Errorf("job error %s", got)
	}
}

// TestRegistryMustReachSuspendedTenants — why the worker gives the handler its own registry (ReachableStatuses): with the
// statuses of the other jobs (provisioning, active — G2 L1) the instance is unreachable as soon as the tenant is
// suspended, so the pre-auth keys cannot be expired: the job stops failed_resumable (instance_unavailable).
func TestRegistryMustReachSuspendedTenants(t *testing.T) {
	g := newRig(t, rigOptions{statuses: []string{"provisioning", "active"}})
	a := g.newTenant(t)
	r, err := g.suspend(t, a, "")
	if err != nil {
		t.Fatal(err)
	}
	g.wait(t, r.Job.ID, jobs.StatusFailedResumable)
	if got := g.str(t, `SELECT coalesce(current_step, '') || ':' || (error ->> 'code') FROM provisioning_jobs WHERE id = $1`,
		r.Job.ID); got != "preauthkeys.expire:instance_unavailable" {
		t.Errorf("job %s", got)
	}
	if !slices.Contains(ReachableStatuses, "suspended") || !slices.Contains(ReachableStatuses, "active") {
		t.Errorf("ReachableStatuses %v", ReachableStatuses)
	}
}
