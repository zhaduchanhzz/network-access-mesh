package devices

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/zhaduchanhzz/network-access-mesh/internal/devices/devicestest"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// TestListFiltersAndPages: stable pages through the cursor, filters (the tagged/has_expiry pair of the periodic review
// of tagged nodes that never expire — P4-T04), the own-only view of the End User (own untagged devices only), cursor
// misuse, fresh=true (bounded sync first; with a cursor ⇒ 422; instance down ⇒ 503), and RLS (tenant B never sees A's
// devices, whatever it asks).
func TestListFiltersAndPages(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	a := f.a
	now := time.Now().UTC()
	for i := uint64(1); i <= 7; i++ {
		owner, user := a.alice, a.aliceUser
		if i%2 == 0 {
			owner, user = a.bob, a.bobUser
		}
		n := userNode(a, i, owner, user, now, tp(now.Add(time.Hour)))
		n.Online = i <= 3
		n.GivenName = fmt.Sprintf("laptop-%d", i)
		if i == 7 {
			n.Tags = []string{"tag:server"}
			n.GivenName = "build-server"
			n.Expiry = nil // a tagged node never expires (HS-19)
		}
		a.hs.PutNode(n)
	}
	// fresh=true syncs first.
	page, err := f.api.List(ctx, a.id, Access{}, ListQuery{Fresh: true, Limit: 3})
	if err != nil || len(page.Items) != 3 || page.NextCursor == "" {
		t.Fatalf("fresh page: %d items, cursor %q, %v", len(page.Items), page.NextCursor, err)
	}
	var all []uuid.UUID
	q := ListQuery{Limit: 3}
	for range 10 {
		p, err := f.api.List(ctx, a.id, Access{}, q)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range p.Items {
			all = append(all, d.ID)
		}
		if p.NextCursor == "" {
			break
		}
		q.Cursor = p.NextCursor
	}
	if len(all) != 7 || len(slices.Compact(slices.Clone(all))) != 7 {
		t.Fatalf("paged %d devices (%v), want 7 distinct", len(all), all)
	}
	check := func(what string, acc Access, q ListQuery, want int) {
		t.Helper()
		p, err := f.api.List(ctx, a.id, acc, q)
		if err != nil || len(p.Items) != want {
			t.Errorf("%s: %d items, %v; want %d", what, len(p.Items), err, want)
		}
	}
	on, off := true, false
	alice := a.alice
	check("online", Access{}, ListQuery{Online: &on}, 3)
	check("offline", Access{}, ListQuery{Online: &off}, 4)
	check("owner Alice", Access{}, ListQuery{Owner: &alice}, 3) // node 7 is tagged: owner never set from Headscale
	check("tag", Access{}, ListQuery{Tag: "tag:server"}, 1)
	check("search", Access{}, ListQuery{Search: "LAPTOP-1"}, 1)
	check("search hostname", Access{}, ListQuery{Search: "host-"}, 7)
	check("search with LIKE wildcards is literal", Access{}, ListQuery{Search: "%"}, 0)
	check("tagged", Access{}, ListQuery{Tagged: &on}, 1)
	check("untagged", Access{}, ListQuery{Tagged: &off}, 6)
	check("never expires", Access{}, ListQuery{HasExpiry: &off}, 1)
	check("has an expiry", Access{}, ListQuery{HasExpiry: &on}, 6)
	check("review: tagged + never expires", Access{}, ListQuery{Tagged: &on, HasExpiry: &off}, 1)
	check("tagged + has an expiry", Access{}, ListQuery{Tagged: &on, HasExpiry: &on}, 0)
	if p, _ := f.api.List(ctx, a.id, Access{}, ListQuery{Tagged: &on, HasExpiry: &off}); len(p.Items) != 1 ||
		p.Items[0].Expiry != nil || !slices.Equal(p.Items[0].Tags, []string{"tag:server"}) || p.Items[0].Owner != nil {
		t.Errorf("review report: %+v", p.Items)
	}
	// The End User sees her own untagged devices only, whatever filter she asks for.
	own := Access{OwnOnly: true, MembershipID: a.alice}
	check("own", own, ListQuery{}, 3)
	bob := a.bob
	check("own + owner Bob", own, ListQuery{Owner: &bob}, 0)
	check("own + tag", own, ListQuery{Tag: "tag:server"}, 0)
	check("own + tagged", own, ListQuery{Tagged: &on}, 0)
	check("own + never expires", own, ListQuery{HasExpiry: &off}, 0)
	f.exec(t, `UPDATE device_inventory_cache SET owner_membership_id = $1 WHERE headscale_node_id = 7`, a.alice)
	check("own never shows a tagged device, even owned", own, ListQuery{}, 3)

	// Cursor misuse and parameters.
	p1, _ := f.api.List(ctx, a.id, Access{}, ListQuery{Limit: 2})
	for what, q := range map[string]ListQuery{
		"cursor": {Cursor: p1.NextCursor, Online: &on}, "limit": {Limit: 201}, "fresh": {Fresh: true, Cursor: p1.NextCursor},
		"tag": {Tag: "server"},
	} {
		if _, err := f.api.List(ctx, a.id, Access{}, q); !isCode(err, CodeValidationFailed) || fromAdapter(err).Field != what {
			t.Errorf("%s: %v, want validation_failed on %s", what, err, what)
		}
	}
	for what, q := range map[string]ListQuery{"tagged": {Cursor: p1.NextCursor, Tagged: &off},
		"has_expiry": {Cursor: p1.NextCursor, HasExpiry: &on}} {
		if _, err := f.api.List(ctx, a.id, Access{}, q); !isCode(err, CodeValidationFailed) {
			t.Errorf("cursor of the unfiltered list with %s: %v", what, err)
		}
	}
	if _, err := f.api.List(ctx, a.id, own, ListQuery{Cursor: p1.NextCursor}); !isCode(err, CodeValidationFailed) {
		t.Errorf("cursor of the full list used by an own-only caller: %v", err)
	}
	if _, err := f.api.List(ctx, f.b.id, Access{}, ListQuery{Cursor: p1.NextCursor}); !isCode(err, CodeValidationFailed) {
		t.Errorf("cursor of tenant A used on B: %v", err)
	}
	a.hs.SetDown(true)
	if _, err := f.api.List(ctx, a.id, Access{}, ListQuery{Fresh: true}); !isCode(err, CodeInstanceUnavailable) {
		t.Errorf("fresh with the instance down: %v", err)
	}
	a.hs.SetDown(false)

	// RLS and the explicit tenant condition: B sees none of A's devices.
	if ids := rowsOf(t, f.api, f.b.id); len(ids) != 0 {
		t.Errorf("tenant B lists %d devices of A", len(ids))
	}
	if _, err := f.api.Get(ctx, f.b.id, all[0], Access{}); !isReason(err, ReasonNoDevice) {
		t.Errorf("device of A through B: %v", err)
	}
}

// TestRename: local DNS-label check (Headscale not called), the pair device.rename.requested → .succeeded with the
// cache updated, own-resource rule, node gone ⇒ not_found + .failed, Headscale conflict ⇒ conflict + .failed.
func TestRename(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	a := f.a
	a.hs.PutNode(userNode(a, 1, a.alice, a.aliceUser, time.Now(), nil))
	if _, err := f.wrk.Sync(ctx, a.id, a.instance); err != nil {
		t.Fatal(err)
	}
	dev := f.deviceOfNode(t, a, 1)
	identity := uuid.New()
	actx := actorCtx(identity, a.id, ActionRename)
	for _, bad := range []string{"Laptop", "-x", "a_b", "", string(make([]byte, 64))} {
		if _, err := f.api.Rename(actx, a.id, dev, Access{}, bad); !isCode(err, CodeValidationFailed) {
			t.Errorf("rename to %q: %v", bad, err)
		}
	}
	if n := a.hs.Calls(devicestest.OpRenameNode); n != 0 {
		t.Errorf("invalid names reached Headscale %d times", n)
	}
	if _, err := f.api.Rename(actx, a.id, dev, Access{OwnOnly: true, MembershipID: a.bob}, "x1"); !isReason(err, ReasonNotOwnResource) {
		t.Errorf("Bob renames Alice's device: %v", err)
	}
	d, err := f.api.Rename(actx, a.id, dev, Access{OwnOnly: true, MembershipID: a.alice, IdentityID: identity}, "alice-laptop")
	if err != nil || d.GivenName != "alice-laptop" {
		t.Fatalf("rename: %+v %v", d, err)
	}
	if n, _ := a.hs.Node(1); n.GivenName != "alice-laptop" || deref(f.row(t, dev).GivenName) != "alice-laptop" {
		t.Errorf("instance %q, cache %q", n.GivenName, deref(f.row(t, dev).GivenName))
	}
	if got := f.auditOf(t, dev.String()); !slices.Equal(got, []string{"device.rename.requested/success", "device.rename.succeeded/success"}) {
		t.Errorf("audit: %v", got)
	}
	if n := count(t, f, `SELECT count(*) FROM audit_events WHERE resource_id = $1 AND actor_identity_id = $2`, dev.String(), identity); n != 2 {
		t.Errorf("events with the actor: %d", n)
	}
	a.hs.Refuse(devicestest.OpRenameNode, true)
	if _, err := f.api.Rename(actx, a.id, dev, Access{}, "other"); !isCode(err, CodeUpstreamRejected) {
		t.Errorf("refused rename: %v", err)
	}
	a.hs.Refuse(devicestest.OpRenameNode, false)
	a.hs.RemoveNode(1)
	if _, err := f.api.Rename(actx, a.id, dev, Access{}, "gone"); !isReason(err, ReasonNodeGone) {
		t.Errorf("node gone: %v", err)
	}
	if n := count(t, f, `SELECT count(*) FROM audit_events WHERE resource_id = $1 AND action = 'device.rename.failed'`, dev.String()); n != 2 {
		t.Errorf("failed renames recorded: %d, want 2", n)
	}
	if f.openOperations(t, a.id) != 0 {
		t.Error("open operation left")
	}
}

// TestRequestSync: POST …/devices/sync enqueues inventory.sync with device.sync.requested handed off; a second request
// while it is queued returns the same job; a replayed Idempotency-Key returns its job; the job closes the pair.
func TestRequestSync(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	a := f.a
	a.hs.PutNode(userNode(a, 1, a.alice, a.aliceUser, time.Now(), nil))
	identity := uuid.New()
	sctx := actorCtx(identity, a.id, ActionSync)
	acc := Access{IdentityID: identity}
	j1, err := f.api.RequestSync(sctx, a.id, acc, "sync-key-0001")
	if err != nil || j1.Kind != KindSync || j1.Status != jobs.StatusQueued {
		t.Fatalf("request: %+v %v", j1, err)
	}
	j2, err := f.api.RequestSync(sctx, a.id, acc, "sync-key-0002")
	if err != nil || j2.ID != j1.ID {
		t.Errorf("second request while queued: %+v %v, want job %s", j2, err, j1.ID)
	}
	j3, err := f.api.RequestSync(sctx, a.id, acc, "sync-key-0001")
	if err != nil || j3.ID != j1.ID {
		t.Errorf("replayed key: %+v %v", j3, err)
	}
	if n := count(t, f, `SELECT count(*) FROM audit_events WHERE action = 'device.sync.requested'`); n != 1 {
		t.Errorf("device.sync.requested: %d, want 1 (the repeated requests start nothing)", n)
	}
	if err := f.wrk.runSync(ctx, f.run(t, j1.ID, 1, 3)); err != nil {
		t.Fatal(err)
	}
	if n := count(t, f, `SELECT count(*) FROM audit_events WHERE action = 'device.sync.succeeded' AND actor_identity_id = $1`, identity); n != 1 {
		t.Errorf("device.sync.succeeded: %d", n)
	}
	if n := count(t, f, `SELECT count(*) FROM device_inventory_cache WHERE tenant_id = $1`, a.id); n != 1 {
		t.Errorf("devices after the job: %d", n)
	}
	// Failure: instance down on the last attempt ⇒ device.sync.failed.
	f.exec(t, `UPDATE provisioning_jobs SET status = 'succeeded', finished_at = now() WHERE id = $1`, j1.ID)
	j4, err := f.api.RequestSync(sctx, a.id, acc, "sync-key-0004")
	if err != nil || j4.ID == j1.ID {
		t.Fatalf("new request after the first finished: %+v %v", j4, err)
	}
	a.hs.SetDown(true)
	if err := f.wrk.runSync(ctx, f.run(t, j4.ID, 1, 3)); err == nil {
		t.Fatal("sync with the instance down succeeded")
	}
	if f.openOperations(t, a.id) != 1 {
		t.Error("the operation must stay open while attempts remain")
	}
	_ = f.wrk.runSync(ctx, f.run(t, j4.ID, 3, 3))
	if n := count(t, f, `SELECT count(*) FROM audit_events WHERE action = 'device.sync.failed'
			AND details ->> 'reason' = 'instance_unavailable'`); n != 1 || f.openOperations(t, a.id) != 0 {
		t.Errorf("device.sync.failed: %d, open %d", n, f.openOperations(t, a.id))
	}
	// No live instance ⇒ unavailable, nothing enqueued.
	f.exec(t, `UPDATE tenant_instances SET status = 'removed' WHERE id = $1`, f.b.instance)
	if _, err := f.api.RequestSync(sctx, f.b.id, acc, "sync-key-b"); !isCode(err, CodeInstanceUnavailable) {
		t.Errorf("tenant without instance: %v", err)
	}
}

// TestScheduler: the schedule notes each running instance on first sight, then enqueues one inventory.sync per
// instance and period, at the instance's own offset; a period already enqueued is not enqueued again.
func TestScheduler(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	sc := f.wrk.NewScheduler(SchedulerConfig{Interval: time.Minute, Tick: time.Second})
	t0 := time.Now()
	if n, err := sc.Tick(ctx, t0); err != nil || n != 0 {
		t.Fatalf("first tick: %d %v, want 0 (instances only noted)", n, err)
	}
	n, err := sc.Tick(ctx, t0.Add(time.Minute))
	if err != nil || n != 2 {
		t.Fatalf("tick after one interval: %d %v, want 2", n, err)
	}
	if n, err := sc.Tick(ctx, t0.Add(time.Minute)); err != nil || n != 0 {
		t.Errorf("tick again in the same period: %d %v, want 0", n, err)
	}
	for _, ten := range []*tenantFx{f.a, f.b} {
		slot := sc.slot(ten.instance, t0.Add(time.Minute))
		if c := count(t, f, `SELECT count(*) FROM provisioning_jobs WHERE kind = 'inventory.sync' AND tenant_id = $1
				AND instance_id = $2 AND dedupe_key = $3`, ten.id, ten.instance, fmt.Sprintf("instance:%s:sync:%d", ten.instance, slot)); c != 1 {
			t.Errorf("scheduled job of %s: %d, want 1", ten.slug, c)
		}
	}
}

// TestRevokeThroughWorker runs device.revoke under the real job framework (River, P2-T12): instance not answering ⇒
// the job retries with backoff (attempt counter grows, device stays pending), then runs out of attempts ⇒ job failed,
// device failed, the framework's alert reaches JobAlert; a whole-job timeout (handler never called again) ⇒ settled by
// JobAlert; the instance back ⇒ applied on the first attempt.
func TestRevokeThroughWorker(t *testing.T) {
	f, a, dev := revokeFixture(t)
	ctx := context.Background()
	cfg := jobs.DefaultConfig()
	cfg.FetchCooldown, cfg.FetchPollInterval = 10*time.Millisecond, 50*time.Millisecond
	cfg.RetryBase, cfg.RetryMax = 50*time.Millisecond, 200*time.Millisecond
	cfg.StartJitter, cfg.SoftStopTimeout = 0, 2*time.Second
	cfg.QueuePoolConns = 4
	k := cfg.Kinds[KindRevoke]
	k.MaxAttempts = 4
	cfg.Kinds[KindRevoke] = k
	alerts := &alertRecorder{next: f.wrk}
	w, err := jobs.NewWorker(f.wrkSt, cfg, jobs.Options{Alerter: alerts, Registerer: prometheus.NewRegistry()})
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

	// Out of attempts. MaxAttempts is fixed at enqueue time from the registry of the API process (8): 4 here comes
	// from the worker's registry, so set the job's own limit like a deployment that tuned it.
	a.hs.SetDown(true)
	res := f.revoke(t, a, dev, RevokeExpire, "")
	f.exec(t, `UPDATE provisioning_jobs SET max_attempts = 4 WHERE id = $1`, res.JobID)
	waitFor(t, 30*time.Second, "device failed", func() bool { return f.row(t, dev).RevocationState == StateFailed })
	var status string
	var attempt int
	waitFor(t, 10*time.Second, "job failed", func() bool {
		f.scan(t, `SELECT status, attempt FROM provisioning_jobs WHERE id = $1`, []any{res.JobID}, &status, &attempt)
		return status == jobs.StatusFailed
	})
	if attempt != 4 || a.hs.Calls(devicestest.OpGetNode) < 4 {
		t.Errorf("job failed after attempt %d (GetNode %d calls), want 4 attempts", attempt, a.hs.Calls(devicestest.OpGetNode))
	}
	waitFor(t, 10*time.Second, "alert", func() bool { return alerts.has(res.JobID, jobs.AlertFailed) })

	// Whole-job timeout: the framework ends the job before calling the handler again; JobAlert settles the device.
	second := f.revoke(t, a, dev, RevokeExpire, "")
	f.exec(t, `UPDATE provisioning_jobs SET max_attempts = 50 WHERE id = $1`, second.JobID)
	waitFor(t, 10*time.Second, "second job running", func() bool {
		f.scan(t, `SELECT status FROM provisioning_jobs WHERE id = $1`, []any{second.JobID}, &status)
		return status == jobs.StatusRunning
	})
	f.exec(t, `UPDATE provisioning_jobs SET timeout_at = now() - interval '1 second' WHERE id = $1`, second.JobID)
	waitFor(t, 30*time.Second, "device failed after the timeout", func() bool { return f.row(t, dev).RevocationState == StateFailed })
	if n := count(t, f, `SELECT count(*) FROM audit_events WHERE action = 'device.expire.failed' AND details ->> 'reason' = 'timeout'`); n != 1 {
		t.Errorf("failed event of the timed-out job: %d", n)
	}

	// Instance back: applied at the first attempt.
	a.hs.SetDown(false)
	third := f.revoke(t, a, dev, RevokeExpire, "")
	waitFor(t, 30*time.Second, "device applied", func() bool { return f.row(t, dev).RevocationState == StateApplied })
	waitFor(t, 10*time.Second, "job succeeded", func() bool {
		f.scan(t, `SELECT status, attempt FROM provisioning_jobs WHERE id = $1`, []any{third.JobID}, &status, &attempt)
		return status == jobs.StatusSucceeded
	})
	if attempt != 1 {
		t.Errorf("applied at attempt %d, want 1", attempt)
	}
	if f.openOperations(t, a.id) != 0 {
		t.Error("open audit operations left")
	}
}

// alertRecorder records the worker's alerts and forwards them to the devices service (the fan-out of P2-T16).
type alertRecorder struct {
	next *Service
	mu   sync.Mutex
	got  []jobs.Alert
}

func (r *alertRecorder) JobAlert(ctx context.Context, a jobs.Alert) {
	r.mu.Lock()
	r.got = append(r.got, a)
	r.mu.Unlock()
	r.next.JobAlert(ctx, a)
}

func (r *alertRecorder) has(job uuid.UUID, reason string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, a := range r.got {
		if a.JobID == job && a.Reason == reason && a.Kind == KindRevoke {
			return true
		}
	}
	return false
}

func waitFor(t *testing.T, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %s waiting for: %s", timeout, what)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestPlatformRolesCannotSeeDevices: the register is a T table — the platform pool has no privilege on it nor on the
// sync state (§6.1); the tenant pool of B sees none of A's rows (RLS).
func TestPlatformRolesCannotSeeDevices(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.a.hs.PutNode(userNode(f.a, 1, f.a.alice, f.a.aliceUser, time.Now(), nil))
	if _, err := f.wrk.Sync(ctx, f.a.id, f.a.instance); err != nil {
		t.Fatal(err)
	}
	err := f.apiSt.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		_, err := q.CountDevices(ctx, f.a.id)
		return err
	})
	if err == nil {
		t.Error("the platform pool read device_inventory_cache")
	}
	err = f.apiSt.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		_, err := q.GetDeviceSyncState(ctx, sqlcdb.GetDeviceSyncStateParams{TenantID: f.a.id, InstanceID: f.a.instance})
		return err
	})
	if err == nil {
		t.Error("the platform pool read device_inventory_sync_state")
	}
	err = f.apiSt.WithTenantTx(ctx, f.b.id, func(q *sqlcdb.Queries) error {
		c, err := q.CountDevices(ctx, f.a.id)
		if err == nil && c.Total != 0 {
			t.Errorf("tenant B's pool counts %d devices of A", c.Total)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}
