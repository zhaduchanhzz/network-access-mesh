package enrollment

// Regression tests of four findings of the adversarial review of P4-T06 fixed on fu-p4b (PostgreSQL + the fake
// Headscale of the harness):
//   - C3: max_live_enrollment_credentials must hold while keys are still being created at Headscale (after the quota
//     transaction committed) — by a create (requested row) and by a /start (row still approved, tenant lock held);
//   - C9: a key reconcile settles consumed counts against max_devices at once (its node enters the inventory in the
//     same transaction), not only after the next inventory.sync;
//   - B1: an inventory row inventory.sync writes after its request ended still gets its enrollment link — the schedule
//     runs reconcile for it although the tenant has no open request;
//   - A3: a consumed reusable key that Headscale ended before its expiry (a device revocation expires it) stops counting
//     as a live credential (and as a tag reference): reconcile revokes it.

import (
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/devices/devicestest"
)

// within waits for ch at most d.
func within[T any](t *testing.T, ch <-chan T, d time.Duration, what string) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(d):
		t.Fatalf("%s: nothing after %s", what, d)
	}
	var zero T
	return zero
}

func TestReviewFindingsQuota(t *testing.T) {
	f := newFixture(t)
	a, b := f.a, f.b
	ctx := t.Context()

	t.Run("C3_InFlightCreateCounts", func(t *testing.T) {
		admin := b.actor("admin", uuid.New())
		kctx := ctxOf(admin, b.id, ActionKeyCreate)
		f.exec(t, `UPDATE subscriptions SET overrides = '{"max_live_enrollment_credentials": 1}' WHERE tenant_id = $1`, b.id)
		target := b.people["user"].membership
		entered, release := make(chan struct{}), make(chan struct{})
		free := sync.OnceFunc(func() { close(release) }) // a failing check never leaves the fake blocked
		defer free()
		b.hs.Before(devicestest.OpCreatePreAuthKey, func(uint64) { close(entered); <-release })
		first := make(chan error, 1)
		go func() {
			_, err := f.api.CreateKey(kctx, b.id, admin, NewKey{Target: &target}, idem("c3-1", "1"))
			first <- err
		}()
		within(t, entered, 30*time.Second, "first key at Headscale")
		// the first key is being created: its request is requested, without an expiry — it must count
		if st := f.str(t, `SELECT status FROM enrollment_requests WHERE tenant_id = $1`, b.id); st != StatusRequested {
			t.Fatalf("in-flight request status %s", st)
		}
		_, err := f.api.CreateKey(kctx, b.id, admin, NewKey{Target: &target}, idem("c3-2", "2"))
		free()
		if codeOf(err) != "quota_exceeded:enrollment_credentials" {
			t.Fatalf("second create while the first key is in flight: %v", err)
		}
		if err := within(t, first, 30*time.Second, "first create"); err != nil {
			t.Fatalf("first create: %v", err)
		}
		if n := len(b.hs.Keys()); n != 1 {
			t.Fatalf("%d keys at Headscale, want 1 (the limit)", n)
		}
	})

	t.Run("C3_StartHoldsTheLock", func(t *testing.T) {
		// an approved request being started: its key is in flight under the tenant's enrollment lock while the row is
		// still approved; a create waits for the lock, then counts the started key
		f.setting(t, a, "enrollment,requires_approval", "true")
		f.setting(t, a, "enrollment,self_enroll", "true")
		defer f.setting(t, a, "enrollment,requires_approval", "false")
		user := a.actor("user", uuid.New())
		req, err := f.api.Create(ctxOf(user, a.id, ActionRequest), a.id, user, NewRequest{Method: MethodPreauthKey}, idem("c3-s", "s"))
		if err != nil || req.Request.Status != StatusPendingApproval {
			t.Fatalf("pending: %+v %v", req.Request, err)
		}
		if _, err := f.api.Approve(ctx, a.id, req.Request.ID, a.actor("owner", uuid.New())); err != nil {
			t.Fatal(err)
		}
		f.exec(t, `UPDATE subscriptions SET overrides = '{"max_live_enrollment_credentials": 1}' WHERE tenant_id = $1`, a.id)
		entered, release := make(chan struct{}), make(chan struct{})
		free := sync.OnceFunc(func() { close(release) }) // a failing check never leaves the fake blocked
		defer free()
		a.hs.Before(devicestest.OpCreatePreAuthKey, func(uint64) { close(entered); <-release })
		started := make(chan error, 1)
		go func() {
			_, err := f.api.Start(ctxOf(user, a.id, ActionStart), a.id, req.Request.ID, user)
			started <- err
		}()
		within(t, entered, 30*time.Second, "started key at Headscale")
		admin := a.actor("admin", uuid.New())
		created := make(chan error, 1)
		go func() {
			_, err := f.api.CreateKey(ctxOf(admin, a.id, ActionKeyCreate), a.id, admin, NewKey{Tags: []string{"tag:server"}},
				idem("c3-k", "k"))
			created <- err
		}()
		select {
		case err := <-created:
			t.Fatalf("a create did not wait for the /start holding the enrollment lock: %v", err)
		case <-time.After(700 * time.Millisecond):
		}
		free()
		if err := within(t, started, 30*time.Second, "start"); err != nil {
			t.Fatalf("start: %v", err)
		}
		if err := within(t, created, 30*time.Second, "create"); codeOf(err) != "quota_exceeded:enrollment_credentials" {
			t.Fatalf("create after the started key: %v", err)
		}
	})

	t.Run("C9_ConsumedKeyCountsAsDevice", func(t *testing.T) {
		admin := b.actor("admin", uuid.New())
		kctx := ctxOf(admin, b.id, ActionKeyCreate)
		f.exec(t, `UPDATE subscriptions SET overrides = '{"max_live_enrollment_credentials": 50}' WHERE tenant_id = $1`, b.id)
		used := f.count(t, `SELECT (SELECT count(*) FROM device_inventory_cache WHERE tenant_id = $1 AND removed_at IS NULL) +
			(SELECT count(*) FROM enrollment_requests WHERE tenant_id = $1 AND status IN ('requested', 'pending_approval',
			'approved', 'awaiting_device', 'claimed', 'registered', 'credential_issued'))`, b.id)
		f.exec(t, `UPDATE subscriptions SET overrides = jsonb_build_object('max_devices', $2::int,
			'max_live_enrollment_credentials', 50) WHERE tenant_id = $1`, b.id, used+1)
		target := b.people["user2"].membership
		if _, err := f.api.CreateKey(kctx, b.id, admin, NewKey{Target: &target}, idem("c9-1", "1")); err != nil {
			t.Fatal(err)
		}
		keys := b.hs.Keys()
		b.hs.UseKey(keys[len(keys)-1].ID, devicestest.Node{MachineKey: "mkey:c9", Hostname: "c9-srv"})
		if _, err := f.api.CreateKey(kctx, b.id, admin, NewKey{Target: &target}, idem("c9-2", "2")); codeOf(err) != "quota_exceeded:devices" {
			t.Fatalf("before reconcile: %v", err)
		}
		// reconcile settles the key consumed: the request leaves the open count, the device enters the inventory in the
		// same transaction — the quota stays full (before the fix it had room until the next inventory.sync)
		if rep, err := f.wrk.Reconcile(ctx, b.id); err != nil || rep.Consumed < 1 {
			t.Fatalf("reconcile %+v %v", rep, err)
		}
		if _, err := f.api.CreateKey(kctx, b.id, admin, NewKey{Target: &target}, idem("c9-3", "3")); codeOf(err) != "quota_exceeded:devices" {
			t.Fatalf("after reconcile, before any inventory.sync: %v", err)
		}
	})
}

func TestReviewFindingsReconcile(t *testing.T) {
	f := newFixture(t)
	a, b := f.a, f.b
	ctx := t.Context()
	admin := a.actor("admin", uuid.New())
	kctx := ctxOf(admin, a.id, ActionKeyCreate)
	lastKey := func() uint64 { k := a.hs.Keys(); return k[len(k)-1].ID }

	t.Run("B1_LinkAfterRequestEnded", func(t *testing.T) {
		user := a.people["user"].membership
		k, err := f.api.CreateKey(kctx, a.id, admin, NewKey{Target: &user}, idem("b1-1", "1"))
		if err != nil {
			t.Fatal(err)
		}
		n := a.hs.UseKey(lastKey(), devicestest.Node{MachineKey: "mkey:b1", Hostname: "b1-srv"})
		// the inventory holds a stale row of this node id (another machine key): reconcile cannot adopt the node
		f.exec(t, `INSERT INTO device_inventory_cache (tenant_id, instance_id, headscale_node_id, machine_key, name)
			VALUES ($1, $2, $3, 'mkey:stale', 'old')`, a.id, a.instance, int64(n.ID)) //nolint:gosec // small test ids
		if rep, err := f.wrk.Reconcile(ctx, a.id); err != nil || rep.Consumed != 1 || rep.NewDevices != 0 || rep.Linked != 0 {
			t.Fatalf("reconcile %+v %v", rep, err)
		}
		// inventory.sync replaces the stale row after the request ended: a new row of the node, no link
		f.exec(t, `UPDATE device_inventory_cache SET removed_at = now() WHERE tenant_id = $1 AND machine_key = 'mkey:stale'`, a.id)
		f.exec(t, `INSERT INTO device_inventory_cache (tenant_id, instance_id, headscale_node_id, machine_key, name,
			owner_membership_id) VALUES ($1, $2, $3, $4, 'b1-srv', $5)`, a.id, a.instance, int64(n.ID), n.MachineKey, user) //nolint:gosec // small test ids
		if open := f.count(t, `SELECT count(*) FROM enrollment_requests WHERE tenant_id = $1 AND status NOT IN
			('consumed', 'verified', 'expired', 'revoked', 'failed', 'rejected')`, a.id); open != 0 {
			t.Fatalf("open requests %d", open)
		}
		jobsOf := func(ten uuid.UUID) int {
			return f.count(t, `SELECT count(*) FROM provisioning_jobs WHERE tenant_id = $1 AND kind = $2`, ten, KindReconcile)
		}
		sc := f.wrk.NewScheduler(SchedulerConfig{Interval: time.Minute})
		now := time.Now()
		if _, err := sc.Tick(ctx, now); err != nil {
			t.Fatal(err)
		}
		if _, err := sc.Tick(ctx, now.Add(2*time.Minute)); err != nil {
			t.Fatal(err)
		}
		if jobsOf(a.id) != 1 || jobsOf(b.id) != 0 {
			t.Fatalf("reconcile jobs A %d (the row waiting for its link), B %d", jobsOf(a.id), jobsOf(b.id))
		}
		rep, err := f.wrk.Reconcile(ctx, a.id)
		if err != nil || rep.Linked != 1 || rep.NewDevices != 1 {
			t.Fatalf("reconcile after sync %+v %v", rep, err)
		}
		var dev uuid.UUID
		f.scan(t, `SELECT id FROM device_inventory_cache WHERE tenant_id = $1 AND enrollment_request_id = $2 AND removed_at IS NULL`,
			[]any{a.id, k.Request.ID}, &dev)
		if got := f.deviceNew(t, a, dev); !slices.Equal(got, sortedIDs(user, a.people["owner"].membership)) {
			t.Fatalf("device.new recipients %v", got)
		}
		if rep, err := f.wrk.Reconcile(ctx, a.id); err != nil || rep.Linked != 0 || rep.NewDevices != 0 {
			t.Fatalf("again %+v %v", rep, err)
		}
		// linked: nothing left to schedule
		if _, err := sc.Tick(ctx, now.Add(4*time.Minute)); err != nil {
			t.Fatal(err)
		}
		if jobsOf(a.id) != 1 {
			t.Fatalf("reconcile scheduled with nothing to do: %d jobs", jobsOf(a.id))
		}
	})

	t.Run("A3_ReusableKeyEndedByDeviceRevocation", func(t *testing.T) {
		f.exec(t, `UPDATE subscriptions SET overrides = '{"max_live_enrollment_credentials": 1}' WHERE tenant_id = $1`, a.id)
		k, err := f.api.CreateKey(kctx, a.id, admin, NewKey{Tags: []string{"tag:server"}, Reusable: true}, idem("a3-1", "1"))
		if err != nil {
			t.Fatal(err)
		}
		kid := lastKey()
		a.hs.UseKey(kid, devicestest.Node{MachineKey: "mkey:a3", Hostname: "ci-a3"})
		if rep, err := f.wrk.Reconcile(ctx, a.id); err != nil || rep.Consumed != 1 || rep.Revoked != 0 {
			t.Fatalf("reconcile %+v %v", rep, err)
		}
		// the consumed reusable key is still live: the one credential of the plan is taken
		if _, err := f.api.CreateKey(kctx, a.id, admin, NewKey{Tags: []string{"tag:server"}}, idem("a3-2", "2")); codeOf(err) != "quota_exceeded:enrollment_credentials" {
			t.Fatalf("while the reusable key is live: %v", err)
		}
		// the device is revoked: devices.expireKeys expires the node's key at Headscale, long before its own expiry
		hk := a.hs.Key(kid)
		hk.Expiration = f.clk.now().Add(-time.Second)
		a.hs.PutKey(hk)
		rep, err := f.wrk.Reconcile(ctx, a.id)
		if err != nil || rep.Revoked != 1 {
			t.Fatalf("reconcile after the revocation %+v %v", rep, err)
		}
		if st := f.str(t, `SELECT status FROM enrollment_requests WHERE id = $1`, k.Request.ID); st != StatusRevoked {
			t.Fatalf("status %s", st)
		}
		if got := f.auditOf(t, k.Request.ID.String()); !slices.Contains(got, "enrollment.revoke/success") {
			t.Fatalf("audit %v", got)
		}
		// the credential is gone: a new key fits again; the tag is no longer referenced by the request
		if _, err := f.api.CreateKey(kctx, a.id, admin, NewKey{Tags: []string{"tag:server"}, Reusable: true}, idem("a3-3", "3")); err != nil {
			t.Fatalf("after the revocation: %v", err)
		}
		if n := f.count(t, `SELECT count(*) FROM enrollment_requests WHERE id = $1 AND 'tag:server' = ANY (requested_tags)
			AND (status IN ('requested', 'pending_approval', 'approved', 'credential_issued')
			     OR (status = 'consumed' AND reusable AND credential_expires_at > now()))`, k.Request.ID); n != 0 {
			t.Fatal("the revoked request still references its tag")
		}
		// a reusable key that simply reached its expiry stays consumed (no revocation)
		kid2 := lastKey()
		a.hs.UseKey(kid2, devicestest.Node{MachineKey: "mkey:a3b", Hostname: "ci-a3b"})
		if rep, err := f.wrk.Reconcile(ctx, a.id); err != nil || rep.Consumed != 1 {
			t.Fatalf("second key consumed %+v %v", rep, err)
		}
		f.clk.advance(16 * time.Minute)
		if rep, err := f.wrk.Reconcile(ctx, a.id); err != nil || rep.Revoked != 0 {
			t.Fatalf("after the natural expiry %+v %v", rep, err)
		}
		if n := f.count(t, `SELECT count(*) FROM enrollment_requests WHERE tenant_id = $1 AND status = 'consumed' AND reusable`, a.id); n != 1 {
			t.Fatalf("consumed reusable keys %d, want 1", n)
		}
	})
}
