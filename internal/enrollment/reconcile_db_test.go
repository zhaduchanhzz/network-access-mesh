package enrollment

// Regression tests of enrollment.reconcile from the integration of the Phase 4 review fixes (PostgreSQL + fake
// Headscale through the real adapter):
//   - A2 (second part): a tenant that is not active has no reachable instance by design — reconcile leaves the rows that
//     need Headscale for a run after its resumption and does not fail (the job is not retried every run);
//   - A6 (third point): the order of production — the key is used, reconcile runs BEFORE inventory.sync and the real
//     inventory.sync (internal/devices) writes the node's row after it — still leaves the device linked once.

import (
	"errors"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/devices"
	"github.com/zhaduchanhzz/network-access-mesh/internal/devices/devicestest"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
)

// TestReconcileInactiveTenant (A2): the locator refuses the instance of a tenant that is not active
// (headscale.ErrNoInstance). While the tenant is active that is a failure the job retries; once it is suspended, the
// issued keys wait (Skipped) and the run succeeds — the schedule keeps enqueueing it, the job no longer fails every run
// of the suspension. What needs no Headscale still converges; after the resumption the key is reconciled.
func TestReconcileInactiveTenant(t *testing.T) {
	f := newFixture(t)
	a := f.a
	ctx := t.Context()
	admin := a.actor("admin", uuid.New())
	out, err := f.api.CreateKey(ctxOf(admin, a.id, ActionKeyCreate), a.id, admin, NewKey{Tags: []string{"tag:server"}},
		idem("a2-1", "1"))
	if err != nil {
		t.Fatal(err)
	}
	// a request waiting for a decision past its window: expired without Headscale
	f.setting(t, a, "enrollment,self_enroll", "true")
	f.setting(t, a, "enrollment,requires_approval", "true")
	user := a.actor("user", uuid.New())
	waiting, err := f.api.Create(ctxOf(user, a.id, ActionRequest), a.id, user, NewRequest{Method: MethodPreauthKey},
		idem("a2-2", "2"))
	if err != nil || waiting.Request.Status != StatusPendingApproval {
		t.Fatalf("pending request: %+v %v", waiting.Request, err)
	}
	f.exec(t, `UPDATE enrollment_requests SET created_at = created_at - interval '25 hours' WHERE id = $1`, waiting.Request.ID)
	// the worker's registry no longer locates tenant A — what the locator answers for a tenant that is not active
	wrk, err := New(f.wrkSt, Config{Registry: devicestest.Registry(map[uuid.UUID]headscale.Target{
		f.b.id: f.b.hs.Target(f.b.instance)}), Now: f.clk.now})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrk.Reconcile(ctx, a.id); !errors.Is(err, headscale.ErrNoInstance) {
		t.Fatalf("active tenant without a located instance: %v, want an error wrapping ErrNoInstance (retried)", err)
	}
	f.exec(t, `UPDATE tenants SET status = 'suspended' WHERE id = $1`, a.id)
	rep, err := wrk.Reconcile(ctx, a.id)
	if err != nil || !rep.Inactive || rep.Skipped != 1 {
		t.Fatalf("suspended tenant: %+v %v, want no error, inactive, 1 skipped", rep, err)
	}
	status := func(id uuid.UUID) string {
		return f.str(t, `SELECT status FROM enrollment_requests WHERE id = $1`, id)
	}
	if st := status(out.Request.ID); st != StatusCredentialIssued {
		t.Fatalf("issued key of the suspended tenant: %s, want left for a run after the resumption", st)
	}
	if st := status(waiting.Request.ID); st != StatusExpired {
		t.Fatalf("decision window past: %s, want expired (no Headscale needed)", st)
	}
	// the job of the schedule: done, not a transient failure
	sc := wrk.NewScheduler(SchedulerConfig{Interval: time.Minute})
	now := time.Now()
	if _, err := sc.Tick(ctx, now); err != nil {
		t.Fatal(err)
	}
	if _, err := sc.Tick(ctx, now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	var id uuid.UUID
	f.scan(t, `SELECT id FROM provisioning_jobs WHERE kind = $1 AND tenant_id = $2 LIMIT 1`, []any{KindReconcile, a.id}, &id)
	run := &jobs.Run{ID: id, Kind: KindReconcile, TenantID: &a.id, Input: []byte(`{}`), Attempt: 1, MaxAttempts: 3,
		Deadline: time.Now().Add(time.Minute), Store: f.wrkSt}
	if err := wrk.runReconcile(ctx, run); err != nil {
		t.Fatalf("job of a suspended tenant: %v, want done", err)
	}
	// resumed: the key is reconciled (used ⇒ consumed with its node)
	f.exec(t, `UPDATE tenants SET status = 'active' WHERE id = $1`, a.id)
	keys := a.hs.Keys()
	node := a.hs.UseKey(keys[len(keys)-1].ID, devicestest.Node{MachineKey: "mkey:a2", Hostname: "a2-srv"})
	if rep, err := f.wrk.Reconcile(ctx, a.id); err != nil || rep.Consumed != 1 || rep.Inactive {
		t.Fatalf("after the resumption %+v %v", rep, err)
	}
	if got := f.str(t, `SELECT status || '/' || consumed_node_id::text FROM enrollment_requests WHERE id = $1`,
		out.Request.ID); got != StatusConsumed+"/"+uintText(node.ID) {
		t.Fatalf("after the resumption: %s", got)
	}
}

// TestPreauthKeyRealOrder (A6, third point): in production the key is used, enrollment.reconcile runs (every 2
// minutes) and inventory.sync — the real one here, internal/devices, against the same fake Headscale — runs after it.
//   - ReconcileThenSync: the consumed transition brings the node into the inventory with its link (C9); the sync that
//     follows keeps that row: one live row, linked, device.new once.
//   - StaleRowThenSync: the transition cannot adopt the node (the inventory holds a stale row of its id — a node id
//     handed out again); the sync replaces that row after the request ended, the schedule runs reconcile for the row
//     waiting for its link although the tenant has no open request (B1), and that run links it, device.new once.
func TestPreauthKeyRealOrder(t *testing.T) {
	f := newFixture(t)
	a := f.a
	ctx := t.Context()
	admin := a.actor("admin", uuid.New())
	user := a.people["user"].membership
	reg := devicestest.Registry(map[uuid.UUID]headscale.Target{f.a.id: f.a.hs.Target(f.a.instance),
		f.b.id: f.b.hs.Target(f.b.instance)})
	inv, err := devices.New(f.wrkSt, devices.Config{Registry: reg, Now: f.clk.now, ExpiryNotice: -1})
	if err != nil {
		t.Fatal(err)
	}
	sync := func(t *testing.T) {
		t.Helper()
		if _, err := inv.Sync(ctx, a.id, a.instance); err != nil {
			t.Fatalf("inventory.sync: %v", err)
		}
	}
	lastKey := func() uint64 { k := a.hs.Keys(); return k[len(k)-1].ID }
	rowsOf := func(t *testing.T, node uint64) []string { // live rows of a node: machine key / link
		t.Helper()
		return f.list(t, `SELECT machine_key || '/' || COALESCE(enrollment_request_id::text, '') FROM device_inventory_cache
			WHERE tenant_id = $1 AND headscale_node_id = $2 AND removed_at IS NULL ORDER BY 1`, a.id, int64(node)) //nolint:gosec // small test ids
	}
	device := func(t *testing.T, req uuid.UUID) uuid.UUID {
		t.Helper()
		var dev uuid.UUID
		f.scan(t, `SELECT id FROM device_inventory_cache WHERE tenant_id = $1 AND enrollment_request_id = $2
			AND removed_at IS NULL`, []any{a.id, req}, &dev)
		return dev
	}
	recipients := sortedIDs(user, a.people["owner"].membership)

	t.Run("ReconcileThenSync", func(t *testing.T) {
		k, err := f.api.CreateKey(ctxOf(admin, a.id, ActionKeyCreate), a.id, admin, NewKey{Target: &user},
			idem("ro-1", "1"))
		if err != nil {
			t.Fatal(err)
		}
		n := a.hs.UseKey(lastKey(), devicestest.Node{MachineKey: "mkey:ro-1", Hostname: "ro-1"})
		if got := rowsOf(t, n.ID); len(got) != 0 {
			t.Fatalf("rows before reconcile %v", got)
		}
		rep, err := f.wrk.Reconcile(ctx, a.id) // before any inventory.sync
		if err != nil || rep.Consumed != 1 || rep.NewDevices != 1 {
			t.Fatalf("reconcile %+v %v", rep, err)
		}
		sync(t) // inventory.sync after the consumed transition lists the node and meets its row
		want := []string{n.MachineKey + "/" + k.Request.ID.String()}
		if got := rowsOf(t, n.ID); !slices.Equal(got, want) {
			t.Fatalf("rows after inventory.sync %v, want %v", got, want)
		}
		if got := f.deviceNew(t, a, device(t, k.Request.ID)); !slices.Equal(got, recipients) {
			t.Fatalf("device.new recipients %v, want %v", got, recipients)
		}
		if rep, err := f.wrk.Reconcile(ctx, a.id); err != nil || rep.Linked != 0 || rep.NewDevices != 0 {
			t.Fatalf("reconcile again %+v %v", rep, err)
		}
		sync(t)
		if got := rowsOf(t, n.ID); !slices.Equal(got, want) {
			t.Fatalf("rows after a second inventory.sync %v, want %v", got, want)
		}
	})

	t.Run("StaleRowThenSync", func(t *testing.T) {
		k, err := f.api.CreateKey(ctxOf(admin, a.id, ActionKeyCreate), a.id, admin, NewKey{Target: &user},
			idem("ro-2", "2"))
		if err != nil {
			t.Fatal(err)
		}
		n := a.hs.UseKey(lastKey(), devicestest.Node{MachineKey: "mkey:ro-2", Hostname: "ro-2"})
		// the inventory holds a stale row of this node id (another machine key): the transition cannot adopt the node
		f.exec(t, `INSERT INTO device_inventory_cache (tenant_id, instance_id, headscale_node_id, machine_key, name)
			VALUES ($1, $2, $3, 'mkey:ro-stale', 'old')`, a.id, a.instance, int64(n.ID)) //nolint:gosec // small test ids
		if rep, err := f.wrk.Reconcile(ctx, a.id); err != nil || rep.Consumed != 1 || rep.NewDevices != 0 {
			t.Fatalf("reconcile %+v %v", rep, err)
		}
		sync(t) // after the request ended: the stale row is replaced by a row of the node, without link
		if got := rowsOf(t, n.ID); !slices.Equal(got, []string{n.MachineKey + "/"}) {
			t.Fatalf("rows after inventory.sync %v", got)
		}
		if open := f.count(t, `SELECT count(*) FROM enrollment_requests WHERE tenant_id = $1 AND status NOT IN
			('consumed', 'verified', 'expired', 'revoked', 'failed', 'rejected')`, a.id); open != 0 {
			t.Fatalf("open requests %d", open)
		}
		jobsOf := func() int {
			return f.count(t, `SELECT count(*) FROM provisioning_jobs WHERE tenant_id = $1 AND kind = $2`, a.id, KindReconcile)
		}
		before := jobsOf()
		sc := f.wrk.NewScheduler(SchedulerConfig{Interval: time.Minute})
		now := time.Now()
		if _, err := sc.Tick(ctx, now); err != nil {
			t.Fatal(err)
		}
		if _, err := sc.Tick(ctx, now.Add(2*time.Minute)); err != nil {
			t.Fatal(err)
		}
		if got := jobsOf(); got != before+1 {
			t.Fatalf("reconcile jobs %d → %d: the row waiting for its link must be scheduled", before, got)
		}
		rep, err := f.wrk.Reconcile(ctx, a.id) // the scheduled run
		if err != nil || rep.Linked != 1 || rep.NewDevices != 1 {
			t.Fatalf("scheduled reconcile %+v %v", rep, err)
		}
		if got := rowsOf(t, n.ID); !slices.Equal(got, []string{n.MachineKey + "/" + k.Request.ID.String()}) {
			t.Fatalf("rows after the scheduled reconcile %v", got)
		}
		if got := f.deviceNew(t, a, device(t, k.Request.ID)); !slices.Equal(got, recipients) {
			t.Fatalf("device.new recipients %v, want %v", got, recipients)
		}
		sync(t)
		if rep, err := f.wrk.Reconcile(ctx, a.id); err != nil || rep.Linked != 0 || rep.NewDevices != 0 {
			t.Fatalf("reconcile again %+v %v", rep, err)
		}
		if got := rowsOf(t, n.ID); !slices.Equal(got, []string{n.MachineKey + "/" + k.Request.ID.String()}) {
			t.Fatalf("rows after another inventory.sync %v", got)
		}
	})
}

// uintText is the decimal text of a node id (as PostgreSQL prints a bigint).
func uintText(id uint64) string { return strconv.FormatUint(id, 10) }

// TestReusableKeyIDHandedOutAgain (A4 on the live reusable keys of fu-p4b): after a restore of an older snapshot the id
// of a consumed reusable key is handed out again to a key of another member, which registers a node. Reconcile never
// adopts that node with the link of the old request (issuedKey: not its key), and the old request's own key is gone —
// revoked, no live credential any more.
func TestReusableKeyIDHandedOutAgain(t *testing.T) {
	f := newFixture(t)
	a := f.a
	ctx := t.Context()
	admin := a.actor("admin", uuid.New())
	user := a.people["user"].membership
	out, err := f.api.CreateKey(ctxOf(admin, a.id, ActionKeyCreate), a.id, admin, NewKey{Target: &user, Reusable: true},
		idem("a4-1", "1"))
	if err != nil {
		t.Fatal(err)
	}
	keys := a.hs.Keys()
	k := keys[len(keys)-1]
	first := a.hs.UseKey(k.ID, devicestest.Node{MachineKey: "mkey:a4-first", Hostname: "a4-first"})
	if rep, err := f.wrk.Reconcile(ctx, a.id); err != nil || rep.Consumed != 1 || rep.NewDevices != 1 {
		t.Fatalf("reconcile %+v %v", rep, err)
	}
	// the restore lost the key and its node; the id goes to a key of another member, which registers a node
	a.hs.RemoveNode(first.ID)
	other := a.people["user2"].membership
	a.hs.PutKey(devicestest.Key{ID: k.ID, UserID: 4242, UserName: "mg-" + other.String(), Reusable: true,
		Expiration: time.Now().Add(10 * time.Minute)})
	later := a.hs.UseKey(k.ID, devicestest.Node{MachineKey: "mkey:a4-later", Hostname: "a4-later"})
	rep, err := f.wrk.Reconcile(ctx, a.id)
	if err != nil || rep.NewDevices != 0 || rep.Revoked != 1 {
		t.Fatalf("reconcile after the id was handed out again %+v %v", rep, err)
	}
	if n := f.count(t, `SELECT count(*) FROM device_inventory_cache WHERE tenant_id = $1 AND headscale_node_id = $2`,
		a.id, int64(later.ID)); n != 0 { //nolint:gosec // small test ids
		t.Fatalf("the node of the other member's key entered the inventory with the old request (%d rows)", n)
	}
	if st := f.str(t, `SELECT status FROM enrollment_requests WHERE id = $1`, out.Request.ID); st != StatusRevoked {
		t.Fatalf("status %s, want revoked (its key is gone)", st)
	}
}
