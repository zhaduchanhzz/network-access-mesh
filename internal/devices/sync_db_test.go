package devices

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/devices/devicestest"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// TestSyncNormalisesFromListNodes: every cache row comes from ListNodes (V-28) — owner of a user-owned node from its
// Headscale user, tagged node without owner but with its subnet routes; GetNode is never called by a sync; the sync
// state records generation and snapshot time.
func TestSyncNormalisesFromListNodes(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	a := f.a
	now := time.Now().UTC()
	a.hs.PutNode(userNode(a, 1, a.alice, a.aliceUser, now.Add(-time.Hour), tp(now.Add(24*time.Hour))))
	tagged := userNode(a, 2, a.bob, a.bobUser, now.Add(-time.Hour), nil)
	tagged.Tags = []string{"tag:server"}
	tagged.Available = []netip.Prefix{netip.MustParsePrefix("10.20.0.0/24")}
	tagged.Approved = []netip.Prefix{netip.MustParsePrefix("10.20.0.0/24")}
	tagged.Subnet = []netip.Prefix{netip.MustParsePrefix("10.20.0.0/24")}
	a.hs.PutNode(tagged)
	stranger := userNode(a, 3, uuid.New(), 99, now.Add(-time.Hour), tp(now.Add(time.Hour)))
	stranger.UserName = "someone-else"
	a.hs.PutNode(stranger)

	rep, err := f.wrk.Sync(ctx, a.id, a.instance)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Nodes != 3 || rep.Inserted != 3 || rep.Generation != 1 || rep.Stale {
		t.Fatalf("report %+v", rep)
	}
	if n := a.hs.Calls(devicestest.OpGetNode); n != 0 {
		t.Errorf("a sync called GetNode %d times; the register must be normalised from ListNodes only (V-28)", n)
	}
	d1, d2, d3 := f.row(t, f.deviceOfNode(t, a, 1)), f.row(t, f.deviceOfNode(t, a, 2)), f.row(t, f.deviceOfNode(t, a, 3))
	if d1.OwnerMembershipID == nil || *d1.OwnerMembershipID != a.alice || deref(d1.HeadscaleUserID) != int64(a.aliceUser) { //nolint:gosec // small test ids
		t.Errorf("user-owned node: owner %v user %v, want membership %s", d1.OwnerMembershipID, d1.HeadscaleUserID, a.alice)
	}
	if d2.OwnerMembershipID != nil || d2.HeadscaleUserID != nil || !slices.Equal(d2.Tags, []string{"tag:server"}) ||
		len(d2.SubnetRoutes) != 1 || d2.SubnetRoutes[0].String() != "10.20.0.0/24" {
		t.Errorf("tagged node: owner %v user %v tags %v subnet %v", d2.OwnerMembershipID, d2.HeadscaleUserID, d2.Tags, d2.SubnetRoutes)
	}
	if d3.OwnerMembershipID != nil {
		t.Errorf("node of a user the platform did not create: owner %v, want none", d3.OwnerMembershipID)
	}
	if deref(d1.RegisterMethod) != "authkey" || !d1.Online || len(d1.IpAddresses) != 1 || d1.SyncGeneration != 1 ||
		!d1.LastSyncedAt.Equal(rep.SyncedAt) {
		t.Errorf("columns of node 1: %+v (report synced_at %s)", d1, rep.SyncedAt)
	}
	sum, err := f.api.Summary(ctx, a.id)
	if err != nil || sum.Total != 3 || sum.Online != 3 || sum.SyncedAt == nil || !sum.SyncedAt.Equal(rep.SyncedAt) {
		t.Errorf("summary %+v %v", sum, err)
	}

	// The API view: no owner on a tagged node; owner display name from the identity.
	page, err := f.api.List(ctx, a.id, Access{}, ListQuery{})
	if err != nil || len(page.Items) != 3 {
		t.Fatalf("list: %v %d", err, len(page.Items))
	}
	if page.SyncedAt == nil || !page.SyncedAt.Equal(rep.SyncedAt) {
		t.Errorf("list synced_at %v, want the sync of the tenant %s", page.SyncedAt, rep.SyncedAt)
	}
	// An empty page (an End User with no device yet) still carries the tenant's last sync (G4b-E9).
	if empty, err := f.api.List(ctx, a.id, Access{OwnOnly: true, MembershipID: uuid.New()}, ListQuery{}); err != nil ||
		len(empty.Items) != 0 || empty.SyncedAt == nil || !empty.SyncedAt.Equal(rep.SyncedAt) {
		t.Errorf("empty own list: %d items, synced_at %v, %v; want the sync of the tenant", len(empty.Items), empty.SyncedAt, err)
	}
	// Tenant B was never synced: no synced_at at all.
	if pb, err := f.api.List(ctx, f.b.id, Access{}, ListQuery{}); err != nil || pb.SyncedAt != nil {
		t.Errorf("tenant B never synced: synced_at %v, %v", pb.SyncedAt, err)
	}
	for _, d := range page.Items {
		switch d.ID {
		case d1.ID:
			if d.Owner == nil || d.Owner.DisplayName != "Alice" || d.Owner.MembershipID != a.alice {
				t.Errorf("device of node 1: owner %+v", d.Owner)
			}
		case d2.ID:
			if d.Owner != nil || len(d.ApprovedRoutes) != 1 || d.RoutesETag == "" || d.TagsETag == "" {
				t.Errorf("tagged device: %+v", d)
			}
		}
	}

	// A tagged node keeps its platform owner (authoritative data) — ListNodes only says tagged-devices.
	f.exec(t, `UPDATE device_inventory_cache SET owner_membership_id = $1 WHERE id = $2`, a.bob, d2.ID)
	if _, err := f.wrk.Sync(ctx, a.id, a.instance); err != nil {
		t.Fatal(err)
	}
	if r := f.row(t, d2.ID); r.OwnerMembershipID == nil || *r.OwnerMembershipID != a.bob || r.SyncGeneration != 2 {
		t.Errorf("tagged node after a sync: owner %v generation %d, want kept owner and generation 2", r.OwnerMembershipID, r.SyncGeneration)
	}
	if n := count(t, f, `SELECT count(*) FROM device_inventory_cache WHERE tenant_id = $1`, f.b.id); n != 0 {
		t.Errorf("tenant B has %d rows after syncs of A", n)
	}
}

// TestSyncNodeIDReuse is the rule of §6.3: the same headscale_node_id with another machine key (after a restore the
// id counter goes back) is a new device — the old row gets removed_at, a new row with a new id is inserted.
func TestSyncNodeIDReuse(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	a := f.a
	now := time.Now().UTC()
	a.hs.PutNode(userNode(a, 5, a.alice, a.aliceUser, now.Add(-time.Hour), tp(now.Add(time.Hour))))
	if _, err := f.wrk.Sync(ctx, a.id, a.instance); err != nil {
		t.Fatal(err)
	}
	old := f.deviceOfNode(t, a, 5)
	other := userNode(a, 5, a.bob, a.bobUser, now, tp(now.Add(time.Hour)))
	other.MachineKey = "mkey:" + "another-machine"
	a.hs.PutNode(other)
	rep, err := f.wrk.Sync(ctx, a.id, a.instance)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Reused != 1 || rep.Inserted != 1 || rep.Removed != 1 {
		t.Errorf("report %+v, want reused 1, inserted 1, removed 1", rep)
	}
	fresh := f.deviceOfNode(t, a, 5)
	if fresh == old {
		t.Fatal("the reused node id kept the old device id")
	}
	if r := f.row(t, old); r.RemovedAt == nil || r.MachineKey == other.MachineKey {
		t.Errorf("old device: removed_at %v machine %s", r.RemovedAt, r.MachineKey)
	}
	if r := f.row(t, fresh); r.MachineKey != other.MachineKey || r.OwnerMembershipID == nil || *r.OwnerMembershipID != a.bob {
		t.Errorf("new device: %+v", r)
	}
	if n := count(t, f, `SELECT count(*) FROM device_inventory_cache WHERE instance_id = $1 AND headscale_node_id = 5`, a.instance); n != 2 {
		t.Errorf("%d rows for node 5, want 2 (old removed + new)", n)
	}
	if _, err := f.api.Get(ctx, a.id, old, Access{}); !isCode(err, CodeNotFound) {
		t.Errorf("GET of the replaced device: %v, want not_found", err)
	}
}

// TestSyncRemovedAndStale: a node absent from ListNodes is marked removed; a snapshot older than the last applied one
// is skipped entirely, and never resurrects a device removed after it was taken.
func TestSyncRemovedAndStale(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	a := f.a
	now := time.Now().UTC()
	n1 := userNode(a, 1, a.alice, a.aliceUser, now.Add(-time.Hour), tp(now.Add(time.Hour)))
	n2 := userNode(a, 2, a.bob, a.bobUser, now.Add(-time.Hour), tp(now.Add(time.Hour)))
	a.hs.PutNode(n1)
	a.hs.PutNode(n2)
	first, err := f.wrk.Sync(ctx, a.id, a.instance)
	if err != nil {
		t.Fatal(err)
	}
	d2 := f.deviceOfNode(t, a, 2)
	a.hs.RemoveNode(2)
	rep, err := f.wrk.Sync(ctx, a.id, a.instance)
	if err != nil || rep.Removed != 1 {
		t.Fatalf("sync after removal: %+v %v", rep, err)
	}
	if r := f.row(t, d2); r.RemovedAt == nil || r.Online {
		t.Errorf("removed device: %+v", r)
	}

	// An old snapshot (taken at the first sync, still listing node 2) arrives late: skipped, nothing changes.
	nodes := []headscale.Node{toNode(n1), toNode(n2)}
	var stale SyncReport
	clamps, _, err := f.wrk.apply(ctx, a.id, a.instance, first.SyncedAt, nodes, map[string]uuid.UUID{}, 0, &stale)
	if err != nil || !stale.Stale || len(clamps) != 0 {
		t.Fatalf("stale snapshot: %+v %v", stale, err)
	}
	if n := count(t, f, `SELECT count(*) FROM device_inventory_cache WHERE instance_id = $1 AND removed_at IS NULL`, a.instance); n != 1 {
		t.Errorf("live devices after a stale snapshot: %d, want 1", n)
	}
	// A snapshot newer than the last applied one but older than the removal of a device does not resurrect it.
	f.exec(t, `UPDATE device_inventory_sync_state SET synced_at = synced_at - interval '1 hour' WHERE instance_id = $1`, a.instance)
	var mid SyncReport
	before := f.row(t, d2).RemovedAt.Add(-time.Second)
	if _, _, err := f.wrk.apply(ctx, a.id, a.instance, before, nodes, map[string]uuid.UUID{}, 0, &mid); err != nil || mid.Stale {
		t.Fatalf("snapshot older than the removal: %+v %v", mid, err)
	}
	if n := count(t, f, `SELECT count(*) FROM device_inventory_cache WHERE instance_id = $1 AND headscale_node_id = 2
			AND removed_at IS NULL`, a.instance); n != 0 {
		t.Errorf("a snapshot older than the removal resurrected the device (%d live rows)", n)
	}
}

// TestSyncKeepsDevicesNewerThanSnapshot (B2): a row that entered the register after the snapshot time — a web-auth claim
// verified while the sync was listing (enrollment's InsertEnrolledDevice, first_seen_at = now()) — is neither marked
// removed because the snapshot lacks its node, nor replaced by the snapshot's node of the same id; the next sync (a
// newer snapshot) settles both.
func TestSyncKeepsDevicesNewerThanSnapshot(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	a := f.a
	now := time.Now().UTC()
	a.hs.PutNode(userNode(a, 1, a.alice, a.aliceUser, now.Add(-time.Hour), tp(now.Add(time.Hour))))
	if _, err := f.wrk.Sync(ctx, a.id, a.instance); err != nil {
		t.Fatal(err)
	}
	// node 9 is listed by the next snapshot; once ListNodes has answered, Headscale registers node 7 and node 9 is
	// deleted and its id handed out to another machine — two claims verify them (their rows, first seen now)
	n9 := userNode(a, 9, a.bob, a.bobUser, now.Add(-time.Hour), tp(now.Add(time.Hour)))
	a.hs.PutNode(n9)
	n7 := userNode(a, 7, a.alice, a.aliceUser, now, tp(now.Add(time.Hour)))
	const claimedKey = "mkey:" + "claimed-after-the-snapshot"
	var d7, d9 uuid.UUID
	a.hs.After(devicestest.OpListNodes, func(uint64) {
		f.scan(t, `INSERT INTO device_inventory_cache (tenant_id, instance_id, headscale_node_id, machine_key, name,
			owner_membership_id) VALUES ($1, $2, 7, $3, 'host-7', $4) RETURNING id`,
			[]any{a.id, a.instance, n7.MachineKey, a.alice}, &d7)
		f.scan(t, `INSERT INTO device_inventory_cache (tenant_id, instance_id, headscale_node_id, machine_key, name,
			owner_membership_id) VALUES ($1, $2, 9, $3, 'host-9', $4) RETURNING id`,
			[]any{a.id, a.instance, claimedKey, a.alice}, &d9)
	})
	rep, err := f.wrk.Sync(ctx, a.id, a.instance)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Removed != 0 || rep.Reused != 0 || rep.Inserted != 0 || rep.Updated != 1 {
		t.Errorf("snapshot older than two claimed devices: %+v, want only node 1 updated", rep)
	}
	if r := f.row(t, d7); r.RemovedAt != nil {
		t.Errorf("the device claimed after the snapshot was removed at %v", r.RemovedAt)
	}
	if r := f.row(t, d9); r.RemovedAt != nil || r.MachineKey != claimedKey {
		t.Errorf("the device claimed after the snapshot was replaced by the snapshot's node: %+v", r)
	}
	if n := count(t, f, `SELECT count(*) FROM device_inventory_cache WHERE instance_id = $1 AND headscale_node_id = 9`,
		a.instance); n != 1 {
		t.Errorf("%d rows for node 9, want the claimed one only", n)
	}
	// the next snapshot lists node 7 (the same device: same row, so the claim's enrollment link stays) and still node 9
	// of the other machine (§6.3: a new device)
	a.hs.PutNode(n7)
	if rep, err = f.wrk.Sync(ctx, a.id, a.instance); err != nil {
		t.Fatal(err)
	}
	if rep.Reused != 1 || rep.Inserted != 1 || rep.Removed != 1 {
		t.Errorf("next sync: %+v, want node 9 replaced", rep)
	}
	if r := f.row(t, d7); r.RemovedAt != nil || r.SyncGeneration != rep.Generation {
		t.Errorf("claimed device after the next sync: %+v", r)
	}
	if r := f.row(t, d9); r.RemovedAt == nil {
		t.Error("the next sync kept the device of the old machine key")
	}
}

// toNode is what the adapter decodes from a ListNodes entry of the fake (for direct calls of apply).
func toNode(n devicestest.Node) headscale.Node {
	u := &headscale.User{ID: n.UserID, Name: n.UserName}
	return headscale.Node{ID: n.ID, MachineKey: n.MachineKey, NodeKey: n.NodeKey, Name: n.Hostname, GivenName: n.GivenName,
		User: u, Tags: n.Tags, IPAddresses: n.IPs, RegisterMethod: headscale.RegisterMethod(n.Method), Online: n.Online,
		Expiry: n.Expiry, CreatedAt: n.CreatedAt}
}

// TestSyncClampsExpiry is §13.4 "Kẹp hạn node" / V-21 (ii) with the fake: a node whose client asked for 10 years is
// expired at registration + node_expiry at the next sync, with the audit pair (actor system) and a tenant security
// event expiry_overridden; a normal node, a legitimate re-auth and a tagged node are not touched; the source of the
// limit is TenantSettings.node_expiry, else the instance's rendered config, else nothing is clamped.
func TestSyncClampsExpiry(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	a := f.a
	now := time.Now().UTC().Truncate(time.Second)
	limit := 720 * time.Hour
	created := now.Add(-2 * time.Hour)
	f.setNodeExpiry(t, a, "720h")
	a.hs.PutNode(userNode(a, 1, a.alice, a.aliceUser, created, tp(created.Add(10*365*24*time.Hour)))) // V-21 override
	a.hs.PutNode(userNode(a, 2, a.bob, a.bobUser, created, tp(created.Add(limit))))                   // default expiry
	never := userNode(a, 3, a.bob, a.bobUser, created, nil)                                           // user node, no expiry
	a.hs.PutNode(never)
	tagged := userNode(a, 4, a.bob, a.bobUser, created, nil) // tagged nodes never expire on Headscale
	tagged.Tags = []string{"tag:ci"}
	a.hs.PutNode(tagged)

	rep, err := f.wrk.Sync(ctx, a.id, a.instance)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Clamped != 2 || rep.ClampFailed != 0 || rep.ClampSource != ClampSourceTenant || rep.ClampLimitHours != 720 {
		t.Fatalf("report %+v, want 2 clamped (override and no expiry) from tenant settings", rep)
	}
	want := created.Add(limit)
	for _, id := range []uint64{1, 3} {
		n, _ := a.hs.Node(id)
		if n.Expiry == nil || !n.Expiry.Equal(want) {
			t.Errorf("node %d on the instance: expiry %v, want %s", id, n.Expiry, want)
		}
		d := f.row(t, f.deviceOfNode(t, a, id))
		if d.Expiry == nil || !d.Expiry.Equal(want) {
			t.Errorf("device of node %d: cached expiry %v, want %s", id, d.Expiry, want)
		}
		got := f.auditOf(t, d.ID.String())
		if !slices.Equal(got, []string{"device.expiry_clamp.requested/success", "device.expiry_clamp.succeeded/success"}) {
			t.Errorf("audit of the clamp of node %d: %v", id, got)
		}
		if n := count(t, f, `SELECT count(*) FROM audit_events WHERE resource_id = $1 AND actor_type = 'system'
				AND actor_identity_id IS NULL AND tenant_id = $2`, d.ID.String(), a.id); n != 2 {
			t.Errorf("clamp events of node %d with actor system in tenant A: %d, want 2", id, n)
		}
		if n := count(t, f, `SELECT count(*) FROM security_events WHERE tenant_id = $1 AND kind = 'expiry_overridden'
				AND source = 'devices' AND details ->> 'device_id' = $2 AND (details ->> 'clamped')::boolean`, a.id, d.ID.String()); n != 1 {
			t.Errorf("security events expiry_overridden for node %d: %d, want 1", id, n)
		}
	}
	for _, id := range []uint64{2, 4} {
		if n, _ := a.hs.Node(id); id == 2 && !n.Expiry.Equal(created.Add(limit)) || id == 4 && n.Expiry != nil {
			t.Errorf("node %d was changed: expiry %v", id, n.Expiry)
		}
	}
	if n := a.hs.Calls(devicestest.OpExpireNode); n != 2 {
		t.Errorf("ExpireNode calls: %d, want 2", n)
	}

	// Next sync: nothing beyond the limit any more.
	a.hs.ResetCalls()
	if rep, err := f.wrk.Sync(ctx, a.id, a.instance); err != nil || rep.Clamped != 0 || a.hs.Calls(devicestest.OpExpireNode) != 0 {
		t.Errorf("second sync: %+v %v, ExpireNode %d", rep, err, a.hs.Calls(devicestest.OpExpireNode))
	}
	// A legitimate re-auth of an existing node (expiry = now + node_expiry) is never clamped.
	reauth := userNode(a, 2, a.bob, a.bobUser, created, tp(now.Add(limit)))
	a.hs.PutNode(reauth)
	if rep, err := f.wrk.Sync(ctx, a.id, a.instance); err != nil || rep.Clamped != 0 {
		t.Errorf("sync after a re-auth: %+v %v", rep, err)
	}
	// A re-auth asking for more than node_expiry is cut to at most now + node_expiry.
	a.hs.PutNode(userNode(a, 2, a.bob, a.bobUser, created, tp(now.Add(5*365*24*time.Hour))))
	rep, err = f.wrk.Sync(ctx, a.id, a.instance)
	if n, _ := a.hs.Node(2); err != nil || rep.Clamped != 1 || n.Expiry.After(time.Now().Add(limit)) {
		t.Errorf("re-auth override: %+v %v, expiry %v", rep, err, n.Expiry)
	}

	// Clamp refused by Headscale: audit .failed, security event clamped=false, reported.
	a.hs.PutNode(userNode(a, 7, a.alice, a.aliceUser, now, tp(now.Add(9*365*24*time.Hour))))
	a.hs.Refuse(devicestest.OpExpireNode, true)
	rep, err = f.wrk.Sync(ctx, a.id, a.instance)
	a.hs.Refuse(devicestest.OpExpireNode, false)
	if err != nil || rep.ClampFailed != 1 || rep.Clamped != 0 {
		t.Fatalf("refused clamp: %+v %v", rep, err)
	}
	d7 := f.deviceOfNode(t, a, 7)
	if got := f.auditOf(t, d7.String()); !slices.Equal(got, []string{"device.expiry_clamp.requested/success", "device.expiry_clamp.failed/failure"}) {
		t.Errorf("audit of a refused clamp: %v", got)
	}
	if n := count(t, f, `SELECT count(*) FROM security_events WHERE kind = 'expiry_overridden' AND details ->> 'device_id' = $1
			AND NOT (details ->> 'clamped')::boolean`, d7.String()); n != 1 {
		t.Errorf("security event of the refused clamp: %d", n)
	}
	// The next sync clamps it.
	if rep, err := f.wrk.Sync(ctx, a.id, a.instance); err != nil || rep.Clamped != 1 {
		t.Errorf("sync after the refusal: %+v %v", rep, err)
	}
	if f.openOperations(t, a.id) != 0 {
		t.Error("an audit operation of a clamp is left open")
	}

	// Source: the instance's rendered config when the tenant has no setting; nothing known ⇒ no clamp.
	f.setNodeExpiry(t, a, "")
	cfg := uuid.New()
	f.exec(t, `INSERT INTO instance_config_versions (id, tenant_id, instance_id, version, template_version, params, rendered_config, config_sha256)
		VALUES ($1, $2, $3, 1, 't1', '{"node_expiry": "48h"}', 'x', repeat('a', 64))`, cfg, a.id, a.instance)
	f.exec(t, `UPDATE tenant_instances SET config_version_id = $1 WHERE id = $2`, cfg, a.instance)
	a.hs.PutNode(userNode(a, 8, a.alice, a.aliceUser, now, tp(now.Add(30*24*time.Hour))))
	rep, err = f.wrk.Sync(ctx, a.id, a.instance)
	if n, _ := a.hs.Node(8); err != nil || rep.ClampSource != ClampSourceInstance || rep.Clamped < 1 || !n.Expiry.Equal(now.Add(48*time.Hour)) {
		t.Errorf("limit from the instance config: %+v %v, expiry %v", rep, err, n.Expiry)
	}
	f.exec(t, `UPDATE tenant_instances SET config_version_id = NULL WHERE id = $1`, a.instance)
	a.hs.PutNode(userNode(a, 9, a.alice, a.aliceUser, now, tp(now.Add(30*24*time.Hour))))
	if rep, err := f.wrk.Sync(ctx, a.id, a.instance); err != nil || rep.ClampSource != ClampSourceNone || rep.Clamped != 0 {
		t.Errorf("no limit known: %+v %v", rep, err)
	}
}

// TestSyncFailures: instance down ⇒ error of kind instance_unavailable and nothing written; instance replaced since
// the job was enqueued ⇒ conflict; tenant without instance ⇒ unavailable.
func TestSyncFailures(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	a := f.a
	a.hs.PutNode(userNode(a, 1, a.alice, a.aliceUser, time.Now(), nil))
	a.hs.SetDown(true)
	_, err := f.wrk.Sync(ctx, a.id, a.instance)
	if !isCode(err, CodeInstanceUnavailable) || !transient(err) {
		t.Errorf("instance down: %v, want transient instance_unavailable", err)
	}
	a.hs.SetDown(false)
	if n := count(t, f, `SELECT count(*) FROM device_inventory_cache`); n != 0 {
		t.Errorf("%d rows written by a failed sync", n)
	}
	if _, err := f.wrk.Sync(ctx, a.id, uuid.New()); !isCode(err, CodeConflict) {
		t.Errorf("another instance: %v, want conflict", err)
	}
	f.exec(t, `UPDATE tenant_instances SET status = 'removed' WHERE id = $1`, a.instance)
	if _, err := f.wrk.Sync(ctx, a.id, a.instance); !isCode(err, CodeInstanceUnavailable) {
		t.Errorf("no live instance: %v", err)
	}
}

func isCode(err error, code string) bool {
	if err == nil {
		return false
	}
	return fromAdapter(err).Code == code
}

// rowsOf lists the device ids of a tenant through the given service (its own role and RLS).
func rowsOf(t *testing.T, s *Service, tenant uuid.UUID) []uuid.UUID {
	t.Helper()
	var out []uuid.UUID
	err := s.st.WithTenantTx(context.Background(), tenant, func(q *sqlcdb.Queries) error {
		rows, err := q.ListDevicesPage(context.Background(), sqlcdb.ListDevicesPageParams{TenantID: tenant, RowLimit: 1000})
		for _, r := range rows {
			out = append(out, r.DeviceInventoryCache.ID)
		}
		return err
	})
	if err != nil && !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	return out
}
