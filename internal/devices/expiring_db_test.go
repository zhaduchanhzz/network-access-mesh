package devices

import (
	"context"
	"testing"
	"time"
)

// TestExpiryNotices (P3-T05b): after a sync, a user-owned device whose key expires within the notice window notifies
// its owner exactly once per expiry (a second pass writes nothing); a device beyond the window, a removed one and one
// being revoked are not notified; the notices belong to the device's tenant only.
func TestExpiryNotices(t *testing.T) {
	f := newFixture(t)
	a, b := f.a, f.b
	ctx := context.Background()
	now := time.Now().UTC()
	a.hs.PutNode(userNode(a, 1, a.alice, a.aliceUser, now.Add(-time.Hour), tp(now.Add(48*time.Hour)))) // within 7 days
	a.hs.PutNode(userNode(a, 2, a.bob, a.bobUser, now.Add(-time.Hour), tp(now.Add(30*24*time.Hour))))  // beyond
	a.hs.PutNode(userNode(a, 3, a.bob, a.bobUser, now.Add(-time.Hour), tp(now.Add(72*time.Hour))))     // revoked below
	b.hs.PutNode(userNode(b, 1, b.alice, b.aliceUser, now.Add(-time.Hour), tp(now.Add(24*time.Hour)))) // tenant B
	for _, ten := range []*tenantFx{a, b} {
		if _, err := f.wrk.Sync(ctx, ten.id, ten.instance); err != nil {
			t.Fatal(err)
		}
	}
	f.exec(t, `UPDATE device_inventory_cache SET revocation_state = 'pending' WHERE id = $1`, f.deviceOfNode(t, a, 3))
	n, err := f.wrk.notifyExpiring(ctx, a.id, a.instance)
	if err != nil || n != 1 {
		t.Fatalf("first pass: %d %v", n, err)
	}
	dev := f.deviceOfNode(t, a, 1)
	if got := count(t, f, `SELECT count(*) FROM notification_outbox WHERE tenant_id = $1 AND kind = 'device.expiring'
		AND recipient_membership_id = $2 AND payload ->> 'device_id' = $3 AND payload ->> 'device_name' = 'host-1'`,
		a.id, a.alice, dev.String()); got != 1 {
		t.Fatalf("alice's notice: %d", got)
	}
	if got := count(t, f, `SELECT count(*) FROM notification_outbox WHERE kind = 'device.expiring'`); got != 1 {
		t.Fatalf("notices in total: %d", got)
	}
	if n, err := f.wrk.notifyExpiring(ctx, a.id, a.instance); err != nil || n != 0 {
		t.Fatalf("second pass: %d %v", n, err)
	}
	if got := count(t, f, `SELECT count(*) FROM notification_outbox WHERE kind = 'device.expiring'`); got != 1 {
		t.Fatalf("a second pass notified again: %d", got)
	}
	// A new expiry (the node re-authenticated) is a new notice.
	f.exec(t, `UPDATE device_inventory_cache SET expiry = expiry + interval '1 hour' WHERE id = $1`, dev)
	if n, err := f.wrk.notifyExpiring(ctx, a.id, a.instance); err != nil || n != 1 {
		t.Fatalf("new expiry: %d %v", n, err)
	}
	// Tenant B's sweep sees only B.
	if n, err := f.wrk.notifyExpiring(ctx, b.id, b.instance); err != nil || n != 1 {
		t.Fatalf("tenant B: %d %v", n, err)
	}
	if got := count(t, f, `SELECT count(*) FROM notification_outbox WHERE tenant_id = $1 AND recipient_membership_id = $2`,
		b.id, b.alice); got != 1 {
		t.Fatal("tenant B's notice")
	}
}
