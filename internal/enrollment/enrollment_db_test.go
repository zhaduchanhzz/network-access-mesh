package enrollment

import (
	"context"
	"crypto/sha256"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/devices/devicestest"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
)

func idem(key, body string) *Idempotency {
	h := sha256.Sum256([]byte(body))
	return &Idempotency{Key: key, Hash: h[:]}
}

func TestEnrollment(t *testing.T) {
	f := newFixture(t)
	a := f.a

	t.Run("PreauthKeyOwnDevice", func(t *testing.T) {
		sess := uuid.New()
		user := a.actor("user", sess)
		ctx := ctxOf(user, a.id, ActionRequest)
		// End User without self-enrolment: refused before anything is written (condition self_enroll, §8.6)
		_, err := f.api.Create(ctx, a.id, user, NewRequest{Method: MethodPreauthKey}, idem("k-eu-0", "a"))
		if codeOf(err) != CodeForbidden || reasonOf(err) != "self_enroll_disabled" {
			t.Fatalf("self-enrol off: %v", err)
		}
		f.setting(t, a, "enrollment,self_enroll", "true")
		label := "laptop-1"
		out, err := f.api.Create(ctx, a.id, user, NewRequest{Method: MethodPreauthKey, DeviceLabel: &label, TTLMinutes: 3},
			idem("k-eu-1", "b"))
		if err != nil {
			t.Fatal(err)
		}
		c := out.Credential
		if c == nil || c.Kind != CredentialPreauthKey || !strings.HasPrefix(c.PreauthKey.Reveal(), "hskey-auth-") ||
			strings.Contains(c.Command, c.PreauthKey.Reveal()) || out.Request.Status != StatusIssued {
			t.Fatalf("issue: %+v", out)
		}
		keys := a.hs.Keys()
		k := keys[len(keys)-1]
		if k.Reusable || k.UserName != un(user) || k.Used || len(k.Tags) != 0 ||
			k.Expiration.Sub(f.clk.now()) > 3*time.Minute+5*time.Second || k.Expiration.Sub(f.clk.now()) < 2*time.Minute {
			t.Fatalf("key at Headscale: %+v", k)
		}
		if a.hs.FullKey(k.ID) != c.PreauthKey.Reveal() {
			t.Fatal("the key shown is not the key Headscale issued")
		}
		if got := f.auditOf(t, out.Request.ID.String()); joined(got) != "enrollment.request.requested/success,enrollment.request.succeeded/success" {
			t.Fatalf("audit %v", got)
		}
		// replay of the same Idempotency-Key: the same key from the Vault; another body ⇒ 422 reuse
		again, err := f.api.Create(ctx, a.id, user, NewRequest{Method: MethodPreauthKey, DeviceLabel: &label, TTLMinutes: 3},
			idem("k-eu-1", "b"))
		if err != nil || again.Request.ID != out.Request.ID || again.Credential.PreauthKey.Reveal() != c.PreauthKey.Reveal() {
			t.Fatalf("replay: %v %+v", err, again.Request)
		}
		if _, err := f.api.Create(ctx, a.id, user, NewRequest{Method: MethodWebAuth}, idem("k-eu-1", "other")); codeOf(err) != CodeIdempotencyReuse {
			t.Fatalf("reuse: %v", err)
		}
		if n := len(a.hs.Keys()); n != len(keys) {
			t.Fatalf("a replay issued another key: %d keys", n)
		}
		// after the credential's TTL the replay cannot show the key again: 410
		f.clk.advance(4 * time.Minute)
		if _, err := f.api.Create(ctx, a.id, user, NewRequest{Method: MethodPreauthKey, DeviceLabel: &label, TTLMinutes: 3},
			idem("k-eu-1", "b")); codeOf(err) != CodeSecretGone {
			t.Fatalf("replay after TTL: %v", err)
		}
		// reconcile: the key expired unused ⇒ expired
		rep, err := f.wrk.Reconcile(t.Context(), a.id)
		if err != nil || rep.Expired < 1 {
			t.Fatalf("reconcile %+v %v", rep, err)
		}
		if st := f.str(t, `SELECT status FROM enrollment_requests WHERE id = $1`, out.Request.ID); st != StatusExpired {
			t.Fatalf("status %s", st)
		}
		f.noKeyMaterial(t)
	})

	t.Run("KeyConsumedAndTTLBound", func(t *testing.T) {
		f.setting(t, a, "enrollment,preauth_key_ttl_max", `"5m"`)
		owner := a.actor("owner", uuid.New())
		out, err := f.api.Create(ctxOf(owner, a.id, ActionRequest), a.id, owner, NewRequest{Method: MethodPreauthKey}, idem("k-o-1", "x"))
		if err != nil {
			t.Fatal(err)
		}
		ttl := out.Credential.ExpiresAt.Sub(*out.Request.IssuedAt)
		if ttl != 5*time.Minute {
			t.Fatalf("ttl %s, want the tenant's bound 5m", ttl)
		}
		f.setting(t, a, "enrollment,preauth_key_ttl_max", `""`)
		keys := a.hs.Keys()
		node := a.hs.UseKey(keys[len(keys)-1].ID, devicestest.Node{MachineKey: "mkey:consumed", Hostname: "srv-1"})
		f.exec(t, `INSERT INTO device_inventory_cache (tenant_id, instance_id, headscale_node_id, machine_key, name)
			VALUES ($1, $2, $3, $4, 'srv-1')`, a.id, a.instance, int64(node.ID), node.MachineKey) //nolint:gosec // small test ids
		// the node is already in the inventory (inventory.sync came first): the consumed transition links it and
		// notifies the new device (device.new — the owner, here also the only Tenant Owner)
		rep, err := f.wrk.Reconcile(t.Context(), a.id)
		if err != nil || rep.Consumed != 1 || rep.NewDevices != 1 || rep.Linked != 0 {
			t.Fatalf("reconcile %+v %v", rep, err)
		}
		r, err := f.api.Get(t.Context(), a.id, out.Request.ID, owner)
		if err != nil || r.Status != StatusConsumed || r.NodeID == nil || *r.NodeID != int64(node.ID) { //nolint:gosec // small test ids
			t.Fatalf("consumed: %+v %v", r, err)
		}
		if n := f.count(t, `SELECT count(*) FROM device_inventory_cache WHERE enrollment_request_id = $1`, out.Request.ID); n != 1 {
			t.Fatalf("device link %d", n)
		}
		var dev uuid.UUID
		f.scan(t, `SELECT id FROM device_inventory_cache WHERE enrollment_request_id = $1`, []any{out.Request.ID}, &dev)
		if got := f.deviceNew(t, a, dev); !slices.Equal(got, sortedIDs(owner.MembershipID)) {
			t.Fatalf("device.new recipients %v", got)
		}
		// a consumed single-use key: revoke ⇒ 409 (the device is revoked through /devices)
		if _, err := f.api.Revoke(t.Context(), a.id, out.Request.ID, owner); codeOf(err) != CodeConflict {
			t.Fatalf("revoke consumed: %v", err)
		}
	})

	t.Run("WebAuthClaim", func(t *testing.T) {
		sess := uuid.New()
		user := a.actor("user", sess)
		label := "phone-1"
		out, err := f.api.Create(ctxOf(user, a.id, ActionRequest), a.id, user,
			NewRequest{Method: MethodWebAuth, DeviceLabel: &label}, idem("k-w-1", "w"))
		if err != nil {
			t.Fatal(err)
		}
		c := out.Credential
		code := c.EnrollCode.Reveal()
		if c.Kind != CredentialEnrollCode || len(code) != 12 || c.Hostname != "mg-"+code ||
			!strings.Contains(c.Command, "--login-server=https://"+a.slug+".mesh.test") ||
			c.ExpiresAt.Sub(*out.Request.IssuedAt) != WebAuthWindow {
			t.Fatalf("credential %+v", c)
		}
		authID := "hskey-authreq-" + strings.Repeat("A", 23) + "1"
		a.hs.PutPending(authID, devicestest.Node{MachineKey: "mkey:web1", Hostname: "mg-" + code})
		// another session of the same member: not the session the code was issued in ⇒ refused, nothing called
		other := a.actor("user", uuid.New())
		a.hs.ResetCalls()
		if _, err := f.api.Claim(ctxOf(other, a.id, ActionClaim), a.id, other, Claim{AuthID: authID}); reasonOf(err) != "no_pending_request" {
			t.Fatalf("other session: %v", err)
		}
		if n := a.hs.Calls(devicestest.OpAuthRegister); n != 0 {
			t.Fatalf("AuthRegister called %d times without a pending request", n)
		}
		r, err := f.api.Claim(ctxOf(user, a.id, ActionClaim), a.id, user, Claim{AuthID: authID})
		if err != nil || r.Status != StatusVerified || r.NodeID == nil {
			t.Fatalf("claim: %+v %v", r, err)
		}
		n, _ := a.hs.Node(uint64(*r.NodeID)) //nolint:gosec // small test ids
		if n.GivenName != label || n.UserName != un(user) {
			t.Fatalf("node %+v", n)
		}
		if k := f.count(t, `SELECT count(*) FROM device_inventory_cache WHERE enrollment_request_id = $1
			AND owner_membership_id = $2`, r.ID, user.MembershipID); k != 1 {
			t.Fatalf("device row %d", k)
		}
		if k := f.count(t, `SELECT count(*) FROM notification_outbox WHERE tenant_id = $1 AND kind = 'device.new'`, a.id); k == 0 {
			t.Fatal("no device.new notification")
		}
		if k := f.count(t, `SELECT count(*) FROM provisioning_jobs WHERE tenant_id = $1 AND kind = 'inventory.sync'`, a.id); k != 1 {
			t.Fatalf("inventory.sync jobs %d", k)
		}
		if got := f.auditOf(t, r.ID.String()); !slices.Contains(got, "enrollment.claim.succeeded/success") {
			t.Fatalf("audit %v", got)
		}
		// the same Auth ID again ⇒ replay refused (security event)
		if _, err := f.api.Claim(ctxOf(user, a.id, ActionClaim), a.id, user, Claim{AuthID: authID}); reasonOf(err) != "auth_id_already_claimed" {
			t.Fatalf("replay: %v", err)
		}
		if k := f.count(t, `SELECT count(*) FROM security_events WHERE tenant_id = $1 AND kind IN ($2, $3)`, a.id,
			EventClaimWithoutRequest, EventClaimReplay); k < 2 {
			t.Fatalf("security events %d", k)
		}
		f.noKeyMaterial(t)
		if k := f.count(t, `SELECT count(*) FROM enrollment_requests WHERE id = $1 AND (auth_id_hash IS NULL
			OR position($2::bytea IN auth_id_hash) > 0)`, r.ID, []byte(authID)); k != 0 {
			t.Fatal("Auth ID stored in clear")
		}
	})

	t.Run("NodeChecks", func(t *testing.T) {
		admin := a.actor("admin", uuid.New())
		ctx := ctxOf(admin, a.id, ActionClaim)
		// a new node whose hostname is not mg-<code>: deleted, failed node_mismatch, security event
		out, err := f.api.Create(ctx, a.id, admin, NewRequest{Method: MethodWebAuth}, idem("k-n-1", "1"))
		if err != nil {
			t.Fatal(err)
		}
		auth1 := "hskey-authreq-" + strings.Repeat("B", 24)
		a.hs.PutPending(auth1, devicestest.Node{MachineKey: "mkey:evil", Hostname: "attacker-box"})
		r, err := f.api.Claim(ctx, a.id, admin, Claim{AuthID: auth1})
		if err != nil || r.Status != StatusFailed || r.FailureCode == nil || *r.FailureCode != FailureNodeMismatch {
			t.Fatalf("mismatch: %+v %v", r, err)
		}
		if _, ok := a.hs.Node(uint64(*r.NodeID)); ok { //nolint:gosec // small test ids
			t.Fatal("the mismatching node was not deleted")
		}
		if k := f.count(t, `SELECT count(*) FROM security_events WHERE tenant_id = $1 AND kind = $2`, a.id, EventNodeMismatch); k != 1 {
			t.Fatalf("security events %d", k)
		}
		_ = out
		// re-authentication of the member's own device already in the inventory: verified, never deleted nor renamed
		a.hs.PutNode(devicestest.Node{ID: 77, MachineKey: "mkey:own", Hostname: "old-name", GivenName: "old-name",
			UserName: un(admin), Method: "cli", CreatedAt: time.Now().Add(-time.Hour)})
		f.exec(t, `INSERT INTO device_inventory_cache (tenant_id, instance_id, headscale_node_id, machine_key, name,
			owner_membership_id) VALUES ($1, $2, 77, 'mkey:own', 'old-name', $3)`, a.id, a.instance, admin.MembershipID)
		if _, err := f.api.Create(ctx, a.id, admin, NewRequest{Method: MethodWebAuth}, idem("k-n-2", "2")); err != nil {
			t.Fatal(err)
		}
		auth2 := "hskey-authreq-" + strings.Repeat("C", 24)
		a.hs.PutPending(auth2, devicestest.Node{MachineKey: "mkey:own", Hostname: "old-name"})
		r, err = f.api.Claim(ctx, a.id, admin, Claim{AuthID: auth2})
		if err != nil || r.Status != StatusVerified || *r.NodeID != 77 {
			t.Fatalf("re-auth: %+v %v", r, err)
		}
		if n, ok := a.hs.Node(77); !ok || n.GivenName != "old-name" || a.hs.Calls(devicestest.OpDeleteNode) != 1 {
			t.Fatalf("re-auth touched the node: %+v %v", n, ok)
		}
		// a node of the member that existed before, on a machine the inventory knows as another member's device (node 78
		// of user2, same machine key — V-28: two users, two nodes): expired, never deleted; user2's node untouched
		user2 := a.people["user2"]
		a.hs.PutNode(devicestest.Node{ID: 78, MachineKey: "mkey:foreign", Hostname: "x", UserName: "mg-" + user2.membership.String(),
			Method: "cli", CreatedAt: time.Now().Add(-2 * time.Hour)})
		f.exec(t, `INSERT INTO device_inventory_cache (tenant_id, instance_id, headscale_node_id, machine_key, name,
			owner_membership_id) VALUES ($1, $2, 78, 'mkey:foreign', 'x', $3)`, a.id, a.instance, user2.membership)
		a.hs.PutNode(devicestest.Node{ID: 79, MachineKey: "mkey:foreign", Hostname: "x", UserName: un(admin),
			Method: "cli", CreatedAt: time.Now().Add(-time.Hour)})
		if _, err := f.api.Create(ctx, a.id, admin, NewRequest{Method: MethodWebAuth}, idem("k-n-3", "3")); err != nil {
			t.Fatal(err)
		}
		auth3 := "hskey-authreq-" + strings.Repeat("D", 24)
		a.hs.PutPending(auth3, devicestest.Node{MachineKey: "mkey:foreign", Hostname: "x"})
		r, err = f.api.Claim(ctx, a.id, admin, Claim{AuthID: auth3})
		if err != nil || r.Status != StatusFailed || *r.FailureCode != FailureForeignNode {
			t.Fatalf("foreign: %+v %v", r, err)
		}
		if n, ok := a.hs.Node(79); !ok || n.Expiry == nil || n.Expiry.After(f.clk.now().Add(time.Minute)) {
			t.Fatalf("foreign node not expired or deleted: %+v %v", n, ok)
		}
		if n, ok := a.hs.Node(78); !ok || n.Expiry != nil {
			t.Fatalf("user2's node was touched: %+v %v", n, ok)
		}
		// user2 then removes their device and inventory.sync makes node 79 a device of the member: a node a claim
		// rejected as foreign is still never accepted as a re-authentication (no mg-<code> check ever ran for it)
		f.exec(t, `UPDATE device_inventory_cache SET removed_at = now() WHERE instance_id = $1 AND headscale_node_id = 78`,
			a.instance)
		a.hs.RemoveNode(78)
		f.exec(t, `INSERT INTO device_inventory_cache (tenant_id, instance_id, headscale_node_id, machine_key, name,
			owner_membership_id) VALUES ($1, $2, 79, 'mkey:foreign', 'x', $3)`, a.id, a.instance, admin.MembershipID)
		if _, err := f.api.Create(ctx, a.id, admin, NewRequest{Method: MethodWebAuth}, idem("k-n-3b", "3b")); err != nil {
			t.Fatal(err)
		}
		auth3b := "hskey-authreq-" + strings.Repeat("S", 24)
		a.hs.PutPending(auth3b, devicestest.Node{MachineKey: "mkey:foreign", Hostname: "x"})
		r, err = f.api.Claim(ctx, a.id, admin, Claim{AuthID: auth3b})
		if err != nil || r.Status != StatusFailed || failureOf(r) != FailureForeignNode || r.NodeID == nil || *r.NodeID != 79 {
			t.Fatalf("re-authentication of a node rejected as foreign: %+v %v", r, err)
		}
		if _, ok := a.hs.Node(79); !ok {
			t.Fatal("the node rejected as foreign was deleted")
		}
		// an Auth ID Headscale no longer holds: failed, 409
		if _, err := f.api.Create(ctx, a.id, admin, NewRequest{Method: MethodWebAuth}, idem("k-n-4", "4")); err != nil {
			t.Fatal(err)
		}
		if _, err := f.api.Claim(ctx, a.id, admin, Claim{AuthID: "hskey-authreq-" + strings.Repeat("E", 24)}); reasonOf(err) != FailureNotPending {
			t.Fatalf("not pending: %v", err)
		}
		// a new node named mg-<a guessed code>: the prefix is right, the code is not the one this request received ⇒
		// deleted (the hash of the code is what binds the device to the requester's session — §7.4 step 8)
		if _, err := f.api.Create(ctx, a.id, admin, NewRequest{Method: MethodWebAuth}, idem("k-n-5", "5")); err != nil {
			t.Fatal(err)
		}
		auth5 := "hskey-authreq-" + strings.Repeat("H", 24)
		a.hs.PutPending(auth5, devicestest.Node{MachineKey: "mkey:guess", Hostname: HostnamePrefix + strings.Repeat("a", 12)})
		r, err = f.api.Claim(ctx, a.id, admin, Claim{AuthID: auth5})
		if err != nil || r.Status != StatusFailed || r.FailureCode == nil || *r.FailureCode != FailureNodeMismatch {
			t.Fatalf("guessed code: %+v %v", r, err)
		}
		if _, ok := a.hs.Node(uint64(*r.NodeID)); ok { //nolint:gosec // small test ids
			t.Fatal("the node with a guessed code was not deleted")
		}
	})

	t.Run("CrossUserMachineKey", func(t *testing.T) {
		// C0 (V-28): AuthRegister on the machine key of ANOTHER member's device creates a NEW node for the claimer and
		// leaves the other node alone. The inventory row of that other node does not make the new node "existing": it
		// is checked as new — not mg-<code> ⇒ deleted (node_mismatch); the other member's node is never expired.
		admin := a.actor("admin", uuid.New())
		ctx := ctxOf(admin, a.id, ActionClaim)
		user2 := a.people["user2"]
		const mkey = "mkey:shared-machine"
		a.hs.PutNode(devicestest.Node{ID: 90, MachineKey: mkey, Hostname: "u2-laptop", GivenName: "u2-laptop",
			UserName: "mg-" + user2.membership.String(), Method: "cli", CreatedAt: time.Now().Add(-time.Hour)})
		f.exec(t, `INSERT INTO device_inventory_cache (tenant_id, instance_id, headscale_node_id, machine_key, name,
			owner_membership_id) VALUES ($1, $2, 90, $3, 'u2-laptop', $4)`, a.id, a.instance, mkey, user2.membership)
		claim := func(key, authID string) Request {
			t.Helper()
			if _, err := f.api.Create(ctx, a.id, admin, NewRequest{Method: MethodWebAuth}, idem(key, key)); err != nil {
				t.Fatal(err)
			}
			a.hs.PutPending(authID, devicestest.Node{MachineKey: mkey, Hostname: "evil-box"})
			r, err := f.api.Claim(ctx, a.id, admin, Claim{AuthID: authID})
			if err != nil {
				t.Fatal(err)
			}
			return r
		}
		r := claim("k-c0-1", "hskey-authreq-"+strings.Repeat("J", 24))
		if r.NodeID == nil || *r.NodeID == 90 {
			t.Fatalf("claim of another member's machine: node %v", r.NodeID)
		}
		if r.Status != StatusFailed || failureOf(r) != FailureNodeMismatch {
			t.Errorf("claim of another member's machine: %s/%s, want failed/%s", r.Status, failureOf(r), FailureNodeMismatch)
		}
		if _, ok := a.hs.Node(uint64(*r.NodeID)); ok { //nolint:gosec // small test ids
			t.Error("the new node of the claimer was left registered")
		}
		if n, ok := a.hs.Node(90); !ok || n.Expiry != nil || len(a.hs.ExpireCalls(90)) != 0 {
			t.Errorf("the other member's node was touched: %+v %v", n, ok)
		}
		// The delete of such a node does not go through: the node stays under the claimer. Once inventory.sync made it a
		// device of the claimer and the other member removed theirs, the same machine signs in again through another
		// claim: Headscale re-authenticates that node (same user, same machine key), which a claim rejected before — it
		// is never accepted as a re-authentication (no mg-<code> check would have run): deleted now.
		a.hs.Refuse(devicestest.OpDeleteNode, true)
		r2 := claim("k-c0-2", "hskey-authreq-"+strings.Repeat("K", 24))
		a.hs.Refuse(devicestest.OpDeleteNode, false)
		if r2.Status != StatusFailed || r2.NodeID == nil {
			t.Fatalf("second claim: %s/%s node %v", r2.Status, failureOf(r2), r2.NodeID)
		}
		left := uint64(*r2.NodeID) //nolint:gosec // small test ids
		n, ok := a.hs.Node(left)
		if !ok || n.Expiry == nil {
			t.Fatalf("the refused delete: node %+v %v, want kept and expired", n, ok)
		}
		// … and it is old by the time of the next claim: neither created since that claim began nor since its request
		n.CreatedAt = time.Now().Add(-time.Hour)
		a.hs.PutNode(n)
		f.exec(t, `INSERT INTO device_inventory_cache (tenant_id, instance_id, headscale_node_id, machine_key, name,
			owner_membership_id) VALUES ($1, $2, $3, $4, 'evil-box', $5)`, a.id, a.instance, int64(left), mkey, //nolint:gosec // small
			admin.MembershipID)
		f.exec(t, `UPDATE device_inventory_cache SET removed_at = now() WHERE instance_id = $1 AND headscale_node_id = 90`,
			a.instance)
		a.hs.RemoveNode(90)
		r3 := claim("k-c0-3", "hskey-authreq-"+strings.Repeat("L", 24))
		if r3.Status != StatusFailed || failureOf(r3) != FailureNodeMismatch || r3.NodeID == nil ||
			uint64(*r3.NodeID) != left { //nolint:gosec // small test ids
			t.Fatalf("re-authentication of a node rejected before: %s/%s node %v, want failed/%s node %d", r3.Status,
				failureOf(r3), r3.NodeID, FailureNodeMismatch, left)
		}
		if _, ok := a.hs.Node(left); ok {
			t.Fatal("the node rejected before was not deleted")
		}
		if k := f.count(t, `SELECT count(*) FROM device_inventory_cache WHERE enrollment_request_id IN ($1, $2, $3)`,
			r.ID, r2.ID, r3.ID); k != 0 {
			t.Fatalf("%d device rows linked to rejected claims", k)
		}
		if k := f.count(t, `SELECT count(*) FROM security_events WHERE tenant_id = $1 AND kind = $2
			AND details->>'request_id' IN ($3, $4, $5)`, a.id, EventNodeMismatch, r.ID.String(), r2.ID.String(),
			r3.ID.String()); k != 3 {
			t.Fatalf("node_mismatch security events %d, want 3", k)
		}
	})

	t.Run("NewNodeAgainstTheInventory", func(t *testing.T) {
		// C0: a row of the node AuthRegister answers proves that the node existed only when the inventory had it when the
		// claim began. An inventory.sync whose snapshot lists the new node commits its row (owner: the claimer, from the
		// user name) before the claim reads the inventory: the node is still new — checked, deleted on mismatch —
		// whatever the clock of the instance says. A new node that gets the id of a row known before (an instance
		// restored from an older backup) is new as well.
		admin := a.actor("admin", uuid.New())
		ctx := ctxOf(admin, a.id, ActionClaim)
		row := func(id uint64, mkey string) {
			f.exec(t, `INSERT INTO device_inventory_cache (tenant_id, instance_id, headscale_node_id, machine_key, name,
				owner_membership_id) VALUES ($1, $2, $3, $4, 'synced', $5)`, a.id, a.instance, int64(id), mkey, //nolint:gosec // small
				admin.MembershipID)
		}
		claim := func(what, key string, n devicestest.Node, setup func(request uuid.UUID)) {
			t.Helper()
			out, err := f.api.Create(ctx, a.id, admin, NewRequest{Method: MethodWebAuth}, idem(key, key))
			if err != nil {
				t.Fatal(err)
			}
			if setup != nil {
				setup(out.Request.ID)
			}
			authID := "hskey-authreq-" + strings.Repeat("V", 20) + key[len(key)-4:]
			a.hs.PutPending(authID, n)
			r, err := f.api.Claim(ctx, a.id, admin, Claim{AuthID: authID})
			if err != nil || r.Status != StatusFailed || failureOf(r) != FailureNodeMismatch || r.NodeID == nil ||
				uint64(*r.NodeID) != n.ID { //nolint:gosec // small test ids
				t.Errorf("%s: %s/%s node %v %v, want failed/%s node %d", what, r.Status, failureOf(r), r.NodeID, err,
					FailureNodeMismatch, n.ID)
			}
			if _, ok := a.hs.Node(n.ID); ok {
				t.Errorf("%s: the new node was left registered", what)
			}
		}
		syncDuring := func(id uint64, mkey string) func(uuid.UUID) {
			return func(uuid.UUID) {
				a.hs.After(devicestest.OpAuthRegister, func(uint64) { row(id, mkey) })
			}
		}
		claim("sync during the claim", "k-c0s-0001", devicestest.Node{ID: 4501, MachineKey: "mkey:c0-sync",
			Hostname: "evil-sync"}, syncDuring(4501, "mkey:c0-sync"))
		// the clock of the instance runs 10 s behind the database's; the requester took 5 minutes to sign in
		claim("sync during the claim, instance clock behind", "k-c0s-0002", devicestest.Node{ID: 4502,
			MachineKey: "mkey:c0-skew", Hostname: "evil-skew", CreatedAt: time.Now().Add(-10 * time.Second)},
			func(request uuid.UUID) {
				f.exec(t, `UPDATE enrollment_requests SET created_at = now() - interval '5 minutes' WHERE id = $1`, request)
				syncDuring(4502, "mkey:c0-skew")(request)
			})
		claim("node id of a row known before", "k-c0s-0003", devicestest.Node{ID: 4503, MachineKey: "mkey:c0-reuse",
			Hostname: "evil-reuse"}, func(uuid.UUID) { row(4503, "mkey:c0-reuse") })
	})

	t.Run("ClaimRunsToItsVerdict", func(t *testing.T) {
		// C1: once AuthRegister may have registered a node, the claim runs to its verdict whatever happens to the request
		// or to the answer — a node is never left registered under the member without the checks of step 8.
		admin := a.actor("admin", uuid.New())
		ctx := ctxOf(admin, a.id, ActionClaim)
		create := func(key string) Issue {
			t.Helper()
			out, err := f.api.Create(ctx, a.id, admin, NewRequest{Method: MethodWebAuth}, idem(key, key))
			if err != nil {
				t.Fatal(err)
			}
			return out
		}
		nodesOf := func(mkey string) []devicestest.Node {
			var out []devicestest.Node
			for _, n := range a.hs.Nodes() {
				if n.MachineKey == mkey {
					out = append(out, n)
				}
			}
			return out
		}
		state := func(id uuid.UUID) string {
			return f.str(t, `SELECT status || '/' || COALESCE(failure_code, '') FROM enrollment_requests WHERE id = $1`, id)
		}
		mismatch := StatusFailed + "/" + FailureNodeMismatch

		// (1) the caller goes away while AuthRegister is in flight: the request context is cancelled once Headscale has
		// registered the node, before its answer arrives
		gone := create("k-c1-1")
		auth := "hskey-authreq-" + strings.Repeat("M", 24)
		a.hs.PutPending(auth, devicestest.Node{MachineKey: "mkey:c1-gone", Hostname: "evil-gone"})
		cctx, cancel := context.WithCancel(ctx)
		a.hs.After(devicestest.OpAuthRegister, func(uint64) { cancel() })
		_, _ = f.api.Claim(cctx, a.id, admin, Claim{AuthID: auth})
		cancel()
		if n := nodesOf("mkey:c1-gone"); len(n) != 0 {
			t.Errorf("caller gone: the unverified node was left registered: %+v", n)
		}
		if st := state(gone.Request.ID); st != mismatch {
			t.Errorf("caller gone: request %s, want %s", st, mismatch)
		}

		// (2) the answer of AuthRegister is lost (the edge answers a bare 504 after Headscale registered the node): the
		// claim reads back — the requester's own device, named mg-<code>, is verified …
		mine := create("k-c1-2")
		auth = "hskey-authreq-" + strings.Repeat("N", 24)
		a.hs.PutPending(auth, devicestest.Node{MachineKey: "mkey:c1-mine", Hostname: "mg-" + mine.Credential.EnrollCode.Reveal()})
		a.hs.LoseAnswer(devicestest.OpAuthRegister, true)
		r, err := f.api.Claim(ctx, a.id, admin, Claim{AuthID: auth})
		a.hs.LoseAnswer(devicestest.OpAuthRegister, false)
		n := nodesOf("mkey:c1-mine")
		if err != nil || r.Status != StatusVerified || len(n) != 1 || r.NodeID == nil ||
			*r.NodeID != int64(n[0].ID) { //nolint:gosec // small test ids
			t.Fatalf("answer lost, own device: %s %v, nodes %+v", r.Status, err, n)
		}
		if k := f.count(t, `SELECT count(*) FROM device_inventory_cache WHERE enrollment_request_id = $1 AND removed_at IS NULL`,
			mine.Request.ID); k != 1 {
			t.Errorf("answer lost, own device: %d device rows", k)
		}
		// … and a node that is not the requester's device is deleted (node_mismatch). The device just verified is
		// within the read-back window of that claim (created since it began) and is the member's untagged CLI node like
		// the stray: the claim that recorded it accounts for it, so it is never removed as a stray
		mineNode := n[0]
		mineNode.CreatedAt = time.Now()
		a.hs.PutNode(mineNode)
		lost := create("k-c1-3")
		auth = "hskey-authreq-" + strings.Repeat("O", 24)
		a.hs.PutPending(auth, devicestest.Node{MachineKey: "mkey:c1-lost", Hostname: "evil-lost"})
		a.hs.LoseAnswer(devicestest.OpAuthRegister, true)
		_, _ = f.api.Claim(ctx, a.id, admin, Claim{AuthID: auth})
		a.hs.LoseAnswer(devicestest.OpAuthRegister, false)
		if n := nodesOf("mkey:c1-lost"); len(n) != 0 {
			t.Errorf("answer lost: the unverified node was left registered: %+v", n)
		}
		if st := state(lost.Request.ID); st != mismatch {
			t.Errorf("answer lost: request %s, want %s", st, mismatch)
		}
		if _, ok := a.hs.Node(mineNode.ID); !ok {
			t.Error("answer lost: the requester's verified device of another claim was removed as a stray")
		}

		// (3) the corrective delete is refused: the node is expired instead, so it cannot stay connected
		refused := create("k-c1-4")
		auth = "hskey-authreq-" + strings.Repeat("P", 24)
		a.hs.PutPending(auth, devicestest.Node{MachineKey: "mkey:c1-refused", Hostname: "evil-refused"})
		a.hs.Refuse(devicestest.OpDeleteNode, true)
		_, _ = f.api.Claim(ctx, a.id, admin, Claim{AuthID: auth})
		a.hs.Refuse(devicestest.OpDeleteNode, false)
		if n := nodesOf("mkey:c1-refused"); len(n) != 1 || n[0].Expiry == nil || n[0].Expiry.After(f.clk.now().Add(time.Minute)) {
			t.Errorf("delete refused: the node was not expired: %+v", n)
		} else {
			a.hs.RemoveNode(n[0].ID)
		}
		if st := state(refused.Request.ID); st != mismatch {
			t.Errorf("delete refused: request %s, want %s", st, mismatch)
		}

		// (4) the registered node cannot be recorded (the database refuses the write of registered): the node this
		// claim created is deleted, never left for inventory.sync to adopt as the member's device; the request records
		// it failed claim_unfinished
		f.exec(t, `CREATE FUNCTION test_refuse_write() RETURNS trigger LANGUAGE plpgsql AS $$
			BEGIN RAISE EXCEPTION 'write refused by the test'; END $$`)
		defer f.exec(t, `DROP FUNCTION test_refuse_write()`)
		refuse := func(id uuid.UUID, when string) func() {
			f.exec(t, `CREATE TRIGGER test_refuse_write BEFORE UPDATE ON enrollment_requests FOR EACH ROW
				WHEN (OLD.id = '`+id.String()+`'::uuid AND `+when+`) EXECUTE FUNCTION test_refuse_write()`)
			return func() { f.exec(t, `DROP TRIGGER test_refuse_write ON enrollment_requests`) }
		}
		consumed := func(id uuid.UUID) uint64 {
			var nid *int64
			f.scan(t, `SELECT consumed_node_id FROM enrollment_requests WHERE id = $1`, []any{id}, &nid)
			if nid == nil {
				return 0
			}
			return uint64(*nid) //nolint:gosec // small test ids
		}
		unfinished := StatusFailed + "/" + FailureClaimUnfinished
		norec := create("k-c1-5")
		auth = "hskey-authreq-" + strings.Repeat("Q", 24)
		a.hs.PutPending(auth, devicestest.Node{ID: 4610, MachineKey: "mkey:c1-norecord", Hostname: "evil-norecord"})
		a.hs.ResetCalls()
		undo := refuse(norec.Request.ID, `NEW.status = 'registered'`)
		_, err = f.api.Claim(ctx, a.id, admin, Claim{AuthID: auth})
		undo()
		if err == nil || a.hs.Calls(devicestest.OpAuthRegister) != 1 || a.hs.Calls(devicestest.OpDeleteNode) != 1 {
			t.Errorf("no record: claim %v, AuthRegister %d DeleteNode %d calls", err,
				a.hs.Calls(devicestest.OpAuthRegister), a.hs.Calls(devicestest.OpDeleteNode))
		}
		if n := nodesOf("mkey:c1-norecord"); len(n) != 0 {
			t.Errorf("no record: the unverified node was left registered: %+v", n)
		}
		if st, nid := state(norec.Request.ID), consumed(norec.Request.ID); st != unfinished || nid != 4610 {
			t.Errorf("no record: request %s node %d, want %s node 4610", st, nid, unfinished)
		}
		// (4b) … the node answered is an older device of the member (a re-authentication): expired, never deleted
		a.hs.PutNode(devicestest.Node{ID: 4611, MachineKey: "mkey:c1-older", Hostname: "laptop", GivenName: "laptop",
			UserName: un(admin), Method: "cli", CreatedAt: time.Now().Add(-time.Hour)})
		older := create("k-c1-5b")
		auth = "hskey-authreq-" + strings.Repeat("Q", 23) + "2"
		a.hs.PutPending(auth, devicestest.Node{MachineKey: "mkey:c1-older", Hostname: "laptop"})
		undo = refuse(older.Request.ID, `NEW.status = 'registered'`)
		_, _ = f.api.Claim(ctx, a.id, admin, Claim{AuthID: auth})
		undo()
		if n, ok := a.hs.Node(4611); !ok || n.Expiry == nil || n.Expiry.After(f.clk.now().Add(time.Minute)) {
			t.Errorf("no record, older node: %+v %v, want kept and expired", n, ok)
		}
		if st := state(older.Request.ID); st != unfinished {
			t.Errorf("no record, older node: request %s, want %s", st, unfinished)
		}
		// (4c) … and the delete is refused as well: the node is expired; once inventory.sync made it a device of the
		// member, the next claim on that machine (a re-authentication by then) deletes it — it never passed the checks
		norec2 := create("k-c1-5c")
		auth = "hskey-authreq-" + strings.Repeat("Q", 23) + "3"
		a.hs.PutPending(auth, devicestest.Node{ID: 4612, MachineKey: "mkey:c1-norecord2", Hostname: "evil-norecord"})
		undo = refuse(norec2.Request.ID, `NEW.status = 'registered'`)
		a.hs.Refuse(devicestest.OpDeleteNode, true)
		_, _ = f.api.Claim(ctx, a.id, admin, Claim{AuthID: auth})
		a.hs.Refuse(devicestest.OpDeleteNode, false)
		undo()
		left, ok := a.hs.Node(4612)
		if !ok || left.Expiry == nil || left.Expiry.After(f.clk.now().Add(time.Minute)) {
			t.Fatalf("no record, delete refused: %+v %v, want kept and expired", left, ok)
		}
		if st, nid := state(norec2.Request.ID), consumed(norec2.Request.ID); st != unfinished || nid != 4612 {
			t.Errorf("no record, delete refused: request %s node %d, want %s node 4612", st, nid, unfinished)
		}
		// time passes: the node was created well after its request, well before the next one
		f.exec(t, `UPDATE enrollment_requests SET created_at = created_at - interval '1 hour' WHERE id = $1`, norec2.Request.ID)
		left.CreatedAt = time.Now().Add(-30 * time.Minute)
		a.hs.PutNode(left)
		f.exec(t, `INSERT INTO device_inventory_cache (tenant_id, instance_id, headscale_node_id, machine_key, name,
			owner_membership_id) VALUES ($1, $2, 4612, 'mkey:c1-norecord2', 'evil-norecord', $3)`, a.id, a.instance,
			admin.MembershipID)
		create("k-c1-5d")
		auth = "hskey-authreq-" + strings.Repeat("Q", 23) + "4"
		a.hs.PutPending(auth, devicestest.Node{MachineKey: "mkey:c1-norecord2", Hostname: "evil-norecord"})
		r, err = f.api.Claim(ctx, a.id, admin, Claim{AuthID: auth})
		if err != nil || r.Status != StatusFailed || failureOf(r) != FailureNodeMismatch || r.NodeID == nil || *r.NodeID != 4612 {
			t.Errorf("re-authentication of a node registered without a verdict: %s/%s node %v %v, want failed/%s node 4612",
				r.Status, failureOf(r), r.NodeID, err, FailureNodeMismatch)
		}
		if _, ok := a.hs.Node(4612); ok {
			t.Error("the node registered without a verdict was not deleted on re-authentication")
		}
	})

	t.Run("LostAnswerReadBack", func(t *testing.T) {
		// C1: the answer of AuthRegister is lost — the claim reads back until it knows, and never closes the request as
		// if nothing had been registered when it does not
		admin := a.actor("admin", uuid.New())
		ctx := ctxOf(admin, a.id, ActionClaim)
		create := func(key string) Issue {
			t.Helper()
			out, err := f.api.Create(ctx, a.id, admin, NewRequest{Method: MethodWebAuth}, idem(key, key))
			if err != nil {
				t.Fatal(err)
			}
			return out
		}
		state := func(id uuid.UUID) string {
			return f.str(t, `SELECT status || '/' || COALESCE(failure_code, '') FROM enrollment_requests WHERE id = $1`, id)
		}
		gone := func(ids ...uint64) bool {
			for _, id := range ids {
				if _, ok := a.hs.Node(id); ok {
					return false
				}
			}
			return true
		}
		mismatch := StatusFailed + "/" + FailureNodeMismatch
		lostClaim := func(req Issue, authID string) error {
			t.Helper()
			a.hs.LoseAnswer(devicestest.OpAuthRegister, true)
			defer a.hs.LoseAnswer(devicestest.OpAuthRegister, false)
			_, err := f.api.Claim(ctx, a.id, admin, Claim{AuthID: authID, RequestID: &req.Request.ID})
			return err
		}

		// (1) another request of the member is claimed at the same time: while its AuthRegister is in flight, Headscale
		// registers its device (mg-<its code>) and another stray node of the member appears; then this claim's answer is
		// lost. The read-back keeps the other claim's device, removes the stray and rejects the newest node (its own)
		other, mine := create("k-lr-1"), create("k-lr-2")
		authOther := "hskey-authreq-" + strings.Repeat("T", 23) + "1"
		authMine := "hskey-authreq-" + strings.Repeat("T", 23) + "2"
		a.hs.PutPending(authOther, devicestest.Node{MachineKey: "mkey:lr-other", Hostname: "mg-" + other.Credential.EnrollCode.Reveal()})
		a.hs.PutPending(authMine, devicestest.Node{ID: 4703, MachineKey: "mkey:lr-mine", Hostname: "evil-lr"})
		var errMine error
		a.hs.Before(devicestest.OpAuthRegister, func(uint64) {
			a.hs.PutNode(devicestest.Node{ID: 4701, MachineKey: "mkey:lr-other", Hostname: "mg-" + other.Credential.EnrollCode.Reveal(),
				GivenName: "mg-" + other.Credential.EnrollCode.Reveal(), UserName: un(admin), Method: "cli", CreatedAt: time.Now()})
			a.hs.PutNode(devicestest.Node{ID: 4702, MachineKey: "mkey:lr-stray", Hostname: "evil-stray", GivenName: "evil-stray",
				UserName: un(admin), Method: "cli", CreatedAt: time.Now().Add(-200 * time.Millisecond)})
			errMine = lostClaim(mine, authMine)
			if _, ok := a.hs.Node(4701); !ok {
				t.Error("concurrent claims: the device of the other claim was removed by the read-back")
			}
		})
		r, err := f.api.Claim(ctx, a.id, admin, Claim{AuthID: authOther, RequestID: &other.Request.ID})
		if err != nil || r.Status != StatusVerified || r.NodeID == nil || *r.NodeID != 4701 {
			t.Errorf("concurrent claims: the other claim %s %v node %v, want verified node 4701", r.Status, err, r.NodeID)
		}
		if st := state(mine.Request.ID); st != mismatch || !gone(4702, 4703) {
			t.Errorf("concurrent claims: request %s, stray and own node gone %v; want %s, true (%v)", st, gone(4702, 4703),
				mismatch, errMine)
		}
		if got := f.str(t, `SELECT consumed_node_id::text FROM enrollment_requests WHERE id = $1`, mine.Request.ID); got != "4703" {
			t.Errorf("concurrent claims: the rejected node is %s, want the newest (4703)", got)
		}

		// (2) the first read-back fails (the instance refuses ListNodes once): the claim reads again and decides
		readFail := create("k-lr-3")
		auth := "hskey-authreq-" + strings.Repeat("T", 23) + "3"
		a.hs.PutPending(auth, devicestest.Node{ID: 4704, MachineKey: "mkey:lr-readfail", Hostname: "evil-readfail"})
		a.hs.Refuse(devicestest.OpListNodes, true)
		a.hs.After(devicestest.OpListNodes, func(uint64) { a.hs.Refuse(devicestest.OpListNodes, false) })
		_ = lostClaim(readFail, auth)
		a.hs.Refuse(devicestest.OpListNodes, false)
		if st := state(readFail.Request.ID); st != mismatch || !gone(4704) {
			t.Errorf("read-back refused once: request %s, node gone %v; want %s, true", st, gone(4704), mismatch)
		}

		// (3) the instance applies the registration after the first read-back (its answer was lost before it acted)
		late := create("k-lr-4")
		auth = "hskey-authreq-" + strings.Repeat("T", 23) + "4" // not pending yet: the instance has not acted
		a.hs.After(devicestest.OpListNodes, func(uint64) {
			a.hs.PutNode(devicestest.Node{ID: 4705, MachineKey: "mkey:lr-late", Hostname: "evil-late", GivenName: "evil-late",
				UserName: un(admin), Method: "cli", CreatedAt: time.Now()})
		})
		_ = lostClaim(late, auth)
		if st := state(late.Request.ID); st != mismatch || !gone(4705) {
			t.Errorf("registered after the first read-back: request %s, node gone %v; want %s, true", st, gone(4705), mismatch)
		}

		// (4) nothing new is ever found: the claim cannot tell — the request is left claimed for reconcile (never closed
		// as if nothing had been registered), the claim operation is closed failed, the caller gets the error
		none := create("k-lr-5")
		auth = "hskey-authreq-" + strings.Repeat("T", 23) + "5"
		if err := lostClaim(none, auth); codeOf(err) != CodeInstanceUnavailable {
			t.Errorf("nothing found: %v, want %s", err, CodeInstanceUnavailable)
		}
		if st := state(none.Request.ID); st != StatusClaimed+"/" {
			t.Errorf("nothing found: request %s, want left %s", st, StatusClaimed)
		}
		if got := f.auditOf(t, none.Request.ID.String()); !slices.Contains(got, "enrollment.claim.failed/failure") {
			t.Errorf("nothing found: audit %v", got)
		}

		// (5) the lost AuthRegister re-authenticated a node an earlier claim rejected (its delete refused, so it was only
		// expired): Headscale gave it a fresh expiry (V-21) — nothing new is found, and the node it rejected before does
		// not stay active: deleted
		rej := create("k-lr-6")
		auth = "hskey-authreq-" + strings.Repeat("T", 23) + "6"
		a.hs.PutPending(auth, devicestest.Node{ID: 4706, MachineKey: "mkey:lr-again", Hostname: "evil-again"})
		a.hs.Refuse(devicestest.OpDeleteNode, true)
		r, err = f.api.Claim(ctx, a.id, admin, Claim{AuthID: auth, RequestID: &rej.Request.ID})
		a.hs.Refuse(devicestest.OpDeleteNode, false)
		n, ok := a.hs.Node(4706)
		if err != nil || failureOf(r) != FailureNodeMismatch || !ok || n.Expiry == nil {
			t.Fatalf("rejected, delete refused: %s/%s %v node %+v %v", r.Status, failureOf(r), err, n, ok)
		}
		n.CreatedAt = time.Now().Add(-time.Hour) // the next sign-in comes later
		a.hs.PutNode(n)
		again := create("k-lr-7")
		auth = "hskey-authreq-" + strings.Repeat("T", 23) + "7"
		a.hs.PutPending(auth, devicestest.Node{MachineKey: "mkey:lr-again", Hostname: "evil-again"})
		_ = lostClaim(again, auth)
		if !gone(4706) {
			n, _ := a.hs.Node(4706)
			t.Errorf("lost re-authentication of a node rejected before: left %+v", n)
		}
		if st := state(again.Request.ID); st != StatusClaimed+"/" {
			t.Errorf("lost re-authentication of a node rejected before: request %s, want left %s", st, StatusClaimed)
		}
	})

	t.Run("UnfinishedClaim", func(t *testing.T) {
		// C1 (5): a claim stops after recording registered — its verdict cannot be written and its corrective calls are
		// refused, as if the process died. Reconcile checks the node before it closes the request claim_unfinished
		// (keeping its node id): a new node failing step 8 is removed with the security event node_mismatch — here its
		// delete is refused too, so it is only expired; once inventory.sync made the node a device of the member, the
		// next claim on that machine (a re-authentication by then) never accepts it: deleted.
		admin := a.actor("admin", uuid.New())
		ctx := ctxOf(admin, a.id, ActionClaim)
		out, err := f.api.Create(ctx, a.id, admin, NewRequest{Method: MethodWebAuth}, idem("k-uc-1", "uc1"))
		if err != nil {
			t.Fatal(err)
		}
		auth := "hskey-authreq-" + strings.Repeat("U", 23) + "1"
		a.hs.PutPending(auth, devicestest.Node{ID: 4801, MachineKey: "mkey:uc", Hostname: "evil-uc"})
		f.exec(t, `CREATE FUNCTION test_refuse_verdict() RETURNS trigger LANGUAGE plpgsql AS $$
			BEGIN RAISE EXCEPTION 'verdict refused by the test'; END $$`)
		f.exec(t, `CREATE TRIGGER test_refuse_verdict BEFORE UPDATE ON enrollment_requests FOR EACH ROW
			WHEN (OLD.id = '`+out.Request.ID.String()+`'::uuid AND OLD.status = 'registered') EXECUTE FUNCTION test_refuse_verdict()`)
		a.hs.Refuse(devicestest.OpDeleteNode, true)
		a.hs.Refuse(devicestest.OpExpireNode, true)
		_, _ = f.api.Claim(ctx, a.id, admin, Claim{AuthID: auth})
		a.hs.Refuse(devicestest.OpDeleteNode, false)
		a.hs.Refuse(devicestest.OpExpireNode, false)
		f.exec(t, `DROP TRIGGER test_refuse_verdict ON enrollment_requests`)
		f.exec(t, `DROP FUNCTION test_refuse_verdict()`)
		if st := f.str(t, `SELECT status FROM enrollment_requests WHERE id = $1`, out.Request.ID); st != StatusRegistered {
			t.Fatalf("stopped claim: request %s, want %s", st, StatusRegistered)
		}
		f.exec(t, `UPDATE enrollment_requests SET claimed_at = claimed_at - interval '20 minutes' WHERE id = $1`, out.Request.ID)
		a.hs.Refuse(devicestest.OpDeleteNode, true)
		rep, err := f.wrk.Reconcile(t.Context(), a.id)
		a.hs.Refuse(devicestest.OpDeleteNode, false)
		if err != nil || rep.Removed != 0 {
			t.Fatalf("reconcile %+v %v", rep, err)
		}
		if st := f.str(t, `SELECT status || '/' || COALESCE(failure_code, '') || '/' || COALESCE(consumed_node_id::text, '')
			FROM enrollment_requests WHERE id = $1`, out.Request.ID); st != StatusFailed+"/"+FailureClaimUnfinished+"/4801" {
			t.Fatalf("reconcile: %s", st)
		}
		if n, ok := a.hs.Node(4801); !ok || n.Expiry == nil || n.Expiry.After(f.clk.now()) {
			t.Fatalf("reconcile left the unverified node of the stopped claim active: %+v %v", n, ok)
		}
		if k := f.count(t, `SELECT count(*) FROM security_events WHERE tenant_id = $1 AND kind = $2
			AND details->>'request_id' = $3 AND details->>'found_by' = 'reconcile'`, a.id, EventNodeMismatch,
			out.Request.ID.String()); k != 1 {
			t.Fatalf("security events of the node reconcile rejected: %d", k)
		}
		// later: inventory.sync adopted the node as the member's device; the same machine signs in again
		f.exec(t, `UPDATE enrollment_requests SET created_at = created_at - interval '1 hour' WHERE id = $1`, out.Request.ID)
		n, ok := a.hs.Node(4801)
		if !ok {
			t.Fatal("the node of the stopped claim is gone")
		}
		n.CreatedAt = time.Now().Add(-30 * time.Minute)
		a.hs.PutNode(n)
		f.exec(t, `INSERT INTO device_inventory_cache (tenant_id, instance_id, headscale_node_id, machine_key, name,
			owner_membership_id) VALUES ($1, $2, 4801, 'mkey:uc', 'evil-uc', $3)`, a.id, a.instance, admin.MembershipID)
		if _, err := f.api.Create(ctx, a.id, admin, NewRequest{Method: MethodWebAuth}, idem("k-uc-2", "uc2")); err != nil {
			t.Fatal(err)
		}
		auth = "hskey-authreq-" + strings.Repeat("U", 23) + "2"
		a.hs.PutPending(auth, devicestest.Node{MachineKey: "mkey:uc", Hostname: "evil-uc"})
		r, err := f.api.Claim(ctx, a.id, admin, Claim{AuthID: auth})
		if err != nil || r.Status != StatusFailed || failureOf(r) != FailureNodeMismatch || r.NodeID == nil || *r.NodeID != 4801 {
			t.Errorf("re-authentication of the node of a stopped claim: %s/%s node %v %v, want failed/%s node 4801",
				r.Status, failureOf(r), r.NodeID, err, FailureNodeMismatch)
		}
		if _, ok := a.hs.Node(4801); ok {
			t.Error("the node of the stopped claim was not deleted on re-authentication")
		}
	})

	t.Run("UnfinishedClaimValidNode", func(t *testing.T) {
		// C1 (regression of 6849d26): a claim of the member's own device (hostname mg-<code>) stops after recording
		// registered. Reconcile checks the node — it passes — and closes the request claim_unfinished without touching it;
		// a lost answer of another claim of the member (reprotect) leaves it alone, and the next claim on that machine is
		// a re-authentication: verified, the node kept. A valid node of an unfinished claim is never taken for a rejected
		// one.
		admin := a.actor("admin", uuid.New())
		ctx := ctxOf(admin, a.id, ActionClaim)
		out, err := f.api.Create(ctx, a.id, admin, NewRequest{Method: MethodWebAuth}, idem("k-ucv-1", "ucv1"))
		if err != nil {
			t.Fatal(err)
		}
		host := HostnamePrefix + out.Credential.EnrollCode.Reveal()
		auth := "hskey-authreq-" + strings.Repeat("V", 23) + "1"
		a.hs.PutPending(auth, devicestest.Node{ID: 4821, MachineKey: "mkey:ucv", Hostname: host})
		f.exec(t, `CREATE FUNCTION test_refuse_verdict() RETURNS trigger LANGUAGE plpgsql AS $$
			BEGIN RAISE EXCEPTION 'verdict refused by the test'; END $$`)
		f.exec(t, `CREATE TRIGGER test_refuse_verdict BEFORE UPDATE ON enrollment_requests FOR EACH ROW
			WHEN (OLD.id = '`+out.Request.ID.String()+`'::uuid AND OLD.status = 'registered') EXECUTE FUNCTION test_refuse_verdict()`)
		_, _ = f.api.Claim(ctx, a.id, admin, Claim{AuthID: auth})
		f.exec(t, `DROP TRIGGER test_refuse_verdict ON enrollment_requests`)
		f.exec(t, `DROP FUNCTION test_refuse_verdict()`)
		if st := f.str(t, `SELECT status FROM enrollment_requests WHERE id = $1`, out.Request.ID); st != StatusRegistered {
			t.Fatalf("stopped claim: request %s, want %s", st, StatusRegistered)
		}
		f.exec(t, `UPDATE enrollment_requests SET claimed_at = claimed_at - interval '20 minutes' WHERE id = $1`, out.Request.ID)
		rep, err := f.wrk.Reconcile(t.Context(), a.id)
		if err != nil || rep.Removed != 0 {
			t.Fatalf("reconcile %+v %v", rep, err)
		}
		if st := f.str(t, `SELECT status || '/' || COALESCE(failure_code, '') || '/' || COALESCE(consumed_node_id::text, '')
			FROM enrollment_requests WHERE id = $1`, out.Request.ID); st != StatusFailed+"/"+FailureClaimUnfinished+"/4821" {
			t.Fatalf("reconcile: %s", st)
		}
		if n, ok := a.hs.Node(4821); !ok || n.Expiry != nil {
			t.Fatalf("reconcile touched the requester's device: %+v %v", n, ok)
		}
		if k := f.count(t, `SELECT count(*) FROM security_events WHERE tenant_id = $1 AND details->>'request_id' = $2`,
			a.id, out.Request.ID.String()); k != 0 {
			t.Fatalf("security events for the requester's device: %d", k)
		}
		// later (the request and its node are older than what follows)
		n, _ := a.hs.Node(4821)
		n.CreatedAt = time.Now().Add(-30 * time.Minute)
		a.hs.PutNode(n)
		f.exec(t, `UPDATE enrollment_requests SET created_at = created_at - interval '1 hour' WHERE id = $1`, out.Request.ID)
		// another claim of the member loses its answer and finds nothing new: reprotect keeps the valid node
		other, err := f.api.Create(ctx, a.id, admin, NewRequest{Method: MethodWebAuth}, idem("k-ucv-2", "ucv2"))
		if err != nil {
			t.Fatal(err)
		}
		a.hs.LoseAnswer(devicestest.OpAuthRegister, true)
		_, err = f.api.Claim(ctx, a.id, admin, Claim{AuthID: "hskey-authreq-" + strings.Repeat("V", 23) + "2",
			RequestID: &other.Request.ID})
		a.hs.LoseAnswer(devicestest.OpAuthRegister, false)
		if codeOf(err) != CodeInstanceUnavailable {
			t.Fatalf("lost answer: %v", err)
		}
		if _, ok := a.hs.Node(4821); !ok {
			t.Fatal("a lost answer of another claim deleted the requester's device (reprotect)")
		}
		// inventory.sync adopted the node as the member's device; the same machine signs in again
		f.exec(t, `INSERT INTO device_inventory_cache (tenant_id, instance_id, headscale_node_id, machine_key, name,
			owner_membership_id) VALUES ($1, $2, 4821, 'mkey:ucv', $3, $4)`, a.id, a.instance, host, admin.MembershipID)
		again, err := f.api.Create(ctx, a.id, admin, NewRequest{Method: MethodWebAuth}, idem("k-ucv-3", "ucv3"))
		if err != nil {
			t.Fatal(err)
		}
		auth = "hskey-authreq-" + strings.Repeat("V", 23) + "3"
		a.hs.PutPending(auth, devicestest.Node{MachineKey: "mkey:ucv", Hostname: HostnamePrefix + again.Credential.EnrollCode.Reveal()})
		r, err := f.api.Claim(ctx, a.id, admin, Claim{AuthID: auth, RequestID: &again.Request.ID})
		if err != nil || r.Status != StatusVerified || r.NodeID == nil || *r.NodeID != 4821 {
			t.Errorf("re-authentication of the requester's device of a stopped claim: %s/%s node %v %v, want verified node 4821",
				r.Status, failureOf(r), r.NodeID, err)
		}
		if _, ok := a.hs.Node(4821); !ok {
			t.Error("the requester's device of a stopped claim was deleted on re-authentication")
		}
	})

	t.Run("StuckClaimedRequest", func(t *testing.T) {
		// C1 (5): a claim stops before it records registered (the process died while AuthRegister was in flight, or the
		// claim could not tell): the request is left claimed without a node id while Headscale registered a node. Before
		// reconcile closes the request claim_unfinished, it finds that node as a lost answer does (registeredBy): a node
		// failing the checks of step 8 is deleted with the security event node_mismatch, the requester's device
		// (mg-<code>) is kept — either is recorded on the request.
		admin := a.actor("admin", uuid.New())
		ctx := ctxOf(admin, a.id, ActionClaim)
		left := func(key, auth string) Issue {
			t.Helper()
			out, err := f.api.Create(ctx, a.id, admin, NewRequest{Method: MethodWebAuth}, idem(key, key))
			if err != nil {
				t.Fatal(err)
			}
			a.hs.LoseAnswer(devicestest.OpAuthRegister, true)
			_, err = f.api.Claim(ctx, a.id, admin, Claim{AuthID: auth, RequestID: &out.Request.ID})
			a.hs.LoseAnswer(devicestest.OpAuthRegister, false)
			if st := f.str(t, `SELECT status FROM enrollment_requests WHERE id = $1`, out.Request.ID); st != StatusClaimed {
				t.Fatalf("claim left: %s %v", st, err)
			}
			return out
		}
		bad := left("k-sc-1", "hskey-authreq-"+strings.Repeat("S", 23)+"1")
		good := left("k-sc-2", "hskey-authreq-"+strings.Repeat("S", 23)+"2")
		claimedAt := func(id uuid.UUID) time.Time {
			f.exec(t, `UPDATE enrollment_requests SET claimed_at = claimed_at - interval '20 minutes' WHERE id = $1`, id)
			var at time.Time
			f.scan(t, `SELECT claimed_at FROM enrollment_requests WHERE id = $1`, []any{id}, &at)
			return at
		}
		goodHost := HostnamePrefix + good.Credential.EnrollCode.Reveal()
		// what Headscale applied after the claims gave up: one node of the member for each
		a.hs.PutNode(devicestest.Node{ID: 4831, MachineKey: "mkey:sc-bad", Hostname: "evil-sc", GivenName: "evil-sc",
			UserName: un(admin), Method: "cli", CreatedAt: claimedAt(bad.Request.ID).Add(2 * time.Second)})
		a.hs.PutNode(devicestest.Node{ID: 4832, MachineKey: "mkey:sc-good", Hostname: goodHost, GivenName: goodHost,
			UserName: un(admin), Method: "cli", CreatedAt: claimedAt(good.Request.ID).Add(3 * time.Second)})
		rep, err := f.wrk.Reconcile(t.Context(), a.id)
		if err != nil || rep.Removed != 1 {
			t.Fatalf("reconcile %+v %v", rep, err)
		}
		state := func(id uuid.UUID) string {
			return f.str(t, `SELECT status || '/' || COALESCE(failure_code, '') || '/' || COALESCE(consumed_node_id::text, '')
				FROM enrollment_requests WHERE id = $1`, id)
		}
		if st := state(bad.Request.ID); st != StatusFailed+"/"+FailureClaimUnfinished+"/4831" {
			t.Errorf("stuck claim with a node failing the checks: %s", st)
		}
		if _, ok := a.hs.Node(4831); ok {
			t.Error("the node failing the checks of a stuck claim was not deleted")
		}
		if k := f.count(t, `SELECT count(*) FROM security_events WHERE tenant_id = $1 AND kind = $2
			AND details->>'request_id' = $3`, a.id, EventNodeMismatch, bad.Request.ID.String()); k != 1 {
			t.Errorf("security events of the stuck claim's node: %d", k)
		}
		if st := state(good.Request.ID); st != StatusFailed+"/"+FailureClaimUnfinished+"/4832" {
			t.Errorf("stuck claim of the requester's device: %s", st)
		}
		if n, ok := a.hs.Node(4832); !ok || n.Expiry != nil {
			t.Errorf("reconcile touched the requester's device of a stuck claim: %+v %v", n, ok)
		}
		if k := f.count(t, `SELECT count(*) FROM security_events WHERE tenant_id = $1 AND details->>'request_id' = $2`,
			a.id, good.Request.ID.String()); k != 0 {
			t.Errorf("security events for the requester's device: %d", k)
		}
	})

	t.Run("ClaimMeetsConcurrentSync", func(t *testing.T) {
		// B2: an inventory.sync whose snapshot already lists the new node inserts the node's row while the claim's
		// verified transaction runs (not committed yet, so LockLiveDeviceOfNode does not see it). The claim's insert waits
		// for the sync and meets its row on the live-node key (23505): the claim links that row — a device registered
		// legitimately is never failed record_failed for it.
		admin := a.actor("admin", uuid.New())
		ctx := ctxOf(admin, a.id, ActionClaim)
		out, err := f.api.Create(ctx, a.id, admin, NewRequest{Method: MethodWebAuth}, idem("k-b2", "b2"))
		if err != nil {
			t.Fatal(err)
		}
		const node = 4242
		auth := "hskey-authreq-" + strings.Repeat("R", 24)
		a.hs.PutPending(auth, devicestest.Node{ID: node, MachineKey: "mkey:b2", Hostname: "mg-" + out.Credential.EnrollCode.Reveal()})
		sync := f.env.Admin(t, f.db)
		var pid int
		if err := sync.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
			t.Fatal(err)
		}
		tx, err := sync.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(context.Background()) }()
		if _, err := tx.Exec(ctx, `INSERT INTO device_inventory_cache (tenant_id, instance_id, headscale_node_id, machine_key,
			name, owner_membership_id) VALUES ($1, $2, $3, 'mkey:b2', 'synced', $4)`, a.id, a.instance, node,
			admin.MembershipID); err != nil {
			t.Fatal(err)
		}
		type result struct {
			r   Request
			err error
		}
		done := make(chan result, 1)
		go func() {
			r, err := f.api.Claim(ctx, a.id, admin, Claim{AuthID: auth})
			done <- result{r, err}
		}()
		for deadline := time.Now().Add(20 * time.Second); f.count(t,
			`SELECT count(*) FROM pg_stat_activity WHERE $1::int = ANY (pg_blocking_pids(pid))`, pid) == 0; {
			if time.Now().After(deadline) {
				t.Fatal("the claim's insert never waited for the sync's row")
			}
			time.Sleep(10 * time.Millisecond)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		res := <-done
		if res.err != nil || res.r.Status != StatusVerified || res.r.NodeID == nil || *res.r.NodeID != node {
			t.Fatalf("claim during a sync: %+v %v, want verified node %d", res.r, res.err, node)
		}
		if k := f.count(t, `SELECT count(*) FROM device_inventory_cache WHERE instance_id = $1 AND headscale_node_id = $2
			AND removed_at IS NULL AND name = 'synced' AND enrollment_request_id = $3`, a.instance, node, out.Request.ID); k != 1 {
			t.Fatalf("the sync's row was not linked to the claim (%d)", k)
		}
	})

	t.Run("CrossTenantClaim", func(t *testing.T) {
		// IT-13 (AC-14): an Auth ID of tenant A's instance sent to tenant B's claim endpoint is refused, no node in either
		ua := a.actor("operator", uuid.New())
		out, err := f.api.Create(ctxOf(ua, a.id, ActionRequest), a.id, ua, NewRequest{Method: MethodWebAuth}, idem("k-x-1", "x"))
		if err != nil {
			t.Fatal(err)
		}
		authA := "hskey-authreq-" + strings.Repeat("F", 24)
		a.hs.PutPending(authA, devicestest.Node{MachineKey: "mkey:x", Hostname: "mg-" + out.Credential.EnrollCode.Reveal()})
		ub := f.b.actor("operator", ua.SessionID) // even with the same session id
		before := len(a.hs.Nodes()) + len(f.b.hs.Nodes())
		a.hs.ResetCalls()
		f.b.hs.ResetCalls()
		if _, err := f.api.Claim(ctxOf(ub, f.b.id, ActionClaim), f.b.id, ub, Claim{AuthID: authA}); reasonOf(err) != "no_pending_request" {
			t.Fatalf("cross-tenant claim: %v", err)
		}
		if a.hs.Calls(devicestest.OpAuthRegister)+f.b.hs.Calls(devicestest.OpAuthRegister) != 0 ||
			len(a.hs.Nodes())+len(f.b.hs.Nodes()) != before {
			t.Fatal("a cross-tenant claim reached Headscale")
		}
		// tenant B cannot read, approve, start or revoke A's request (404)
		if _, err := f.api.Get(t.Context(), f.b.id, out.Request.ID, ub); codeOf(err) != CodeNotFound {
			t.Fatalf("get cross: %v", err)
		}
		if _, err := f.api.Revoke(t.Context(), f.b.id, out.Request.ID, ub); codeOf(err) != CodeNotFound {
			t.Fatalf("revoke cross: %v", err)
		}
	})

	t.Run("ApprovalBeforeDevice", func(t *testing.T) {
		f.setting(t, a, "enrollment,requires_approval", "true")
		defer f.setting(t, a, "enrollment,requires_approval", "false")
		sess := uuid.New()
		user := a.actor("user", sess)
		ctx := ctxOf(user, a.id, ActionRequest)
		out, err := f.api.Create(ctx, a.id, user, NewRequest{Method: MethodWebAuth}, idem("k-a-1", "a"))
		if err != nil || out.Request.Status != StatusPendingApproval || out.Credential != nil {
			t.Fatalf("pending: %+v %v", out, err)
		}
		// no code yet: a claim finds nothing pending; /start before the decision ⇒ 409
		if _, err := f.api.Claim(ctx, a.id, user, Claim{AuthID: "hskey-authreq-" + strings.Repeat("G", 24)}); reasonOf(err) != "no_pending_request" {
			t.Fatalf("claim before approval: %v", err)
		}
		if _, err := f.api.Start(ctx, a.id, out.Request.ID, user); reasonOf(err) != "not_approved" {
			t.Fatalf("start before approval: %v", err)
		}
		// a member who can approve does not wait
		op := a.actor("operator", uuid.New())
		if o, err := f.api.Create(ctx, a.id, op, NewRequest{Method: MethodWebAuth}, idem("k-a-2", "b")); err != nil || o.Credential == nil {
			t.Fatalf("approver's own request: %+v %v", o, err)
		}
		// the requester cannot decide its own request (CHECK of 0020 too)
		self := user
		self.CanApprove = true
		if _, err := f.api.Approve(ctx, a.id, out.Request.ID, self); reasonOf(err) != "self_approval" {
			t.Fatalf("self approval: %v", err)
		}
		decisions := func(id uuid.UUID) []string {
			return f.list(t, `SELECT kind || '|' || recipient_membership_id || '|' || COALESCE(payload->>'decided_by', '') || '|' ||
					(payload ? 'expires_at')::text FROM notification_outbox
				WHERE tenant_id = $1 AND payload->>'request_id' = $2 ORDER BY created_at, id`, a.id, id.String())
		}
		if got := decisions(out.Request.ID); len(got) != 0 {
			t.Fatalf("notified before the decision: %v", got)
		}
		r, err := f.api.Approve(ctx, a.id, out.Request.ID, a.actor("admin", uuid.New()))
		if err != nil || r.Status != StatusApproved || r.Approver == nil {
			t.Fatalf("approve: %+v %v", r, err)
		}
		// §7.4: the requester — and only the requester — is told, in the decision's transaction
		if got := decisions(out.Request.ID); !slices.Equal(got, []string{"enrollment.approved|" + user.MembershipID.String() + "|admin|true"}) {
			t.Fatalf("approval notification %v", got)
		}
		if _, err := f.api.Approve(ctx, a.id, out.Request.ID, a.actor("owner", uuid.New())); reasonOf(err) != "not_pending_approval" {
			t.Fatalf("approve twice: %v", err)
		}
		if got := decisions(out.Request.ID); len(got) != 1 {
			t.Fatalf("a refused second decision notified: %v", got)
		}
		if _, err := f.api.Start(ctx, a.id, out.Request.ID, a.actor("user2", uuid.New())); reasonOf(err) != "not_requester" {
			t.Fatalf("start by another member: %v", err)
		}
		iss, err := f.api.Start(ctx, a.id, out.Request.ID, user)
		if err != nil || iss.Credential == nil || iss.Request.Status != StatusIssued {
			t.Fatalf("start: %+v %v", iss, err)
		}
		if _, err := f.api.Start(ctx, a.id, out.Request.ID, user); reasonOf(err) != "already_started" {
			t.Fatalf("start twice: %v", err)
		}
		// reject; then the 24-hour window of a pending request (reconcile)
		rej, err := f.api.Create(ctx, a.id, user, NewRequest{Method: MethodPreauthKey}, idem("k-a-3", "c"))
		if err != nil {
			t.Fatal(err)
		}
		if r, err := f.api.Reject(ctx, a.id, rej.Request.ID, a.actor("owner", uuid.New())); err != nil || r.Status != StatusRejected {
			t.Fatalf("reject: %+v %v", r, err)
		}
		if got := decisions(rej.Request.ID); !slices.Equal(got, []string{"enrollment.rejected|" + user.MembershipID.String() + "|owner|false"}) {
			t.Fatalf("rejection notification %v", got)
		}
		stale, err := f.api.Create(ctx, a.id, user, NewRequest{Method: MethodWebAuth}, idem("k-a-4", "d"))
		if err != nil {
			t.Fatal(err)
		}
		f.exec(t, `UPDATE enrollment_requests SET created_at = now() - interval '25 hours' WHERE id = $1`, stale.Request.ID)
		if _, err := f.wrk.Reconcile(t.Context(), a.id); err != nil {
			t.Fatal(err)
		}
		if st := f.str(t, `SELECT status FROM enrollment_requests WHERE id = $1`, stale.Request.ID); st != StatusExpired {
			t.Fatalf("stale pending: %s", st)
		}
	})

	t.Run("PrivilegedKeysAndRevoke", func(t *testing.T) {
		admin := a.actor("admin", uuid.New())
		ctx := ctxOf(admin, a.id, ActionKeyCreate)
		if _, err := f.api.CreateKey(ctx, a.id, admin, NewKey{Tags: []string{"tag:unknown"}}, idem("k-p-1", "1")); codeOf(err) != CodeValidationFailed {
			t.Fatalf("tag outside the catalog: %v", err)
		}
		if _, err := f.api.CreateKey(ctx, a.id, admin, NewKey{}, idem("k-p-2", "2")); reasonOf(err) != "tags_required" {
			t.Fatalf("tag-only without tags: %v", err)
		}
		f.exec(t, `UPDATE tenant_memberships SET status = 'locked' WHERE id = $1`, a.people["viewer"].membership)
		v := a.people["viewer"].membership
		if _, err := f.api.CreateKey(ctx, a.id, admin, NewKey{Target: &v}, idem("k-p-3", "3")); reasonOf(err) != "member_not_active" {
			t.Fatalf("inactive target: %v", err)
		}
		out, err := f.api.CreateKey(ctx, a.id, admin, NewKey{Tags: []string{"tag:server"}, Reusable: true, Ephemeral: true},
			idem("k-p-4", "4"))
		if err != nil || out.Request.Target != nil || !slices.Equal(out.Request.Tags, []string{"tag:server"}) {
			t.Fatalf("tag-only key: %+v %v", out, err)
		}
		keys := a.hs.Keys()
		k := keys[len(keys)-1]
		if !k.Reusable || k.UserID != 0 || !slices.Equal(k.Tags, []string{"tag:server"}) {
			t.Fatalf("key at Headscale %+v", k)
		}
		// the tag is now referenced by a live key: the catalog refuses to delete it (P4-T15 reference count)
		if n := f.count(t, `SELECT count(*) FROM enrollment_requests WHERE tenant_id = $1 AND 'tag:server' = ANY (requested_tags)
			AND status = 'credential_issued'`, a.id); n != 1 {
			t.Fatalf("live tagged keys %d", n)
		}
		// End User: another member's request does not exist for it
		eu := a.actor("user", uuid.New())
		if _, err := f.api.Revoke(ctx, a.id, out.Request.ID, eu); codeOf(err) != CodeNotFound {
			t.Fatalf("EU revoke of another's: %v", err)
		}
		r, err := f.api.Revoke(ctxOf(admin, a.id, ActionRevoke), a.id, out.Request.ID, admin)
		if err != nil || r.Status != StatusRevoked {
			t.Fatalf("revoke: %+v %v", r, err)
		}
		if k := a.hs.Key(k.ID); k.Expiration.After(time.Now().Add(time.Second)) {
			t.Fatalf("key not expired at Headscale: %+v", k)
		}
		if got := f.auditOf(t, r.ID.String()); !slices.Contains(got, "enrollment.revoke.succeeded/success") {
			t.Fatalf("audit %v", got)
		}
		if _, err := f.api.Revoke(ctx, a.id, out.Request.ID, admin); reasonOf(err) != "already_final" {
			t.Fatalf("revoke twice: %v", err)
		}
		// Headscale down: the revoke fails closed (503) and the request stays revocable
		out2, err := f.api.CreateKey(ctx, a.id, admin, NewKey{Tags: []string{"tag:server"}}, idem("k-p-5", "5"))
		if err != nil {
			t.Fatal(err)
		}
		a.hs.SetDown(true)
		if _, err := f.api.Revoke(ctx, a.id, out2.Request.ID, admin); codeOf(err) != CodeInstanceUnavailable {
			t.Fatalf("revoke while down: %v", err)
		}
		a.hs.SetDown(false)
		if st := f.str(t, `SELECT status FROM enrollment_requests WHERE id = $1`, out2.Request.ID); st != StatusCredentialIssued {
			t.Fatalf("status after a failed revoke: %s", st)
		}
		f.noKeyMaterial(t)
	})

	t.Run("Quota", func(t *testing.T) {
		b := f.b
		owner := b.actor("owner", uuid.New())
		ctx := ctxOf(owner, b.id, ActionRequest)
		f.exec(t, `INSERT INTO device_inventory_cache (tenant_id, instance_id, headscale_node_id, machine_key, name)
			VALUES ($1, $2, 5, 'mkey:q', 'q')`, b.id, b.instance)
		f.exec(t, `UPDATE subscriptions SET overrides = '{"max_devices": 2}' WHERE tenant_id = $1`, b.id)
		if _, err := f.api.Create(ctx, b.id, owner, NewRequest{Method: MethodWebAuth}, idem("k-q-1", "1")); err != nil {
			t.Fatal(err)
		}
		// 1 device + 1 open request = 2: one more would exceed max_devices
		if _, err := f.api.Create(ctx, b.id, owner, NewRequest{Method: MethodWebAuth}, idem("k-q-2", "2")); codeOf(err) != "quota_exceeded:devices" {
			t.Fatalf("devices quota: %v", err)
		}
		f.exec(t, `UPDATE subscriptions SET overrides = '{"max_devices": 50, "max_live_enrollment_credentials": 1}' WHERE tenant_id = $1`, b.id)
		if _, err := f.api.Create(ctx, b.id, owner, NewRequest{Method: MethodWebAuth}, idem("k-q-3", "3")); codeOf(err) != "quota_exceeded:enrollment_credentials" {
			t.Fatalf("credentials quota: %v", err)
		}
		if n := f.count(t, `SELECT count(*) FROM enrollment_requests WHERE tenant_id = $1`, b.id); n != 1 {
			t.Fatalf("a refused request was written: %d", n)
		}
	})

	t.Run("TaggedDevicesQuota", func(t *testing.T) {
		// PlanLimits.max_tagged_devices (P4-T06 follow-up): tagged devices of the inventory + open requests with tags,
		// counted under the subscription's row lock in the transaction that creates the key
		b := f.b
		admin := b.actor("admin", uuid.New())
		ctx := ctxOf(admin, b.id, ActionKeyCreate)
		f.exec(t, `UPDATE subscriptions SET overrides = '{"max_devices": 50, "max_live_enrollment_credentials": 50,
			"max_tagged_devices": 3}' WHERE tenant_id = $1`, b.id)
		f.exec(t, `INSERT INTO device_inventory_cache (tenant_id, instance_id, headscale_node_id, machine_key, name, tags)
			VALUES ($1, $2, 11, 'mkey:tagged', 'tagged-1', '{tag:server}'), ($1, $2, 12, 'mkey:personal', 'personal-1', '{}')`,
			b.id, b.instance)
		tagged := NewKey{Tags: []string{"tag:server"}}
		k1, err := f.api.CreateKey(ctx, b.id, admin, tagged, idem("k-t-1", "1"))
		if err != nil {
			t.Fatal(err)
		}
		k2, err := f.api.CreateKey(ctx, b.id, admin, tagged, idem("k-t-2", "2")) // 1 device + 1 open + 1 = 3
		if err != nil {
			t.Fatal(err)
		}
		keysBefore := len(b.hs.Keys())
		if _, err := f.api.CreateKey(ctx, b.id, admin, tagged, idem("k-t-3", "3")); codeOf(err) != "quota_exceeded:tagged_devices" {
			t.Fatalf("tagged quota: %v", err)
		}
		if n := len(b.hs.Keys()); n != keysBefore {
			t.Fatalf("a refused key reached Headscale: %d keys", n)
		}
		// a key without tags is not a tagged device; the personal device of the inventory did not count either
		target := b.people["user"].membership
		if _, err := f.api.CreateKey(ctx, b.id, admin, NewKey{Target: &target}, idem("k-t-4", "4")); err != nil {
			t.Fatalf("untagged key under a full tagged quota: %v", err)
		}
		if n := f.count(t, `SELECT count(*) FROM enrollment_requests WHERE tenant_id = $1 AND cardinality(requested_tags) > 0`, b.id); n != 2 {
			t.Fatalf("tagged requests written %d", n)
		}
		// revoked keys free their place; concurrent creations serialise on the subscription row: with 2 places left,
		// exactly 2 of 6 pass
		for _, k := range []Issue{k1, k2} {
			if _, err := f.api.Revoke(ctxOf(admin, b.id, ActionRevoke), b.id, k.Request.ID, admin); err != nil {
				t.Fatalf("revoke: %v", err)
			}
		}
		var (
			wg        sync.WaitGroup
			mu        sync.Mutex
			ok, quota int
			others    []string
		)
		for i := range 6 {
			wg.Go(func() {
				_, err := f.api.CreateKey(ctx, b.id, admin, tagged, idem(fmt.Sprintf("k-t-c%d", i), fmt.Sprint(i)))
				mu.Lock()
				defer mu.Unlock()
				switch c := codeOf(err); c {
				case "":
					ok++
				case "quota_exceeded:tagged_devices":
					quota++
				default:
					others = append(others, c)
				}
			})
		}
		wg.Wait()
		if ok != 2 || quota != 4 || len(others) > 0 {
			t.Fatalf("concurrent tagged keys: %d ok, %d refused, others %v; want 2 and 4", ok, quota, others)
		}
		f.noKeyMaterial(t)
	})

	// T-06 (§18.1, P5-T09): a tenant that switches web-auth off refuses a new web-auth request and the claim of a code
	// issued before the switch — before Headscale is called; a pre-auth key is still issued.
	t.Run("WebAuthDisabled", func(t *testing.T) {
		f.setting(t, a, "enrollment,self_enroll", "true") // the End User enrolls its own device (also when run alone)
		sess := uuid.New()
		user := a.actor("user", sess)
		label := "laptop-off"
		out, err := f.api.Create(ctxOf(user, a.id, ActionRequest), a.id, user,
			NewRequest{Method: MethodWebAuth, DeviceLabel: &label}, idem("k-woff-1", "woff-1"))
		if err != nil {
			t.Fatal(err)
		}
		code := out.Credential.EnrollCode.Reveal()
		f.setting(t, a, "enrollment,web_auth_enabled", "false")
		defer f.setting(t, a, "enrollment,web_auth_enabled", "true")
		if _, err := f.api.Create(ctxOf(user, a.id, ActionRequest), a.id, user,
			NewRequest{Method: MethodWebAuth, DeviceLabel: &label}, idem("k-woff-2", "woff-2")); reasonOf(err) != "web_auth_disabled" {
			t.Fatalf("web-auth request while disabled: %v", err)
		}
		authID := "hskey-authreq-" + strings.Repeat("D", 23) + "1"
		a.hs.PutPending(authID, devicestest.Node{MachineKey: "mkey:woff", Hostname: "mg-" + code})
		a.hs.ResetCalls()
		if _, err := f.api.Claim(ctxOf(user, a.id, ActionClaim), a.id, user, Claim{AuthID: authID}); reasonOf(err) != "web_auth_disabled" {
			t.Fatalf("claim while disabled: %v", err)
		}
		if n := a.hs.Calls(devicestest.OpAuthRegister); n != 0 {
			t.Fatalf("AuthRegister called %d times while web-auth is disabled", n)
		}
		if k := f.count(t, `SELECT count(*) FROM enrollment_requests WHERE id = $1 AND status = 'claimed'`, out.Request.ID); k != 0 {
			t.Fatal("the request was claimed while web-auth is disabled")
		}
		if _, err := f.api.Create(ctxOf(user, a.id, ActionRequest), a.id, user,
			NewRequest{Method: MethodPreauthKey, DeviceLabel: &label}, idem("k-woff-3", "woff-3")); err != nil {
			t.Fatalf("pre-auth key while web-auth is disabled: %v", err)
		}
	})

	t.Run("ListAndInstructions", func(t *testing.T) {
		eu := a.actor("user", uuid.New())
		page, err := f.api.List(t.Context(), a.id, eu, 2, "", "")
		if err != nil || len(page.Items) != 2 || page.NextCursor == "" {
			t.Fatalf("page: %+v %v", page, err)
		}
		all := map[uuid.UUID]bool{}
		for cur := ""; ; {
			p, err := f.api.List(t.Context(), a.id, eu, 2, cur, "")
			if err != nil {
				t.Fatal(err)
			}
			for _, r := range p.Items {
				if r.RequestedBy != eu.MembershipID && (r.Target == nil || *r.Target != eu.MembershipID) {
					t.Fatalf("End User sees another member's request %s", r.ID)
				}
				all[r.ID] = true
			}
			if cur = p.NextCursor; cur == "" {
				break
			}
		}
		if len(all) == 0 {
			t.Fatal("no request listed")
		}
		if _, err := f.api.List(t.Context(), a.id, eu, 10, "", "nope"); codeOf(err) != CodeValidationFailed {
			t.Fatalf("bad status: %v", err)
		}
		in, err := f.api.Instructions(t.Context(), a.id, "linux")
		if err != nil || in.LoginServer != "https://"+a.slug+".mesh.test" || in.WebAuthCommand == nil ||
			in.ManagedEnv["TS_NO_LOGS_NO_SUPPORT"] != "true" {
			t.Fatalf("instructions %+v %v", in, err)
		}
		if in, err := f.api.Instructions(t.Context(), a.id, "ios"); err != nil || in.WebAuthCommand != nil {
			t.Fatalf("mobile: %+v %v", in, err)
		}
		// G4b-E3: the instructions carry enrollment.self_enroll (the Portal shows an End User why it cannot add a device)
		for _, v := range []string{"false", "true"} {
			f.setting(t, a, "enrollment,self_enroll", v)
			if in, err := f.api.Instructions(t.Context(), a.id, "linux"); err != nil || in.SelfEnroll != (v == "true") {
				t.Fatalf("self_enroll %s: %+v %v", v, in.SelfEnroll, err)
			}
		}
	})

	t.Run("ReconcileJobAndSchedule", func(t *testing.T) {
		sc := f.wrk.NewScheduler(SchedulerConfig{Interval: time.Minute})
		now := time.Now()
		if _, err := sc.Tick(t.Context(), now); err != nil { // first sight: no job
			t.Fatal(err)
		}
		n, err := sc.Tick(t.Context(), now.Add(2*time.Minute))
		if err != nil || n < 1 {
			t.Fatalf("schedule: %d %v", n, err)
		}
		if k := f.count(t, `SELECT count(*) FROM provisioning_jobs WHERE kind = $1`, KindReconcile); k < 1 {
			t.Fatalf("jobs %d", k)
		}
		var id uuid.UUID
		f.scan(t, `SELECT id FROM provisioning_jobs WHERE kind = $1 AND tenant_id = $2 LIMIT 1`, []any{KindReconcile, a.id}, &id)
		run := &jobs.Run{ID: id, Kind: KindReconcile, TenantID: &a.id, Input: []byte(`{}`), Attempt: 1, MaxAttempts: 3,
			Deadline: time.Now().Add(time.Minute), Store: f.wrkSt}
		if err := f.wrk.runReconcile(t.Context(), run); err != nil {
			t.Fatal(err)
		}
	})
}

// TestPreauthDeviceNew — P4-T06 follow-up: a device registered with a pre-auth key enters the inventory with its
// enrollment link and is notified once (device.new: its owner + the Tenant Owners), whether enrollment.reconcile or
// inventory.sync sees the node first; every node of a reusable key while it is live; the schedule keeps running for a
// live reusable key alone.
func TestPreauthDeviceNew(t *testing.T) {
	f := newFixture(t)
	a := f.a
	ctx := t.Context()
	admin := a.actor("admin", uuid.New())
	kctx := ctxOf(admin, a.id, ActionKeyCreate)
	owner, user, user2 := a.people["owner"].membership, a.people["user"].membership, a.people["user2"].membership
	lastKey := func() uint64 { k := a.hs.Keys(); return k[len(k)-1].ID }
	deviceOf := func(node uint64) (id uuid.UUID, req, own string) {
		f.scan(t, `SELECT id, COALESCE(enrollment_request_id::text, ''), COALESCE(owner_membership_id::text, '')
			FROM device_inventory_cache WHERE tenant_id = $1 AND headscale_node_id = $2 AND removed_at IS NULL`,
			[]any{a.id, int64(node)}, &id, &req, &own) //nolint:gosec // small test ids
		return id, req, own
	}

	// 1. a key for a member, used; reconcile sees the node first: the device enters the inventory (owner, link),
	// inventory.sync is enqueued (expiry clamp), device.new goes to the member and the Tenant Owner — not the issuer
	k1, err := f.api.CreateKey(kctx, a.id, admin, NewKey{Target: &user}, idem("dn-1", "1"))
	if err != nil {
		t.Fatal(err)
	}
	n1 := a.hs.UseKey(lastKey(), devicestest.Node{MachineKey: "mkey:dn1", Hostname: "srv-1", GivenName: "srv-1"})
	rep, err := f.wrk.Reconcile(ctx, a.id)
	if err != nil || rep.Consumed != 1 || rep.NewDevices != 1 {
		t.Fatalf("reconcile %+v %v", rep, err)
	}
	d1, req, own := deviceOf(n1.ID)
	if req != k1.Request.ID.String() || own != user.String() {
		t.Fatalf("inventory row: request %s owner %s", req, own)
	}
	if got := f.deviceNew(t, a, d1); !slices.Equal(got, sortedIDs(user, owner)) {
		t.Fatalf("device.new recipients %v", got)
	}
	if k := f.count(t, `SELECT count(*) FROM provisioning_jobs WHERE tenant_id = $1 AND kind = 'inventory.sync'`, a.id); k != 1 {
		t.Fatalf("inventory.sync jobs %d", k)
	}
	// again: nothing new, never twice
	if rep, err := f.wrk.Reconcile(ctx, a.id); err != nil || rep.NewDevices != 0 {
		t.Fatalf("second reconcile %+v %v", rep, err)
	}
	if got := f.deviceNew(t, a, d1); len(got) != 2 {
		t.Fatalf("notified twice: %v", got)
	}

	// 2. inventory.sync first: the node is in the inventory without a link (as sync writes it) ⇒ linked and notified at
	// the consumed transition
	if _, err := f.api.CreateKey(kctx, a.id, admin, NewKey{Target: &user2}, idem("dn-2", "2")); err != nil {
		t.Fatal(err)
	}
	n2 := a.hs.UseKey(lastKey(), devicestest.Node{MachineKey: "mkey:dn2", Hostname: "srv-2"})
	f.exec(t, `INSERT INTO device_inventory_cache (tenant_id, instance_id, headscale_node_id, machine_key, name,
		owner_membership_id) VALUES ($1, $2, $3, $4, 'srv-2', $5)`, a.id, a.instance, int64(n2.ID), n2.MachineKey, user2) //nolint:gosec // small test ids
	if rep, err := f.wrk.Reconcile(ctx, a.id); err != nil || rep.Consumed != 1 || rep.NewDevices != 1 {
		t.Fatalf("reconcile after sync %+v %v", rep, err)
	}
	d2, req, _ := deviceOf(n2.ID)
	if req == "" {
		t.Fatal("the synced row was not linked")
	}
	if got := f.deviceNew(t, a, d2); !slices.Equal(got, sortedIDs(user2, owner)) {
		t.Fatalf("device.new recipients %v", got)
	}

	// 3. a reusable tag-only key: each node it registers while live, once (tagged: no owner — the Tenant Owners only)
	k3, err := f.api.CreateKey(kctx, a.id, admin, NewKey{Tags: []string{"tag:server"}, Reusable: true}, idem("dn-3", "3"))
	if err != nil {
		t.Fatal(err)
	}
	kid := lastKey()
	t1 := a.hs.UseKey(kid, devicestest.Node{MachineKey: "mkey:t1", Hostname: "ci-1"})
	if rep, err := f.wrk.Reconcile(ctx, a.id); err != nil || rep.Consumed != 1 || rep.NewDevices != 1 {
		t.Fatalf("reusable, first node %+v %v", rep, err)
	}
	t2 := a.hs.UseKey(kid, devicestest.Node{MachineKey: "mkey:t2", Hostname: "ci-2"})
	if rep, err := f.wrk.Reconcile(ctx, a.id); err != nil || rep.NewDevices != 1 {
		t.Fatalf("reusable, second node %+v %v", rep, err)
	}
	if rep, err := f.wrk.Reconcile(ctx, a.id); err != nil || rep.NewDevices != 0 {
		t.Fatalf("reusable, nothing new %+v %v", rep, err)
	}
	for _, n := range []devicestest.Node{t1, t2} {
		d, req, own := deviceOf(n.ID)
		if req != k3.Request.ID.String() || own != "" {
			t.Fatalf("tagged row %d: request %s owner %q", n.ID, req, own)
		}
		if got := f.deviceNew(t, a, d); !slices.Equal(got, sortedIDs(owner)) {
			t.Fatalf("tagged device.new recipients %v", got)
		}
	}
	// a reusable key that registered two nodes before reconcile first saw it: both at the consumed transition
	k4, err := f.api.CreateKey(kctx, a.id, admin, NewKey{Tags: []string{"tag:server"}, Reusable: true}, idem("dn-4", "4"))
	if err != nil {
		t.Fatal(err)
	}
	kid4 := lastKey()
	u1 := a.hs.UseKey(kid4, devicestest.Node{MachineKey: "mkey:u1", Hostname: "ci-3"})
	u2 := a.hs.UseKey(kid4, devicestest.Node{MachineKey: "mkey:u2", Hostname: "ci-4"})
	if rep, err := f.wrk.Reconcile(ctx, a.id); err != nil || rep.Consumed != 1 || rep.NewDevices != 2 {
		t.Fatalf("reusable, two nodes at once %+v %v", rep, err)
	}
	for _, n := range []devicestest.Node{u1, u2} {
		d, req, _ := deviceOf(n.ID)
		if got := f.deviceNew(t, a, d); req != k4.Request.ID.String() || !slices.Equal(got, sortedIDs(owner)) {
			t.Fatalf("node %d: request %s, device.new recipients %v", n.ID, req, got)
		}
	}

	// 4. no open request is left, only the live reusable key: the schedule still runs reconcile for this tenant (a third
	// node would be seen); after the key's grace it stops
	if n := f.count(t, `SELECT count(*) FROM enrollment_requests WHERE tenant_id = $1 AND status NOT IN
		('consumed', 'verified', 'expired', 'revoked', 'failed', 'rejected')`, a.id); n != 0 {
		t.Fatalf("open requests %d", n)
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
	if jobsOf(a.id) != 1 || jobsOf(f.b.id) != 0 {
		t.Fatalf("reconcile jobs A %d, B %d", jobsOf(a.id), jobsOf(f.b.id))
	}
	f.clk.advance(time.Hour)
	if _, err := sc.Tick(ctx, now.Add(4*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if jobsOf(a.id) != 1 {
		t.Fatalf("reconcile scheduled after the key's grace: %d jobs", jobsOf(a.id))
	}
	f.noKeyMaterial(t)
}

// failureOf is the failure code of a request ("" when none).
func failureOf(r Request) string {
	if r.FailureCode == nil {
		return ""
	}
	return *r.FailureCode
}

// un is the Headscale user name of an actor.
func un(a Actor) string { return "mg-" + a.MembershipID.String() }
