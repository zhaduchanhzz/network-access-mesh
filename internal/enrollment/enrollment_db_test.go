package enrollment

import (
	"context"
	"crypto/sha256"
	"slices"
	"strings"
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
		rep, err := f.wrk.Reconcile(t.Context(), a.id)
		if err != nil || rep.Consumed != 1 || rep.Linked != 1 {
			t.Fatalf("reconcile %+v %v", rep, err)
		}
		r, err := f.api.Get(t.Context(), a.id, out.Request.ID, owner)
		if err != nil || r.Status != StatusConsumed || r.NodeID == nil || *r.NodeID != int64(node.ID) { //nolint:gosec // small test ids
			t.Fatalf("consumed: %+v %v", r, err)
		}
		if n := f.count(t, `SELECT count(*) FROM device_inventory_cache WHERE enrollment_request_id = $1`, out.Request.ID); n != 1 {
			t.Fatalf("device link %d", n)
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
		if n := nodesOf("mkey:c1-mine"); err != nil || r.Status != StatusVerified || len(n) != 1 || r.NodeID == nil ||
			*r.NodeID != int64(n[0].ID) { //nolint:gosec // small test ids
			t.Errorf("answer lost, own device: %s %v, nodes %+v", r.Status, err, n)
		}
		if k := f.count(t, `SELECT count(*) FROM device_inventory_cache WHERE enrollment_request_id = $1 AND removed_at IS NULL`,
			mine.Request.ID); k != 1 {
			t.Errorf("answer lost, own device: %d device rows", k)
		}
		// … and a node that is not the requester's device is deleted (node_mismatch)
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

		// (4) the registered node cannot be recorded (the database refuses the write): the node this claim created is
		// deleted, never left for inventory.sync to adopt as the member's device
		norec := create("k-c1-5")
		auth = "hskey-authreq-" + strings.Repeat("Q", 24)
		a.hs.PutPending(auth, devicestest.Node{MachineKey: "mkey:c1-norecord", Hostname: "evil-norecord"})
		f.exec(t, `CREATE FUNCTION test_refuse_write() RETURNS trigger LANGUAGE plpgsql AS $$
			BEGIN RAISE EXCEPTION 'write refused by the test'; END $$`)
		a.hs.After(devicestest.OpAuthRegister, func(uint64) {
			f.exec(t, `CREATE TRIGGER test_refuse_write BEFORE UPDATE ON enrollment_requests FOR EACH ROW
				WHEN (OLD.id = '`+norec.Request.ID.String()+`'::uuid) EXECUTE FUNCTION test_refuse_write()`)
		})
		if _, err := f.api.Claim(ctx, a.id, admin, Claim{AuthID: auth}); err == nil {
			t.Error("no record: the claim succeeded")
		}
		f.exec(t, `DROP TRIGGER test_refuse_write ON enrollment_requests`)
		f.exec(t, `DROP FUNCTION test_refuse_write()`)
		if n := nodesOf("mkey:c1-norecord"); len(n) != 0 {
			t.Errorf("no record: the unverified node was left registered: %+v", n)
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
		r, err := f.api.Approve(ctx, a.id, out.Request.ID, a.actor("admin", uuid.New()))
		if err != nil || r.Status != StatusApproved || r.Approver == nil {
			t.Fatalf("approve: %+v %v", r, err)
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

// failureOf is the failure code of a request ("" when none).
func failureOf(r Request) string {
	if r.FailureCode == nil {
		return ""
	}
	return *r.FailureCode
}

// un is the Headscale user name of an actor.
func un(a Actor) string { return "mg-" + a.MembershipID.String() }
