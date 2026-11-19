package enrollment

import (
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
		// a node that existed before and belongs to someone else (inventory owner): expired, never deleted
		user2 := a.people["user2"]
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

// un is the Headscale user name of an actor.
func un(a Actor) string { return "mg-" + a.MembershipID.String() }
