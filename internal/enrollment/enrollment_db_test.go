package enrollment

import (
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
			VALUES ($1, $2, $3, $4, 'srv-1')`, a.id, a.instance, int64(node.ID), node.MachineKey)
		rep, err := f.wrk.Reconcile(t.Context(), a.id)
		if err != nil || rep.Consumed != 1 || rep.Linked != 1 {
			t.Fatalf("reconcile %+v %v", rep, err)
		}
		r, err := f.api.Get(t.Context(), a.id, out.Request.ID, owner)
		if err != nil || r.Status != StatusConsumed || r.NodeID == nil || *r.NodeID != int64(node.ID) {
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
		n, _ := a.hs.Node(uint64(*r.NodeID))
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
		if _, ok := a.hs.Node(uint64(*r.NodeID)); ok {
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

// un is the Headscale user name of an actor.
func un(a Actor) string { return "mg-" + a.MembershipID.String() }
