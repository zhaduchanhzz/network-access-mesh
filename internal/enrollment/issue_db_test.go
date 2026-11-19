package enrollment

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/devices/devicestest"
)

// TestIssueAndRevoke: what an issuance or a revocation stores, and what it finds when another actor moved the request,
// the tenant or the Headscale state meanwhile (regression tests of the adversarial review of P4-T06 — evidence §7). The
// hooks of the fake interleave the other actor at the exact point of the call.
func TestIssueAndRevoke(t *testing.T) {
	f := newFixture(t)
	a := f.a
	admin := a.actor("admin", uuid.New())
	owner := a.actor("owner", uuid.New())
	status := func(t *testing.T, id uuid.UUID) string {
		t.Helper()
		return f.str(t, `SELECT status FROM enrollment_requests WHERE id = $1`, id)
	}
	// latest is the id of the newest request of tenant A in status st (read from inside a hook: no t.Fatal there).
	latest := func(st string) (uuid.UUID, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		var id uuid.UUID
		err := f.su.QueryRow(context.Background(), `SELECT id FROM enrollment_requests WHERE tenant_id = $1 AND status = $2
			ORDER BY created_at DESC, id DESC LIMIT 1`, a.id, st).Scan(&id)
		return id, err
	}
	lastKey := func() devicestest.Key {
		keys := a.hs.Keys()
		return keys[len(keys)-1]
	}

	t.Run("WebAuthReplayHoldsNoCode", func(t *testing.T) {
		// the hostname mg-<code> and the command carry the one-time code: the body an Idempotency-Key replays keeps
		// neither (§13.1 — no secret in the stored body; 0020 keeps only the code's SHA-256); a replay rebuilds both
		label := "phone-r"
		out, err := f.api.Create(ctxOf(owner, a.id, ActionRequest), a.id, owner,
			NewRequest{Method: MethodWebAuth, DeviceLabel: &label}, idem("k-i-0", "0"))
		if err != nil || out.Credential == nil {
			t.Fatalf("web-auth issue: %+v %v", out, err)
		}
		c := out.Credential
		code := c.EnrollCode.Reveal()
		if len(code) != 12 || c.Hostname != HostnamePrefix+code || !strings.HasSuffix(c.Command, " --hostname="+c.Hostname) {
			t.Fatalf("credential %+v", c)
		}
		f.noSecret(t, code)
		again, err := f.api.Create(ctxOf(owner, a.id, ActionRequest), a.id, owner,
			NewRequest{Method: MethodWebAuth, DeviceLabel: &label}, idem("k-i-0", "0"))
		if err != nil || again.Request.ID != out.Request.ID || again.Credential == nil ||
			again.Credential.Kind != CredentialEnrollCode || again.Credential.EnrollCode.Reveal() != code ||
			again.Credential.Hostname != c.Hostname || again.Credential.Command != c.Command ||
			!again.Credential.ExpiresAt.Equal(c.ExpiresAt) {
			t.Fatalf("replay of the web-auth issue: %+v %v", again.Credential, err)
		}
	})

	t.Run("RevokeDuringIssuance", func(t *testing.T) {
		// the row is committed `requested` before the key is created at Headscale; an admin revokes it in that window
		// (no key id yet: /revoke ends it locally) — the issuance must not bring it back nor hand the key out
		var (
			revoked Request
			rerr    error
		)
		a.hs.Before(devicestest.OpCreatePreAuthKey, func(uint64) {
			id, err := latest(StatusRequested)
			if err != nil {
				rerr = err
				return
			}
			revoked, rerr = f.api.Revoke(ctxOf(owner, a.id, ActionRevoke), a.id, id, owner)
		})
		out, err := f.api.CreateKey(ctxOf(admin, a.id, ActionKeyCreate), a.id, admin, NewKey{Tags: []string{"tag:server"}},
			idem("k-i-1", "1"))
		if rerr != nil || revoked.Status != StatusRevoked {
			t.Fatalf("revoke during the issuance: %+v %v", revoked, rerr)
		}
		if codeOf(err) != CodeConflict || reasonOf(err) != "already_final" || out.Credential != nil {
			t.Fatalf("issuance of a revoked request: %+v %v", out, err)
		}
		if st := status(t, revoked.ID); st != StatusRevoked {
			t.Fatalf("status %s, want the revocation kept", st)
		}
		if k := lastKey(); k.Expiration.After(time.Now().Add(time.Second)) {
			t.Fatalf("the key created for the revoked request is still live: %+v", k)
		}
		if got := f.auditOf(t, revoked.ID.String()); !slices.Contains(got, "enrollment.key.create.failed/failure") ||
			slices.Contains(got, "enrollment.key.create.succeeded/success") {
			t.Fatalf("audit %v", got)
		}
	})

	t.Run("SuspendDuringIssuance", func(t *testing.T) {
		// the authorizer let the call through; the tenant is suspended before the key is created — after the
		// suspension's preauthkeys.expire read (P3-T08), so that step never sees the key: the issuance refuses it
		defer f.exec(t, `UPDATE tenants SET status = 'active' WHERE id = $1`, a.id)
		var serr error
		a.hs.Before(devicestest.OpCreatePreAuthKey, func(uint64) {
			f.mu.Lock()
			defer f.mu.Unlock()
			_, serr = f.su.Exec(context.Background(), `UPDATE tenants SET status = 'suspended' WHERE id = $1`, a.id)
		})
		out, err := f.api.Create(ctxOf(owner, a.id, ActionRequest), a.id, owner, NewRequest{Method: MethodPreauthKey},
			idem("k-i-2", "2"))
		if serr != nil {
			t.Fatal(serr)
		}
		if codeOf(err) != "tenant_suspended" || out.Credential != nil {
			t.Fatalf("issuance on a tenant suspended meanwhile: %+v %v", out, err)
		}
		if k := lastKey(); k.Expiration.After(time.Now().Add(time.Second)) {
			t.Fatalf("a key outlives the suspension: %+v", k)
		}
		id, err := latest(StatusFailed)
		if err != nil {
			t.Fatal(err)
		}
		if code := f.str(t, `SELECT failure_code FROM enrollment_requests WHERE id = $1`, id); code != "tenant_suspended" {
			t.Fatalf("failure_code %s", code)
		}
	})

	t.Run("RevokeUsedKey", func(t *testing.T) {
		// a single-use key used at once, revoked before reconcile ran: the revocation answers 409 already_final (the
		// device is revoked through /devices) and leaves the request to reconcile, which records it consumed with its
		// node and links the device row — never revoked with the device forgotten
		out, err := f.api.Create(ctxOf(owner, a.id, ActionRequest), a.id, owner, NewRequest{Method: MethodPreauthKey},
			idem("k-i-3", "3"))
		if err != nil {
			t.Fatal(err)
		}
		node := a.hs.UseKey(lastKey().ID, devicestest.Node{MachineKey: "mkey:used-at-once", Hostname: "srv-used"})
		if _, err := f.api.Revoke(ctxOf(owner, a.id, ActionRevoke), a.id, out.Request.ID, owner); reasonOf(err) != "already_final" {
			t.Fatalf("revoke of a used key: %v", err)
		}
		if st := status(t, out.Request.ID); st != StatusCredentialIssued {
			t.Fatalf("status %s after the revoke of a used key, want it left to reconcile", st)
		}
		// the device row the inventory sync writes is linked to the request once reconcile consumed it
		f.exec(t, `INSERT INTO device_inventory_cache (tenant_id, instance_id, headscale_node_id, machine_key, name)
			VALUES ($1, $2, $3, $4, 'srv-used')`, a.id, a.instance, int64(node.ID), node.MachineKey) //nolint:gosec // small test ids
		if rep, err := f.wrk.Reconcile(t.Context(), a.id); err != nil || rep.Consumed < 1 || rep.Linked < 1 {
			t.Fatalf("reconcile %+v %v", rep, err)
		}
		r, err := f.api.Get(t.Context(), a.id, out.Request.ID, owner)
		if err != nil || r.Status != StatusConsumed || r.NodeID == nil || *r.NodeID != int64(node.ID) { //nolint:gosec // small test ids
			t.Fatalf("request after the revoke of a used key: %+v %v", r, err)
		}
		if n := f.count(t, `SELECT count(*) FROM device_inventory_cache WHERE enrollment_request_id = $1`, out.Request.ID); n != 1 {
			t.Fatalf("device link %d", n)
		}
		got := f.auditOf(t, out.Request.ID.String())
		if !slices.Contains(got, "enrollment.consume/success") || !slices.Contains(got, "enrollment.revoke.failed/failure") ||
			slices.Contains(got, "enrollment.revoke.succeeded/success") {
			t.Fatalf("audit %v", got)
		}
	})

	t.Run("RevokeRacesReconcile", func(t *testing.T) {
		// reconcile settles the request consumed while the revocation expires its key: the newer final state stays
		out, err := f.api.Create(ctxOf(owner, a.id, ActionRequest), a.id, owner, NewRequest{Method: MethodPreauthKey},
			idem("k-i-4", "4"))
		if err != nil {
			t.Fatal(err)
		}
		node := a.hs.UseKey(lastKey().ID, devicestest.Node{MachineKey: "mkey:raced", Hostname: "srv-raced"})
		var rerr error
		a.hs.After(devicestest.OpExpirePreAuthKey, func(uint64) {
			_, rerr = f.wrk.Reconcile(context.Background(), a.id)
		})
		if _, err := f.api.Revoke(ctxOf(owner, a.id, ActionRevoke), a.id, out.Request.ID, owner); reasonOf(err) != "already_final" {
			t.Fatalf("revoke raced by reconcile: %v", err)
		}
		if rerr != nil {
			t.Fatal(rerr)
		}
		r, err := f.api.Get(t.Context(), a.id, out.Request.ID, owner)
		if err != nil || r.Status != StatusConsumed || r.NodeID == nil || *r.NodeID != int64(node.ID) { //nolint:gosec // small test ids
			t.Fatalf("request after the race: %+v %v", r, err)
		}
	})

	t.Run("ReusableKeyKeepsItsDevice", func(t *testing.T) {
		// a reusable key used before reconcile saw it: revoked, and the device it registered stays on the request
		out, err := f.api.CreateKey(ctxOf(admin, a.id, ActionKeyCreate), a.id, admin,
			NewKey{Tags: []string{"tag:server"}, Reusable: true}, idem("k-i-5", "5"))
		if err != nil {
			t.Fatal(err)
		}
		node := a.hs.UseKey(lastKey().ID, devicestest.Node{MachineKey: "mkey:reusable", Hostname: "ci-1"})
		r, err := f.api.Revoke(ctxOf(admin, a.id, ActionRevoke), a.id, out.Request.ID, admin)
		if err != nil || r.Status != StatusRevoked || r.NodeID == nil || *r.NodeID != int64(node.ID) { //nolint:gosec // small test ids
			t.Fatalf("revoke of a used reusable key: %+v %v", r, err)
		}
		if k := a.hs.Key(lastKey().ID); k.Expiration.After(time.Now().Add(time.Second)) {
			t.Fatalf("the revoked reusable key is still live: %+v", k)
		}
	})

	t.Run("KeyIDHandedOutAgain", func(t *testing.T) {
		// a restore of an older snapshot lost the keys of two issued requests and Headscale handed their ids out again
		// (§6.3): under the first id, a key of the same member issued after the restore (it lives later) registered a
		// new device; under the second, a key of another member (shorter lifetime). Neither is the request's key.
		first, err := f.api.Create(ctxOf(owner, a.id, ActionRequest), a.id, owner, NewRequest{Method: MethodPreauthKey},
			idem("k-i-7", "7"))
		if err != nil {
			t.Fatal(err)
		}
		k1 := lastKey()
		second, err := f.api.Create(ctxOf(owner, a.id, ActionRequest), a.id, owner, NewRequest{Method: MethodPreauthKey},
			idem("k-i-8", "8"))
		if err != nil {
			t.Fatal(err)
		}
		k2 := lastKey()
		a.hs.PutKey(devicestest.Key{ID: k1.ID, UserID: k1.UserID, UserName: k1.UserName,
			Expiration: first.Credential.ExpiresAt.Add(3 * time.Minute)})
		later := a.hs.UseKey(k1.ID, devicestest.Node{MachineKey: "mkey:after-restore", Hostname: "laptop-new"})
		other := un(a.actor("user2", uuid.New()))
		a.hs.PutKey(devicestest.Key{ID: k2.ID, UserID: 4242, UserName: other, Expiration: time.Now().Add(5 * time.Minute)})
		// revoke: the other member's key under the id is left alone (the request's own key no longer exists)
		a.hs.ResetCalls()
		if rv, err := f.api.Revoke(ctxOf(owner, a.id, ActionRevoke), a.id, second.Request.ID, owner); err != nil ||
			rv.Status != StatusRevoked {
			t.Fatalf("revoke: %+v %v", rv, err)
		}
		if n := a.hs.Calls(devicestest.OpExpirePreAuthKey); n != 0 {
			t.Fatalf("the revocation expired the key of another member (%d calls)", n)
		}
		if k := a.hs.Key(k2.ID); !k.Expiration.After(time.Now().Add(4 * time.Minute)) {
			t.Fatalf("the other member's key was expired: %+v", k)
		}
		// reconcile: the request's key is gone (failed key_missing within its lifetime), never consumed by the node of
		// the later key
		if _, err := f.wrk.Reconcile(t.Context(), a.id); err != nil {
			t.Fatal(err)
		}
		r, err := f.api.Get(t.Context(), a.id, first.Request.ID, owner)
		if err != nil || r.Status != StatusFailed || r.FailureCode == nil || *r.FailureCode != FailureKeyMissing || r.NodeID != nil {
			t.Fatalf("request whose key id was handed out again: %+v %v (node of the later key %d)", r, err, later.ID)
		}
	})

	t.Run("ApprovedKeyKeepsItsTTL", func(t *testing.T) {
		// the ttl_minutes of a request that waits for approval is the lifetime /start issues (0027)
		f.setting(t, a, "enrollment,self_enroll", "true")
		f.setting(t, a, "enrollment,requires_approval", "true")
		defer f.setting(t, a, "enrollment,requires_approval", "false")
		user := a.actor("user", uuid.New())
		out, err := f.api.Create(ctxOf(user, a.id, ActionRequest), a.id, user,
			NewRequest{Method: MethodPreauthKey, TTLMinutes: 2}, idem("k-i-6", "6"))
		if err != nil || out.Request.Status != StatusPendingApproval || out.Credential != nil {
			t.Fatalf("pending: %+v %v", out, err)
		}
		if _, err := f.api.Approve(ctxOf(admin, a.id, ActionApprove), a.id, out.Request.ID, admin); err != nil {
			t.Fatal(err)
		}
		iss, err := f.api.Start(ctxOf(user, a.id, ActionStart), a.id, out.Request.ID, user)
		if err != nil || iss.Credential == nil || iss.Request.IssuedAt == nil {
			t.Fatalf("start: %+v %v", iss, err)
		}
		if ttl := iss.Credential.ExpiresAt.Sub(*iss.Request.IssuedAt); ttl != 2*time.Minute {
			t.Fatalf("lifetime of the started key %s, want the 2 minutes requested", ttl)
		}
		if k := lastKey(); time.Until(k.Expiration) > 2*time.Minute+5*time.Second {
			t.Fatalf("key at Headscale %+v", k)
		}
	})
	f.noKeyMaterial(t)
}

// noSecret fails when a table of the platform holds secret in clear — e.g. the enrollment code of a web-auth request,
// which has no hskey- shape for noKeyMaterial to find.
func (f *fixture) noSecret(t *testing.T, secret string) {
	t.Helper()
	for _, tbl := range []string{"enrollment_requests", "idempotency_keys", "audit_events", "security_events",
		"provisioning_jobs", "notification_outbox", "device_inventory_cache"} {
		if n := f.count(t, `SELECT count(*) FROM `+tbl+` x WHERE position($1 IN x::text) > 0`, secret); n != 0 {
			t.Errorf("%s: %d row(s) hold the secret in clear", tbl, n)
		}
	}
}
