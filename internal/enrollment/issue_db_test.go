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
