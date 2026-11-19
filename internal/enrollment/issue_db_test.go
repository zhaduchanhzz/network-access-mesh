package enrollment

import (
	"strings"
	"testing"

	"github.com/google/uuid"
)

// TestIssueAndRevoke: what an issuance or a revocation stores, and what it finds when another actor moved the request,
// the tenant or the Headscale state meanwhile (regression tests of the adversarial review of P4-T06 — evidence §7). The
// hooks of the fake interleave the other actor at the exact point of the call.
func TestIssueAndRevoke(t *testing.T) {
	f := newFixture(t)
	a := f.a
	owner := a.actor("owner", uuid.New())

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
