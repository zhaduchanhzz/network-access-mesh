package main

// revoke-sessions and enable-identity (G2 round 2, A-2 — ASVS 7.4.2, 7.4.5) through the command line: environment of
// the api container, a real PostgreSQL migrated like a deployment, the detached audit writer configured (audit_events).

import (
	"crypto/rand"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/store/storetest"
)

// TestRevokeSessionsCommand — the reversed probe P5: X has two live sessions (one with a logout hint), Y of the same
// tenant one, a platform identity one. revoke-sessions for X revokes exactly X's sessions (hints cleared), disables X
// (new logins refused), leaves Y and the platform identity alone, and writes the audit pair under X's tenant; a re-run
// changes nothing; --keep-enabled revokes without disabling; enable-identity undoes the lock.
func TestRevokeSessionsCommand(t *testing.T) {
	c := newCLIEnv(t, "", "")
	pg := storetest.Require(t)
	c.vars["MG_DB_AUDIT_WRITER_PASSWORD_FILE"] = pg.Creds(t, "mg_audit_writer").PasswordFile
	ctx := t.Context()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := c.su.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("fixture: %v\n%s", err, sql)
		}
	}
	scalar := func(sql string, args ...any) string {
		t.Helper()
		var v string
		if err := c.su.QueryRow(ctx, sql, args...).Scan(&v); err != nil {
			t.Fatalf("%v\n%s", err, sql)
		}
		return v
	}
	tenant, idpA, idpP := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	exec(`INSERT INTO tenants (id, slug, name, status) VALUES ($1, 'tenant-x', 'X', 'active')`, tenant)
	exec(`INSERT INTO identity_providers (id, scope, tenant_id, issuer, client_id, driver, driver_ref, status)
		VALUES ($1, 'tenant', $2, 'https://auth.mg.test/realms/tenant-x', 'mg-portal', 'keycloak', 'tenant-x', 'active')`, idpA, tenant)
	exec(`INSERT INTO identity_providers (id, scope, issuer, client_id, driver, driver_ref, status)
		VALUES ($1, 'platform', 'https://auth.mg.test/realms/platform-x', 'mg-portal', 'keycloak', 'platform-x', 'active')`, idpP)
	subX, subY, subP := uuid.NewString(), uuid.NewString(), uuid.NewString()
	x, y, p := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	exec(`INSERT INTO identities (id, idp_id, tenant_id, scope, subject) VALUES ($1, $2, $3, 'tenant', $4), ($5, $2, $3, 'tenant', $6)`,
		x, idpA, tenant, subX, y, subY)
	exec(`INSERT INTO identities (id, idp_id, scope, subject) VALUES ($1, $2, 'platform', $3)`, p, idpP, subP)
	session := func(ident, idp uuid.UUID, origin string, hint bool) {
		t.Helper()
		h := make([]byte, 32)
		_, _ = rand.Read(h)
		var enc []byte
		if hint {
			enc = make([]byte, 64)
			_, _ = rand.Read(enc)
		}
		exec(`INSERT INTO sessions (id_hash, identity_id, idp_id, origin, auth_time, idle_expires_at, absolute_expires_at,
				id_token_hint_enc)
			VALUES ($1, $2, $3, $4, now(), now() + interval '30 minutes', now() + interval '8 hours', $5)`, h, ident, idp, origin, enc)
	}
	session(x, idpA, "app", true)
	session(x, idpA, "app", false)
	session(y, idpA, "app", true)
	session(p, idpP, "admin", false)
	live := func(ident uuid.UUID) string {
		return scalar(`SELECT count(*)::text FROM sessions WHERE identity_id = $1 AND revoked_at IS NULL`, ident)
	}
	status := func(ident uuid.UUID) string { return scalar(`SELECT status FROM identities WHERE id = $1`, ident) }

	var code int
	expect := func(what string, want int, wants ...string) {
		t.Helper()
		out := c.stdout.String() + c.stderr.String()
		if code != want {
			t.Fatalf("%s: exit %d, want %d\n%s", what, code, want, out)
		}
		for _, w := range wants {
			if !strings.Contains(out, w) {
				t.Errorf("%s: output lacks %q:\n%s", what, w, out)
			}
		}
	}
	// usage errors: nothing opened, nothing written
	for name, args := range map[string][]string{
		"no --idp":         {"revoke-sessions", "--subject", subX},
		"bad --idp":        {"revoke-sessions", "--idp", "tenant-x", "--subject", subX},
		"no --subject":     {"revoke-sessions", "--idp", idpA.String()},
		"space in subject": {"revoke-sessions", "--idp", idpA.String(), "--subject", "a b"},
		"positional":       {"revoke-sessions", "--idp", idpA.String(), "--subject", subX, "now"},
		"enable, no --idp": {"enable-identity", "--subject", subX},
	} {
		if code = c.run(nil, args...); code != 2 {
			t.Errorf("%s: exit %d\n%s", name, code, c.stderr.String())
		}
	}
	code = c.run(nil, "revoke-sessions", "--idp", idpA.String(), "--subject", uuid.NewString())
	expect("unknown identity", 1, "nothing was written", "no such identity")
	if live(x) != "2" || status(x) != "active" {
		t.Fatal("a refused command changed something")
	}

	code = c.run(nil, "revoke-sessions", "--idp", idpA.String(), "--subject", subX)
	expect("revoke X", 0, "identity "+x.String(), "tenant "+tenant.String(), "sessions revoked: 2",
		"status: active → disabled", "enable-identity --idp "+idpA.String(), "identity.sessions.revoke.requested + .succeeded", "OK")
	if live(x) != "0" || status(x) != "disabled" || live(y) != "1" || status(y) != "active" || live(p) != "1" {
		t.Fatalf("after revoke X: X live %s %s, Y live %s %s, platform live %s", live(x), status(x), live(y), status(y), live(p))
	}
	if n := scalar(`SELECT count(*)::text FROM sessions WHERE identity_id = $1 AND id_token_hint_enc IS NOT NULL`, x); n != "0" {
		t.Fatalf("%s logout hints left on X's revoked sessions", n)
	}
	rows := scalar(`SELECT string_agg(action || '/' || outcome || '/' || COALESCE(tenant_id::text, '-') || '/' || actor_type ||
			'/' || COALESCE(details->>'sessions_revoked', '-'), ',' ORDER BY occurred_at, action)
		FROM audit_events WHERE resource_id = $1`, x.String())
	want := "identity.sessions.revoke.requested/success/" + tenant.String() + "/system/-," +
		"identity.sessions.revoke.succeeded/success/" + tenant.String() + "/system/2"
	if rows != want {
		t.Fatalf("audit of X:\n got %s\nwant %s", rows, want)
	}
	if pair := scalar(`SELECT count(DISTINCT operation_id)::text FROM audit_events WHERE resource_id = $1`, x.String()); pair != "1" {
		t.Fatalf("the two events of the run carry %s operation ids", pair)
	}

	code = c.run(nil, "revoke-sessions", "--idp", idpA.String(), "--subject", subX)
	expect("revoke X again", 0, "sessions revoked: 0", "status: disabled (unchanged)", "OK")

	code = c.run(nil, "revoke-sessions", "--idp", idpA.String(), "--subject", subY, "--keep-enabled")
	expect("revoke Y, keep enabled", 0, "sessions revoked: 1", "status: active (unchanged)", "stays active", "OK")
	if live(y) != "0" || status(y) != "active" {
		t.Fatalf("Y: live %s status %s", live(y), status(y))
	}

	code = c.run(nil, "revoke-sessions", "--idp", idpP.String(), "--subject", subP)
	expect("revoke platform staff", 0, "identity "+p.String()+" (platform)", "sessions revoked: 1", "active → disabled")
	if n := scalar(`SELECT count(*)::text FROM audit_events WHERE resource_id = $1 AND tenant_id IS NULL`, p.String()); n != "2" {
		t.Fatalf("platform identity: %s platform audit events, want 2", n)
	}

	code = c.run(nil, "enable-identity", "--idp", idpA.String(), "--subject", subX)
	expect("enable X", 0, "disabled → active", "identity.enable")
	code = c.run(nil, "enable-identity", "--idp", idpA.String(), "--subject", subX)
	expect("enable X again", 0, "already active: nothing changed")
	if status(x) != "active" || live(x) != "0" {
		t.Fatalf("X after enable: %s, %s live sessions (enable must not revive sessions)", status(x), live(x))
	}
	if n := scalar(`SELECT count(*)::text FROM audit_events WHERE resource_id = $1 AND action = 'identity.enable'`, x.String()); n != "1" {
		t.Fatalf("%s identity.enable events, want 1", n)
	}
}
