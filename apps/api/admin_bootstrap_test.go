package main

// bootstrap-super-admin and seed-membership (P2-T11a) through the command line: environment of the api container, a
// real PostgreSQL migrated like a deployment, the platform IdP registered by register-platform-idp, flags, output and
// exit status (0 done, 1 refused, 2 usage).

import (
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestBootstrapCommands(t *testing.T) {
	c := newCLIEnv(t, "", "")
	idpP := uuid.Must(uuid.NewV7())
	c.vars["MG_IDP_ID_PLATFORM"] = idpP.String()
	if code := c.run(nil, "register-platform-idp"); code != 0 {
		t.Fatalf("register-platform-idp: %d %s", code, c.stderr.String())
	}
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := c.su.Exec(t.Context(), sql, args...); err != nil {
			t.Fatalf("fixture: %v", err)
		}
	}
	var code int
	run := func(args ...string) { code = c.run(nil, args...) }
	// tenants A and B with their realms' IdPs (what adopt-instance registers)
	a, b := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	idpA, idpB := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	for _, x := range []struct {
		t, idp uuid.UUID
		slug   string
	}{{a, idpA, "tenant-a"}, {b, idpB, "tenant-b"}} {
		exec(`INSERT INTO tenants (id, slug, name, status) VALUES ($1, $2::text, $2::text, 'active')`, x.t, x.slug)
		exec(`INSERT INTO identity_providers (id, scope, tenant_id, issuer, client_id, driver, driver_ref, status)
			VALUES ($1, 'tenant', $2, 'https://auth.mg.test/realms/'||$3::text, 'mg-portal', 'keycloak', $3::text, 'active')`,
			x.idp, x.t, x.slug)
	}
	expect := func(what string, want int, wants ...string) string {
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
		return out
	}
	s1, s2, s3 := uuid.NewString(), uuid.NewString(), uuid.NewString()

	// usage errors: nothing opened
	run("bootstrap-super-admin")
	expect("no --subject", 2, "--subject is required", "never an e-mail")
	run("bootstrap-super-admin", "--subject", "a b")
	expect("space in sub", 2, "1–255 visible ASCII")
	run("bootstrap-super-admin", "--subject", s1, "extra")
	expect("positional argument", 2, "no positional argument")
	run("bootstrap-super-admin", "--subjekt="+s1)
	if out := expect("unknown flag", 2, "invalid flags"); strings.Contains(out, "subjekt") {
		t.Errorf("the usage error repeats the flag: %s", out)
	}
	// an e-mail or a username is not a Keycloak sub: refused once the IdP is known
	run("bootstrap-super-admin", "--subject", "owner@example.test")
	expect("e-mail as sub", 1, "not a username or an e-mail", "RUNBOOK")

	// the first two Super Admins
	run("bootstrap-super-admin", "--subject", s1, "--display-name", "Owner One")
	expect("first", 0, "platform identity provider "+idpP.String(), "issuer https://auth.mg.test/realms/platform",
		"(subject "+s1+") — created", "super_admin, active — created", "audit: platform.super_admin.bootstrap",
		"active Super Admins: 1", "WARNING: fewer than 2", "OK")
	run("bootstrap-super-admin", "--subject", s1)
	expect("first again", 0, "— existing", "already an active Super Admin: nothing changed", "OK")
	if strings.Contains(c.stdout.String(), "audit:") {
		t.Error("a re-run reports an audit event")
	}
	run("bootstrap-super-admin", "--subject", s2)
	if out := expect("second", 0, "active Super Admins: 2", "OK"); strings.Contains(out, "WARNING") {
		t.Errorf("warning with two Super Admins: %s", out)
	}
	run("bootstrap-super-admin", "--subject", s3)
	expect("third", 1, "bootstrap path is closed — nothing was written", "FAILED: bootstrap closed: 2 active Super Admins",
		"super-admin-role with dual control")
	run("bootstrap-super-admin", "--subject", s2)
	expect("second again at the threshold", 0, "nothing changed")

	// the platform IdP comes from MG_IDP_ID_PLATFORM: a tenant's IdP there is refused, a missing one too
	c.vars["MG_IDP_ID_PLATFORM"] = idpA.String()
	run("bootstrap-super-admin", "--subject", uuid.NewString())
	expect("tenant IdP as platform IdP", 1, "belongs to a tenant, not to the platform")
	delete(c.vars, "MG_IDP_ID_PLATFORM")
	run("bootstrap-super-admin", "--subject", uuid.NewString())
	expect("no platform IdP", 1, "MG_IDP_ID_PLATFORM must hold")
	c.vars["MG_IDP_ID_PLATFORM"] = idpP.String()

	// seed-membership
	to, ta := uuid.NewString(), uuid.NewString()
	for _, role := range []string{"super_admin", "platform_operator", "tenant_operator", "end_user", ""} {
		run("seed-membership", "--tenant", "tenant-a", "--role", role, "--subject", to)
		expect("role "+role, 2, "--role must be tenant_owner or tenant_admin")
	}
	run("seed-membership", "--role", "tenant_owner", "--subject", to)
	expect("no tenant", 2, "--tenant is required")
	run("seed-membership", "--tenant", "tenant-a", "--role", "tenant_owner")
	expect("no subject", 2, "--subject is required")
	run("seed-membership", "--tenant", "tenant-z", "--role", "tenant_owner", "--subject", to)
	expect("unknown tenant", 1, `no tenant "tenant-z"`)

	run("seed-membership", "--tenant", "tenant-a", "--role", "tenant_owner", "--subject", to)
	expect("TO of A", 0, "tenant tenant-a ("+a.String()+"), identity provider "+idpA.String(),
		"issuer https://auth.mg.test/realms/tenant-a", "(subject "+to+") — created", "tenant_owner, active — created",
		"audit: platform.identity.seed + tenant.membership.seed", "OK")
	run("seed-membership", "--tenant", a.String(), "--role", "tenant_owner", "--subject", to)
	expect("TO of A again, by id", 0, "— existing", "already tenant_owner, active: nothing changed", "OK")
	run("seed-membership", "--tenant", "tenant-a", "--role", "tenant_admin", "--subject", to)
	expect("TA over the TO", 1, "never changes an existing membership")
	run("seed-membership", "--tenant", "tenant-b", "--role", "tenant_admin", "--subject", ta,
		"--display-name", "Admin B")
	expect("TA of B", 0, "tenant tenant-b", "issuer https://auth.mg.test/realms/tenant-b", "tenant_admin, active — created")

	// what the database holds: 2 Super Admins of the platform IdP, TO of A and TA of B of their own IdPs
	var got string
	if err := c.su.QueryRow(t.Context(), `SELECT string_agg(x, ',' ORDER BY x) FROM (
			SELECT 'sa:' || (i.idp_id = $1) AS x FROM platform_users pu JOIN identities i ON i.id = pu.identity_id
			UNION ALL
			SELECT r.key || ':' || t.slug || ':' || (i.idp_id = p.id) FROM tenant_memberships m
			JOIN tenants t ON t.id = m.tenant_id JOIN identities i ON i.id = m.identity_id
			JOIN identity_providers p ON p.tenant_id = t.id AND p.status = 'active' JOIN roles r ON r.id = m.role_id) s`,
		idpP).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != "sa:true,sa:true,tenant_admin:tenant-b:true,tenant_owner:tenant-a:true" {
		t.Fatalf("database: %s", got)
	}
	var events int
	if err := c.su.QueryRow(t.Context(), `SELECT count(*) FROM audit_events WHERE actor_type = 'system'
		AND action IN ('platform.super_admin.bootstrap', 'platform.identity.seed', 'tenant.membership.seed')`).
		Scan(&events); err != nil || events != 6 {
		t.Fatalf("audit events: %d %v, want 2 bootstrap + 2 identity + 2 membership", events, err)
	}
}
