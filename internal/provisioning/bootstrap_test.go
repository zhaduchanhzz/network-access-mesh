package provisioning_test

// P2-T11a below the command line: the bootstrap of the first Super Admins and the seed of TO/TA memberships on a real
// PostgreSQL migrated like a deployment (storetest) with the api's login roles (mg_api_platform, mg_api_tenant) — the
// threshold and its race, idempotency, the issuer binding (in the code and, without the code, in the database), and the
// audit rows written with each change.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/zhaduchanhzz/network-access-mesh/internal/authz"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/storetest"
)

type bootFixture struct {
	t        *testing.T
	su       *pgx.Conn
	st       *store.Store
	b        *provisioning.Bootstrapper
	platIdP  uuid.UUID
	a, b2    uuid.UUID // tenants tenant-a, tenant-b
	idpA     uuid.UUID
	idpB     uuid.UUID
	extTen   uuid.UUID // tenant-ext: an IdP of driver external (any sub shape)
	gone     uuid.UUID // tenant-gone: deleted
	noIdP    uuid.UUID // tenant-noidp: its only IdP is pending
	suMu     sync.Mutex
	saRoleID uuid.UUID
}

func newBootFixture(t *testing.T) *bootFixture {
	t.Helper()
	pg := storetest.Require(t)
	db := pg.NewDatabase(t)
	f := &bootFixture{t: t, su: pg.Admin(t, db), st: pg.OpenStore(t, db, "mg_api_tenant", "mg_api_platform", 16)}
	f.b = &provisioning.Bootstrapper{Store: f.st}
	f.platIdP = uuid.Must(uuid.NewV7())
	f.exec(`INSERT INTO identity_providers (id, scope, issuer, client_id, driver, driver_ref, status)
		VALUES ($1, 'platform', 'https://auth.mg.test/realms/platform', 'mg-portal', 'keycloak', 'platform', 'active')`,
		f.platIdP)
	f.a, f.idpA = f.tenant("tenant-a", "active", "keycloak", "active")
	f.b2, f.idpB = f.tenant("tenant-b", "active", "keycloak", "active")
	f.extTen, _ = f.tenant("tenant-ext", "active", "external", "active")
	f.gone, _ = f.tenant("tenant-gone", "deleted", "keycloak", "active")
	f.noIdP, _ = f.tenant("tenant-noidp", "active", "keycloak", "pending")
	f.scan(`SELECT id FROM roles WHERE scope = 'platform' AND key = 'super_admin'`, nil, &f.saRoleID)
	return f
}

func (f *bootFixture) tenant(slug, status, driver, idpStatus string) (uuid.UUID, uuid.UUID) {
	f.t.Helper()
	id, idp := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	f.exec(`INSERT INTO tenants (id, slug, name, status) VALUES ($1, $2::text, $2::text, $3)`, id, slug, status)
	f.exec(`INSERT INTO identity_providers (id, scope, tenant_id, issuer, client_id, driver, driver_ref, status)
		VALUES ($1, 'tenant', $2, 'https://auth.mg.test/realms/'||$3::text, 'mg-portal', $4, $3::text, $5)`,
		idp, id, slug, driver, idpStatus)
	return id, idp
}

func (f *bootFixture) exec(sql string, args ...any) {
	f.t.Helper()
	f.suMu.Lock()
	defer f.suMu.Unlock()
	if _, err := f.su.Exec(context.Background(), sql, args...); err != nil {
		f.t.Fatalf("fixture: %v\n%s", err, sql)
	}
}

func (f *bootFixture) scan(sql string, args []any, dest ...any) {
	f.t.Helper()
	f.suMu.Lock()
	defer f.suMu.Unlock()
	if err := f.su.QueryRow(context.Background(), sql, args...).Scan(dest...); err != nil {
		f.t.Fatalf("fixture: %v\n%s", err, sql)
	}
}

func (f *bootFixture) count(sql string, args ...any) int {
	f.t.Helper()
	var n int
	f.scan(sql, args, &n)
	return n
}

// activeSAs counts the active Super Admins independently of the code under test (the decision of internal/authz).
func (f *bootFixture) activeSAs() int {
	return f.count(`SELECT count(*) FROM platform_users pu JOIN identities i ON i.id = pu.identity_id
		JOIN roles r ON r.id = pu.role_id WHERE r.scope = 'platform' AND r.key = 'super_admin'
		AND pu.status = 'active' AND i.status = 'active'`)
}

// auditEvent is one row of audit_events as the tests check it.
type auditEvent struct {
	Action, ActorType, Outcome, ResourceType, ResourceID, Details string
	TenantID, ActorIdentity                                       *uuid.UUID
	ActorDisplay                                                  *string
	OperationID                                                   *uuid.UUID
}

// events returns the audit events of one command run (request id), oldest first.
func (f *bootFixture) events(requestID string) []auditEvent {
	f.t.Helper()
	f.suMu.Lock()
	defer f.suMu.Unlock()
	rows, err := f.su.Query(context.Background(), `SELECT action, actor_type, outcome, resource_type,
			coalesce(resource_id, ''), details::text, tenant_id, actor_identity_id, actor_display, operation_id
		FROM audit_events WHERE request_id = $1 ORDER BY occurred_at, id`, requestID)
	if err != nil {
		f.t.Fatal(err)
	}
	out, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (auditEvent, error) {
		var e auditEvent
		err := r.Scan(&e.Action, &e.ActorType, &e.Outcome, &e.ResourceType, &e.ResourceID, &e.Details, &e.TenantID,
			&e.ActorIdentity, &e.ActorDisplay, &e.OperationID)
		return e, err
	})
	if err != nil {
		f.t.Fatal(err)
	}
	return out
}

func (f *bootFixture) superAdmin(sub, name, reqID string) (provisioning.SuperAdminResult, error) {
	return f.b.BootstrapSuperAdmin(context.Background(), provisioning.SuperAdminRequest{
		PlatformIdP: f.platIdP, Subject: sub, DisplayName: name, RequestID: reqID})
}

func (f *bootFixture) seed(tenant, role, sub, reqID string) (provisioning.MembershipResult, error) {
	return f.b.SeedMembership(context.Background(), provisioning.MembershipRequest{
		Tenant: tenant, Role: role, Subject: sub, RequestID: reqID})
}

// systemEvent checks the fields every event of the bootstrap commands has: actor_type system without actor identity,
// success, no operation id, the actor display of the command; and no subject or display name in the details (§6.3
// stores them in identities — the audit trail carries ids only).
func systemEvent(t *testing.T, e auditEvent, action string, tenant *uuid.UUID, resourceType string, pii ...string) {
	t.Helper()
	if e.Action != action || e.ActorType != "system" || e.ActorIdentity != nil || e.Outcome != "success" ||
		e.OperationID != nil || e.ResourceType != resourceType || e.ActorDisplay == nil ||
		!strings.HasPrefix(*e.ActorDisplay, "meshguard admin ") || (tenant == nil) != (e.TenantID == nil) ||
		(tenant != nil && *tenant != *e.TenantID) {
		t.Errorf("audit event %+v, want %s (tenant %v, %s)", e, action, tenant, resourceType)
	}
	for _, p := range pii {
		if strings.Contains(e.Details, p) {
			t.Errorf("audit details of %s carry %q: %s", action, p, e.Details)
		}
	}
}

// TestBootstrapSuperAdmin — the first two Super Admins by (platform IdP, sub); re-runs change nothing; from the
// threshold on the command is refused and writes nothing; it never changes an existing platform user.
func TestBootstrapSuperAdmin(t *testing.T) {
	f := newBootFixture(t)
	if provisioning.SuperAdminThreshold != 2 {
		t.Fatalf("threshold %d: D-11 decided two or more operators (§25.4)", provisioning.SuperAdminThreshold)
	}
	if provisioning.RoleSuperAdmin != authz.RoleSuperAdmin || provisioning.RoleTenantOwner != authz.RoleTenantOwner ||
		provisioning.RoleTenantAdmin != authz.RoleTenantAdmin {
		t.Fatal("role keys differ from internal/authz")
	}
	s1, s2, s3 := uuid.NewString(), uuid.NewString(), uuid.NewString()

	// 1. first Super Admin: identity + platform user + one platform event, in one transaction
	r1, err := f.superAdmin(s1, "Owner One", "req-sa-1")
	if err != nil || !r1.Created || !r1.IdentityCreated || r1.ActiveSupers != 1 || r1.IdPID != f.platIdP ||
		r1.Issuer != "https://auth.mg.test/realms/platform" {
		t.Fatalf("first bootstrap: %+v %v", r1, err)
	}
	var (
		scope, subject, puStatus, roleKey string
		tenantID, createdBy               *uuid.UUID
		email, name                       *string
	)
	f.scan(`SELECT i.scope, i.subject, i.tenant_id, i.email, i.display_name, pu.status, r.key, pu.created_by
		FROM identities i JOIN platform_users pu ON pu.identity_id = i.id JOIN roles r ON r.id = pu.role_id
		WHERE i.id = $1 AND i.idp_id = $2 AND pu.id = $3`, []any{r1.IdentityID, f.platIdP, r1.PlatformUserID},
		&scope, &subject, &tenantID, &email, &name, &puStatus, &roleKey, &createdBy)
	if scope != "platform" || subject != s1 || tenantID != nil || email != nil || name == nil || *name != "Owner One" ||
		puStatus != "active" || roleKey != "super_admin" || createdBy != nil {
		t.Fatalf("rows: scope %s, subject ok %v, tenant %v, email %v, name %v, status %s, role %s, created_by %v",
			scope, subject == s1, tenantID, email, name, puStatus, roleKey, createdBy)
	}
	ev := f.events("req-sa-1")
	if len(ev) != 1 {
		t.Fatalf("audit of the first bootstrap: %+v", ev)
	}
	systemEvent(t, ev[0], provisioning.ActionBootstrapSuperAdmin, nil, "platform_user", s1, "Owner One")
	for _, want := range []string{`"identity_id": "` + r1.IdentityID.String(), `"active_super_admins": 1`,
		`"identity_created": true`, `"threshold": 2`, `"role": "super_admin"`} {
		if ev[0].ResourceID != r1.PlatformUserID.String() || !strings.Contains(ev[0].Details, want) {
			t.Errorf("audit details %s (resource %s) lack %s", ev[0].Details, ev[0].ResourceID, want)
		}
	}

	// 2. re-run: nothing written, nothing audited
	again, err := f.superAdmin(s1, "Owner One", "req-sa-1b")
	if err != nil || again.Created || again.IdentityCreated || again.IdentityID != r1.IdentityID ||
		again.PlatformUserID != r1.PlatformUserID || again.ActiveSupers != 1 || len(f.events("req-sa-1b")) != 0 {
		t.Fatalf("re-run: %+v %v", again, err)
	}

	// 3. second Super Admin whose identity exists already (the person logged in before being bootstrapped)
	var pre uuid.UUID
	f.scan(`INSERT INTO identities (idp_id, scope, subject, email, email_verified, display_name)
		VALUES ($1, 'platform', $2, 'two@example.test', true, 'Owner Two') RETURNING id`, []any{f.platIdP, s2}, &pre)
	r2, err := f.superAdmin(s2, "", "req-sa-2")
	if err != nil || !r2.Created || r2.IdentityCreated || r2.IdentityID != pre || r2.ActiveSupers != 2 {
		t.Fatalf("second bootstrap: %+v %v", r2, err)
	}
	if ev := f.events("req-sa-2"); len(ev) != 1 || !strings.Contains(ev[0].Details, `"identity_created": false`) {
		t.Fatalf("audit of the second bootstrap: %+v", ev)
	} else {
		systemEvent(t, ev[0], provisioning.ActionBootstrapSuperAdmin, nil, "platform_user", s2, "two@example.test")
	}

	// 4. threshold reached: refused, nothing written (no identity for s3, no platform user, no event)
	before := f.count(`SELECT count(*) FROM identities`) + f.count(`SELECT count(*) FROM platform_users`)
	_, err = f.superAdmin(s3, "Three", "req-sa-3")
	if !errors.Is(err, provisioning.ErrBootstrapClosed) || !strings.Contains(err.Error(), "2 active Super Admins") {
		t.Fatalf("third bootstrap: %v", err)
	}
	if after := f.count(`SELECT count(*) FROM identities`) + f.count(`SELECT count(*) FROM platform_users`); after != before ||
		len(f.events("req-sa-3")) != 0 || f.activeSAs() != 2 {
		t.Fatalf("a refused bootstrap wrote something: rows %d → %d, %d active", before, after, f.activeSAs())
	}
	// idempotent at the threshold too
	if r, err := f.superAdmin(s1, "", "req-sa-1c"); err != nil || r.Created || r.ActiveSupers != 2 {
		t.Fatalf("re-run at the threshold: %+v %v", r, err)
	}

	// 5. a disabled Super Admin (platform user or identity) does not count: the bootstrap opens again, once
	f.exec(`UPDATE identities SET status = 'disabled' WHERE id = $1`, r2.IdentityID)
	if r, err := f.superAdmin(s3, "", "req-sa-3b"); err != nil || !r.Created || r.ActiveSupers != 2 {
		t.Fatalf("bootstrap after an identity was disabled: %+v %v", r, err)
	}
	if _, err := f.superAdmin(uuid.NewString(), "", "req-sa-4"); !errors.Is(err, provisioning.ErrBootstrapClosed) {
		t.Fatalf("fourth bootstrap: %v", err)
	}
	// the disabled identity is refused, never re-enabled by the bootstrap
	f.exec(`UPDATE platform_users SET status = 'disabled' WHERE identity_id = $1`, r1.IdentityID) // 1 active now
	if _, err := f.superAdmin(s2, "", "req-sa-2b"); !errors.Is(err, provisioning.ErrBootstrapRefused) ||
		!strings.Contains(err.Error(), "disabled") {
		t.Fatalf("bootstrap of a disabled identity: %v", err)
	}
	// a platform user that is not an active Super Admin is never changed (role changes go through the API)
	if _, err := f.superAdmin(s1, "", "req-sa-1d"); !errors.Is(err, provisioning.ErrBootstrapRefused) ||
		!strings.Contains(err.Error(), "never changes an existing platform user") {
		t.Fatalf("bootstrap of a disabled platform user: %v", err)
	}
	po := uuid.NewString()
	f.exec(`WITH i AS (INSERT INTO identities (idp_id, scope, subject) VALUES ($1, 'platform', $2) RETURNING id)
		INSERT INTO platform_users (identity_id, role_id) SELECT i.id, r.id FROM i, roles r
		WHERE r.scope = 'platform' AND r.key = 'platform_operator'`, f.platIdP, po)
	if _, err := f.superAdmin(po, "", "req-po"); !errors.Is(err, provisioning.ErrBootstrapRefused) ||
		!strings.Contains(err.Error(), "role platform_operator") {
		t.Fatalf("bootstrap of a Platform Operator: %v", err)
	}
	for _, id := range []string{"req-sa-2b", "req-sa-1d", "req-po"} {
		if n := len(f.events(id)); n != 0 {
			t.Errorf("%s: %d audit events for a refusal", id, n)
		}
	}
	if f.activeSAs() != 1 {
		t.Fatalf("active SAs %d after the refusals, want 1", f.activeSAs())
	}
}

// TestBootstrapSuperAdminRefusals — the input and the IdP: a malformed sub, a sub of the wrong shape for Keycloak
// (an e-mail, a username), the IdP of a tenant (§8.4 invariant 1), an unknown or inactive platform IdP. Nothing is
// written by any of them.
func TestBootstrapSuperAdminRefusals(t *testing.T) {
	f := newBootFixture(t)
	ctx := context.Background()
	inactive := uuid.Must(uuid.NewV7())
	f.exec(`INSERT INTO identity_providers (id, scope, issuer, client_id, driver, status)
		VALUES ($1, 'platform', 'https://auth.mg.test/realms/platform-old', 'mg-portal', 'keycloak', 'retiring')`, inactive)
	sub := uuid.NewString()
	for name, c := range map[string]struct {
		idp       uuid.UUID
		sub, name string
		want      string
	}{
		"empty sub":             {f.platIdP, "", "", "1–255 visible ASCII"},
		"sub with a space":      {f.platIdP, "a b", "", "1–255 visible ASCII"},
		"sub with a newline":    {f.platIdP, sub + "\n", "", "1–255 visible ASCII"},
		"256-byte sub":          {f.platIdP, strings.Repeat("a", 256), "", "1–255 visible ASCII"},
		"non-ASCII sub":         {f.platIdP, "ü" + sub, "", "1–255 visible ASCII"},
		"e-mail as sub":         {f.platIdP, "owner@example.test", "", "not a username or an e-mail"},
		"username as sub":       {f.platIdP, "owner", "", "not a username or an e-mail"},
		"upper-case UUID":       {f.platIdP, strings.ToUpper(sub), "", "not a username or an e-mail"},
		"control in name":       {f.platIdP, sub, "a\x1bb", "display name"},
		"blank name":            {f.platIdP, sub, "   ", "display name"},
		"tenant A's IdP":        {f.idpA, sub, "", "belongs to a tenant"},
		"unknown IdP":           {uuid.New(), sub, "", "is not registered"},
		"retiring platform IdP": {inactive, sub, "", "not active"},
	} {
		_, err := f.b.BootstrapSuperAdmin(ctx, provisioning.SuperAdminRequest{PlatformIdP: c.idp, Subject: c.sub,
			DisplayName: c.name, RequestID: "req-" + name})
		if !errors.Is(err, provisioning.ErrBootstrapRefused) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want refusal %q", name, err, c.want)
		}
	}
	if n := f.count(`SELECT count(*) FROM identities`) + f.count(`SELECT count(*) FROM platform_users`) +
		f.count(`SELECT count(*) FROM audit_events`); n != 0 {
		t.Fatalf("refusals wrote %d rows", n)
	}
	// an IdP of driver external takes any well-formed sub (here the numeric shape of some public IdPs)
	ext := uuid.Must(uuid.NewV7())
	f.exec(`INSERT INTO identity_providers (id, scope, issuer, client_id, driver, status)
		VALUES ($1, 'platform', 'https://login.example.test', 'meshguard', 'external', 'active')`, ext)
	if r, err := f.b.BootstrapSuperAdmin(ctx, provisioning.SuperAdminRequest{PlatformIdP: ext,
		Subject: "104837562938475610293"}); err != nil || !r.Created {
		t.Fatalf("external IdP: %+v %v", r, err)
	}
}

// TestBootstrapSuperAdminRace — concurrent runs cannot pass the threshold together: from 0 active Super Admins,
// exactly two of 12 simultaneous runs succeed; from 1, exactly one of 12. The losers write nothing.
func TestBootstrapSuperAdminRace(t *testing.T) {
	for _, start := range []int{0, 1} {
		t.Run(fmt.Sprintf("from %d", start), func(t *testing.T) {
			f := newBootFixture(t)
			if start == 1 {
				if _, err := f.superAdmin(uuid.NewString(), "", "req-first"); err != nil {
					t.Fatal(err)
				}
			}
			const runs = 12
			var (
				wg      sync.WaitGroup
				mu      sync.Mutex
				created []provisioning.SuperAdminResult
				closed  int
				others  []error
			)
			gate := make(chan struct{})
			for i := range runs {
				wg.Add(1)
				go func() {
					defer wg.Done()
					<-gate
					r, err := f.superAdmin(uuid.NewString(), "", fmt.Sprintf("req-race-%d", i))
					mu.Lock()
					defer mu.Unlock()
					switch {
					case err == nil && r.Created:
						created = append(created, r)
					case errors.Is(err, provisioning.ErrBootstrapClosed):
						closed++
					default:
						others = append(others, fmt.Errorf("%+v %w", r, err))
					}
				}()
			}
			close(gate)
			wg.Wait()
			want := provisioning.SuperAdminThreshold - start
			if len(created) != want || closed != runs-want || len(others) != 0 {
				t.Fatalf("%d created, %d closed, others %v — want %d created", len(created), closed, others, want)
			}
			if f.activeSAs() != provisioning.SuperAdminThreshold ||
				f.count(`SELECT count(*) FROM platform_users`) != provisioning.SuperAdminThreshold ||
				f.count(`SELECT count(*) FROM identities`) != provisioning.SuperAdminThreshold ||
				f.count(`SELECT count(*) FROM audit_events WHERE action = $1`, provisioning.ActionBootstrapSuperAdmin) !=
					provisioning.SuperAdminThreshold {
				t.Fatalf("after the race: %d active SAs, %d platform users, %d identities", f.activeSAs(),
					f.count(`SELECT count(*) FROM platform_users`), f.count(`SELECT count(*) FROM identities`))
			}
			seen := map[int]bool{}
			for _, r := range created {
				seen[r.ActiveSupers] = true
			}
			for n := start + 1; n <= provisioning.SuperAdminThreshold; n++ {
				if !seen[n] {
					t.Errorf("the winners reported counts %v, want each of %d..%d once", seen, start+1,
						provisioning.SuperAdminThreshold)
				}
			}
		})
	}
}

// TestSeedMembership — TO/TA of tenants A and B by (the tenant's own IdP, sub): two events per new person (the
// identity on the platform pool, the membership in the tenant's audit), idempotent, never a platform role, never a
// change of an existing membership.
func TestSeedMembership(t *testing.T) {
	f := newBootFixture(t)
	ownerA, adminA, ownerB := uuid.NewString(), uuid.NewString(), uuid.NewString()

	r, err := f.seed("tenant-a", provisioning.RoleTenantOwner, ownerA, "req-to-a")
	if err != nil || !r.Created || !r.IdentityCreated || r.TenantID != f.a || r.IdPID != f.idpA || r.Slug != "tenant-a" ||
		r.Issuer != "https://auth.mg.test/realms/tenant-a" {
		t.Fatalf("seed TO of A: %+v %v", r, err)
	}
	var (
		scope, roleKey, status string
		tenantID               *uuid.UUID
		idp                    uuid.UUID
		invitedBy              *uuid.UUID
	)
	f.scan(`SELECT i.scope, i.tenant_id, i.idp_id, r.key, m.status, m.invited_by FROM tenant_memberships m
		JOIN identities i ON i.id = m.identity_id JOIN roles r ON r.id = m.role_id
		WHERE m.id = $1 AND m.tenant_id = $2 AND i.id = $3 AND i.subject = $4`,
		[]any{r.MembershipID, f.a, r.IdentityID, ownerA}, &scope, &tenantID, &idp, &roleKey, &status, &invitedBy)
	if scope != "tenant" || tenantID == nil || *tenantID != f.a || idp != f.idpA || roleKey != "tenant_owner" ||
		status != "active" || invitedBy != nil {
		t.Fatalf("rows: %s %v %s %s %s %v", scope, tenantID, idp, roleKey, status, invitedBy)
	}
	ev := f.events("req-to-a")
	if len(ev) != 2 {
		t.Fatalf("audit of the seed: %+v", ev)
	}
	systemEvent(t, ev[0], provisioning.ActionSeedIdentity, nil, "identity", ownerA)
	systemEvent(t, ev[1], provisioning.ActionSeedMembership, &f.a, "membership", ownerA)
	if ev[0].ResourceID != r.IdentityID.String() || ev[1].ResourceID != r.MembershipID.String() ||
		!strings.Contains(ev[1].Details, `"role": "tenant_owner"`) || !strings.Contains(ev[1].Details, r.IdentityID.String()) {
		t.Fatalf("audit resources/details: %+v", ev)
	}

	// re-run (by tenant id this time): nothing written, nothing audited
	again, err := f.seed(f.a.String(), provisioning.RoleTenantOwner, ownerA, "req-to-a2")
	if err != nil || again.Created || again.IdentityCreated || again.MembershipID != r.MembershipID ||
		len(f.events("req-to-a2")) != 0 {
		t.Fatalf("re-run: %+v %v", again, err)
	}
	// a TA of A whose identity exists (an earlier login): only the tenant event
	var pre uuid.UUID
	f.scan(`INSERT INTO identities (idp_id, tenant_id, scope, subject, email) VALUES ($1, $2, 'tenant', $3, 'ta@a.test')
		RETURNING id`, []any{f.idpA, f.a, adminA}, &pre)
	ta, err := f.seed("tenant-a", provisioning.RoleTenantAdmin, adminA, "req-ta-a")
	if err != nil || !ta.Created || ta.IdentityCreated || ta.IdentityID != pre {
		t.Fatalf("seed TA of A: %+v %v", ta, err)
	}
	if ev := f.events("req-ta-a"); len(ev) != 1 || ev[0].Action != provisioning.ActionSeedMembership {
		t.Fatalf("audit of a seed with an existing identity: %+v", ev)
	}

	// the same sub string under B's IdP is another identity (another issuer): issuer binding, not string equality
	tb, err := f.seed("tenant-b", provisioning.RoleTenantOwner, ownerA, "req-to-b-samesub")
	if err != nil || !tb.Created || !tb.IdentityCreated || tb.IdentityID == r.IdentityID || tb.IdPID != f.idpB {
		t.Fatalf("same sub in B: %+v %v", tb, err)
	}
	if _, err := f.seed("tenant-b", provisioning.RoleTenantAdmin, ownerB, "req-ta-b"); err != nil {
		t.Fatal(err)
	}
	if n := f.count(`SELECT count(*) FROM identities WHERE subject = $1`, ownerA); n != 2 {
		t.Fatalf("identities with the shared sub: %d, want one per IdP", n)
	}
	// a tenant IdP's identity has no platform role (and is no Super Admin)
	if f.count(`SELECT count(*) FROM platform_users`) != 0 {
		t.Fatal("a seed created a platform user")
	}

	// an existing membership is never changed by the seed — another role, or not active
	if _, err := f.seed("tenant-a", provisioning.RoleTenantAdmin, ownerA, "req-demote"); !errors.Is(err,
		provisioning.ErrBootstrapRefused) || !strings.Contains(err.Error(), "role tenant_owner") {
		t.Fatalf("seed TA over a TO: %v", err)
	}
	f.exec(`UPDATE tenant_memberships SET status = 'locked' WHERE id = $1`, ta.MembershipID)
	if _, err := f.seed("tenant-a", provisioning.RoleTenantAdmin, adminA, "req-locked"); !errors.Is(err,
		provisioning.ErrBootstrapRefused) || !strings.Contains(err.Error(), "status locked") {
		t.Fatalf("seed over a locked membership: %v", err)
	}
	// a disabled identity is refused
	f.exec(`UPDATE identities SET status = 'disabled' WHERE id = $1`, tb.IdentityID)
	if _, err := f.seed("tenant-b", provisioning.RoleTenantOwner, ownerA, "req-disabled"); !errors.Is(err,
		provisioning.ErrBootstrapRefused) || !strings.Contains(err.Error(), "disabled") {
		t.Fatalf("seed of a disabled identity: %v", err)
	}
	for _, id := range []string{"req-demote", "req-locked", "req-disabled"} {
		if n := len(f.events(id)); n != 0 {
			t.Errorf("%s: %d events for a refusal", id, n)
		}
	}
	var role string
	f.scan(`SELECT r.key FROM tenant_memberships m JOIN roles r ON r.id = m.role_id WHERE m.id = $1`,
		[]any{r.MembershipID}, &role)
	if role != "tenant_owner" {
		t.Fatalf("the refused seed changed the role to %s", role)
	}
}

// TestSeedMembershipRefusals — only TO/TA (never a platform or support role, never TP/TV/EU), only a live tenant with
// an active IdP, only a sub of the IdP's shape. Nothing is written by any of them.
func TestSeedMembershipRefusals(t *testing.T) {
	f := newBootFixture(t)
	sub := uuid.NewString()
	for _, role := range []string{"super_admin", "platform_operator", "platform_support", "platform_viewer",
		"support_admin", "support_operator", "tenant_operator", "tenant_viewer", "end_user", "Tenant_Owner", ""} {
		if _, err := f.seed("tenant-a", role, sub, "req-role-"+role); !errors.Is(err, provisioning.ErrBootstrapRefused) ||
			!strings.Contains(err.Error(), "tenant_owner or tenant_admin only") {
			t.Errorf("role %q: %v", role, err)
		}
	}
	for name, c := range map[string]struct{ tenant, sub, want string }{
		"unknown slug":     {"tenant-z", sub, `no tenant "tenant-z"`},
		"unknown id":       {uuid.NewString(), sub, "no tenant"},
		"deleted tenant":   {"tenant-gone", sub, "no tenant"},
		"deleted by id":    {f.gone.String(), sub, "is deleted"},
		"no active IdP":    {"tenant-noidp", sub, "no active identity provider"},
		"e-mail as sub":    {"tenant-a", "owner@a.test", "not a username or an e-mail"},
		"malformed sub":    {"tenant-a", "a\tb", "1–255 visible ASCII"},
		"non-canonical id": {strings.ToUpper(f.a.String()), sub, "no tenant"},
	} {
		if _, err := f.seed(c.tenant, provisioning.RoleTenantOwner, c.sub, "req-"+name); !errors.Is(err,
			provisioning.ErrBootstrapRefused) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
	if n := f.count(`SELECT count(*) FROM identities`) + f.count(`SELECT count(*) FROM tenant_memberships`) +
		f.count(`SELECT count(*) FROM audit_events`); n != 0 {
		t.Fatalf("refusals wrote %d rows", n)
	}
	// an IdP of driver external takes any well-formed sub
	if r, err := f.seed("tenant-ext", provisioning.RoleTenantAdmin, "00u1abcdEFGH2345x697", "req-ext"); err != nil ||
		!r.Created {
		t.Fatalf("external IdP: %+v %v", r, err)
	}
}

// TestIssuerBindingInTheDatabase — without the code: the api's own login roles try the writes a broken bootstrap
// would make, and the composite foreign keys of 0002 refuse them (§8.4 invariant 1), as do the table grants.
func TestIssuerBindingInTheDatabase(t *testing.T) {
	f := newBootFixture(t)
	ctx := context.Background()
	idA, err := f.seed("tenant-a", provisioning.RoleTenantOwner, uuid.NewString(), "")
	if err != nil {
		t.Fatal(err)
	}
	sa, err := f.superAdmin(uuid.NewString(), "", "")
	if err != nil {
		t.Fatal(err)
	}
	var toRole uuid.UUID
	f.scan(`SELECT id FROM roles WHERE scope = 'tenant' AND key = 'tenant_owner'`, nil, &toRole)
	platform := func(name string, fn func(q *sqlcdb.Queries) error) error {
		return f.st.WithPlatformTx(ctx, fn)
	}
	inTenant := func(tenant uuid.UUID) func(string, func(q *sqlcdb.Queries) error) error {
		return func(_ string, fn func(q *sqlcdb.Queries) error) error { return f.st.WithTenantTx(ctx, tenant, fn) }
	}
	a, b := f.a, f.b2
	for _, c := range []struct {
		name  string
		tx    func(string, func(q *sqlcdb.Queries) error) error
		write func(q *sqlcdb.Queries) error
		state string
	}{
		{"identity of tenant A's IdP with platform scope (a tenant IdP's user as platform staff)", platform,
			func(q *sqlcdb.Queries) error {
				_, err := q.InsertSeededIdentity(ctx, sqlcdb.InsertSeededIdentityParams{IdpID: f.idpA, Scope: "platform",
					Subject: uuid.NewString()})
				return err
			}, "23503"},
		{"identity of the platform IdP inside tenant A", platform, func(q *sqlcdb.Queries) error {
			_, err := q.InsertSeededIdentity(ctx, sqlcdb.InsertSeededIdentityParams{IdpID: f.platIdP, TenantID: &a,
				Scope: "tenant", Subject: uuid.NewString()})
			return err
		}, "23503"},
		{"identity of tenant A's IdP inside tenant B", platform, func(q *sqlcdb.Queries) error {
			_, err := q.InsertSeededIdentity(ctx, sqlcdb.InsertSeededIdentityParams{IdpID: f.idpA, TenantID: &b,
				Scope: "tenant", Subject: uuid.NewString()})
			return err
		}, "23503"},
		{"platform user for an identity of tenant A (Super Admin from a tenant IdP)", platform,
			func(q *sqlcdb.Queries) error {
				_, err := q.InsertPlatformUser(ctx, sqlcdb.InsertPlatformUserParams{IdentityID: idA.IdentityID,
					RoleID: f.saRoleID})
				return err
			}, "23503"},
		{"platform user with a tenant role", platform, func(q *sqlcdb.Queries) error {
			var other uuid.UUID
			f.scan(`INSERT INTO identities (idp_id, scope, subject) VALUES ($1, 'platform', $2) RETURNING id`,
				[]any{f.platIdP, uuid.NewString()}, &other)
			_, err := q.InsertPlatformUser(ctx, sqlcdb.InsertPlatformUserParams{IdentityID: other, RoleID: toRole})
			return err
		}, "23503"},
		{"membership in B for the identity of A's IdP", inTenant(b), func(q *sqlcdb.Queries) error {
			_, err := q.InsertSeededMembership(ctx, sqlcdb.InsertSeededMembershipParams{TenantID: b,
				IdentityID: idA.IdentityID, RoleID: toRole})
			return err
		}, "23503"},
		{"membership in A for a platform identity (the Super Admin)", inTenant(a), func(q *sqlcdb.Queries) error {
			_, err := q.InsertSeededMembership(ctx, sqlcdb.InsertSeededMembershipParams{TenantID: a,
				IdentityID: sa.IdentityID, RoleID: toRole})
			return err
		}, "23503"},
		{"membership with the Super Admin role", inTenant(a), func(q *sqlcdb.Queries) error {
			var other uuid.UUID
			f.scan(`INSERT INTO identities (idp_id, tenant_id, scope, subject) VALUES ($1, $2, 'tenant', $3) RETURNING id`,
				[]any{f.idpA, a, uuid.NewString()}, &other)
			_, err := q.InsertSeededMembership(ctx, sqlcdb.InsertSeededMembershipParams{TenantID: a, IdentityID: other,
				RoleID: f.saRoleID})
			return err
		}, "23503"},
		{"membership written on the platform pool (mg_api_platform has no right on tenant_memberships)", platform,
			func(q *sqlcdb.Queries) error {
				_, err := q.InsertSeededMembership(ctx, sqlcdb.InsertSeededMembershipParams{TenantID: a,
					IdentityID: idA.IdentityID, RoleID: toRole})
				return err
			}, "42501"},
		{"identity written on the tenant pool (mg_api_tenant may not insert identities)", inTenant(a),
			func(q *sqlcdb.Queries) error {
				_, err := q.InsertSeededIdentity(ctx, sqlcdb.InsertSeededIdentityParams{IdpID: f.idpA, TenantID: &a,
					Scope: "tenant", Subject: uuid.NewString()})
				return err
			}, "42501"},
	} {
		err := c.tx(c.name, c.write)
		if store.SQLState(err) != c.state {
			t.Errorf("%s: %v (SQLSTATE %q), want %s", c.name, err, store.SQLState(err), c.state)
		}
	}
	if n := f.count(`SELECT count(*) FROM platform_users`); n != 1 {
		t.Fatalf("platform users: %d, want only the bootstrapped Super Admin", n)
	}
	if n := f.count(`SELECT count(*) FROM tenant_memberships`); n != 1 {
		t.Fatalf("memberships: %d, want only the seeded TO of A", n)
	}
}
