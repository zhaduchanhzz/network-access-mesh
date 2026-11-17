package authz

// The RBAC seed in a real database (store.Migrate → database/seeds/rbac.sql): the catalog the Authorizer reads, its
// lattice properties, and the agreement between the SQL rule the guards use and the Go rule of the tests.

import (
	"context"
	"maps"
	"slices"
	"sort"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

type grantRow struct{ scope, condition string }

type catalogRole struct {
	role   Role
	system bool
	grants map[Permission]grantRow
}

// loadCatalog reads every role and grant through the application's platform pool (ListRoleGrants).
func loadCatalog(t *testing.T, s *store.Store) map[string]*catalogRole {
	t.Helper()
	var rows []sqlcdb.ListRoleGrantsRow
	if err := s.WithPlatformTx(t.Context(), func(q *sqlcdb.Queries) (err error) {
		rows, err = q.ListRoleGrants(t.Context())
		return err
	}); err != nil {
		t.Fatal(err)
	}
	out := map[string]*catalogRole{}
	for _, r := range rows {
		c := out[r.RoleKey]
		if c == nil {
			c = &catalogRole{role: Role{ID: r.RoleID, Scope: Scope(r.RoleScope), Key: r.RoleKey, Rank: int(r.RoleRank)},
				system: r.IsSystem, grants: map[Permission]grantRow{}}
			out[r.RoleKey] = c
		}
		if r.PermissionKey != nil {
			c.grants[Permission(*r.PermissionKey)] = grantRow{deref(r.GrantScope), deref(r.GrantCondition)}
		}
	}
	return out
}

// notCovered lists the grants of need that have does not cover: scope any covers own, an unconditional grant
// covers a conditional one — the rule of the query CountGrantsNotCovered, written independently.
func notCovered(need, have map[Permission]grantRow) []Permission {
	var out []Permission
	for p, n := range need {
		h, ok := have[p]
		if !ok || (h.scope != GrantAny && n.scope != GrantOwn) || (h.condition != "" && h.condition != n.condition) {
			out = append(out, p)
		}
	}
	slices.Sort(out)
	return out
}

func systemRoles(cat map[string]*catalogRole, scope Scope) []*catalogRole {
	var out []*catalogRole
	for _, c := range cat {
		if c.system && c.role.Scope == scope {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].role.Rank > out[j].role.Rank })
	return out
}

// TestSeedCatalog: the seeded roles are exactly the roles of §8.4 + the two support roles of §8.6 with their ranks;
// every permission of the spec exists with its scope; grants never cross scopes (invariant 2), ○ only on tenant
// roles, the four conditional cells are the four known conditions; the top role of each scope holds its whole
// matrix; the seed is idempotent; the application roles cannot write the RBAC tables.
func TestSeedCatalog(t *testing.T) {
	e := requireDB(t)
	s := e.openStore(t)
	su := e.superuser(t)
	ctx := t.Context()
	cat := loadCatalog(t, s)

	want := map[string]struct {
		scope Scope
		rank  int
	}{
		RoleSuperAdmin: {ScopePlatform, 4}, RolePlatformOperator: {ScopePlatform, 3}, RolePlatformSupport: {ScopePlatform, 2},
		RolePlatformViewer: {ScopePlatform, 1}, RoleTenantOwner: {ScopeTenant, 5}, RoleTenantAdmin: {ScopeTenant, 4},
		RoleTenantOperator: {ScopeTenant, 3}, RoleTenantViewer: {ScopeTenant, 2}, RoleEndUser: {ScopeTenant, 1},
		RoleSupportAdmin: {ScopeSupport, 2}, RoleSupportOperator: {ScopeSupport, 1},
	}
	for key, w := range want {
		c := cat[key]
		if c == nil || !c.system || c.role.Scope != w.scope || c.role.Rank != w.rank {
			t.Errorf("role %s = %+v, want system role of scope %s rank %d", key, c, w.scope, w.rank)
		}
	}
	for key, c := range cat {
		if _, ok := want[key]; c.system && !ok {
			t.Errorf("unexpected system role %s", key)
		}
	}

	rows, err := su.Query(ctx, "SELECT key, scope FROM permissions")
	if err != nil {
		t.Fatal(err)
	}
	pairs, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (p [2]string, err error) {
		err = r.Scan(&p[0], &p[1])
		return p, err
	})
	if err != nil {
		t.Fatal(err)
	}
	perms := map[Permission]Scope{}
	for _, r := range pairs {
		perms[Permission(r[0])] = Scope(r[1])
	}
	for _, o := range Operations() {
		if sc := o.Permission.Scope(); sc != "" && perms[o.Permission] != sc {
			t.Errorf("%s: permission %s of the spec missing from the seed (scope %q)", o.ID, o.Permission, perms[o.Permission])
		}
	}

	conds := map[string]int{}
	for _, c := range cat {
		if !c.system {
			continue
		}
		for p, g := range c.grants {
			if (c.role.Scope == ScopePlatform) != (p.Scope() == ScopePlatform) {
				t.Errorf("%s (%s) holds %s: invariant 2", c.role.Key, c.role.Scope, p)
			}
			if g.scope == GrantOwn && c.role.Scope != ScopeTenant {
				t.Errorf("%s holds %s on own resources: ○ exists only for tenant roles", c.role.Key, p)
			}
			if g.condition != "" {
				conds[c.role.Key+"/"+string(p)+"="+g.condition]++
			}
		}
	}
	wantConds := []string{
		RoleEndUser + "/tenant.enrollment:request=" + CondSelfEnroll,
		RoleSuperAdmin + "/platform.user:assign=" + CondExcludesSuperAdmin,
		RoleSuperAdmin + "/platform.idp:manage=" + CondTenantIdPDualControl,
		RolePlatformOperator + "/platform.approval:decide=" + CondRestoreOnly,
	}
	if got := slices.Sorted(maps.Keys(conds)); !slices.Equal(got, slices.Sorted(slices.Values(wantConds))) {
		t.Errorf("conditional grants = %v, want %v (a new condition needs a constant and code that enforces it)", got, wantConds)
	}
	for p, sc := range perms {
		top := RoleTenantOwner
		if sc == ScopePlatform {
			top = RoleSuperAdmin
		}
		if _, ok := cat[top].grants[p]; !ok {
			t.Errorf("%s does not hold %s (the top role holds its whole matrix — §8.5/§8.6)", top, p)
		}
	}
	if miss := notCovered(cat[RoleSupportOperator].grants, cat[RoleSupportAdmin].grants); len(miss) > 0 {
		t.Errorf("support_operator holds %v beyond support_admin", miss)
	}
	// spot checks against cells of §8.5/§8.6
	for _, c := range []struct {
		role  string
		perm  Permission
		grant *grantRow // nil = no grant
	}{
		{RoleTenantViewer, "tenant.audit:read", &grantRow{GrantAny, ""}},
		{RoleTenantOperator, "tenant.audit:read", nil},
		{RoleEndUser, "tenant.device:read", &grantRow{GrantOwn, ""}},
		{RoleEndUser, "tenant.dashboard:read", nil},
		{RoleTenantOwner, "tenant.notification:read", &grantRow{GrantOwn, ""}},
		{RoleTenantAdmin, "tenant.billing:read", nil},
		{RoleTenantAdmin, "tenant.membership:assign_admin", nil},
		{RoleSupportAdmin, "tenant.device:tag", &grantRow{GrantAny, ""}},
		{RoleSupportOperator, "tenant.device:tag", nil},
		{RoleSupportAdmin, "tenant.user:manage", nil},
		{RolePlatformViewer, "platform.tenant:create", nil},
		{RolePlatformSupport, "platform.audit:read", nil},
		{RoleSuperAdmin, "platform.tenant:delete", &grantRow{GrantAny, ""}},
	} {
		g, ok := cat[c.role].grants[c.perm]
		if (c.grant == nil) == ok || (ok && g != *c.grant) {
			t.Errorf("%s / %s = %+v (held %v), want %+v", c.role, c.perm, g, ok, c.grant)
		}
	}

	// idempotent: a second run leaves the system roles (same IDs) and their grants unchanged
	snapshot := func(cat map[string]*catalogRole) map[string]catalogRole {
		out := map[string]catalogRole{}
		for k, c := range cat {
			if c.system {
				out[k] = *c
			}
		}
		return out
	}
	before := snapshot(cat)
	if err := store.Seed(ctx, e.migrator(t)); err != nil {
		t.Fatalf("second seed: %v", err)
	}
	after := snapshot(loadCatalog(t, s))
	if len(before) != len(after) {
		t.Fatalf("system roles %d before, %d after a second seed", len(before), len(after))
	}
	for k, b := range before {
		a := after[k]
		if a.role != b.role || !maps.Equal(a.grants, b.grants) {
			t.Errorf("%s changed after a second seed: %+v → %+v", k, b.role, a.role)
		}
	}

	// application roles only read the RBAC tables (the seed runs as mg_migrator)
	app := e.connectAs(t, "mg_api_platform")
	for _, sql := range []string{
		"INSERT INTO permissions (key, scope) VALUES ('tenant.fixture_x:read', 'tenant')",
		"UPDATE roles SET rank = 9",
		"DELETE FROM role_permissions",
	} {
		_, err := app.Exec(ctx, sql)
		wantCode(t, "mg_api_platform: "+sql, err, "42501")
	}
}

// TestRoleLatticeOnSeed is the property test of the role lattice on the seeded data (§8.4 invariant 3, 3a): for every
// role that may give roles and every (current role, new role) pair CheckRoleAssignment accepts, the new role holds no
// grant the giver lacks — no role can grant more than it has; and the SQL rule of the guards (CountGrantsNotCovered)
// agrees with the Go rule on every ordered pair of roles.
func TestRoleLatticeOnSeed(t *testing.T) {
	e := requireDB(t)
	s := e.openStore(t)
	cat := loadCatalog(t, s)
	assign := map[Scope][]Permission{
		ScopeTenant:   {"tenant.user:manage", "tenant.membership:assign", "tenant.invitation:manage"},
		ScopePlatform: {"platform.user:assign"},
	}
	checked := 0
	for scope, perms := range assign {
		roles := systemRoles(cat, scope)
		for _, giver := range roles {
			if !slices.ContainsFunc(perms, func(p Permission) bool { _, ok := giver.grants[p]; return ok }) {
				continue
			}
			for _, next := range roles {
				for _, cur := range append(slices.Clone(roles), nil) {
					var current *Role
					if cur != nil {
						current = &cur.role
					}
					if CheckRoleAssignment(giver.role, current, next.role) != nil {
						continue
					}
					checked++
					if miss := notCovered(next.grants, giver.grants); len(miss) > 0 {
						t.Errorf("%s may give %s, which holds %v beyond it", giver.role.Key, next.role.Key, miss)
					}
				}
			}
		}
	}
	if checked < 20 {
		t.Fatalf("only %d accepted assignments checked — the property would hold vacuously", checked)
	}

	var all []*catalogRole
	for _, c := range cat {
		if c.system {
			all = append(all, c)
		}
	}
	for _, a := range all {
		for _, b := range all {
			var n int64
			if err := s.WithPlatformTx(t.Context(), func(q *sqlcdb.Queries) (err error) {
				n, err = q.CountGrantsNotCovered(t.Context(), sqlcdb.CountGrantsNotCoveredParams{RoleID: a.role.ID, GiverRoleID: b.role.ID})
				return err
			}); err != nil {
				t.Fatal(err)
			}
			if want := len(notCovered(a.grants, b.grants)); int(n) != want {
				t.Errorf("CountGrantsNotCovered(%s, giver %s) = %d, the Go rule finds %d", a.role.Key, b.role.Key, n, want)
			}
		}
	}
	// the top role of each scope covers every role of the scope
	for _, sc := range []Scope{ScopeTenant, ScopePlatform} {
		roles := systemRoles(cat, sc)
		for _, r := range roles[1:] {
			if miss := notCovered(r.grants, roles[0].grants); len(miss) > 0 {
				t.Errorf("%s holds %v beyond %s", r.role.Key, miss, roles[0].role.Key)
			}
		}
	}
}

func wantCode(t *testing.T, what string, err error, code string) {
	t.Helper()
	if got := store.SQLState(err); got != code {
		t.Errorf("%s: SQLSTATE %q (err %v), want %s", what, got, err, code)
	}
}

// connectAs opens a connection as a login role (derived password) — to show what the role itself may do.
func (e *pgEnv) connectAs(t *testing.T, role string) *pgx.Conn {
	t.Helper()
	cfg, err := pgx.ParseConfig(e.storeURL(e.database(t)))
	if err != nil {
		t.Fatal(err)
	}
	cfg.User, cfg.Password = role, e.password(role)
	c, err := pgx.ConnectConfig(t.Context(), cfg)
	if err != nil {
		t.Fatalf("connect as %s: %v", role, err)
	}
	t.Cleanup(func() { _ = c.Close(context.Background()) })
	return c
}
