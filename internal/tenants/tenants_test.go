package tenants_test

// Integration tests of the Tenant Registry (P2-T11) on a real PostgreSQL migrated like a deployment (storetest: goose,
// RBAC seed, River) with the api roles: tenant-scope reads stay inside the tenant of the call (RLS + filters), platform
// reads return registry metadata only, adoption writes are idempotent and refuse contradictions.

import (
	"errors"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/storetest"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
)

func TestMain(m *testing.M) {
	code := m.Run()
	storetest.Cleanup()
	os.Exit(code)
}

type fixture struct {
	t    *testing.T
	su   *pgx.Conn
	st   *store.Store
	svc  *tenants.Service
	host uuid.UUID
	n    int
	db   string // the test database (P4-T13: a second store with the worker roles)
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	pg := storetest.Require(t)
	db := pg.NewDatabase(t)
	f := &fixture{t: t, su: pg.Admin(t, db), st: pg.OpenStore(t, db, "mg_api_tenant", "mg_api_platform", 8), db: db}
	f.svc = tenants.New(f.st, tenants.Options{BaseDomain: "mg.test"})
	f.host = uuid.Must(uuid.NewV7())
	f.exec(`INSERT INTO hosts (id, name, region, run_uid_range, tenant_net_pool)
		VALUES ($1, 'host-1', 'lab', int4range(30000, 40000), '10.250.0.0/16')`, f.host)
	return f
}

func (f *fixture) exec(sql string, args ...any) {
	f.t.Helper()
	if _, err := f.su.Exec(f.t.Context(), sql, args...); err != nil {
		f.t.Fatalf("fixture: %v\n%s", err, sql)
	}
}

// tenant inserts a tenant (and, when withInstance, a running instance) and its IdP; it returns the tenant and IdP ids.
func (f *fixture) tenant(slug, name, status string, withInstance bool) (uuid.UUID, uuid.UUID) {
	f.t.Helper()
	f.n++
	id, idp := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	f.exec(`INSERT INTO tenants (id, slug, name, status, deployment_region) VALUES ($1, $2::text, $3, $4, 'lab')`,
		id, slug, name, status)
	if withInstance {
		inst := uuid.Must(uuid.NewV7())
		f.exec(`INSERT INTO tenant_instances (id, tenant_id, host_id, status, headscale_version, image_digest,
				control_hostname, server_url, base_domain, internal_address, run_uid, net_cidr, data_path)
			VALUES ($1, $2, $3, 'running', 'v0.29.7', 'sha256:'||repeat('a', 64), $4||'.mesh.mg.test',
				'https://'||$4||'.mesh.mg.test', $4||'.tail.mg.test', 'hs-'||$4||':8080', $5, $6::cidr, '/data')`,
			inst, id, f.host, slug, 30000+f.n, "10.250.0."+strconv.Itoa(8*f.n)+"/29")
	}
	f.exec(`INSERT INTO identity_providers (id, scope, tenant_id, issuer, client_id, driver, status)
		VALUES ($1, 'tenant', $2, 'https://idp.test/'||$3, 'portal', 'external', 'active')`, idp, id, slug)
	return id, idp
}

// member inserts an identity of the tenant's IdP and its membership; it returns identity and membership ids.
func (f *fixture) member(tenant, idp uuid.UUID, name, email, role, status string) (uuid.UUID, uuid.UUID) {
	f.t.Helper()
	ident, m := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	var display, mail any
	if name != "" {
		display = name
	}
	if email != "" {
		mail = email
	}
	f.exec(`INSERT INTO identities (id, idp_id, tenant_id, scope, subject, email, display_name)
		VALUES ($1, $2, $3, 'tenant', $4, $5, $6)`, ident, idp, tenant, "sub-"+ident.String(), mail, display)
	f.exec(`INSERT INTO tenant_memberships (id, tenant_id, identity_id, role_id, status)
		SELECT $1, $2, $3, id, $4 FROM roles WHERE scope = 'tenant' AND key = $5`, m, tenant, ident, status, role)
	time.Sleep(2 * time.Millisecond) // distinct created_at for a deterministic order
	return ident, m
}

func ids(ms []tenants.Member) []uuid.UUID {
	out := make([]uuid.UUID, 0, len(ms))
	for _, m := range ms {
		out = append(out, m.ID)
	}
	return out
}

// TestTenantScopeReads — GET /tenants, /tenants/{t}, /tenants/{t}/users[/{id}]: each call stays in the tenant of the
// path (or of the caller's identity); another tenant's object reads exactly like a missing one.
func TestTenantScopeReads(t *testing.T) {
	f := newFixture(t)
	a, idpA := f.tenant("tenant-a", "Tenant A", "active", true)
	b, idpB := f.tenant("tenant-b", "Tenant B", "active", true)
	p, _ := f.tenant("tenant-p", "Pending", "pending", false) // no instance yet
	alice, mAlice := f.member(a, idpA, "Alice Nguyen", "alice@a.test", "tenant_owner", "active")
	_, mBob := f.member(a, idpA, "", "bob_x@a.test", "tenant_viewer", "active") // no display name: falls back to e-mail
	_, mCarl := f.member(a, idpA, "Carl 100%", "", "end_user", "locked")
	bert, mBert := f.member(b, idpB, "Bert", "bert@b.test", "tenant_owner", "active")
	_, mAnon := f.member(b, idpB, "", "", "tenant_viewer", "active") // neither name nor e-mail: the subject
	ctx := t.Context()

	// GET /tenants/{t}
	ta, err := f.svc.GetTenant(ctx, a)
	if err != nil || ta.ID != a || ta.Slug != "tenant-a" || ta.ControlURL != "https://tenant-a.mesh.mg.test" ||
		ta.DeploymentRegion != "lab" || ta.Version != 1 {
		t.Fatalf("GetTenant(A) = %+v, %v", ta, err)
	}
	if tp, err := f.svc.GetTenant(ctx, p); err != nil || tp.ControlURL != "https://tenant-p.mesh.mg.test" {
		t.Fatalf("GetTenant(pending) = %+v, %v (control URL derived from the base domain)", tp, err)
	}
	if _, err := f.svc.GetTenant(ctx, uuid.New()); !errors.Is(err, tenants.ErrNotFound) {
		t.Fatalf("unknown tenant: %v", err)
	}

	// GET /tenants/{t}/users
	page, err := f.svc.ListMembers(ctx, a, tenants.MemberFilter{})
	if err != nil || !slices.Equal(ids(page.Items), []uuid.UUID{mAlice, mBob, mCarl}) || page.NextCursor != "" {
		t.Fatalf("ListMembers(A) = %v, %v", ids(page.Items), err)
	}
	for _, m := range page.Items {
		if m.TenantID != a || !strings.HasPrefix(m.HeadscaleUsername, "mg-") {
			t.Errorf("member %+v", m)
		}
	}
	if got := page.Items[1].DisplayName; got != "bob_x@a.test" {
		t.Errorf("display name of a member without one = %q, want the e-mail", got)
	}
	if got := page.Items[2].DisplayName; got != "Carl 100%" || page.Items[2].Email != "" {
		t.Errorf("member with a name and no e-mail: %+v", page.Items[2])
	}
	pb, _ := f.svc.ListMembers(ctx, b, tenants.MemberFilter{})
	if !slices.Equal(ids(pb.Items), []uuid.UUID{mBert, mAnon}) {
		t.Fatalf("ListMembers(B) = %v", ids(pb.Items))
	}
	if got := pb.Items[1].DisplayName; !strings.HasPrefix(got, "sub-") {
		t.Errorf("display name without name and e-mail = %q, want the subject", got)
	}
	for name, c := range map[string]struct {
		f    tenants.MemberFilter
		want []uuid.UUID
	}{
		"role":                {tenants.MemberFilter{Role: "tenant_owner"}, []uuid.UUID{mAlice}},
		"status":              {tenants.MemberFilter{Status: "locked"}, []uuid.UUID{mCarl}},
		"q display name":      {tenants.MemberFilter{Query: "nguyen"}, []uuid.UUID{mAlice}},
		"q e-mail":            {tenants.MemberFilter{Query: "BOB_X@"}, []uuid.UUID{mBob}},
		"q % is literal":      {tenants.MemberFilter{Query: "100%"}, []uuid.UUID{mCarl}},
		"q _ is literal":      {tenants.MemberFilter{Query: "b_x"}, []uuid.UUID{mBob}},
		"q matches nothing":   {tenants.MemberFilter{Query: "%%"}, nil},
		"other tenant's name": {tenants.MemberFilter{Query: "Bert"}, nil},
	} {
		got, err := f.svc.ListMembers(ctx, a, c.f)
		if err != nil || !slices.Equal(ids(got.Items), c.want) {
			t.Errorf("%s: %v, %v (want %v)", name, ids(got.Items), err, c.want)
		}
	}
	// pagination
	p1, err := f.svc.ListMembers(ctx, a, tenants.MemberFilter{Page: tenants.Page{Limit: 2}})
	if err != nil || len(p1.Items) != 2 || p1.NextCursor == "" {
		t.Fatalf("page 1: %v %v", ids(p1.Items), err)
	}
	p2, err := f.svc.ListMembers(ctx, a, tenants.MemberFilter{Page: tenants.Page{Limit: 2, Cursor: p1.NextCursor}})
	if err != nil || !slices.Equal(ids(p2.Items), []uuid.UUID{mCarl}) || p2.NextCursor != "" {
		t.Fatalf("page 2: %v %v", ids(p2.Items), err)
	}
	for name, mf := range map[string]tenants.MemberFilter{
		"limit 201": {Page: tenants.Page{Limit: 201}}, "limit -1": {Page: tenants.Page{Limit: -1}},
		"cursor": {Page: tenants.Page{Cursor: "%%%"}}, "role": {Role: "Tenant Owner"},
		"status": {Status: "ACTIVE"}, "q too long": {Query: strings.Repeat("x", 65)},
	} {
		if _, err := f.svc.ListMembers(ctx, a, mf); !errors.Is(err, tenants.ErrInvalid) {
			t.Errorf("invalid %s: %v", name, err)
		}
	}

	// GET /tenants/{t}/users/{id}: another tenant's membership is not found
	if m, err := f.svc.GetMember(ctx, a, mAlice); err != nil || m.IdentityID != alice || m.Role != "tenant_owner" {
		t.Fatalf("GetMember(A, alice) = %+v, %v", m, err)
	}
	for name, c := range map[string][2]uuid.UUID{"B's member in A": {a, mBert}, "A's member in B": {b, mAlice},
		"unknown": {a, uuid.New()}, "unknown tenant": {uuid.New(), mAlice}} {
		if _, err := f.svc.GetMember(ctx, c[0], c[1]); !errors.Is(err, tenants.ErrNotFound) {
			t.Errorf("%s: %v", name, err)
		}
	}

	// GET /tenants: the identity's own tenant only, active memberships only
	if l, err := f.svc.ListMemberTenants(ctx, alice, a, tenants.Page{}); err != nil || len(l.Items) != 1 || l.Items[0].ID != a {
		t.Fatalf("ListMemberTenants(alice) = %+v, %v", l, err)
	}
	if l, err := f.svc.ListMemberTenants(ctx, alice, b, tenants.Page{}); err != nil || len(l.Items) != 0 {
		t.Fatalf("alice in the scope of B: %+v, %v", l, err)
	}
	if l, err := f.svc.ListMemberTenants(ctx, bert, b, tenants.Page{}); err != nil || len(l.Items) != 1 || l.Items[0].ID != b {
		t.Fatalf("ListMemberTenants(bert) = %+v, %v", l, err)
	}
	f.exec(`UPDATE tenant_memberships SET status = 'locked' WHERE id = $1`, mBert)
	if l, _ := f.svc.ListMemberTenants(ctx, bert, b, tenants.Page{}); len(l.Items) != 0 {
		t.Errorf("locked membership listed: %+v", l)
	}
	f.exec(`UPDATE tenants SET status = 'deleted' WHERE id = $1`, a)
	if l, _ := f.svc.ListMemberTenants(ctx, alice, a, tenants.Page{}); len(l.Items) != 0 {
		t.Errorf("deleted tenant listed: %+v", l)
	}
}

// TestPlatformReads — GET /platform/tenants[/{t}]: every tenant's registry metadata; memberships stay invisible to the
// platform pool (tenant_memberships has no platform branch — §6.1), whatever a caller would try.
func TestPlatformReads(t *testing.T) {
	f := newFixture(t)
	a, idpA := f.tenant("tenant-a", "Tenant A", "active", true)
	b, _ := f.tenant("tenant-b", "Bravo_Corp", "suspended", true)
	c, _ := f.tenant("tenant-c", "Demo", "deleted", false)
	f.member(a, idpA, "Alice", "alice@a.test", "tenant_owner", "active")
	ctx := t.Context()

	all, err := f.svc.ListRegistry(ctx, tenants.RegistryFilter{})
	if err != nil || len(all.Items) != 3 || all.Items[0].ID != a || all.Items[1].ID != b || all.Items[2].ID != c {
		t.Fatalf("ListRegistry = %+v, %v", all, err)
	}
	for name, c := range map[string]struct {
		f    tenants.RegistryFilter
		want []uuid.UUID
	}{
		"status":       {tenants.RegistryFilter{Status: "suspended"}, []uuid.UUID{b}},
		"q slug":       {tenants.RegistryFilter{Query: "TENANT-C"}, []uuid.UUID{c}},
		"q name":       {tenants.RegistryFilter{Query: "o_c"}, []uuid.UUID{b}},
		"q literal _":  {tenants.RegistryFilter{Query: "t_nant"}, nil},
		"page of one":  {tenants.RegistryFilter{Page: tenants.Page{Limit: 1}}, []uuid.UUID{a}},
		"q and status": {tenants.RegistryFilter{Status: "active", Query: "tenant-b"}, nil},
	} {
		got, err := f.svc.ListRegistry(ctx, c.f)
		var gotIDs []uuid.UUID
		for _, x := range got.Items {
			gotIDs = append(gotIDs, x.ID)
		}
		if err != nil || !slices.Equal(gotIDs, c.want) {
			t.Errorf("%s: %v, %v (want %v)", name, gotIDs, err, c.want)
		}
	}
	if _, err := f.svc.ListRegistry(ctx, tenants.RegistryFilter{Status: "sleeping"}); !errors.Is(err, tenants.ErrInvalid) {
		t.Errorf("unknown status: %v", err)
	}
	if tb, err := f.svc.GetRegistry(ctx, b); err != nil || tb.Status != "suspended" || tb.Name != "Bravo_Corp" {
		t.Fatalf("GetRegistry(B) = %+v, %v", tb, err)
	}
	if _, err := f.svc.GetRegistry(ctx, uuid.New()); !errors.Is(err, tenants.ErrNotFound) {
		t.Errorf("unknown: %v", err)
	}
	// the platform pool cannot read memberships at all, even with the tenant's id: mg_api_platform has no privilege on
	// tenant_memberships (0002) — staff see registry metadata only (§8.4 invariant 2)
	err = f.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		rows, err := q.ListTenantMembersPage(ctx, sqlcdb.ListTenantMembersPageParams{TenantID: a, RowLimit: 10})
		if err == nil {
			t.Errorf("platform scope read %d memberships", len(rows))
		}
		return err
	})
	if store.SQLState(err) != "42501" {
		t.Fatalf("platform scope on tenant_memberships: %v, want permission denied (42501)", err)
	}
}

// TestLocateInstance — the registry half of Registry.ForTenant: the live instance of a tenant with its key reference,
// read in the tenant's own scope.
func TestLocateInstance(t *testing.T) {
	f := newFixture(t)
	a, _ := f.tenant("tenant-a", "Tenant A", "active", true)
	b, _ := f.tenant("tenant-b", "Tenant B", "active", true)
	p, _ := f.tenant("tenant-p", "Pending", "pending", false)
	f.exec(`UPDATE tenant_instances SET api_key_secret_ref = 'mgsec://'||tenant_id::text||'/headscale-api-key#3',
		api_key_prefix = 'pfx' WHERE tenant_id = $1`, a)
	ctx := t.Context()
	ra, err := f.svc.LocateInstance(ctx, a)
	if err != nil || ra.TenantID != a || ra.TenantSlug != "tenant-a" || ra.TenantStatus != "active" ||
		ra.Status != "running" || ra.APIKeyRef != "mgsec://"+a.String()+"/headscale-api-key#3" || ra.APIKeyPrefix != "pfx" {
		t.Fatalf("LocateInstance(A) = %+v, %v", ra, err)
	}
	rb, err := f.svc.LocateInstance(ctx, b)
	if err != nil || rb.TenantID != b || rb.InstanceID == ra.InstanceID || rb.APIKeyRef != "" {
		t.Fatalf("LocateInstance(B) = %+v, %v", rb, err)
	}
	for name, id := range map[string]uuid.UUID{"unknown": uuid.New(), "no instance": p, "nil": uuid.Nil} {
		if _, err := f.svc.LocateInstance(ctx, id); !errors.Is(err, tenants.ErrNotFound) {
			t.Errorf("%s: %v", name, err)
		}
	}
	f.exec(`UPDATE tenant_instances SET status = 'removed' WHERE tenant_id = $1`, b)
	if _, err := f.svc.LocateInstance(ctx, b); !errors.Is(err, tenants.ErrNotFound) {
		t.Errorf("removed instance: %v", err)
	}
}

func adoption(host uuid.UUID, slug string, n int32) tenants.Adoption {
	tid := uuid.Must(uuid.NewV7())
	return tenants.Adoption{TenantID: tid, Slug: slug, Name: "Tenant " + slug, Region: "lab",
		Instance: tenants.InstanceSpec{ID: uuid.Must(uuid.NewV7()), HostID: host, HeadscaleVersion: "v0.29.7",
			ImageDigest: "sha256:" + strings.Repeat("b", 64), ControlHostname: slug + ".mesh.mg.test",
			ServerURL: "https://" + slug + ".mesh.mg.test", BaseDomain: slug + ".tail.mg.test",
			InternalAddress: "hs-" + slug + ":8080", RunUID: 30100 + n,
			NetCIDR: netip.MustParsePrefix("10.250.1." + strconv.Itoa(int(8*n)) + "/29"), DataPath: "/data/" + slug},
		IdP: tenants.IdPSpec{ID: uuid.Must(uuid.NewV7()), Scope: "tenant", TenantID: &tid,
			Issuer: "https://auth.mg.test/realms/" + slug, ClientID: "mg-portal", Driver: "keycloak", DriverRef: slug}}
}

// TestRegisterIsIdempotent — CheckAdoption writes nothing; Register creates once, then is a no-op; Activate moves
// provisioning/starting to active/running once; database constraints become ErrConflict.
func TestRegisterIsIdempotent(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	ad := adoption(f.host, "tenant-a", 1)
	st, err := f.svc.CheckAdoption(ctx, ad)
	if err != nil || st.TenantExists || st.InstanceExists || st.IdPExists {
		t.Fatalf("CheckAdoption on an empty registry = %+v, %v", st, err)
	}
	var n int
	if err := f.su.QueryRow(ctx, `SELECT count(*) FROM tenants`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("CheckAdoption wrote %d tenants (%v)", n, err)
	}
	if _, err := f.svc.Register(ctx, ad); err != nil {
		t.Fatal(err)
	}
	st, err = f.svc.Register(ctx, ad)
	if err != nil || !st.TenantExists || !st.InstanceExists || !st.IdPExists || st.RuntimeUpdated ||
		st.TenantStatus != "provisioning" || st.InstanceStatus != "starting" {
		t.Fatalf("second Register = %+v, %v", st, err)
	}
	// a new Headscale version is an observation: updated, not a conflict
	ad.Instance.HeadscaleVersion = "v0.29.8"
	if st, err := f.svc.Register(ctx, ad); err != nil || !st.RuntimeUpdated {
		t.Fatalf("Register with a new version = %+v, %v", st, err)
	}
	act, err := f.svc.Activate(ctx, ad.TenantID, ad.Instance.ID)
	if err != nil || act.TenantFrom != "provisioning" || act.InstanceFrom != "starting" {
		t.Fatalf("Activate = %+v, %v", act, err)
	}
	if act, err := f.svc.Activate(ctx, ad.TenantID, ad.Instance.ID); err != nil || act != (tenants.Activation{}) {
		t.Fatalf("second Activate = %+v, %v", act, err)
	}
	prev, err := f.svc.SetInstanceAPIKey(ctx, ad.TenantID, ad.Instance.ID, tenants.APIKey{
		Ref: "mgsec://" + ad.TenantID.String() + "/headscale-api-key#1", Prefix: "p1"})
	if err != nil || prev.Ref != "" {
		t.Fatalf("SetInstanceAPIKey = %+v, %v", prev, err)
	}
	if prev, _ := f.svc.SetInstanceAPIKey(ctx, ad.TenantID, ad.Instance.ID, tenants.APIKey{}); prev.Prefix != "p1" {
		t.Fatalf("previous key %+v", prev)
	}
	if _, err := f.svc.SetInstanceAPIKey(ctx, uuid.New(), ad.Instance.ID, tenants.APIKey{}); !errors.Is(err, tenants.ErrNotFound) {
		t.Fatalf("SetInstanceAPIKey for another tenant: %v", err)
	}

	// another tenant on the same UID or network of the host: refused by the database ⇒ ErrConflict
	b := adoption(f.host, "tenant-b", 2)
	b.Instance.RunUID = ad.Instance.RunUID
	if _, err := f.svc.Register(ctx, b); !errors.Is(err, tenants.ErrConflict) {
		t.Fatalf("same run_uid: %v", err)
	}
	b = adoption(f.host, "tenant-b", 2)
	b.Instance.NetCIDR = ad.Instance.NetCIDR
	if _, err := f.svc.Register(ctx, b); !errors.Is(err, tenants.ErrConflict) {
		t.Fatalf("same net_cidr: %v", err)
	}
	if err := f.su.QueryRow(ctx, `SELECT count(*) FROM tenants WHERE slug = 'tenant-b'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("a refused registration left %d rows (%v)", n, err)
	}
	// invalid specifications
	bad := adoption(f.host, "Bad_Slug", 3)
	if _, err := f.svc.Register(ctx, bad); !errors.Is(err, tenants.ErrInvalid) {
		t.Fatalf("invalid slug: %v", err)
	}
	bad = adoption(uuid.Nil, "tenant-c", 3)
	if _, err := f.svc.Register(ctx, bad); !errors.Is(err, tenants.ErrInvalid) {
		t.Fatalf("Register without host: %v", err)
	}
	if _, err := f.svc.CheckAdoption(ctx, bad); err != nil {
		t.Fatalf("CheckAdoption accepts a host not registered yet: %v", err)
	}
}

// TestIdentityProviders — the platform IdP and client secret references (register-platform-idp,
// set-idp-client-secret): idempotent, issuer/client immutable, one active platform IdP.
func TestIdentityProviders(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	spec := tenants.IdPSpec{ID: uuid.Must(uuid.NewV7()), Scope: "platform", Issuer: "https://auth.mg.test/realms/platform",
		ClientID: "mg-portal", Driver: "keycloak", DriverRef: "platform"}
	p, existed, err := f.svc.RegisterIdP(ctx, spec)
	if err != nil || existed || p.Status != "active" || p.TenantID != nil || p.DriverRef != "platform" {
		t.Fatalf("RegisterIdP = %+v, %v, %v", p, existed, err)
	}
	if _, existed, err := f.svc.RegisterIdP(ctx, spec); err != nil || !existed {
		t.Fatalf("second RegisterIdP: %v %v", existed, err)
	}
	other := spec
	other.Issuer = "https://auth.other.test/realms/platform"
	if _, _, err := f.svc.RegisterIdP(ctx, other); !errors.Is(err, tenants.ErrConflict) {
		t.Fatalf("issuer change: %v", err)
	}
	second := spec
	second.ID, second.ClientID = uuid.Must(uuid.NewV7()), "mg-portal-2"
	if _, _, err := f.svc.RegisterIdP(ctx, second); !errors.Is(err, tenants.ErrConflict) {
		t.Fatalf("second active platform IdP: %v", err)
	}
	bad := spec
	bad.Issuer = "http://auth.mg.test/realms/platform"
	if _, _, err := f.svc.RegisterIdP(ctx, bad); !errors.Is(err, tenants.ErrInvalid) {
		t.Fatalf("http issuer: %v", err)
	}
	ref := "mgsec://platform/idp-client-secret." + spec.ID.String() + "#1"
	if prev, err := f.svc.SetIdPClientSecretRef(ctx, spec.ID, ref); err != nil || prev != "" {
		t.Fatalf("SetIdPClientSecretRef = %q, %v", prev, err)
	}
	if got, err := f.svc.GetIdP(ctx, spec.ID); err != nil || got.ClientSecretRef != ref {
		t.Fatalf("GetIdP = %+v, %v", got, err)
	}
	if _, err := f.svc.SetIdPClientSecretRef(ctx, uuid.New(), ref); !errors.Is(err, tenants.ErrNotFound) {
		t.Fatalf("unknown IdP: %v", err)
	}
}
