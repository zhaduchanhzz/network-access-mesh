package policies

// PostgreSQL integration harness of the policy core: every test gets its own database (internal/store/storetest) with two
// tenants, each with a running instance and four members (Owner, Admin, Viewer, End User — verified addresses), and a
// fake Headscale per tenant behind a fake headscale.Registry (the adapter's policy calls only). The real Headscale is
// exercised by the contract tests (tests/integration/headscale, phase 12).

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/storetest"
)

func TestMain(m *testing.M) {
	code := m.Run()
	storetest.Cleanup()
	os.Exit(code)
}

// fakeHS is the policy part of a Headscale instance: it stores the policy like 0.29.7 (GetPolicy returns exactly what
// SetPolicy stored) and records every call. Other Instance methods are not implemented (nil embedded interface).
type fakeHS struct {
	headscale.Instance
	name string

	mu        sync.Mutex
	stored    string
	calls     []string
	inflight  int
	max       int
	delay     time.Duration
	checkErr  error               // CheckPolicy answers this (persistent)
	setErrs   []error             // next SetPolicy answers (consumed); nil entry = success
	swapOnErr bool                // a failing SetPolicy still swaps the policy (V-26: in memory before the DB write)
	getErr    error               // GetPolicy answers this (persistent)
	mangle    func(string) string // read-back alteration
	global    *concurrency        // cross-tenant concurrency observer
}

type concurrency struct {
	mu       sync.Mutex
	inflight int
	max      int
}

func (f *fakeHS) enter(op string) func() {
	f.mu.Lock()
	f.calls = append(f.calls, op)
	f.inflight++
	if f.inflight > f.max {
		f.max = f.inflight
	}
	f.mu.Unlock()
	if f.global != nil {
		f.global.mu.Lock()
		f.global.inflight++
		if f.global.inflight > f.global.max {
			f.global.max = f.global.inflight
		}
		f.global.mu.Unlock()
	}
	if f.delay > 0 {
		time.Sleep(f.delay)
	}
	return func() {
		f.mu.Lock()
		f.inflight--
		f.mu.Unlock()
		if f.global != nil {
			f.global.mu.Lock()
			f.global.inflight--
			f.global.mu.Unlock()
		}
	}
}

func (f *fakeHS) CheckPolicy(_ context.Context, p string) error {
	defer f.enter("CheckPolicy")()
	if err := headscale.ValidatePolicyDocument(p); err != nil {
		return &headscale.Error{Op: headscale.OpCheckPolicy, Kind: headscale.KindValidation}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.checkErr
}

func (f *fakeHS) SetPolicy(_ context.Context, p string) (headscale.Policy, error) {
	defer f.enter("SetPolicy")()
	f.mu.Lock()
	defer f.mu.Unlock()
	var err error
	if len(f.setErrs) > 0 {
		err, f.setErrs = f.setErrs[0], f.setErrs[1:]
	}
	if err != nil {
		if f.swapOnErr {
			f.stored = p
		}
		return headscale.Policy{}, err
	}
	f.stored = p
	return headscale.Policy{Data: p, UpdatedAt: time.Now()}, nil
}

func (f *fakeHS) GetPolicy(context.Context) (headscale.Policy, error) {
	defer f.enter("GetPolicy")()
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.getErr != nil {
		return headscale.Policy{}, f.getErr
	}
	if f.stored == "" {
		return headscale.Policy{}, &headscale.Error{Op: headscale.OpGetPolicy, Kind: headscale.KindNoPolicy}
	}
	d := f.stored
	if f.mangle != nil {
		d = f.mangle(d)
	}
	return headscale.Policy{Data: d, UpdatedAt: time.Now()}, nil
}

func (f *fakeHS) Stored() string { f.mu.Lock(); defer f.mu.Unlock(); return f.stored }
func (f *fakeHS) Calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

// fakeReg is the headscale.Registry of the tests: ForTenant returns the tenant's fake and counts the calls.
type fakeReg struct {
	mu    sync.Mutex
	hs    map[uuid.UUID]*fakeHS
	calls int
}

func (r *fakeReg) ForTenant(_ context.Context, t uuid.UUID) (headscale.Instance, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	h, ok := r.hs[t]
	if !ok {
		return nil, &headscale.Error{Op: headscale.OpForTenant, Kind: headscale.KindUnavailable}
	}
	return h, nil
}

func (r *fakeReg) count() int { r.mu.Lock(); defer r.mu.Unlock(); return r.calls }

// tenantFx is one fixture tenant.
type tenantFx struct {
	id, instance                uuid.UUID
	slug                        string
	owner, admin, viewer, endUs uuid.UUID // memberships
	hs                          *fakeHS
}

type fixture struct {
	env  *storetest.Env
	db   string
	su   *pgx.Conn
	mu   sync.Mutex
	a, b *tenantFx
	reg  *fakeReg
	st   *store.Store // worker (mg_worker_*)
	svc  *Service
	host uuid.UUID
	n    int
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	env := storetest.Require(t)
	f := &fixture{env: env, db: env.NewDatabase(t), host: uuid.New()}
	f.su = env.Admin(t, f.db)
	f.exec(t, `INSERT INTO hosts (id, name, region, run_uid_range, tenant_net_pool)
		VALUES ($1, 'host-1', 'lab', int4range(30000, 40000), '10.250.0.0/16')`, f.host)
	f.a, f.b = f.newTenant(t), f.newTenant(t)
	f.reg = &fakeReg{hs: map[uuid.UUID]*fakeHS{f.a.id: f.a.hs, f.b.id: f.b.hs}}
	f.st = env.OpenStore(t, f.db, "mg_worker_tenant", "mg_worker_platform", 8)
	svc, err := New(f.st, Config{Registry: f.reg, LockWait: 30 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	f.svc = svc
	return f
}

func (f *fixture) newTenant(t *testing.T) *tenantFx {
	t.Helper()
	f.n++
	i := f.n
	ten := &tenantFx{id: uuid.New(), instance: uuid.New(), slug: fmt.Sprintf("tenant%02d", i)}
	ten.hs = &fakeHS{name: ten.slug}
	f.exec(t, `INSERT INTO tenants (id, slug, name, status) VALUES ($1, $2, $3, 'active')`, ten.id, ten.slug, "Tenant "+ten.slug)
	f.exec(t, `INSERT INTO tenant_instances (id, tenant_id, host_id, status, headscale_version, image_digest,
			control_hostname, server_url, base_domain, internal_address, run_uid, net_cidr, data_path)
		VALUES ($1, $2, $3, 'running', '0.29.7', 'sha256:'||repeat('a', 64), $4, 'https://'||$4, $5, $6, $7, $8::cidr, $9)`,
		ten.instance, ten.id, f.host, ten.slug+".mesh.test", ten.slug+".ts.test", "hs-"+ten.slug+":8080", 30000+i,
		fmt.Sprintf("10.250.%d.0/29", i), "/opt/meshguard/tenants/"+ten.instance.String())
	idp := uuid.New()
	f.exec(t, `INSERT INTO identity_providers (id, scope, tenant_id, issuer, client_id, driver, status)
		VALUES ($1, 'tenant', $2, $3, 'mg-portal', 'keycloak', 'active')`, idp, ten.id, "https://idp.invalid/realms/"+ten.slug)
	member := func(name, role string) uuid.UUID {
		ident, m := uuid.New(), uuid.Nil
		f.exec(t, `INSERT INTO identities (id, idp_id, tenant_id, scope, subject, email, email_verified, display_name)
			VALUES ($1, $2, $3, 'tenant', $4, $5, true, $6)`, ident, idp, ten.id, name+"-"+ten.slug, name+"@"+ten.slug+".test", name)
		f.scan(t, `INSERT INTO tenant_memberships (tenant_id, identity_id, role_id, status)
			SELECT $1, $2, id, 'active' FROM roles WHERE scope = 'tenant' AND key = $3 RETURNING id`,
			[]any{ten.id, ident, role}, &m)
		return m
	}
	ten.owner, ten.admin = member("owner", "tenant_owner"), member("admin", "tenant_admin")
	ten.viewer, ten.endUs = member("viewer", "tenant_viewer"), member("eu", "end_user")
	return ten
}

func (f *fixture) exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, err := f.su.Exec(context.Background(), sql, args...); err != nil {
		t.Fatalf("superuser exec: %v\n%s", err, sql)
	}
}

func (f *fixture) scan(t *testing.T, sql string, args []any, dest ...any) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.su.QueryRow(context.Background(), sql, args...).Scan(dest...); err != nil {
		t.Fatalf("superuser query: %v\n%s", err, sql)
	}
}

func (f *fixture) count(t *testing.T, sql string, args ...any) int {
	t.Helper()
	var n int
	f.scan(t, sql, args, &n)
	return n
}
