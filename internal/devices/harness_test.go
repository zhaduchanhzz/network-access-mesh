package devices

// PostgreSQL integration harness of internal/devices: every test gets its own database (internal/store/storetest:
// bootstrap, goose + River migrations, role passwords — the only place that holds the cluster lock and derives role
// passwords) with two tenants, each with a running instance served by its own fake Headscale (devicestest) reached
// through the real adapter.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/devices/devicestest"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/storetest"
)

func TestMain(m *testing.M) {
	code := m.Run()
	storetest.Cleanup()
	os.Exit(code)
}

// tenantFx is one fixture tenant: its running instance, its fake Headscale and two members.
type tenantFx struct {
	id, instance uuid.UUID
	slug         string
	hs           *devicestest.Fake
	alice, bob   uuid.UUID // memberships (tenant_memberships.id); Headscale user names mg-<id>
	aliceUser    uint64    // Headscale user ids of the fake
	bobUser      uint64
}

func (t *tenantFx) userName(m uuid.UUID) string { return "mg-" + m.String() }

type fixture struct {
	env   *storetest.Env
	db    string
	su    *pgx.Conn
	mu    sync.Mutex // guards su
	a, b  *tenantFx
	reg   *headscale.CachingRegistry
	api   *Service // api process (mg_api_*)
	wrk   *Service // worker process (mg_worker_*)
	apiSt *store.Store
	wrkSt *store.Store
	host  uuid.UUID
	n     int
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	env := storetest.Require(t)
	f := &fixture{env: env, db: env.NewDatabase(t), host: uuid.New()}
	f.su = env.Admin(t, f.db)
	f.exec(t, `INSERT INTO hosts (id, name, region, run_uid_range, tenant_net_pool)
		VALUES ($1, 'host-1', 'lab', int4range(30000, 40000), '10.250.0.0/16')`, f.host)
	f.a, f.b = f.newTenant(t), f.newTenant(t)
	f.reg = devicestest.Registry(map[uuid.UUID]headscale.Target{
		f.a.id: f.a.hs.Target(f.a.instance), f.b.id: f.b.hs.Target(f.b.instance)})
	f.apiSt = env.OpenStore(t, f.db, "mg_api_tenant", "mg_api_platform", 6)
	f.wrkSt = env.OpenStore(t, f.db, "mg_worker_tenant", "mg_worker_platform", 6)
	f.api = f.service(t, f.apiSt)
	f.wrk = f.service(t, f.wrkSt)
	return f
}

func (f *fixture) service(t *testing.T, st *store.Store) *Service {
	t.Helper()
	s, err := New(st, Config{Registry: f.reg, Registerer: prometheus.NewRegistry(), FreshTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	s.sysWait = 5 * time.Second
	return s
}

func (f *fixture) newTenant(t *testing.T) *tenantFx {
	t.Helper()
	f.n++
	i := f.n
	ten := &tenantFx{id: uuid.New(), instance: uuid.New(), slug: fmt.Sprintf("tenant%02d", i)}
	ten.hs = devicestest.New(t, ten.slug)
	f.exec(t, `INSERT INTO tenants (id, slug, name, status) VALUES ($1, $2, $3, 'active')`, ten.id, ten.slug, "Tenant "+ten.slug)
	f.exec(t, `INSERT INTO tenant_instances (id, tenant_id, host_id, status, headscale_version, image_digest,
			control_hostname, server_url, base_domain, internal_address, run_uid, net_cidr, data_path)
		VALUES ($1, $2, $3, 'running', '0.29.7', 'sha256:'||repeat('a', 64), $4, 'https://'||$4, $5, $6, $7, $8::cidr, $9)`,
		ten.instance, ten.id, f.host, ten.slug+".mesh.test", ten.slug+".ts.test", "hs-"+ten.slug+":8080", 30000+i,
		fmt.Sprintf("10.250.%d.0/29", i), "/opt/meshguard/tenants/"+ten.instance.String())
	idp := uuid.New()
	f.exec(t, `INSERT INTO identity_providers (id, scope, tenant_id, issuer, client_id, driver, status)
		VALUES ($1, 'tenant', $2, $3, 'mg-portal', 'keycloak', 'active')`, idp, ten.id, "https://idp.invalid/realms/"+ten.slug)
	member := func(name string) uuid.UUID {
		ident, m := uuid.New(), uuid.Nil
		f.exec(t, `INSERT INTO identities (id, idp_id, tenant_id, scope, subject, email, email_verified, display_name)
			VALUES ($1, $2, $3, 'tenant', $4, $5, true, $6)`, ident, idp, ten.id, name+"-"+ten.slug, name+"@"+ten.slug+".test", name)
		f.scan(t, `INSERT INTO tenant_memberships (tenant_id, identity_id, role_id, status)
			SELECT $1, $2, id, 'active' FROM roles WHERE scope = 'tenant' AND key = 'end_user' RETURNING id`,
			[]any{ten.id, ident}, &m)
		return m
	}
	ten.alice, ten.bob = member("Alice"), member("Bob")
	ten.aliceUser, ten.bobUser = 11, 12
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

func count(t *testing.T, f *fixture, sql string, args ...any) int {
	t.Helper()
	var n int
	f.scan(t, sql, args, &n)
	return n
}

// row reads a device row as the superuser (bypasses RLS: the test checks the database itself).
func (f *fixture) row(t *testing.T, id uuid.UUID) sqlcdb.DeviceInventoryCache {
	t.Helper()
	var r sqlcdb.DeviceInventoryCache
	err := f.wrkSt.WithTenantTx(context.Background(), f.tenantOf(t, id), func(q *sqlcdb.Queries) error {
		var err error
		r, err = q.LockDevice(context.Background(), sqlcdb.LockDeviceParams{TenantID: f.tenantOf(t, id), ID: id})
		return err
	})
	if err != nil {
		t.Fatalf("device %s: %v", id, err)
	}
	return r
}

func (f *fixture) tenantOf(t *testing.T, device uuid.UUID) uuid.UUID {
	t.Helper()
	var ten uuid.UUID
	f.scan(t, `SELECT tenant_id FROM device_inventory_cache WHERE id = $1`, []any{device}, &ten)
	return ten
}

// deviceOfNode returns the live device of a node of tenant ten.
func (f *fixture) deviceOfNode(t *testing.T, ten *tenantFx, node uint64) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	f.scan(t, `SELECT id FROM device_inventory_cache WHERE tenant_id = $1 AND instance_id = $2 AND headscale_node_id = $3
		AND removed_at IS NULL`, []any{ten.id, ten.instance, int64(node)}, &id) //nolint:gosec // test node ids
	return id
}

// setNodeExpiry sets TenantSettings.node_expiry of a tenant ("" removes it).
func (f *fixture) setNodeExpiry(t *testing.T, ten *tenantFx, v string) {
	t.Helper()
	if v == "" {
		f.exec(t, `UPDATE tenants SET settings = settings - 'node_expiry' WHERE id = $1`, ten.id)
		return
	}
	f.exec(t, `UPDATE tenants SET settings = jsonb_set(settings, '{node_expiry}', to_jsonb($2::text)) WHERE id = $1`, ten.id, v)
}

// userNode builds a node of a member, registered at created with expiry exp.
func userNode(ten *tenantFx, id uint64, member uuid.UUID, user uint64, created time.Time, exp *time.Time) devicestest.Node {
	return devicestest.Node{ID: id, MachineKey: fmt.Sprintf("mkey:%064x", id+uint64(ten.instance[0])<<32),
		NodeKey: fmt.Sprintf("nodekey:%064x", id), Hostname: fmt.Sprintf("host-%d", id), GivenName: fmt.Sprintf("host-%d", id),
		UserID: user, UserName: ten.userName(member), IPs: []netip.Addr{netip.MustParseAddr(fmt.Sprintf("100.64.0.%d", id))},
		Method: "authkey", Online: true, CreatedAt: created, Expiry: exp}
}

func tp(t time.Time) *time.Time { return &t }

// actor is the audit scope of a request of an identity (what the audit middleware sets).
func actorCtx(identity uuid.UUID, tenant uuid.UUID, action string) context.Context {
	id, ten := identity, tenant
	return audit.WithRequest(context.Background(), &audit.Request{Action: action, ActorType: audit.ActorIdentity,
		ActorIdentityID: &id, ActorTenantID: &ten, TenantID: &ten, ResourceType: "device", RequestID: "req-" + action})
}

// run builds the jobs.Run a worker hands to a handler for one attempt of job id.
func (f *fixture) run(t *testing.T, id uuid.UUID, attempt, maxAttempts int) *jobs.Run {
	t.Helper()
	r, err := f.runOf(id, attempt, maxAttempts)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// runOf is run without testing.T, for the hooks of the fake (they run on its handler goroutine: no t.Fatal there).
func (f *fixture) runOf(id uuid.UUID, attempt, maxAttempts int) (*jobs.Run, error) {
	var j sqlcdb.ProvisioningJob
	if err := f.wrkSt.WithPlatformTx(context.Background(), func(q *sqlcdb.Queries) error {
		var err error
		j, err = q.GetJob(context.Background(), id)
		return err
	}); err != nil {
		return nil, fmt.Errorf("job %s: %w", id, err)
	}
	return &jobs.Run{ID: j.ID, Kind: j.Kind, TenantID: j.TenantID, InstanceID: j.InstanceID, Input: json.RawMessage(j.Input),
		Attempt: attempt, MaxAttempts: maxAttempts, Deadline: time.Now().Add(time.Minute), Store: f.wrkSt}, nil
}

// auditActions lists the actions of the events of an operation or resource, oldest first.
func (f *fixture) auditOf(t *testing.T, resource string) []string {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	rows, err := f.su.Query(context.Background(), `SELECT action || '/' || outcome FROM audit_events WHERE resource_id = $1
		ORDER BY occurred_at, id`, resource)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		out = append(out, s)
	}
	return out
}

// pairs reports whether every *.requested of the resource has exactly one outcome with the same operation id.
func (f *fixture) openOperations(t *testing.T, tenant uuid.UUID) int {
	t.Helper()
	return count(t, f, `SELECT count(*) FROM audit_events r WHERE r.tenant_id = $1 AND r.action LIKE '%.requested'
		AND NOT EXISTS (SELECT 1 FROM audit_events o WHERE o.operation_id = r.operation_id
		                AND (o.action LIKE '%.succeeded' OR o.action LIKE '%.failed'))`, tenant)
}

// finishJob records the end of a job as the framework does once a handler called directly returned.
func (f *fixture) finishJob(t *testing.T, id uuid.UUID, status string) {
	t.Helper()
	f.exec(t, `UPDATE provisioning_jobs SET status = $2, finished_at = now() WHERE id = $1`, id, status)
}
