package monitoring

// PostgreSQL integration harness of internal/monitoring: every test gets its own database (internal/store/storetest —
// the only place that holds the cluster lock and derives role passwords) with two tenants A and B, each with a running
// instance served by its own fake Headscale (devicestest) reached through the REAL adapter (internal/headscale: version
// check, error classification, circuit breaker). The Prober and DeviceCounter are the glue of apps/* (§13.6) — the
// test files may import headscale and devices; the package itself does not (internal/archtest).

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

	"github.com/zhaduchanhzz/network-access-mesh/internal/devices"
	"github.com/zhaduchanhzz/network-access-mesh/internal/devices/devicestest"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/storetest"
)

func TestMain(m *testing.M) {
	code := m.Run()
	storetest.Cleanup()
	os.Exit(code)
}

// adapterProber is the Prober of apps/*: headscale.CachingRegistry.Probe mapped to the module's type.
func adapterProber(reg *headscale.CachingRegistry) Prober {
	return ProberFunc(func(ctx context.Context, t uuid.UUID) InstanceProbe {
		p := reg.Probe(ctx, t)
		return InstanceProbe{InstanceID: p.InstanceID, Version: p.Version, Database: p.Database, Breaker: string(p.Breaker),
			Reason: p.Reason(), Duration: p.Duration}
	})
}

// deviceCounter is the DeviceCounter of apps/*: devices.Service.Summary (same fields — the conversion is checked by
// the compiler).
func deviceCounter(svc *devices.Service) DeviceCounter {
	return DeviceCounterFunc(func(ctx context.Context, t uuid.UUID) (DeviceCounts, error) {
		s, err := svc.Summary(ctx, t)
		return DeviceCounts(s), err
	})
}

type tenantFx struct {
	id, instance uuid.UUID
	slug         string
	hs           *devicestest.Fake
}

type fixture struct {
	env    *storetest.Env
	db     string
	su     *pgx.Conn
	mu     sync.Mutex // guards su
	a, b   *tenantFx
	host   uuid.UUID
	n      int
	reg    *headscale.CachingRegistry
	apiSt  *store.Store
	wrkSt  *store.Store
	devAPI *devices.Service // devices of the api process (dashboard figures)
	devWrk *devices.Service // devices of the worker process (syncs)
	api    *Service         // monitoring of the api process (mg_api_*)
	wrk    *Service         // monitoring of the worker process (mg_worker_*)
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	env := storetest.Require(t)
	f := &fixture{env: env, db: env.NewDatabase(t), host: uuid.New()}
	f.su = env.Admin(t, f.db)
	f.exec(t, `INSERT INTO hosts (id, name, region, run_uid_range, tenant_net_pool)
		VALUES ($1, 'host-1', 'lab', int4range(30000, 40000), '10.250.0.0/16')`, f.host)
	f.a, f.b = f.newTenant(t, "active"), f.newTenant(t, "active")
	f.reg = devicestest.Registry(map[uuid.UUID]headscale.Target{f.a.id: f.a.hs.Target(f.a.instance), f.b.id: f.b.hs.Target(f.b.instance)})
	f.apiSt = env.OpenStore(t, f.db, "mg_api_tenant", "mg_api_platform", 6)
	f.wrkSt = env.OpenStore(t, f.db, "mg_worker_tenant", "mg_worker_platform", 6)
	var err error
	if f.devAPI, err = devices.New(f.apiSt, devices.Config{Registry: f.reg}); err != nil {
		t.Fatal(err)
	}
	if f.devWrk, err = devices.New(f.wrkSt, devices.Config{Registry: f.reg}); err != nil {
		t.Fatal(err)
	}
	f.api = f.service(t, f.apiSt, f.devAPI, nil)
	f.wrk = f.service(t, f.wrkSt, f.devWrk, adapterProber(f.reg))
	return f
}

func (f *fixture) service(t *testing.T, st *store.Store, dev *devices.Service, p Prober) *Service {
	t.Helper()
	s, err := New(st, Config{Devices: deviceCounter(dev), Prober: p, Registerer: prometheus.NewRegistry()})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// newTenant creates a tenant with the given status and a running instance served by a fresh fake Headscale.
func (f *fixture) newTenant(t *testing.T, status string) *tenantFx {
	t.Helper()
	f.n++
	i := f.n
	ten := &tenantFx{id: uuid.New(), instance: uuid.New(), slug: fmt.Sprintf("tenant%02d", i)}
	ten.hs = devicestest.New(t, ten.slug)
	f.exec(t, `INSERT INTO tenants (id, slug, name, status) VALUES ($1, $2, $3, $4)`, ten.id, ten.slug, "Tenant "+ten.slug, status)
	f.addInstance(t, ten, ten.instance, "running")
	return ten
}

func (f *fixture) addInstance(t *testing.T, ten *tenantFx, id uuid.UUID, status string) {
	t.Helper()
	f.n++
	f.exec(t, `INSERT INTO tenant_instances (id, tenant_id, host_id, status, headscale_version, image_digest,
			control_hostname, server_url, base_domain, internal_address, run_uid, net_cidr, data_path)
		VALUES ($1, $2, $3, $4, '0.29.7', 'sha256:'||repeat('a', 64), $5, 'https://'||$5, $6, $7, $8, $9::cidr, $10)`,
		id, ten.id, f.host, status, fmt.Sprintf("%s-%d.mesh.test", ten.slug, f.n), ten.slug+".ts.test", "hs-"+ten.slug+":8080",
		30000+f.n, fmt.Sprintf("10.250.%d.0/29", f.n), "/opt/meshguard/tenants/"+id.String())
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

// instanceRow is what the database holds for an instance (read as the superuser).
type instanceRow struct {
	status       string
	health       record
	raw          []byte
	healthAt     *time.Time
	version      int64
	updatedAt    time.Time
	hasHealthDoc bool
}

func (f *fixture) instanceRow(t *testing.T, id uuid.UUID) instanceRow {
	t.Helper()
	var r instanceRow
	f.scan(t, `SELECT status, last_health, last_health_at, version, updated_at FROM tenant_instances WHERE id = $1`, []any{id},
		&r.status, &r.raw, &r.healthAt, &r.version, &r.updatedAt)
	if len(r.raw) > 0 {
		r.hasHealthDoc = true
		if err := json.Unmarshal(r.raw, &r.health); err != nil {
			t.Fatalf("last_health of %s: %v (%s)", id, err, r.raw)
		}
	}
	return r
}

// node is a user-owned node of the fake instance.
func node(id uint64, online bool) devicestest.Node {
	now := time.Now().UTC()
	exp := now.Add(24 * time.Hour)
	return devicestest.Node{ID: id, MachineKey: fmt.Sprintf("mkey:%064x", id), NodeKey: fmt.Sprintf("nodekey:%064x", id),
		Hostname: fmt.Sprintf("host-%d", id), GivenName: fmt.Sprintf("host-%d", id), UserID: 7, UserName: "someone",
		IPs: []netip.Addr{netip.MustParseAddr(fmt.Sprintf("100.64.0.%d", id))}, Method: "cli", Online: online,
		CreatedAt: now.Add(-time.Hour), Expiry: &exp}
}
