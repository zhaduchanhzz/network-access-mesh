package relay

// PostgreSQL integration harness of internal/relay: every test gets its own database (internal/store/storetest) with
// two tenants A and B, each with a running instance and the embedded relay region + assignment that step 17 of the
// Tenant Orchestrator writes (code mg-<slug>, DERP region 901, hostname = control hostname, public entry + shared STUN,
// verify in_process, active). The Prober is a fake that records what it was asked; the wiring over the real prober is
// tested in apps/internal/runner (TestRelayProber, with apps/probe's stubs).

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/storetest"
)

func TestMain(m *testing.M) {
	code := m.Run()
	storetest.Cleanup()
	os.Exit(code)
}

const (
	edgeAddr  = "10.249.0.2:443"
	entryIPv4 = "192.0.2.10"
)

// fakeProber answers relay probes with the result set for the host (healthy by default) and records the requests.
type fakeProber struct {
	mu      sync.Mutex
	reqs    []ProbeRequest
	results map[string]ProbeResult
	err     error
	block   chan struct{} // when set, a probe waits for it (or for its context)
}

var healthyResult = ProbeResult{DERP: Check{OK: true, Status: 200, Duration: 12 * time.Millisecond},
	STUN: Check{OK: true, Duration: 3 * time.Millisecond}}

func (p *fakeProber) Relay(ctx context.Context, r ProbeRequest) (ProbeResult, error) {
	p.mu.Lock()
	p.reqs = append(p.reqs, r)
	res, ok := p.results[r.Host]
	err, block := p.err, p.block
	p.mu.Unlock()
	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
			return ProbeResult{}, ctx.Err()
		}
	}
	if err != nil {
		return ProbeResult{}, err
	}
	if !ok {
		res = healthyResult
	}
	return res, nil
}

func (p *fakeProber) set(host string, r ProbeResult) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.results == nil {
		p.results = map[string]ProbeResult{}
	}
	p.results[host] = r
}

func (p *fakeProber) requests() []ProbeRequest {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]ProbeRequest(nil), p.reqs...)
}

type tenantFx struct {
	id, instance, region, assignment uuid.UUID
	slug, host                       string
}

type fixture struct {
	db     string
	su     *pgx.Conn
	mu     sync.Mutex // guards su
	host   uuid.UUID
	a, b   *tenantFx
	n      int
	apiSt  *store.Store
	wrkSt  *store.Store
	prober *fakeProber
	api    *Service // relay of the api process (mg_api_*): reads only
	wrk    *Service // relay of the worker process (mg_worker_*): probes
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	env := storetest.Require(t)
	f := &fixture{db: env.NewDatabase(t), host: uuid.New(), prober: &fakeProber{}}
	f.su = env.Admin(t, f.db)
	f.exec(t, `INSERT INTO hosts (id, name, region, run_uid_range, tenant_net_pool, public_entry)
		VALUES ($1, 'host-1', 'lab', int4range(30000, 40000), '10.250.0.0/16', jsonb_build_object('ipv4', $2::text, 'mode', 'direct'))`,
		f.host, entryIPv4)
	f.a, f.b = f.newTenant(t), f.newTenant(t)
	f.apiSt = env.OpenStore(t, f.db, "mg_api_tenant", "mg_api_platform", 4)
	f.wrkSt = env.OpenStore(t, f.db, "mg_worker_tenant", "mg_worker_platform", 4)
	var err error
	if f.api, err = New(f.apiSt, Config{Registerer: prometheus.NewRegistry()}); err != nil {
		t.Fatal(err)
	}
	if f.wrk, err = New(f.wrkSt, Config{Prober: f.prober, EdgeAddress: edgeAddr, Registerer: prometheus.NewRegistry()}); err != nil {
		t.Fatal(err)
	}
	return f
}

// newTenant creates an active tenant with a running instance and the relay rows of step 17.
func (f *fixture) newTenant(t *testing.T) *tenantFx {
	t.Helper()
	f.n++
	i := f.n
	ten := &tenantFx{id: uuid.New(), instance: uuid.New(), region: uuid.New(), assignment: uuid.New(), slug: fmt.Sprintf("tenant%02d", i)}
	ten.host = ten.slug + ".mesh.test"
	f.exec(t, `INSERT INTO tenants (id, slug, name, status) VALUES ($1, $2, $3, 'active')`, ten.id, ten.slug, "Tenant "+ten.slug)
	f.exec(t, `INSERT INTO tenant_instances (id, tenant_id, host_id, status, headscale_version, image_digest,
			control_hostname, server_url, base_domain, internal_address, run_uid, net_cidr, data_path, derp_region_id)
		VALUES ($1, $2, $3, 'running', '0.29.7', 'sha256:'||repeat('a', 64), $4, 'https://'||$4, $5, $6, $7, $8::cidr, $9, 901)`,
		ten.instance, ten.id, f.host, ten.host, ten.slug+".ts.test", "hs-"+ten.slug+":8080", 30000+i,
		fmt.Sprintf("10.250.%d.0/29", i), "/opt/meshguard/tenants/"+ten.instance.String())
	f.exec(t, `INSERT INTO relay_regions (id, tenant_id, code, name, kind, derp_region_id, hostname, ipv4, stun_port, derp_port,
			verify_mode, host_id, status)
		VALUES ($1, $2, 'mg-'||$3, 'MeshGuard '||$3, 'embedded', 901, $4, $5::inet, 3478, 443, 'in_process', $6, 'active')`,
		ten.region, ten.id, ten.slug, ten.host, entryIPv4, f.host)
	f.exec(t, `INSERT INTO relay_assignments (id, tenant_id, instance_id, relay_region_id, priority, status)
		VALUES ($1, $2, $3, $4, 0, 'active')`, ten.assignment, ten.id, ten.instance, ten.region)
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

func (f *fixture) execErr(sql string, args ...any) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, err := f.su.Exec(context.Background(), sql, args...)
	return err
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

// regionRow is what the database holds for a region (read as the superuser).
type regionRow struct {
	rec       record
	raw       []byte
	probeAt   *time.Time
	version   int64
	updatedAt time.Time
}

func (f *fixture) regionRow(t *testing.T, id uuid.UUID) regionRow {
	t.Helper()
	var r regionRow
	f.scan(t, `SELECT last_probe, last_probe_at, version, updated_at FROM relay_regions WHERE id = $1`, []any{id},
		&r.raw, &r.probeAt, &r.version, &r.updatedAt)
	if len(r.raw) > 0 {
		if err := json.Unmarshal(r.raw, &r.rec); err != nil {
			t.Fatalf("last_probe of %s: %v (%s)", id, err, r.raw)
		}
	}
	return r
}

func (f *fixture) dbNow(t *testing.T) time.Time {
	t.Helper()
	var now time.Time
	f.scan(t, `SELECT clock_timestamp()`, nil, &now)
	return now
}
