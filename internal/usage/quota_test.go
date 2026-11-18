package usage_test

// The minimal QuotaChecker (P3-T06a) on a real PostgreSQL migrated like a deployment (storetest): the tenant cap
// (system_settings quota.max_tenants, platform pool) and the device quota (plan ⊕ override of the live subscription,
// tenant pool), their boundaries, the typed refusal (⇒ 403 quota_exceeded — tenantsapi), the fail-closed readings, the
// isolation between tenants, and the locked variants under concurrency (exactly the limit passes).

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/storetest"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
	"github.com/zhaduchanhzz/network-access-mesh/internal/usage"
)

func TestMain(m *testing.M) {
	code := m.Run()
	storetest.Cleanup()
	os.Exit(code)
}

type world struct {
	t       *testing.T
	su      *pgx.Conn
	api     *store.Store // mg_api_tenant / mg_api_platform: validate (step 1), enrollment requests
	checker *usage.Checker
	host    uuid.UUID
	sfx     string
}

// shared is the one database of this test binary (database creation holds the cluster-wide lock of storetest — one per
// test would slow every package of `go test ./...`). The tests run one after the other; the tenant-cap tests work
// relative to the tenants already there and put quota.max_tenants back to 10 when they end.
var shared struct {
	sync.Mutex
	db string
}

func newWorld(t *testing.T) *world {
	t.Helper()
	pg := storetest.Require(t)
	shared.Lock()
	if shared.db == "" {
		shared.db = pg.NewDatabase(t)
	}
	db := shared.db
	shared.Unlock()
	w := &world{t: t, su: pg.Admin(t, db), api: pg.OpenStore(t, db, "mg_api_tenant", "mg_api_platform", 8)}
	w.checker = usage.NewChecker(w.api)
	w.host = uuid.Must(uuid.NewV7())
	w.sfx = w.host.String()[30:]
	w.exec(`INSERT INTO hosts (id, name, region, run_uid_range, tenant_net_pool)
		VALUES ($1, 'h-'||$2, 'lab', int4range(30000, 40000), '10.250.0.0/16')`, w.host, w.sfx)
	return w
}

// liveTenants counts the tenants that take a place under quota.max_tenants: neither deleted nor failed (P3-T09).
func (w *world) liveTenants() int64 {
	w.t.Helper()
	var n int64
	if err := w.su.QueryRow(w.t.Context(), `SELECT count(*) FROM tenants WHERE status NOT IN ('deleted', 'failed')`).Scan(&n); err != nil {
		w.t.Fatal(err)
	}
	return n
}

// setCap sets quota.max_tenants and puts back the value of 0012 (10) when the test ends.
func (w *world) setCap(v string) {
	w.t.Helper()
	w.exec(`INSERT INTO system_settings (key, value) VALUES ('quota.max_tenants', $1::jsonb)
		ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`, v)
	w.t.Cleanup(func() {
		_, _ = w.su.Exec(context.Background(), `INSERT INTO system_settings (key, value) VALUES ('quota.max_tenants', '10')
			ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`)
	})
}

func (w *world) exec(sql string, args ...any) {
	w.t.Helper()
	if _, err := w.su.Exec(w.t.Context(), sql, args...); err != nil {
		w.t.Fatalf("fixture: %v\n%s", err, sql)
	}
}

var seq int

// tenant inserts a tenant with a live instance (status) and returns ids.
func (w *world) tenant(status, instanceStatus string) (uuid.UUID, uuid.UUID) {
	w.t.Helper()
	seq++
	tid, iid := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	slug := fmt.Sprintf("t-%d-%s", seq, tid.String()[:6])
	w.exec(`INSERT INTO tenants (id, slug, name, status) VALUES ($1, $2::text, $2::text, $3)`, tid, slug, status)
	w.exec(`INSERT INTO tenant_instances (id, tenant_id, host_id, status, headscale_version, image_digest, control_hostname,
			server_url, base_domain, internal_address, run_uid, net_cidr, data_path)
		VALUES ($1, $2, $3, $4, 'v0.29.7', 'sha256:'||repeat('a', 64), $5||'.mesh.test', 'https://'||$5||'.mesh.test',
			$5||'.tail.test', 'hs-'||$5||':8080', 30000 + $6::int, $7::cidr, '/data')`,
		iid, tid, w.host, instanceStatus, slug, seq, fmt.Sprintf("10.250.%d.%d/29", seq/32, seq%32*8))
	return tid, iid
}

// devices adds n devices of the instance (removed = true: rows that left the inventory).
func (w *world) devices(tid, iid uuid.UUID, n int, removed bool) {
	w.t.Helper()
	for range n {
		seq++
		w.exec(`INSERT INTO device_inventory_cache (tenant_id, instance_id, headscale_node_id, machine_key, removed_at)
			VALUES ($1, $2, $3::bigint, 'mkey:'||$3::bigint, CASE WHEN $4 THEN now() END)`, tid, iid, seq, removed)
	}
}

// plan inserts the plan <key>-<sfx> (a check names the plan by that key).
func (w *world) plan(key, limits string) uuid.UUID {
	w.t.Helper()
	id := uuid.Must(uuid.NewV7())
	w.exec(`INSERT INTO subscription_plans (id, key, name, limits) VALUES ($1, $2, $2, $3)`, id, key+"-"+w.sfx, limits)
	return id
}

func limits(maxDevices int) string {
	return fmt.Sprintf(`{"max_devices": %d, "max_users": 10, "max_tagged_devices": 5, "max_live_enrollment_credentials": 5}`, maxDevices)
}

func (w *world) subscribe(tid, plan uuid.UUID, status, overrides string) {
	w.t.Helper()
	w.exec(`INSERT INTO subscriptions (tenant_id, plan_id, status, overrides) VALUES ($1, $2, $3, $4)`, tid, plan, status, overrides)
}

func wantStatus(t *testing.T, what string, got, want tenants.QuotaStatus, err error, exceeded bool) {
	t.Helper()
	if got != want {
		t.Errorf("%s: status %+v, want %+v", what, got, want)
	}
	var q *tenants.QuotaExceededError
	switch {
	case exceeded && (!errors.Is(err, tenants.ErrQuotaExceeded) || !errors.As(err, &q) || q.Status != want ||
		q.QuotaResource() != want.Resource || q.QuotaLimit() != want.Limit):
		t.Errorf("%s: error %v, want a QuotaExceededError of %+v", what, err, want)
	case !exceeded && err != nil:
		t.Errorf("%s: %v, want allowed", what, err)
	}
}

// TestTenantCap — quota.max_tenants (0012: 10) against the tenants that take a place, at the boundaries (relative to the
// tenants already in the shared database: base); deleted tenants free their slot and failed ones (a provisioning rolled
// back — P3-T09, the observation of P3-T07) take none, while a tenant being deprovisioned keeps its slot; 0 refuses
// everything; a missing or malformed setting is ErrQuotaUnavailable (never unlimited); the tenant pool cannot read the
// setting.
func TestTenantCap(t *testing.T) {
	w := newWorld(t)
	ctx := t.Context()
	base := w.liveTenants()
	st, err := w.checker.CheckTenantCreation(ctx)
	wantStatus(t, "cap 10 of 0012", st, tenants.QuotaStatus{Resource: "tenants", Limit: 10, Used: base, Requested: 1}, err, base >= 10)
	w.setCap(fmt.Sprint(base + 3))
	w.tenant("active", "running")
	failed, _ := w.tenant("failed", "failed")
	st, err = w.checker.CheckTenantCreation(ctx)
	wantStatus(t, "1 of 3: a failed tenant takes no slot", st,
		tenants.QuotaStatus{Resource: "tenants", Limit: base + 3, Used: base + 1, Requested: 1}, err, false)
	w.tenant("provisioning", "allocated")
	gone, _ := w.tenant("deprovisioning", "running")
	st, err = w.checker.CheckTenantCreation(ctx)
	wantStatus(t, "3 of 3: a tenant being deprovisioned keeps its slot", st,
		tenants.QuotaStatus{Resource: "tenants", Limit: base + 3, Used: base + 3, Requested: 1}, err, true)
	w.exec(`UPDATE tenants SET status = 'deleted', deleted_at = now() WHERE id = $1`, gone)
	st, err = w.checker.CheckTenantCreation(ctx)
	wantStatus(t, "a deleted tenant frees its slot", st,
		tenants.QuotaStatus{Resource: "tenants", Limit: base + 3, Used: base + 2, Requested: 1}, err, false)
	w.exec(`UPDATE tenants SET status = 'deleted', deleted_at = now() WHERE id = $1`, failed)
	st, err = w.checker.CheckTenantCreation(ctx)
	wantStatus(t, "a failed tenant deleted: no change", st,
		tenants.QuotaStatus{Resource: "tenants", Limit: base + 3, Used: base + 2, Requested: 1}, err, false)
	w.setCap("0")
	st, err = w.checker.CheckTenantCreation(ctx)
	wantStatus(t, "cap 0", st, tenants.QuotaStatus{Resource: "tenants", Limit: 0, Used: base + 2, Requested: 1}, err, true)
	for _, v := range []string{`"10"`, `-1`, `1.5`, `2147483648`, `null`, `{"max": 10}`, `[10]`, `true`} {
		w.exec(`UPDATE system_settings SET value = $1::jsonb WHERE key = 'quota.max_tenants'`, v)
		if _, err := w.checker.CheckTenantCreation(ctx); !errors.Is(err, usage.ErrQuotaUnavailable) || errors.Is(err, tenants.ErrQuotaExceeded) {
			t.Errorf("setting %s: %v, want ErrQuotaUnavailable", v, err)
		}
	}
	w.exec(`UPDATE system_settings SET value = '10.0' WHERE key = 'quota.max_tenants'`) // integral, written with a fraction
	if st, err := w.checker.CheckTenantCreation(ctx); (err != nil && !errors.Is(err, tenants.ErrQuotaExceeded)) || st.Limit != 10 {
		t.Errorf("setting 10.0: %+v, %v", st, err)
	}
	w.exec(`DELETE FROM system_settings WHERE key = 'quota.max_tenants'`)
	if _, err := w.checker.CheckTenantCreation(ctx); !errors.Is(err, usage.ErrQuotaUnavailable) {
		t.Errorf("missing setting: %v", err)
	}
	// the tenant pool never reads system_settings (platform table)
	tid, _ := w.tenant("active", "running")
	err = w.api.WithTenantTx(ctx, tid, func(q *sqlcdb.Queries) error {
		_, err := usage.TenantCreationTx(ctx, q)
		return err
	})
	if store.SQLState(err) != "42501" {
		t.Errorf("tenant cap from the tenant pool: %v, want 42501", err)
	}
}

// TestTenantCapConcurrent — registry.create under the lock: with room for 4 tenants, 12 concurrent creations that each
// check TenantCreationTx and insert in one platform transaction ⇒ exactly 4 tenants, 8 typed refusals.
func TestTenantCapConcurrent(t *testing.T) {
	w := newWorld(t)
	ctx := t.Context()
	w.tenant("active", "running")
	base := w.liveTenants()
	w.setCap(fmt.Sprint(base + 4))
	var (
		mu            sync.Mutex
		ok, exceeded  int
		wg            sync.WaitGroup
		start         = make(chan struct{})
		unexpectedErr []error
	)
	for i := range 12 {
		wg.Go(func() {
			<-start
			err := w.api.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
				if _, err := usage.TenantCreationTx(ctx, q); err != nil {
					return err
				}
				_, err := q.CreateTenant(ctx, sqlcdb.CreateTenantParams{Slug: fmt.Sprintf("conc-%02d-%s", i, w.sfx), Name: "c",
					Status: tenants.StatusProvisioning, Settings: []byte("{}")})
				return err
			})
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				ok++
			case errors.Is(err, tenants.ErrQuotaExceeded):
				exceeded++
			default:
				unexpectedErr = append(unexpectedErr, err)
			}
		})
	}
	close(start)
	wg.Wait()
	if ok != 4 || exceeded != 8 || len(unexpectedErr) > 0 {
		t.Errorf("created %d, refused %d, other errors %v; want 4 and 8", ok, exceeded, unexpectedErr)
	}
	if n := w.liveTenants(); n != base+4 {
		t.Errorf("%d live tenants, want the cap %d", n, base+4)
	}
}

// TestDeviceQuota — max_devices of the live subscription (plan ⊕ override) against the devices in the inventory of the
// tenant's live instance, at the boundaries; removed devices, devices of a removed instance and another tenant's
// devices do not count; no live subscription ⇒ no allowance; a cancelled subscription is no subscription.
func TestDeviceQuota(t *testing.T) {
	w := newWorld(t)
	ctx := t.Context()
	small := w.plan("small", limits(3))
	a, ai := w.tenant("active", "running")
	w.subscribe(a, small, "active", "{}")
	w.devices(a, ai, 2, false)
	w.devices(a, ai, 4, true)                  // left the inventory
	_, oldI := func() (uuid.UUID, uuid.UUID) { // an earlier instance of A, removed, with devices still listed
		iid := uuid.Must(uuid.NewV7())
		seq++
		w.exec(`INSERT INTO tenant_instances (id, tenant_id, host_id, status, headscale_version, image_digest, control_hostname,
				server_url, base_domain, internal_address, run_uid, net_cidr, data_path)
			VALUES ($1, $2, $3, 'removed', 'v0.29.7', 'sha256:'||repeat('a', 64), 'old.mesh.test', 'https://old.mesh.test',
				'old.tail.test', 'hs-old:8080', 39000, '10.250.200.0/29', '/data')`, iid, a, w.host)
		return a, iid
	}()
	w.devices(a, oldI, 5, false)
	b, bi := w.tenant("active", "running") // tenant B: many devices, generous plan
	w.subscribe(b, w.plan("big", limits(1000)), "active", "{}")
	w.devices(b, bi, 20, false)

	st := func(limit, used, req int64) tenants.QuotaStatus {
		return tenants.QuotaStatus{Resource: "devices", Plan: "small-" + w.sfx, Limit: limit, Used: used, Requested: req}
	}
	got, err := w.checker.CheckDevices(ctx, a, 1)
	wantStatus(t, "2 of 3 + 1", got, st(3, 2, 1), err, false)
	got, err = w.checker.CheckDevices(ctx, a, 2)
	wantStatus(t, "2 of 3 + 2", got, st(3, 2, 2), err, true)
	got, err = w.checker.CheckDevices(ctx, a, 0)
	wantStatus(t, "2 of 3 + 0", got, st(3, 2, 0), err, false)
	w.devices(a, ai, 1, false)
	got, err = w.checker.CheckDevices(ctx, a, 1)
	wantStatus(t, "3 of 3 + 1", got, st(3, 3, 1), err, true)
	got, err = w.checker.CheckDevices(ctx, a, 0)
	wantStatus(t, "3 of 3 + 0", got, st(3, 3, 0), err, false)
	// an override replaces the plan's key
	w.exec(`UPDATE subscriptions SET overrides = '{"max_devices": 5}' WHERE tenant_id = $1`, a)
	got, err = w.checker.CheckDevices(ctx, a, 2)
	wantStatus(t, "override 5: 3 + 2", got, st(5, 3, 2), err, false)
	got, err = w.checker.CheckDevices(ctx, a, 3)
	wantStatus(t, "override 5: 3 + 3", got, st(5, 3, 3), err, true)
	w.exec(`UPDATE subscriptions SET overrides = '{"max_devices": 0}' WHERE tenant_id = $1`, a)
	got, err = w.checker.CheckDevices(ctx, a, 1)
	wantStatus(t, "override 0", got, st(0, 3, 1), err, true)
	// B is untouched by A's numbers and the other way round
	got, err = w.checker.CheckDevices(ctx, b, 1)
	wantStatus(t, "tenant B", got, tenants.QuotaStatus{Resource: "devices", Plan: "big-" + w.sfx, Limit: 1000, Used: 20, Requested: 1}, err, false)
	// no live subscription: cancelled, then none at all
	w.exec(`UPDATE subscriptions SET status = 'cancelled' WHERE tenant_id = $1`, a)
	got, err = w.checker.CheckDevices(ctx, a, 1)
	wantStatus(t, "cancelled subscription", got, tenants.QuotaStatus{Resource: "devices", Limit: 0, Used: 3, Requested: 1}, err, true)
	if err == nil || err.Error() != "quota exceeded: devices — the tenant has no live subscription" {
		t.Errorf("message %v", err)
	}
	c, _ := w.tenant("active", "running")
	got, err = w.checker.CheckDevices(ctx, c, 0)
	wantStatus(t, "never subscribed, nothing added", got, tenants.QuotaStatus{Resource: "devices", Requested: 0}, err, false)
	// invalid input
	if _, err := w.checker.CheckDevices(ctx, uuid.Nil, 1); !errors.Is(err, usage.ErrInvalid) {
		t.Errorf("nil tenant: %v", err)
	}
	if _, err := w.checker.CheckDevices(ctx, a, -1); !errors.Is(err, usage.ErrInvalid) {
		t.Errorf("negative amount: %v", err)
	}
	// DevicesTx in the caller's tenant transaction sees only that tenant: B's id inside A's scope finds nothing
	err = w.api.WithTenantTx(ctx, a, func(q *sqlcdb.Queries) error {
		st, err := usage.DevicesTx(ctx, q, b, 0)
		if st.Used != 0 || st.Plan != "" {
			t.Errorf("tenant B read from A's scope: %+v", st)
		}
		return err
	})
	if err != nil {
		t.Errorf("DevicesTx: %v", err)
	}
}

// TestDeviceQuotaConcurrent — enrollment under the lock (§7.4 step 3): with room for 5 devices, 12 concurrent requests
// that each check DevicesTx and add a device in one tenant transaction ⇒ exactly 5 devices, 7 typed refusals.
func TestDeviceQuotaConcurrent(t *testing.T) {
	w := newWorld(t)
	ctx := t.Context()
	a, ai := w.tenant("active", "running")
	w.subscribe(a, w.plan("five", limits(5)), "active", "{}")
	var (
		mu           sync.Mutex
		ok, exceeded int
		others       []error
		wg           sync.WaitGroup
		start        = make(chan struct{})
	)
	for i := range 12 {
		wg.Go(func() {
			<-start
			err := w.api.WithTenantTx(ctx, a, func(q *sqlcdb.Queries) error {
				if _, err := usage.DevicesTx(ctx, q, a, 1); err != nil {
					return err
				}
				_, err := q.InsertSyncedDevice(ctx, sqlcdb.InsertSyncedDeviceParams{TenantID: a, InstanceID: ai,
					HeadscaleNodeID: int64(1000 + i), MachineKey: fmt.Sprintf("mkey:%d", i), IpAddresses: []netip.Addr{},
					Tags: []string{}, ApprovedRoutes: []netip.Prefix{}, AvailableRoutes: []netip.Prefix{},
					SubnetRoutes: []netip.Prefix{}, SyncedAt: time.Now()})
				return err
			})
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				ok++
			case errors.Is(err, tenants.ErrQuotaExceeded):
				exceeded++
			default:
				others = append(others, err)
			}
		})
	}
	close(start)
	wg.Wait()
	if ok != 5 || exceeded != 7 || len(others) > 0 {
		t.Errorf("added %d, refused %d, other errors %v; want 5 and 7", ok, exceeded, others)
	}
	var n int
	if err := w.su.QueryRow(ctx, `SELECT count(*) FROM device_inventory_cache WHERE tenant_id = $1 AND removed_at IS NULL`, a).Scan(&n); err != nil ||
		n != 5 {
		t.Errorf("%d devices, want the limit 5 (%v)", n, err)
	}
}

// TestQuotaStatus — the arithmetic of a status and the typed refusal, without a database.
func TestQuotaStatus(t *testing.T) {
	for _, c := range []struct {
		s    tenants.QuotaStatus
		want bool
	}{
		{tenants.QuotaStatus{Limit: 10, Used: 9, Requested: 1}, true},
		{tenants.QuotaStatus{Limit: 10, Used: 10, Requested: 1}, false},
		{tenants.QuotaStatus{Limit: 10, Used: 10, Requested: 0}, true},
		{tenants.QuotaStatus{Limit: 10, Used: 11, Requested: 0}, false}, // already over (a lowered plan)
		{tenants.QuotaStatus{Limit: 0, Used: 0, Requested: 0}, true},
		{tenants.QuotaStatus{Limit: 0, Used: 0, Requested: 1}, false},
		{tenants.QuotaStatus{Limit: 5, Used: 0, Requested: -1}, false},
		{tenants.QuotaStatus{Limit: 2147483647, Used: 9223372036854775000, Requested: 1}, false}, // no overflow
	} {
		if got := c.s.Allowed(); got != c.want {
			t.Errorf("%+v Allowed = %v", c.s, got)
		}
		if err := c.s.Exceeded(); (err == nil) != c.want || (err != nil && !errors.Is(err, tenants.ErrQuotaExceeded)) {
			t.Errorf("%+v Exceeded = %v", c.s, err)
		}
	}
	var _ tenants.QuotaChecker = (*usage.Checker)(nil)
}
