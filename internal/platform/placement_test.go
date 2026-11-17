package platform_test

// Integration tests of placement (P3-T04, §11.3 step 3) on a real PostgreSQL migrated like a deployment (storetest), with
// the worker's roles (mg_worker_tenant / mg_worker_platform — placement runs on the platform pool of the worker).
// The verification of §20: "Test đua tranh cấp phát (UID và hostname); instance thay thế của cùng tenant chèn được khi
// hàng cũ đã removed".

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/zhaduchanhzz/network-access-mesh/internal/platform"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/storetest"
)

const (
	baseDomain = "mg.test"
	digest     = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	hsVersion  = "v0.29.7"
)

// world is a migrated database seen by one test: its superuser connection, a Placer on the worker's pools, and the
// suffix that keeps the test's hosts, regions and slugs apart from those of the other tests sharing the database.
type world struct {
	t      *testing.T
	su     *pgx.Conn
	st     *store.Store
	placer *platform.Placer
	sfx    string
	own    bool // a database of its own: a tenant without region may land on any host
}

// shared is the database of the tests that keep to their own region (created once per test binary — database creation
// holds the cluster-wide lock of storetest, so a database per test slows every package of `go test ./...`).
var shared struct {
	sync.Mutex
	db string
}

// newWorld returns a world on the shared database: every tenant gets a region of the test (nil ⇒ "lab").
func newWorld(t *testing.T, maxConns int32, o platform.PlacerOptions) *world {
	t.Helper()
	pg := storetest.Require(t)
	shared.Lock()
	if shared.db == "" {
		shared.db = pg.NewDatabase(t)
	}
	db := shared.db
	shared.Unlock()
	return openWorld(t, pg, db, maxConns, o, false)
}

// newOwnWorld returns a world on a database of its own (tests of placement across every host).
func newOwnWorld(t *testing.T, maxConns int32, o platform.PlacerOptions) *world {
	t.Helper()
	pg := storetest.Require(t)
	return openWorld(t, pg, pg.NewDatabase(t), maxConns, o, true)
}

func openWorld(t *testing.T, pg *storetest.Env, db string, maxConns int32, o platform.PlacerOptions, own bool) *world {
	t.Helper()
	b := make([]byte, 3)
	_, _ = rand.Read(b)
	w := &world{t: t, su: pg.Admin(t, db), st: pg.OpenStore(t, db, "mg_worker_tenant", "mg_worker_platform", maxConns),
		sfx: hex.EncodeToString(b), own: own}
	if o.BaseDomain == "" {
		o.BaseDomain = baseDomain
	}
	var err error
	if w.placer, err = platform.NewPlacer(w.st, o); err != nil {
		t.Fatal(err)
	}
	return w
}

func (w *world) exec(sql string, args ...any) {
	w.t.Helper()
	if _, err := w.su.Exec(w.t.Context(), sql, args...); err != nil {
		w.t.Fatalf("fixture: %v\n%s", err, sql)
	}
}

// region is the name of a region of this test.
func (w *world) region(r string) string { return r + "-" + w.sfx }

// host registers an active host <name>-<sfx> in region <region>-<sfx> with a public entry; extra is "col = expr"
// assignments applied afterwards.
func (w *world) host(name, region string, uidFirst, uidLast int, pool string, maxInstances int, extra ...string) uuid.UUID {
	w.t.Helper()
	id := uuid.Must(uuid.NewV7())
	name, region = name+"-"+w.sfx, w.region(region)
	w.exec(`INSERT INTO hosts (id, name, region, run_uid_range, tenant_net_pool, capacity, public_entry)
		VALUES ($1, $2, $3, int4range($4, $5, '[]'), $6::cidr, jsonb_build_object('max_instances', $7::int),
			'{"ipv4": "203.0.113.7", "mode": "vps_gateway"}')`, id, name, region, uidFirst, uidLast, pool, maxInstances)
	for _, e := range extra {
		w.exec(`UPDATE hosts SET `+e+` WHERE id = $1`, id)
	}
	return id
}

// tenant registers a tenant <slug>-<sfx> (status provisioning unless given) in region <region>-<sfx> — on the shared
// database a tenant without region goes to "lab" of the test — and returns its id.
func (w *world) tenant(slug string, region *string, status ...string) uuid.UUID {
	w.t.Helper()
	id := uuid.Must(uuid.NewV7())
	slug += "-" + w.sfx
	switch {
	case region != nil:
		region = ptr(w.region(*region))
	case !w.own:
		region = ptr(w.region("lab"))
	}
	st := "provisioning"
	if len(status) > 0 {
		st = status[0]
	}
	w.exec(`INSERT INTO tenants (id, slug, name, status, deployment_region) VALUES ($1, $2::text, $2::text, $3, $4)`,
		id, slug, st, region)
	return id
}

func (w *world) allocate(tenant uuid.UUID) (platform.Allocation, error) {
	return w.placer.Allocate(w.t.Context(), platform.AllocationRequest{TenantID: tenant, InstanceID: uuid.Must(uuid.NewV7()),
		HeadscaleVersion: hsVersion, ImageDigest: digest})
}

func (w *world) mustAllocate(tenant uuid.UUID) platform.Allocation {
	w.t.Helper()
	a, err := w.allocate(tenant)
	if err != nil {
		w.t.Fatalf("allocate for %s: %v", tenant, err)
	}
	return a
}

func ptr(s string) *string { return &s }

// TestAllocate — one allocation end to end: the derived names, the smallest UID and /29, the registered row (status
// allocated, no STUN port, worker role), the idempotent repeat, and the refusals.
func TestAllocate(t *testing.T) {
	w := newWorld(t, 4, platform.PlacerOptions{})
	ctx := t.Context()
	hid := w.host("h1", "lab", 30000, 39999, "10.250.0.0/16", 100)
	tid := w.tenant("acme", nil)
	iid := uuid.Must(uuid.NewV7())
	req := platform.AllocationRequest{TenantID: tid, InstanceID: iid, HeadscaleVersion: hsVersion, ImageDigest: digest}
	a, err := w.placer.Allocate(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	slug := "acme-" + w.sfx
	want := platform.Allocation{InstanceID: iid, TenantID: tid, Slug: slug, HostID: hid, HostName: "h1-" + w.sfx,
		Region: w.region("lab"), RunUID: 30000, NetCIDR: netip.MustParsePrefix("10.250.0.0/29"),
		PublicEntryIPv4: netip.MustParseAddr("203.0.113.7"), ControlHostname: slug + ".mesh.mg.test",
		ServerURL: "https://" + slug + ".mesh.mg.test", BaseDomain: slug + ".tail.mg.test",
		InternalAddress: "hs-" + slug + ":8080", DataPath: "/opt/meshguard/tenants/" + iid.String() + "/data",
		HeadscaleVersion: hsVersion, ImageDigest: digest, Status: "allocated"}
	if a != want {
		t.Fatalf("allocation\n%+v\nwant\n%+v", a, want)
	}
	var (
		status, control, server, base, internal, data string
		uid                                           int32
		net                                           netip.Prefix
		stun                                          *int32
		host                                          uuid.UUID
	)
	if err := w.su.QueryRow(ctx, `SELECT status, control_hostname, server_url, base_domain, internal_address, data_path, run_uid,
			net_cidr, stun_port, host_id FROM tenant_instances WHERE id = $1 AND tenant_id = $2`, iid, tid).Scan(&status, &control,
		&server, &base, &internal, &data, &uid, &net, &stun, &host); err != nil {
		t.Fatal(err)
	}
	if status != "allocated" || control != want.ControlHostname || server != want.ServerURL || base != want.BaseDomain ||
		internal != want.InternalAddress || data != want.DataPath || uid != 30000 || net != want.NetCIDR || stun != nil || host != hid {
		t.Errorf("row: %s %s %s %s %s %s %d %s %v %s", status, control, server, base, internal, data, uid, net, stun, host)
	}
	// the same step again: the registered allocation, nothing written
	again, err := w.placer.Allocate(ctx, req)
	want.Existing = true
	if err != nil || again != want {
		t.Errorf("repeat = %+v, %v", again, err)
	}
	var n int
	if err := w.su.QueryRow(ctx, `SELECT count(*) FROM tenant_instances WHERE host_id = $1`, hid).Scan(&n); err != nil || n != 1 {
		t.Errorf("%d rows after the repeat (%v)", n, err)
	}
	// refusals
	if _, err := w.allocate(tid); !errors.Is(err, platform.ErrTenantHasInstance) || !errors.Is(err, platform.ErrConflict) {
		t.Errorf("second instance of the tenant: %v", err)
	}
	if _, err := w.placer.Allocate(ctx, platform.AllocationRequest{TenantID: w.tenant("other", nil), InstanceID: iid,
		HeadscaleVersion: hsVersion, ImageDigest: digest}); !errors.Is(err, platform.ErrConflict) {
		t.Errorf("instance id of another tenant: %v", err)
	}
	if _, err := w.allocate(uuid.Must(uuid.NewV7())); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("unknown tenant: %v", err)
	}
	for _, st := range []string{"pending", "active", "suspended", "deprovisioning", "deleted", "failed"} {
		if _, err := w.allocate(w.tenant("st-"+st, nil, st)); !errors.Is(err, platform.ErrTenantNotPlaceable) {
			t.Errorf("tenant %s: %v", st, err)
		}
	}
	for name, r := range map[string]platform.AllocationRequest{
		"no tenant":   {InstanceID: iid, HeadscaleVersion: hsVersion, ImageDigest: digest},
		"no instance": {TenantID: tid, HeadscaleVersion: hsVersion, ImageDigest: digest},
		"tag digest":  {TenantID: tid, InstanceID: iid, HeadscaleVersion: hsVersion, ImageDigest: "latest"},
		"no version":  {TenantID: tid, InstanceID: iid, ImageDigest: digest},
	} {
		if _, err := w.placer.Allocate(ctx, r); !errors.Is(err, platform.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := platform.NewPlacer(w.st, platform.PlacerOptions{BaseDomain: "not a domain"}); !errors.Is(err, platform.ErrInvalid) {
		t.Errorf("bad base domain: %v", err)
	}
	if _, err := platform.NewPlacer(w.st, platform.PlacerOptions{BaseDomain: baseDomain, TenantsDir: "rel/dir"}); !errors.Is(err, platform.ErrInvalid) {
		t.Errorf("relative tenants dir: %v", err)
	}
}

// TestAllocateConcurrent — the race of §20: N workers allocate at the same time on one host (fewer connections than
// workers, so they queue on the host lock): every allocation succeeds, UIDs are N distinct values — exactly the N
// smallest of the range —, subnets N distinct /29 of the pool — the N lowest —, hostnames N distinct. Then the same
// tenant raced with N different instance IDs: exactly one wins, every other gets a typed conflict; and one instance ID
// raced N times: one insert, N-1 identical "existing" answers.
func TestAllocateConcurrent(t *testing.T) {
	const n = 24
	w := newWorld(t, 6, platform.PlacerOptions{})
	hid := w.host("h1", "lab", 30000, 39999, "10.250.0.0/16", 100)
	ids := make([]uuid.UUID, n)
	for i := range ids {
		ids[i] = w.tenant(fmt.Sprintf("race-%02d", i), nil)
	}
	allocs := make([]platform.Allocation, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range n {
		wg.Go(func() {
			<-start
			allocs[i], errs[i] = w.allocate(ids[i])
		})
	}
	close(start)
	wg.Wait()
	uids := map[int32]bool{}
	nets := map[netip.Prefix]bool{}
	hosts := map[string]bool{}
	for i, a := range allocs {
		if errs[i] != nil {
			t.Fatalf("worker %d: %v", i, errs[i])
		}
		uids[a.RunUID], nets[a.NetCIDR], hosts[a.ControlHostname] = true, true, true
	}
	if len(uids) != n || len(nets) != n || len(hosts) != n {
		t.Fatalf("distinct UIDs %d, subnets %d, hostnames %d; want %d each", len(uids), len(nets), len(hosts), n)
	}
	for i := range n {
		if !uids[int32(30000+i)] || !nets[netip.PrefixFrom(netip.AddrFrom4([4]byte{10, 250, byte(i / 32), byte(i % 32 * 8)}), 29)] {
			t.Errorf("UID %d or the %d-th /29 not allocated: the allocation is not the smallest free one", 30000+i, i)
		}
	}
	// the database agrees (and every row is a live allocation)
	var rows, distinctUID, distinctNet, distinctHost int
	if err := w.su.QueryRow(t.Context(), `SELECT count(*), count(DISTINCT run_uid), count(DISTINCT net_cidr),
			count(DISTINCT control_hostname) FROM tenant_instances WHERE status = 'allocated' AND host_id = $1`, hid).Scan(&rows, &distinctUID,
		&distinctNet, &distinctHost); err != nil || rows != n || distinctUID != n || distinctNet != n || distinctHost != n {
		t.Errorf("rows %d, distinct uid %d net %d host %d (%v)", rows, distinctUID, distinctNet, distinctHost, err)
	}

	// one tenant, N instance ids at once
	one := w.tenant("race-one", nil)
	won, conflicts := race(t, n, func(int) (platform.Allocation, error) { return w.allocate(one) })
	if len(won) != 1 || conflicts != n-1 {
		t.Errorf("same tenant: %d won, %d typed conflicts; want 1 and %d", len(won), conflicts, n-1)
	}
	// one instance id, N times at once
	same := w.tenant("race-same", nil)
	req := platform.AllocationRequest{TenantID: same, InstanceID: uuid.Must(uuid.NewV7()), HeadscaleVersion: hsVersion,
		ImageDigest: digest}
	won, conflicts = race(t, n, func(int) (platform.Allocation, error) { return w.placer.Allocate(t.Context(), req) })
	fresh := 0
	for _, a := range won {
		if !a.Existing {
			fresh++
		}
		b := a
		b.Existing = won[0].Existing
		if b != won[0] {
			t.Errorf("different answers for one instance id: %+v vs %+v", a, won[0])
		}
	}
	if len(won) != n || conflicts != 0 || fresh != 1 {
		t.Errorf("same instance id: %d answers (%d fresh), %d conflicts; want %d answers, 1 fresh", len(won), fresh, conflicts, n)
	}
}

// race runs f n times at once; it returns the allocations that succeeded and the number of typed conflicts, and fails
// the test on any other error.
func race(t *testing.T, n int, f func(int) (platform.Allocation, error)) ([]platform.Allocation, int) {
	t.Helper()
	var (
		mu        sync.Mutex
		won       []platform.Allocation
		conflicts int
		wg        sync.WaitGroup
	)
	start := make(chan struct{})
	for i := range n {
		wg.Go(func() {
			<-start
			a, err := f(i)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				won = append(won, a)
			case errors.Is(err, platform.ErrTenantHasInstance), errors.Is(err, platform.ErrHostnameInUse):
				conflicts++
			default:
				t.Errorf("worker %d: %v", i, err)
			}
		})
	}
	close(start)
	wg.Wait()
	return won, conflicts
}

// TestReplacementAfterRemoved — "instance thay thế của cùng tenant chèn được khi hàng cũ đã removed": Release (the
// compensation of step 3) marks the allocation removed without deleting it; a replacement of the same tenant then gets
// the same hostname and the freed subnet, but a NEW UID — the old one is never handed out again, also to other tenants.
func TestReplacementAfterRemoved(t *testing.T) {
	w := newWorld(t, 4, platform.PlacerOptions{})
	ctx := t.Context()
	w.host("h1", "lab", 30000, 39999, "10.250.0.0/16", 100)
	tid := w.tenant("phoenix", nil)
	old := w.mustAllocate(tid)
	if released, err := w.placer.Release(ctx, tid, old.InstanceID); err != nil || !released {
		t.Fatalf("Release = %v, %v", released, err)
	}
	if released, err := w.placer.Release(ctx, tid, old.InstanceID); err != nil || released {
		t.Errorf("second Release = %v, %v; want a no-op", released, err)
	}
	var status string
	if err := w.su.QueryRow(ctx, `SELECT status FROM tenant_instances WHERE id = $1`, old.InstanceID).Scan(&status); err != nil ||
		status != "removed" {
		t.Fatalf("old row: %q, %v (want kept, removed)", status, err)
	}
	repl := w.mustAllocate(tid)
	if repl.InstanceID == old.InstanceID || repl.ControlHostname != old.ControlHostname || repl.NetCIDR != old.NetCIDR ||
		repl.RunUID == old.RunUID || repl.RunUID != old.RunUID+1 {
		t.Errorf("replacement %+v\nold %+v\nwant same hostname and subnet, the next UID", repl, old)
	}
	if _, err := w.placer.Allocate(ctx, platform.AllocationRequest{TenantID: tid, InstanceID: old.InstanceID,
		HeadscaleVersion: hsVersion, ImageDigest: digest}); !errors.Is(err, platform.ErrInstanceRemoved) {
		t.Errorf("allocating the removed id again: %v", err)
	}
	// the removed UID stays consumed for everyone; its subnet is free again once the replacement is removed too
	other := w.mustAllocate(w.tenant("other", nil))
	if other.RunUID == old.RunUID || other.NetCIDR == repl.NetCIDR {
		t.Errorf("other tenant got %d / %s", other.RunUID, other.NetCIDR)
	}
	// Release refuses an instance that started, and another tenant's instance reads as not found
	w.exec(`UPDATE tenant_instances SET status = 'running' WHERE id = $1`, repl.InstanceID)
	if _, err := w.placer.Release(ctx, tid, repl.InstanceID); !errors.Is(err, platform.ErrConflict) {
		t.Errorf("Release of a running instance: %v", err)
	}
	if _, err := w.placer.Release(ctx, other.TenantID, repl.InstanceID); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("Release through another tenant: %v", err)
	}
	w.exec(`UPDATE tenant_instances SET status = 'failed' WHERE id = $1`, repl.InstanceID)
	if released, err := w.placer.Release(ctx, tid, repl.InstanceID); err != nil || !released {
		t.Errorf("Release of a failed instance = %v, %v", released, err)
	}
	third := w.mustAllocate(tid)
	if third.RunUID <= other.RunUID || third.NetCIDR != old.NetCIDR {
		t.Errorf("third instance %d %s", third.RunUID, third.NetCIDR)
	}
}

// TestHostnameOfDeletedTenant — §11.4: the slug of a deleted tenant is not reusable while objects of the old instance
// remain. A new tenant with that slug is refused by placement (hostname held) until the old instance is removed; at the
// database level the partial unique index refuses a second live row with that hostname whatever the writer.
func TestHostnameOfDeletedTenant(t *testing.T) {
	w := newWorld(t, 4, platform.PlacerOptions{})
	ctx := t.Context()
	w.host("h1", "lab", 30000, 39999, "10.250.0.0/16", 100)
	gone := w.tenant("reborn", nil)
	first := w.mustAllocate(gone)
	w.exec(`UPDATE tenants SET status = 'deleted' WHERE id = $1`, gone)
	w.exec(`UPDATE tenant_instances SET status = 'stopped' WHERE id = $1`, first.InstanceID)
	again := w.tenant("reborn", nil)
	if _, err := w.allocate(again); !errors.Is(err, platform.ErrHostnameInUse) {
		t.Fatalf("hostname of a deleted tenant's live instance: %v", err)
	}
	err := w.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		_, err := q.CreateTenantInstance(ctx, sqlcdb.CreateTenantInstanceParams{ID: uuid.Must(uuid.NewV7()), TenantID: again,
			HostID: first.HostID, Status: "allocated", HeadscaleVersion: hsVersion, ImageDigest: digest,
			ControlHostname: first.ControlHostname, ServerUrl: first.ServerURL, BaseDomain: first.BaseDomain,
			InternalAddress: first.InternalAddress, RunUid: 39999, NetCidr: netip.MustParsePrefix("10.250.200.0/29"),
			DataPath: "/x"})
		return err
	})
	if store.SQLState(err) != "23505" || store.SQLConstraint(err) != "tenant_instances_hostname_live_key" {
		t.Errorf("direct insert of a held hostname: %v", err)
	}
	w.exec(`UPDATE tenant_instances SET status = 'removed' WHERE id = $1`, first.InstanceID)
	if a := w.mustAllocate(again); a.ControlHostname != first.ControlHostname || a.RunUID == first.RunUID {
		t.Errorf("after the old instance is removed: %+v", a)
	}
}

// TestExhaustion — each limit of a host gives the typed NoCapacityError naming the reason, also under a race: K
// resources and N > K concurrent allocations ⇒ exactly K succeed.
func TestExhaustion(t *testing.T) {
	w := newWorld(t, 6, platform.PlacerOptions{})
	ctx := t.Context()
	noCap := func(err error, reason string) bool {
		var nc *platform.NoCapacityError
		return errors.Is(err, platform.ErrNoCapacity) && errors.As(err, &nc) &&
			(reason == "" && len(nc.Rejected) == 0 || len(nc.Rejected) == 1 && nc.Rejected[0].Reason == reason)
	}
	// UIDs: 3 in the range, raced by 10
	w.host("uids", "r-uid", 30000, 30002, "10.250.0.0/16", 100)
	won := 0
	var mu sync.Mutex
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range 10 {
		tid := w.tenant(fmt.Sprintf("uid-%d", i), ptr("r-uid"))
		wg.Go(func() {
			<-start
			_, err := w.allocate(tid)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				won++
			case !noCap(err, platform.RejectRunUIDExhausted):
				t.Errorf("uid race: %v", err)
			}
		})
	}
	close(start)
	wg.Wait()
	if won != 3 {
		t.Errorf("uid race: %d allocations, want 3", won)
	}
	// subnets: a /28 holds two /29
	w.host("nets", "r-net", 30000, 39999, "10.250.0.0/28", 100)
	for i := range 2 {
		w.mustAllocate(w.tenant(fmt.Sprintf("net-%d", i), ptr("r-net")))
	}
	if _, err := w.allocate(w.tenant("net-x", ptr("r-net"))); !noCap(err, platform.RejectNetPoolExhausted) {
		t.Errorf("third /29 of a /28: %v", err)
	}
	// capacity: one instance; a removed one does not count
	w.host("cap", "r-cap", 30000, 39999, "10.251.0.0/16", 1)
	c1 := w.mustAllocate(w.tenant("cap-1", ptr("r-cap")))
	c2 := w.tenant("cap-2", ptr("r-cap"))
	if _, err := w.allocate(c2); !noCap(err, platform.RejectFull) {
		t.Errorf("second instance on a host of capacity 1: %v", err)
	}
	if _, err := w.placer.Release(ctx, c1.TenantID, c1.InstanceID); err != nil {
		t.Fatal(err)
	}
	if a := w.mustAllocate(c2); a.RunUID != c1.RunUID+1 {
		t.Errorf("after release: %+v", a)
	}
	// no public entry; capacity 0
	w.host("noentry", "r-entry", 30000, 39999, "10.252.0.0/16", 100, `public_entry = '{}'`)
	if _, err := w.allocate(w.tenant("entry", ptr("r-entry"))); !noCap(err, platform.RejectNoPublicEntry) {
		t.Errorf("host without public entry: %v", err)
	}
	w.host("zero", "r-zero", 30000, 39999, "10.253.0.0/16", 0)
	if _, err := w.allocate(w.tenant("zero", ptr("r-zero"))); !noCap(err, platform.RejectFull) {
		t.Errorf("host of capacity 0: %v", err)
	}
	// draining / disabled hosts and an empty region are no candidates at all
	w.host("drain", "r-drain", 30000, 39999, "10.254.0.0/16", 100, `status = 'draining'`)
	w.host("off", "r-drain", 30000, 39999, "10.254.0.0/16", 100, `status = 'disabled'`)
	if _, err := w.allocate(w.tenant("drain", ptr("r-drain"))); !noCap(err, "") {
		t.Errorf("only draining/disabled hosts: %v", err)
	}
	if _, err := w.allocate(w.tenant("nowhere", ptr("mars"))); !noCap(err, "") {
		t.Errorf("region without host: %v", err)
	}
}

// TestMultiHost — N hosts: a tenant with a region only lands in it, one without lands anywhere; the least used host
// (live / max_instances) is chosen, ties by name; UIDs and subnets are per host (the same UID on two hosts is fine);
// concurrent allocations over two hosts never duplicate a UID or a subnet within a host.
func TestMultiHost(t *testing.T) {
	w := newOwnWorld(t, 6, platform.PlacerOptions{})
	ha := w.host("h-a", "lab", 30000, 39999, "10.250.0.0/16", 4)
	hb := w.host("h-b", "lab", 30000, 39999, "10.250.0.0/16", 8)
	hc := w.host("h-c", "dc2", 40000, 49999, "10.240.0.0/16", 100)
	var got []uuid.UUID
	for i := range 6 {
		got = append(got, w.mustAllocate(w.tenant(fmt.Sprintf("lab-%d", i), ptr("lab"))).HostID)
	}
	// h-a 0/4 = h-b 0/8 ⇒ name; then h-b (0 < 1/4); then 1/4 vs 1/8 ⇒ h-b; 1/4 vs 2/8 ⇒ name h-a; 2/4 vs 2/8 ⇒ h-b; 2/4 vs 3/8 ⇒ h-b
	if want := []uuid.UUID{ha, hb, hb, ha, hb, hb}; !slices.Equal(got, want) {
		t.Errorf("hosts in order %v, want %v (h-a=%s h-b=%s)", got, want, ha, hb)
	}
	if a := w.mustAllocate(w.tenant("far", ptr("dc2"))); a.HostID != hc || a.RunUID != 40000 || a.NetCIDR != netip.MustParsePrefix("10.240.0.0/29") {
		t.Errorf("dc2 tenant: %+v", a)
	}
	// h-c is the least used of all (1/100): a tenant without region goes there
	if a := w.mustAllocate(w.tenant("anywhere", nil)); a.HostID != hc {
		t.Errorf("tenant without region on %s", a.HostName)
	}
	// concurrent: the two lab hosts have room for 2 (h-a: 2/4) + 4 (h-b: 4/8) more
	var wg sync.WaitGroup
	start := make(chan struct{})
	errs := make(chan error, 12)
	for i := range 12 {
		tid := w.tenant(fmt.Sprintf("multi-%02d", i), ptr("lab"))
		wg.Go(func() {
			<-start
			_, err := w.allocate(tid)
			errs <- err
		})
	}
	close(start)
	wg.Wait()
	close(errs)
	ok, full := 0, 0
	for err := range errs {
		switch {
		case err == nil:
			ok++
		case errors.Is(err, platform.ErrNoCapacity):
			full++
		default:
			t.Errorf("multi-host race: %v", err)
		}
	}
	if ok != 6 || full != 6 {
		t.Errorf("multi-host race: %d placed, %d refused; want 6 (2 on h-a + 4 on h-b) and 6", ok, full)
	}
	var dupUID, dupNet, perHost int
	if err := w.su.QueryRow(t.Context(), `SELECT
			(SELECT count(*) FROM (SELECT host_id, run_uid FROM tenant_instances GROUP BY 1, 2 HAVING count(*) > 1) d),
			(SELECT count(*) FROM (SELECT host_id, net_cidr FROM tenant_instances GROUP BY 1, 2 HAVING count(*) > 1) d),
			(SELECT count(*) FROM tenant_instances WHERE host_id = $1)`, ha).Scan(&dupUID, &dupNet, &perHost); err != nil ||
		dupUID != 0 || dupNet != 0 || perHost != 4 {
		t.Errorf("duplicates uid %d net %d, h-a holds %d (%v)", dupUID, dupNet, perHost, err)
	}
}

// TestPerTenantSTUN — the fallback design (§10.1) is off by default: no STUN port, column NULL. With
// PerTenantSTUN, a host needs a stun_port_range; ports skip the platform's own (3478…) and run out with a typed error.
func TestPerTenantSTUN(t *testing.T) {
	w := newWorld(t, 4, platform.PlacerOptions{PerTenantSTUN: true})
	w.host("plain", "r-plain", 30000, 39999, "10.250.0.0/16", 100)
	if _, err := w.allocate(w.tenant("plain", ptr("r-plain"))); !errors.Is(err, platform.ErrNoCapacity) {
		t.Errorf("per-tenant STUN on a host without range: %v", err)
	}
	sh := w.host("stun", "r-stun", 30000, 39999, "10.251.0.0/16", 100, `stun_port_range = int4range(3478, 3480, '[]')`)
	var ports []int32
	for i := range 2 {
		ports = append(ports, w.mustAllocate(w.tenant(fmt.Sprintf("stun-%d", i), ptr("r-stun"))).STUNPort)
	}
	if !slices.Equal(ports, []int32{3479, 3480}) {
		t.Errorf("STUN ports %v, want [3479 3480] (3478 is the shared STUN)", ports)
	}
	var nc *platform.NoCapacityError
	if _, err := w.allocate(w.tenant("stun-x", ptr("r-stun"))); !errors.As(err, &nc) || len(nc.Rejected) != 1 ||
		nc.Rejected[0].Reason != platform.RejectSTUNExhausted {
		t.Errorf("third STUN port: %v", err)
	}
	var stored int32
	if err := w.su.QueryRow(t.Context(), `SELECT stun_port FROM tenant_instances WHERE host_id = $1 AND stun_port IS NOT NULL
		ORDER BY stun_port LIMIT 1`, sh).Scan(&stored); err != nil ||
		stored != 3479 {
		t.Errorf("stored STUN port %d (%v)", stored, err)
	}
	// default placer on the same database: shared STUN
	def, err := platform.NewPlacer(w.st, platform.PlacerOptions{BaseDomain: baseDomain})
	if err != nil {
		t.Fatal(err)
	}
	a, err := def.Allocate(t.Context(), platform.AllocationRequest{TenantID: w.tenant("shared", ptr("r-plain")),
		InstanceID: uuid.Must(uuid.NewV7()), HeadscaleVersion: hsVersion, ImageDigest: digest})
	if err != nil || a.STUNPort != 0 {
		t.Errorf("default placer: %+v, %v", a, err)
	}
}

// TestPlacementScope — placement needs the platform pool: the tenant pool of the worker cannot even lock or read a host
// (42501 — hosts is not granted to the tenant roles), so a tenant-scoped connection can never allocate.
func TestPlacementScope(t *testing.T) {
	w := newWorld(t, 2, platform.PlacerOptions{})
	ctx := t.Context()
	w.host("h1", "lab", 30000, 39999, "10.250.0.0/16", 100)
	tid := w.tenant("scoped", nil)
	err := w.st.WithTenantTx(ctx, tid, func(q *sqlcdb.Queries) error {
		_, err := q.LockPlacementHosts(ctx, nil)
		return err
	})
	if store.SQLState(err) != "42501" {
		t.Errorf("tenant pool locking hosts: %v, want 42501", err)
	}
	err = w.st.WithTenantTx(ctx, tid, func(q *sqlcdb.Queries) error {
		_, err := q.CreateTenantInstance(ctx, sqlcdb.CreateTenantInstanceParams{ID: uuid.Must(uuid.NewV7()), TenantID: tid,
			HostID: uuid.Must(uuid.NewV7()), Status: "allocated", HeadscaleVersion: hsVersion, ImageDigest: digest,
			ControlHostname: "x", ServerUrl: "https://x", BaseDomain: "x", InternalAddress: "x", RunUid: 30000,
			NetCidr: netip.MustParsePrefix("10.250.0.0/29"), DataPath: "/x"})
		return err
	})
	if store.SQLState(err) != "42501" {
		t.Errorf("tenant pool inserting an instance: %v, want 42501", err)
	}
	// the same store allocates through its platform pool (mg_worker_platform — store.Open checked its group)
	if a := w.mustAllocate(tid); a.TenantID != tid || a.RunUID != 30000 {
		t.Errorf("allocation on the worker's platform pool: %+v", a)
	}
}
