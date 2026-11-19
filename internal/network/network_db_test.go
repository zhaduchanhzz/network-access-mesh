package network

// PostgreSQL integration tests of the network module (P4-T12): one database for the package (internal/store/storetest),
// two fresh tenants per test, each with a running instance and a fake Headscale (internal/devices/devicestest — the
// adapter over HTTP, approve_routes replaces the whole set like 0.29.7). The register of devices is the one of
// internal/devices (RouteRegister — §13.6), the tag catalog check the one of internal/policies (RequireTags).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/zhaduchanhzz/network-access-mesh/internal/devices"
	"github.com/zhaduchanhzz/network-access-mesh/internal/devices/devicestest"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/policies"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/storetest"
)

func TestMain(m *testing.M) {
	code := m.Run()
	storetest.Cleanup()
	os.Exit(code)
}

var shared struct {
	mu sync.Mutex
	db string
}

func sharedDB(t *testing.T, env *storetest.Env) string {
	t.Helper()
	shared.mu.Lock()
	defer shared.mu.Unlock()
	if shared.db == "" {
		shared.db = env.NewDatabase(t)
	}
	return shared.db
}

type tenantFx struct {
	id, instance uuid.UUID
	slug         string
	admin        uuid.UUID // identity of the Tenant Admin
	group        uuid.UUID
	hs           *devicestest.Fake
}

type fixture struct {
	su    *pgx.Conn
	mu    sync.Mutex
	a, b  *tenantFx
	st    *store.Store
	svc   *Service
	reg   *headscale.CachingRegistry
	host  uuid.UUID
	recon []ReconfigureRequest
}

var seq struct {
	mu sync.Mutex
	n  int
}

func next() int {
	seq.mu.Lock()
	defer seq.mu.Unlock()
	seq.n++
	return seq.n
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	env := storetest.Require(t)
	db := sharedDB(t, env)
	f := &fixture{host: uuid.New()}
	f.su = env.Admin(t, db)
	f.exec(t, `INSERT INTO hosts (id, name, region, run_uid_range, tenant_net_pool)
		VALUES ($1, $2, 'lab', int4range(30000, 40000), '10.250.0.0/16')`, f.host, "host-"+uuid.NewString()[:8])
	f.a, f.b = f.newTenant(t), f.newTenant(t)
	f.reg = devicestest.Registry(map[uuid.UUID]headscale.Target{f.a.id: f.a.hs.Target(f.a.instance), f.b.id: f.b.hs.Target(f.b.instance)})
	f.st = env.OpenStore(t, db, "mg_api_tenant", "mg_api_platform", 8)
	svc, err := New(f.st, Config{Registry: f.reg, Devices: devices.RouteRegister{}, Tags: policies.RequireTags,
		ResourceRefs: policies.ResourceReferences,
		Reconfigure:  f.reconfigure, BaseDomain: "mg.test"})
	if err != nil {
		t.Fatal(err)
	}
	f.svc = svc
	return f
}

// reconfigure stands in for orchestrator.EnqueueReconfigure: it enqueues the job the same way (kind, dedupe) without the
// audit operation (the request scope that fills the tenant of the event is the HTTP chain's).
func (f *fixture) reconfigure(ctx context.Context, tx *store.Tx, req ReconfigureRequest) (jobs.Job, bool, error) {
	f.mu.Lock()
	f.recon = append(f.recon, req)
	f.mu.Unlock()
	e, err := jobs.Enqueue(ctx, tx, jobs.Spec{Kind: "instance.reconfigure", TenantID: &req.TenantID, InstanceID: &req.InstanceID,
		Input: map[string]any{"change": map[string]any{"nameservers": req.Nameservers}}, RequestedBy: req.RequestedBy})
	if err != nil {
		return jobs.Job{}, false, err
	}
	j, err := jobs.ProjectTx(ctx, tx.Q, e.Job.ID)
	return j, e.Created, err
}

func (f *fixture) newTenant(t *testing.T) *tenantFx {
	t.Helper()
	i := next()
	ten := &tenantFx{id: uuid.New(), instance: uuid.New(), slug: fmt.Sprintf("n%s%02d", strings.ReplaceAll(uuid.NewString()[:6], "-", ""), i%100)}
	ten.hs = devicestest.New(t, ten.slug)
	f.exec(t, `INSERT INTO tenants (id, slug, name, status) VALUES ($1, $2, $3, 'active')`, ten.id, ten.slug, "Tenant "+ten.slug)
	f.exec(t, `INSERT INTO tenant_instances (id, tenant_id, host_id, status, headscale_version, image_digest,
			control_hostname, server_url, base_domain, internal_address, run_uid, net_cidr, data_path)
		VALUES ($1, $2, $3, 'running', '0.29.7', 'sha256:'||repeat('a', 64), $4, 'https://'||$4, $5, $6, $7, $8::cidr, $9)`,
		ten.instance, ten.id, f.host, ten.slug+".mesh.mg.test", ten.slug+".tail.mg.test", "hs-"+ten.slug+":8080", 30000+i,
		fmt.Sprintf("10.250.%d.%d/29", (i/32)%256, (i%32)*8), "/opt/meshguard/tenants/"+ten.instance.String())
	idp := uuid.New()
	f.exec(t, `INSERT INTO identity_providers (id, scope, tenant_id, issuer, client_id, driver, status)
		VALUES ($1, 'tenant', $2, $3, 'mg-portal', 'keycloak', 'active')`, idp, ten.id, "https://idp.invalid/realms/"+ten.slug)
	ten.admin = uuid.New()
	f.exec(t, `INSERT INTO identities (id, idp_id, tenant_id, scope, subject, email, email_verified, display_name)
		VALUES ($1, $2, $3, 'tenant', $4, $5, true, 'admin')`, ten.admin, idp, ten.id, "admin-"+ten.slug, "admin@"+ten.slug+".test")
	f.exec(t, `INSERT INTO tenant_memberships (tenant_id, identity_id, role_id, status)
		SELECT $1, $2, id, 'active' FROM roles WHERE scope = 'tenant' AND key = 'tenant_admin'`, ten.id, ten.admin)
	ten.group = uuid.New()
	f.exec(t, `INSERT INTO groups (id, tenant_id, name) VALUES ($1, $2, 'ops')`, ten.group, ten.id)
	f.exec(t, `INSERT INTO tenant_tags (tenant_id, name, purpose) VALUES ($1, 'tag:server', 'server')`, ten.id)
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

func (f *fixture) strings(t *testing.T, sql string, args ...any) []string {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	rows, err := f.su.Query(context.Background(), sql, args...)
	if err != nil {
		t.Fatalf("superuser query: %v\n%s", err, sql)
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

func pfx(ss ...string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(ss))
	for _, s := range ss {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

// router puts a node on the fake Headscale and its row in the register (as inventory.sync would).
func (f *fixture) router(t *testing.T, ten *tenantFx, nodeID uint64, ip string, tags []string, available, approved []netip.Prefix) uuid.UUID {
	t.Helper()
	mk := "mkey:" + uuid.NewString()
	ten.hs.PutNode(devicestest.Node{ID: nodeID, MachineKey: mk, Hostname: fmt.Sprintf("r%d", nodeID), GivenName: fmt.Sprintf("r%d", nodeID),
		Tags: tags, IPs: []netip.Addr{netip.MustParseAddr(ip)}, Available: available, Approved: approved, CreatedAt: time.Now()})
	id := uuid.New()
	if tags == nil {
		tags = []string{}
	}
	f.exec(t, `INSERT INTO device_inventory_cache (id, tenant_id, instance_id, headscale_node_id, machine_key, name, given_name,
			ip_addresses, tags, available_routes, approved_routes)
		VALUES ($1, $2, $3, $4, $5, $6, $6, ARRAY[$7::inet], $8, $9::cidr[], $10::cidr[])`,
		id, ten.id, ten.instance, int64(nodeID), mk, fmt.Sprintf("r%d", nodeID), ip, tags, strs(available), strs(approved)) //nolint:gosec // test ids
	return id
}

func strs(ps []netip.Prefix) []string {
	out := []string{}
	for _, p := range ps {
		out = append(out, p.String())
	}
	return out
}

func codeOf(err error) string {
	if e, ok := AsError(err); ok {
		return e.Code + "/" + e.Reason
	}
	if err == nil {
		return "ok"
	}
	return "other: " + err.Error()
}

func (f *fixture) approved(t *testing.T, ten *tenantFx, nodeID uint64) []string {
	t.Helper()
	n, ok := ten.hs.Node(nodeID)
	if !ok {
		t.Fatalf("node %d gone", nodeID)
	}
	out := strs(n.Approved)
	slices.Sort(out)
	return out
}

func idem(key string) *Idempotency {
	return &Idempotency{Key: key, Hash: jobs.RequestHash("POST", "/x/"+key, []byte(`{}`))}
}

// TestRoutesApprove: the read–check–write of PL-10 with every refusal before Headscale is written; the register and
// the paired audit follow the read-back; the warnings of T-08.
func TestRoutesApprove(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	a := Actor{IdentityID: f.a.admin}
	r1 := f.router(t, f.a, 1, "100.64.0.1", nil, pfx("10.10.0.0/24", "10.20.0.0/24", "0.0.0.0/0", "::/0"), nil)
	r2 := f.router(t, f.a, 2, "100.64.0.2", []string{"tag:server"}, pfx("10.10.0.0/16"), pfx("10.10.0.0/16"))
	f.router(t, f.b, 1, "100.64.0.1", nil, pfx("10.10.0.0/24"), nil)

	list, err := f.svc.ListRoutes(ctx, f.a.id)
	if err != nil || len(list) != 2 {
		t.Fatalf("ListRoutes: %v %v", list, err)
	}
	var d1 RouteDevice
	for _, d := range list {
		if d.DeviceID == r1 {
			d1 = d
		}
	}
	codes := map[string]bool{}
	for _, w := range d1.Warnings {
		codes[w.Code] = true
	}
	if len(d1.Pending) != 4 || !d1.ExitAdvertised || d1.ExitApproved || !codes[WarnUntaggedRouter] || !codes[WarnOverlap] ||
		!codes[WarnExitNode] || d1.ETag != RoutesETag(nil) {
		t.Fatalf("r1 routes: %+v", d1)
	}

	in := RouteChangeInput{DeviceID: r1, Prefixes: []string{"10.10.0.0/24"}}
	cases := []struct {
		name    string
		ifMatch string
		in      RouteChangeInput
		want    string
	}{
		{"missing If-Match", "", in, CodePreconditionReq + "/if_match_required"},
		{"stale If-Match", RoutesETag(pfx("10.99.0.0/24")), in, CodePreconditionFailed + "/" + ReasonStaleRoutes},
		{"not advertised", d1.ETag, RouteChangeInput{DeviceID: r1, Prefixes: []string{"10.30.0.0/24"}}, CodeValidationFailed + "/route_not_advertised"},
		{"host bits", d1.ETag, RouteChangeInput{DeviceID: r1, Prefixes: []string{"10.10.0.1/24"}}, CodeValidationFailed + "/prefix_not_canonical"},
		{"exit without confirmation", d1.ETag, RouteChangeInput{DeviceID: r1, Prefixes: []string{"0.0.0.0/0"}}, CodeValidationFailed + "/exit_node_confirmation_required"},
		{"another tenant's device", d1.ETag, RouteChangeInput{DeviceID: uuid.New(), Prefixes: []string{"10.10.0.0/24"}}, CodeNotFound + "/" + ReasonNoDevice},
	}
	for _, c := range cases {
		if _, err := f.svc.ApproveRoutes(ctx, f.a.id, a, c.ifMatch, c.in, nil); codeOf(err) != c.want {
			t.Errorf("%s: %s, want %s", c.name, codeOf(err), c.want)
		}
	}
	// the device of tenant B is invisible from tenant A (RLS + tenant_id)
	listB, _ := f.svc.ListRoutes(ctx, f.b.id)
	if _, err := f.svc.ApproveRoutes(ctx, f.a.id, a, d1.ETag, RouteChangeInput{DeviceID: listB[0].DeviceID, Prefixes: []string{"10.10.0.0/24"}}, nil); codeOf(err) != CodeNotFound+"/"+ReasonNoDevice {
		t.Errorf("tenant B's device from A: %s", codeOf(err))
	}
	if got := f.approved(t, f.a, 1); len(got) != 0 {
		t.Fatalf("a refusal wrote Headscale: %v", got)
	}

	res, err := f.svc.ApproveRoutes(ctx, f.a.id, a, d1.ETag, in, idem("approve-1"))
	if err != nil || res.Device == nil {
		t.Fatalf("approve: %v", err)
	}
	if got := f.approved(t, f.a, 1); !slices.Equal(got, []string{"10.10.0.0/24"}) || res.Device.ETag != RoutesETag(pfx("10.10.0.0/24")) {
		t.Fatalf("Headscale %v, etag %s", got, res.Device.ETag)
	}
	cache := f.strings(t, `SELECT unnest(approved_routes)::text FROM device_inventory_cache WHERE id = $1`, r1)
	if !slices.Equal(cache, []string{"10.10.0.0/24"}) {
		t.Fatalf("register: %v", cache)
	}
	// a replay of the same Idempotency-Key answers the device as it is, without a second write
	before := f.a.hs.Calls(devicestest.OpSetApprovedRoutes)
	if rep, err := f.svc.ApproveRoutes(ctx, f.a.id, a, d1.ETag, in, idem("approve-1")); err != nil || rep.Device == nil ||
		f.a.hs.Calls(devicestest.OpSetApprovedRoutes) != before {
		t.Fatalf("replay: %v", err)
	}
	audit := f.strings(t, `SELECT action FROM audit_events WHERE tenant_id = $1 AND resource_id = $2 ORDER BY occurred_at, id`,
		f.a.id, r1.String())
	if !slices.Contains(audit, "route.approve.requested") || !slices.Contains(audit, "route.approve.succeeded") {
		t.Fatalf("audit: %v", audit)
	}

	// exit node: both families, with the confirmation
	etag := res.Device.ETag
	res, err = f.svc.ApproveRoutes(ctx, f.a.id, a, etag, RouteChangeInput{DeviceID: r1, Prefixes: []string{"::/0"}, ConfirmExitNode: true}, nil)
	if err != nil || !res.Device.ExitApproved {
		t.Fatalf("exit node: %v", err)
	}
	if got := f.approved(t, f.a, 1); !slices.Equal(got, []string{"0.0.0.0/0", "10.10.0.0/24", "::/0"}) {
		t.Fatalf("exit node on Headscale: %v", got)
	}

	// revoke: only approved prefixes; the exit node leaves with both families
	etag = res.Device.ETag
	if _, err := f.svc.RevokeRoutes(ctx, f.a.id, a, etag, RouteChangeInput{DeviceID: r1, Prefixes: []string{"10.20.0.0/24"}}); codeOf(err) != CodeValidationFailed+"/route_not_approved" {
		t.Fatalf("revoke not approved: %s", codeOf(err))
	}
	dv, err := f.svc.RevokeRoutes(ctx, f.a.id, a, etag, RouteChangeInput{DeviceID: r1, Prefixes: []string{"0.0.0.0/0"}})
	if err != nil || dv.ExitApproved {
		t.Fatalf("revoke exit: %v", err)
	}
	if got := f.approved(t, f.a, 1); !slices.Equal(got, []string{"10.10.0.0/24"}) {
		t.Fatalf("after revoke: %v", got)
	}

	// Headscale acknowledges but does not apply ⇒ 502 readback_mismatch, route.approve.failed
	f.a.hs.Ignore(devicestest.OpSetApprovedRoutes, true)
	_, err = f.svc.ApproveRoutes(ctx, f.a.id, a, dv.ETag, RouteChangeInput{DeviceID: r1, Prefixes: []string{"10.20.0.0/24"}}, nil)
	f.a.hs.Ignore(devicestest.OpSetApprovedRoutes, false)
	if codeOf(err) != CodeUpstreamRejected+"/"+ReasonReadbackMismatch {
		t.Fatalf("read-back: %s", codeOf(err))
	}
	failed := f.strings(t, `SELECT action FROM audit_events WHERE tenant_id = $1 AND resource_id = $2 AND action = 'route.approve.failed' AND details->>'reason' = 'readback_mismatch'`,
		f.a.id, r1.String())
	if len(failed) != 1 {
		t.Fatalf("failed events: %v", failed)
	}
	_ = r2
}

// TestRoutesConcurrent: two approvals of one device on the same ETag — the second waits for the row, reads the new set
// from Headscale and gets 412: no prefix is lost (§20 P4-T12).
func TestRoutesConcurrent(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	a := Actor{IdentityID: f.a.admin}
	r := f.router(t, f.a, 7, "100.64.0.7", []string{"tag:server"}, pfx("10.1.0.0/24", "10.2.0.0/24", "10.3.0.0/24"), pfx("10.3.0.0/24"))
	etag := RoutesETag(pfx("10.3.0.0/24"))
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i, p := range []string{"10.1.0.0/24", "10.2.0.0/24"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = f.svc.ApproveRoutes(ctx, f.a.id, a, etag, RouteChangeInput{DeviceID: r, Prefixes: []string{p}}, nil)
		}()
	}
	wg.Wait()
	ok, stale := 0, 0
	for _, err := range errs {
		switch codeOf(err) {
		case "ok":
			ok++
		case CodePreconditionFailed + "/" + ReasonStaleRoutes:
			stale++
		default:
			t.Errorf("unexpected: %s", codeOf(err))
		}
	}
	got := f.approved(t, f.a, 7)
	if ok != 1 || stale != 1 || len(got) != 2 || !slices.Contains(got, "10.3.0.0/24") {
		t.Fatalf("ok %d stale %d Headscale %v", ok, stale, got)
	}
}

// TestRoutesFourEyes: with routes.four_eyes the approval writes nothing and yields the payload; the execution applies
// exactly the approved change, only while the approved set still has the ETag of the request.
func TestRoutesFourEyes(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	a := Actor{IdentityID: f.a.admin}
	r := f.router(t, f.a, 3, "100.64.0.3", []string{"tag:server"}, pfx("10.5.0.0/24", "10.6.0.0/24"), nil)
	f.exec(t, `UPDATE tenants SET settings = '{"routes":{"four_eyes":true}}' WHERE id = $1`, f.a.id)
	etag := RoutesETag(nil)
	res, err := f.svc.ApproveRoutes(ctx, f.a.id, a, etag, RouteChangeInput{DeviceID: r, Prefixes: []string{"10.5.0.0/24"}}, nil)
	if err != nil || res.Approval == nil || res.Device != nil {
		t.Fatalf("four eyes: %+v %v", res, err)
	}
	p := *res.Approval
	if err := p.Validate(); err != nil || !slices.Equal(p.Approved, []string{"10.5.0.0/24"}) || p.IfMatch != etag {
		t.Fatalf("payload %+v: %v", p, err)
	}
	if got := f.approved(t, f.a, 3); len(got) != 0 {
		t.Fatalf("written before the approval: %v", got)
	}
	// not advertised: refused already at the request
	if _, err := f.svc.ApproveRoutes(ctx, f.a.id, a, etag, RouteChangeInput{DeviceID: r, Prefixes: []string{"10.7.0.0/24"}}, nil); codeOf(err) != CodeValidationFailed+"/route_not_advertised" {
		t.Fatalf("four eyes, not advertised: %s", codeOf(err))
	}
	exec := func(p RouteApprovalPayload) error {
		return f.st.WithTenantJobTx(ctx, f.a.id, func(tx *store.Tx) error {
			_, err := f.svc.ExecuteRouteApproval(ctx, tx, f.a.id, uuid.New(), p.DeviceID.String(), f.a.admin, p)
			return err
		})
	}
	if err := exec(p); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if got := f.approved(t, f.a, 3); !slices.Equal(got, []string{"10.5.0.0/24"}) {
		t.Fatalf("after execution: %v", got)
	}
	// the same approval again: the set no longer has the approved ETag ⇒ refused, nothing written
	if err := exec(p); codeOf(err) != CodePreconditionFailed+"/"+ReasonStaleRoutes {
		t.Fatalf("stale execution: %s", codeOf(err))
	}
	// a payload naming another device than the request
	if err := f.st.WithTenantJobTx(ctx, f.a.id, func(tx *store.Tx) error {
		_, err := f.svc.ExecuteRouteApproval(ctx, tx, f.a.id, uuid.New(), uuid.NewString(), f.a.admin, p)
		return err
	}); err == nil {
		t.Fatal("payload of another device executed")
	}
	// revocation never needs the second person
	if _, err := f.svc.RevokeRoutes(ctx, f.a.id, a, RoutesETag(pfx("10.5.0.0/24")), RouteChangeInput{DeviceID: r, Prefixes: []string{"10.5.0.0/24"}}); err != nil {
		t.Fatalf("revoke under four eyes: %v", err)
	}
}

type fakeWriter struct {
	mu    sync.Mutex
	calls [][]DNSRecord
	err   error
}

func (w *fakeWriter) WriteRecords(_ context.Context, ref InstanceRef, _ uuid.UUID, recs []DNSRecord) (string, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.err != nil {
		return "", w.err
	}
	w.calls = append(w.calls, slices.Clone(recs))
	return strings.Repeat("a", 64), nil
}

// TestDNSRecords: the shape and T-09 lint of a record, the platform domain, duplicates, one queued dns.records_write job
// for several changes, delete, replay; the job writes the whole set and records it.
func TestDNSRecords(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	a := Actor{IdentityID: f.a.admin}
	f.router(t, f.a, 1, "100.64.0.1", []string{"tag:server"}, pfx("10.40.0.0/24"), pfx("10.40.0.0/24"))
	f.router(t, f.a, 2, "100.64.0.2", nil, pfx("0.0.0.0/0", "::/0"), pfx("0.0.0.0/0", "::/0"))
	own := "db." + f.a.slug + ".tail.mg.test"
	cases := []struct {
		in   DNSRecordInput
		want string
	}{
		{DNSRecordInput{Name: "db", Type: "A", Value: "100.64.0.1"}, CodeValidationFailed + "/invalid_name"},
		{DNSRecordInput{Name: "*.corp.example", Type: "A", Value: "100.64.0.1"}, CodeValidationFailed + "/invalid_name"},
		{DNSRecordInput{Name: "db.corp.example", Type: "AAAA", Value: "100.64.0.1"}, CodeValidationFailed + "/type_mismatch"},
		{DNSRecordInput{Name: "db.corp.example", Type: "TXT", Value: "100.64.0.1"}, CodeValidationFailed + "/invalid_type"},
		{DNSRecordInput{Name: "db.corp.example", Type: "A", Value: "8.8.8.8"}, CodeValidationFailed + "/value_not_in_tailnet"},
		{DNSRecordInput{Name: "db.corp.example", Type: "A", Value: "100.64.0.99"}, CodeValidationFailed + "/value_not_in_tailnet"},
		{DNSRecordInput{Name: "app.mesh.mg.test", Type: "A", Value: "100.64.0.1"}, CodeValidationFailed + "/name_platform_domain"},
		{DNSRecordInput{Name: "db." + f.b.slug + ".tail.mg.test", Type: "A", Value: "100.64.0.1"}, CodeValidationFailed + "/name_platform_domain"},
	}
	for _, c := range cases {
		if _, err := f.svc.CreateDNSRecord(ctx, f.a.id, a, c.in, nil); codeOf(err) != c.want {
			t.Errorf("%+v: %s, want %s", c.in, codeOf(err), c.want)
		}
	}
	r1, err := f.svc.CreateDNSRecord(ctx, f.a.id, a, DNSRecordInput{Name: "DB.Corp.Example.", Type: "A", Value: "100.64.0.1"}, idem("rec-1"))
	if err != nil || r1.Record.Name != "db.corp.example" || r1.Job.Kind != KindDNSRecordsWrite {
		t.Fatalf("create: %+v %v", r1, err)
	}
	r2, err := f.svc.CreateDNSRecord(ctx, f.a.id, a, DNSRecordInput{Name: own, Type: "A", Value: "10.40.0.9"}, nil)
	if err != nil || r2.Job.ID != r1.Job.ID {
		t.Fatalf("second record (approved subnet route, own MagicDNS domain): %v — job %s vs %s", err, r2.Job.ID, r1.Job.ID)
	}
	if _, err := f.svc.CreateDNSRecord(ctx, f.a.id, a, DNSRecordInput{Name: "db.corp.example", Type: "A", Value: "100.64.0.1"}, nil); codeOf(err) != CodeConflict+"/record_exists" {
		t.Fatalf("duplicate: %s", codeOf(err))
	}
	if rep, err := f.svc.CreateDNSRecord(ctx, f.a.id, a, DNSRecordInput{Name: "DB.Corp.Example.", Type: "A", Value: "100.64.0.1"}, idem("rec-1")); err != nil || rep.Record.ID != r1.Record.ID {
		t.Fatalf("replay: %v", err)
	}
	// tenant B sees none of it
	if recs, _ := f.svc.ListDNSRecords(ctx, f.b.id); len(recs) != 0 {
		t.Fatalf("tenant B lists %d records", len(recs))
	}
	if _, err := f.svc.DeleteDNSRecord(ctx, f.b.id, r1.Record.ID, Actor{IdentityID: f.b.admin}); codeOf(err) != CodeNotFound+"/record_not_found" {
		t.Fatalf("delete from B: %s", codeOf(err))
	}

	// the job: the whole set, sorted; recorded
	w := &fakeWriter{}
	run := &jobs.Run{ID: r1.Job.ID, Kind: KindDNSRecordsWrite, TenantID: &f.a.id, Store: f.st}
	if err := f.svc.runRecordsJob(ctx, run, w); err != nil {
		t.Fatal(err)
	}
	if len(w.calls) != 1 || len(w.calls[0]) != 2 || w.calls[0][0].Name != "db.corp.example" {
		t.Fatalf("written: %+v", w.calls)
	}
	var out RecordsJobOutput
	if err := json.Unmarshal(run.Output(), &out); err != nil || out.Records != 2 || out.Rounds != 1 {
		t.Fatalf("output %s: %v", run.Output(), err)
	}
	if ev := f.strings(t, `SELECT action FROM audit_events WHERE tenant_id = $1 AND action = 'dns.records.write' AND actor_type = 'system'`, f.a.id); len(ev) != 1 {
		t.Fatalf("records write audit: %v", ev)
	}
	// a transient agent failure is retried, a refusal is final
	w.err = jobs.Transient("agent_unavailable", errors.New("down"))
	if err := f.svc.runRecordsJob(ctx, run, w); jobs.IsPermanent(err) || err == nil {
		t.Fatalf("transient: %v", err)
	}
	w.err = nil

	// delete both: the last one leaves an empty set
	for _, r := range []DNSRecordChange{r1, r2} {
		if _, err := f.svc.DeleteDNSRecord(ctx, f.a.id, r.Record.ID, a); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.svc.runRecordsJob(ctx, run, w); err != nil || len(w.calls[len(w.calls)-1]) != 0 {
		t.Fatalf("empty set: %v %+v", err, w.calls)
	}
	// a quarantined instance is never written to
	f.exec(t, `UPDATE tenant_instances SET status = 'quarantined' WHERE id = $1`, f.a.instance)
	n := len(w.calls)
	if err := f.svc.runRecordsJob(ctx, run, w); err != nil || len(w.calls) != n {
		t.Fatalf("quarantined: %v", err)
	}
	audit := f.strings(t, `SELECT action FROM audit_events WHERE tenant_id = $1 AND action LIKE 'dns.record.%' ORDER BY occurred_at, id`, f.a.id)
	if len(audit) < 4 || audit[0] != ActionDNSRecordCreate {
		t.Fatalf("audit: %v", audit)
	}
}

// TestDNSSettings: the view of the configuration in force, If-Match, the nameserver rules, the reconfiguration.
func TestDNSSettings(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	a := Actor{IdentityID: f.a.admin}
	v, err := f.svc.GetDNS(ctx, f.a.id)
	if err != nil || !v.MagicDNS || v.BaseDomain != f.a.slug+".tail.mg.test" || v.Nameservers != nil || v.ConfigVersion != nil {
		t.Fatalf("view without a version: %+v %v", v, err)
	}
	vid := uuid.New()
	f.exec(t, `INSERT INTO instance_config_versions (id, tenant_id, instance_id, version, template_version, params, rendered_config,
			config_sha256, status) VALUES ($1, $2, $3, 1, '2', '{"nameservers":["1.1.1.1"]}', 'x', repeat('e', 64), 'applied')`,
		vid, f.a.id, f.a.instance)
	f.exec(t, `UPDATE tenant_instances SET config_version_id = $1 WHERE id = $2`, vid, f.a.instance)
	v, err = f.svc.GetDNS(ctx, f.a.id)
	if err != nil || !slices.Equal(v.Nameservers, []string{"1.1.1.1"}) || v.ConfigVersion == nil || *v.ConfigVersion != 1 {
		t.Fatalf("view: %+v %v", v, err)
	}
	for _, c := range []struct {
		ifMatch string
		ns      []string
		want    string
	}{
		{"", []string{"9.9.9.9"}, CodePreconditionReq + "/if_match_required"},
		{`"stale"`, []string{"9.9.9.9"}, CodePreconditionFailed + "/stale_etag"},
		{v.ETag, nil, CodeValidationFailed + "/invalid_count"},
		{v.ETag, []string{"127.0.0.1"}, CodeValidationFailed + "/invalid_address"},
		{v.ETag, []string{"9.9.9.9", "9.9.9.9"}, CodeValidationFailed + "/duplicate_address"},
	} {
		if _, _, err := f.svc.UpdateDNSSettings(ctx, f.a.id, a, c.ifMatch, c.ns); codeOf(err) != c.want {
			t.Errorf("%v %q: %s, want %s", c.ns, c.ifMatch, codeOf(err), c.want)
		}
	}
	j, created, err := f.svc.UpdateDNSSettings(ctx, f.a.id, a, v.ETag, []string{"9.9.9.9", "2620:fe::fe"})
	if err != nil || !created || j.Kind != "instance.reconfigure" || len(f.recon) != 1 ||
		!slices.Equal(f.recon[0].Nameservers, []string{"9.9.9.9", "2620:fe::fe"}) || f.recon[0].Action != ActionDNSSettingsUpdate ||
		f.recon[0].InstanceID != f.a.instance {
		t.Fatalf("reconfigure: %+v %v %v", j, created, err)
	}
	v, _ = f.svc.GetDNS(ctx, f.a.id)
	if v.Pending == nil || v.Pending.JobID != j.ID || !slices.Equal(v.Pending.Nameservers, []string{"9.9.9.9", "2620:fe::fe"}) {
		t.Fatalf("pending: %+v", v.Pending)
	}
	if _, err := f.svc.GetDNS(ctx, uuid.New()); codeOf(err) != CodeConflict+"/"+ReasonNoInstance {
		t.Fatalf("unknown tenant: %s", codeOf(err))
	}
}

// TestResources: the catalog's rules, tags from the catalog only, the owner group of the tenant, If-Match, one
// policy.apply (resource_change) per change, isolation.
func TestResources(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	a := Actor{IdentityID: f.a.admin}
	bad := []struct {
		in   ResourceInput
		want string
	}{
		{ResourceInput{Name: "DB", Kind: KindHost, Address: "10.0.0.5"}, CodeValidationFailed + "/invalid_name"},
		{ResourceInput{Name: "db", Kind: "vm", Address: "10.0.0.5"}, CodeValidationFailed + "/invalid_kind"},
		{ResourceInput{Name: "db", Kind: KindHost, Address: "10.0.0.0/24"}, CodeValidationFailed + "/single_address"},
		{ResourceInput{Name: "net", Kind: KindSubnet, Address: "10.0.0.1/24"}, CodeValidationFailed + "/address_not_canonical"},
		{ResourceInput{Name: "net", Kind: KindSubnet, Address: "0.0.0.0/0"}, CodeValidationFailed + "/subnet_prefix"},
		{ResourceInput{Name: "svc", Kind: KindService, Address: "10.0.0.5"}, CodeValidationFailed + "/service_needs_ports"},
		{ResourceInput{Name: "db", Kind: KindHost, Address: "10.0.0.5", Ports: []string{"22"}, Protocol: ProtocolICMP}, CodeValidationFailed + "/ports_with_icmp"},
		{ResourceInput{Name: "db", Kind: KindHost, Address: "10.0.0.5", Ports: []string{"70000"}}, CodeValidationFailed + "/invalid_port"},
		{ResourceInput{Name: "db", Kind: KindHost, Address: "10.0.0.5", Tags: []string{"tag:undeclared"}}, CodeValidationFailed + "/tag_not_in_catalog"},
		{ResourceInput{Name: "db", Kind: KindHost, Address: "10.0.0.5", OwnerGroupID: &f.b.group}, CodeValidationFailed + "/unknown_group"},
	}
	for _, c := range bad {
		if _, err := f.svc.CreateResource(ctx, f.a.id, a, c.in, nil); codeOf(err) != c.want {
			t.Errorf("%+v: %s, want %s", c.in, codeOf(err), c.want)
		}
	}
	ch, err := f.svc.CreateResource(ctx, f.a.id, a, ResourceInput{Name: "web", Kind: KindService, Address: "10.0.0.5/32",
		Ports: []string{"8443", "443", "443", "8000-8100"}, Protocol: ProtocolTCP, Tags: []string{"tag:server"},
		OwnerGroupID: &f.a.group, Description: "  web  "}, idem("res-1"))
	if err != nil {
		t.Fatal(err)
	}
	r := ch.Resource
	if r.AddressString() != "10.0.0.5" || !slices.Equal(r.Ports, []string{"443", "8000-8100", "8443"}) || r.Description != "web" ||
		r.ETag() != `"1"` || ch.PolicyJobID == uuid.Nil {
		t.Fatalf("created: %+v", r)
	}
	trig := f.strings(t, `SELECT input->>'trigger' FROM provisioning_jobs WHERE id = $1 AND kind = 'policy.apply'`, ch.PolicyJobID)
	if !slices.Equal(trig, []string{TriggerResourceChange}) {
		t.Fatalf("policy.apply: %v", trig)
	}
	if rep, err := f.svc.CreateResource(ctx, f.a.id, a, ResourceInput{Name: "web", Kind: KindService, Address: "10.0.0.5", Ports: []string{"443"}}, idem("res-1")); err != nil || rep.Resource.ID != r.ID {
		t.Fatalf("replay: %v", err)
	}
	if _, err := f.svc.CreateResource(ctx, f.a.id, a, ResourceInput{Name: "web", Kind: KindHost, Address: "10.0.0.6"}, nil); codeOf(err) != CodeConflict+"/resource_exists" {
		t.Fatalf("duplicate name: %s", codeOf(err))
	}
	// the tag of the resource now holds the tag in the catalog (tag_in_use counts resources — P4-T15)
	if n := f.strings(t, `SELECT count(*)::text FROM network_resources WHERE tenant_id = $1 AND 'tag:server' = ANY(tags)`, f.a.id); n[0] != "1" {
		t.Fatalf("tagged resources: %v", n)
	}

	name := "web-2"
	if _, err := f.svc.UpdateResource(ctx, f.a.id, r.ID, a, "", ResourcePatch{Name: &name}); codeOf(err) != CodePreconditionReq+"/if_match_required" {
		t.Fatalf("patch without If-Match: %s", codeOf(err))
	}
	if _, err := f.svc.UpdateResource(ctx, f.a.id, r.ID, a, `"9"`, ResourcePatch{Name: &name}); codeOf(err) != CodePreconditionFailed+"/stale_etag" {
		t.Fatalf("patch stale: %s", codeOf(err))
	}
	noOwner, anyProto := "", ProtocolAny
	up, err := f.svc.UpdateResource(ctx, f.a.id, r.ID, a, r.ETag(), ResourcePatch{Name: &name, OwnerGroupID: &noOwner, Protocol: &anyProto})
	if err != nil || up.Resource.Name != "web-2" || up.Resource.OwnerGroupID != nil || up.Resource.Protocol != ProtocolAny ||
		up.Resource.ETag() != `"2"` {
		t.Fatalf("patch: %+v %v", up.Resource, err)
	}
	if _, err := f.svc.GetResource(ctx, f.b.id, r.ID); codeOf(err) != CodeNotFound+"/resource_not_found" {
		t.Fatalf("tenant B reads A's resource: %s", codeOf(err))
	}
	if _, err := f.svc.DeleteResource(ctx, f.b.id, r.ID, Actor{IdentityID: f.b.admin}, up.Resource.ETag()); codeOf(err) != CodeNotFound+"/resource_not_found" {
		t.Fatalf("tenant B deletes A's resource: %s", codeOf(err))
	}
	if _, err := f.svc.CreateResource(ctx, f.a.id, a, ResourceInput{Name: "lan", Kind: KindSubnet, Address: "192.168.10.0/24"}, nil); err != nil {
		t.Fatal(err)
	}
	page, err := f.svc.ListResources(ctx, f.a.id, 1, "")
	if err != nil || len(page.Items) != 1 || page.NextCursor == "" {
		t.Fatalf("page: %+v %v", page, err)
	}
	if _, err := f.svc.DeleteResource(ctx, f.a.id, r.ID, a, ""); codeOf(err) != CodePreconditionReq+"/if_match_required" {
		t.Fatalf("delete without If-Match: %s", codeOf(err))
	}
	// a typed policy version that names the resource keeps it (P4-T10's principal {type: resource})
	pv := uuid.New()
	f.exec(t, `INSERT INTO policy_versions (id, tenant_id, version, kind, state, content_sha256, source, created_by)
		VALUES ($1, $2, 1, 'user', 'draft', repeat('c', 64), $3::jsonb, $4)`, pv, f.a.id,
		`{"grants":[{"src":[{"type":"group","ref":"`+f.a.group.String()+`"}],"dst":[{"type":"resource","ref":"`+r.ID.String()+`"}],"ip":["tcp:443"]}],"ssh":[]}`, f.a.admin)
	if _, err := f.svc.DeleteResource(ctx, f.a.id, r.ID, a, up.Resource.ETag()); codeOf(err) != CodeConflict+"/resource_in_use" {
		t.Fatalf("delete of a named resource: %s", codeOf(err))
	}
	f.exec(t, `UPDATE policy_versions SET state = 'rejected', rejected_at = now() WHERE id = $1`, pv)
	if _, err := f.svc.DeleteResource(ctx, f.a.id, r.ID, a, up.Resource.ETag()); err != nil {
		t.Fatal(err)
	}
	audit := f.strings(t, `SELECT action FROM audit_events WHERE tenant_id = $1 AND resource_id = $2 ORDER BY occurred_at, id`, f.a.id, r.ID.String())
	if !slices.Equal(audit, []string{ActionResourceCreate, ActionResourceCreate, ActionResourceUpdate, ActionResourceDelete}) &&
		!slices.Equal(audit, []string{ActionResourceCreate, ActionResourceUpdate, ActionResourceDelete}) {
		t.Fatalf("audit: %v", audit)
	}
}
