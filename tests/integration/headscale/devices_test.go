package contract

// Phases 7–9: the device inventory of P2-T13 (internal/devices) against the real Headscale of the contract run, with
// the register in a real PostgreSQL (versions.lock [images.postgres], MG_TEST_PG_ADMIN_URL set by run.sh) and
// device.revoke run by the real job framework (River, P2-T12):
//
//	P7 — inventory.sync normalises every node from ListNodes, and clamps every user-owned node whose expiry exceeds
//	     registration + node_expiry (V-21 (ii): the far expiries the clients of phase 1 obtained, and a new node that
//	     asked for 10 years) with the audit pair and security_event expiry_overridden; rename; two-phase revocation
//	     (expire and delete) applied only after the read-back. The runner then snapshots Headscale's database.
//	P8 — a node X registers (node id N) and is synced. The runner restores the snapshot: Headscale forgets X.
//	P9 — a node Y registers: Headscale hands out N again; the sync marks X's device removed and inserts Y as a new
//	     device (the node-id reuse rule of §6.3).

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/zhaduchanhzz/network-access-mesh/internal/devices"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/logx"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/storetest"
)

// devEnv is the device side of a phase: the register's database and the two processes' services.
type devEnv struct {
	*env
	pg    *storetest.Env
	su    *pgx.Conn // superuser connection to the register database (checks; one per test)
	db    string
	api   *devices.Service
	wrk   *devices.Service
	wrkSt *store.Store
	m     uuid.UUID // membership whose Headscale user is mg-<m>
}

// devSetup opens (phase 7: creates) the register database of the run, recorded in the run's state.
func devSetup(t *testing.T) *devEnv {
	t.Helper()
	e := setup(t)
	pg := storetest.Require(t)
	s := e.loadState(t)
	d := &devEnv{env: e, pg: pg, db: s.Values["dev_db"]}
	created := d.db == ""
	if created {
		d.db = pg.NewDatabase(t)
	}
	d.su = pg.Admin(t, d.db)
	if created {
		d.m = uuid.New()
		host, idp, ident := uuid.New(), uuid.New(), uuid.New()
		for _, q := range []struct {
			sql  string
			args []any
		}{
			{`INSERT INTO hosts (id, name, region, run_uid_range, tenant_net_pool) VALUES ($1, 'hsct', 'lab', int4range(30000, 40000), '10.250.0.0/16')`, []any{host}},
			{`INSERT INTO tenants (id, slug, name, status, settings) VALUES ($1, $2, 'Contract', 'active', jsonb_build_object('node_expiry', $3::text))`,
				[]any{tenantID, e.slug, fmt.Sprintf("%dh", int(e.nodeExpiry.Hours()))}},
			{`INSERT INTO tenant_instances (id, tenant_id, host_id, status, headscale_version, image_digest, control_hostname, server_url,
				base_domain, internal_address, run_uid, net_cidr, data_path)
				VALUES ($1, $2, $3, 'running', '0.29.7', 'sha256:'||repeat('a', 64), 'hsct.contract.test', 'https://hsct.contract.test',
				'contract.test', 'hs-hsct:8080', 30001, '10.250.254.248/29', '/opt/meshguard/tenants/hsct')`, []any{instanceID, tenantID, host}},
			{`INSERT INTO identity_providers (id, scope, tenant_id, issuer, client_id, driver, status)
				VALUES ($1, 'tenant', $2, 'https://idp.invalid/realms/hsct', 'mg-portal', 'keycloak', 'active')`, []any{idp, tenantID}},
			{`INSERT INTO identities (id, idp_id, tenant_id, scope, subject, email, email_verified, display_name)
				VALUES ($1, $2, $3, 'tenant', 'dev-owner', 'dev-owner@contract.test', true, 'Dev Owner')`, []any{ident, idp, tenantID}},
			{`INSERT INTO tenant_memberships (id, tenant_id, identity_id, role_id, status)
				SELECT $1, $2, $3, id, 'active' FROM roles WHERE scope = 'tenant' AND key = 'end_user'`, []any{d.m, tenantID, ident}},
		} {
			if _, err := d.su.Exec(context.Background(), q.sql, q.args...); err != nil {
				t.Fatalf("register fixture: %v\n%s", err, q.sql)
			}
		}
		s.Values["dev_db"], s.Values["dev_member"] = d.db, d.m.String()
		e.saveState(t, s)
	} else {
		d.m = uuid.MustParse(s.Values["dev_member"])
	}
	apiSt := pg.OpenStore(t, d.db, "mg_api_tenant", "mg_api_platform", 4)
	d.wrkSt = pg.OpenStore(t, d.db, "mg_worker_tenant", "mg_worker_platform", 6)
	lf, err := os.OpenFile(filepath.Join(e.stateDir, "adapter.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600) //nolint:gosec // G304/G703: run.sh's state directory
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lf.Close() })
	log := logx.New(lf, slog.LevelDebug, "devices")
	for _, p := range []struct {
		st  *store.Store
		dst **devices.Service
	}{{apiSt, &d.api}, {d.wrkSt, &d.wrk}} {
		svc, err := devices.New(p.st, devices.Config{Registry: e.reg, Logger: log, Registerer: prometheus.NewRegistry()})
		if err != nil {
			t.Fatal(err)
		}
		*p.dst = svc
	}
	return d
}

func (d *devEnv) user() string { return "mg-" + d.m.String() }

func (d *devEnv) count(t *testing.T, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := d.su.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
	return n
}

func (d *devEnv) deviceOf(t *testing.T, nodeID uint64) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := d.su.QueryRow(context.Background(), `SELECT id FROM device_inventory_cache WHERE instance_id = $1
			AND headscale_node_id = $2 AND removed_at IS NULL`, instanceID, int64(nodeID)).Scan(&id); err != nil { //nolint:gosec // node ids of the run
		t.Fatalf("device of node %d: %v", nodeID, err)
	}
	return id
}

// worker starts the job framework with the device handlers (fast retries) for the rest of the test.
func (d *devEnv) worker(t *testing.T) {
	t.Helper()
	cfg := jobs.DefaultConfig()
	cfg.FetchCooldown, cfg.FetchPollInterval = 10*time.Millisecond, 50*time.Millisecond
	cfg.RetryBase, cfg.RetryMax, cfg.StartJitter, cfg.SoftStopTimeout, cfg.QueuePoolConns = 100*time.Millisecond, time.Second, 0, 2*time.Second, 4
	w, err := jobs.NewWorker(d.wrkSt, cfg, jobs.Options{Alerter: d.wrk, Registerer: prometheus.NewRegistry(),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	if err := d.wrk.Register(w); err != nil {
		t.Fatal(err)
	}
	if err := w.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = w.Stop(c)
	})
}

func (d *devEnv) waitState(t *testing.T, device uuid.UUID, want string) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for {
		var s string
		if err := d.su.QueryRow(context.Background(), `SELECT revocation_state FROM device_inventory_cache WHERE id = $1`,
			device).Scan(&s); err != nil {
			t.Fatal(err)
		}
		if s == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("device %s: revocation %s, want %s", device, s, want)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func TestP7_DevicesSyncClampAndRevocation(t *testing.T) {
	d := devSetup(t)
	inst := d.inst(t)
	c := ctx(t)
	u := d.ensureUser(t, inst, d.user())

	// A node of the platform's user that asks for 10 years (V-21), and one to delete.
	far := time.Now().Add(10 * 365 * 24 * time.Hour).UTC().Truncate(time.Second)
	n := newFakeNode("ct-dev-far")
	d.registerWithKey(t, n, d.userKey(t, inst, u.ID), far)
	del := newFakeNode("ct-dev-del")
	d.registerWithKey(t, del, d.userKey(t, inst, u.ID), time.Time{})
	before, err := inst.ListNodes(c, "")
	if err != nil {
		t.Fatal(err)
	}
	var beyond []string
	for _, x := range before {
		if _, need := headscale.ExpiryClamp(x, x.CreatedAt, d.nodeExpiry); need {
			beyond = append(beyond, fmt.Sprintf("%s(%s)", x.Name, expiryString(x.Expiry)))
		}
	}

	rep, err := d.api.Sync(c, tenantID, instanceID)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Nodes != len(before) || rep.Inserted != len(before) || rep.Clamped != len(beyond) || rep.ClampFailed != 0 ||
		rep.ClampSource != devices.ClampSourceTenant {
		t.Fatalf("first sync: %+v; %d nodes, %d beyond the limit: %v", rep, len(before), len(beyond), beyond)
	}
	after, err := inst.ListNodes(c, "")
	if err != nil {
		t.Fatal(err)
	}
	var tagged int
	for _, x := range after {
		if x.IsTagged() {
			tagged++
			continue
		}
		if x.Expiry == nil || x.Expiry.After(x.CreatedAt.Add(d.nodeExpiry+headscale.ExpiryClampSlack)) {
			t.Errorf("node %s still beyond the limit after the sync: %s", x.Name, expiryString(x.Expiry))
		}
	}
	node := d.nodeOf(t, inst, n)
	want := node.CreatedAt.Add(d.nodeExpiry).UTC()
	if node.Expiry == nil || !node.Expiry.Equal(want) {
		t.Fatalf("ct-dev-far: expiry %s, want created_at + %s = %s", expiryString(node.Expiry), d.nodeExpiry, want)
	}
	mr := d.firstMap(t, n)
	if !within(mr.Node.KeyExpiry, want, time.Second) {
		t.Errorf("KeyExpiry sent to the node %s, want %s", mr.Node.KeyExpiry, want)
	}
	dev := d.deviceOf(t, node.ID)
	pairs := d.count(t, `SELECT count(*) FROM audit_events WHERE resource_id = $1 AND actor_type = 'system'
			AND action IN ('device.expiry_clamp.requested', 'device.expiry_clamp.succeeded')`, dev.String())
	sec := d.count(t, `SELECT count(*) FROM security_events WHERE tenant_id = $1 AND kind = 'expiry_overridden'
			AND (details ->> 'clamped')::boolean`, tenantID)
	owner := d.count(t, `SELECT count(*) FROM device_inventory_cache WHERE id = $1 AND owner_membership_id = $2 AND expiry = $3`, dev, d.m, want)
	if pairs != 2 || sec != len(beyond) || owner != 1 {
		t.Errorf("audit pair %d (want 2), security events %d (want %d), cache row with owner and clamped expiry %d", pairs, sec, len(beyond), owner)
	}
	d.record(t, "V-21", "inventory.sync kẹp hạn (P2-T13) — Headscale thật",
		fmt.Sprintf("lần sync đầu: %d node (%d tagged), %d node thuộc user có hạn vượt created_at + %s: %s ⇒ cả %d được ExpireNode về đúng created_at + %s; "+
			"ct-dev-far (client xin %s) ⇒ %s, KeyExpiry gửi xuống node %s; audit device.expiry_clamp.requested→succeeded (actor system); %d security_event expiry_overridden (tenant)",
			len(after), tagged, len(beyond), d.nodeExpiry, strings.Join(beyond, ", "), rep.Clamped, d.nodeExpiry, far.Format(time.RFC3339),
			expiryString(node.Expiry), mr.Node.KeyExpiry.UTC().Format(time.RFC3339), sec),
		"devices.Service.Sync: chuẩn hóa từ ListNodes; clampOf (lần đầu thấy: từ created_at) + ExpireNode(at) + đọc lại; security_event(kind=expiry_overridden)")
	if rep2, err := d.api.Sync(c, tenantID, instanceID); err != nil || rep2.Clamped != 0 || rep2.Inserted != 0 || rep2.Generation != rep.Generation+1 {
		t.Errorf("second sync: %+v %v", rep2, err)
	}

	// Rename (PATCH): checked locally, applied, cache updated.
	renamed, err := d.api.Rename(c, tenantID, dev, devices.Access{}, "dev-renamed")
	if got, _ := inst.GetNode(c, node.ID); err != nil || renamed.GivenName != "dev-renamed" || got.GivenName != "dev-renamed" {
		t.Fatalf("rename: %+v %v, instance %q", renamed, err, got.GivenName)
	}

	// Two-phase revocation through the job framework: pending until the read-back matches.
	d.worker(t)
	live := d.userKey(t, inst, u.ID) // a live key of the user: the revocation expires it (§7.4)
	res, err := d.api.Revoke(c, tenantID, dev, devices.Access{IdentityID: uuid.New()}, devices.RevokeExpire, "")
	if err != nil || res.Device.Revocation.State != devices.StatePending {
		t.Fatalf("expire: %+v %v", res, err)
	}
	d.waitState(t, dev, devices.StateApplied)
	expired, _ := inst.GetNode(c, node.ID)
	if expired.Expiry == nil || expired.Expiry.After(time.Now()) {
		t.Errorf("node after the expire: %s", expiryString(expired.Expiry))
	}
	keys, _ := inst.ListPreAuthKeys(c)
	liveLeft := 0
	for _, k := range keys {
		if k.User != nil && k.User.ID == u.ID && k.Expiration.After(time.Now()) && (k.Reusable || !k.Used) {
			liveLeft++
		}
	}
	if liveLeft != 0 || live == "" {
		t.Errorf("%d live pre-auth keys of the user after the revocation", liveLeft)
	}
	delNode := d.nodeOf(t, inst, del)
	delDev := d.deviceOf(t, delNode.ID)
	if _, err := d.api.Revoke(c, tenantID, delDev, devices.Access{}, devices.RevokeDelete, ""); err != nil {
		t.Fatal(err)
	}
	d.waitState(t, delDev, devices.StateApplied)
	if _, err := inst.GetNode(c, delNode.ID); !isKind(err, headscale.KindNotFound) {
		t.Errorf("deleted node still answers: %v", err)
	}
	if open := d.count(t, `SELECT count(*) FROM audit_events r WHERE r.action LIKE '%.requested' AND NOT EXISTS
			(SELECT 1 FROM audit_events o WHERE o.operation_id = r.operation_id AND (o.action LIKE '%.succeeded' OR o.action LIKE '%.failed'))`); open != 0 {
		t.Errorf("%d audit operations left open", open)
	}
	d.record(t, "P2-T13", "đổi tên và thu hồi hai pha với Headscale thật",
		fmt.Sprintf("RenameNode ⇒ given_name %q (đọc lại); expire ⇒ pending → applied sau GetNode (expiry %s ≤ now), key còn hạn của user bị expire (§7.4); delete ⇒ applied, GetNode ⇒ not_found",
			renamed.GivenName, expiryString(expired.Expiry)), "job device.revoke chạy trong khung job thật (River)")
}

func isKind(err error, k headscale.Kind) bool {
	he, ok := headscale.AsError(err)
	return ok && he.Kind == k
}

// TestP8_DevicesRegisterBeforeRestore: node X registers after the runner's snapshot of Headscale's database.
func TestP8_DevicesRegisterBeforeRestore(t *testing.T) {
	d := devSetup(t)
	inst := d.inst(t)
	u := d.ensureUser(t, inst, d.user())
	x := newFakeNode("ct-dev-x")
	d.registerWithKey(t, x, d.userKey(t, inst, u.ID), time.Time{})
	if _, err := d.api.Sync(ctx(t), tenantID, instanceID); err != nil {
		t.Fatal(err)
	}
	node := d.nodeOf(t, inst, x)
	s := d.loadState(t)
	s.Values["dev_x_node"], s.Values["dev_x_device"], s.Values["dev_x_machine"] = strconv.FormatUint(node.ID, 10),
		d.deviceOf(t, node.ID).String(), node.MachineKey
	d.saveState(t, s)
}

// TestP9_DevicesNodeIDReusedAfterRestore: after the restore Headscale no longer knows X; a new machine Y gets X's node
// id; the sync removes X's device and inserts Y as a new device (§6.3).
func TestP9_DevicesNodeIDReusedAfterRestore(t *testing.T) {
	d := devSetup(t)
	inst := d.inst(t)
	c := ctx(t)
	s := d.loadState(t)
	xID, _ := strconv.ParseUint(s.Values["dev_x_node"], 10, 64)
	xDev := uuid.MustParse(s.Values["dev_x_device"])
	if _, err := inst.GetNode(c, xID); !isKind(err, headscale.KindNotFound) {
		t.Fatalf("node %d after the restore: %v, want not_found", xID, err)
	}
	u := d.ensureUser(t, inst, d.user())
	y := newFakeNode("ct-dev-y")
	d.registerWithKey(t, y, d.userKey(t, inst, u.ID), time.Time{})
	yNode := d.nodeOf(t, inst, y)
	rep, err := d.api.Sync(c, tenantID, instanceID)
	if err != nil {
		t.Fatal(err)
	}
	yDev := d.deviceOf(t, yNode.ID)
	xRemoved := d.count(t, `SELECT count(*) FROM device_inventory_cache WHERE id = $1 AND removed_at IS NOT NULL AND machine_key = $2`,
		xDev, s.Values["dev_x_machine"])
	if yNode.ID != xID {
		// Headscale did not hand the id out again: the rule is then the plain "node absent ⇒ removed" one.
		t.Logf("Headscale gave node id %d to Y (X had %d): no reuse observed", yNode.ID, xID)
	}
	if yDev == xDev || xRemoved != 1 || (yNode.ID == xID && rep.Reused != 1) {
		t.Fatalf("after the sync: X device %s removed %d, Y device %s, report %+v", xDev, xRemoved, yDev, rep)
	}
	rows := d.count(t, `SELECT count(*) FROM device_inventory_cache WHERE instance_id = $1 AND headscale_node_id = $2`, instanceID, int64(xID)) //nolint:gosec // node id of the run
	d.record(t, "§6.3", "node id được cấp lại sau khi restore SQLite cũ hơn (Headscale thật)",
		fmt.Sprintf("X đăng ký sau snapshot ⇒ node id %d; restore snapshot ⇒ GetNode(%d) not_found; Y (machine key khác) ⇒ node id %d (%s); sync: %d hàng cho node id %d, X removed, Y là thiết bị mới (reused=%d)",
			xID, xID, yNode.ID, map[bool]string{true: "CẤP LẠI", false: "không cấp lại"}[yNode.ID == xID], rows, xID, rep.Reused),
		"quy tắc sync §6.3: cùng headscale_node_id khác machine_key ⇒ removed_at cho hàng cũ + hàng mới")

	// Canary of §25.1 rule 9 over the device phases too: no credential in the logs or the observations.
	logs, err := os.ReadFile(filepath.Join(d.stateDir, "adapter.log"))
	if err != nil {
		t.Fatal(err)
	}
	obs, _ := os.ReadFile(d.obsFile)
	for name, secret := range map[string]string{"api key": d.apiKey, "edge token": d.edgeToken} {
		for _, needle := range []string{secret, secretPart(secret)} {
			if strings.Contains(string(logs), needle) || strings.Contains(string(obs), needle) {
				t.Errorf("%s leaked into the logs of the device phases", name)
			}
		}
	}
}
