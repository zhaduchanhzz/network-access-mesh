//go:build mgtestfixture

// Package devicesauthz drives the device operations of P2-T13 through the composed API — identity session layer,
// authorization (authz), audit middleware, devicesapi — with sessions minted by the fixture of P2-T15a for every role
// of §8.6, a fake Headscale per tenant behind the real adapter, and the real job worker running device.revoke:
// authorization of each operation, object-level checks (a device of another tenant, of another member, a tagged one),
// the own-resource rule of the End User (§8.4 invariant 3b) and the audit trail of the two-phase revocation.
package devicesauthz

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/authz"
	"github.com/zhaduchanhzz/network-access-mesh/internal/devices"
	"github.com/zhaduchanhzz/network-access-mesh/internal/devices/devicestest"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/auditapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/authzhook"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/devicesapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/gen"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/identityapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/logx"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/ratelimit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/storetest"
	"github.com/zhaduchanhzz/network-access-mesh/tests/security/sessionfixture"
)

func TestMain(m *testing.M) {
	code := m.Run()
	storetest.Cleanup()
	os.Exit(code)
}

// env is the composed api process of the test (the fixture's world + the device handlers + the audit middleware).
type env struct {
	w   *sessionfixture.World
	api http.Handler
}

func (e *env) do(t *testing.T, s *sessionfixture.Session, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = bytes.NewBufferString(body)
	}
	r := s.Request(context.Background(), method, path, rd)
	if method == http.MethodPost {
		r.Header.Set("Idempotency-Key", "k-"+uuid.NewString())
	}
	rec := httptest.NewRecorder()
	e.api.ServeHTTP(rec, r)
	return rec
}

func unlimited() httpapi.RateLimits {
	l := ratelimit.Limit{Every: time.Nanosecond, Burst: 1_000_000_000}
	out := httpapi.RateLimits{}
	for _, c := range httpapi.Classes {
		out[c] = httpapi.ClassLimits{PerIP: l, PerIdentity: l}
	}
	return out
}

// TestDevicesThroughTheComposedAPI: every tenant role of A against the device operations (expectations written from
// the matrix of §8.6, independently of the seed), object-level checks, then the worker applies the revocations and
// the audit trail is complete.
func TestDevicesThroughTheComposedAPI(t *testing.T) {
	w := sessionfixture.New(t, sessionfixture.Options{})
	pg := storetest.Require(t)
	ctx := context.Background()
	host := uuid.New()
	w.Exec(t, `INSERT INTO hosts (id, name, region, run_uid_range, tenant_net_pool)
		VALUES ($1, 'host-1', 'lab', int4range(30000, 40000), '10.250.0.0/16')`, host)
	instances := map[*sessionfixture.Tenant]uuid.UUID{w.A: uuid.New(), w.B: uuid.New()}
	fakes := map[*sessionfixture.Tenant]*devicestest.Fake{}
	targets := map[uuid.UUID]headscale.Target{}
	i := 0
	for ten, inst := range instances {
		i++
		w.Exec(t, `INSERT INTO tenant_instances (id, tenant_id, host_id, status, headscale_version, image_digest,
				control_hostname, server_url, base_domain, internal_address, run_uid, net_cidr, data_path)
			VALUES ($1, $2, $3, 'running', '0.29.7', 'sha256:'||repeat('a', 64), $4, 'https://'||$4, $5, $6, $7, $8::cidr, $9)`,
			inst, ten.ID, host, ten.Slug+".mesh.test", ten.Slug+".ts.test", "hs-"+ten.Slug+":8080", 30000+i,
			fmt.Sprintf("10.250.%d.0/29", i), "/opt/meshguard/tenants/"+inst.String())
		fakes[ten] = devicestest.New(t, ten.Slug)
		targets[ten.ID] = fakes[ten].Target(inst)
	}
	reg := devicestest.Registry(targets)
	apiSvc, err := devices.New(w.Store, devices.Config{Registry: reg})
	if err != nil {
		t.Fatal(err)
	}
	logger, err := audit.New(w.Store, pg.OpenAuditWriter(t, w.DB), audit.Config{Registerer: prometheus.NewRegistry()})
	if err != nil {
		t.Fatal(err)
	}
	hooks := authzhook.Hooks(w.Identity, authz.New(w.Store))
	hooks.Audit = auditapi.Middleware(logger)
	api, err := httpapi.New(httpapi.Options{Logger: logx.New(io.Discard, slog.LevelInfo, "api"), Hooks: hooks, RateLimits: unlimited(),
		Handlers: httpapi.Handlers{Auth: identityapi.New(w.Identity), Devices: devicesapi.New(apiSvc)}})
	if err != nil {
		t.Fatal(err)
	}
	e := &env{w: w, api: api}

	// Nodes. A: one owned by the Tenant Admin ("other"), two owned by the End User, one tagged that the End User
	// enrolled (owner kept by the platform, never visible to her: invariant 3b). B: one owned by B's End User.
	eu, ta := w.Actor(t, authz.RoleEndUser, w.A), w.Actor(t, authz.RoleTenantAdmin, w.A)
	euB := w.Actor(t, authz.RoleEndUser, w.B)
	now := time.Now().UTC()
	node := func(id uint64, member uuid.UUID, tags ...string) devicestest.Node {
		return devicestest.Node{ID: id, MachineKey: fmt.Sprintf("mkey:%064x", id), NodeKey: fmt.Sprintf("nodekey:%064x", id),
			Hostname: fmt.Sprintf("host-%d", id), GivenName: fmt.Sprintf("host-%d", id), UserID: id, UserName: "mg-" + member.String(),
			IPs: []netip.Addr{netip.MustParseAddr(fmt.Sprintf("100.64.0.%d", id))}, Method: "cli", Online: true, CreatedAt: now,
			Expiry: tp(now.Add(24 * time.Hour)), Tags: tags}
	}
	fakes[w.A].PutNode(node(1, ta.MembershipID))
	fakes[w.A].PutNode(node(2, eu.MembershipID))
	fakes[w.A].PutNode(node(3, eu.MembershipID))
	fakes[w.A].PutNode(node(4, eu.MembershipID, "tag:server"))
	fakes[w.B].PutNode(node(1, euB.MembershipID))
	for ten, inst := range instances {
		if _, err := apiSvc.Sync(ctx, ten.ID, inst); err != nil {
			t.Fatal(err)
		}
	}
	devOf := func(ten *sessionfixture.Tenant, nodeID int) string {
		var id uuid.UUID
		w.Scan(t, `SELECT id FROM device_inventory_cache WHERE tenant_id = $1 AND headscale_node_id = $2 AND removed_at IS NULL`,
			[]any{ten.ID, nodeID}, &id)
		return id.String()
	}
	other, mine, mine2, tagged, ofB := devOf(w.A, 1), devOf(w.A, 2), devOf(w.A, 3), devOf(w.A, 4), devOf(w.B, 1)
	w.Exec(t, `UPDATE device_inventory_cache SET owner_membership_id = $1 WHERE id = $2`, eu.MembershipID, tagged)
	a := "/tenants/" + w.A.ID.String() + "/devices"

	type check struct {
		method, path, body string
		want               map[string]int // role → status; missing role ⇒ want[""]
	}
	all := func(code int) map[string]int { return map[string]int{"": code} }
	roles := sessionfixture.TenantRoles
	checks := []check{
		// read (✔ TO TA TP TV, ○ EU)
		{http.MethodGet, a + "/" + other, "", map[string]int{"": 200, authz.RoleEndUser: 404}},
		{http.MethodGet, a + "/" + mine, "", all(200)},
		{http.MethodGet, a + "/" + tagged, "", map[string]int{"": 200, authz.RoleEndUser: 404}},
		{http.MethodGet, a + "/" + ofB, "", all(404)},                                     // B's device through A's path
		{http.MethodGet, a + "/" + uuid.NewString(), "", all(404)},                        // unknown
		{http.MethodGet, "/tenants/" + w.B.ID.String() + "/devices/" + ofB, "", all(404)}, // B's path: not a member
		// rename (✔ TO TA TP, — TV, ○ EU)
		{http.MethodPatch, a + "/" + other, `{"given_name":"renamed-other"}`,
			map[string]int{"": 200, authz.RoleTenantViewer: 403, authz.RoleEndUser: 404}},
		{http.MethodPatch, a + "/" + mine, `{"given_name":"my-laptop"}`, map[string]int{"": 200, authz.RoleTenantViewer: 403}},
		{http.MethodPatch, a + "/" + mine, `{"given_name":"Not_A_Label"}`, map[string]int{"": 422, authz.RoleTenantViewer: 403}},
		{http.MethodPatch, a + "/" + tagged, `{"given_name":"x1"}`, map[string]int{"": 200, authz.RoleTenantViewer: 403, authz.RoleEndUser: 404}},
		// expire (✔ TO TA TP, — TV, ○ EU) — the first grant starts it, the next ones get the same pending revocation
		{http.MethodPost, a + "/" + other + "/expire", "", map[string]int{"": 202, authz.RoleTenantViewer: 403, authz.RoleEndUser: 404}},
		{http.MethodPost, a + "/" + mine + "/expire", "", map[string]int{"": 202, authz.RoleTenantViewer: 403}},
		{http.MethodPost, a + "/" + ofB + "/expire", "", map[string]int{"": 404, authz.RoleTenantViewer: 403}},
		// delete (✔ TO TA, — TP TV, ○ EU): another kind pending ⇒ 409 after the checks of authorization and ownership
		{http.MethodDelete, a + "/" + other, "",
			map[string]int{"": 409, authz.RoleTenantOperator: 403, authz.RoleTenantViewer: 403, authz.RoleEndUser: 404}},
		{http.MethodDelete, a + "/" + tagged, "",
			map[string]int{"": 202, authz.RoleTenantOperator: 403, authz.RoleTenantViewer: 403, authz.RoleEndUser: 404}},
		// sync (✔ TO TA TP, — TV EU)
		{http.MethodPost, a + "/sync", "", map[string]int{"": 202, authz.RoleTenantViewer: 403, authz.RoleEndUser: 403}},
	}
	for _, role := range roles {
		s := w.Login(t, w.Actor(t, role, w.A))
		for _, c := range checks {
			want, ok := c.want[role]
			if !ok {
				want = c.want[""]
			}
			if rec := e.do(t, s, c.method, c.path, c.body); rec.Code != want {
				t.Errorf("%s %s %s: HTTP %d %s, want %d", role, c.method, c.path, rec.Code, rec.Body.String(), want)
			}
		}
	}
	// The End User deletes her second device; she lists only her own untagged devices.
	sEU := w.Login(t, eu)
	if rec := e.do(t, sEU, http.MethodDelete, a+"/"+mine2, ""); rec.Code != http.StatusAccepted || rec.Header().Get("Location") == "" {
		t.Fatalf("EU deletes her device: %d %s", rec.Code, rec.Body.String())
	}
	var list gen.DeviceList
	rec := e.do(t, sEU, http.MethodGet, a, "")
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &list) != nil || len(list.Items) != 2 {
		t.Fatalf("EU list: %d %s", rec.Code, rec.Body.String())
	}
	for _, d := range list.Items {
		if (d.Id.String() != mine && d.Id.String() != mine2) || d.Owner == nil || d.Owner.MembershipId != eu.MembershipID {
			t.Errorf("EU sees %s (owner %+v)", d.Id, d.Owner)
		}
	}
	if rec := e.do(t, sEU, http.MethodGet, a+"?owner="+ta.MembershipID.String(), ""); json.Unmarshal(rec.Body.Bytes(), &list) != nil ||
		len(list.Items) != 0 {
		t.Errorf("EU filtering on another member: %s", rec.Body.String())
	}
	// AC-04: the backend manages both tenants through the adapter — each tenant's admin lists its own devices after a
	// bounded sync of its own instance (fresh=true), and nothing of the other tenant.
	for ten, want := range map[*sessionfixture.Tenant][]string{w.A: {other, mine, mine2, tagged}, w.B: {ofB}} {
		s := w.Login(t, w.Actor(t, authz.RoleTenantAdmin, ten))
		rec := e.do(t, s, http.MethodGet, "/tenants/"+ten.ID.String()+"/devices?fresh=true", "")
		var l gen.DeviceList
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &l) != nil || len(l.Items) != len(want) {
			t.Fatalf("AC-04: admin of %s lists %d devices: %d %s", ten.Name, len(want), rec.Code, rec.Body.String())
		}
		got := map[string]bool{}
		for _, d := range l.Items {
			got[d.Id.String()] = !d.SyncedAt.IsZero()
		}
		for _, id := range want {
			if !got[id] {
				t.Errorf("AC-04: %s does not list %s with its synced_at (%v)", ten.Name, id, got)
			}
		}
	}
	// Platform staff without a Support Access Grant: 403 on every tenant device route (AC-05a).
	sSA := w.Login(t, w.Actor(t, authz.RoleSuperAdmin, nil))
	if rec := e.do(t, sSA, http.MethodGet, a, ""); rec.Code != http.StatusForbidden {
		t.Errorf("super admin on a tenant route: %d", rec.Code)
	}
	// B's End User probing A: 404 everywhere, and A's register is untouched.
	sB := w.Login(t, euB)
	for _, p := range []string{a, a + "/" + mine} {
		if rec := e.do(t, sB, http.MethodGet, p, ""); rec.Code != http.StatusNotFound {
			t.Errorf("EU of B on %s: %d", p, rec.Code)
		}
	}

	// The worker applies the revocations (two-phase: pending → applied only after the read-back).
	workerStore := pg.OpenStore(t, w.DB, "mg_worker_tenant", "mg_worker_platform", 6)
	wrkSvc, err := devices.New(workerStore, devices.Config{Registry: reg})
	if err != nil {
		t.Fatal(err)
	}
	cfg := jobs.DefaultConfig()
	cfg.FetchCooldown, cfg.FetchPollInterval = 10*time.Millisecond, 50*time.Millisecond
	cfg.RetryBase, cfg.RetryMax, cfg.StartJitter, cfg.SoftStopTimeout, cfg.QueuePoolConns = 50*time.Millisecond, 200*time.Millisecond, 0, 2*time.Second, 4
	worker, err := jobs.NewWorker(workerStore, cfg, jobs.Options{Alerter: wrkSvc, Registerer: prometheus.NewRegistry()})
	if err != nil {
		t.Fatal(err)
	}
	if err := wrkSvc.Register(worker); err != nil {
		t.Fatal(err)
	}
	if err := worker.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = worker.Stop(c)
	})
	state := func(id string) string {
		var s string
		w.Scan(t, `SELECT revocation_state FROM device_inventory_cache WHERE id = $1`, []any{id}, &s)
		return s
	}
	deadline := time.Now().Add(30 * time.Second)
	for state(other) != devices.StateApplied || state(mine) != devices.StateApplied || state(mine2) != devices.StateApplied ||
		state(tagged) != devices.StateApplied {
		if time.Now().After(deadline) {
			t.Fatalf("revocations not applied: other %s, mine %s, mine2 %s, tagged %s", state(other), state(mine), state(mine2), state(tagged))
		}
		time.Sleep(50 * time.Millisecond)
	}
	var got gen.Device
	if rec := e.do(t, sEU, http.MethodGet, a+"/"+mine, ""); rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &got) != nil ||
		got.Revocation.State != gen.DeviceRevocationStateApplied || got.Revocation.VerifiedAt == nil || got.Expiry == nil ||
		got.Expiry.After(time.Now()) {
		t.Errorf("EU's expired device: %d %s", rec.Code, rec.Body.String())
	}
	if rec := e.do(t, sEU, http.MethodGet, a+"/"+mine2, ""); rec.Code != http.StatusNotFound {
		t.Errorf("deleted device: %d", rec.Code)
	}
	if _, ok := fakes[w.A].Node(3); ok {
		t.Error("node 3 still exists on the instance after the delete")
	}

	// Audit: every operation pair closed, the actor kept, the End User's refusal on someone else's device recorded
	// with the authorization reason; B's audit holds nothing of A.
	n := func(sql string, args ...any) int {
		var v int
		w.Scan(t, sql, args, &v)
		return v
	}
	// Operations closed by a background job (inventory.sync enqueued by the POST /sync rows of the matrix above) may still
	// be running when the revocations are applied: the property is "every pair is eventually closed", so wait (bounded) —
	// an operation that never closes still fails the test. (CI run 44031823265 hit this race on a slower runner.)
	openOps := func() int {
		return n(`SELECT count(*) FROM audit_events r WHERE r.action LIKE '%.requested' AND NOT EXISTS
			(SELECT 1 FROM audit_events o WHERE o.operation_id = r.operation_id AND (o.action LIKE '%.succeeded' OR o.action LIKE '%.failed'))`)
	}
	deadline = time.Now().Add(30 * time.Second)
	for open := openOps(); open != 0; open = openOps() {
		if time.Now().After(deadline) {
			t.Errorf("%d audit operations left open after 30 s", open)
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if v := n(`SELECT count(*) FROM audit_events WHERE action = 'device.delete.succeeded' AND resource_id = $1 AND actor_identity_id = $2
			AND tenant_id = $3`, mine2, eu.IdentityID, w.A.ID); v != 1 {
		t.Errorf("device.delete.succeeded of the End User: %d", v)
	}
	if v := n(`SELECT count(*) FROM audit_events WHERE outcome = 'denied' AND actor_identity_id = $1 AND resource_id = $2
			AND details ->> 'reason' = 'not_own_resource'`, eu.IdentityID, other); v < 3 {
		t.Errorf("denials of the End User on another member's device: %d, want ≥ 3 (read, rename, expire, delete)", v)
	}
	// B's End User probing A: the denials are B's (the actor's tenant) with A as target, never in A's audit (§6.1).
	if v := n(`SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND resource_type = 'device'
			AND NOT (outcome = 'denied' AND target_tenant_id = $2)`, w.B.ID, w.A.ID); v != 0 {
		t.Errorf("tenant B's audit has %d device events other than its member's denials on A", v)
	}
	if v := n(`SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND actor_identity_id = $2`, w.A.ID, euB.IdentityID); v != 0 {
		t.Errorf("tenant A's audit shows %d events of B's End User", v)
	}
	if v := n(`SELECT count(*) FROM audit_events WHERE outcome = 'success' AND action = 'device.rename.succeeded' AND resource_id = $1`, other); v != 3 {
		t.Errorf("renames of the Admin's device: %d, want 3 (TO, TA, TP)", v)
	}
}

func tp(t time.Time) *time.Time { return &t }
