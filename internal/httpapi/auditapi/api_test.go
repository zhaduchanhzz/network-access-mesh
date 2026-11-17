package auditapi_test

// End-to-end test of the audit trail through the public API (P2-T08), on a real PostgreSQL migrated like a deployment
// (storetest): httpapi.New with the session layer of identity, the authorization of authz and the audit middleware in
// Hooks.Audit, the audit handlers, the identity adapter as identity.Auditor, and device handlers standing in for
// P2-T13 that write like real ones (paired operations, success event in a transaction that then fails).

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/authz"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/auditapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/authzhook"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/gen"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/identityapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/problem"
	"github.com/zhaduchanhzz/network-access-mesh/internal/identity"
	"github.com/zhaduchanhzz/network-access-mesh/internal/identity/identitytest"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/logx"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/storetest"
)

const (
	appHost   = "app.mg.test"
	adminHost = "admin.mg.test"
)

func TestMain(m *testing.M) {
	code := m.Run()
	storetest.Cleanup()
	os.Exit(code)
}

// browser keeps cookies per host, never follows redirects and knows its CSRF token once signed in.
type browser struct {
	t    *testing.T
	h    http.Handler
	host string
	jar  map[string]map[string]string
	csrf string
}

func (b *browser) do(method, rawURL string, hdr http.Header, body string) *httptest.ResponseRecorder {
	b.t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req := httptest.NewRequestWithContext(b.t.Context(), method, rawURL, rd)
	for k, vs := range hdr {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	for name, value := range b.jar[req.Host] {
		req.Header.Add("Cookie", name+"="+value)
	}
	rec := httptest.NewRecorder()
	b.h.ServeHTTP(rec, req)
	for _, line := range rec.Header().Values("Set-Cookie") {
		c, err := http.ParseSetCookie(line)
		if err != nil {
			b.t.Fatalf("bad Set-Cookie: %v", err)
		}
		if b.jar[req.Host] == nil {
			b.jar[req.Host] = map[string]string{}
		}
		if c.MaxAge < 0 {
			delete(b.jar[req.Host], c.Name)
		} else {
			b.jar[req.Host][c.Name] = c.Value
		}
	}
	return rec
}

func (b *browser) get(path string) *httptest.ResponseRecorder {
	return b.do(http.MethodGet, "https://"+b.host+"/api/v1"+path, nil, "")
}

// write sends an unsafe request the way the Portal does: CSRF token, same Origin, Idempotency-Key.
func (b *browser) write(method, path, body string) *httptest.ResponseRecorder {
	h := http.Header{"Origin": {"https://" + b.host}, identity.CSRFHeader: {b.csrf}, "Idempotency-Key": {uuid.NewString()}}
	if body != "" {
		h.Set("Content-Type", "application/json")
	}
	return b.do(method, "https://"+b.host+"/api/v1"+path, h, body)
}

// login runs GET /auth/login → fake IdP → callback, then reads the CSRF token.
func (b *browser) login(query string) {
	b.t.Helper()
	start := b.get("/auth/login?" + query)
	if start.Code != http.StatusFound {
		b.t.Fatalf("login start: HTTP %d %s", start.Code, start.Body.String())
	}
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, _ := http.NewRequestWithContext(b.t.Context(), http.MethodGet, start.Header().Get("Location"), nil)
	resp, err := c.Do(req)
	if err != nil {
		b.t.Fatalf("authorize: %v", err)
	}
	_ = resp.Body.Close()
	if cb := b.do(http.MethodGet, resp.Header.Get("Location"), nil, ""); cb.Code != http.StatusFound {
		b.t.Fatalf("callback: HTTP %d %s", cb.Code, cb.Body.String())
	}
	rec := b.get("/auth/session")
	var s gen.Session
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &s) != nil || s.CsrfToken == "" {
		b.t.Fatalf("GET /auth/session: HTTP %d %s", rec.Code, rec.Body.String())
	}
	b.csrf = s.CsrfToken
}

// list pages through an audit list with the given query (limit 2 to exercise the cursor) and returns every item.
func (b *browser) list(path string, query url.Values) []gen.AuditEvent {
	b.t.Helper()
	var all []gen.AuditEvent
	for range 100 {
		q := url.Values{"limit": {"2"}}
		for k, v := range query {
			q[k] = v
		}
		rec := b.get(path + "?" + q.Encode())
		var page gen.AuditEventList
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &page) != nil {
			b.t.Fatalf("GET %s: HTTP %d %s", path, rec.Code, rec.Body.String())
		}
		all = append(all, page.Items...)
		if page.NextCursor == nil {
			return all
		}
		query = cloneWith(query, "cursor", *page.NextCursor)
	}
	b.t.Fatalf("GET %s: pagination does not end", path)
	return nil
}

func cloneWith(v url.Values, k, val string) url.Values {
	out := url.Values{}
	for key, vals := range v {
		out[key] = slices.Clone(vals)
	}
	out.Set(k, val)
	return out
}

func problemOf(t *testing.T, what string, rec *httptest.ResponseRecorder, status int, code gen.ProblemCode) gen.Problem {
	t.Helper()
	var p gen.Problem
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil || rec.Code != status || p.Code != code {
		t.Fatalf("%s: HTTP %d %s, want %d %s", what, rec.Code, rec.Body.String(), status, code)
	}
	return p
}

// testDevices stands in for the device handlers of P2-T13 and writes the way they must.
type testDevices struct {
	httpapi.NotImplemented
	st *store.Store

	mu        sync.Mutex
	handedOff []audit.Operation
}

// SyncDevices: the operation is requested (committed before "Headscale"), then the instance rejects it ⇒ 502. The
// middleware has to close the pair with device.sync.failed.
func (d *testDevices) SyncDevices(ctx context.Context, req gen.SyncDevicesRequestObject) (gen.SyncDevicesResponseObject, error) {
	if err := d.st.WithTenantTx(ctx, req.TenantId, func(q *sqlcdb.Queries) error {
		_, err := audit.Requested(ctx, q, audit.Event{})
		return err
	}); err != nil {
		return nil, err
	}
	return nil, problem.New(gen.ProblemCodeUpstreamRejected, "The tenant instance rejected the request.")
}

// ExpireDevice: the operation is requested in the transaction that "enqueues the job" and handed off to it (202).
func (d *testDevices) ExpireDevice(ctx context.Context, req gen.ExpireDeviceRequestObject) (gen.ExpireDeviceResponseObject, error) {
	var op audit.Operation
	if err := d.st.WithTenantTx(ctx, req.TenantId, func(q *sqlcdb.Queries) error {
		var err error
		op, err = audit.Requested(ctx, q, audit.Event{Details: audit.Details{"kind": "expire"}})
		return err
	}); err != nil {
		return nil, err
	}
	audit.HandOff(ctx, op)
	d.mu.Lock()
	d.handedOff = append(d.handedOff, op)
	d.mu.Unlock()
	return gen.ExpireDevice202JSONResponse{Headers: gen.ExpireDevice202ResponseHeaders{
		Location: "/api/v1/tenants/" + req.TenantId.String() + "/jobs/" + uuid.NewString()}}, nil
}

// RenameDevice: writes its success event, then finds the device is not the caller's ⇒ 404 inside the same
// transaction, which rolls back: the success event is gone, the denied event of the middleware must remain.
func (d *testDevices) RenameDevice(ctx context.Context, req gen.RenameDeviceRequestObject) (gen.RenameDeviceResponseObject, error) {
	return nil, d.st.WithTenantTx(ctx, req.TenantId, func(q *sqlcdb.Queries) error {
		if err := audit.Record(ctx, q, audit.Event{Details: audit.Details{"given_name": req.Body.GivenName}}); err != nil {
			return err
		}
		return problem.New(gen.ProblemCodeNotFound, "The resource does not exist.")
	})
}

// TestAuditThroughTheAPI — the acceptance criteria of P2-T08 (§20) through the whole chain: a cross-tenant denial never
// appears in GET /tenants/{target}/audit (it is in the actor's tenant, and an abnormal chain raises a platform
// security event); the denied event remains after the business transaction rolled back; GET /platform/audit lists
// only platform events; the request/outcome pairing of the middleware; identity events; pagination through the API.
func TestAuditThroughTheAPI(t *testing.T) {
	env := storetest.Require(t)
	db := env.NewDatabase(t)
	su := env.Admin(t, db)
	st := env.OpenStore(t, db, "mg_api_tenant", "mg_api_platform", 10)
	reg := prometheus.NewRegistry()
	logger, err := audit.New(st, env.OpenAuditWriter(t, db), audit.Config{CrossTenantThreshold: 3, Registerer: reg})
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := su.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("fixture: %v\n%s", err, sql)
		}
	}
	count := func(sql string, args ...any) int64 {
		t.Helper()
		var n int64
		if err := su.QueryRow(ctx, sql, args...).Scan(&n); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
		return n
	}

	// Tenants A and B, each with its IdP; the platform IdP.
	a, b := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	exec(`INSERT INTO tenants (id, slug, name, status) VALUES ($1, 'tenant-a', 'Tenant A', 'active'), ($2, 'tenant-b', 'Tenant B', 'active')`, a, b)
	secrets := map[string]string{}
	idp := func(tenant *uuid.UUID, host, client string) (*identitytest.FakeIdP, uuid.UUID) {
		fake := identitytest.NewFakeIdP(t, time.Now)
		id := uuid.Must(uuid.NewV7())
		scope, owner := "platform", "platform"
		if tenant != nil {
			scope, owner = "tenant", tenant.String()
		}
		ref := "mgsec://" + owner + "/idp-client#1"
		exec(`INSERT INTO identity_providers (id, scope, tenant_id, issuer, client_id, client_secret_ref, driver, status)
			VALUES ($1, $2, $3, $4, $5, $6, 'external', 'active')`, id, scope, tenant, fake.Issuer, client, ref)
		secrets[ref] = "secret-" + uuid.NewString()
		fake.AddClient(client, secrets[ref], "https://"+host+"/api/v1/auth/callback/"+id.String())
		return fake, id
	}
	fakeA, idpA := idp(&a, appHost, "portal-a")
	fakeB, idpB := idp(&b, appHost, "portal-b")
	fakeP, idpP := idp(nil, adminHost, "console")

	svc, err := identity.New(st, identity.Config{
		AppHost: appHost, AdminHost: adminHost, HTTPClient: &http.Client{Timeout: 5 * time.Second},
		ClientSecrets: identity.ClientSecretFunc(func(_ context.Context, ref string) (string, error) {
			if s, ok := secrets[ref]; ok {
				return s, nil
			}
			return "", errors.New("unknown secret ref")
		}),
		Logger: slog.New(slog.DiscardHandler), RequestID: authzhook.RequestID, ClientIP: authzhook.ClientIP,
		Auditor: auditapi.IdentityAuditor(logger),
	})
	if err != nil {
		t.Fatal(err)
	}
	hooks := authzhook.Hooks(svc, authz.New(st))
	hooks.Audit = auditapi.Middleware(logger)
	devices := &testDevices{st: st}
	h, err := httpapi.New(httpapi.Options{
		Logger: logx.New(io.Discard, slog.LevelInfo, "api"), Hooks: hooks,
		Handlers: httpapi.Handlers{Auth: identityapi.New(svc), Audit: auditapi.New(audit.NewReader(st)), Devices: devices},
	})
	if err != nil {
		t.Fatal(err)
	}
	newBrowser := func(host string) *browser {
		return &browser{t: t, h: h, host: host, jar: map[string]map[string]string{}}
	}

	// 1. Alice (Tenant Admin of A), Bob (Tenant Admin of B), Pat (Platform Viewer) sign in.
	identityOf := func(idpID uuid.UUID, sub string) uuid.UUID {
		t.Helper()
		var id uuid.UUID
		if err := su.QueryRow(ctx, "SELECT id FROM identities WHERE idp_id = $1 AND subject = $2", idpID, sub).Scan(&id); err != nil {
			t.Fatalf("identity %s: %v", sub, err)
		}
		return id
	}
	alice, bob, pat := newBrowser(appHost), newBrowser(appHost), newBrowser(adminHost)
	fakeA.SetUser(identitytest.FakeUser{Sub: "alice", Email: "alice@a.test", EmailVerified: true, Name: "Alice"})
	fakeB.SetUser(identitytest.FakeUser{Sub: "bob", Email: "bob@b.test", EmailVerified: true, Name: "Bob"})
	fakeP.SetUser(identitytest.FakeUser{Sub: "pat", Email: "pat@ops.test", EmailVerified: true, Name: "Pat"})
	alice.login("scope=tenant&tenant=tenant-a")
	bob.login("scope=tenant&tenant=tenant-b")
	pat.login("scope=platform")
	aliceID, bobID, patID := identityOf(idpA, "alice"), identityOf(idpB, "bob"), identityOf(idpP, "pat")
	for tenant, who := range map[uuid.UUID]uuid.UUID{a: aliceID, b: bobID} {
		exec(`INSERT INTO tenant_memberships (tenant_id, identity_id, role_id, status)
			SELECT $1, $2, id, 'active' FROM roles WHERE scope = 'tenant' AND key = $3`, tenant, who, authz.RoleTenantAdmin)
	}
	exec(`INSERT INTO platform_users (identity_id, role_id) SELECT $1, id FROM roles WHERE scope = 'platform' AND key = $2`,
		patID, authz.RolePlatformViewer)

	// 2. Identity events land in the identity's own tenant (the platform for staff).
	if n := count(`SELECT count(*) FROM audit_events WHERE action = 'auth.login' AND outcome = 'success'
			AND ((actor_identity_id = $1 AND tenant_id = $3) OR (actor_identity_id = $2 AND tenant_id IS NULL))`, aliceID, patID, a); n != 2 {
		t.Errorf("login events of Alice (tenant A) and Pat (platform): %d, want 2", n)
	}

	// 3. Alice probes tenant B: three refusals (404, as for a missing tenant), recorded in A with target B.
	probe := []string{"/tenants/" + b.String() + "/audit", "/tenants/" + b.String() + "/devices",
		"/tenants/" + b.String() + "/devices/" + uuid.NewString()}
	var probeRequestID string
	for i, path := range probe {
		rec := alice.get(path)
		problemOf(t, "Alice on B "+path, rec, http.StatusNotFound, gen.ProblemCodeNotFound)
		if i == 0 {
			probeRequestID = rec.Header().Get("X-Request-Id")
		}
	}
	if n := count(`SELECT count(*) FROM audit_events WHERE actor_identity_id = $1 AND outcome = 'denied'
			AND tenant_id = $2 AND target_tenant_id = $3`, aliceID, a, b); n != 3 {
		t.Errorf("denials of Alice under A with target B: %d, want 3", n)
	}
	if n := count(`SELECT count(*) FROM audit_events WHERE request_id = $1 AND details ->> 'reason' = 'not_a_member'`,
		probeRequestID); n != 1 {
		t.Errorf("the denial does not carry the request id of the response (%s) and its authz reason", probeRequestID)
	}
	if n := count(`SELECT count(*) FROM security_events WHERE tenant_id IS NULL AND kind = $1 AND details ->> 'actor_identity_id' = $2`,
		audit.KindCrossTenantDenials, aliceID.String()); n != 1 {
		t.Errorf("security events for Alice's chain of 3 cross-tenant denials: %d, want 1", n)
	}
	// ... and the target tenant never sees them, nor who probed it.
	for _, e := range bob.list("/tenants/"+b.String()+"/audit", nil) {
		if e.Outcome == gen.AuditOutcomeDenied || e.Actor.IdentityId != nil && *e.Actor.IdentityId == aliceID {
			t.Errorf("tenant B's audit shows %s %s by %v", e.Action, e.Outcome, e.Actor.IdentityId)
		}
	}
	denied := alice.list("/tenants/"+a.String()+"/audit", url.Values{"outcome": {"denied"}})
	var actions []string
	for _, e := range denied {
		if e.Actor.IdentityId == nil || *e.Actor.IdentityId != aliceID || e.Actor.DisplayName == nil || *e.Actor.DisplayName != "Alice" {
			t.Errorf("denied event %s: actor %+v", e.Action, e.Actor)
		}
		actions = append(actions, e.Action)
	}
	slices.Sort(actions)
	if want := []string{"audit.list", "device.list", "device.read"}; !slices.Equal(actions, want) {
		t.Errorf("tenant A's denied events: %v, want %v", actions, want)
	}

	// 4. Pat, platform staff without a support grant, on a tenant route: 403, a platform event, not in A's audit.
	problemOf(t, "Pat on A", pat.get("/tenants/"+a.String()+"/devices"), http.StatusForbidden, gen.ProblemCodeForbidden)
	platform := pat.list("/platform/audit", nil)
	var sawPatDenial bool
	for _, e := range platform {
		var tenant *uuid.UUID
		if err := su.QueryRow(ctx, "SELECT tenant_id FROM audit_events WHERE id = $1", e.Id).Scan(&tenant); err != nil || tenant != nil {
			t.Errorf("GET /platform/audit returned %s (%s) of tenant %v (%v)", e.Id, e.Action, tenant, err)
		}
		sawPatDenial = sawPatDenial || e.Action == "device.list" && e.Outcome == gen.AuditOutcomeDenied
	}
	if want := count("SELECT count(*) FROM audit_events WHERE tenant_id IS NULL"); int64(len(platform)) != want || !sawPatDenial {
		t.Errorf("GET /platform/audit: %d events (Pat's denial %v), want the %d platform events", len(platform), sawPatDenial, want)
	}
	for _, e := range alice.list("/tenants/"+a.String()+"/audit", nil) {
		if e.Actor.IdentityId != nil && *e.Actor.IdentityId == patID {
			t.Errorf("tenant A's audit shows Pat's %s", e.Action)
		}
	}

	// 5. Pairing through the middleware.
	problemOf(t, "sync", alice.write(http.MethodPost, "/tenants/"+a.String()+"/devices/sync", ""), http.StatusBadGateway,
		gen.ProblemCodeUpstreamRejected)
	var syncOp *uuid.UUID
	if err := su.QueryRow(ctx, "SELECT operation_id FROM audit_events WHERE action = 'device.sync.requested'").Scan(&syncOp); err != nil {
		t.Fatal(err)
	}
	if n := count(`SELECT count(*) FROM audit_events WHERE operation_id = $1 AND action = 'device.sync.failed'
			AND outcome = 'failure' AND tenant_id = $2 AND details ->> 'reason' = 'upstream_rejected'`, syncOp, a); n != 1 {
		t.Errorf("device.sync.failed of operation %v: %d, want 1", syncOp, n)
	}
	device := uuid.NewString()
	if rec := alice.write(http.MethodPost, "/tenants/"+a.String()+"/devices/"+device+"/expire", ""); rec.Code != http.StatusAccepted {
		t.Fatalf("expire: HTTP %d %s", rec.Code, rec.Body.String())
	}
	open, err := logger.OpenOperations(ctx, &a, 0, 10)
	if err != nil || len(open) != 1 || open[0].Action != "device.expire" || open[0].ResourceID != device {
		t.Fatalf("open operations after the hand-off: %+v %v", open, err)
	}
	devices.mu.Lock()
	op := devices.handedOff[0]
	devices.mu.Unlock()
	if err := st.WithTenantTx(ctx, a, func(q *sqlcdb.Queries) error { return op.Succeeded(ctx, q, nil) }); err != nil {
		t.Fatal(err) // "the job" finishes the pair
	}
	if open, err := logger.OpenOperations(ctx, &a, 0, 10); err != nil || len(open) != 0 {
		t.Errorf("open operations after the job: %+v %v", open, err)
	}
	if n := count("SELECT count(*) FROM audit_events WHERE operation_id = $1 AND actor_identity_id = $2 AND resource_id = $3",
		op.ID, aliceID, device); n != 2 {
		t.Errorf("pair of the handed-off operation: %d events, want 2 (actor and resource kept)", n)
	}

	// 6. The denied event remains after the business transaction rolled back (its success event did not).
	problemOf(t, "rename", alice.write(http.MethodPatch, "/tenants/"+a.String()+"/devices/"+device, `{"given_name":"laptop-2"}`),
		http.StatusNotFound, gen.ProblemCodeNotFound)
	if n := count("SELECT count(*) FROM audit_events WHERE action = 'device.rename' AND outcome = 'success'"); n != 0 {
		t.Errorf("%d success events of the rolled-back rename", n)
	}
	if n := count(`SELECT count(*) FROM audit_events WHERE action = 'device.rename' AND outcome = 'denied' AND tenant_id = $1
			AND target_tenant_id IS NULL AND resource_id = $2 AND actor_identity_id = $3`, a, device, aliceID); n != 1 {
		t.Errorf("denied event of the rolled-back rename: %d, want 1", n)
	}

	// 7. Pagination through the API: every event of A exactly once, newest first; misuse is 422 naming the parameter.
	all := alice.list("/tenants/"+a.String()+"/audit", nil)
	if want := count("SELECT count(*) FROM audit_events WHERE tenant_id = $1", a); int64(len(all)) != want {
		t.Errorf("paged %d events of A, want %d", len(all), want)
	}
	seen := map[uuid.UUID]bool{}
	for i, e := range all {
		if seen[e.Id] || i > 0 && e.OccurredAt.After(all[i-1].OccurredAt) {
			t.Errorf("event %d (%s): duplicate or out of order", i, e.Id)
		}
		seen[e.Id] = true
	}
	first := alice.get("/tenants/" + a.String() + "/audit?limit=1")
	var page gen.AuditEventList
	if err := json.Unmarshal(first.Body.Bytes(), &page); err != nil || page.NextCursor == nil {
		t.Fatalf("first page: %v %s", err, first.Body.String())
	}
	for what, path := range map[string]string{
		"cursor": "/tenants/" + a.String() + "/audit?outcome=denied&cursor=" + url.QueryEscape(*page.NextCursor),
		"limit":  "/tenants/" + a.String() + "/audit?limit=0",
	} {
		p := problemOf(t, what, alice.get(path), http.StatusUnprocessableEntity, gen.ProblemCodeValidationFailed)
		if p.Errors == nil || len(*p.Errors) != 1 || (*p.Errors)[0].Field != what {
			t.Errorf("%s: errors %+v", what, p.Errors)
		}
	}

	// No request left the trail incomplete.
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range mfs {
		if mf.GetName() == "meshguard_audit_gaps_total" || mf.GetName() == "meshguard_audit_write_failures_total" {
			for _, m := range mf.GetMetric() {
				if m.GetCounter().GetValue() != 0 {
					t.Errorf("%s %v = %v", mf.GetName(), m.GetLabel(), m.GetCounter().GetValue())
				}
			}
		}
	}
}
