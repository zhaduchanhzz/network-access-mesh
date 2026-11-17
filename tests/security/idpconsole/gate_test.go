//go:build mgtestfixture

// Package idpconsole_test is the PostgreSQL test of the Keycloak console session of P3-T15 (§8.2 (3)) through the
// composed API of the api process: the 2P request (POST /platform/idp-console/sessions), its approval by a second Super
// Admin (POST /platform/approvals/{id}/approve), the list (GET /platform/idp-console/sessions) and the gate the edge
// calls as forward_auth (GET /internal/edge/idp-console) — real sessions (sessionfixture), the real authorizer,
// approvals service, console grants and audit Logger.
package idpconsole_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/authz"
	"github.com/zhaduchanhzz/network-access-mesh/internal/authz/approvals"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/approvalsapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/auditapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/idpconsoleapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/idp/console"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/storetest"
	"github.com/zhaduchanhzz/network-access-mesh/tests/security/sessionfixture"
)

func TestMain(m *testing.M) {
	code := m.Run()
	storetest.Cleanup()
	os.Exit(code)
}

// clock is the gate's clock (moved past the end of a session).
type clock struct {
	mu sync.Mutex
	at time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.at.IsZero() {
		return time.Now()
	}
	return c.at
}

func (c *clock) set(t time.Time) { c.mu.Lock(); c.at = t; c.mu.Unlock() }

const client = "192.0.2.10" // the address of the console's browser (httptest's peer = the client: no trusted proxy)

func world(t *testing.T) (*sessionfixture.World, *clock) {
	t.Helper()
	clk := &clock{}
	w := sessionfixture.New(t, sessionfixture.Options{Mount: func(w *sessionfixture.World) sessionfixture.Mount {
		logger, err := audit.New(w.Store, storetest.Require(t).OpenAuditWriter(t, w.DB), audit.Config{})
		if err != nil {
			t.Fatal(err)
		}
		authorizer := authz.New(w.Store)
		actions, err := approvals.NewRegistry(approvals.Typed(approvals.Spec{Name: console.Action, Scope: authz.ScopePlatform,
			ResourceType: console.ResourceType, Permission: console.Permission},
			func(context.Context, *store.Tx, approvals.Execution, console.Payload) (*uuid.UUID, error) {
				return nil, nil
			}))
		if err != nil {
			t.Fatal(err)
		}
		appr, err := approvals.New(w.Store, approvals.Config{Approvers: authorizer, Registry: actions, Security: logger})
		if err != nil {
			t.Fatal(err)
		}
		gate := idpconsoleapi.NewGate(idpconsoleapi.GateConfig{Grants: console.NewStore(w.Store), Authz: authorizer,
			Audit: logger, Now: clk.now})
		return sessionfixture.Mount{
			Handlers: httpapi.Handlers{Approvals: approvalsapi.New(appr), IdPConsole: idpconsoleapi.New(appr)},
			Audit:    auditapi.Middleware(logger),
			Internal: map[string]http.Handler{"GET " + idpconsoleapi.GatePath: gate},
		}
	}})
	return w, clk
}

// gate sends what the edge's forward_auth sends for a console request of s from addr.
func gate(w *sessionfixture.World, s *sessionfixture.Session, addr, method, uri string) *httptest.ResponseRecorder {
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "https://"+s.Host+idpconsoleapi.GatePath, nil)
	s.Apply(r)
	r.RemoteAddr = addr + ":40000"
	r.Header.Set("X-Forwarded-Method", method)
	r.Header.Set("X-Forwarded-Uri", uri)
	rec := httptest.NewRecorder()
	w.API.ServeHTTP(rec, r)
	return rec
}

// do sends an API request of s from addr.
func do(t *testing.T, w *sessionfixture.World, s *sessionfixture.Session, addr, method, path string, body any, hdr http.Header) *httptest.ResponseRecorder {
	t.Helper()
	var rd *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	var r *http.Request
	if rd != nil {
		r = s.Request(context.Background(), method, path, rd)
	} else {
		r = s.Request(context.Background(), method, path, nil)
	}
	r.RemoteAddr = addr + ":40001"
	for k, vs := range hdr {
		for _, v := range vs {
			r.Header.Add(k, v)
		}
	}
	rec := httptest.NewRecorder()
	w.API.ServeHTTP(rec, r)
	return rec
}

type approval struct {
	ID            uuid.UUID      `json:"id"`
	Status        string         `json:"status"`
	PayloadSHA256 string         `json:"payload_sha256"`
	Payload       map[string]any `json:"payload"`
}

func decode[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode %d %s: %v", rec.Code, rec.Body.String(), err)
	}
	return v
}

func key() http.Header { return http.Header{"Idempotency-Key": {"console-" + uuid.NewString()}} }

// TestConsoleSessionDualControl: request (202 + Location, Idempotency-Key replay), no self-approval, a second Super
// Admin approves; the gate lets the requester through from the bound address during the window only, refuses another
// address, another person, a person without platform.idp:console, no session, impersonation; the list shows it.
func TestConsoleSessionDualControl(t *testing.T) {
	w, clk := world(t)
	sa1 := w.Login(t, w.Actor(t, authz.RoleSuperAdmin, nil))
	sa2 := w.Login(t, w.NewActor(t, authz.RoleSuperAdmin, nil))
	po := w.Login(t, w.Actor(t, authz.RolePlatformOperator, nil))
	console1 := "/admin/master/console/"

	// before anything: no session ⇒ 401, Super Admin without an approved session ⇒ 403
	if rec := gate(w, w.Anonymous("admin"), client, "GET", console1); rec.Code != http.StatusUnauthorized {
		t.Errorf("anonymous: %d", rec.Code)
	}
	if rec := gate(w, sa1, client, "GET", console1); rec.Code != http.StatusForbidden {
		t.Errorf("no approval: %d", rec.Code)
	}
	// a Platform Operator cannot even ask (platform.idp:console is the Super Admin's only — §8.5)
	if rec := do(t, w, po, client, "POST", "/platform/idp-console/sessions", map[string]any{"reason": "x"}, key()); rec.Code != http.StatusForbidden {
		t.Errorf("PO request: %d %s", rec.Code, rec.Body.String())
	}
	k := key()
	rec := do(t, w, sa1, client, "POST", "/platform/idp-console/sessions", map[string]any{"reason": "ticket 42", "duration_minutes": 10}, k)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("request: %d %s", rec.Code, rec.Body.String())
	}
	req := decode[approval](t, rec)
	if rec.Header().Get("Location") != "/api/v1/platform/approvals/"+req.ID.String() || req.Status != "pending" ||
		req.Payload["source_cidr"] != client+"/32" || req.Payload["duration_minutes"] != float64(10) ||
		req.Payload["identity_id"] != sa1.Actor.IdentityID.String() {
		t.Fatalf("request: %s %s", rec.Header().Get("Location"), rec.Body.String())
	}
	replay := do(t, w, sa1, client, "POST", "/platform/idp-console/sessions", map[string]any{"reason": "ticket 42", "duration_minutes": 10}, k)
	if replay.Code != http.StatusAccepted || decode[approval](t, replay).ID != req.ID {
		t.Errorf("replay: %d %s", replay.Code, replay.Body.String())
	}
	reuse := do(t, w, sa1, client, "POST", "/platform/idp-console/sessions", map[string]any{"reason": "other", "duration_minutes": 10}, k)
	if reuse.Code != http.StatusUnprocessableEntity || !strings.Contains(reuse.Body.String(), "idempotency_key_reuse") {
		t.Errorf("key reuse: %d %s", reuse.Code, reuse.Body.String())
	}
	again := do(t, w, sa1, client, "POST", "/platform/idp-console/sessions", map[string]any{"reason": "again"}, key())
	if again.Code != http.StatusConflict {
		t.Errorf("second open request: %d %s", again.Code, again.Body.String())
	}
	for _, bad := range []map[string]any{{"reason": "x", "duration_minutes": 61}, {"reason": "x", "source_cidr": "0.0.0.0/0"},
		{"reason": "x", "source_cidr": "10.0.0.0/8"}, {"duration_minutes": 10}} {
		if rec := do(t, w, sa2, client, "POST", "/platform/idp-console/sessions", bad, key()); rec.Code != http.StatusUnprocessableEntity {
			t.Errorf("invalid %v: %d", bad, rec.Code)
		}
	}
	decision := map[string]any{"payload_sha256": req.PayloadSHA256}
	path := "/platform/approvals/" + req.ID.String()
	if rec := do(t, w, sa1, client, "POST", path+"/approve", decision, nil); rec.Code != http.StatusForbidden {
		t.Errorf("self approval: %d", rec.Code)
	}
	if rec := do(t, w, po, client, "POST", path+"/approve", decision, nil); rec.Code != http.StatusForbidden {
		t.Errorf("PO approval: %d %s", rec.Code, rec.Body.String())
	}
	if rec := gate(w, sa1, client, "GET", console1); rec.Code != http.StatusForbidden {
		t.Errorf("pending request opens the console: %d", rec.Code)
	}
	ok := do(t, w, sa2, client, "POST", path+"/approve", decision, nil)
	if ok.Code != http.StatusOK || decode[approval](t, ok).Status != "executed" {
		t.Fatalf("approve: %d %s", ok.Code, ok.Body.String())
	}
	for _, uri := range []string{console1, "/resources/abc/admin/keycloak.v2/assets/main.js",
		"/realms/master/protocol/openid-connect/token", "/admin/realms/tenant-a/users?first=0&max=20"} {
		if rec := gate(w, sa1, client, "GET", uri); rec.Code != http.StatusNoContent {
			t.Errorf("approved session, %s: %d %s", uri, rec.Code, rec.Body.String())
		}
	}
	if rec := gate(w, sa1, "192.0.2.11", "GET", console1); rec.Code != http.StatusForbidden {
		t.Errorf("another address: %d", rec.Code)
	}
	if rec := gate(w, sa2, client, "GET", console1); rec.Code != http.StatusForbidden {
		t.Errorf("the approver has no session of their own: %d", rec.Code)
	}
	if rec := gate(w, po, client, "GET", console1); rec.Code != http.StatusForbidden {
		t.Errorf("platform operator: %d", rec.Code)
	}
	if rec := gate(w, sa1.OnHost(w.AppHost), client, "GET", console1); rec.Code != http.StatusUnauthorized {
		t.Errorf("the admin session on the app host: %d", rec.Code)
	}
	imp := "/admin/realms/tenant-a/users/" + uuid.NewString() + "/impersonation"
	if rec := gate(w, sa1, client, "POST", imp); rec.Code != http.StatusForbidden {
		t.Errorf("impersonation: %d", rec.Code)
	}
	var n int
	w.Scan(t, `SELECT count(*) FROM security_events WHERE kind = $1 AND severity = 'critical' AND details ->> 'identity_id' = $2`,
		[]any{console.KindImpersonationAttempt, sa1.Actor.IdentityID.String()}, &n)
	if n != 1 {
		t.Errorf("impersonation security event: %d", n)
	}
	w.Scan(t, `SELECT count(*) FROM audit_events WHERE tenant_id IS NULL AND action = $1 AND outcome = 'success'
		AND actor_identity_id = $2 AND resource_id = $3`, []any{idpconsoleapi.ActionConsoleOpen, sa1.Actor.IdentityID,
		req.ID.String()}, &n)
	if n != 1 {
		t.Errorf("console opening audited %d times, want once", n)
	}
	var reasons []string
	for _, who := range []uuid.UUID{sa1.Actor.IdentityID, sa2.Actor.IdentityID, po.Actor.IdentityID} {
		var r string
		w.Scan(t, `SELECT string_agg(DISTINCT details ->> 'reason', ',' ORDER BY details ->> 'reason') FROM audit_events
			WHERE action = $1 AND outcome = 'denied' AND actor_identity_id = $2`, []any{idpconsoleapi.ActionConsoleAccess, who}, &r)
		reasons = append(reasons, r)
	}
	want := []string{"impersonation_refused,no_console_session,source_ip_not_allowed", "no_console_session", "not_allowed"}
	for i := range want {
		if reasons[i] != want[i] {
			t.Errorf("denial reasons of person %d: %q, want %q", i, reasons[i], want[i])
		}
	}
	// the list: SA1's session active
	list := do(t, w, po, client, "GET", "/platform/idp-console/sessions?limit=10", nil, nil)
	type item struct {
		ID         uuid.UUID `json:"id"`
		Status     string    `json:"status"`
		SourceCIDR string    `json:"source_cidr"`
		ApprovedBy *struct {
			IdentityID uuid.UUID `json:"identity_id"`
		} `json:"approved_by"`
	}
	items := decode[struct {
		Items []item `json:"items"`
	}](t, list).Items
	if list.Code != http.StatusOK || len(items) != 1 || items[0].ID != req.ID || items[0].Status != "active" ||
		items[0].SourceCIDR != client+"/32" || items[0].ApprovedBy == nil || items[0].ApprovedBy.IdentityID != sa2.Actor.IdentityID {
		t.Errorf("list: %d %s", list.Code, list.Body.String())
	}
	// past the window: refused, listed as ended
	clk.set(time.Now().Add(11 * time.Minute))
	if rec := gate(w, sa1, client, "GET", console1); rec.Code != http.StatusForbidden {
		t.Errorf("after the window: %d", rec.Code)
	}
}
