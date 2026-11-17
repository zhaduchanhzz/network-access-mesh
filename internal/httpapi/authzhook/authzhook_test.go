package authzhook

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/authz"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/gen"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/problem"
	"github.com/zhaduchanhzz/network-access-mesh/internal/identity"
)

// TestPrincipalValues: PrincipalOf converts by value — the scopes and origins of identity and authz must stay the
// same strings.
func TestPrincipalValues(t *testing.T) {
	pairs := [][2]string{
		{string(identity.ScopeTenant), string(authz.ScopeTenant)},
		{string(identity.ScopePlatform), string(authz.ScopePlatform)},
		{string(identity.OriginApp), string(authz.OriginApp)},
		{string(identity.OriginAdmin), string(authz.OriginAdmin)},
	}
	for _, p := range pairs {
		if p[0] != p[1] {
			t.Errorf("identity %q ≠ authz %q", p[0], p[1])
		}
	}
	id := uuid.New()
	got := PrincipalOf(&identity.Session{IdentityID: id, Scope: identity.ScopePlatform, Origin: identity.OriginAdmin})
	if got != (authz.Principal{IdentityID: id, Scope: authz.ScopePlatform, Origin: authz.OriginAdmin}) {
		t.Fatalf("PrincipalOf = %+v", got)
	}
}

type call struct {
	operation string
	tenant    uuid.UUID
}

// fakeAuthorizer records the calls and answers with decide.
type fakeAuthorizer struct {
	mu     sync.Mutex
	calls  []call
	decide func(operation string) (authz.Decision, error)
}

func (f *fakeAuthorizer) RequireOperation(_ context.Context, operation string, tenantID uuid.UUID) (authz.Decision, error) {
	f.mu.Lock()
	f.calls = append(f.calls, call{operation, tenantID})
	f.mu.Unlock()
	return f.decide(operation)
}

func (f *fakeAuthorizer) last() call {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.calls) == 0 {
		return call{}
	}
	return f.calls[len(f.calls)-1]
}

// devices implements GetDevice only: it reports the decision it sees (never blocking — a broken hook must fail the
// test, not hang it) and answers a 409 problem (any non-501 answer proves that the handler ran).
type devices struct {
	httpapi.NotImplemented
	seen chan authz.Decision
}

func (d devices) GetDevice(ctx context.Context, _ gen.GetDeviceRequestObject) (gen.GetDeviceResponseObject, error) {
	dec, _ := DecisionFrom(ctx)
	select {
	case d.seen <- dec:
	default:
	}
	return nil, problem.New(gen.ProblemCodeConflict, "handler ran")
}

func serve(t *testing.T, h http.Handler, method, path string) (*httptest.ResponseRecorder, gen.Problem) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), method, path, nil))
	var p gen.Problem
	if rec.Body.Len() > 0 {
		if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
			t.Fatalf("%s %s: body is not a problem: %v\n%s", method, path, err, rec.Body.String())
		}
	}
	return rec, p
}

// TestAuthzHook — the hook passes the Go operation name and the {tenantId} of the path, refuses with the problem of
// §13.1 before any handler runs (generic detail, never the denial reason), and hands a granted request's decision
// to the handler.
func TestAuthzHook(t *testing.T) {
	var denyWith error
	fa := &fakeAuthorizer{decide: func(string) (authz.Decision, error) {
		if denyWith != nil {
			return authz.Decision{}, denyWith
		}
		return authz.Decision{Permission: "tenant.device:read", OwnOnly: true}, nil
	}}
	dev := devices{seen: make(chan authz.Decision, 1)}
	h, err := httpapi.New(httpapi.Options{
		Logger: slog.New(slog.DiscardHandler), Handlers: httpapi.Handlers{Devices: dev},
		Hooks: httpapi.Hooks{Authz: Authz(fa), Session: func(next http.Handler) http.Handler { return next },
			Audit: func(f gen.StrictHandlerFunc, _ string) gen.StrictHandlerFunc { return f }},
	})
	if err != nil {
		t.Fatal(err)
	}
	tenant, device := uuid.New(), uuid.New()
	getDevice := "/api/v1/tenants/" + tenant.String() + "/devices/" + device.String()

	// granted: the handler runs and sees the decision
	rec, p := serve(t, h, http.MethodGet, getDevice)
	if rec.Code != http.StatusConflict || p.Code != gen.ProblemCodeConflict {
		t.Fatalf("granted GetDevice: HTTP %d %+v", rec.Code, p)
	}
	if d := <-dev.seen; !d.OwnOnly || d.Permission != "tenant.device:read" {
		t.Errorf("decision seen by the handler: %+v", d)
	}
	if c := fa.last(); c.operation != "GetDevice" || c.tenant != tenant {
		t.Errorf("authorizer called with %+v, want GetDevice in tenant %s", c, tenant)
	}

	// granted but not implemented: 501
	rec, p = serve(t, h, http.MethodGet, "/api/v1/tenants/"+tenant.String()+"/jobs")
	if rec.Code != http.StatusNotImplemented || p.Code != gen.ProblemCodeNotImplemented {
		t.Errorf("ListTenantJobs: HTTP %d %+v", rec.Code, p)
	}
	// platform operation: no tenant in the path
	serve(t, h, http.MethodGet, "/api/v1/platform/jobs")
	if c := fa.last(); c.operation != "ListPlatformJobs" || c.tenant != uuid.Nil {
		t.Errorf("authorizer called with %+v, want ListPlatformJobs without tenant", c)
	}

	// refused: problem of §13.1, handler not run, reason not sent
	for _, tc := range []struct {
		err    error
		status int
		code   gen.ProblemCode
	}{
		{&authz.Denial{Kind: authz.ErrUnauthenticated, Reason: "no_principal"}, 401, gen.ProblemCodeUnauthenticated},
		{&authz.Denial{Kind: authz.ErrNotFound, Reason: "not_a_member"}, 404, gen.ProblemCodeNotFound},
		{&authz.Denial{Kind: authz.ErrForbidden, Reason: "no_grant"}, 403, gen.ProblemCodeForbidden},
		{&authz.Denial{Kind: authz.ErrTenantSuspended, Reason: "tenant_suspended"}, 403, gen.ProblemCodeTenantSuspended},
		{errors.New("authz: load tenant access: connection refused"), 500, gen.ProblemCodeInternalError},
	} {
		denyWith = tc.err
		rec, p := serve(t, h, http.MethodGet, getDevice)
		if rec.Code != tc.status || p.Code != tc.code || p.Status != tc.status {
			t.Errorf("%v: HTTP %d %+v, want %d %s", tc.err, rec.Code, p, tc.status, tc.code)
		}
		if body := rec.Body.String(); strings.Contains(body, "no_grant") || strings.Contains(body, "not_a_member") ||
			strings.Contains(body, "connection refused") || strings.Contains(body, "no_principal") {
			t.Errorf("%v: the problem leaks the internal reason: %s", tc.err, body)
		}
		select {
		case d := <-dev.seen:
			t.Errorf("%v: the handler ran (decision %+v)", tc.err, d)
		default:
		}
	}
	// the 404 of a non-member reads exactly like the 404 of a missing resource (§8.4 invariant 6)
	denyWith = &authz.Denial{Kind: authz.ErrNotFound, Reason: "not_a_member"}
	_, a := serve(t, h, http.MethodGet, getDevice)
	denyWith = &authz.Denial{Kind: authz.ErrNotFound, Reason: "no_tenant"}
	_, b := serve(t, h, http.MethodGet, getDevice)
	if a.Title != b.Title || *a.Detail != *b.Detail || a.Type != b.Type {
		t.Errorf("two 404 refusals differ: %+v vs %+v", a, b)
	}
}

// TestNoHandlersWithoutAuthz — deny by default is httpapi's: the hooks of this package are what makes mounting legal.
func TestNoHandlersWithoutAuthz(t *testing.T) {
	_, err := httpapi.New(httpapi.Options{Logger: slog.New(slog.DiscardHandler),
		Handlers: httpapi.Handlers{Devices: devices{}}})
	if err == nil {
		t.Fatal("httpapi.New accepted handlers without an Authz hook")
	}
	hooks := Hooks(nil, &fakeAuthorizer{})
	if hooks.Authz == nil || hooks.Session == nil || hooks.CSRF != nil {
		t.Fatalf("Hooks: Authz %v, Session %v, CSRF %v — want Authz and Session, CSRF in the session layer",
			hooks.Authz != nil, hooks.Session != nil, hooks.CSRF != nil)
	}
}

// TestClientIPAndRequestID — outside the chain the helpers fall back to the peer address and an empty id.
func TestClientIPAndRequestID(t *testing.T) {
	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	r.RemoteAddr = "192.0.2.7:4321"
	if got := ClientIP(r); got != "192.0.2.7" {
		t.Errorf("ClientIP = %q", got)
	}
	if got := RequestID(r); got != "" {
		t.Errorf("RequestID = %q", got)
	}
}
