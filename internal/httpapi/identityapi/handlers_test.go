package identityapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/gen"
	"github.com/zhaduchanhzz/network-access-mesh/internal/identity"
)

// TestCallbackRedirectSetsTwoCookies — the generated AuthCallback302Response can only carry one Set-Cookie; the
// handler's own response type sets the session cookie and deletes the binding cookie.
func TestCallbackRedirectSetsTwoCookies(t *testing.T) {
	rec := httptest.NewRecorder()
	r := redirectResponse{location: "/devices", cookies: []*http.Cookie{
		identity.SessionCookie("s"), identity.ExpiredCookie(identity.AuthRequestCookieName),
	}}
	var obj gen.AuthCallbackResponseObject = r
	if err := obj.VisitAuthCallbackResponse(rec); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/devices" {
		t.Fatalf("HTTP %d Location %q", rec.Code, rec.Header().Get("Location"))
	}
	cookies := rec.Header().Values("Set-Cookie")
	if len(cookies) != 2 || !strings.HasPrefix(cookies[0], identity.SessionCookieName+"=s;") ||
		!strings.HasPrefix(cookies[1], identity.AuthRequestCookieName+"=;") || !strings.Contains(cookies[1], "Max-Age=0") {
		t.Fatalf("Set-Cookie %q", cookies)
	}
	if rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Fatal("cache/referrer headers")
	}
}

func TestProblemResponse(t *testing.T) {
	rec := httptest.NewRecorder()
	p := problemFor(identity.ErrReauthRequired, identity.RequestInfo{RequestID: "r-1", Path: "/api/v1/auth/session"},
		identity.ExpiredCookie(identity.AuthRequestCookieName))
	var obj gen.GetAuthSessionResponseObject = p
	if err := obj.VisitGetAuthSessionResponse(rec); err != nil {
		t.Fatal(err)
	}
	var body gen.Problem
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if rec.Code != 401 || body.Code != "reauth_required" || body.RequestId != "r-1" || body.Instance == nil ||
		*body.Instance != "/api/v1/auth/session" || rec.Header().Get("Content-Type") != "application/problem+json" ||
		rec.Header().Get("X-Request-Id") != "r-1" || len(rec.Header().Values("Set-Cookie")) != 1 {
		t.Fatalf("HTTP %d %+v %v", rec.Code, body, rec.Header())
	}
}

func TestLogoutDeletesTheSessionCookie(t *testing.T) {
	rec := httptest.NewRecorder()
	if err := (logoutResponse{}).VisitAuthLogoutResponse(rec); err != nil {
		t.Fatal(err)
	}
	c, err := http.ParseSetCookie(rec.Header().Get("Set-Cookie"))
	if err != nil || rec.Code != http.StatusNoContent || c.Name != identity.SessionCookieName || c.MaxAge >= 0 {
		t.Fatalf("HTTP %d cookie %+v %v", rec.Code, c, err)
	}
}

// TestHandlersRequireTheMiddleware — without identity.Service.Middleware in the chain every operation answers 500
// (fail closed) instead of acting without an origin or a session.
func TestHandlersRequireTheMiddleware(t *testing.T) {
	h := New(nil)
	ctx := context.Background()
	check := func(name string, resp any, err error) {
		t.Helper()
		p, ok := resp.(problemResponse)
		if err != nil || !ok || p.problem.Status != 500 || p.problem.Code != "internal_error" {
			t.Errorf("%s: %#v %v", name, resp, err)
		}
	}
	r1, err := h.AuthLogin(ctx, gen.AuthLoginRequestObject{Params: gen.AuthLoginParams{Scope: "tenant"}})
	check("login", r1, err)
	r2, err := h.AuthCallback(ctx, gen.AuthCallbackRequestObject{IdpId: uuid.New()})
	check("callback", r2, err)
	r3, err := h.AuthLogout(ctx, gen.AuthLogoutRequestObject{})
	check("logout", r3, err)
	r4, err := h.GetAuthSession(ctx, gen.GetAuthSessionRequestObject{})
	check("session", r4, err)
	r5, err := h.ListAuthSessions(ctx, gen.ListAuthSessionsRequestObject{})
	check("sessions", r5, err)
	r6, err := h.RevokeAuthSession(ctx, gen.RevokeAuthSessionRequestObject{SessionId: uuid.New()})
	check("revoke", r6, err)

	// With the middleware's request information but no session, the authenticated operations answer 401.
	ctx = identity.WithRequestInfo(ctx, identity.RequestInfo{Origin: identity.OriginApp, RequestID: "r"})
	r7, _ := h.GetAuthSession(ctx, gen.GetAuthSessionRequestObject{})
	if p, ok := r7.(problemResponse); !ok || p.problem.Status != 401 || p.problem.Code != "unauthenticated" {
		t.Fatalf("no session: %#v", r7)
	}
	r8, _ := h.AuthLogout(ctx, gen.AuthLogoutRequestObject{})
	if p, ok := r8.(problemResponse); !ok || p.problem.Status != 401 {
		t.Fatalf("logout without session: %#v", r8)
	}
}

func TestToSession(t *testing.T) {
	now := time.Date(2026, 11, 17, 1, 2, 3, 0, time.FixedZone("x", 7*3600))
	tenant := uuid.New()
	v := &identity.SessionView{
		Session: &identity.Session{PublicID: uuid.New(), IdentityID: uuid.New(), IdPID: uuid.New(), Scope: identity.ScopeTenant,
			TenantID: &tenant, Subject: "sub", Origin: identity.OriginApp, AuthTime: now, IdleExpiresAt: now, AbsoluteExpiresAt: now},
		Memberships: []identity.Membership{{ID: uuid.New(), TenantID: tenant, TenantSlug: "tenant-a", TenantName: "A", Role: "owner", Status: "active"}},
	}
	s := toSession(v)
	if s.Principal.DisplayName != "sub" || s.Principal.Email != nil || s.Principal.PlatformRole != nil || s.Origin != "app" ||
		len(s.Memberships) != 1 || s.Memberships[0].TenantSlug != "tenant-a" || s.SupportGrants == nil || s.CsrfToken == "" ||
		s.AuthTime.Location() != time.UTC {
		t.Fatalf("%+v", s)
	}
}
