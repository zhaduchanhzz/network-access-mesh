package authzhook_test

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/authz"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/authzhook"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/gen"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/identityapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/identity"
	"github.com/zhaduchanhzz/network-access-mesh/internal/identity/identitytest"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/logx"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/storetest"
)

// TestIdentityProblemsThroughTheChain — the refusals written by the session middleware itself (unknown host 404,
// Origin/Sec-Fetch-Site 403, CSRF 403, session lookup failure 500) leave through httpapi.WriteProblem when
// identity.Config.ProblemWriter = authzhook.WriteProblem: X-Content-Type-Options: nosniff and the code on the
// access-log line, like every other problem of the API (P2 integration finding, fixed in P2-T15a). Without the writer
// the module's default still sends nosniff.
func TestIdentityProblemsThroughTheChain(t *testing.T) {
	env := storetest.Require(t)
	db := env.NewDatabase(t)
	su := env.Admin(t, db)
	st := env.OpenStore(t, db, "mg_api_tenant", "mg_api_platform", 4)

	fake := identitytest.NewFakeIdP(t, time.Now)
	tenant, idp := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	ref := "mgsec://" + tenant.String() + "/idp." + idp.String() + ".client#1" // the IdP's own secret (G2 F3)
	secret := "secret-" + uuid.NewString()
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO tenants (id, slug, name, status) VALUES ($1, 'tenant-p', 'Tenant P', 'active')`, []any{tenant}},
		{`INSERT INTO identity_providers (id, scope, tenant_id, issuer, client_id, client_secret_ref, driver, status)
			VALUES ($1, 'tenant', $2, $3, 'portal-p', $4, 'external', 'active')`, []any{idp, tenant, fake.Issuer, ref}},
	} {
		if _, err := su.Exec(t.Context(), q.sql, q.args...); err != nil {
			t.Fatalf("fixture: %v", err)
		}
	}
	fake.AddClient("portal-p", secret, "https://"+appHost+"/api/v1/auth/callback/"+idp.String())

	compose := func(s *store.Store, writer func(http.ResponseWriter, *http.Request, error)) (http.Handler, *syncBuffer) {
		t.Helper()
		svc, err := identity.New(s, identity.Config{
			AppHost: appHost, AdminHost: adminHost,
			HTTPClient: &http.Client{Timeout: 5 * time.Second},
			ClientSecrets: identity.ClientSecretFunc(func(_ context.Context, r string) (string, error) {
				if r != ref {
					return "", errors.New("unknown secret ref")
				}
				return secret, nil
			}),
			Logger: slog.New(slog.DiscardHandler), RequestID: authzhook.RequestID, ClientIP: authzhook.ClientIP,
			ProblemWriter: writer,
		})
		if err != nil {
			t.Fatal(err)
		}
		logs := &syncBuffer{}
		h, err := httpapi.New(httpapi.Options{
			Logger:   logx.New(logs, slog.LevelInfo, "api"),
			Handlers: httpapi.Handlers{Auth: identityapi.New(svc)},
			Hooks:    authzhook.Hooks(svc, authz.New(s)),
		})
		if err != nil {
			t.Fatal(err)
		}
		return h, logs
	}
	wired, wiredLogs := compose(st, authzhook.WriteProblem)
	bare, bareLogs := compose(st, nil)

	// A real session (fake IdP login through the wired chain); the same cookie is valid for both compositions.
	br := &browser{t: t, h: wired, jar: map[string]map[string]string{}}
	br.login(appHost, "scope=tenant&tenant=tenant-p")
	cookie := br.jar[appHost][identity.SessionCookieName]
	logout := "https://" + appHost + "/api/v1/auth/logout"
	cases := []struct {
		name, method, url string
		hdr               http.Header
		status            int
		code              gen.ProblemCode
	}{
		{"unknown host", http.MethodGet, "https://evil.example/api/v1/auth/session", nil, 404, gen.ProblemCodeNotFound},
		{"foreign Origin", http.MethodPost, logout, http.Header{"Origin": {"https://evil.example"}}, 403, gen.ProblemCodeForbidden},
		{"cross-site fetch", http.MethodPost, logout, http.Header{"Sec-Fetch-Site": {"cross-site"}}, 403, gen.ProblemCodeForbidden},
		{"no CSRF token", http.MethodPost, logout, http.Header{"Origin": {"https://" + appHost}}, 403, gen.ProblemCodeForbidden},
		{"wrong CSRF token", http.MethodPost, logout,
			http.Header{"Origin": {"https://" + appHost}, identity.CSRFHeader: {strings.Repeat("A", 43)}}, 403, gen.ProblemCodeForbidden},
	}
	for _, c := range []struct {
		name string
		h    http.Handler
		logs *syncBuffer
	}{{"wired", wired, wiredLogs}, {"default writer", bare, bareLogs}} {
		b := &browser{t: t, h: c.h, jar: map[string]map[string]string{appHost: {identity.SessionCookieName: cookie}}}
		for _, tc := range cases {
			rec := b.do(tc.method, tc.url, tc.hdr)
			p := decodeProblem(t, c.name+" "+tc.name, rec, tc.status, tc.code)
			if rec.Header().Get("X-Content-Type-Options") != "nosniff" || rec.Header().Get("Cache-Control") != "no-store" {
				t.Errorf("%s %s: headers %v", c.name, tc.name, rec.Header())
			}
			id := rec.Header().Get("X-Request-Id")
			if id == "" || p.RequestId != id {
				t.Errorf("%s %s: request id header %q, body %q", c.name, tc.name, id, p.RequestId)
			}
			line := c.logs.accessLine(t, id)
			if line["status"] != float64(tc.status) {
				t.Errorf("%s %s: access line %v", c.name, tc.name, line)
			}
			if c.name == "wired" && line["problem"] != string(tc.code) {
				t.Errorf("%s %s: access line without problem=%s: %v", c.name, tc.name, tc.code, line)
			}
		}
	}
	// The refusals left the session alive.
	if rec := br.get("https://" + appHost + "/api/v1/auth/session"); rec.Code != http.StatusOK {
		t.Fatalf("session after the refused requests: HTTP %d", rec.Code)
	}

	// 500: the session lookup fails (store closed) — internal_error on the wire, the cause only in the access log.
	broken := env.OpenStore(t, db, "mg_api_tenant", "mg_api_platform", 2)
	h, logs := compose(broken, authzhook.WriteProblem)
	broken.Close()
	b := &browser{t: t, h: h, jar: map[string]map[string]string{appHost: {identity.SessionCookieName: cookie}}}
	rec := b.get("https://" + appHost + "/api/v1/auth/session")
	decodeProblem(t, "session lookup failure", rec, http.StatusInternalServerError, gen.ProblemCodeInternalError)
	line := logs.accessLine(t, rec.Header().Get("X-Request-Id"))
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" || line["problem"] != string(gen.ProblemCodeInternalError) ||
		!strings.Contains(stringOf(line["error"]), "session_lookup_failed") {
		t.Errorf("session lookup failure: headers %v, access line %v", rec.Header(), line)
	}
	if body := rec.Body.String(); strings.Contains(body, "session_lookup_failed") || strings.Contains(body, "closed") {
		t.Errorf("the 500 leaks its cause: %s", body)
	}
}

func stringOf(v any) string {
	s, _ := v.(string)
	return s
}
