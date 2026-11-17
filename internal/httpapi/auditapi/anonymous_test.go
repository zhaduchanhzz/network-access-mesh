package auditapi_test

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/auditapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/gen"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/identityapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/identity"
	"github.com/zhaduchanhzz/network-access-mesh/internal/identity/identitytest"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/storetest"
)

// authOnly supplies the operations of other modules; the auth operations of identityapi.Handlers are promoted at a
// shallower depth and win.
type authOnly struct{ gen.StrictServerInterface }

type authAPI struct {
	authOnly
	*identityapi.Handlers
}

// TestAnonymousRejectionsAreBounded — G2 F2: requests refused before any identity exists (Origin of another site on a
// state-changing request, invalid or cross-site login starts, broken callbacks) cannot grow the append-only audit
// trail one row per request. Per (client address — IPv4 /32 or IPv6 /64 —, action, reason, tenant) and window they
// leave at most ⌊log10 n⌋+1 rows, each carrying the running count; the metric counts every one. 1 000 requests of one
// kind from one source ⇒ at most 4 rows, the last with count 1 000, and the same for 1 000 addresses of one /64. Once
// an identity exists the rule of §8.8 is unchanged: one row per denial (a bad CSRF token of a signed-in user).
func TestAnonymousRejectionsAreBounded(t *testing.T) {
	env := storetest.Require(t)
	db := env.NewDatabase(t)
	su := env.Admin(t, db)
	st := env.OpenStore(t, db, "mg_api_tenant", "mg_api_platform", 10)
	reg := prometheus.NewRegistry()
	logger, err := audit.New(st, env.OpenAuditWriter(t, db), audit.Config{Registerer: reg})
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
	tenant, idpID := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	exec(`INSERT INTO tenants (id, slug, name, status) VALUES ($1, 'tenant-a', 'Tenant A', 'active')`, tenant)
	fake := identitytest.NewFakeIdP(t, time.Now)
	ref := "mgsec://" + tenant.String() + "/idp." + idpID.String() + ".client#1"
	exec(`INSERT INTO identity_providers (id, scope, tenant_id, issuer, client_id, client_secret_ref, driver, status)
		VALUES ($1, 'tenant', $2, $3, 'portal-a', $4, 'external', 'active')`, idpID, tenant, fake.Issuer, ref)
	fake.AddClient("portal-a", "secret-a", "https://"+appHost+"/api/v1/auth/callback/"+idpID.String())
	fake.SetUser(identitytest.FakeUser{Sub: "alice", Email: "alice@a.test", EmailVerified: true})
	svc, err := identity.New(st, identity.Config{
		AppHost: appHost, AdminHost: adminHost, HTTPClient: &http.Client{Timeout: 5 * time.Second},
		ClientSecrets: identity.ClientSecretFunc(func(_ context.Context, r string) (string, error) {
			if r == ref {
				return "secret-a", nil
			}
			return "", errors.New("unknown secret ref")
		}),
		Logger: slog.New(slog.DiscardHandler), Auditor: auditapi.IdentityAuditor(logger),
	})
	if err != nil {
		t.Fatal(err)
	}
	h := svc.Middleware(gen.HandlerWithOptions(gen.NewStrictHandler(authAPI{Handlers: identityapi.New(svc)}, nil),
		gen.StdHTTPServerOptions{BaseURL: "/api/v1"}))
	send := func(method, path, remote string, hdr http.Header) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequestWithContext(ctx, method, "https://"+appHost+"/api/v1"+path, nil)
		req.RemoteAddr = remote
		for k, vs := range hdr {
			for _, v := range vs {
				req.Header.Add(k, v)
			}
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	const n = 1000
	const ipv4 = "198.51.100.7"
	evil := http.Header{"Origin": {"https://evil.example"}}
	for i := range n {
		if c := send(http.MethodPost, "/auth/logout", ipv4+":4000", evil).Code; c != http.StatusForbidden {
			t.Fatalf("foreign Origin: HTTP %d", c)
		}
		if c := send(http.MethodPost, "/auth/logout", "[2001:db8:42:7::"+strconv.FormatInt(int64(i+1), 16)+"]:443", evil).Code; c != http.StatusForbidden {
			t.Fatalf("foreign Origin over IPv6: HTTP %d", c)
		}
		if c := send(http.MethodGet, "/auth/login?scope=nope", ipv4+":4000", nil).Code; c != http.StatusUnprocessableEntity {
			t.Fatalf("invalid login start: HTTP %d", c)
		}
		send(http.MethodGet, "/auth/login?scope=tenant&tenant=tenant-a", ipv4+":4000", http.Header{"Sec-Fetch-Site": {"cross-site"}})
		if c := send(http.MethodGet, "/auth/callback/"+idpID.String()+"?state=not-a-state", ipv4+":4000", nil).Code; c != http.StatusUnauthorized {
			t.Fatalf("broken callback: HTTP %d", c)
		}
	}

	type key struct{ action, reason, prefix string }
	type agg struct{ rows, maxCount int }
	got := map[key]agg{}
	rows, err := su.Query(ctx, `SELECT action, details ->> 'reason', COALESCE(details ->> 'client_prefix', ''), count(*)::int,
			COALESCE(max((details ->> 'count')::int), 0)
		FROM audit_events WHERE actor_identity_id IS NULL AND outcome <> 'success' GROUP BY 1, 2, 3`)
	if err != nil {
		t.Fatal(err)
	}
	total := 0
	for rows.Next() {
		var k key
		var a agg
		if err := rows.Scan(&k.action, &k.reason, &k.prefix, &a.rows, &a.maxCount); err != nil {
			t.Fatal(err)
		}
		got[k] = a
		total += a.rows
	}
	rows.Close()
	want := []key{
		{identity.ActionSessionCheck, "origin_header_mismatch", ipv4 + "/32"},
		{identity.ActionSessionCheck, "origin_header_mismatch", "2001:db8:42:7::/64"},
		{identity.ActionLoginStart, "enum", ipv4 + "/32"},
		{identity.ActionLoginStart, "sec_fetch_site_cross_origin", ipv4 + "/32"},
		{identity.ActionLogin, "state_malformed", ipv4 + "/32"},
	}
	for _, k := range want {
		a, ok := got[k]
		if !ok || a.rows < 1 || a.rows > 4 || a.maxCount != n {
			t.Errorf("%+v: %d rows, last count %d — want 1 to 4 rows (⌊log10 %d⌋+1) and the running count %d", k, a.rows,
				a.maxCount, n, n)
		}
	}
	if len(got) != len(want) || total > 4*len(want) {
		t.Errorf("%d anonymous rows in %d groups for %d refused requests: %v", total, len(got), len(want)*n, got)
	}
	var counted float64
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range mfs {
		if mf.GetName() == "meshguard_audit_anonymous_denials_total" {
			for _, m := range mf.GetMetric() {
				counted += m.GetCounter().GetValue()
			}
		}
	}
	if counted != float64(len(want)*n) {
		t.Errorf("meshguard_audit_anonymous_denials_total = %v, want %d", counted, len(want)*n)
	}

	// With an identity the rule is unchanged: one row per denial.
	jar := map[string]string{}
	keep := func(rec *httptest.ResponseRecorder) {
		for _, line := range rec.Header().Values("Set-Cookie") {
			if c, err := http.ParseSetCookie(line); err == nil {
				jar[c.Name] = c.Value
			}
		}
	}
	withJar := func(hdr http.Header) http.Header {
		out := hdr.Clone()
		if out == nil {
			out = http.Header{}
		}
		for k, v := range jar {
			out.Add("Cookie", k+"="+v)
		}
		return out
	}
	start := send(http.MethodGet, "/auth/login?scope=tenant&tenant=tenant-a", ipv4+":4000", nil)
	keep(start)
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	areq, _ := http.NewRequestWithContext(ctx, http.MethodGet, start.Header().Get("Location"), nil)
	resp, err := client.Do(areq)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	cb, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	done := send(http.MethodGet, "/auth/callback/"+idpID.String()+"?"+cb.RawQuery, ipv4+":4000", withJar(nil))
	keep(done)
	if done.Code != http.StatusFound || jar[identity.SessionCookieName] == "" {
		t.Fatalf("login: HTTP %d %s", done.Code, done.Body.String())
	}
	for range 5 {
		rec := send(http.MethodPost, "/auth/logout", ipv4+":4000",
			withJar(http.Header{"Origin": {"https://" + appHost}, "X-Csrf-Token": {"not-the-token"}}))
		if rec.Code != http.StatusForbidden {
			t.Fatalf("bad CSRF token: HTTP %d", rec.Code)
		}
	}
	var perRow int
	if err := su.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE action = $1 AND details ->> 'reason' = 'csrf_token_invalid'
			AND actor_identity_id IS NOT NULL AND tenant_id = $2`, identity.ActionSessionCheck, tenant).Scan(&perRow); err != nil {
		t.Fatal(err)
	}
	if perRow != 5 {
		t.Errorf("denials of a signed-in identity: %d rows, want one per request (5)", perRow)
	}
}
