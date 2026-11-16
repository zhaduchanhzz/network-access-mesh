package httpapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/gen"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/problem"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/logx"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/ratelimit"
)

// leaky handlers fail in every way a real handler could while holding a secret.
type leaky struct{ NotImplemented }

func (leaky) ListMyTenants(context.Context, gen.ListMyTenantsRequestObject) (gen.ListMyTenantsResponseObject, error) {
	return gen.ListMyTenants200JSONResponse{Items: []gen.Tenant{}}, nil
}

func (leaky) GetTenant(context.Context, gen.GetTenantRequestObject) (gen.GetTenantResponseObject, error) {
	panic("decrypting DEK with " + canary) // panic value holding a secret
}

func (leaky) ListPlatformTenants(context.Context, gen.ListPlatformTenantsRequestObject) (gen.ListPlatformTenantsResponseObject, error) {
	// an internal error quoting credentials in the forms §16.5 names
	return nil, fmt.Errorf("headscale: POST /api/v1/preauthkey with Authorization: Bearer %s returned hskey-auth-x1-%s; "+
		"retry with client_secret=%s", canary, canary, canary)
}

func (leaky) RenameDevice(context.Context, gen.RenameDeviceRequestObject) (gen.RenameDeviceResponseObject, error) {
	// an upstream rejection: the raw upstream body is the cause (logged, redacted), the client gets a fixed detail
	return nil, &problem.Error{Code: gen.ProblemCodeUpstreamRejected, Detail: "Headscale rejected the new name.",
		Cause: errors.New(`upstream body {"message":"unauthorized","api_key":"` + canary + `"} for postgres://mg:` + canary + `@db/x`)}
}

func (leaky) SyncDevices(context.Context, gen.SyncDevicesRequestObject) (gen.SyncDevicesResponseObject, error) {
	return nil, problem.New(gen.ProblemCodeConflict, "A sync is already running.")
}

// TestCanarySecretNeverLogged is the verification of P2-T14 ("Canary không xuất hiện trong log", §25.1 rule 9).
//
// A known secret travels through every channel that carries secrets — credential headers (Authorization,
// Proxy-Authorization, Cookie, X-CSRF-Token, X-MG-Token, X-Api-Key), the query string (OAuth code/state, token=),
// secret fields of the body, a panic value, a handler error, an upstream error, and the URL path — across every
// outcome: 200, 404 (path and method), 422 (path, query and header parameters; malformed, mistyped and oversized
// body), 429, 409, 500 (panic and error), 501, 502. A session hook also logs the request carelessly (whole header map,
// query values, credential headers by name), as a future hook must not — logx still covers it. No log line may
// contain the canary; the access lines and redaction markers must be there, so the logs were really written.
func TestCanarySecretNeverLogged(t *testing.T) {
	var e *env
	careless := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			e.log.DebugContext(r.Context(), "session lookup",
				slog.Any("headers", r.Header), slog.Any("query", r.URL.Query()),
				"cookie", r.Header.Get("Cookie"), "authorization", r.Header.Get("Authorization"),
				"csrf", r.Header.Get("X-CSRF-Token"), "x_mg_token", r.Header.Get("X-MG-Token"))
			next.ServeHTTP(w, r)
		})
	}
	e = newEnv(t, Options{
		Handlers:     Handlers{Tenants: leaky{}, Devices: leaky{}},
		Hooks:        Hooks{Authz: passAuthz, Session: careless},
		MaxBodyBytes: 512,
		RateLimits: RateLimits{ClassAuth: {
			PerIP:       ratelimit.Limit{Every: time.Hour, Burst: 3},
			PerIdentity: ratelimit.Limit{Every: time.Hour, Burst: 3},
		}},
	})
	credentials := func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+canary)
		r.Header.Set("Proxy-Authorization", "Basic "+canary)
		r.Header.Set("Cookie", "__Host-mg_session="+canary+"; __Host-mg_authreq="+canary)
		r.Header.Set("X-CSRF-Token", canary)
		r.Header.Set("X-MG-Token", canary)
		r.Header.Set("X-Api-Key", canary)
		r.Header.Set("Referer", "https://app.example/devices?token="+canary)
	}
	device := "/api/v1/tenants/" + tenantID + "/devices/" + itemID
	secretBody := `{"given_name":"laptop-1","client_secret":"` + canary + `","password":"` + canary + `"}`
	requests := []struct {
		name, method, target, body string
		extra                      []func(*http.Request)
		status                     int
	}{
		{"200 with a query secret", http.MethodGet, "/api/v1/tenants?cursor=" + canary, "", nil, 200},
		{"501 OAuth callback (auth 1/3)", http.MethodGet, "/api/v1/auth/callback/" + itemID + "?state=" + canary + "&code=" + canary + "&iss=https://" + canary, "", nil, 501},
		{"404 path", http.MethodGet, "/api/v1/" + canary + "?token=" + canary, "", nil, 404},
		{"404 method", http.MethodPut, "/api/v1/tenants/" + canary, secretBody, nil, 404},
		{"422 path parameter", http.MethodGet, "/api/v1/tenants/" + canary + "/devices", "", nil, 422},
		{"422 query parameter", http.MethodGet, "/api/v1/tenants/" + tenantID + "/devices?limit=" + canary, "", nil, 422},
		{"422 header parameter", http.MethodPost, "/api/v1/tenants/" + tenantID + "/devices/sync", "", nil, 422},
		{"422 malformed body", http.MethodPatch, device, `{"given_name":"laptop-1","password":"` + canary, nil, 422},
		{"422 mistyped body", http.MethodPatch, device, `{"given_name":{"secret":"` + canary + `"}}`, nil, 422},
		{"422 body too large", http.MethodPatch, device, `{"given_name":"x","client_secret":"` + strings.Repeat(canary, 40) + `"}`, nil, 422},
		{"409 handler problem", http.MethodPost, "/api/v1/tenants/" + tenantID + "/devices/sync", "", []func(*http.Request){idempotency}, 409},
		{"502 upstream cause", http.MethodPatch, device, secretBody, nil, 502},
		{"500 handler error", http.MethodGet, "/api/v1/platform/tenants", "", nil, 500},
		{"500 panic", http.MethodGet, "/api/v1/tenants/" + tenantID, "", nil, 500},
		{"auth 2/3", http.MethodGet, "/api/v1/auth/session?token=" + canary, "", nil, 501},
		{"auth 3/3", http.MethodGet, "/api/v1/auth/session?token=" + canary, "", nil, 501},
		{"429 rate limited", http.MethodGet, "/api/v1/auth/session?token=" + canary, "", nil, 429},
	}
	for _, rq := range requests {
		w := e.do(rq.method, rq.target, rq.body, append([]func(*http.Request){credentials}, rq.extra...)...)
		if w.Code != rq.status {
			t.Errorf("%s: status %d, want %d: %s", rq.name, w.Code, rq.status, w.Body.String())
		}
		// The response may echo the client's own path (problem.instance) — never anything else.
		body := w.Body.String()
		if path, _, _ := strings.Cut(rq.target, "?"); strings.Contains(path, canary) {
			body = strings.ReplaceAll(body, path, "<instance>")
		}
		if strings.Contains(body, canary) {
			t.Errorf("%s: response echoes the canary: %s", rq.name, body)
		}
	}

	out := e.logs.String()
	if strings.Contains(out, canary) {
		for _, ln := range strings.Split(out, "\n") {
			if strings.Contains(ln, canary) {
				t.Errorf("canary in log line: %s", ln)
			}
		}
		t.FailNow()
	}
	if n := strings.Count(out, `"msg":"http request"`); n != len(requests) {
		t.Errorf("%d access lines for %d requests", n, len(requests))
	}
	// Every request but the two refused before the session hook (oversized body, 429) went through it.
	if n := strings.Count(out, `"msg":"session lookup"`); n != len(requests)-2 {
		t.Errorf("the careless hook logged %d times, want %d", n, len(requests)-2)
	}
	for _, want := range []string{
		`"msg":"panic recovered"`, `"problem":"upstream_rejected"`, `"rate_limited_by":"auth/ip"`,
		"headscale: POST /api/v1/preauthkey with Authorization: Bearer [REDACTED] returned [REDACTED]; retry with client_secret=[REDACTED]",
		`\"api_key\":\"[REDACTED]\"`, "postgres://mg:[REDACTED]@db/x",
		`"Authorization":["[REDACTED]"]`, `"Cookie":["[REDACTED]"]`, `"X-Mg-Token":["[REDACTED]"]`, `"X-Api-Key":["[REDACTED]"]`,
		`"code":["[REDACTED]"]`, `"csrf":"` + logx.Redacted + `"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("log lacks %s", want)
		}
	}
}
