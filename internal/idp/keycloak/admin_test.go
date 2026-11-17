package keycloak

import (
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zhaduchanhzz/network-access-mesh/internal/idp"
	"github.com/zhaduchanhzz/network-access-mesh/internal/idp/idptest"
	"github.com/zhaduchanhzz/network-access-mesh/internal/secrets"
)

const canary = "KC-UPSTREAM-CANARY-91c2"

// fakeKC is a tiny stand-in for the token endpoint and a few Admin REST answers.
type fakeKC struct {
	mu        sync.Mutex
	tokens    int    // token requests served
	secret    string // the client secret it accepts
	expiresIn int
	revoked   bool // the next admin call answers 401 once
	calls     []string
}

func (f *fakeKC) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, r.Method+" "+r.URL.Path)
	w.Header().Set("Content-Type", "application/json")
	if strings.HasSuffix(r.URL.Path, "/protocol/openid-connect/token") {
		_ = r.ParseForm()
		if r.PostForm.Get("client_secret") != f.secret || r.PostForm.Get("grant_type") != "client_credentials" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"error":"unauthorized_client","error_description":"`+canary+`"}`)
			return
		}
		f.tokens++
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "tok-" + strings.Repeat("x", f.tokens), "expires_in": f.expiresIn})
		return
	}
	if f.revoked {
		f.revoked = false
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	switch r.URL.Path {
	case "/admin/realms/r1":
		_, _ = io.WriteString(w, `{"id":"abc","realm":"r1","accessTokenLifespan":300,"ratio":1.5}`)
	case "/admin/realms/r1/users":
		w.Header().Set("Location", "https://example.com/admin/realms/r1/users/6f1c1a4e-8a8e-4a2e-9f0e-1d2c3b4a5f60")
		w.WriteHeader(http.StatusCreated)
	case "/admin/realms/conflict":
		w.WriteHeader(http.StatusConflict)
		_, _ = io.WriteString(w, `{"errorMessage":"`+canary+`"}`)
	default:
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, canary)
	}
}

func newFake(t *testing.T) (*admin, *fakeKC, tokenSource) {
	t.Helper()
	f := &fakeKC{secret: "s3cr3t", expiresIn: 300}
	srv := httptest.NewTLSServer(f)
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	route, err := idp.NewPlatformRoute(idp.PlatformRouteConfig{Host: "example.com", Address: srv.Listener.Addr().String(), RootCAs: pool})
	if err != nil {
		t.Fatal(err)
	}
	st := idptest.NewSecrets()
	ref := secrets.PlatformRef("idp.test.provisioner", 1)
	if err := st.Put(t.Context(), ref, []byte("s3cr3t")); err != nil {
		t.Fatal(err)
	}
	return newAdmin(route, st, nil, nil), f, tokenSource{realm: "master", clientID: "mg-provisioner", secret: ref}
}

// TestAdminCall: JSON decoded with exact numbers, accepted statuses returned without error, other statuses mapped to
// stable codes whose text never carries the upstream body, ids read from Location.
func TestAdminCall(t *testing.T) {
	a, f, ts := newFake(t)
	ctx := t.Context()
	var rep map[string]any
	st, _, err := a.call(ctx, "op", ts, http.MethodGet, "/admin/realms/r1", nil, &rep)
	if err != nil || st != 200 || rep["accessTokenLifespan"] != json.Number("300") || rep["ratio"] != json.Number("1.5") {
		t.Fatalf("GET: %d %v %v", st, rep, err)
	}
	_, h, err := a.call(ctx, "op", ts, http.MethodPost, "/admin/realms/r1/users", map[string]any{"username": "u"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if id, err := createdID("op", h); err != nil || id != "6f1c1a4e-8a8e-4a2e-9f0e-1d2c3b4a5f60" {
		t.Fatalf("createdID = %q, %v", id, err)
	}
	if _, err := createdID("op", http.Header{"Location": {"https://example.com/x/../not-a-uuid"}}); idp.CodeOf(err) != idp.CodeUpstream {
		t.Fatalf("bad Location: %v", err)
	}
	st, _, err = a.call(ctx, "op", ts, http.MethodPost, "/admin/realms/conflict", map[string]any{}, nil, http.StatusConflict)
	if err != nil || st != http.StatusConflict {
		t.Fatalf("accepted 409: %d %v", st, err)
	}
	_, _, err = a.call(ctx, "op", ts, http.MethodPost, "/admin/realms/conflict", map[string]any{}, nil)
	if idp.CodeOf(err) != idp.CodeConflict || strings.Contains(err.Error(), canary) {
		t.Fatalf("409: %v", err)
	}
	_, _, err = a.call(ctx, "op", ts, http.MethodGet, "/admin/realms/other", nil, nil)
	if idp.CodeOf(err) != idp.CodeUnavailable || strings.Contains(err.Error(), canary) {
		t.Fatalf("500: %v", err)
	}
	if f.tokens != 1 {
		t.Fatalf("token requests = %d, want 1 (cached)", f.tokens)
	}
}

// TestAdminTokenLifecycle: a token is cached until shortly before it expires; a 401 from the Admin API drops it and
// the call is retried once with a fresh token; a refused secret is CodeUnauthenticated without upstream text.
func TestAdminTokenLifecycle(t *testing.T) {
	a, f, ts := newFake(t)
	ctx := t.Context()
	now := time.Now()
	a.now = func() time.Time { return now }
	for range 3 {
		if _, _, err := a.call(ctx, "op", ts, http.MethodGet, "/admin/realms/r1", nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	if f.tokens != 1 {
		t.Fatalf("tokens %d, want 1", f.tokens)
	}
	now = now.Add(271 * time.Second) // 300 s lifetime − 30 s skew
	if _, _, err := a.call(ctx, "op", ts, http.MethodGet, "/admin/realms/r1", nil, nil); err != nil || f.tokens != 2 {
		t.Fatalf("expired token not renewed: %d %v", f.tokens, err)
	}
	f.revoked = true
	if _, _, err := a.call(ctx, "op", ts, http.MethodGet, "/admin/realms/r1", nil, nil); err != nil || f.tokens != 3 {
		t.Fatalf("401 not retried with a fresh token: %d %v", f.tokens, err)
	}
	f.secret = "rotated-elsewhere"
	a.invalidate(ts)
	_, _, err := a.call(ctx, "op", ts, http.MethodGet, "/admin/realms/r1", nil, nil)
	if idp.CodeOf(err) != idp.CodeUnauthenticated || strings.Contains(err.Error(), canary) || strings.Contains(err.Error(), "s3cr3t") {
		t.Fatalf("refused secret: %v", err)
	}
	a.tokens["r1|x||mgsec://platform/x#1"] = cachedToken{value: "t", exp: now.Add(time.Hour)}
	a.invalidateRealm("r1")
	if len(a.tokens) != 0 {
		t.Fatalf("invalidateRealm left %v", a.tokens)
	}
}
