package headscale

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// sampleNode is the shape of a node object returned by 0.29.7 (protojson: lowerCamelCase, uint64 as strings).
const sampleNode = `{"id":"7", "machineKey":"mkey:aa", "nodeKey":"nodekey:bb", "discoKey":"discokey:cc",
 "ipAddresses":["100.64.0.7", "fd7a:115c:a1e0::7"], "name":"host7",
 "user":{"id":"3", "name":"mg-a", "createdAt":"2026-11-17T01:10:40.687187047Z", "displayName":"A", "email":"",
  "providerId":"", "provider":"", "profilePicUrl":""},
 "lastSeen":null, "expiry":"0001-01-01T00:00:00Z", "preAuthKey":{"id":"9", "key":"", "aclTags":[]},
 "createdAt":"2026-11-17T01:12:00Z", "registerMethod":"REGISTER_METHOD_AUTH_KEY", "givenName":"host7",
 "online":true, "approvedRoutes":["10.0.0.0/24"], "availableRoutes":["10.0.0.0/24"], "subnetRoutes":[], "tags":[]}`

func nodeBody() string { return `{"node":` + sampleNode + `}` }

func TestHeaderSchemeAndVersionProbe(t *testing.T) {
	h := newHarness(t, Options{})
	h.edge.on("GET", "/api/v1/user", 200, `{"users":[]}`)
	inst := h.instance(t)
	if _, err := inst.ListUsers(context.Background(), UserFilter{}); err != nil {
		t.Fatal(err)
	}
	reqs := h.edge.requests()
	if len(reqs) != 2 || reqs[0].Path != "/version" || reqs[1].Path != "/api/v1/user" {
		t.Fatalf("requests = %+v", reqs)
	}
	for _, r := range reqs {
		if r.Header.Get(HeaderEdgeToken) != testEdgeToken || r.Header.Get(HeaderInstance) != "tenant-a" {
			t.Errorf("%s: edge headers missing", r.Path)
		}
	}
	if reqs[0].Header.Get("Authorization") != "" {
		t.Error("GET /version must not carry the instance API key")
	}
	if reqs[1].Header.Get("Authorization") != "Bearer "+h.edge.apiKey {
		t.Error("/api/v1 call without the instance API key")
	}
	if v, ok := h.reg.CachedVersion(testTenant); !ok || v.String() != "0.29.7" {
		t.Errorf("cached version = %v %v", v, ok)
	}
}

// TestRequestShapes pins where each parameter goes on 0.29.7 (query / body / path — P2-T10 "tham số query").
func TestRequestShapes(t *testing.T) {
	h := newHarness(t, Options{})
	for _, p := range []string{"/api/v1/node/7/expire", "/api/v1/node/7", "/api/v1/node/7/rename/web-1",
		"/api/v1/node/7/tags", "/api/v1/node/7/approve_routes", "/api/v1/auth/register"} {
		for _, m := range []string{"GET", "POST"} {
			h.edge.on(m, p, 200, nodeBody())
		}
	}
	h.edge.on("DELETE", "/api/v1/node/7", 200, `{}`)
	h.edge.on("GET", "/api/v1/node", 200, `{"nodes":[]}`)
	h.edge.on("DELETE", "/api/v1/preauthkey", 200, `{}`)
	h.edge.on("POST", "/api/v1/preauthkey/expire", 200, `{}`)
	h.edge.on("POST", "/api/v1/preauthkey", 200,
		`{"preAuthKey":{"user":{"id":"5","name":"mg-a"}, "id":"11", "key":"KEYVALUE", "reusable":false, "ephemeral":false, "used":false, "expiration":"2026-11-17T08:15:00Z", "createdAt":"2026-11-17T08:00:00Z", "aclTags":[]}}`)
	h.edge.on("POST", "/api/v1/apikey", 200, `{"apiKey":"NEWKEY"}`)
	h.edge.on("POST", "/api/v1/apikey/expire", 200, `{}`)
	h.edge.on("POST", "/api/v1/auth/approve", 200, `{}`)
	h.edge.on("POST", "/api/v1/auth/reject", 200, `{}`)
	h.edge.on("POST", "/api/v1/user/3/rename/mg-b.c", 200, `{"user":{"id":"3","name":"mg-b.c"}}`)
	h.edge.on("DELETE", "/api/v1/user/3", 200, `{}`)
	h.edge.on("GET", "/api/v1/user", 200, `{"users":[]}`)
	inst := h.instance(t)
	ctx := context.Background()
	at := time.Date(2027, 2, 15, 1, 2, 3, 4, time.FixedZone("ICT", 7*3600))
	authID := testAuthID("A")

	cases := []struct {
		name   string
		call   func() error
		method string
		path   string
		query  url.Values
		body   string
	}{
		{"ExpireNode explicit time in query, converted to UTC", func() error { _, err := inst.ExpireNode(ctx, 7, &at); return err },
			"POST", "/api/v1/node/7/expire", url.Values{"expiry": {"2027-02-14T18:02:03.000000004Z"}}, ""},
		{"ExpireNode nil = now, still explicit", func() error { _, err := inst.ExpireNode(ctx, 7, nil); return err },
			"POST", "/api/v1/node/7/expire", url.Values{"expiry": {"2026-11-17T08:00:00Z"}}, ""},
		{"DeletePreAuthKey id in query", func() error { return inst.DeletePreAuthKey(ctx, 9) },
			"DELETE", "/api/v1/preauthkey", url.Values{"id": {"9"}}, ""},
		{"ListNodes user in query", func() error { _, err := inst.ListNodes(ctx, "mg-a"); return err },
			"GET", "/api/v1/node", url.Values{"user": {"mg-a"}}, ""},
		{"ListUsers name in query", func() error { _, err := inst.ListUsers(ctx, UserFilter{Name: "mg-a"}); return err },
			"GET", "/api/v1/user", url.Values{"name": {"mg-a"}}, ""},
		{"AuthRegister body", func() error { _, err := inst.AuthRegister(ctx, "mg-a", authID); return err },
			"POST", "/api/v1/auth/register", nil, `{"user":"mg-a","authId":"` + authID + `"}`},
		{"AuthApprove body", func() error { return inst.AuthApprove(ctx, authID) },
			"POST", "/api/v1/auth/approve", nil, `{"authId":"` + authID + `"}`},
		{"AuthReject body", func() error { return inst.AuthReject(ctx, authID) },
			"POST", "/api/v1/auth/reject", nil, `{"authId":"` + authID + `"}`},
		{"CreatePreAuthKey explicit expiration, user as string, aclTags []", func() error {
			_, err := inst.CreatePreAuthKey(ctx, PreAuthKeyOpts{User: 5, Expiration: h.clk.t.Add(15 * time.Minute)})
			return err
		}, "POST", "/api/v1/preauthkey", nil,
			`{"user":"5","reusable":false,"ephemeral":false,"expiration":"2026-11-17T08:15:00Z","aclTags":[]}`},
		{"CreatePreAuthKey tag-only key omits user", func() error {
			_, err := inst.CreatePreAuthKey(ctx, PreAuthKeyOpts{Tags: []string{"tag:server"}, Expiration: h.clk.t.Add(time.Minute)})
			return err
		}, "POST", "/api/v1/preauthkey", nil,
			`{"reusable":false,"ephemeral":false,"expiration":"2026-11-17T08:01:00Z","aclTags":["tag:server"]}`},
		{"CreateAPIKey explicit expiration", func() error { _, err := inst.CreateAPIKey(ctx, h.clk.t.Add(90*24*time.Hour)); return err },
			"POST", "/api/v1/apikey", nil, `{"expiration":"2027-02-15T08:00:00Z"}`},
		{"ExpireAPIKey normalises the display prefix", func() error { return inst.ExpireAPIKey(ctx, "hskey-api-abcdefghijkl-***") },
			"POST", "/api/v1/apikey/expire", nil, `{"prefix":"abcdefghijkl"}`},
		{"ExpireAPIKey bare prefix with URL-safe characters", func() error { return inst.ExpireAPIKey(ctx, "ab-d_fghijkl") },
			"POST", "/api/v1/apikey/expire", nil, `{"prefix":"ab-d_fghijkl"}`},
		{"ExpirePreAuthKey id as string in body", func() error { return inst.ExpirePreAuthKey(ctx, 2) },
			"POST", "/api/v1/preauthkey/expire", nil, `{"id":"2"}`},
		{"RenameUser new name in path", func() error { _, err := inst.RenameUser(ctx, 3, "mg-b.c"); return err },
			"POST", "/api/v1/user/3/rename/mg-b.c", nil, ""},
		{"RenameNode new name in path", func() error { _, err := inst.RenameNode(ctx, 7, "web-1"); return err },
			"POST", "/api/v1/node/7/rename/web-1", nil, ""},
		{"SetTags body", func() error { _, err := inst.SetTags(ctx, 7, []string{"tag:web", "tag:db"}); return err },
			"POST", "/api/v1/node/7/tags", nil, `{"tags":["tag:web","tag:db"]}`},
		{"SetApprovedRoutes replaces the whole set, sorted, deduplicated", func() error {
			_, err := inst.SetApprovedRoutes(ctx, 7, []netip.Prefix{netip.MustParsePrefix("10.1.0.0/16"),
				netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("10.1.0.0/16")})
			return err
		}, "POST", "/api/v1/node/7/approve_routes", nil, `{"routes":["0.0.0.0/0","10.1.0.0/16"]}`},
		{"SetApprovedRoutes with no route sends [] (revoke all)", func() error { _, err := inst.SetApprovedRoutes(ctx, 7, nil); return err },
			"POST", "/api/v1/node/7/approve_routes", nil, `{"routes":[]}`},
		{"GetNode", func() error { _, err := inst.GetNode(ctx, 7); return err }, "GET", "/api/v1/node/7", nil, ""},
		{"DeleteNode", func() error { return inst.DeleteNode(ctx, 7) }, "DELETE", "/api/v1/node/7", nil, ""},
		{"DeleteUser", func() error { return inst.DeleteUser(ctx, 3) }, "DELETE", "/api/v1/user/3", nil, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h.edge.reset()
			if err := tc.call(); err != nil {
				t.Fatalf("call: %v", err)
			}
			reqs := h.edge.apiRequests()
			if len(reqs) != 1 {
				t.Fatalf("expected one request, got %d", len(reqs))
			}
			r := reqs[0]
			if r.Method != tc.method || r.Path != tc.path {
				t.Fatalf("got %s %s, want %s %s", r.Method, r.Path, tc.method, tc.path)
			}
			gotQ, _ := url.ParseQuery(r.RawQuery)
			if len(tc.query) != len(gotQ) {
				t.Fatalf("query = %v, want %v", gotQ, tc.query)
			}
			for k, v := range tc.query {
				if gotQ.Get(k) != v[0] {
					t.Fatalf("query %s = %q, want %q", k, gotQ.Get(k), v[0])
				}
			}
			if tc.body == "" {
				if len(r.Body) != 0 {
					t.Fatalf("unexpected body %s", r.Body)
				}
				return
			}
			if !jsonEqual(t, string(r.Body), tc.body) {
				t.Fatalf("body = %s, want %s", r.Body, tc.body)
			}
			if r.Header.Get("Content-Type") != "application/json" {
				t.Fatal("JSON body without Content-Type")
			}
		})
	}
}

func jsonEqual(t *testing.T, a, b string) bool {
	t.Helper()
	var x, y any
	if err := json.Unmarshal([]byte(a), &x); err != nil {
		t.Fatalf("bad JSON %s: %v", a, err)
	}
	if err := json.Unmarshal([]byte(b), &y); err != nil {
		t.Fatalf("bad JSON %s: %v", b, err)
	}
	xa, _ := json.Marshal(x)
	ya, _ := json.Marshal(y)
	return string(xa) == string(ya)
}

func TestDecodeNodeAndKeys(t *testing.T) {
	h := newHarness(t, Options{})
	h.edge.on("GET", "/api/v1/node/7", 200, nodeBody())
	h.edge.on("GET", "/api/v1/preauthkey", 200,
		`{"preAuthKeys":[{"user":null, "id":"4", "key":"hskey-auth-Ab-dE_Gh1234-***", "reusable":true, "ephemeral":false, "used":false, "expiration":"2026-11-17T08:15:00Z", "createdAt":"2026-11-17T08:00:00Z", "aclTags":["tag:ci"]}]}`)
	h.edge.on("GET", "/api/v1/apikey", 200,
		`{"apiKeys":[{"id":"1", "prefix":"hskey-api-i8TEBo0QeMi7-***", "expiration":"2026-11-17T03:10:40.490287126Z", "createdAt":"2026-11-17T01:10:40.573751704Z", "lastSeen":null}]}`)
	inst := h.instance(t)
	n, err := inst.GetNode(context.Background(), 7)
	if err != nil {
		t.Fatal(err)
	}
	if n.ID != 7 || n.User == nil || n.User.ID != 3 || n.RegisterMethod != RegisterMethodAuthKey || !n.Online ||
		n.PreAuthKeyID != 9 || len(n.IPAddresses) != 2 || n.IPAddresses[1].String() != "fd7a:115c:a1e0::7" ||
		len(n.ApprovedRoutes) != 1 || n.ApprovedRoutes[0].String() != "10.0.0.0/24" || len(n.SubnetRoutes) != 0 {
		t.Fatalf("decoded node = %+v", n)
	}
	if n.Expiry != nil || n.LastSeen != nil {
		t.Fatal("zero/null timestamps must decode to nil (no expiry)")
	}
	keys, err := inst.ListPreAuthKeys(context.Background())
	if err != nil || len(keys) != 1 || keys[0].KeyPrefix != "Ab-dE_Gh1234" || !keys[0].Key.IsZero() || keys[0].User != nil {
		t.Fatalf("pre-auth keys = %+v, %v", keys, err)
	}
	ak, err := inst.ListAPIKeys(context.Background())
	if err != nil || len(ak) != 1 || ak[0].Prefix != "i8TEBo0QeMi7" || ak[0].LastSeen != nil {
		t.Fatalf("api keys = %+v, %v", ak, err)
	}
}

// TestLocalValidation: invalid input is rejected before any request (§13.4 "Kiểm tra trước").
func TestLocalValidation(t *testing.T) {
	h := newHarness(t, Options{})
	inst := h.instance(t)
	ctx := context.Background()
	past := h.clk.t.Add(-time.Second)
	cases := map[string]func() error{
		"SetTags empty (V-28)":       func() error { _, err := inst.SetTags(ctx, 1, nil); return err },
		"SetTags bad format":         func() error { _, err := inst.SetTags(ctx, 1, []string{"Tag:X"}); return err },
		"SetTags duplicate":          func() error { _, err := inst.SetTags(ctx, 1, []string{"tag:a", "tag:a"}); return err },
		"AuthRegister bad auth id":   func() error { _, err := inst.AuthRegister(ctx, "mg-a", "hskey-authreq-short"); return err },
		"AuthRegister bad user":      func() error { _, err := inst.AuthRegister(ctx, "1abc", testAuthID("z")); return err },
		"AuthApprove bad auth id":    func() error { return inst.AuthApprove(ctx, "../../etc") },
		"CreateUser bad name":        func() error { _, err := inst.CreateUser(ctx, CreateUser{Name: "a/b"}); return err },
		"CreateUser two @":           func() error { _, err := inst.CreateUser(ctx, CreateUser{Name: "a@b@c"}); return err },
		"RenameUser path traversal":  func() error { _, err := inst.RenameUser(ctx, 1, "../x"); return err },
		"RenameNode not a DNS label": func() error { _, err := inst.RenameNode(ctx, 1, "Web_1"); return err },
		"RenameNode slash":           func() error { _, err := inst.RenameNode(ctx, 1, "a/b"); return err },
		"GetNode id 0":               func() error { _, err := inst.GetNode(ctx, 0); return err },
		"route not canonical": func() error {
			_, err := inst.SetApprovedRoutes(ctx, 1, []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")})
			return err
		},
		"PAK without expiration": func() error { _, err := inst.CreatePreAuthKey(ctx, PreAuthKeyOpts{User: 1}); return err },
		"PAK expired": func() error {
			_, err := inst.CreatePreAuthKey(ctx, PreAuthKeyOpts{User: 1, Expiration: past})
			return err
		},
		"PAK without owner or tag": func() error {
			_, err := inst.CreatePreAuthKey(ctx, PreAuthKeyOpts{Expiration: h.clk.t.Add(time.Minute)})
			return err
		},
		"API key without expiration": func() error { _, err := inst.CreateAPIKey(ctx, time.Time{}); return err },
		"ExpireAPIKey garbage":       func() error { return inst.ExpireAPIKey(ctx, "a b") },
		"ExpireAPIKey given a full key": func() error {
			return inst.ExpireAPIKey(ctx, testAPIKey("abcdefghijkl"))
		},
		"ListUsers two filters": func() error { _, err := inst.ListUsers(ctx, UserFilter{ID: 1, Name: "mg-a"}); return err },
		"ExpireNode year 10000": func() error {
			at := time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
			_, err := inst.ExpireNode(ctx, 1, &at)
			return err
		},
		"SetPolicy empty (PL-06)":     func() error { _, err := inst.SetPolicy(ctx, "  "); return err },
		"SetPolicy grants null":       func() error { _, err := inst.SetPolicy(ctx, `{"grants":null}`); return err },
		"CheckPolicy #grants":         func() error { return inst.CheckPolicy(ctx, `{"grants":[],"#grants":[{"src":["*"]}]}`) },
		"CheckPolicy Grants spelling": func() error { return inst.CheckPolicy(ctx, `{"Grants":[]}`) },
	}
	for name, call := range cases {
		t.Run(name, func(t *testing.T) {
			h.edge.reset()
			err := call()
			if !errors.Is(err, ErrValidation) {
				t.Fatalf("err = %v, want validation", err)
			}
			if e, _ := AsError(err); e.ProblemCode() != "validation_failed" || e.Outcome != OutcomeNotApplied {
				t.Fatalf("problem/outcome = %s/%s", e.ProblemCode(), e.Outcome)
			}
			if n := len(h.edge.apiRequests()); n != 0 {
				t.Fatalf("Headscale was called %d time(s)", n)
			}
		})
	}
}

func TestRetryOnlySafeGETs(t *testing.T) {
	h := newHarness(t, Options{Retry: RetryPolicy{Attempts: 3, BaseDelay: 100 * time.Millisecond, MaxDelay: time.Second}})
	var calls atomic.Int32
	h.edge.onFunc("GET", "/api/v1/node", func(w http.ResponseWriter, _ *http.Request, _ []byte) {
		if calls.Add(1) < 3 {
			w.WriteHeader(503)
			_, _ = w.Write([]byte(gw(14, "unavailable")))
			return
		}
		_, _ = w.Write([]byte(`{"nodes":[]}`))
	})
	h.edge.on("POST", "/api/v1/user", 503, gw(14, "unavailable"))
	h.edge.on("GET", "/api/v1/node/5", 404, gw(5, "node not found"))
	inst := h.instance(t)
	ctx := context.Background()

	if _, err := inst.ListNodes(ctx, ""); err != nil {
		t.Fatalf("GET not retried to success: %v", err)
	}
	if calls.Load() != 3 || len(h.sleeps) != 2 {
		t.Fatalf("calls=%d sleeps=%v", calls.Load(), h.sleeps)
	}
	if h.sleeps[0] < 50*time.Millisecond || h.sleeps[0] > 100*time.Millisecond ||
		h.sleeps[1] < 100*time.Millisecond || h.sleeps[1] > 200*time.Millisecond {
		t.Fatalf("backoff out of bounds: %v", h.sleeps)
	}

	h.edge.reset()
	_, err := inst.CreateUser(ctx, CreateUser{Name: "mg-a"})
	if !errors.Is(err, ErrUnavailable) || len(h.edge.apiRequests()) != 1 {
		t.Fatalf("non-idempotent POST must not be retried: err=%v requests=%d", err, len(h.edge.apiRequests()))
	}

	h.edge.reset()
	if _, err := inst.GetNode(ctx, 5); !errors.Is(err, ErrNotFound) || len(h.edge.apiRequests()) != 1 {
		t.Fatalf("a business error must not be retried: %v", err)
	}
}

func TestCircuitBreaker(t *testing.T) {
	h := newHarness(t, Options{Breaker: BreakerConfig{FailureThreshold: 2, OpenFor: time.Minute},
		Retry: RetryPolicy{Attempts: 1}})
	h.edge.on("GET", "/api/v1/node", 503, gw(14, "unavailable"))
	h.edge.on("GET", "/api/v1/node/1", 404, gw(5, "node not found"))
	inst := h.instance(t)
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if _, err := inst.ListNodes(ctx, ""); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	if h.reg.BreakerState(testInstance) != BreakerOpen {
		t.Fatal("breaker did not open after 2 counted failures")
	}
	h.edge.reset()
	_, err := inst.GetNode(ctx, 1)
	if !errors.Is(err, ErrCircuitOpen) || len(h.edge.requests()) != 0 {
		t.Fatalf("open breaker must fail fast without calling: %v (%d requests)", err, len(h.edge.requests()))
	}
	if e, _ := AsError(err); e.ProblemCode() != "instance_unavailable" {
		t.Fatalf("problem code = %s", e.ProblemCode())
	}
	h.clk.advance(time.Minute)
	// The trial call reaches the instance; a business answer (404) proves it is alive and closes the breaker.
	if _, err := inst.GetNode(ctx, 1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("trial call: %v", err)
	}
	if h.reg.BreakerState(testInstance) != BreakerClosed {
		t.Fatal("a business answer must close the breaker")
	}
	// Business errors and storage failures (500) are never counted.
	h.edge.on("GET", "/api/v1/health", 500, gw(2, "pinging database: database is locked"))
	for i := 0; i < 5; i++ {
		_, _ = inst.Health(ctx)
		_, _ = inst.GetNode(ctx, 1)
	}
	if h.reg.BreakerState(testInstance) != BreakerClosed {
		t.Fatal("non-transient errors opened the breaker")
	}
}

func TestTimeoutCountsCallerCancelDoesNot(t *testing.T) {
	h := newHarness(t, Options{Timeout: 50 * time.Millisecond, Retry: RetryPolicy{Attempts: 1},
		Breaker: BreakerConfig{FailureThreshold: 1, OpenFor: time.Hour}})
	h.edge.on("GET", "/api/v1/node", 200, `{"nodes":[]}`)
	inst := h.instance(t)
	h.edge.set(func(f *fakeEdge) { f.delay = 300 * time.Millisecond })

	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(10 * time.Millisecond); cancel() }()
	_, err := inst.ListNodes(ctx, "")
	if !errors.Is(err, context.Canceled) || h.reg.BreakerState(testInstance) != BreakerClosed {
		t.Fatalf("caller cancellation: err=%v breaker=%s", err, h.reg.BreakerState(testInstance))
	}

	_, err = inst.ListNodes(context.Background(), "")
	if !errors.Is(err, ErrUnavailable) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timeout: %v", err)
	}
	if h.reg.BreakerState(testInstance) != BreakerOpen {
		t.Fatal("a timeout must count for the breaker")
	}
}

func TestCredentialReloadAfter401(t *testing.T) {
	h := newHarness(t, Options{})
	h.edge.on("GET", "/api/v1/user", 200, `{"users":[]}`)
	inst := h.instance(t)
	ctx := context.Background()

	// The key was rotated in the SecretStore: the edge now accepts only the new key.
	rotated := testAPIKey("rotatedpfx12")
	h.edge.set(func(f *fakeEdge) { f.apiKey = rotated })
	h.loc.setKey(rotated)
	before := h.loc.count()
	if _, err := inst.ListUsers(ctx, UserFilter{}); err != nil {
		t.Fatalf("call after rotation: %v", err)
	}
	if h.loc.count() != before+1 {
		t.Fatal("the locator was not asked again after 401")
	}
	reqs := h.edge.apiRequests()
	if last := reqs[len(reqs)-1]; last.Header.Get("Authorization") != "Bearer "+rotated {
		t.Fatal("replay did not use the reloaded key")
	}

	// The instance refuses a key the registry still has: suspect a replaced database (§13.4).
	h.edge.set(func(f *fakeEdge) { f.apiKey = testAPIKey("otherprefix1") })
	_, err := inst.ListUsers(ctx, UserFilter{})
	if !errors.Is(err, ErrAPIKeyRejected) {
		t.Fatalf("err = %v, want api key rejected", err)
	}
	if !strings.Contains(h.logBuf.String(), "rejected the platform API key") {
		t.Fatal("no error log for a rejected key")
	}
}

func TestEdgeAnswers(t *testing.T) {
	h := newHarness(t, Options{Retry: RetryPolicy{Attempts: 2, BaseDelay: time.Millisecond}})
	h.edge.on("GET", "/api/v1/user", 200, `{"users":[]}`)
	inst := h.instance(t)
	ctx := context.Background()

	h.edge.set(func(f *fakeEdge) { f.token = strings.Repeat("X", 40) })
	if _, err := inst.ListUsers(ctx, UserFilter{}); !errors.Is(err, ErrEdgeRejected) {
		t.Fatalf("wrong edge token: %v", err)
	}
	h.edge.set(func(f *fakeEdge) { f.token = testEdgeToken; f.slug = "tenant-b" })
	h.edge.reset()
	if _, err := inst.ListUsers(ctx, UserFilter{}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("edge cannot route: %v", err)
	}
	if n := len(h.edge.requests()); n != 2 {
		t.Fatalf("an unroutable GET should be retried (2 attempts), got %d", n)
	}
}

func TestVersionGate(t *testing.T) {
	for v, ok := range map[string]bool{"v0.29.7": true, "v0.29.12": true, "0.29.7": true, "v0.29.6": false,
		"v0.30.0": false, "v0.28.3": false, "v0.29.7-dirty": false, "v1.0.0": false, "": false} {
		h := newHarness(t, Options{})
		h.edge.set(func(f *fakeEdge) { f.version = v })
		_, err := h.reg.ForTenant(context.Background(), testTenant)
		if ok && err != nil {
			t.Errorf("%q rejected: %v", v, err)
		}
		if !ok && !errors.Is(err, ErrUnsupportedVersion) && !errors.Is(err, ErrUpstreamRejected) {
			t.Errorf("%q accepted or wrong error: %v", v, err)
		}
	}
}

func TestRegistryCacheAndInvalidate(t *testing.T) {
	h := newHarness(t, Options{CacheTTL: time.Minute})
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if _, err := h.reg.ForTenant(ctx, testTenant); err != nil {
			t.Fatal(err)
		}
	}
	if h.loc.count() != 1 || len(h.edge.requests()) != 1 {
		t.Fatalf("cache miss on every call: locate=%d requests=%d", h.loc.count(), len(h.edge.requests()))
	}
	h.clk.advance(time.Minute)
	_, _ = h.reg.ForTenant(ctx, testTenant)
	if h.loc.count() != 2 {
		t.Fatal("expired entry was not located again")
	}
	h.reg.Invalidate(testTenant)
	_, _ = h.reg.ForTenant(ctx, testTenant)
	if h.loc.count() != 3 {
		t.Fatal("Invalidate did not drop the entry")
	}
}

func TestLocatorAndTargetErrors(t *testing.T) {
	ctx := context.Background()
	reg := NewRegistry(StaticLocator{}, Options{})
	if _, err := reg.ForTenant(ctx, testTenant); !errors.Is(err, ErrUnavailable) || !errors.Is(err, ErrNoInstance) {
		t.Fatalf("no instance: %v", err)
	}
	good := Target{InstanceID: testInstance, Slug: "tenant-a", AdminURL: "http://10.249.2.2:8081",
		APIKey: NewSecret("k"), EdgeToken: NewSecret(testEdgeToken)}
	bad := map[string]func(t *Target){
		"admin URL with path":     func(t *Target) { t.AdminURL = "http://10.249.2.2:8081/api" },
		"admin URL with query":    func(t *Target) { t.AdminURL = "http://10.249.2.2:8081?x=1" },
		"admin URL with userinfo": func(t *Target) { t.AdminURL = "http://u:p@10.249.2.2:8081" },
		"admin URL scheme":        func(t *Target) { t.AdminURL = "ftp://10.249.2.2" },
		"slug":                    func(t *Target) { t.Slug = "Tenant_A" },
		"edge token":              func(t *Target) { t.EdgeToken = NewSecret("short") },
		"api key":                 func(t *Target) { t.APIKey = Secret{} },
		"instance id":             func(t *Target) { t.InstanceID = [16]byte{} },
	}
	for name, mutate := range bad {
		tg := good
		mutate(&tg)
		reg := NewRegistry(StaticLocator{testTenant: tg}, Options{})
		if _, err := reg.ForTenant(ctx, testTenant); !errors.Is(err, ErrInternal) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := reg.ForTenant(ctx, [16]byte{}); !errors.Is(err, ErrInternal) {
		t.Errorf("nil tenant: %v", err)
	}
}

func TestRedirectIsNotFollowed(t *testing.T) {
	var leaked atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { leaked.Add(1) }))
	defer other.Close()
	h := newHarness(t, Options{Retry: RetryPolicy{Attempts: 1}})
	h.edge.onFunc("GET", "/api/v1/user", func(w http.ResponseWriter, r *http.Request, _ []byte) {
		http.Redirect(w, r, other.URL+"/steal", http.StatusFound)
	})
	inst := h.instance(t)
	if _, err := inst.ListUsers(context.Background(), UserFilter{}); !errors.Is(err, ErrUpstreamRejected) {
		t.Fatalf("redirect: %v", err)
	}
	if leaked.Load() != 0 {
		t.Fatal("the adapter followed a redirect (X-MG-Token would leak)")
	}
}

func TestSetPolicyFlow(t *testing.T) {
	const doc = `{"grants":[{"src":["autogroup:member"],"dst":["autogroup:self"],"ip":["*"]}],"ssh":[]}`
	h := newHarness(t, Options{})
	h.edge.on("POST", "/api/v1/policy/check", 200, `{}`)
	h.edge.on("PUT", "/api/v1/policy", 200, `{"policy":`+mustJSON(doc)+`, "updatedAt":"2026-11-17T08:00:00Z"}`)
	inst := h.instance(t)
	ctx := context.Background()

	p, err := inst.SetPolicy(ctx, doc)
	if err != nil || p.Data != doc {
		t.Fatalf("SetPolicy: %v %+v", err, p)
	}
	reqs := h.edge.apiRequests()
	if len(reqs) != 2 || reqs[0].Path != "/api/v1/policy/check" || reqs[1].Method != "PUT" {
		t.Fatalf("CheckPolicy must run before SetPolicy: %+v", reqs)
	}

	// Rejected by CheckPolicy: never PUT, nothing applied.
	h.edge.on("POST", "/api/v1/policy/check", 400, gw(3, `parsing policy: unknown group "group:x"`))
	h.edge.reset()
	_, err = inst.SetPolicy(ctx, doc)
	if e, _ := AsError(err); !errors.Is(err, ErrPolicyRejected) || e.Outcome != OutcomeNotApplied || len(h.edge.apiRequests()) != 1 {
		t.Fatalf("check rejection: %v", err)
	}

	// Fails after the in-memory swap (V-26): outcome unknown.
	h.edge.on("POST", "/api/v1/policy/check", 200, `{}`)
	h.edge.on("PUT", "/api/v1/policy", 500, gw(2, "database or disk is full"))
	_, err = inst.SetPolicy(ctx, doc)
	if e, _ := AsError(err); !errors.Is(err, ErrPolicyRejected) || e.Outcome != OutcomeUnknown {
		t.Fatalf("storage failure: %v", err)
	}

	// Stored something else: unknown.
	h.edge.on("PUT", "/api/v1/policy", 200, `{"policy":"{}", "updatedAt":"2026-11-17T08:00:00Z"}`)
	_, err = inst.SetPolicy(ctx, doc)
	if e, _ := AsError(err); e == nil || e.Outcome != OutcomeUnknown {
		t.Fatalf("mismatching echo: %v", err)
	}
}

func TestGetPolicyNoPolicy(t *testing.T) {
	h := newHarness(t, Options{})
	inst := h.instance(t)
	h.edge.on("GET", "/api/v1/policy", 500, gw(2, "loading ACL from database: acl policy not found"))
	if _, err := inst.GetPolicy(context.Background()); !errors.Is(err, ErrNoPolicy) {
		t.Fatalf("no row: %v", err)
	}
	h.edge.on("GET", "/api/v1/policy", 200, `{"policy":"", "updatedAt":"2026-11-17T08:00:00Z"}`)
	if _, err := inst.GetPolicy(context.Background()); !errors.Is(err, ErrNoPolicy) {
		t.Fatalf("empty stored policy (PL-06): %v", err)
	}
}

func TestWriteTransportErrorOutcome(t *testing.T) {
	h := newHarness(t, Options{Retry: RetryPolicy{Attempts: 1}})
	h.edge.onFunc("POST", "/api/v1/user", func(w http.ResponseWriter, _ *http.Request, _ []byte) {
		hj, _ := w.(http.Hijacker)
		c, _, _ := hj.Hijack()
		_ = c.Close() // request received, answer lost
	})
	inst := h.instance(t)
	_, err := inst.CreateUser(context.Background(), CreateUser{Name: "mg-a"})
	if e, _ := AsError(err); !errors.Is(err, ErrUnavailable) || e.Outcome != OutcomeUnknown {
		t.Fatalf("lost answer to a write must be outcome unknown: %v", err)
	}
	// The edge's bare 404 when the instance died in the middle of a write (observed, V-26): outcome unknown for the
	// write, not applied for a read.
	bare404 := func(w http.ResponseWriter, _ *http.Request, _ []byte) { w.WriteHeader(http.StatusNotFound) }
	h.edge.onFunc("POST", "/api/v1/auth/register", bare404)
	h.edge.onFunc("GET", "/api/v1/node", bare404)
	_, err = inst.AuthRegister(context.Background(), "mg-a", testAuthID("w"))
	if e, _ := AsError(err); !errors.Is(err, ErrUnavailable) || e.Outcome != OutcomeUnknown {
		t.Fatalf("edge 404 on a write: %v", err)
	}
	_, err = inst.ListNodes(context.Background(), "")
	if e, _ := AsError(err); !errors.Is(err, ErrUnavailable) || e.Outcome != OutcomeNotApplied {
		t.Fatalf("edge 404 on a read: %v", err)
	}
	// A dial failure never sent the request.
	h.loc.mu.Lock()
	h.loc.t.AdminURL = "http://127.0.0.1:1"
	h.loc.mu.Unlock()
	h.reg.Invalidate(testTenant)
	_, err = h.reg.ForTenant(context.Background(), testTenant)
	if e, _ := AsError(err); !errors.Is(err, ErrUnavailable) || e.Outcome != OutcomeNotApplied {
		t.Fatalf("dial failure: %v", err)
	}
}

func TestAPIKeyPrefix(t *testing.T) {
	if got := APIKeyPrefix(NewSecret(testAPIKey("a-b_c-d_e-f_"))); got != "a-b_c-d_e-f_" {
		t.Fatalf("APIKeyPrefix = %q", got)
	}
	if got := APIKeyPrefix(NewSecret("not a key")); got != "" {
		t.Fatalf("APIKeyPrefix(garbage) = %q", got)
	}
}

func mustJSON(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
