package hostsapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/authz"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/authzhook"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/gen"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/logx"
	"github.com/zhaduchanhzz/network-access-mesh/internal/platform"
)

// fakeService records what the handlers asked and answers what the test sets. The rules themselves are tested on
// PostgreSQL (internal/platform/hosts_test.go) and through the composed API (tests/security/hostsauthz).
type fakeService struct {
	filter platform.HostFilter
	config platform.HostConfig
	patch  platform.HostPatch
	write  platform.HostWrite
	id     uuid.UUID
	view   platform.HostView
	page   platform.HostPage
	err    error
	calls  int
}

func (f *fakeService) ListHosts(_ context.Context, fl platform.HostFilter) (platform.HostPage, error) {
	f.calls++
	f.filter = fl
	return f.page, f.err
}

func (f *fakeService) GetHost(_ context.Context, id uuid.UUID) (platform.HostView, error) {
	f.calls++
	f.id = id
	return f.view, f.err
}

func (f *fakeService) CreateHost(_ context.Context, in platform.HostConfig, w platform.HostWrite) (platform.HostView, error) {
	f.calls++
	f.config, f.write = in, w
	return f.view, f.err
}

func (f *fakeService) UpdateHost(_ context.Context, id uuid.UUID, p platform.HostPatch, w platform.HostWrite) (platform.HostView, error) {
	f.calls++
	f.id, f.patch, f.write = id, p, w
	return f.view, f.err
}

// fakeAuthorizer grants every operation with a fixed decision (authorization itself: P2-T07 and the matrix).
type fakeAuthorizer struct{ d authz.Decision }

func (a fakeAuthorizer) RequireOperation(context.Context, string, uuid.UUID) (authz.Decision, error) {
	return a.d, nil
}

var operator = uuid.MustParse("0194f3a2-7c1e-7d40-8a55-0d1b2c3e4f99")

func noSession(next http.Handler) http.Handler { return next }

func noAudit(f gen.StrictHandlerFunc, _ string) gen.StrictHandlerFunc { return f }

// noDecision is an authorization hook that lets the request through without a decision in the context (a wiring
// mistake the write handlers must refuse).
func noDecision(f gen.StrictHandlerFunc, _ string) gen.StrictHandlerFunc { return f }

func serve(t *testing.T, svc *fakeService, authz gen.StrictMiddlewareFunc, method, path, body string, hdr map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	h, err := httpapi.New(httpapi.Options{Logger: logx.New(io.Discard, slog.LevelInfo, "api"),
		Handlers: httpapi.Handlers{Hosts: New(svc)}, Hooks: httpapi.Hooks{Authz: authz, Session: noSession, Audit: noAudit}})
	if err != nil {
		t.Fatal(err)
	}
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	r := httptest.NewRequestWithContext(t.Context(), method, "https://admin.mg.test/api/v1"+path, rd)
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

func granted() gen.StrictMiddlewareFunc {
	return authzhook.Authz(fakeAuthorizer{d: authz.Decision{Principal: authz.Principal{IdentityID: operator}}})
}

type problemBody struct {
	Code   string `json:"code"`
	Detail string `json:"detail"`
	Errors []struct {
		Field string `json:"field"`
		Code  string `json:"code"`
	} `json:"errors"`
}

func problemOf(t *testing.T, rec *httptest.ResponseRecorder) problemBody {
	t.Helper()
	var p problemBody
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
		t.Fatalf("not a problem: %s", rec.Body)
	}
	return p
}

func sampleView() platform.HostView {
	return platform.HostView{
		Host: platform.Host{ID: uuid.MustParse("0194f3a2-7c1e-7d40-8a55-0d1b2c3e4f51"), Name: "mg-staging", Region: "lab",
			Status: platform.HostActive, RunUIDFirst: 30000, RunUIDLast: 39999, TenantNetPool: netip.MustParsePrefix("10.250.0.0/16"),
			MaxInstances: 100, PublicEntry: netip.MustParseAddr("203.0.113.7"), EntryMode: platform.EntryVPSGateway},
		CreatedAt: time.Date(2026, 11, 18, 1, 2, 3, 0, time.UTC), UpdatedAt: time.Date(2026, 11, 18, 4, 5, 6, 0, time.UTC),
		Usage: platform.HostUsage{LiveInstances: 2, ByStatus: map[string]int{"running": 2}, RunUIDsFree: 9996, NetSlotsFree: 8190},
		ETag:  `"0123456789abcdef0123456789abcdef"`,
	}
}

// TestHostMapping — schema Host from the platform view, ETag header on reads and writes.
func TestHostMapping(t *testing.T) {
	svc := &fakeService{view: sampleView()}
	id := svc.view.ID.String()
	rec := serve(t, svc, granted(), http.MethodGet, "/platform/hosts/"+id, "", nil)
	if rec.Code != http.StatusOK || rec.Header().Get("ETag") != svc.view.ETag || svc.id != svc.view.ID {
		t.Fatalf("get: %d %s %v", rec.Code, rec.Body, rec.Header())
	}
	var h gen.Host
	if err := json.Unmarshal(rec.Body.Bytes(), &h); err != nil {
		t.Fatal(err)
	}
	if h.Name != "mg-staging" || h.Status != gen.HostStatus("active") || h.Capacity.MaxInstances != 100 || h.PublicEntry.Ipv4 == nil ||
		*h.PublicEntry.Ipv4 != "203.0.113.7" || h.PublicEntry.Mode == nil || *h.PublicEntry.Mode != "vps_gateway" ||
		h.RunUidRange != (gen.HostRange{First: 30000, Last: 39999}) || h.StunPortRange != nil || h.TenantNetPool != "10.250.0.0/16" ||
		h.Usage.LiveInstances != 2 || h.Usage.ByStatus["running"] != 2 || h.Usage.RunUidsFree != 9996 || h.Usage.NetSlotsFree != 8190 ||
		h.Etag != svc.view.ETag || h.LastHeartbeatAt != nil {
		t.Errorf("host %+v", h)
	}
	if !strings.Contains(rec.Body.String(), `"last_heartbeat_at":null`) || strings.Contains(rec.Body.String(), "stun_port_range") {
		t.Errorf("nullable / optional fields: %s", rec.Body)
	}
	// no public entry, a STUN range, a heartbeat
	v := sampleView()
	v.PublicEntry, v.EntryMode, v.STUNPortFirst, v.STUNPortLast = netip.Addr{}, "", 40000, 40100
	hb := time.Date(2026, 11, 18, 5, 0, 0, 0, time.UTC)
	v.LastHeartbeatAt = &hb
	g := toHost(v)
	if g.PublicEntry.Ipv4 != nil || g.PublicEntry.Mode != nil || g.StunPortRange == nil || *g.StunPortRange != (gen.HostRange{First: 40000, Last: 40100}) ||
		g.LastHeartbeatAt == nil || !g.LastHeartbeatAt.Equal(hb) {
		t.Errorf("toHost %+v", g)
	}
	// another id than asked ⇒ 404
	svc.view.ID = uuid.New()
	if rec := serve(t, svc, granted(), http.MethodGet, "/platform/hosts/"+id, "", nil); rec.Code != http.StatusNotFound {
		t.Errorf("mismatched id: %d", rec.Code)
	}
}

func TestListHosts(t *testing.T) {
	svc := &fakeService{page: platform.HostPage{Items: []platform.HostView{sampleView()}, NextCursor: "abc"}}
	rec := serve(t, svc, granted(), http.MethodGet, "/platform/hosts?limit=5&cursor=xyz&status=draining&region=lab", "", nil)
	if rec.Code != http.StatusOK || svc.filter != (platform.HostFilter{Limit: 5, Cursor: "xyz", Status: "draining", Region: "lab"}) {
		t.Fatalf("list: %d %+v %s", rec.Code, svc.filter, rec.Body)
	}
	var l gen.HostList
	if err := json.Unmarshal(rec.Body.Bytes(), &l); err != nil || len(l.Items) != 1 || l.NextCursor == nil || *l.NextCursor != "abc" {
		t.Errorf("list body %s", rec.Body)
	}
	svc.page = platform.HostPage{}
	if rec := serve(t, svc, granted(), http.MethodGet, "/platform/hosts", "", nil); rec.Code != http.StatusOK ||
		!strings.Contains(rec.Body.String(), `"items":[]`) || !strings.Contains(rec.Body.String(), `"next_cursor":null`) {
		t.Errorf("empty list: %s", rec.Body)
	}
	// the binding does not enforce the schema bounds: an explicit limit=0 reaches the service as out of range (-1, not
	// "default"), an unknown status as is — the service refuses both (ErrInvalid, below); an empty region never leaves
	if serve(t, svc, granted(), http.MethodGet, "/platform/hosts?limit=0&status=gone", "", nil); svc.filter.Limit != -1 ||
		svc.filter.Status != "gone" {
		t.Errorf("limit=0: %+v", svc.filter)
	}
	svc.calls = 0
	if rec := serve(t, svc, granted(), http.MethodGet, "/platform/hosts?region=", "", nil); rec.Code != http.StatusUnprocessableEntity ||
		problemOf(t, rec).Code != "validation_failed" || svc.calls != 0 {
		t.Errorf("empty region: %d %s", rec.Code, rec.Body)
	}
	svc.err = platform.ErrInvalid
	if rec := serve(t, svc, granted(), http.MethodGet, "/platform/hosts?cursor=bad", "", nil); rec.Code != http.StatusUnprocessableEntity ||
		problemOf(t, rec).Errors[0].Field != "query" {
		t.Errorf("service refusal: %d %s", rec.Code, rec.Body)
	}
}

const createBody = `{"name":"mg-staging","region":"lab","status":"draining","capacity":{"max_instances":7},
	"public_entry":{"ipv4":"203.0.113.7","mode":"vps_gateway"},"run_uid_range":{"first":30000,"last":39999},
	"stun_port_range":{"first":40000,"last":40100},"tenant_net_pool":"10.250.0.0/16"}`

func TestCreateHost(t *testing.T) {
	svc := &fakeService{view: sampleView()}
	rec := serve(t, svc, granted(), http.MethodPost, "/platform/hosts", createBody, map[string]string{"Idempotency-Key": "key-0001"})
	if rec.Code != http.StatusCreated || rec.Header().Get("ETag") != svc.view.ETag {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	c := svc.config
	if c.Name != "mg-staging" || c.Region != "lab" || c.Status != "draining" || c.MaxInstances == nil || *c.MaxInstances != 7 ||
		c.PublicEntry.IPv4 == nil || *c.PublicEntry.IPv4 != "203.0.113.7" || c.PublicEntry.Mode == nil || *c.PublicEntry.Mode != "vps_gateway" ||
		c.RunUIDRange != (platform.IntRange{First: 30000, Last: 39999}) || c.STUNPortRange == nil ||
		*c.STUNPortRange != (platform.IntRange{First: 40000, Last: 40100}) || c.TenantNetPool != "10.250.0.0/16" {
		t.Errorf("config %+v", c)
	}
	idem := svc.write.Idempotency
	if idem == nil || idem.IdentityID != operator || idem.Key != "key-0001" || len(idem.Hash) != 32 || svc.write.System != nil {
		t.Fatalf("write %+v", svc.write)
	}
	// the hash covers the request, not its formatting
	first := idem.Hash
	compact := strings.Join(strings.Fields(createBody), "")
	serve(t, svc, granted(), http.MethodPost, "/platform/hosts", compact, map[string]string{"Idempotency-Key": "key-0001"})
	if string(svc.write.Idempotency.Hash) != string(first) {
		t.Error("the same request with other whitespace hashes differently")
	}
	serve(t, svc, granted(), http.MethodPost, "/platform/hosts", strings.Replace(createBody, `"lab"`, `"lab2"`, 1),
		map[string]string{"Idempotency-Key": "key-0001"})
	if string(svc.write.Idempotency.Hash) == string(first) {
		t.Error("another request hashes the same")
	}
	if want := jobs.RequestHash("POST", "/platform/hosts", []byte(compact)); string(want) != string(first) {
		t.Error("hash differs from jobs.RequestHash of the request")
	}
	// minimal body: defaults stay unset (the service applies them)
	serve(t, svc, granted(), http.MethodPost, "/platform/hosts",
		`{"name":"h1","region":"lab","run_uid_range":{"first":30000,"last":30001},"tenant_net_pool":"10.250.0.0/24"}`,
		map[string]string{"Idempotency-Key": "key-0002"})
	if c := svc.config; c.Status != "" || c.MaxInstances != nil || c.PublicEntry.IPv4 != nil || c.PublicEntry.Mode != nil || c.STUNPortRange != nil {
		t.Errorf("minimal config %+v", c)
	}
	// the jsonb objects are read as the database reads them: 1e2 is the integer 100, null is absent
	serve(t, svc, granted(), http.MethodPost, "/platform/hosts", `{"name":"h1","capacity":{"max_instances":1e2},"public_entry":null}`,
		map[string]string{"Idempotency-Key": "key-0004"})
	if c := svc.config; c.MaxInstances == nil || *c.MaxInstances != 100 || c.PublicEntry.IPv4 != nil {
		t.Errorf("1e2: %+v", c)
	}
	// refused before the service: missing key, body that does not decode, a jsonb object the CHECKs refuse, no decision
	key := map[string]string{"Idempotency-Key": "key-0003"}
	for name, c := range map[string]struct {
		authz gen.StrictMiddlewareFunc
		body  string
		hdr   map[string]string
		code  int
		field string
	}{
		"no key":          {granted(), createBody, nil, http.StatusUnprocessableEntity, "Idempotency-Key"},
		"invalid json":    {granted(), `{"name":`, key, http.StatusUnprocessableEntity, "body"},
		"string capacity": {granted(), `{"name":"h","capacity":{"max_instances":"many"}}`, key, http.StatusUnprocessableEntity, "capacity.max_instances"},
		"fraction":        {granted(), `{"name":"h","capacity":{"max_instances":10.0}}`, key, http.StatusUnprocessableEntity, "capacity.max_instances"},
		"empty capacity":  {granted(), `{"name":"h","capacity":{}}`, key, http.StatusUnprocessableEntity, "capacity.max_instances"},
		"capacity key":    {granted(), `{"name":"h","capacity":{"max_instances":1,"cpu":2}}`, key, http.StatusUnprocessableEntity, "capacity"},
		"ipv6 entry":      {granted(), `{"name":"h","public_entry":{"ipv6":"2001:db8::1"}}`, key, http.StatusUnprocessableEntity, "public_entry"},
		"numeric ipv4":    {granted(), `{"name":"h","public_entry":{"ipv4":3405803783}}`, key, http.StatusUnprocessableEntity, "public_entry.ipv4"},
		"array entry":     {granted(), `{"name":"h","public_entry":[]}`, key, http.StatusUnprocessableEntity, "public_entry"},
		"no decision":     {noDecision, createBody, key, http.StatusInternalServerError, ""},
	} {
		svc.calls = 0
		rec := serve(t, svc, c.authz, http.MethodPost, "/platform/hosts", c.body, c.hdr)
		if rec.Code != c.code || svc.calls != 0 {
			t.Errorf("%s: %d (calls %d) %s", name, rec.Code, svc.calls, rec.Body)
			continue
		}
		if p := problemOf(t, rec); c.field != "" && (len(p.Errors) == 0 || p.Errors[0].Field != c.field) {
			t.Errorf("%s: errors %+v, want %s", name, p.Errors, c.field)
		}
	}
	// PATCH reads them the same way
	svc.calls = 0
	if rec := serve(t, svc, granted(), http.MethodPatch, "/platform/hosts/"+svc.view.ID.String(), `{"public_entry":{"ipv4":"203.0.113.7","ipv6":"::1"}}`,
		map[string]string{"If-Match": svc.view.ETag}); rec.Code != http.StatusUnprocessableEntity || svc.calls != 0 {
		t.Errorf("patch with ipv6: %d %s", rec.Code, rec.Body)
	}
}

func TestUpdateHost(t *testing.T) {
	svc := &fakeService{view: sampleView()}
	id := svc.view.ID.String()
	body := `{"status":"disabled","capacity":{"max_instances":3},"public_entry":{},"region":"hn1",
		"run_uid_range":{"first":30000,"last":30099},"stun_port_range":{"first":40000,"last":40001},"tenant_net_pool":"10.251.0.0/16"}`
	rec := serve(t, svc, granted(), http.MethodPatch, "/platform/hosts/"+id, body, map[string]string{"If-Match": svc.view.ETag})
	if rec.Code != http.StatusOK || rec.Header().Get("ETag") != svc.view.ETag || svc.id != svc.view.ID {
		t.Fatalf("patch: %d %s", rec.Code, rec.Body)
	}
	p, w := svc.patch, svc.write
	if p.Status == nil || *p.Status != "disabled" || p.MaxInstances == nil || *p.MaxInstances != 3 || p.PublicEntry == nil ||
		p.PublicEntry.IPv4 != nil || p.PublicEntry.Mode != nil || p.Region == nil || *p.Region != "hn1" || p.RunUIDRange == nil ||
		*p.RunUIDRange != (platform.IntRange{First: 30000, Last: 30099}) || p.STUNPortRange == nil || p.TenantNetPool == nil ||
		*p.TenantNetPool != "10.251.0.0/16" || w.IfMatch != svc.view.ETag || w.Idempotency != nil || w.System != nil {
		t.Errorf("patch %+v write %+v", p, w)
	}
	// absent fields stay nil; no If-Match reaches the service as "" (it answers 428)
	serve(t, svc, granted(), http.MethodPatch, "/platform/hosts/"+id, `{"status":"active"}`, nil)
	if p := svc.patch; p.Status == nil || p.MaxInstances != nil || p.PublicEntry != nil || p.Region != nil || p.RunUIDRange != nil ||
		p.STUNPortRange != nil || p.TenantNetPool != nil || svc.write.IfMatch != "" {
		t.Errorf("partial patch %+v %+v", p, svc.write)
	}
	svc.calls = 0
	if rec := serve(t, svc, noDecision, http.MethodPatch, "/platform/hosts/"+id, `{"status":"active"}`, nil); rec.Code != http.StatusInternalServerError ||
		svc.calls != 0 {
		t.Errorf("no decision: %d", rec.Code)
	}
}

// TestFailures — every service error has its problem; the detail never carries a submitted value or a cause.
func TestFailures(t *testing.T) {
	for _, c := range []struct {
		err    error
		status int
		code   string
		field  string
		retry  string
	}{
		{platform.ErrNotFound, http.StatusNotFound, "not_found", "", ""},
		{&platform.ValidationError{Fields: []platform.FieldError{{Field: "public_entry.ipv4", Code: "inside_pool", Message: "must lie outside tenant_net_pool"}}},
			http.StatusUnprocessableEntity, "validation_failed", "public_entry.ipv4", ""},
		{&platform.HostConflictError{Reason: platform.ConflictNameTaken}, http.StatusConflict, "conflict", "", ""},
		{&platform.HostConflictError{Reason: platform.ConflictCapacityBelowLive, Live: 4}, http.StatusConflict, "conflict", "", ""},
		{&platform.HostConflictError{Reason: platform.ConflictAllocationInUse, Fields: []string{"tenant_net_pool"}, Live: 1}, http.StatusConflict, "conflict", "", ""},
		{&platform.IdempotencyBusyError{RetryAfter: 2500 * time.Millisecond}, http.StatusConflict, "conflict", "", "3"},
		{platform.ErrIdempotencyKeyReuse, http.StatusUnprocessableEntity, "idempotency_key_reuse", "", ""},
		{platform.ErrPreconditionRequired, http.StatusPreconditionRequired, "precondition_required", "", ""},
		{platform.ErrPreconditionFailed, http.StatusPreconditionFailed, "precondition_failed", "", ""},
		{errors.New("db exploded at 10.250.0.1"), http.StatusInternalServerError, "internal_error", "", ""},
	} {
		svc := &fakeService{err: c.err}
		rec := serve(t, svc, granted(), http.MethodPatch, "/platform/hosts/"+uuid.NewString(), `{"status":"active"}`,
			map[string]string{"If-Match": `"x"`})
		p := problemOf(t, rec)
		if rec.Code != c.status || p.Code != c.code || rec.Header().Get("Retry-After") != c.retry {
			t.Errorf("%v: %d %s retry %q", c.err, rec.Code, p.Code, rec.Header().Get("Retry-After"))
		}
		if c.field != "" && (len(p.Errors) != 1 || p.Errors[0].Field != c.field || p.Errors[0].Code != "inside_pool") {
			t.Errorf("%v: errors %+v", c.err, p.Errors)
		}
		if strings.Contains(rec.Body.String(), "10.250.0.1") || strings.Contains(p.Detail, "exploded") {
			t.Errorf("%v: cause leaked: %s", c.err, rec.Body)
		}
	}
}
