package devicesapi

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
	"github.com/zhaduchanhzz/network-access-mesh/internal/devices"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/authzhook"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/gen"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/problem"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/logx"
)

// fakeService records what the handlers pass and answers what the test sets.
type fakeService struct {
	access  devices.Access
	query   devices.ListQuery
	kind    string
	key     string
	name    string
	err     error
	device  devices.Device
	job     jobs.Job
	revoked devices.RevokeResult
	calls   int
}

func (f *fakeService) List(_ context.Context, _ uuid.UUID, a devices.Access, q devices.ListQuery) (devices.Page, error) {
	f.calls++
	f.access, f.query = a, q
	return devices.Page{Items: []devices.Device{f.device}, NextCursor: "next"}, f.err
}

func (f *fakeService) Get(_ context.Context, _, _ uuid.UUID, a devices.Access) (devices.Device, error) {
	f.calls++
	f.access = a
	return f.device, f.err
}

func (f *fakeService) Rename(_ context.Context, _, _ uuid.UUID, a devices.Access, name string) (devices.Device, error) {
	f.calls++
	f.access, f.name = a, name
	return f.device, f.err
}

func (f *fakeService) Revoke(_ context.Context, _, _ uuid.UUID, a devices.Access, kind, key string) (devices.RevokeResult, error) {
	f.calls++
	f.access, f.kind, f.key = a, kind, key
	return f.revoked, f.err
}

func (f *fakeService) RequestSync(_ context.Context, _ uuid.UUID, a devices.Access, key string) (jobs.Job, error) {
	f.calls++
	f.access, f.key = a, key
	return f.job, f.err
}

// fakeAuthorizer grants every operation with a fixed decision (the authorization itself is tested by P2-T07; the
// composed test with real sessions is tests/security/devicesauthz).
type fakeAuthorizer struct{ d authz.Decision }

func (a fakeAuthorizer) RequireOperation(context.Context, string, uuid.UUID) (authz.Decision, error) {
	return a.d, nil
}

func serve(t *testing.T, svc *fakeService, authorizer gen.StrictMiddlewareFunc, method, path, body string, hdr http.Header) *httptest.ResponseRecorder {
	t.Helper()
	h, err := httpapi.New(httpapi.Options{Logger: logx.New(io.Discard, slog.LevelInfo, "api"),
		Handlers: httpapi.Handlers{Devices: New(svc)}, Hooks: httpapi.Hooks{Authz: authorizer, Session: noSession, Audit: noAudit}})
	if err != nil {
		t.Fatal(err)
	}
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	r := httptest.NewRequestWithContext(t.Context(), method, "https://app.mg.test/api/v1"+path, rd)
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	for k, v := range hdr {
		r.Header[k] = v
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

func problemOfResponse(t *testing.T, rec *httptest.ResponseRecorder) gen.Problem {
	t.Helper()
	var p gen.Problem
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
		t.Fatalf("not a problem: %s", rec.Body.String())
	}
	return p
}

// TestHandlersMapRequestsAndResponses: parameters, the decision's own-resource obligation and the actor reach the
// service; the device and job are mapped to the schemas; 202 carries the Location of the tenant's job.
func TestHandlersMapRequestsAndResponses(t *testing.T) {
	tenant, dev, job, member, identity := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	now := time.Date(2026, 11, 17, 8, 0, 0, 0, time.UTC)
	d := devices.Device{ID: dev, Name: "host", GivenName: "laptop", IPAddresses: []netip.Addr{netip.MustParseAddr("100.64.0.1")},
		Owner: &devices.Owner{MembershipID: member, DisplayName: "Alice"}, Tags: []string{}, RegisterMethod: "authkey",
		AdvertisedRoutes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}, RoutesETag: `"r"`, TagsETag: `"t"`,
		Revocation: devices.Revocation{State: devices.StatePending, Kind: devices.RevokeExpire, RequestedAt: &now}, SyncedAt: now}
	svc := &fakeService{device: d, revoked: devices.RevokeResult{Device: d, JobID: job, Created: true},
		job: jobs.Job{ID: job, Kind: devices.KindSync, Status: jobs.StatusQueued, Steps: []jobs.Step{}, CreatedAt: now}}
	authorizer := authzhook.Authz(fakeAuthorizer{d: authz.Decision{OwnOnly: true, MembershipID: member,
		Principal: authz.Principal{IdentityID: identity}}})
	base := "/tenants/" + tenant.String() + "/devices"

	rec := serve(t, svc, authorizer, http.MethodGet, base+"?limit=7&online=true&tag=tag:x&q=lap&fresh=true&owner="+member.String(), "", nil)
	var list gen.DeviceList
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &list) != nil || len(list.Items) != 1 || list.NextCursor == nil {
		t.Fatalf("list: %d %s", rec.Code, rec.Body.String())
	}
	q := svc.query
	if q.Limit != 7 || q.Online == nil || !*q.Online || q.Tag != "tag:x" || q.Search != "lap" || !q.Fresh || q.Owner == nil || *q.Owner != member {
		t.Errorf("query passed: %+v", q)
	}
	if !svc.access.OwnOnly || svc.access.MembershipID != member || svc.access.IdentityID != identity {
		t.Errorf("access passed: %+v", svc.access)
	}
	got := list.Items[0]
	if got.Id != dev || got.IpAddresses[0] != "100.64.0.1" || got.Owner == nil || got.Owner.DisplayName != "Alice" ||
		got.Revocation.Kind == nil || *got.Revocation.Kind != gen.DeviceRevocationKindExpire || got.Routes.Advertised[0] != "10.0.0.0/24" ||
		got.Routes.Approved == nil || got.Tags == nil || got.TagsEtag != `"t"` {
		t.Errorf("device: %+v", got)
	}

	rec = serve(t, svc, authorizer, http.MethodPost, base+"/"+dev.String()+"/expire", "", http.Header{"Idempotency-Key": {"key-12345678"}})
	if rec.Code != http.StatusAccepted || rec.Header().Get("Location") != "/api/v1/tenants/"+tenant.String()+"/jobs/"+job.String() ||
		svc.kind != devices.RevokeExpire || svc.key != "key-12345678" {
		t.Errorf("expire: %d %q kind %s key %s", rec.Code, rec.Header().Get("Location"), svc.kind, svc.key)
	}
	rec = serve(t, svc, authorizer, http.MethodDelete, base+"/"+dev.String(), "", nil)
	if rec.Code != http.StatusAccepted || svc.kind != devices.RevokeDelete || svc.key != "" {
		t.Errorf("delete: %d kind %s", rec.Code, svc.kind)
	}
	rec = serve(t, svc, authorizer, http.MethodPatch, base+"/"+dev.String(), `{"given_name":"new-name"}`, nil)
	if rec.Code != http.StatusOK || svc.name != "new-name" {
		t.Errorf("rename: %d %s", rec.Code, rec.Body.String())
	}
	rec = serve(t, svc, authorizer, http.MethodPost, base+"/sync", "", http.Header{"Idempotency-Key": {"sync-12345678"}})
	var j gen.Job
	if rec.Code != http.StatusAccepted || json.Unmarshal(rec.Body.Bytes(), &j) != nil || j.Id != job || j.Kind != devices.KindSync ||
		rec.Header().Get("Location") != "/api/v1/tenants/"+tenant.String()+"/jobs/"+job.String() {
		t.Errorf("sync: %d %s", rec.Code, rec.Body.String())
	}
	rec = serve(t, svc, authorizer, http.MethodGet, base+"/"+dev.String(), "", nil)
	if rec.Code != http.StatusOK {
		t.Errorf("get: %d", rec.Code)
	}
	// Owner never shown for a tagged device; revocation kind absent when never revoked.
	if out := device(devices.Device{Tags: []string{"tag:a"}, Revocation: devices.Revocation{State: devices.StateNone}}); out.Owner != nil ||
		out.Revocation.Kind != nil || out.IpAddresses == nil {
		t.Errorf("tagged device mapping: %+v", out)
	}
}

// TestHandlersFailClosed: without the authorization decision the handlers answer 500 and never call the service;
// parameter errors are 422 before the service.
func TestHandlersFailClosed(t *testing.T) {
	svc := &fakeService{}
	tenant := uuid.New()
	noDecision := gen.StrictMiddlewareFunc(func(f gen.StrictHandlerFunc, _ string) gen.StrictHandlerFunc { return f })
	rec := serve(t, svc, noDecision, http.MethodGet, "/tenants/"+tenant.String()+"/devices", "", nil)
	if rec.Code != http.StatusInternalServerError || svc.calls != 0 {
		t.Errorf("without decision: %d, %d service calls", rec.Code, svc.calls)
	}
	authorizer := authzhook.Authz(fakeAuthorizer{})
	// limit=0 is not "the default": it reaches the service as an out-of-range limit (the service owns the range check).
	if rec := serve(t, svc, authorizer, http.MethodGet, "/tenants/"+tenant.String()+"/devices?limit=0", "", nil); rec.Code != http.StatusOK ||
		svc.query.Limit != -1 {
		t.Errorf("limit=0 passed as %d", svc.query.Limit)
	}
	calls := svc.calls
	rec = serve(t, svc, authorizer, http.MethodGet, "/tenants/"+tenant.String()+"/devices?q=", "", nil)
	if p := problemOfResponse(t, rec); rec.Code != http.StatusUnprocessableEntity || p.Errors == nil || (*p.Errors)[0].Field != "q" ||
		svc.calls != calls {
		t.Errorf("empty q: %d %s", rec.Code, rec.Body.String())
	}
	rec = serve(t, svc, authorizer, http.MethodPatch, "/tenants/"+tenant.String()+"/devices/"+uuid.NewString(), `{"given_name":`, nil)
	if p := problemOfResponse(t, rec); rec.Code != http.StatusUnprocessableEntity || p.Code != gen.ProblemCodeValidationFailed || svc.calls != calls {
		t.Errorf("broken body: %d %s", rec.Code, rec.Body.String())
	}
}

// TestProblemMapping: every code of the service is the Problem code of §13.1; a device the own-only caller may not
// see is a 404 whose cause is an authorization denial (reason not_own_resource for the audit, never sent); an
// unknown error is 500 without its text.
func TestProblemMapping(t *testing.T) {
	cases := []struct {
		err    error
		code   gen.ProblemCode
		status int
	}{
		{&devices.Error{Code: devices.CodeNotFound, Reason: devices.ReasonNoDevice}, gen.ProblemCodeNotFound, 404},
		{&devices.Error{Code: devices.CodeConflict, Reason: devices.ReasonRevocationInProgress}, gen.ProblemCodeConflict, 409},
		{&devices.Error{Code: devices.CodeValidationFailed, Field: "given_name", Detail: "bad"}, gen.ProblemCodeValidationFailed, 422},
		{&devices.Error{Code: devices.CodeIdempotencyKeyReuse}, gen.ProblemCodeIdempotencyKeyReuse, 422},
		{&devices.Error{Code: devices.CodeInstanceUnavailable}, gen.ProblemCodeInstanceUnavailable, 503},
		{&devices.Error{Code: devices.CodeUpstreamRejected, Err: errors.New("upstream said " + "hskey-" + "api-x")}, gen.ProblemCodeUpstreamRejected, 502},
		{&devices.Error{Code: devices.CodeInternal, Err: errors.New("db")}, gen.ProblemCodeInternalError, 500},
		{errors.New("plain"), gen.ProblemCodeInternalError, 500},
	}
	for _, c := range cases {
		var p *problem.Error
		if !errors.As(problemOf(c.err), &p) || p.Code != c.code || p.Status() != c.status {
			t.Errorf("%v: %+v, want %s %d", c.err, p, c.code, c.status)
			continue
		}
		if strings.Contains(p.Detail, "hskey") || strings.Contains(p.Detail, "plain") {
			t.Errorf("%v: detail %q leaks the cause", c.err, p.Detail)
		}
	}
	var p *problem.Error
	_ = errors.As(problemOf(&devices.Error{Code: devices.CodeNotFound, Reason: devices.ReasonNotOwnResource}), &p)
	var d *authz.Denial
	if p == nil || p.Status() != 404 || !errors.As(p, &d) || d.Reason != devices.ReasonNotOwnResource {
		t.Errorf("not own resource: %+v", p)
	}
	_ = errors.As(problemOf(&devices.Error{Code: devices.CodeValidationFailed, Field: "cursor", Detail: "x"}), &p)
	if len(p.Fields) != 1 || p.Fields[0].Field != "cursor" {
		t.Errorf("validation fields: %+v", p.Fields)
	}
	_ = errors.As(problemOf(&devices.Error{Code: devices.CodeInstanceUnavailable}), &p)
	if p.RetryAfter <= 0 {
		t.Error("instance_unavailable without Retry-After")
	}
}

// noSession and noAudit are explicit pass-through hooks: httpapi.New requires Session and Audit once handlers are
// mounted (P2-T16); this test exercises the handlers behind the authorization hook only.
func noSession(next http.Handler) http.Handler { return next }

func noAudit(f gen.StrictHandlerFunc, _ string) gen.StrictHandlerFunc { return f }
