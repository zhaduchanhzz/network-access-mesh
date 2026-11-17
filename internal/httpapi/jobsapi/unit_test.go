package jobsapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
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
)

// fakeService records what it was asked and answers what the test sets.
type fakeService struct {
	tenants  []uuid.UUID
	filters  []jobs.ListFilter
	list     jobs.JobList
	job      jobs.Job
	platform jobs.PlatformJob
	err      error
	calls    int
}

func (f *fakeService) ListTenantJobs(_ context.Context, t uuid.UUID, fl jobs.ListFilter) (jobs.JobList, error) {
	f.calls++
	f.tenants, f.filters = append(f.tenants, t), append(f.filters, fl)
	return f.list, f.err
}

func (f *fakeService) GetTenantJob(_ context.Context, t, _ uuid.UUID) (jobs.Job, error) {
	f.calls++
	f.tenants = append(f.tenants, t)
	return f.job, f.err
}

func (f *fakeService) ListPlatformJobs(_ context.Context, fl jobs.ListFilter) (jobs.JobList, error) {
	f.calls++
	f.filters = append(f.filters, fl)
	return f.list, f.err
}

func (f *fakeService) GetPlatformJob(context.Context, uuid.UUID) (jobs.PlatformJob, error) {
	f.calls++
	return f.platform, f.err
}

// fakeAuthorizer answers every operation with a fixed decision, completed the way authz completes it (the tenant of
// the path on tenant routes). Authorization itself is tested by P2-T07; with real sessions and roles by the authz
// matrix (tests/security/authzmatrix — the Jobs set is mounted there since P2-T16).
type fakeAuthorizer struct {
	d           authz.Decision
	wrongTenant bool
}

func (a fakeAuthorizer) RequireOperation(_ context.Context, _ string, tenantID uuid.UUID) (authz.Decision, error) {
	d := a.d
	if tenantID != uuid.Nil {
		d.TenantID = tenantID
		if a.wrongTenant {
			d.TenantID = uuid.New()
		}
	}
	return d, nil
}

func serve(t *testing.T, svc *fakeService, authorizer gen.StrictMiddlewareFunc, path string) *httptest.ResponseRecorder {
	t.Helper()
	h, err := httpapi.New(httpapi.Options{Logger: logx.New(io.Discard, slog.LevelInfo, "api"),
		Handlers: httpapi.Handlers{Jobs: New(svc)}, Hooks: httpapi.Hooks{Authz: authorizer, Session: noSession, Audit: noAudit}})
	if err != nil {
		t.Fatal(err)
	}
	return serveHandler(t, h, path)
}

func serveHandler(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://app.mg.test/api/v1"+path, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

func granted(own bool) gen.StrictMiddlewareFunc {
	return authzhook.Authz(fakeAuthorizer{d: authz.Decision{OwnOnly: own}})
}

func code(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var p struct {
		Code   string `json:"code"`
		Errors []struct {
			Field string `json:"field"`
		} `json:"errors"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &p)
	if len(p.Errors) > 0 {
		return p.Code + ":" + p.Errors[0].Field
	}
	return p.Code
}

func sampleJob(tenant *uuid.UUID) jobs.Job {
	started := time.Date(2026, 11, 17, 8, 0, 0, 0, time.FixedZone("x", 7*3600))
	msg := "Failed: instance_unavailable"
	return jobs.Job{ID: uuid.New(), Kind: "device.revoke", TenantID: tenant, Status: "failed",
		Resource: &jobs.Resource{Type: "device", ID: "d-1"}, CreatedAt: started,
		Steps: []jobs.Step{{Name: "expire_node", Status: "failed", Attempt: 2, StartedAt: &started, Message: &msg}},
		Error: &jobs.ErrorCode{Code: "instance_unavailable"}}
}

// TestTenantJobs: the tenant of the path is the only tenant asked; the safe projection is mapped unchanged (UTC);
// filters reach the service; a job of another tenant asked by id is 404; a job of another tenant returned by a lower
// layer is never sent (500).
func TestTenantJobs(t *testing.T) {
	tenant := uuid.New()
	j := sampleJob(&tenant)
	next := "c-1"
	svc := &fakeService{list: jobs.JobList{Items: []jobs.Job{j}, NextCursor: &next}, job: j}
	rec := serve(t, svc, granted(false), "/tenants/"+tenant.String()+"/jobs?limit=5&status=failed&kind=device.revoke&cursor=abc")
	if rec.Code != http.StatusOK {
		t.Fatalf("list: %d %s", rec.Code, rec.Body)
	}
	var list gen.JobList
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	got := list.Items[0]
	if len(list.Items) != 1 || got.Id != j.ID || got.Kind != "device.revoke" || *got.TenantId != tenant ||
		got.Error == nil || got.Error.Code != "instance_unavailable" || got.Resource.Type != "device" ||
		got.Steps[0].Attempt != 2 || *got.Steps[0].Message != "Failed: instance_unavailable" ||
		got.Steps[0].StartedAt.Location() != time.UTC || *list.NextCursor != "c-1" {
		t.Fatalf("list = %+v", list)
	}
	if f := svc.filters[0]; svc.tenants[0] != tenant || f.Limit != 5 || f.Status != "failed" || f.Kind != "device.revoke" ||
		f.Cursor != "abc" {
		t.Fatalf("service asked %v %+v", svc.tenants, f)
	}
	if rec := serve(t, svc, granted(false), "/tenants/"+tenant.String()+"/jobs/"+j.ID.String()); rec.Code != http.StatusOK ||
		strings.Contains(rec.Body.String(), `"detail"`) {
		t.Fatalf("get: %d %s", rec.Code, rec.Body)
	}

	other := uuid.New()
	svc = &fakeService{err: fmt.Errorf("wrapped: %w", jobs.ErrNotFound)}
	if rec := serve(t, svc, granted(false), "/tenants/"+tenant.String()+"/jobs/"+uuid.NewString()); rec.Code != http.StatusNotFound ||
		code(t, rec) != "not_found" {
		t.Fatalf("missing / other tenant's job: %d %s", rec.Code, rec.Body)
	}
	for name, s := range map[string]*fakeService{
		"foreign job in a list":  {list: jobs.JobList{Items: []jobs.Job{sampleJob(&other)}}},
		"platform job in a list": {list: jobs.JobList{Items: []jobs.Job{sampleJob(nil)}}},
		"foreign job by id":      {job: sampleJob(&other)},
	} {
		path := "/tenants/" + tenant.String() + "/jobs"
		if strings.HasSuffix(name, "by id") {
			path += "/" + s.job.ID.String()
		}
		rec := serve(t, s, granted(false), path)
		if rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), other.String()) {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body)
		}
	}
}

// TestPlatformJobs: the platform view carries the raw (redacted) step detail and the full error; the list uses the
// safe projection.
func TestPlatformJobs(t *testing.T) {
	tenant := uuid.New()
	j := sampleJob(&tenant)
	msg := "edge returned 502"
	pj := jobs.PlatformJob{ID: j.ID, Kind: j.Kind, TenantID: &tenant, Status: "failed", CreatedAt: j.CreatedAt,
		Steps: []jobs.PlatformStep{{Step: j.Steps[0], Detail: map[string]any{"http_status": 502}}},
		Error: &jobs.PlatformError{Code: "instance_unavailable", Message: &msg, Detail: map[string]any{"attempts": 8}}}
	svc := &fakeService{list: jobs.JobList{Items: []jobs.Job{j}}, platform: pj}
	rec := serve(t, svc, granted(false), "/platform/jobs?kind=device.revoke")
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), `"detail"`) || svc.filters[0].Kind != "device.revoke" {
		t.Fatalf("list: %d %s", rec.Code, rec.Body)
	}
	rec = serve(t, svc, granted(false), "/platform/jobs/"+j.ID.String())
	var got gen.PlatformJob
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &got) != nil {
		t.Fatalf("get: %d %s", rec.Code, rec.Body)
	}
	if got.Error == nil || *got.Error.Message != msg || (*got.Error.Detail)["attempts"] != float64(8) ||
		(*got.Steps[0].Detail)["http_status"] != float64(502) || *got.TenantId != tenant {
		t.Fatalf("platform job = %+v", got)
	}
	svc.platform.ID = uuid.New()
	if rec := serve(t, svc, granted(false), "/platform/jobs/"+j.ID.String()); rec.Code != http.StatusInternalServerError {
		t.Fatalf("another job returned: %d", rec.Code)
	}
}

// TestDecisionRequired: without the authorization hook, with a decision about another tenant, or with an own-only
// grant, nothing reaches the service (fail closed).
func TestDecisionRequired(t *testing.T) {
	tenant := uuid.New()
	paths := []string{"/tenants/" + tenant.String() + "/jobs", "/tenants/" + tenant.String() + "/jobs/" + uuid.NewString()}
	noDecision := gen.StrictMiddlewareFunc(func(f gen.StrictHandlerFunc, _ string) gen.StrictHandlerFunc { return f })
	for _, p := range append(paths, "/platform/jobs", "/platform/jobs/"+uuid.NewString()) {
		svc := &fakeService{}
		if rec := serve(t, svc, noDecision, p); rec.Code != http.StatusInternalServerError || svc.calls != 0 {
			t.Errorf("%s without decision: %d, %d calls", p, rec.Code, svc.calls)
		}
	}
	for _, p := range paths {
		svc := &fakeService{}
		if rec := serve(t, svc, authzhook.Authz(fakeAuthorizer{wrongTenant: true}), p); rec.Code != http.StatusInternalServerError ||
			svc.calls != 0 {
			t.Errorf("%s with another tenant's decision: %d", p, rec.Code)
		}
		if rec := serve(t, svc, granted(true), p); rec.Code != http.StatusForbidden || code(t, rec) != "forbidden" || svc.calls != 0 {
			t.Errorf("%s with an own-only grant: %d %s", p, rec.Code, rec.Body)
		}
	}
}

// TestFilterValidation: out-of-range limits, unknown statuses and the service's own refusals (kind, cursor) are 422
// naming the parameter; other service errors are 500 without their text.
func TestFilterValidation(t *testing.T) {
	tenant := uuid.New()
	base := "/tenants/" + tenant.String() + "/jobs"
	for q, want := range map[string]string{
		"limit=0": "validation_failed:limit", "limit=201": "validation_failed:limit", "status=done": "validation_failed:status",
	} {
		svc := &fakeService{}
		if rec := serve(t, svc, granted(false), base+"?"+q); rec.Code != http.StatusUnprocessableEntity || code(t, rec) != want ||
			svc.calls != 0 {
			t.Errorf("%s: %d %s", q, rec.Code, code(t, rec))
		}
	}
	for q, c := range map[string]struct {
		err  error
		want string
	}{
		"kind=BAD":    {fmt.Errorf("%w: invalid kind", jobs.ErrInvalidFilter), "validation_failed:kind"},
		"cursor=zzzz": {fmt.Errorf("%w: invalid cursor", jobs.ErrInvalidFilter), "validation_failed:cursor"},
	} {
		svc := &fakeService{err: c.err}
		if rec := serve(t, svc, granted(false), base+"?"+q); rec.Code != http.StatusUnprocessableEntity || code(t, rec) != c.want {
			t.Errorf("%s: %d %s", q, rec.Code, code(t, rec))
		}
	}
	svc := &fakeService{err: errors.New("dial tcp 10.249.1.5:5432: secret-dsn")}
	if rec := serve(t, svc, granted(false), "/platform/jobs"); rec.Code != http.StatusInternalServerError ||
		strings.Contains(rec.Body.String(), "secret-dsn") {
		t.Errorf("service failure: %d %s", rec.Code, rec.Body)
	}
}

// noSession and noAudit are explicit pass-through hooks: httpapi.New requires Session and Audit once handlers are
// mounted (P2-T16); this test exercises the handlers behind the authorization hook only.
func noSession(next http.Handler) http.Handler { return next }

func noAudit(f gen.StrictHandlerFunc, _ string) gen.StrictHandlerFunc { return f }
