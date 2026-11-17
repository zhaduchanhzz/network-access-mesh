package jobs

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// TestJobAPI: the job endpoints in the api process's roles — a tenant lists and reads only its own jobs (another
// tenant's job and platform jobs are 404), in the safe projection; the platform lists every job and reads the raw
// detail; pages are stable (created_at, id) with an opaque cursor; filters are validated.
func TestJobAPI(t *testing.T) {
	f := newFixture(t)
	api := f.api(t)
	svc := NewService(api)
	ctx := t.Context()

	a1 := mustEnqueue(t, api, Spec{Kind: "policy.apply", TenantID: &f.a}).Job.ID
	a2 := mustEnqueue(t, api, Spec{Kind: "device.revoke", TenantID: &f.a, Object: "dev-1"}).Job.ID
	a3 := mustEnqueue(t, api, Spec{Kind: "instance.restart", TenantID: &f.a, InstanceID: &f.instA}).Job.ID
	b1 := mustEnqueue(t, api, Spec{Kind: "policy.apply", TenantID: &f.b}).Job.ID
	p1 := mustEnqueue(t, api, Spec{Kind: "retention.sweep", Slot: "20261117T000000Z"}).Job.ID
	for i, id := range []uuid.UUID{a1, a2, a3, b1, p1} {
		f.exec(t, "UPDATE provisioning_jobs SET created_at = now() - make_interval(mins => $1) WHERE id = $2", 10-i, id)
	}
	f.exec(t, "UPDATE provisioning_jobs SET status = 'succeeded', finished_at = now() WHERE id = $1", a2)
	f.exec(t, `INSERT INTO provisioning_job_steps (tenant_id, job_id, seq, name, status, attempt, started_at, finished_at)
		VALUES ($1, $2, 0, 'headscale.expire', 'succeeded', 1, now(), now())`, f.a, a2)
	f.exec(t, `UPDATE provisioning_jobs SET status = 'failed_resumable', current_step = 'instance.stop',
		error = '{"code": "worker_lost", "message": "agent at /opt/meshguard/run/agent.sock gone", "detail": {"host": "10.250.0.9"}}'
		WHERE id = $1`, a3)
	f.exec(t, `INSERT INTO provisioning_job_steps (tenant_id, job_id, seq, name, status, attempt, error_code, detail)
		VALUES ($1, $2, 0, 'instance.stop', 'failed', 2, 'agent_unavailable', '{"error": "dial unix /run/meshguard/agent.sock"}')`, f.a, a3)

	ids := func(l JobList) []uuid.UUID {
		out := make([]uuid.UUID, 0, len(l.Items))
		for _, j := range l.Items {
			out = append(out, j.ID)
		}
		return out
	}
	list, err := svc.ListTenantJobs(ctx, f.a, ListFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if got := ids(list); !slices.Equal(got, []uuid.UUID{a3, a2, a1}) || list.NextCursor != nil {
		t.Fatalf("tenant A list = %v (cursor %v), want [a3 a2 a1] newest first", got, list.NextCursor)
	}
	raw, _ := json.Marshal(list)
	for _, leak := range []string{"/opt/meshguard", "/run/meshguard", "10.250.0.9", `"detail"`, "agent.sock"} {
		if strings.Contains(string(raw), leak) {
			t.Errorf("tenant view leaks %q: %s", leak, raw)
		}
	}
	got := list.Items[0]
	if got.Error == nil || got.Error.Code != CodeWorkerLost || len(got.Steps) != 1 || *got.Steps[0].Message != "Failed (agent_unavailable)" ||
		got.CurrentStep == nil || *got.CurrentStep != "instance.stop" {
		t.Errorf("tenant view of a3 = %+v", got)
	}
	for _, c := range []struct {
		tenant, job uuid.UUID
	}{{f.a, b1}, {f.a, p1}, {f.b, a1}, {f.a, uuid.New()}} {
		if _, err := svc.GetTenantJob(ctx, c.tenant, c.job); !errors.Is(err, ErrNotFound) {
			t.Errorf("tenant %s reading job %s: %v, want ErrNotFound", c.tenant, c.job, err)
		}
	}
	if j, err := svc.GetTenantJob(ctx, f.b, b1); err != nil || j.ID != b1 || j.Status != StatusQueued || j.TenantID == nil || *j.TenantID != f.b {
		t.Errorf("tenant B reading its job: %+v %v", j, err)
	}

	all, err := svc.ListPlatformJobs(ctx, ListFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if got := ids(all); !slices.Equal(got, []uuid.UUID{p1, b1, a3, a2, a1}) {
		t.Errorf("platform list = %v", got)
	}
	plat, err := svc.GetPlatformJob(ctx, a3)
	if err != nil {
		t.Fatal(err)
	}
	if plat.Error == nil || plat.Error.Message == nil || !strings.Contains(*plat.Error.Message, "agent.sock") ||
		plat.Error.Detail["host"] != "10.250.0.9" || plat.Steps[0].Detail["error"] == nil {
		t.Errorf("platform view of a3 = %+v", plat)
	}

	// pagination: stable order, opaque cursor, no overlap
	var paged []uuid.UUID
	cursor := ""
	for page := 0; ; page++ {
		l, err := svc.ListPlatformJobs(ctx, ListFilter{Limit: 2, Cursor: cursor})
		if err != nil || page > 3 {
			t.Fatalf("page %d: %v", page, err)
		}
		paged = append(paged, ids(l)...)
		if l.NextCursor == nil {
			break
		}
		cursor = *l.NextCursor
	}
	if !slices.Equal(paged, []uuid.UUID{p1, b1, a3, a2, a1}) {
		t.Errorf("paged platform list = %v", paged)
	}
	tenantPage, err := svc.ListTenantJobs(ctx, f.a, ListFilter{Limit: 2})
	if err != nil || tenantPage.NextCursor == nil || len(tenantPage.Items) != 2 {
		t.Fatalf("tenant page 1: %+v %v", tenantPage, err)
	}
	if rest, err := svc.ListTenantJobs(ctx, f.a, ListFilter{Limit: 2, Cursor: *tenantPage.NextCursor}); err != nil ||
		!slices.Equal(ids(rest), []uuid.UUID{a1}) || rest.NextCursor != nil {
		t.Errorf("tenant page 2: %v %v", ids(rest), err)
	}

	// filters
	if l, err := svc.ListTenantJobs(ctx, f.a, ListFilter{Status: StatusFailedResumable}); err != nil || !slices.Equal(ids(l), []uuid.UUID{a3}) {
		t.Errorf("status filter: %v %v", ids(l), err)
	}
	if l, err := svc.ListPlatformJobs(ctx, ListFilter{Kind: "policy.apply"}); err != nil || !slices.Equal(ids(l), []uuid.UUID{b1, a1}) {
		t.Errorf("kind filter: %v %v", ids(l), err)
	}
	for _, bad := range []ListFilter{{Status: "exploded"}, {Kind: "x"}, {Limit: 500}, {Cursor: "not-a-cursor"}} {
		if _, err := svc.ListTenantJobs(ctx, f.a, bad); !errors.Is(err, ErrInvalidFilter) {
			t.Errorf("filter %+v: %v, want ErrInvalidFilter", bad, err)
		}
	}
}

// TestIdempotencyKeys: §13.1 — first use proceeds; a duplicate while in progress gets 409 + Retry-After; the same key
// with another request gets 422; a completed request is replayed; a failed or crashed request releases the key; an
// expired key can be taken by a new request; keys are scoped by tenant (and platform) and identity.
func TestIdempotencyKeys(t *testing.T) {
	f := newFixture(t)
	api := f.api(t)
	ctx := t.Context()
	h1 := RequestHash("POST", "/api/v1/tenants/a/devices/x/expire", []byte(`{}`))
	h2 := RequestHash("POST", "/api/v1/tenants/a/devices/y/expire", []byte(`{}`))
	key := IdempotencyKey{TenantID: &f.a, IdentityID: f.identity, OperationID: "expireDevice", Key: "idem-key-0001"}
	inScope := func(k IdempotencyKey, fn func(q *sqlcdb.Queries) error) error {
		if k.TenantID != nil {
			return api.WithTenantTx(ctx, *k.TenantID, fn)
		}
		return api.WithPlatformTx(ctx, fn)
	}
	begin := func(k IdempotencyKey, h []byte) IdempotencyDecision {
		t.Helper()
		var d IdempotencyDecision
		if err := inScope(k, func(q *sqlcdb.Queries) error {
			var err error
			d, err = BeginIdempotent(ctx, q, k, h, 30*time.Second)
			return err
		}); err != nil {
			t.Fatalf("begin %s: %v", k.Key, err)
		}
		return d
	}
	complete := func(k IdempotencyKey, h []byte, r StoredResponse) error {
		return inScope(k, func(q *sqlcdb.Queries) error { return CompleteIdempotent(ctx, q, k, h, r) })
	}

	if d := begin(key, h1); d.Outcome != IdempotencyProceed {
		t.Fatalf("first use: %+v", d)
	}
	if d := begin(key, h1); d.Outcome != IdempotencyInProgress || d.RetryAfter <= 0 || d.RetryAfter > 30*time.Second {
		t.Errorf("duplicate in progress: %+v, want 409 + Retry-After", d)
	}
	if d := begin(key, h2); d.Outcome != IdempotencyKeyReuse {
		t.Errorf("same key, other request: %+v, want key reuse", d)
	}
	resp := StoredResponse{Status: 202, Body: json.RawMessage(`{"id":"job-1"}`), Resource: &Resource{Type: "job", ID: "job-1"}}
	if err := complete(key, h1, resp); err != nil {
		t.Fatal(err)
	}
	d := begin(key, h1)
	if d.Outcome != IdempotencyReplay || d.Response == nil || d.Response.Status != 202 || d.Response.Resource.ID != "job-1" {
		t.Fatalf("replay: %+v", d)
	}
	var body map[string]string
	if json.Unmarshal(d.Response.Body, &body) != nil || body["id"] != "job-1" {
		t.Errorf("replayed body %s", d.Response.Body)
	}
	if d := begin(key, h2); d.Outcome != IdempotencyKeyReuse {
		t.Errorf("completed key with another request: %+v", d)
	}
	if err := complete(key, h1, resp); !errors.Is(err, ErrIdempotencyLost) {
		t.Errorf("completing twice: %v, want ErrIdempotencyLost", err)
	}

	// a failed request releases the key
	k2 := key
	k2.Key = "idem-key-0002"
	begin(k2, h1)
	if err := inScope(k2, func(q *sqlcdb.Queries) error { return FailIdempotent(ctx, q, k2, h1) }); err != nil {
		t.Fatal(err)
	}
	if d := begin(k2, h1); d.Outcome != IdempotencyProceed {
		t.Errorf("retry after a failure: %+v", d)
	}
	// a crashed request (in progress past locked_until) no longer blocks
	k3 := key
	k3.Key = "idem-key-0003"
	begin(k3, h1)
	f.exec(t, "UPDATE idempotency_keys SET locked_until = now() - interval '1 second' WHERE key = $1", k3.Key)
	if d := begin(k3, h1); d.Outcome != IdempotencyProceed {
		t.Errorf("retry after a crash: %+v", d)
	}
	// an expired key (not yet swept) is free for a new request; the old request lost it
	f.exec(t, "UPDATE idempotency_keys SET expires_at = now() - interval '1 second' WHERE key = $1", key.Key)
	if d := begin(key, h2); d.Outcome != IdempotencyProceed {
		t.Errorf("expired key reused: %+v", d)
	}
	if err := complete(key, h1, resp); !errors.Is(err, ErrIdempotencyLost) {
		t.Errorf("completing with the old request: %v, want ErrIdempotencyLost", err)
	}
	// scopes: tenant B, platform, other identity — separate keys
	kB, kP, kI := key, key, key
	kB.TenantID, kP.TenantID, kI.IdentityID = &f.b, nil, uuid.New()
	for name, k := range map[string]IdempotencyKey{"tenant B": kB, "platform": kP, "other identity": kI} {
		if d := begin(k, h1); d.Outcome != IdempotencyProceed {
			t.Errorf("%s: %+v, want a key of its own", name, d)
		}
	}
	if n := scalar[int64](t, f, "SELECT count(*) FROM idempotency_keys WHERE key = $1", key.Key); n != 4 {
		t.Errorf("%d rows for the key, want 4 (tenant A, tenant B, platform, other identity)", n)
	}
	for _, bad := range []IdempotencyKey{{TenantID: &f.a, IdentityID: f.identity, OperationID: "x"}, {TenantID: &f.a, OperationID: "x", Key: "k"}} {
		if err := inScope(bad, func(q *sqlcdb.Queries) error {
			_, err := BeginIdempotent(ctx, q, bad, h1, time.Second)
			return err
		}); !errors.Is(err, ErrInvalidIdempotencyKey) {
			t.Errorf("invalid key %+v: %v", bad, err)
		}
	}
	if err := inScope(key, func(q *sqlcdb.Queries) error {
		_, err := BeginIdempotent(ctx, q, key, h1[:31], time.Second)
		return err
	}); !errors.Is(err, ErrInvalidIdempotencyKey) {
		t.Errorf("short request hash: %v", err)
	}
}
