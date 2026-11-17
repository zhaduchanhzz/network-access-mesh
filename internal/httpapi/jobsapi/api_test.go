package jobsapi

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/authz"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/authzhook"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/gen"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/logx"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/storetest"
)

func TestMain(m *testing.M) {
	code := m.Run()
	storetest.Cleanup()
	os.Exit(code)
}

// TestJobsOverRealService: the handlers over jobs.Service and the api process's pools on a database migrated like a
// deployment. Tenant A's path lists A's jobs only (RLS + the service's own filter + the handler's check); B's job asked
// on A's path is 404 like a missing one; the raw step detail and error message (canaries) appear only in the platform
// view of one job — never in a tenant answer nor in a list.
func TestJobsOverRealService(t *testing.T) {
	pg := storetest.Require(t)
	db := pg.NewDatabase(t)
	st := pg.OpenStore(t, db, "mg_api_tenant", "mg_api_platform", 2)
	a, b, jobA, jobB, jobP := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	const canaryDetail, canaryMessage = "mg-canary-step-detail-7f3a", "mg-canary-error-message-91c2"
	for i, ten := range []uuid.UUID{a, b} {
		pg.Exec(t, db, `INSERT INTO tenants (id, slug, name, status) VALUES ($1, $2, $3, 'active')`, ten, []string{"ten-a", "ten-b"}[i], "Tenant "+[]string{"A", "B"}[i])
	}
	for _, j := range []struct {
		id     uuid.UUID
		tenant *uuid.UUID
	}{{jobA, &a}, {jobB, &b}, {jobP, nil}} {
		pg.Exec(t, db, `INSERT INTO provisioning_jobs (id, tenant_id, kind, status, error, created_at, finished_at)
			VALUES ($1, $2, 'device.revoke', 'failed', jsonb_build_object('code', 'instance_unavailable', 'message', $3::text), now(), now())`,
			j.id, j.tenant, canaryMessage)
		pg.Exec(t, db, `INSERT INTO provisioning_job_steps (tenant_id, job_id, seq, name, status, attempt, error_code, detail)
			VALUES ($1, $2, 0, 'expire_node', 'failed', 1, 'instance_unavailable', jsonb_build_object('upstream', $3::text))`,
			j.tenant, j.id, canaryDetail)
	}
	h, err := httpapi.New(httpapi.Options{Logger: logx.New(io.Discard, slog.LevelInfo, "api"),
		Handlers: httpapi.Handlers{Jobs: New(jobs.NewService(st))},
		Hooks: httpapi.Hooks{Authz: authzhook.Authz(fakeAuthorizer{d: authz.Decision{}}), Session: noSession,
			Audit: noAudit}})
	if err != nil {
		t.Fatal(err)
	}
	get := func(path string) (int, string) {
		t.Helper()
		rec := serveHandler(t, h, path)
		return rec.Code, rec.Body.String()
	}

	status, body := get("/tenants/" + a.String() + "/jobs")
	var list gen.JobList
	if status != http.StatusOK || json.Unmarshal([]byte(body), &list) != nil || len(list.Items) != 1 || list.Items[0].Id != jobA {
		t.Fatalf("tenant A list: %d %s", status, body)
	}
	if status, body = get("/tenants/" + a.String() + "/jobs/" + jobA.String()); status != http.StatusOK {
		t.Fatalf("tenant A job: %d %s", status, body)
	}
	for _, path := range []string{"/tenants/" + a.String() + "/jobs/" + jobB.String(), "/tenants/" + a.String() + "/jobs/" + jobP.String(),
		"/tenants/" + a.String() + "/jobs/" + uuid.NewString()} {
		if status, body := get(path); status != http.StatusNotFound || !strings.Contains(body, `"not_found"`) {
			t.Errorf("%s: %d %s", path, status, body)
		}
	}
	answers := []string{}
	for _, path := range []string{"/tenants/" + a.String() + "/jobs", "/tenants/" + a.String() + "/jobs/" + jobA.String(),
		"/tenants/" + b.String() + "/jobs", "/platform/jobs"} {
		status, body := get(path)
		if status != http.StatusOK {
			t.Fatalf("%s: %d %s", path, status, body)
		}
		answers = append(answers, body)
	}
	for _, body := range answers {
		if strings.Contains(body, canaryDetail) || strings.Contains(body, canaryMessage) {
			t.Fatalf("raw detail in a tenant answer or a list: %s", body)
		}
	}
	if err := json.Unmarshal([]byte(answers[3]), &list); err != nil || len(list.Items) != 3 {
		t.Fatalf("platform list: %s", answers[3])
	}
	status, body = get("/platform/jobs/" + jobB.String())
	if status != http.StatusOK || !strings.Contains(body, canaryDetail) || !strings.Contains(body, canaryMessage) {
		t.Fatalf("platform job: %d %s", status, body)
	}
}
