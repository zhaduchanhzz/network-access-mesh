package tenantsapi

// P3-T06a "Vượt quota ⇒ 403 quota_exceeded": a quota refusal of the services (tenants.QuotaExceededError, as
// usage.Checker returns it — wrapped or not) leaves the handlers as RFC 9457 problem+json 403 quota_exceeded naming the
// quota and its limit; any other error keeps its mapping.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/gen"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/problem"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
)

func TestQuotaRefusalIs403QuotaExceeded(t *testing.T) {
	for name, err := range map[string]error{
		"tenant cap": (tenants.QuotaStatus{Resource: tenants.QuotaTenants, Limit: 10, Used: 10, Requested: 1}).Exceeded(),
		"devices, wrapped": fmt.Errorf("create enrollment: %w",
			(tenants.QuotaStatus{Resource: tenants.QuotaDevices, Plan: "standard", Limit: 100, Used: 100, Requested: 1}).Exceeded()),
		"no subscription": (tenants.QuotaStatus{Resource: tenants.QuotaDevices, Limit: 0, Used: 0, Requested: 1}).Exceeded(),
	} {
		if !errors.Is(err, tenants.ErrQuotaExceeded) {
			t.Fatalf("%s: %v is not ErrQuotaExceeded", name, err)
		}
		p := failure(err)
		rec := httptest.NewRecorder()
		problem.Write(rec, httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/platform/tenants?x=secret", nil), p)
		var body gen.Problem
		if e := json.Unmarshal(rec.Body.Bytes(), &body); e != nil {
			t.Fatalf("%s: body %q: %v", name, rec.Body.String(), e)
		}
		var q *tenants.QuotaExceededError
		errors.As(err, &q)
		want := fmt.Sprintf("The %s quota is reached (limit %d).", q.Status.Resource, q.Status.Limit)
		if rec.Code != http.StatusForbidden || rec.Header().Get("Content-Type") != problem.ContentType ||
			body.Code != gen.ProblemCodeQuotaExceeded || body.Status != http.StatusForbidden ||
			body.Type != problem.TypePrefix+"quota_exceeded" || body.Detail == nil || *body.Detail != want ||
			body.Instance == nil || strings.Contains(*body.Instance, "secret") {
			t.Errorf("%s: %d %s %+v", name, rec.Code, rec.Header().Get("Content-Type"), body)
		}
	}
	// other errors keep their mapping
	if p := failure(tenants.ErrNotFound); p.Code != gen.ProblemCodeNotFound {
		t.Errorf("not found ⇒ %s", p.Code)
	}
	if p := failure(errors.New("boom")); p.Code != gen.ProblemCodeInternalError {
		t.Errorf("other ⇒ %s", p.Code)
	}
	if _, ok := problem.FromQuota(tenants.ErrQuotaExceeded); ok { // the bare sentinel carries no quota to name…
		t.Error("bare ErrQuotaExceeded mapped by FromQuota")
	}
	if p := failure(fmt.Errorf("x: %w", tenants.ErrQuotaExceeded)); p.Code != gen.ProblemCodeQuotaExceeded ||
		p.Status() != http.StatusForbidden { // …but is still 403 quota_exceeded
		t.Errorf("bare sentinel ⇒ %s %d", p.Code, p.Status())
	}
}
