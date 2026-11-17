package provisioningapi

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/gen"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/problem"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/orchestrator"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
)

func TestFailureMapping(t *testing.T) {
	for _, c := range []struct {
		err    error
		code   gen.ProblemCode
		status int
	}{
		{&orchestrator.CreateError{Kind: orchestrator.ErrInvalid, Reason: "invalid_slug", Field: "slug"}, gen.ProblemCodeValidationFailed, 422},
		{&orchestrator.CreateError{Kind: orchestrator.ErrConflict, Reason: "slug_taken"}, gen.ProblemCodeConflict, 409},
		{&orchestrator.CreateError{Kind: orchestrator.ErrIdempotencyInProgress, RetryAfter: 3 * time.Second}, gen.ProblemCodeConflict, 409},
		{&orchestrator.CreateError{Kind: orchestrator.ErrIdempotencyKeyReuse}, gen.ProblemCodeIdempotencyKeyReuse, 422},
		{&tenants.QuotaExceededError{Status: tenants.QuotaStatus{Resource: tenants.QuotaTenants, Limit: 10, Used: 10, Requested: 1}},
			gen.ProblemCodeQuotaExceeded, 403},
		{fmt.Errorf("wrap: %w", jobs.ErrNotFound), gen.ProblemCodeNotFound, 404},
		{&jobs.StateError{Action: "retry", Kind: "tenant.provision", Status: "succeeded", Reason: "status_not_allowed"}, gen.ProblemCodeConflict, 409},
		{errors.New("database down"), gen.ProblemCodeInternalError, 500},
	} {
		var p *problem.Error
		if !errors.As(failure(c.err), &p) || p.Code != c.code || p.Status() != c.status {
			t.Errorf("%v ⇒ %+v, want %s %d", c.err, p, c.code, c.status)
		}
	}
	var p *problem.Error
	_ = errors.As(failure(&orchestrator.CreateError{Kind: orchestrator.ErrIdempotencyInProgress, RetryAfter: 3 * time.Second}), &p)
	if p.RetryAfter != 3*time.Second {
		t.Fatal("Retry-After lost")
	}
	_ = errors.As(failure(&orchestrator.CreateError{Kind: orchestrator.ErrInvalid, Reason: "invalid_email", Field: "owner_email"}), &p)
	if len(p.Fields) != 1 || p.Fields[0].Field != "owner_email" || p.Fields[0].Code != "invalid_email" {
		t.Fatalf("fields %+v", p.Fields)
	}
}

// TestRequestHashIgnoresClientSecret: the Idempotency-Key hash never depends on (nor stores) the write-only secret,
// but does on everything else.
func TestRequestHashIgnoresClientSecret(t *testing.T) {
	body := func(secret, slug string) *gen.CreatePlatformTenantJSONRequestBody {
		iss, cid := "https://login.acme.example", "meshguard"
		return &gen.CreatePlatformTenantJSONRequestBody{Slug: slug, Name: "Acme", PlanKey: "standard", OwnerEmail: "o@acme.example",
			IdentityProvider: gen.TenantIdentityProviderCreate{Driver: "external", Issuer: &iss, ClientId: &cid, ClientSecret: &secret}}
	}
	a, err := requestHash(body("secret-one", "acme"))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := requestHash(body("secret-two", "acme"))
	c, _ := requestHash(body("secret-one", "other"))
	if !bytes.Equal(a, b) || bytes.Equal(a, c) || len(a) != 32 {
		t.Fatal("hash must ignore the client secret and only it")
	}
	if JobLocation([16]byte{}) != "/api/v1/platform/jobs/00000000-0000-0000-0000-000000000000" {
		t.Fatal(JobLocation([16]byte{}))
	}
}
