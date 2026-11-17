package invitationsapi

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/authz"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/gen"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/problem"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
)

// TestFailureMapping — the refusals of the service and of the role guard keep their §13.1 codes.
func TestFailureMapping(t *testing.T) {
	for _, tc := range []struct {
		err   error
		code  gen.ProblemCode
		field string
	}{
		{&tenants.InvitationError{Kind: tenants.ErrNotFound, Reason: "invitation_not_found"}, gen.ProblemCodeNotFound, ""},
		{&tenants.InvitationError{Kind: tenants.ErrConflict, Reason: "already_member"}, gen.ProblemCodeConflict, ""},
		{fmt.Errorf("%w: refused by the database", tenants.ErrConflict), gen.ProblemCodeConflict, ""},
		{&tenants.InvitationError{Kind: tenants.ErrInvalid, Reason: "invalid_email"}, gen.ProblemCodeValidationFailed, "email"},
		{&tenants.InvitationError{Kind: tenants.ErrInvalid, Reason: "role_not_invitable"}, gen.ProblemCodeValidationFailed, "role"},
		{&tenants.InvitationError{Kind: tenants.ErrIdempotencyKeyReuse, Reason: "idempotency_key_reuse"}, gen.ProblemCodeIdempotencyKeyReuse, ""},
		{&tenants.InvitationError{Kind: tenants.ErrIdempotencyInProgress, Reason: "x", RetryAfter: 3 * time.Second}, gen.ProblemCodeConflict, ""},
		{&authz.Denial{Kind: authz.ErrForbidden, Reason: "role_not_lower"}, gen.ProblemCodeForbidden, ""},
		{errors.New("boom"), gen.ProblemCodeInternalError, ""},
	} {
		var p *problem.Error
		if !errors.As(failure(tc.err), &p) || p.Code != tc.code {
			t.Errorf("%v: %v, want %s", tc.err, failure(tc.err), tc.code)
			continue
		}
		if tc.field != "" && (len(p.Fields) != 1 || p.Fields[0].Field != tc.field) {
			t.Errorf("%v: fields %+v, want %s", tc.err, p.Fields, tc.field)
		}
		if errors.Is(tc.err, tenants.ErrIdempotencyInProgress) && p.RetryAfter != 3*time.Second {
			t.Errorf("in progress without Retry-After")
		}
	}
}

func TestHours(t *testing.T) {
	two, zero := 2, 0
	if hours(nil) != 0 || hours(&two) != 2*time.Hour || hours(&zero) >= 0 {
		t.Fatal("hours")
	}
}

// TestHandlersNeedTheChain — without the session and the authorization decision a write fails closed.
func TestHandlersNeedTheChain(t *testing.T) {
	h := New(nil, nil)
	if _, err := h.CreateTenantInvitation(context.Background(), gen.CreateTenantInvitationRequestObject{TenantId: uuid.New(),
		Body: &gen.InvitationCreate{Email: "a@b.test", Role: "tenant_viewer"}}); err == nil {
		t.Fatal("create without session")
	}
}
