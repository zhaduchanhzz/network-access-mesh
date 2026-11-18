package lifecycleapi

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/authz"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/gen"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/problem"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/lifecycle"
)

func TestFailureMapping(t *testing.T) {
	conflict := func(reason string) error { return &lifecycle.RequestError{Kind: lifecycle.ErrConflict, Reason: reason} }
	for _, c := range []struct {
		err    error
		code   gen.ProblemCode
		status int
		detail string
	}{
		{&lifecycle.RequestError{Kind: lifecycle.ErrNotFound, Reason: "not_found"}, gen.ProblemCodeNotFound, 404, "The resource does not exist."},
		{conflict(lifecycle.ReasonAlreadySuspended), gen.ProblemCodeConflict, 409, "The tenant is already suspended."},
		{conflict(lifecycle.ReasonNotSuspended), gen.ProblemCodeConflict, 409, "The tenant is not suspended."},
		{conflict(lifecycle.ReasonNoPolicy), gen.ProblemCodeConflict, 409, "The tenant has no desired policy version to restore on resume."},
		{conflict(lifecycle.ReasonLifecycleJobActive), gen.ProblemCodeConflict, 409, "Another lifecycle job of the tenant is not finished."},
		{conflict("something_new"), gen.ProblemCodeConflict, 409, "The request conflicts with the tenant's state."},
		{&lifecycle.RequestError{Kind: lifecycle.ErrIdempotencyKeyReuse, Reason: "idempotency_key_reuse"}, gen.ProblemCodeIdempotencyKeyReuse, 422, ""},
		{&lifecycle.RequestError{Kind: lifecycle.ErrIdempotencyInProgress, Reason: "idempotency_in_progress", RetryAfter: 3 * time.Second},
			gen.ProblemCodeConflict, 409, ""},
		{errors.New("database down"), gen.ProblemCodeInternalError, 500, ""},
	} {
		var p *problem.Error
		if !errors.As(failure(c.err), &p) || p.Code != c.code || p.Status() != c.status || (c.detail != "" && p.Detail != c.detail) {
			t.Errorf("%v ⇒ %+v, want %s %d %q", c.err, p, c.code, c.status, c.detail)
			continue
		}
		var d *authz.Denial
		if c.status != 500 && (!errors.As(p.Cause, &d) || d.Reason == "") {
			t.Errorf("%v: cause %v carries no reason for the audit", c.err, p.Cause)
		}
	}
	var p *problem.Error
	_ = errors.As(failure(&lifecycle.RequestError{Kind: lifecycle.ErrIdempotencyInProgress, RetryAfter: 3 * time.Second}), &p)
	if p.RetryAfter != 3*time.Second {
		t.Fatal("Retry-After lost")
	}
}

// TestIdempotencyHash: the hash names the action and the tenant (the request has no body) — a suspend and a resume, or
// two tenants, are never the same request.
func TestIdempotencyHash(t *testing.T) {
	a, b := uuid.New(), uuid.New()
	s1, s2, r1 := idem("suspend", a, "k"), idem("suspend", b, "k"), idem("resume", a, "k")
	if bytes.Equal(s1.Hash, s2.Hash) || bytes.Equal(s1.Hash, r1.Hash) || !bytes.Equal(s1.Hash, idem("suspend", a, "x").Hash) ||
		len(s1.Hash) != 32 || s1.Key != "k" {
		t.Fatal("the request hash must depend on the action and the tenant only")
	}
	if JobLocation(uuid.Nil) != "/api/v1/platform/jobs/00000000-0000-0000-0000-000000000000" {
		t.Fatal(JobLocation(uuid.Nil))
	}
}

// TestHandlersNeedTheirHooks: without a session and a platform decision the handlers never call the requester.
func TestHandlersNeedTheirHooks(t *testing.T) {
	called := 0
	h := New(requesterFunc(func() { called++ }))
	_, err := h.SuspendPlatformTenant(context.Background(), gen.SuspendPlatformTenantRequestObject{TenantId: uuid.New()})
	var p *problem.Error
	if !errors.As(err, &p) || p.Code != gen.ProblemCodeInternalError || called != 0 {
		t.Errorf("suspend without hooks: %v (requester called %d times)", err, called)
	}
	_, err = h.ResumePlatformTenant(context.Background(), gen.ResumePlatformTenantRequestObject{TenantId: uuid.New()})
	if !errors.As(err, &p) || p.Code != gen.ProblemCodeInternalError || called != 0 {
		t.Errorf("resume without hooks: %v (requester called %d times)", err, called)
	}
}

type requesterFunc func()

func (f requesterFunc) Suspend(context.Context, uuid.UUID, uuid.UUID, *lifecycle.Idempotency) (lifecycle.Requested, error) {
	f()
	return lifecycle.Requested{}, fmt.Errorf("not expected")
}

func (f requesterFunc) Resume(context.Context, uuid.UUID, uuid.UUID, *lifecycle.Idempotency) (lifecycle.Requested, error) {
	f()
	return lifecycle.Requested{}, fmt.Errorf("not expected")
}
