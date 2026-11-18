package quarantineapi

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/authz"
	"github.com/zhaduchanhzz/network-access-mesh/internal/authz/approvals"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/gen"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/problem"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/quarantine"
)

func TestFailureMapping(t *testing.T) {
	re := func(kind error, reason string) error { return &quarantine.RequestError{Kind: kind, Reason: reason} }
	for _, c := range []struct {
		err    error
		code   gen.ProblemCode
		status int
		detail string
	}{
		{re(quarantine.ErrNotFound, "not_found"), gen.ProblemCodeNotFound, 404, "The resource does not exist."},
		{re(quarantine.ErrConflict, quarantine.ReasonRemoved), gen.ProblemCodeConflict, 409, "The instance was removed."},
		{re(quarantine.ErrConflict, quarantine.ReasonNotQuarantined), gen.ProblemCodeConflict, 409, "The instance is not quarantined."},
		{re(quarantine.ErrConflict, quarantine.ReasonQuarantineActive), gen.ProblemCodeConflict, 409,
			"The quarantine of the instance is still in progress."},
		{re(quarantine.ErrConflict, "something_new"), gen.ProblemCodeConflict, 409, "The request conflicts with the instance's state."},
		{re(quarantine.ErrInvalid, quarantine.ReasonReasonRequired), gen.ProblemCodeValidationFailed, 422, ""},
		{re(quarantine.ErrIdempotencyKeyReuse, "idempotency_key_reuse"), gen.ProblemCodeIdempotencyKeyReuse, 422, ""},
		{&quarantine.RequestError{Kind: quarantine.ErrIdempotencyInProgress, RetryAfter: 2 * time.Second}, gen.ProblemCodeConflict, 409, ""},
		{errors.New("database down"), gen.ProblemCodeInternalError, 500, ""},
	} {
		var p *problem.Error
		if !errors.As(failure(c.err), &p) || p.Code != c.code || p.Status() != c.status || (c.detail != "" && p.Detail != c.detail) {
			t.Errorf("%v ⇒ %+v, want %s %d %q", c.err, p, c.code, c.status, c.detail)
		}
	}
	var p *problem.Error
	_ = errors.As(failure(&quarantine.RequestError{Kind: quarantine.ErrIdempotencyInProgress, RetryAfter: 2 * time.Second}), &p)
	if p.RetryAfter != 2*time.Second {
		t.Fatal("Retry-After lost")
	}
	if JobLocation(uuid.Nil) != "/api/v1/platform/jobs/00000000-0000-0000-0000-000000000000" {
		t.Fatal(JobLocation(uuid.Nil))
	}
}

// TestHandlersNeedTheirHooks: without a session and a platform decision nothing is called — no quarantine, no approval
// request.
func TestHandlersNeedTheirHooks(t *testing.T) {
	f := &fakes{}
	h := New(f, f)
	_, err := h.QuarantinePlatformInstance(context.Background(), gen.QuarantinePlatformInstanceRequestObject{InstanceId: uuid.New(),
		Body: &gen.InstanceQuarantineRequest{Reason: "x"}})
	var p *problem.Error
	if !errors.As(err, &p) || p.Code != gen.ProblemCodeInternalError || f.calls != 0 {
		t.Errorf("quarantine without hooks: %v (%d calls)", err, f.calls)
	}
	_, err = h.ReleasePlatformInstance(context.Background(), gen.ReleasePlatformInstanceRequestObject{InstanceId: uuid.New(),
		Body: &gen.InstanceReleaseRequest{Reason: "x"}})
	if !errors.As(err, &p) || p.Code != gen.ProblemCodeInternalError || f.calls != 0 {
		t.Errorf("release without hooks: %v (%d calls)", err, f.calls)
	}
}

type fakes struct{ calls int }

func (f *fakes) Quarantine(context.Context, uuid.UUID, uuid.UUID, string, *quarantine.Idempotency) (quarantine.Requested, error) {
	f.calls++
	return quarantine.Requested{}, errors.New("not expected")
}

func (f *fakes) ReleasePayload(context.Context, uuid.UUID) (quarantine.ReleasePayload, error) {
	f.calls++
	return quarantine.ReleasePayload{}, errors.New("not expected")
}

func (f *fakes) RequestIdempotent(context.Context, approvals.Actor, approvals.NewRequest, approvals.Idempotency) (approvals.Request, error) {
	f.calls++
	return approvals.Request{Scope: authz.ScopePlatform}, errors.New("not expected")
}
