package instanceopsapi

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/gen"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/problem"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/orchestrator"
)

func TestFailureMapping(t *testing.T) {
	for _, c := range []struct {
		err    error
		code   gen.ProblemCode
		status int
	}{
		{&orchestrator.CreateError{Kind: orchestrator.ErrInvalid, Reason: "invalid_digest", Field: "image_digest"}, gen.ProblemCodeValidationFailed, 422},
		{&orchestrator.CreateError{Kind: orchestrator.ErrConflict, Reason: "instance_quarantined"}, gen.ProblemCodeConflict, 409},
		{&orchestrator.CreateError{Kind: orchestrator.ErrConflict, Reason: "already_on_target"}, gen.ProblemCodeConflict, 409},
		{&orchestrator.CreateError{Kind: orchestrator.ErrConflict, Reason: "upgrade_in_progress"}, gen.ProblemCodeConflict, 409},
		{&orchestrator.CreateError{Kind: orchestrator.ErrIdempotencyInProgress, RetryAfter: 3 * time.Second}, gen.ProblemCodeConflict, 409},
		{&orchestrator.CreateError{Kind: orchestrator.ErrIdempotencyKeyReuse}, gen.ProblemCodeIdempotencyKeyReuse, 422},
		{fmt.Errorf("wrap: %w", orchestrator.ErrNotFound), gen.ProblemCodeNotFound, 404},
		{errors.New("database down"), gen.ProblemCodeInternalError, 500},
	} {
		var p *problem.Error
		if !errors.As(failure(c.err), &p) || p.Code != c.code || p.Status() != c.status {
			t.Errorf("%v ⇒ %+v, want %s %d", c.err, p, c.code, c.status)
		}
	}
	var p *problem.Error
	_ = errors.As(failure(&orchestrator.CreateError{Kind: orchestrator.ErrConflict, Reason: "already_on_target"}), &p)
	if !strings.Contains(p.Detail, "already runs this image") {
		t.Fatalf("detail %q", p.Detail)
	}
	_ = errors.As(failure(&orchestrator.CreateError{Kind: orchestrator.ErrInvalid, Reason: "invalid_digest", Field: "image_digest"}), &p)
	if len(p.Fields) != 1 || p.Fields[0].Field != "image_digest" {
		t.Fatalf("fields %+v", p.Fields)
	}
}

// TestRequestHash: the Idempotency-Key hash of an upgrade covers the instance and the target.
func TestRequestHash(t *testing.T) {
	i1, i2 := uuid.New(), uuid.New()
	d1, d2 := "sha256:"+strings.Repeat("a", 64), "sha256:"+strings.Repeat("b", 64)
	a, _ := requestHash(i1, &gen.InstanceUpgrade{ImageDigest: d1})
	b, _ := requestHash(i1, &gen.InstanceUpgrade{ImageDigest: d1})
	c, _ := requestHash(i2, &gen.InstanceUpgrade{ImageDigest: d1})
	d, _ := requestHash(i1, &gen.InstanceUpgrade{ImageDigest: d2})
	if !bytes.Equal(a, b) || bytes.Equal(a, c) || bytes.Equal(a, d) || len(a) != 32 {
		t.Fatal("hash")
	}
	if JobLocation(uuid.Nil) != "/api/v1/platform/jobs/00000000-0000-0000-0000-000000000000" {
		t.Fatal(JobLocation(uuid.Nil))
	}
}

type nopService struct{}

func (nopService) Restart(context.Context, uuid.UUID, uuid.UUID, *orchestrator.Idempotency) (orchestrator.Reconfigured, error) {
	return orchestrator.Reconfigured{}, errors.New("never called")
}

func (nopService) Upgrade(context.Context, uuid.UUID, uuid.UUID, string, *orchestrator.Idempotency) (orchestrator.Reconfigured, error) {
	return orchestrator.Reconfigured{}, errors.New("never called")
}

// TestHandlerNeedsDecision: without the session and the platform decision of the hooks, nothing is enqueued.
func TestHandlerNeedsDecision(t *testing.T) {
	var p *problem.Error
	_, err := New(nopService{}).RestartPlatformInstance(context.Background(), gen.RestartPlatformInstanceRequestObject{InstanceId: uuid.New()})
	if !errors.As(err, &p) || p.Code != gen.ProblemCodeInternalError {
		t.Fatalf("restart: %v", err)
	}
	_, err = New(nopService{}).UpgradePlatformInstance(context.Background(), gen.UpgradePlatformInstanceRequestObject{InstanceId: uuid.New(),
		Body: &gen.InstanceUpgrade{ImageDigest: "sha256:" + strings.Repeat("a", 64)}})
	if !errors.As(err, &p) || p.Code != gen.ProblemCodeInternalError {
		t.Fatalf("upgrade: %v", err)
	}
}
