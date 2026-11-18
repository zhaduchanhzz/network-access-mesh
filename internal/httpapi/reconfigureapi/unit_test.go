package reconfigureapi

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
		{&orchestrator.CreateError{Kind: orchestrator.ErrInvalid, Reason: "out_of_range", Field: "node_expiry_days"}, gen.ProblemCodeValidationFailed, 422},
		{&orchestrator.CreateError{Kind: orchestrator.ErrConflict, Reason: "instance_quarantined"}, gen.ProblemCodeConflict, 409},
		{&orchestrator.CreateError{Kind: orchestrator.ErrConflict, Reason: "reconfigure_in_progress"}, gen.ProblemCodeConflict, 409},
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
	_ = errors.As(failure(&orchestrator.CreateError{Kind: orchestrator.ErrConflict, Reason: "no_config_version"}), &p)
	if !strings.Contains(p.Detail, "configuration version") {
		t.Fatalf("detail %q", p.Detail)
	}
	_ = errors.As(failure(&orchestrator.CreateError{Kind: orchestrator.ErrInvalid, Reason: "invalid_address", Field: "nameservers"}), &p)
	if len(p.Fields) != 1 || p.Fields[0].Field != "nameservers" || p.Fields[0].Code != "invalid_address" {
		t.Fatalf("fields %+v", p.Fields)
	}
}

func TestChange(t *testing.T) {
	warn := gen.InstanceLogLevelWarn
	days, derp := 30, 950
	ns := []string{"2001:DB8::53", "9.9.9.9"}
	c, err := Change(gen.InstanceReconfigure{LogLevel: &warn, NodeExpiryDays: &days, DerpRegionId: &derp, Nameservers: &ns})
	if err != nil || c.LogLevel != "warn" || *c.NodeExpiryDays != 30 || *c.DERPRegionID != 950 ||
		strings.Join(c.Nameservers, ",") != "2001:db8::53,9.9.9.9" {
		t.Fatalf("%+v %v", c, err)
	}
	if c, err := Change(gen.InstanceReconfigure{}); err != nil || !c.Equal(orchestrator.ConfigChange{}) {
		t.Fatalf("empty body: %+v %v", c, err)
	}
	zero, big, empty, bad := 0, 1000, gen.InstanceLogLevel(""), gen.InstanceLogLevel("debug")
	none := []string{}
	for field, b := range map[string]gen.InstanceReconfigure{
		"node_expiry_days": {NodeExpiryDays: &zero},
		"derp_region_id":   {DerpRegionId: &big},
		"nameservers":      {Nameservers: &none},
		"log_level":        {LogLevel: &empty},
	} {
		var ce *orchestrator.CreateError
		if _, err := Change(b); !errors.As(err, &ce) || ce.Field != field {
			t.Errorf("%s: %v", field, err)
		}
	}
	if _, err := Change(gen.InstanceReconfigure{LogLevel: &bad}); !errors.Is(err, orchestrator.ErrInvalid) {
		t.Fatal(err)
	}
}

// TestRequestHash: the Idempotency-Key hash covers the instance and the body.
func TestRequestHash(t *testing.T) {
	warn, errl := gen.InstanceLogLevelWarn, gen.InstanceLogLevelError
	i1, i2 := uuid.New(), uuid.New()
	a, _ := requestHash(i1, &gen.InstanceReconfigure{LogLevel: &warn})
	b, _ := requestHash(i1, &gen.InstanceReconfigure{LogLevel: &warn})
	c, _ := requestHash(i2, &gen.InstanceReconfigure{LogLevel: &warn})
	d, _ := requestHash(i1, &gen.InstanceReconfigure{LogLevel: &errl})
	if !bytes.Equal(a, b) || bytes.Equal(a, c) || bytes.Equal(a, d) || len(a) != 32 {
		t.Fatal("hash")
	}
	if JobLocation(uuid.Nil) != "/api/v1/platform/jobs/00000000-0000-0000-0000-000000000000" {
		t.Fatal(JobLocation(uuid.Nil))
	}
}

type nopService struct{}

func (nopService) Request(context.Context, uuid.UUID, uuid.UUID, orchestrator.ConfigChange, *orchestrator.Idempotency) (orchestrator.Reconfigured, error) {
	return orchestrator.Reconfigured{}, errors.New("never called")
}

// TestHandlerNeedsDecision: without the session and the platform decision of the hooks, nothing is enqueued.
func TestHandlerNeedsDecision(t *testing.T) {
	warn := gen.InstanceLogLevelWarn
	_, err := New(nopService{}).ReconfigurePlatformInstance(context.Background(), gen.ReconfigurePlatformInstanceRequestObject{
		InstanceId: uuid.New(), Body: &gen.InstanceReconfigure{LogLevel: &warn}})
	var p *problem.Error
	if !errors.As(err, &p) || p.Code != gen.ProblemCodeInternalError {
		t.Fatalf("%v", err)
	}
}
