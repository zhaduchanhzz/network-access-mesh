package quarantine

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	agentv1 "github.com/zhaduchanhzz/network-access-mesh/api/agent/v1"
	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
)

func refusal(code codes.Code, reason agentv1.RefusalReason, msg string) error {
	st, err := status.New(code, msg).WithDetails(&agentv1.Refusal{Reason: reason, Field: "instance", Message: msg})
	if err != nil {
		panic(err)
	}
	return st.Err()
}

// TestKindsAndSteps: the two kinds exist in the §13.5 registry with the dedupe keys of this task (release keyed apart
// from quarantine: an unfinished release never delays a quarantine), no lifecycle lock (a quarantine never waits for
// it), the quarantine on its own queue; step names unique and valid.
func TestKindsAndSteps(t *testing.T) {
	ks := jobs.DefaultKinds()
	q, r := ks[KindQuarantine], ks[KindRelease]
	if q.Dedupe != "instance:{instance}:quarantine" || r.Dedupe != "instance:{instance}:release" || q.Lock != jobs.LockNone ||
		r.Lock != jobs.LockNone || q.Queue != jobs.QueueUrgent || q.Scope != jobs.ScopeInstance || r.Scope != jobs.ScopeInstance {
		t.Fatalf("kinds: %+v / %+v", q, r)
	}
	for _, kind := range [][]string{QuarantineSteps, ReleaseSteps} {
		seen := map[string]bool{}
		for _, s := range kind {
			if seen[s] || !strings.Contains(s, ".") && s != StepValidate && s != StepNotify {
				t.Errorf("step %q repeated or not dotted", s)
			}
			seen[s] = true
		}
	}
	if dedupe(uuid.Nil) == releaseDedupe(uuid.Nil) {
		t.Fatal("quarantine and release share a dedupe key")
	}
}

// TestInputs: inputs, payloads and reasons are checked.
func TestInputs(t *testing.T) {
	id, tid := uuid.New(), uuid.New()
	op := audit.Operation{ID: uuid.New(), Action: ActionQuarantine}
	if (Input{TenantID: tid, InstanceID: id, Slug: "acme", Operation: op}).validate() != nil ||
		(Input{TenantID: tid, InstanceID: id, Operation: op}).validate() == nil ||
		(Input{TenantID: tid, InstanceID: id, Slug: "acme"}).validate() == nil {
		t.Fatal("Input.validate")
	}
	if (ReleaseInput{TenantID: tid, InstanceID: id, Slug: "acme", ApprovalID: uuid.New(), Operation: op}).validate() != nil ||
		(ReleaseInput{TenantID: tid, InstanceID: id, Slug: "acme", Operation: op}).validate() == nil {
		t.Fatal("ReleaseInput.validate")
	}
	if (ReleasePayload{InstanceID: id, TenantID: tid}).Validate() != nil || (ReleasePayload{InstanceID: id}).Validate() == nil ||
		(ReleasePayload{InstanceID: id, TenantID: id}).Validate() == nil {
		t.Fatal("ReleasePayload.Validate")
	}
	for _, bad := range []string{"", "   ", strings.Repeat("x", MaxReason+1), "\xff"} {
		if _, err := CleanReason(bad); !errors.Is(err, ErrInvalid) {
			t.Errorf("reason %q accepted", bad)
		}
	}
	if r, err := CleanReason("  suspected compromise  "); err != nil || r != "suspected compromise" {
		t.Fatalf("reason: %q %v", r, err)
	}
	if r, err := CleanReason(strings.Repeat("ê", MaxReason)); err != nil || len([]rune(r)) != MaxReason {
		t.Fatal("a reason of MaxReason characters is refused")
	}
}

// TestErrorClassification: agent and Headscale errors, final errors, helpers.
func TestErrorClassification(t *testing.T) {
	for _, c := range []struct {
		err       error
		code      string
		permanent bool
	}{
		{status.Error(codes.Unavailable, "down"), "agent_unavailable", false},
		{refusal(codes.Aborted, agentv1.RefusalReason_REFUSAL_REASON_BUSY, "busy"), "agent_busy", false},
		{status.Error(codes.DeadlineExceeded, "slow"), "agent_unavailable", false},
		{refusal(codes.FailedPrecondition, agentv1.RefusalReason_REFUSAL_REASON_STATE, "start guard (§11.4): x"), "agent_state", true},
		{refusal(codes.NotFound, agentv1.RefusalReason_REFUSAL_REASON_NOT_FOUND, "no instance"), "agent_not_found", true},
		{status.Error(codes.Unimplemented, "no"), "agent_error", true},
	} {
		got := agentErr("X", c.err)
		if jobs.CodeOf(got) != c.code || jobs.IsPermanent(got) != c.permanent {
			t.Errorf("%v ⇒ %s permanent=%v, want %s %v", c.err, jobs.CodeOf(got), jobs.IsPermanent(got), c.code, c.permanent)
		}
	}
	if !notFound(refusal(codes.NotFound, agentv1.RefusalReason_REFUSAL_REASON_NOT_FOUND, "x")) || notFound(status.Error(codes.NotFound, "x")) {
		t.Fatal("notFound")
	}
	if !startGuardRefusal(refusal(codes.FailedPrecondition, agentv1.RefusalReason_REFUSAL_REASON_STATE, "Start guard (§11.4): x")) ||
		startGuardRefusal(refusal(codes.FailedPrecondition, agentv1.RefusalReason_REFUSAL_REASON_STATE, "the instance is quarantined")) {
		t.Fatal("startGuardRefusal")
	}
	for _, c := range []struct {
		err       error
		code      string
		permanent bool
	}{
		{&headscale.Error{Kind: headscale.KindUnavailable}, "instance_unavailable", false},
		{&headscale.Error{Kind: headscale.KindCircuitOpen}, "instance_unavailable", false},
		{headscale.ErrNoInstance, "instance_unavailable", false},
		{&headscale.Error{Kind: headscale.KindAPIKeyRejected, Err: headscale.ErrAPIKeyRejected}, "headscale_api_key_rejected", true},
		{&headscale.Error{Kind: headscale.KindUpstreamRejected}, "headscale_upstream_rejected", true},
	} {
		got := headscaleErr("X", c.err)
		if jobs.CodeOf(got) != c.code || jobs.IsPermanent(got) != c.permanent {
			t.Errorf("%v ⇒ %s %v", c.err, jobs.CodeOf(got), jobs.IsPermanent(got))
		}
	}
	if f := final(jobs.Resumable("x_y", errors.New("e"))); !jobs.IsPermanent(f) || jobs.CodeOf(f) != "x_y" {
		t.Fatal("final keeps the code and makes it permanent")
	}
	running := []agentv1.ContainerState{agentv1.ContainerState_CONTAINER_STATE_RUNNING, agentv1.ContainerState_CONTAINER_STATE_RESTARTING,
		agentv1.ContainerState_CONTAINER_STATE_PAUSED, agentv1.ContainerState_CONTAINER_STATE_UNSPECIFIED}
	for s := range agentv1.ContainerState_name {
		st := agentv1.ContainerState(s)
		if containerRunning(st) != slices.Contains(running, st) {
			t.Errorf("containerRunning(%s)", st)
		}
	}
	for _, s := range tenants.InstanceStatuses {
		if nothingOnHost(s) != (s == tenants.InstanceAllocated || s == tenants.InstanceFailed) {
			t.Errorf("nothingOnHost(%s)", s)
		}
	}
}

// TestNewChecksTheConfiguration: a store and a registry are required.
func TestNewChecksTheConfiguration(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Fatal("New without store")
	}
}
