package approvalsapi

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/authz"
	"github.com/zhaduchanhzz/network-access-mesh/internal/authz/approvals"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/gen"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/problem"
)

// TestFailureMapping — every refusal of the service keeps its §13.1 code, a fixed detail and its reason as the
// authz.Denial cause (read by the audit middleware, never sent).
func TestFailureMapping(t *testing.T) {
	for _, tc := range []struct {
		err  error
		code gen.ProblemCode
	}{
		{&approvals.Error{Kind: approvals.ErrNotFound, Reason: approvals.ReasonNotFound}, gen.ProblemCodeNotFound},
		{&approvals.Error{Kind: approvals.ErrForbidden, Reason: approvals.ReasonSelfDecision}, gen.ProblemCodeForbidden},
		{&approvals.Error{Kind: approvals.ErrReauthRequired, Reason: approvals.ReasonStepUp}, gen.ProblemCodeReauthRequired},
		{&approvals.Error{Kind: approvals.ErrPayloadChanged, Reason: approvals.ReasonPayloadChanged}, gen.ProblemCodePreconditionFailed},
		{&approvals.Error{Kind: approvals.ErrConflict, Reason: approvals.ReasonExpired}, gen.ProblemCodeConflict},
		{&approvals.Error{Kind: approvals.ErrUnavailable, Reason: approvals.ReasonActionUnavailable}, gen.ProblemCodeConflict},
		{&approvals.Error{Kind: approvals.ErrInvalid, Reason: approvals.ReasonInvalidInput}, gen.ProblemCodeValidationFailed},
		{&authz.Denial{Kind: authz.ErrForbidden, Reason: "no_grant"}, gen.ProblemCodeForbidden},
		{errors.New("database down"), gen.ProblemCodeInternalError},
	} {
		var p *problem.Error
		if !errors.As(failure(tc.err), &p) || p.Code != tc.code {
			t.Errorf("%v: %v, want %s", tc.err, failure(tc.err), tc.code)
			continue
		}
		var d *authz.Denial
		if tc.code != gen.ProblemCodeInternalError && (!errors.As(p, &d) || d.Reason == "") {
			t.Errorf("%v: no denial reason for the audit", tc.err)
		}
		if strings.Contains(p.Detail, "self_approval") || strings.Contains(p.Detail, "approval_expired") {
			t.Errorf("%v: the reason leaks into the detail %q", tc.err, p.Detail)
		}
	}
}

// TestToAPI — the payload goes out as stored (canonical JSON), optional fields only when set.
func TestToAPI(t *testing.T) {
	now := time.Now().UTC()
	job, by := uuid.New(), uuid.New()
	r := approvals.Request{ID: uuid.New(), Scope: authz.ScopePlatform, Action: "platform.instance.restore",
		ResourceType: "instance", Payload: json.RawMessage(`{"backup_id":"b"}`), PayloadSHA256: strings.Repeat("a", 64),
		Status: approvals.StatusExecuted, RequestedBy: approvals.Person{IdentityID: by, Display: "SA"},
		DecidedBy: &approvals.Person{IdentityID: uuid.New(), Display: "PO"}, DecidedAt: &now, ExpiresAt: now, JobID: &job,
		CreatedAt: now}
	out := toAPI(r)
	raw, _ := json.Marshal(out)
	if !strings.Contains(string(raw), `"payload":{"backup_id":"b"}`) || out.ResourceId != nil || out.Reason != nil ||
		out.DecidedBy == nil || out.JobId == nil || *out.JobId != job || out.Status != gen.ApprovalStatusExecuted {
		t.Fatalf("toAPI %s", raw)
	}
}

// TestHandlersNeedTheChain — without the session and the authorization decision a decision handler fails closed.
func TestHandlersNeedTheChain(t *testing.T) {
	h := New(nil)
	if _, err := h.ApprovePlatformApproval(context.Background(), gen.ApprovePlatformApprovalRequestObject{
		ApprovalId: uuid.New(), Body: &gen.ApprovalDecision{PayloadSha256: strings.Repeat("a", 64)}}); err == nil {
		t.Fatal("approve without session")
	}
	if _, err := reviewed(&gen.ApprovalDecision{PayloadSha256: "ABC"}); err == nil {
		t.Fatal("malformed hash accepted")
	}
	if _, err := reviewed(nil); err == nil {
		t.Fatal("missing body accepted")
	}
}
