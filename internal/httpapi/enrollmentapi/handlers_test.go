package enrollmentapi

import (
	"errors"
	"testing"

	"github.com/zhaduchanhzz/network-access-mesh/internal/enrollment"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/gen"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/problem"
)

// P4-T08: the claim page tells the conflicts of POST /enrollment/web-auth/claim apart by Problem.errors[0].code (never
// by detail); other problems keep their shape (404 says nothing more than "not found").
func TestFailureCarriesStableReason(t *testing.T) {
	cases := []struct {
		name   string
		err    error
		code   gen.ProblemCode
		field  string
		reason string // "" ⇒ no errors[]
	}{
		{"no pending request", &enrollment.Error{Code: enrollment.CodeConflict, Reason: "no_pending_request", Detail: "d"},
			gen.ProblemCodeConflict, "request", "no_pending_request"},
		{"already claimed", &enrollment.Error{Code: enrollment.CodeConflict, Reason: "auth_id_already_claimed", Detail: "d"},
			gen.ProblemCodeConflict, "request", "auth_id_already_claimed"},
		{"not pending at Headscale (wrapped)", errors.Join(errors.New("x"), &enrollment.Error{Code: enrollment.CodeConflict,
			Reason: enrollment.FailureNotPending}), gen.ProblemCodeConflict, "request", enrollment.FailureNotPending},
		{"already started", &enrollment.Error{Code: enrollment.CodeConflict, Reason: "already_started", Detail: "d"},
			gen.ProblemCodeConflict, "request", "already_started"},
		{"odd reason is not echoed", &enrollment.Error{Code: enrollment.CodeConflict, Reason: "Bad Reason!", Detail: "d"},
			gen.ProblemCodeConflict, "", ""},
		{"validation keeps its field", &enrollment.Error{Code: enrollment.CodeValidationFailed, Reason: "request_id_required",
			Field: "request_id", Detail: "d"}, gen.ProblemCodeValidationFailed, "request_id", "request_id_required"},
		{"not found says nothing more", &enrollment.Error{Code: enrollment.CodeNotFound, Reason: "membership", Detail: "d"},
			gen.ProblemCodeNotFound, "", ""},
		{"forbidden says nothing more", &enrollment.Error{Code: enrollment.CodeForbidden, Reason: "self_approval", Detail: "d"},
			gen.ProblemCodeForbidden, "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var p *problem.Error
			if !errors.As(failure(c.err), &p) {
				t.Fatalf("failure(%v) is not a problem", c.err)
			}
			if p.Code != c.code || p.Detail == "" {
				t.Fatalf("code %q detail %q, want %q and a detail", p.Code, p.Detail, c.code)
			}
			if c.reason == "" {
				if len(p.Fields) != 0 {
					t.Fatalf("errors %+v, want none", p.Fields)
				}
				return
			}
			if len(p.Fields) != 1 || p.Fields[0].Code != c.reason || p.Fields[0].Field != c.field || p.Fields[0].Message == "" {
				t.Fatalf("errors %+v, want one {%s %s}", p.Fields, c.field, c.reason)
			}
		})
	}
}
