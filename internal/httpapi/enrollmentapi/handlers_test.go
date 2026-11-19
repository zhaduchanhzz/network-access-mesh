package enrollmentapi

import (
	"errors"
	"net/http"
	"net/netip"
	"testing"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/authz"
	"github.com/zhaduchanhzz/network-access-mesh/internal/enrollment"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/gen"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/problem"
	"github.com/zhaduchanhzz/network-access-mesh/internal/identity"
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

// The caller of a request (C4): platform staff acting through a live Support Access Grant (authz.decideSupport — no
// membership, the grant, the effective role; never scope own) is a caller like a tenant role of scope any — not the 500
// of a missing hook —; an operation that records a membership (memberOf: create, key, start, claim, approve, reject)
// refuses it with 403 forbidden whose cause carries the reason support_actor_not_member (the audit's); a member's
// decision keeps its obligations; a decision that is neither a member's nor a support actor's, or both, or of another
// identity, or no session ⇒ 500.
func TestActorFromDecision(t *testing.T) {
	id, member, grant := uuid.New(), uuid.New(), uuid.New()
	s := &identity.Session{IdentityID: id, PublicID: uuid.New(), Email: "staff@example.test"}
	who := authz.Principal{IdentityID: id, Scope: authz.ScopePlatform, Origin: authz.OriginAdmin}
	ip := netip.MustParseAddr("192.0.2.7")
	support := authz.Decision{Principal: who, TenantID: uuid.New(), RoleKey: authz.RoleSupportOperator,
		PlatformUserID: uuid.New(), SupportGrantID: grant}
	a, err := actorFrom(s, support, ip)
	if err != nil || a.MembershipID != uuid.Nil || a.OwnOnly || a.SelfEnrollOnly || a.IdentityID != id ||
		a.SessionID != s.PublicID || a.Display != s.Email || a.ClientIP != ip {
		t.Fatalf("support actor %+v, %v", a, err)
	}
	_, err = asMember(a, nil)
	var p *problem.Error
	var d *authz.Denial
	if !errors.As(err, &p) || p.Code != gen.ProblemCodeForbidden || p.Status() != http.StatusForbidden || p.Detail == "" ||
		!errors.As(err, &d) || d.Reason != ReasonSupportNotMember {
		t.Fatalf("a support actor on an operation that records a member: %v", err)
	}

	tenant := authz.Decision{Principal: who, MembershipID: member, OwnOnly: true, Condition: authz.CondSelfEnroll}
	if a, err := asMember(actorFrom(s, tenant, ip)); err != nil || a.MembershipID != member || !a.OwnOnly || !a.SelfEnrollOnly {
		t.Fatalf("member %+v, %v", a, err)
	}

	for name, d := range map[string]authz.Decision{
		"no membership, no grant": {Principal: who},
		"membership and grant":    {Principal: who, MembershipID: member, SupportGrantID: grant},
		"another identity":        {Principal: authz.Principal{IdentityID: uuid.New()}, SupportGrantID: grant},
	} {
		if _, err := actorFrom(s, d, ip); !errors.As(err, &p) || p.Code != gen.ProblemCodeInternalError {
			t.Errorf("%s: %v, want 500", name, err)
		}
	}
	if _, err := actorFrom(nil, support, ip); !errors.As(err, &p) || p.Code != gen.ProblemCodeInternalError {
		t.Errorf("no session: %v, want 500", err)
	}
	if _, err := asMember(enrollment.Actor{}, problem.Internal(errNoDecision)); !errors.As(err, &p) ||
		p.Code != gen.ProblemCodeInternalError {
		t.Errorf("asMember must keep the error of actorOf: %v", err)
	}
}
