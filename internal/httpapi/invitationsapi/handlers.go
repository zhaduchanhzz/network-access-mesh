// Package invitationsapi serves the invitation operations of api/openapi.yaml built by P3-T05a
// (httpapi.InvitationHandlers): listTenantInvitations, createTenantInvitation, revokeTenantInvitation,
// resendTenantInvitation — all `tenant.invitation:manage` (TO, TA — §8.6). It translates between the generated types
// and internal/tenants; the role an invitation carries is checked by authz.GuardInvitationRole (§8.4 rules 3, 3a)
// inside the service's transaction. The binding of an invitation at the first login is in the identity callback
// (identity.InvitationBinder, implemented by tenants.Service).
//
// Wiring (apps/internal/runner — api process):
//
//	httpapi.Handlers{…, Invitations: invitationsapi.New(tenantsService, authz.GuardInvitationRole)}
package invitationsapi

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/authz"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/authzhook"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/gen"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/problem"
	"github.com/zhaduchanhzz/network-access-mesh/internal/identity"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
)

// Service is the part of *tenants.Service the handlers use.
type Service interface {
	ListInvitations(ctx context.Context, tenantID uuid.UUID, f tenants.InvitationFilter) (tenants.InvitationPage, error)
	CreateInvitation(ctx context.Context, tenantID uuid.UUID, actor tenants.InvitationActor, in tenants.NewInvitation,
		guard tenants.RoleGuard, idem *tenants.Idempotency) (tenants.Invitation, error)
	RevokeInvitation(ctx context.Context, tenantID, id uuid.UUID, actor tenants.InvitationActor, guard tenants.RoleGuard) error
	ResendInvitation(ctx context.Context, tenantID, id uuid.UUID, actor tenants.InvitationActor, ttl time.Duration,
		guard tenants.RoleGuard) (tenants.Invitation, error)
}

var _ Service = (*tenants.Service)(nil)

// Handlers implements httpapi.InvitationHandlers.
type Handlers struct {
	svc   Service
	guard tenants.RoleGuard
}

var _ httpapi.InvitationHandlers = (*Handlers)(nil)

// New returns the handler set of P3-T05a; guard is authz.GuardInvitationRole.
func New(svc Service, guard tenants.RoleGuard) *Handlers { return &Handlers{svc: svc, guard: guard} }

var errNoDecision = errors.New("invitationsapi: no session or decision in the request context (hooks missing)")

// actorOf is the caller: its identity (session) and its membership in the tenant of the path (decision).
func actorOf(ctx context.Context) (tenants.InvitationActor, error) {
	s, ok := identity.SessionFromContext(ctx)
	d, okd := authzhook.DecisionFrom(ctx)
	if !ok || !okd || d.MembershipID == uuid.Nil || d.Principal.IdentityID != s.IdentityID {
		return tenants.InvitationActor{}, problem.Internal(errNoDecision)
	}
	display := s.DisplayName
	if display == "" {
		display = s.Email
	}
	return tenants.InvitationActor{IdentityID: s.IdentityID, MembershipID: d.MembershipID, Display: display,
		ClientIP: httpapi.ClientIP(ctx)}, nil
}

// failure maps an error of the service: the authorization refusals of the role guard as decided, not found ⇒ 404,
// invalid ⇒ 422, conflict ⇒ 409, the Idempotency-Key outcomes of §13.1, anything else ⇒ 500.
func failure(err error) error {
	var d *authz.Denial
	if errors.As(err, &d) {
		return authzhook.Problem(err)
	}
	reason := "conflict"
	var ie *tenants.InvitationError
	if errors.As(err, &ie) {
		reason = ie.Reason
	}
	cause := &authz.Denial{Kind: err, Reason: reason}
	switch {
	case errors.Is(err, tenants.ErrNotFound):
		return &problem.Error{Code: gen.ProblemCodeNotFound, Detail: "The resource does not exist.", Cause: cause}
	case errors.Is(err, tenants.ErrIdempotencyInProgress):
		p := &problem.Error{Code: gen.ProblemCodeConflict, Cause: cause,
			Detail: "A request with this Idempotency-Key is still in progress."}
		if ie != nil {
			p.RetryAfter = ie.RetryAfter
		}
		return p
	case errors.Is(err, tenants.ErrIdempotencyKeyReuse):
		return &problem.Error{Code: gen.ProblemCodeIdempotencyKeyReuse, Cause: cause,
			Detail: "The Idempotency-Key was used for another request."}
	case errors.Is(err, tenants.ErrInvalid):
		field := "body"
		switch reason {
		case "invalid_email":
			field = "email"
		case "role_not_invitable":
			field = "role"
		case "invalid_ttl":
			field = "expires_in_hours"
		}
		return problem.Validation("The request is invalid.", problem.Field(field, reason, "has an invalid value"))
	case errors.Is(err, tenants.ErrConflict):
		detail := map[string]string{
			"already_member":            "This e-mail address already belongs to a member of the tenant.",
			"invitation_pending":        "This e-mail address already has a pending invitation.",
			"invitation_not_pending":    "The invitation is no longer pending.",
			"invitation_not_resendable": "Only a pending or expired invitation can be sent again.",
			"no_active_idp":             "The tenant has no active identity provider.",
		}[reason]
		if detail == "" {
			detail = "The request conflicts with the current state of the invitations."
		}
		return &problem.Error{Code: gen.ProblemCodeConflict, Detail: detail, Cause: cause}
	}
	return problem.Internal(err)
}

func toAPI(i tenants.Invitation) gen.Invitation {
	out := gen.Invitation{Id: i.ID, Email: i.Email, Role: i.Role, Status: gen.InvitationStatus(i.Status),
		ExpiresAt: i.ExpiresAt, AcceptedIdentityId: i.AcceptedIdentityID, AcceptedAt: i.AcceptedAt,
		CreatedAt: i.CreatedAt, UpdatedAt: i.UpdatedAt}
	if i.InvitedBy != nil {
		out.InvitedBy = &gen.IdentityRef{IdentityId: *i.InvitedBy, DisplayName: i.InvitedByDisplay}
	}
	return out
}

func hours(h *int) time.Duration {
	if h == nil {
		return 0
	}
	if *h <= 0 {
		return -1 // out of range: the service refuses it (an explicit 0 is not "the default")
	}
	return time.Duration(*h) * time.Hour
}

// ListTenantInvitations implements GET /tenants/{tenantId}/invitations.
func (h *Handlers) ListTenantInvitations(ctx context.Context, req gen.ListTenantInvitationsRequestObject) (gen.ListTenantInvitationsResponseObject, error) {
	var f tenants.InvitationFilter
	if p := req.Params.Limit; p != nil {
		f.Limit = *p
		if f.Limit == 0 {
			f.Limit = -1
		}
	}
	if c := req.Params.Cursor; c != nil {
		f.Cursor = *c
	}
	if st := req.Params.Status; st != nil {
		f.Status = string(*st)
	}
	page, err := h.svc.ListInvitations(ctx, req.TenantId, f)
	if err != nil {
		return nil, failure(err)
	}
	out := gen.InvitationList{Items: make([]gen.Invitation, 0, len(page.Items))}
	for _, i := range page.Items {
		out.Items = append(out.Items, toAPI(i))
	}
	if page.NextCursor != "" {
		c := page.NextCursor
		out.NextCursor = &c
	}
	return gen.ListTenantInvitations200JSONResponse(out), nil
}

// CreateTenantInvitation implements POST /tenants/{tenantId}/invitations (Idempotency-Key: the hash covers the method,
// the path with the tenant and the canonical body — §13.1).
func (h *Handlers) CreateTenantInvitation(ctx context.Context, req gen.CreateTenantInvitationRequestObject) (gen.CreateTenantInvitationResponseObject, error) {
	a, err := actorOf(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, problem.Validation("The request body is invalid.", problem.Field("body", "required", "a JSON body is required"))
	}
	body, err := json.Marshal(req.Body)
	if err != nil {
		return nil, problem.Internal(err)
	}
	idem := &tenants.Idempotency{Key: req.Params.IdempotencyKey,
		Hash: jobs.RequestHash("POST", "/tenants/"+req.TenantId.String()+"/invitations", body)}
	inv, err := h.svc.CreateInvitation(ctx, req.TenantId, a, tenants.NewInvitation{Email: req.Body.Email,
		Role: string(req.Body.Role), TTL: hours(req.Body.ExpiresInHours)}, h.guard, idem)
	if err != nil {
		return nil, failure(err)
	}
	return gen.CreateTenantInvitation201JSONResponse(toAPI(inv)), nil
}

// RevokeTenantInvitation implements DELETE /tenants/{tenantId}/invitations/{invitationId}.
func (h *Handlers) RevokeTenantInvitation(ctx context.Context, req gen.RevokeTenantInvitationRequestObject) (gen.RevokeTenantInvitationResponseObject, error) {
	a, err := actorOf(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.svc.RevokeInvitation(ctx, req.TenantId, req.InvitationId, a, h.guard); err != nil {
		return nil, failure(err)
	}
	return gen.RevokeTenantInvitation204Response{}, nil
}

// ResendTenantInvitation implements POST /tenants/{tenantId}/invitations/{invitationId}/resend.
func (h *Handlers) ResendTenantInvitation(ctx context.Context, req gen.ResendTenantInvitationRequestObject) (gen.ResendTenantInvitationResponseObject, error) {
	a, err := actorOf(ctx)
	if err != nil {
		return nil, err
	}
	var ttl time.Duration
	if req.Body != nil {
		ttl = hours(req.Body.ExpiresInHours)
	}
	inv, err := h.svc.ResendInvitation(ctx, req.TenantId, req.InvitationId, a, ttl, h.guard)
	if err != nil {
		return nil, failure(err)
	}
	return gen.ResendTenantInvitation200JSONResponse(toAPI(inv)), nil
}
