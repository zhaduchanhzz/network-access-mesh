// Package membersapi serves the operations of api/openapi.yaml built by P4-T09 (httpapi.MemberHandlers): the write
// side of the users of a tenant — updateTenantUser (lock/unlock), offboardTenantUser (two-phase offboarding),
// setTenantUserRole, setTenantUserAdminRole, transferTenantOwnership, revokeTenantUserSessions — and its groups —
// listTenantGroups, createTenantGroup, getTenantGroup, updateTenantGroup, deleteTenantGroup, setTenantGroupMembers
// (a sensitive group turns into a tenant-scope approval request, P3-T04a: 202 + Location of /approvals/{id}). It
// translates between the generated types and internal/members; the membership rules of §8.4 (3, 3a, last Owner) are
// authz.GuardMembershipChange inside the service's transactions, their refusals answered as authorization decided.
//
// Wiring (apps/internal/runner — api process):
//
//	httpapi.Handlers{…, Members: membersapi.New(membersService, approvalsService)}
package membersapi

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/authz"
	"github.com/zhaduchanhzz/network-access-mesh/internal/authz/approvals"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/approvalsapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/authzhook"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/gen"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/problem"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/tenantsapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/identity"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/members"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
)

// Service is the part of *members.Service the handlers use.
type Service interface {
	SetStatus(ctx context.Context, tenantID, id uuid.UUID, a members.Actor, ifMatch, status string) (tenants.Member, error)
	SetRole(ctx context.Context, tenantID, id uuid.UUID, a members.Actor, ifMatch, role string, admin bool) (tenants.Member, error)
	TransferOwnership(ctx context.Context, tenantID uuid.UUID, a members.Actor, target uuid.UUID, previousRole string) (tenants.Member, error)
	RevokeUserSessions(ctx context.Context, tenantID, id uuid.UUID, a members.Actor) (int64, error)
	Offboard(ctx context.Context, tenantID, id uuid.UUID, a members.Actor) (members.OffboardResult, error)
	ListGroups(ctx context.Context, tenantID uuid.UUID, f members.GroupFilter) (members.GroupPage, error)
	GetGroup(ctx context.Context, tenantID, id uuid.UUID) (members.Group, error)
	CreateGroup(ctx context.Context, tenantID uuid.UUID, a members.Actor, in members.NewGroup, idem *members.Idempotency) (members.Group, error)
	UpdateGroup(ctx context.Context, tenantID, id uuid.UUID, a members.Actor, ifMatch string, p members.GroupPatch) (members.Group, error)
	DeleteGroup(ctx context.Context, tenantID, id uuid.UUID, a members.Actor, ifMatch string) error
	SetGroupMembers(ctx context.Context, tenantID, id uuid.UUID, a members.Actor, ifMatch string, ids []uuid.UUID) (members.SetMembersResult, error)
}

// Approvals is the part of *approvals.Service the sensitive groups use.
type Approvals interface {
	Request(ctx context.Context, actor approvals.Actor, in approvals.NewRequest) (approvals.Request, error)
}

var (
	_ Service   = (*members.Service)(nil)
	_ Approvals = (*approvals.Service)(nil)
)

// Handlers implements httpapi.MemberHandlers.
type Handlers struct {
	svc  Service
	appr Approvals
}

var _ httpapi.MemberHandlers = (*Handlers)(nil)

// New returns the handler set of P4-T09.
func New(svc Service, appr Approvals) *Handlers { return &Handlers{svc: svc, appr: appr} }

var errNoDecision = errors.New("membersapi: no session or decision in the request context (hooks missing)")

// actorOf is the caller: its identity and session (auth_time) and its membership in the tenant of the path.
func actorOf(ctx context.Context) (members.Actor, error) {
	s, ok := identity.SessionFromContext(ctx)
	d, okd := authzhook.DecisionFrom(ctx)
	if !ok || !okd || d.MembershipID == uuid.Nil || d.Principal.IdentityID != s.IdentityID {
		return members.Actor{}, problem.Internal(errNoDecision)
	}
	display := s.DisplayName
	if display == "" {
		display = s.Email
	}
	return members.Actor{IdentityID: s.IdentityID, MembershipID: d.MembershipID, Display: display,
		ClientIP: httpapi.ClientIP(ctx), AuthTime: s.AuthTime}, nil
}

// ifMatch is the If-Match of a write ("" when missing or "*": 428 — the IfMatch parameter of the spec).
func ifMatch(p *gen.IfMatch) string {
	if p == nil || *p == "*" {
		return ""
	}
	return *p
}

// failure maps an error of the service: a refusal of the membership rules (authz.Denial) as authorization decides
// it, the module's refusals by kind (the reason goes to the audit through the problem's cause), anything else ⇒ 500.
func failure(err error) error {
	var d *authz.Denial
	if errors.As(err, &d) {
		return authzhook.Problem(err)
	}
	var e *members.Error
	if !errors.As(err, &e) {
		return problem.Internal(err)
	}
	cause := &authz.Denial{Kind: err, Reason: e.Reason}
	switch {
	case errors.Is(err, members.ErrNotFound):
		return &problem.Error{Code: gen.ProblemCodeNotFound, Detail: "The resource does not exist.", Cause: cause}
	case errors.Is(err, members.ErrInvalid):
		field := e.Field
		if field == "" {
			field = "body"
		}
		p := problem.Validation(invalidDetail(e.Reason), problem.Field(field, e.Reason, "has an invalid value"))
		p.Cause = cause
		return p
	case errors.Is(err, members.ErrPreconditionRequired):
		return &problem.Error{Code: gen.ProblemCodePreconditionRequired, Cause: cause,
			Detail: "If-Match with the current ETag of the resource is required."}
	case errors.Is(err, members.ErrPreconditionFailed):
		return &problem.Error{Code: gen.ProblemCodePreconditionFailed, Cause: cause,
			Detail: "The resource changed since it was read; read it again."}
	case errors.Is(err, members.ErrReauthRequired):
		return &problem.Error{Code: gen.ProblemCodeReauthRequired, Cause: cause,
			Detail: "This operation needs a recent sign-in: sign in again."}
	case errors.Is(err, members.ErrIdempotencyInProgress):
		return &problem.Error{Code: gen.ProblemCodeConflict, RetryAfter: e.RetryAfter, Cause: cause,
			Detail: "A request with this Idempotency-Key is still in progress."}
	case errors.Is(err, members.ErrIdempotencyKeyReuse):
		return &problem.Error{Code: gen.ProblemCodeIdempotencyKeyReuse, Cause: cause,
			Detail: "The Idempotency-Key was used for another request."}
	case errors.Is(err, members.ErrConflict):
		return &problem.Error{Code: gen.ProblemCodeConflict, Detail: conflictDetail(e.Reason), Cause: cause}
	}
	return problem.Internal(err)
}

func invalidDetail(reason string) string {
	switch reason {
	case members.ReasonUseAdminRole:
		return "Giving or taking the Tenant Admin role, or changing an Owner, is PUT /users/{id}/admin-role."
	case members.ReasonUseRole:
		return "A change between roles below Tenant Admin is PUT /users/{id}/role."
	case members.ReasonOwnerRole:
		return "The Owner role is only given by POST /ownership-transfer."
	case members.ReasonMemberNotActive:
		return "Every member of a group must be an active member of the tenant."
	}
	return "The request is invalid."
}

func conflictDetail(reason string) string {
	if d, ok := map[string]string{
		members.ReasonOffboarded:        "The member was offboarded: the membership no longer changes.",
		members.ReasonGroupNameTaken:    "A group of the tenant already has this name.",
		members.ReasonGroupInUse:        "A network resource still names this group as its owner.",
		members.ReasonSensitiveNotEmpty: "A sensitive group with members cannot be deleted: empty it through an approval first.",
	}[reason]; ok {
		return d
	}
	return "The request conflicts with the current state."
}

func membership(m tenants.Member) gen.Membership { return tenantsapi.ToMembership(m) }

func jobLocation(tenantID, jobID uuid.UUID) string {
	return "/api/v1/tenants/" + tenantID.String() + "/jobs/" + jobID.String()
}

// UpdateTenantUser implements PATCH /tenants/{tenantId}/users/{membershipId}.
func (h *Handlers) UpdateTenantUser(ctx context.Context, req gen.UpdateTenantUserRequestObject) (gen.UpdateTenantUserResponseObject, error) {
	a, err := actorOf(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, problem.Validation("The request body is invalid.", problem.Field("body", "required", "a JSON body is required"))
	}
	m, err := h.svc.SetStatus(ctx, req.TenantId, req.MembershipId, a, ifMatch(req.Params.IfMatch), string(req.Body.Status))
	if err != nil {
		return nil, failure(err)
	}
	return gen.UpdateTenantUser200JSONResponse{Body: membership(m),
		Headers: gen.UpdateTenantUser200ResponseHeaders{ETag: members.ETag(m.Version)}}, nil
}

// OffboardTenantUser implements DELETE /tenants/{tenantId}/users/{membershipId}: 202 + Location of the job.
func (h *Handlers) OffboardTenantUser(ctx context.Context, req gen.OffboardTenantUserRequestObject) (gen.OffboardTenantUserResponseObject, error) {
	a, err := actorOf(ctx)
	if err != nil {
		return nil, err
	}
	res, err := h.svc.Offboard(ctx, req.TenantId, req.MembershipId, a)
	if err != nil {
		return nil, failure(err)
	}
	return gen.OffboardTenantUser202JSONResponse{Body: membership(res.Member),
		Headers: gen.OffboardTenantUser202ResponseHeaders{Location: jobLocation(req.TenantId, res.JobID)}}, nil
}

// SetTenantUserRole implements PUT /tenants/{tenantId}/users/{membershipId}/role.
func (h *Handlers) SetTenantUserRole(ctx context.Context, req gen.SetTenantUserRoleRequestObject) (gen.SetTenantUserRoleResponseObject, error) {
	a, err := actorOf(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, problem.Validation("The request body is invalid.", problem.Field("body", "required", "a JSON body is required"))
	}
	m, err := h.svc.SetRole(ctx, req.TenantId, req.MembershipId, a, ifMatch(req.Params.IfMatch), string(req.Body.Role), false)
	if err != nil {
		return nil, failure(err)
	}
	return gen.SetTenantUserRole200JSONResponse{Body: membership(m),
		Headers: gen.SetTenantUserRole200ResponseHeaders{ETag: members.ETag(m.Version)}}, nil
}

// SetTenantUserAdminRole implements PUT /tenants/{tenantId}/users/{membershipId}/admin-role.
func (h *Handlers) SetTenantUserAdminRole(ctx context.Context, req gen.SetTenantUserAdminRoleRequestObject) (gen.SetTenantUserAdminRoleResponseObject, error) {
	a, err := actorOf(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, problem.Validation("The request body is invalid.", problem.Field("body", "required", "a JSON body is required"))
	}
	m, err := h.svc.SetRole(ctx, req.TenantId, req.MembershipId, a, ifMatch(req.Params.IfMatch), string(req.Body.Role), true)
	if err != nil {
		return nil, failure(err)
	}
	return gen.SetTenantUserAdminRole200JSONResponse{Body: membership(m),
		Headers: gen.SetTenantUserAdminRole200ResponseHeaders{ETag: members.ETag(m.Version)}}, nil
}

// TransferTenantOwnership implements POST /tenants/{tenantId}/ownership-transfer.
func (h *Handlers) TransferTenantOwnership(ctx context.Context, req gen.TransferTenantOwnershipRequestObject) (gen.TransferTenantOwnershipResponseObject, error) {
	a, err := actorOf(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, problem.Validation("The request body is invalid.", problem.Field("body", "required", "a JSON body is required"))
	}
	prev := ""
	if req.Body.PreviousOwnerRole != nil {
		prev = string(*req.Body.PreviousOwnerRole)
	}
	m, err := h.svc.TransferOwnership(ctx, req.TenantId, a, req.Body.MembershipId, prev)
	if err != nil {
		return nil, failure(err)
	}
	return gen.TransferTenantOwnership200JSONResponse(membership(m)), nil
}

// RevokeTenantUserSessions implements DELETE /tenants/{tenantId}/users/{membershipId}/sessions.
func (h *Handlers) RevokeTenantUserSessions(ctx context.Context, req gen.RevokeTenantUserSessionsRequestObject) (gen.RevokeTenantUserSessionsResponseObject, error) {
	a, err := actorOf(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := h.svc.RevokeUserSessions(ctx, req.TenantId, req.MembershipId, a); err != nil {
		return nil, failure(err)
	}
	return gen.RevokeTenantUserSessions204Response{}, nil
}

func toGroup(g members.Group) gen.Group {
	out := gen.Group{Id: g.ID, Name: g.Name, Source: gen.GroupSource(g.Source), Sensitive: g.Sensitive,
		MemberCount: g.MemberCount, Version: g.Version, CreatedAt: g.CreatedAt, UpdatedAt: g.UpdatedAt}
	if g.Description != "" {
		d := g.Description
		out.Description = &d
	}
	if g.Members != nil {
		ms := make([]gen.GroupMember, 0, len(g.Members))
		for _, m := range g.Members {
			gm := gen.GroupMember{MembershipId: m.MembershipID, DisplayName: m.DisplayName, Role: m.Role, Status: m.Status}
			if m.Email != "" {
				e := m.Email
				gm.Email = &e
			}
			ms = append(ms, gm)
		}
		out.Members = &ms
	}
	return out
}

// ListTenantGroups implements GET /tenants/{tenantId}/groups.
func (h *Handlers) ListTenantGroups(ctx context.Context, req gen.ListTenantGroupsRequestObject) (gen.ListTenantGroupsResponseObject, error) {
	var f members.GroupFilter
	if p := req.Params.Limit; p != nil {
		f.Limit = *p
		if f.Limit == 0 {
			f.Limit = -1
		}
	}
	if c := req.Params.Cursor; c != nil {
		f.Cursor = *c
	}
	if q := req.Params.Q; q != nil {
		f.Query = *q
	}
	page, err := h.svc.ListGroups(ctx, req.TenantId, f)
	if err != nil {
		return nil, failure(err)
	}
	out := gen.GroupList{Items: make([]gen.Group, 0, len(page.Items))}
	for _, g := range page.Items {
		out.Items = append(out.Items, toGroup(g))
	}
	if page.NextCursor != "" {
		c := page.NextCursor
		out.NextCursor = &c
	}
	return gen.ListTenantGroups200JSONResponse(out), nil
}

// CreateTenantGroup implements POST /tenants/{tenantId}/groups (Idempotency-Key — §13.1).
func (h *Handlers) CreateTenantGroup(ctx context.Context, req gen.CreateTenantGroupRequestObject) (gen.CreateTenantGroupResponseObject, error) {
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
	in := members.NewGroup{Name: req.Body.Name}
	if req.Body.Description != nil {
		in.Description = *req.Body.Description
	}
	g, err := h.svc.CreateGroup(ctx, req.TenantId, a, in, &members.Idempotency{Key: req.Params.IdempotencyKey,
		Hash: jobs.RequestHash("POST", "/tenants/"+req.TenantId.String()+"/groups", body)})
	if err != nil {
		return nil, failure(err)
	}
	return gen.CreateTenantGroup201JSONResponse{Body: toGroup(g),
		Headers: gen.CreateTenantGroup201ResponseHeaders{ETag: members.ETag(g.Version)}}, nil
}

// GetTenantGroup implements GET /tenants/{tenantId}/groups/{groupId}.
func (h *Handlers) GetTenantGroup(ctx context.Context, req gen.GetTenantGroupRequestObject) (gen.GetTenantGroupResponseObject, error) {
	g, err := h.svc.GetGroup(ctx, req.TenantId, req.GroupId)
	if err != nil {
		return nil, failure(err)
	}
	return gen.GetTenantGroup200JSONResponse{Body: toGroup(g),
		Headers: gen.GetTenantGroup200ResponseHeaders{ETag: members.ETag(g.Version)}}, nil
}

// UpdateTenantGroup implements PATCH /tenants/{tenantId}/groups/{groupId}.
func (h *Handlers) UpdateTenantGroup(ctx context.Context, req gen.UpdateTenantGroupRequestObject) (gen.UpdateTenantGroupResponseObject, error) {
	a, err := actorOf(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil || req.Body.Name == nil && req.Body.Description == nil {
		return nil, problem.Validation("The request body is invalid.", problem.Field("body", "required",
			"name or description is required"))
	}
	g, err := h.svc.UpdateGroup(ctx, req.TenantId, req.GroupId, a, ifMatch(req.Params.IfMatch),
		members.GroupPatch{Name: req.Body.Name, Description: req.Body.Description})
	if err != nil {
		return nil, failure(err)
	}
	return gen.UpdateTenantGroup200JSONResponse{Body: toGroup(g),
		Headers: gen.UpdateTenantGroup200ResponseHeaders{ETag: members.ETag(g.Version)}}, nil
}

// DeleteTenantGroup implements DELETE /tenants/{tenantId}/groups/{groupId}.
func (h *Handlers) DeleteTenantGroup(ctx context.Context, req gen.DeleteTenantGroupRequestObject) (gen.DeleteTenantGroupResponseObject, error) {
	a, err := actorOf(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.svc.DeleteGroup(ctx, req.TenantId, req.GroupId, a, ifMatch(req.Params.IfMatch)); err != nil {
		return nil, failure(err)
	}
	return gen.DeleteTenantGroup204Response{}, nil
}

// SetTenantGroupMembers implements PUT /tenants/{tenantId}/groups/{groupId}/members: 200 with the group, or — for a
// sensitive group — 202 with the tenant-scope approval request (§7.3, §8.6), whose creation needs the caller's step-up.
func (h *Handlers) SetTenantGroupMembers(ctx context.Context, req gen.SetTenantGroupMembersRequestObject) (gen.SetTenantGroupMembersResponseObject, error) {
	a, err := actorOf(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, problem.Validation("The request body is invalid.", problem.Field("body", "required", "a JSON body is required"))
	}
	res, err := h.svc.SetGroupMembers(ctx, req.TenantId, req.GroupId, a, ifMatch(req.Params.IfMatch), req.Body.MembershipIds)
	if err != nil {
		return nil, failure(err)
	}
	if res.Approval == nil {
		return gen.SetTenantGroupMembers200JSONResponse{Body: toGroup(*res.Group),
			Headers: gen.SetTenantGroupMembers200ResponseHeaders{ETag: members.ETag(res.Group.Version)}}, nil
	}
	r, err := h.appr.Request(ctx, approvals.Actor{IdentityID: a.IdentityID, Scope: authz.ScopeTenant, AuthTime: a.AuthTime},
		approvals.NewRequest{Action: members.ApprovalAction, TenantID: req.TenantId, ResourceID: req.GroupId.String(),
			Payload: res.Approval, Reason: "PUT /groups/" + req.GroupId.String() + "/members"})
	if err != nil {
		return nil, approvalsapi.Failure(err)
	}
	return gen.SetTenantGroupMembers202JSONResponse{Body: approvalsapi.View(r),
		Headers: gen.SetTenantGroupMembers202ResponseHeaders{Location: approvals.Location(r)}}, nil
}
