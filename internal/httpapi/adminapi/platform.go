package adminapi

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/zhaduchanhzz/network-access-mesh/internal/authz"
	"github.com/zhaduchanhzz/network-access-mesh/internal/authz/approvals"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/approvalsapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/gen"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/problem"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/tenantsapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/platform"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
)

func limitOf(p *gen.Limit) int {
	if p == nil {
		return 0
	}
	if *p == 0 {
		return -1 // an explicit 0 is out of range, not "the default"
	}
	return *p
}

func strOf(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func nextCursor(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func toPlatformUser(u platform.PlatformUser) gen.PlatformUser {
	out := gen.PlatformUser{Id: u.ID, IdentityId: u.IdentityID, Subject: u.Subject, DisplayName: u.DisplayName,
		Role: gen.PlatformRole(u.Role), Status: gen.PlatformUserStatus(u.Status), LastLoginAt: u.LastLoginAt,
		CreatedAt: u.CreatedAt, UpdatedAt: u.UpdatedAt, Version: u.Version, Etag: u.ETag}
	if u.Email != "" {
		out.Email = ptr(u.Email)
	}
	if u.IdentityStatus != "" {
		out.IdentityStatus = ptr(u.IdentityStatus)
	}
	return out
}

// ListPlatformUsers implements GET /platform/users.
func (h *Handlers) ListPlatformUsers(ctx context.Context, req gen.ListPlatformUsersRequestObject) (gen.ListPlatformUsersResponseObject, error) {
	f := platform.UserFilter{Limit: limitOf(req.Params.Limit), Cursor: strOf(req.Params.Cursor)}
	if req.Params.Status != nil {
		f.Status = string(*req.Params.Status)
	}
	if req.Params.Role != nil {
		f.Role = string(*req.Params.Role)
	}
	p, err := h.platform.ListUsers(ctx, f)
	if err != nil {
		return nil, failure(err)
	}
	out := gen.ListPlatformUsers200JSONResponse{Items: make([]gen.PlatformUser, 0, len(p.Items)), NextCursor: nextCursor(p.NextCursor)}
	for _, u := range p.Items {
		out.Items = append(out.Items, toPlatformUser(u))
	}
	return out, nil
}

// GetPlatformUser implements GET /platform/users/{platformUserId}.
func (h *Handlers) GetPlatformUser(ctx context.Context, req gen.GetPlatformUserRequestObject) (gen.GetPlatformUserResponseObject, error) {
	u, err := h.platform.GetUser(ctx, req.PlatformUserId)
	if err != nil {
		return nil, failure(err)
	}
	return gen.GetPlatformUser200JSONResponse{Body: toPlatformUser(u), Headers: gen.GetPlatformUser200ResponseHeaders{ETag: u.ETag}}, nil
}

// CreatePlatformUser implements POST /platform/users (Idempotency-Key over method, path and body).
func (h *Handlers) CreatePlatformUser(ctx context.Context, req gen.CreatePlatformUserRequestObject) (gen.CreatePlatformUserResponseObject, error) {
	a, _, err := platformActor(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, problem.Validation("The request body is invalid.", problem.Field("body", "required", "a JSON body is required"))
	}
	raw, err := json.Marshal(req.Body)
	if err != nil {
		return nil, problem.Internal(err)
	}
	u, err := h.platform.CreateUser(ctx, a, platform.UserCreate{Subject: req.Body.Subject, Role: string(req.Body.Role),
		DisplayName: strOf(req.Body.DisplayName)}, &platform.Idempotency{IdentityID: a.IdentityID,
		Key: req.Params.IdempotencyKey, Hash: jobs.RequestHash("POST", "/platform/users", raw)})
	if err != nil {
		return nil, failure(err)
	}
	return gen.CreatePlatformUser201JSONResponse{Body: toPlatformUser(u), Headers: gen.CreatePlatformUser201ResponseHeaders{ETag: u.ETag}}, nil
}

// UpdatePlatformUser implements PATCH /platform/users/{platformUserId}.
func (h *Handlers) UpdatePlatformUser(ctx context.Context, req gen.UpdatePlatformUserRequestObject) (gen.UpdatePlatformUserResponseObject, error) {
	a, _, err := platformActor(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, problem.Validation("The request body is invalid.", problem.Field("body", "required", "a JSON body is required"))
	}
	var p platform.UserPatch
	if req.Body.Role != nil {
		p.Role = ptr(string(*req.Body.Role))
	}
	if req.Body.Status != nil {
		p.Status = ptr(string(*req.Body.Status))
	}
	u, err := h.platform.UpdateUser(ctx, a, req.PlatformUserId, p, ifMatchOf(req.Params.IfMatch))
	if err != nil {
		return nil, failure(err)
	}
	return gen.UpdatePlatformUser200JSONResponse{Body: toPlatformUser(u), Headers: gen.UpdatePlatformUser200ResponseHeaders{ETag: u.ETag}}, nil
}

// DeletePlatformUser implements DELETE /platform/users/{platformUserId} (status disabled, sessions revoked).
func (h *Handlers) DeletePlatformUser(ctx context.Context, req gen.DeletePlatformUserRequestObject) (gen.DeletePlatformUserResponseObject, error) {
	a, _, err := platformActor(ctx)
	if err != nil {
		return nil, err
	}
	u, err := h.platform.DisableUser(ctx, a, req.PlatformUserId, ifMatchOf(req.Params.IfMatch))
	if err != nil {
		return nil, failure(err)
	}
	return gen.DeletePlatformUser200JSONResponse{Body: toPlatformUser(u), Headers: gen.DeletePlatformUser200ResponseHeaders{ETag: u.ETag}}, nil
}

// SetPlatformUserSuperAdminRole implements PUT /platform/users/{platformUserId}/super-admin-role: always a 2P request.
func (h *Handlers) SetPlatformUserSuperAdminRole(ctx context.Context, req gen.SetPlatformUserSuperAdminRoleRequestObject) (gen.SetPlatformUserSuperAdminRoleResponseObject, error) {
	_, s, err := platformActor(ctx)
	if err != nil {
		return nil, err
	}
	if _, d, _ := session(ctx); !d.NeedsApproval() { // x-dual-control: never run directly (§8.5)
		return nil, problem.Internal(errors.New("adminapi: the decision does not require a second approver"))
	}
	if req.Body == nil {
		return nil, problem.Validation("The request body is invalid.", problem.Field("body", "required", "a JSON body is required"))
	}
	roleAfter := ""
	if req.Body.RoleAfter != nil {
		roleAfter = string(*req.Body.RoleAfter)
	}
	payload, err := h.platform.SuperAdminRequest(ctx, req.PlatformUserId, req.Body.SuperAdmin, roleAfter)
	if err != nil {
		return nil, failure(err)
	}
	r, err := h.appr.Request(ctx, approvals.Actor{IdentityID: s.IdentityID, Scope: authz.ScopePlatform, AuthTime: s.AuthTime},
		approvals.NewRequest{Action: platform.SuperAdminAction, ResourceID: req.PlatformUserId.String(), Payload: payload,
			Reason: req.Body.Reason})
	if err != nil {
		return nil, approvalsapi.Failure(err)
	}
	return gen.SetPlatformUserSuperAdminRole202JSONResponse{Body: approvalsapi.View(r),
		Headers: gen.SetPlatformUserSuperAdminRole202ResponseHeaders{Location: approvals.Location(r)}}, nil
}

func toSetting(s platform.Setting) gen.SystemSetting {
	out := gen.SystemSetting{Key: s.Key, Value: json.RawMessage(`null`), Writable: s.Writable, Description: s.Description,
		Version: s.Version, UpdatedAt: s.UpdatedAt, UpdatedBy: s.UpdatedBy, Etag: s.ETag}
	if len(s.Value) > 0 {
		out.Value = json.RawMessage(s.Value)
	}
	if len(s.Default) > 0 {
		d := json.RawMessage(s.Default)
		out.Default = &d
	}
	return out
}

// ListPlatformSettings implements GET /platform/settings.
func (h *Handlers) ListPlatformSettings(ctx context.Context, _ gen.ListPlatformSettingsRequestObject) (gen.ListPlatformSettingsResponseObject, error) {
	l, err := h.platform.ListSettings(ctx)
	if err != nil {
		return nil, failure(err)
	}
	out := gen.ListPlatformSettings200JSONResponse{Items: make([]gen.SystemSetting, 0, len(l))}
	for _, s := range l {
		out.Items = append(out.Items, toSetting(s))
	}
	return out, nil
}

// GetPlatformSetting implements GET /platform/settings/{settingKey}.
func (h *Handlers) GetPlatformSetting(ctx context.Context, req gen.GetPlatformSettingRequestObject) (gen.GetPlatformSettingResponseObject, error) {
	s, err := h.platform.GetSetting(ctx, req.SettingKey)
	if err != nil {
		return nil, failure(err)
	}
	return gen.GetPlatformSetting200JSONResponse{Body: toSetting(s), Headers: gen.GetPlatformSetting200ResponseHeaders{ETag: s.ETag}}, nil
}

// PutPlatformSetting implements PUT /platform/settings/{settingKey}.
func (h *Handlers) PutPlatformSetting(ctx context.Context, req gen.PutPlatformSettingRequestObject) (gen.PutPlatformSettingResponseObject, error) {
	a, _, err := platformActor(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil || len(req.Body.Value) == 0 {
		return nil, problem.Validation("The request body is invalid.", problem.Field("value", "required", "a value is required"))
	}
	s, err := h.platform.PutSetting(ctx, a, req.SettingKey, req.Body.Value, ifMatchOf(req.Params.IfMatch))
	if err != nil {
		return nil, failure(err)
	}
	return gen.PutPlatformSetting200JSONResponse{Body: toSetting(s), Headers: gen.PutPlatformSetting200ResponseHeaders{ETag: s.ETag}}, nil
}

// ToIdentityProvider is schema IdentityProvider (shared with the tenant operation).
func ToIdentityProvider(c tenants.IdPConfig) gen.IdentityProvider {
	mapping := c.ClaimMapping
	if mapping == nil {
		mapping = map[string]string{}
	}
	return gen.IdentityProvider{Id: c.ID, Scope: gen.IdentityProviderScope(c.Scope), TenantId: c.TenantID, Issuer: c.Issuer,
		ClientId: c.ClientID, Driver: gen.IdentityProviderDriver(c.Driver), Status: gen.IdentityProviderStatus(c.Status),
		RequiredClaims: rawOrEmpty(c.RequiredClaims), RequireEmailVerified: c.RequireEmailVerified,
		AllowedEmailDomains: c.AllowedEmailDomains, ClaimMapping: mapping, ClientSecretSet: c.ClientSecretSet,
		CreatedAt: c.CreatedAt, UpdatedAt: c.UpdatedAt, Version: c.Version, Etag: c.ETag}
}

// ListPlatformIdentityProviders implements GET /platform/identity-providers.
func (h *Handlers) ListPlatformIdentityProviders(ctx context.Context, req gen.ListPlatformIdentityProvidersRequestObject) (gen.ListPlatformIdentityProvidersResponseObject, error) {
	f := platform.IdPFilter{Limit: limitOf(req.Params.Limit), Cursor: strOf(req.Params.Cursor)}
	if req.Params.Scope != nil {
		f.Scope = string(*req.Params.Scope)
	}
	p, err := h.platform.ListIdPs(ctx, f)
	if err != nil {
		return nil, failure(err)
	}
	out := gen.ListPlatformIdentityProviders200JSONResponse{Items: make([]gen.IdentityProvider, 0, len(p.Items)),
		NextCursor: nextCursor(p.NextCursor)}
	for _, c := range p.Items {
		out.Items = append(out.Items, ToIdentityProvider(c))
	}
	return out, nil
}

// GetPlatformIdentityProvider implements GET /platform/identity-providers/{idpId}.
func (h *Handlers) GetPlatformIdentityProvider(ctx context.Context, req gen.GetPlatformIdentityProviderRequestObject) (gen.GetPlatformIdentityProviderResponseObject, error) {
	c, err := h.platform.GetIdP(ctx, req.IdpId)
	if err != nil {
		return nil, failure(err)
	}
	return gen.GetPlatformIdentityProvider200JSONResponse{Body: ToIdentityProvider(c),
		Headers: gen.GetPlatformIdentityProvider200ResponseHeaders{ETag: c.ETag}}, nil
}

// immutableFields refuses issuer / client_id / driver in a change body (§8.2 (1): 422, nothing written).
func immutableFields(issuer, clientID, driver any) error {
	for name, v := range map[string]any{"issuer": issuer, "client_id": clientID, "driver": driver} {
		if v != nil {
			return problem.Validation("issuer, client_id and driver are immutable — changing the identity provider is a migration.",
				problem.Field(name, platform.ReasonImmutable, "is immutable"))
		}
	}
	return nil
}

func idpChange(rc *json.RawMessage, domains *[]string, mapping *map[string]string) tenants.IdPChange {
	c := tenants.IdPChange{AllowedEmailDomains: domains, ClaimMapping: mapping}
	if rc != nil {
		c.RequiredClaims = *rc
	}
	return c
}

// UpdatePlatformIdentityProvider implements PATCH /platform/identity-providers/{idpId}: a platform row changes now
// (200); a tenant row becomes a 2P request (202), recorded in the tenant's audit and notified to its Owners.
func (h *Handlers) UpdatePlatformIdentityProvider(ctx context.Context, req gen.UpdatePlatformIdentityProviderRequestObject) (gen.UpdatePlatformIdentityProviderResponseObject, error) {
	a, s, err := platformActor(ctx)
	if err != nil {
		return nil, err
	}
	b := req.Body
	if b == nil {
		return nil, problem.Validation("The request body is invalid.", problem.Field("body", "required", "a JSON body is required"))
	}
	if err := immutableFields(b.Issuer, b.ClientId, b.Driver); err != nil {
		return nil, err
	}
	res, err := h.platform.UpdateIdP(ctx, a, req.IdpId, idpChange(b.RequiredClaims, b.AllowedEmailDomains, b.ClaimMapping),
		ifMatchOf(req.Params.IfMatch))
	if err != nil {
		return nil, failure(err)
	}
	if res.Approval == nil {
		return gen.UpdatePlatformIdentityProvider200JSONResponse{Body: ToIdentityProvider(res.View),
			Headers: gen.UpdatePlatformIdentityProvider200ResponseHeaders{ETag: res.View.ETag}}, nil
	}
	r, err := h.appr.Request(ctx, approvals.Actor{IdentityID: s.IdentityID, Scope: authz.ScopePlatform, AuthTime: s.AuthTime},
		approvals.NewRequest{Action: tenants.PlatformIdPChangeApprovalAction, ResourceID: req.IdpId.String(),
			Payload: res.Approval, Reason: "PATCH /platform/identity-providers/" + req.IdpId.String()})
	if err != nil {
		return nil, approvalsapi.Failure(err)
	}
	// §8.2: the request is visible to the tenant (its audit) and notified to its Owners — not in effect yet
	if err := h.tenants.RecordPlatformIdPChangeRequested(ctx, *res.Approval, r.ID, s.IdentityID, displayOf(s), r.ExpiresAt); err != nil {
		return nil, problem.Internal(err)
	}
	return gen.UpdatePlatformIdentityProvider202JSONResponse{Body: approvalsapi.View(r),
		Headers: gen.UpdatePlatformIdentityProvider202ResponseHeaders{Location: approvals.Location(r)}}, nil
}

func toPlan(p platform.Plan) gen.Plan {
	n := int(p.TenantCount)
	return gen.Plan{Id: p.ID, Key: p.Key, Name: p.Name, Limits: rawOrEmpty(p.Limits), IsActive: p.IsActive, TenantCount: &n,
		CreatedAt: p.CreatedAt, UpdatedAt: p.UpdatedAt, Version: p.Version, Etag: p.ETag}
}

// ListPlatformPlans implements GET /platform/plans.
func (h *Handlers) ListPlatformPlans(ctx context.Context, _ gen.ListPlatformPlansRequestObject) (gen.ListPlatformPlansResponseObject, error) {
	l, err := h.platform.ListPlans(ctx)
	if err != nil {
		return nil, failure(err)
	}
	out := gen.ListPlatformPlans200JSONResponse{Items: make([]gen.Plan, 0, len(l))}
	for _, p := range l {
		out.Items = append(out.Items, toPlan(p))
	}
	return out, nil
}

// GetPlatformPlan implements GET /platform/plans/{planId}.
func (h *Handlers) GetPlatformPlan(ctx context.Context, req gen.GetPlatformPlanRequestObject) (gen.GetPlatformPlanResponseObject, error) {
	p, err := h.platform.GetPlan(ctx, req.PlanId)
	if err != nil {
		return nil, failure(err)
	}
	return gen.GetPlatformPlan200JSONResponse{Body: toPlan(p), Headers: gen.GetPlatformPlan200ResponseHeaders{ETag: p.ETag}}, nil
}

// CreatePlatformPlan implements POST /platform/plans.
func (h *Handlers) CreatePlatformPlan(ctx context.Context, req gen.CreatePlatformPlanRequestObject) (gen.CreatePlatformPlanResponseObject, error) {
	a, _, err := platformActor(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, problem.Validation("The request body is invalid.", problem.Field("body", "required", "a JSON body is required"))
	}
	raw, err := json.Marshal(req.Body)
	if err != nil {
		return nil, problem.Internal(err)
	}
	active := true
	if req.Body.IsActive != nil {
		active = *req.Body.IsActive
	}
	p, err := h.platform.CreatePlan(ctx, a, platform.PlanCreate{Key: req.Body.Key, Name: req.Body.Name,
		Limits: req.Body.Limits, IsActive: active}, &platform.Idempotency{IdentityID: a.IdentityID,
		Key: req.Params.IdempotencyKey, Hash: jobs.RequestHash("POST", "/platform/plans", raw)})
	if err != nil {
		return nil, failure(err)
	}
	return gen.CreatePlatformPlan201JSONResponse{Body: toPlan(p), Headers: gen.CreatePlatformPlan201ResponseHeaders{ETag: p.ETag}}, nil
}

// UpdatePlatformPlan implements PATCH /platform/plans/{planId}.
func (h *Handlers) UpdatePlatformPlan(ctx context.Context, req gen.UpdatePlatformPlanRequestObject) (gen.UpdatePlatformPlanResponseObject, error) {
	if _, _, err := platformActor(ctx); err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, problem.Validation("The request body is invalid.", problem.Field("body", "required", "a JSON body is required"))
	}
	pp := platform.PlanPatch{Name: req.Body.Name, IsActive: req.Body.IsActive}
	if req.Body.Limits != nil {
		pp.Limits = *req.Body.Limits
	}
	p, err := h.platform.UpdatePlan(ctx, req.PlanId, pp, ifMatchOf(req.Params.IfMatch))
	if err != nil {
		return nil, failure(err)
	}
	return gen.UpdatePlatformPlan200JSONResponse{Body: toPlan(p), Headers: gen.UpdatePlatformPlan200ResponseHeaders{ETag: p.ETag}}, nil
}

// UpdatePlatformTenant implements PATCH /platform/tenants/{tenantId}: the registry view is read back after the write.
func (h *Handlers) UpdatePlatformTenant(ctx context.Context, req gen.UpdatePlatformTenantRequestObject) (gen.UpdatePlatformTenantResponseObject, error) {
	if _, _, err := platformActor(ctx); err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, problem.Validation("The request body is invalid.", problem.Field("body", "required", "a JSON body is required"))
	}
	p := platform.TenantPatch{Name: req.Body.Name, PlanKey: req.Body.PlanKey}
	if req.Body.LimitsOverride != nil {
		p.LimitsOverride = *req.Body.LimitsOverride
	}
	if err := h.platform.UpdateTenant(ctx, req.TenantId, p, ifMatchOf(req.Params.IfMatch)); err != nil {
		return nil, failure(err)
	}
	t, err := h.tenants.GetRegistry(ctx, req.TenantId)
	if err != nil {
		return nil, failure(err)
	}
	return gen.UpdatePlatformTenant200JSONResponse{Body: tenantsapi.ToTenant(t),
		Headers: gen.UpdatePlatformTenant200ResponseHeaders{ETag: tenantsapi.ETag(t.Version)}}, nil
}
