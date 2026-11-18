package adminapi

import (
	"context"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/authz"
	"github.com/zhaduchanhzz/network-access-mesh/internal/authz/approvals"
	"github.com/zhaduchanhzz/network-access-mesh/internal/config"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/approvalsapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/gen"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/problem"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
)

func toSettingsView(v tenants.SettingsView) gen.TenantSettingsView {
	s := v.Settings
	out := gen.TenantSettingsView{Etag: v.ETag}
	g := &out.Settings
	g.Enrollment = gen.TenantEnrollmentSettings{IdentityMode: gen.TenantIdentityMode(s.Enrollment.IdentityMode),
		WebAuthEnabled: s.Enrollment.WebAuthEnabled, SelfEnroll: s.Enrollment.SelfEnroll,
		RequiresApproval: s.Enrollment.RequiresApproval}
	if s.Enrollment.PreauthKeyTTLMax != "" {
		g.Enrollment.PreauthKeyTtlMax = ptr(s.Enrollment.PreauthKeyTTLMax)
	}
	if s.NodeExpiry != "" {
		g.NodeExpiry = ptr(s.NodeExpiry)
	}
	g.Policy.FourEyes = s.Policy.FourEyes
	g.Policy.SensitiveGroups = s.Policy.SensitiveGroups
	if g.Policy.SensitiveGroups == nil {
		g.Policy.SensitiveGroups = []uuid.UUID{}
	}
	g.Routes.FourEyes = s.Routes.FourEyes
	g.Dns = rawOrEmpty(s.DNS)
	g.Notifications.NewDevice = s.Notifications.NewDevice
	g.Notifications.PolicyApplied = s.Notifications.PolicyApplied
	return out
}

// GetTenantSettings implements GET /tenants/{tenantId}/settings.
func (h *Handlers) GetTenantSettings(ctx context.Context, req gen.GetTenantSettingsRequestObject) (gen.GetTenantSettingsResponseObject, error) {
	v, err := h.tenants.GetSettings(ctx, req.TenantId)
	if err != nil {
		return nil, failure(err)
	}
	return gen.GetTenantSettings200JSONResponse{Body: toSettingsView(v), Headers: gen.GetTenantSettings200ResponseHeaders{ETag: v.ETag}}, nil
}

func securityKey(name string) error {
	return problem.Validation("Security settings change only through PUT /settings/security.",
		problem.Field(name, "security_setting", "is a security setting"))
}

// UpdateTenantSettings implements PATCH /tenants/{tenantId}/settings: regular keys only.
func (h *Handlers) UpdateTenantSettings(ctx context.Context, req gen.UpdateTenantSettingsRequestObject) (gen.UpdateTenantSettingsResponseObject, error) {
	if _, _, err := tenantActor(ctx, req.TenantId); err != nil {
		return nil, err
	}
	b := req.Body
	if b == nil {
		return nil, problem.Validation("The request body is invalid.", problem.Field("body", "required", "a JSON body is required"))
	}
	switch {
	case b.NodeExpiry != nil:
		return nil, securityKey("node_expiry")
	case b.Policy != nil:
		return nil, securityKey("policy")
	case b.Routes != nil:
		return nil, securityKey("routes")
	case b.Dns != nil:
		return nil, problem.Validation("DNS settings change through PUT /dns/settings.",
			problem.Field("dns", "dns_setting", "changes through PUT /dns/settings"))
	}
	var p config.SettingsPatch
	if e := b.Enrollment; e != nil {
		switch {
		case e.IdentityMode != nil:
			return nil, securityKey("enrollment.identity_mode")
		case e.WebAuthEnabled != nil:
			return nil, securityKey("enrollment.web_auth_enabled")
		case e.SelfEnroll != nil:
			return nil, securityKey("enrollment.self_enroll")
		case e.RequiresApproval != nil:
			return nil, securityKey("enrollment.requires_approval")
		}
		p.PreauthKeyTTLMax = e.PreauthKeyTtlMax
	}
	if n := b.Notifications; n != nil {
		p.NewDevice, p.PolicyApplied = n.NewDevice, n.PolicyApplied
	}
	v, err := h.tenants.PatchSettings(ctx, req.TenantId, p, ifMatchOf(req.Params.IfMatch))
	if err != nil {
		return nil, failure(err)
	}
	return gen.UpdateTenantSettings200JSONResponse{Body: toSettingsView(v), Headers: gen.UpdateTenantSettings200ResponseHeaders{ETag: v.ETag}}, nil
}

// PutTenantSecuritySettings implements PUT /tenants/{tenantId}/settings/security: written now (200), or — lifting a
// second-person control — a tenant approval request (202).
func (h *Handlers) PutTenantSecuritySettings(ctx context.Context, req gen.PutTenantSecuritySettingsRequestObject) (gen.PutTenantSecuritySettingsResponseObject, error) {
	a, s, err := tenantActor(ctx, req.TenantId)
	if err != nil {
		return nil, err
	}
	b := req.Body
	if b == nil {
		return nil, problem.Validation("The request body is invalid.", problem.Field("body", "required", "a JSON body is required"))
	}
	want := config.SecuritySettings{IdentityMode: string(b.Enrollment.IdentityMode), WebAuthEnabled: b.Enrollment.WebAuthEnabled,
		SelfEnroll: b.Enrollment.SelfEnroll, RequiresApproval: b.Enrollment.RequiresApproval, NodeExpiry: strOf(b.NodeExpiry),
		PolicyFourEyes: b.Policy.FourEyes, SensitiveGroups: b.Policy.SensitiveGroups, RoutesFourEyes: b.Routes.FourEyes}
	res, err := h.tenants.PutSecuritySettings(ctx, a, req.TenantId, want, ifMatchOf(req.Params.IfMatch))
	if err != nil {
		return nil, failure(err)
	}
	if res.Approval == nil {
		return gen.PutTenantSecuritySettings200JSONResponse{Body: toSettingsView(res.View),
			Headers: gen.PutTenantSecuritySettings200ResponseHeaders{ETag: res.View.ETag}}, nil
	}
	r, err := h.appr.Request(ctx, approvals.Actor{IdentityID: s.IdentityID, Scope: authz.ScopeTenant, AuthTime: s.AuthTime},
		approvals.NewRequest{Action: tenants.SecuritySettingsApprovalAction, TenantID: req.TenantId,
			ResourceID: req.TenantId.String(), Payload: res.Approval, Reason: "PUT /settings/security"})
	if err != nil {
		return nil, approvalsapi.Failure(err)
	}
	return gen.PutTenantSecuritySettings202JSONResponse{Body: approvalsapi.View(r),
		Headers: gen.PutTenantSecuritySettings202ResponseHeaders{Location: approvals.Location(r)}}, nil
}

// GetTenantIdentityProvider implements GET /tenants/{tenantId}/identity-provider.
func (h *Handlers) GetTenantIdentityProvider(ctx context.Context, req gen.GetTenantIdentityProviderRequestObject) (gen.GetTenantIdentityProviderResponseObject, error) {
	c, err := h.tenants.GetActiveIdP(ctx, req.TenantId)
	if err != nil {
		return nil, failure(err)
	}
	return gen.GetTenantIdentityProvider200JSONResponse{Body: ToIdentityProvider(c),
		Headers: gen.GetTenantIdentityProvider200ResponseHeaders{ETag: c.ETag}}, nil
}

// UpdateTenantIdentityProvider implements PATCH /tenants/{tenantId}/identity-provider.
func (h *Handlers) UpdateTenantIdentityProvider(ctx context.Context, req gen.UpdateTenantIdentityProviderRequestObject) (gen.UpdateTenantIdentityProviderResponseObject, error) {
	a, _, err := tenantActor(ctx, req.TenantId)
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
	var secret []byte
	if b.ClientSecret != nil {
		secret = []byte(*b.ClientSecret)
		defer clear(secret)
	}
	c, err := h.tenants.UpdateIdP(ctx, a, req.TenantId, idpChange(b.RequiredClaims, b.AllowedEmailDomains, b.ClaimMapping),
		secret, ifMatchOf(req.Params.IfMatch))
	if err != nil {
		return nil, failure(err)
	}
	return gen.UpdateTenantIdentityProvider200JSONResponse{Body: ToIdentityProvider(c),
		Headers: gen.UpdateTenantIdentityProvider200ResponseHeaders{ETag: c.ETag}}, nil
}

// RequestTenantDeletion implements POST /tenants/{tenantId}/request-deletion.
func (h *Handlers) RequestTenantDeletion(ctx context.Context, req gen.RequestTenantDeletionRequestObject) (gen.RequestTenantDeletionResponseObject, error) {
	a, _, err := tenantActor(ctx, req.TenantId)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, problem.Validation("The request body is invalid.", problem.Field("body", "required", "a JSON body is required"))
	}
	d, err := h.tenants.RequestDeletion(ctx, a, req.TenantId, req.Body.ConfirmSlug, req.Body.Reason)
	if err != nil {
		return nil, failure(err)
	}
	return gen.RequestTenantDeletion200JSONResponse{TenantId: d.TenantID, RequestedAt: d.RequestedAt,
		RequestedBy:      gen.IdentityRef{IdentityId: d.RequestedBy, DisplayName: d.RequestedByName},
		PlatformNotified: d.PlatformNotified}, nil
}
