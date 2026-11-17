// Package tenantsapi serves the registry read operations of api/openapi.yaml built by P2-T11 (httpapi.TenantHandlers):
// listMyTenants, getTenant, listTenantUsers, getTenantUser (tenant scope) and listPlatformTenants, getPlatformTenant,
// listPlatformInstances, getPlatformInstance (platform scope). It only translates between the generated types and
// internal/tenants / internal/platform, which run every query in the scope of the request.
//
// Layers of §8.8: authz (layer 1, internal/httpapi/authzhook) decided the route before the handler runs — membership in
// the tenant of the path (else 404), the permission, the origin; this package and the services do layer 2 (the object
// read must belong to the tenant of the path, else 404 — a membership of another tenant reads exactly like a missing
// one) and layer 3–4 (tenant-scope reads run in store.WithTenantTx of the path tenant, RLS). Platform staff get the
// registry metadata of schema Tenant/Instance only — never memberships or any other tenant-internal data (§8.4
// invariant 2), and never the reference of an instance API key.
//
// The health of an instance is derived by monitoring.HealthOf — the rule of the dashboards (P2-T13a): the verdict of
// the last recorded probe while it is younger than monitoring.DefaultStaleAfter at the database clock of the read,
// otherwise unknown with a stable reason (never_checked, instance_not_running, invalid_record, stale). The api's
// monitoring.Config.StaleAfter must stay at that default while this view uses it (P2-T16).
//
// Wiring (P2-T16, apps/internal/runner):
//
//	tenantsapi.New(tenants.New(apiStore, tenants.Options{BaseDomain: cfg.BaseDomain}), platform.New(apiStore))
//
// mounted as httpapi.Handlers{Tenants: …}, behind authzhook.Hooks (identity.Service.Middleware sets the session that
// listMyTenants reads).
package tenantsapi

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/gen"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/problem"
	"github.com/zhaduchanhzz/network-access-mesh/internal/identity"
	"github.com/zhaduchanhzz/network-access-mesh/internal/monitoring"
	"github.com/zhaduchanhzz/network-access-mesh/internal/platform"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
)

// TenantService is the part of *tenants.Service the handlers use.
type TenantService interface {
	GetTenant(ctx context.Context, tenantID uuid.UUID) (tenants.Tenant, error)
	ListMemberTenants(ctx context.Context, identityID, identityTenant uuid.UUID, p tenants.Page) (tenants.TenantPage, error)
	ListMembers(ctx context.Context, tenantID uuid.UUID, f tenants.MemberFilter) (tenants.MemberPage, error)
	GetMember(ctx context.Context, tenantID, membershipID uuid.UUID) (tenants.Member, error)
	ListRegistry(ctx context.Context, f tenants.RegistryFilter) (tenants.TenantPage, error)
	GetRegistry(ctx context.Context, tenantID uuid.UUID) (tenants.Tenant, error)
}

// InstanceService is the part of *platform.Service the handlers use.
type InstanceService interface {
	ListInstances(ctx context.Context, f platform.InstanceFilter) (platform.InstancePage, error)
	GetInstance(ctx context.Context, id uuid.UUID) (platform.Instance, error)
}

var (
	_ TenantService   = (*tenants.Service)(nil)
	_ InstanceService = (*platform.Service)(nil)
)

// Handlers implements httpapi.TenantHandlers.
type Handlers struct {
	tenants  TenantService
	platform InstanceService
}

var _ httpapi.TenantHandlers = (*Handlers)(nil)

// New returns the handler set of P2-T11.
func New(t TenantService, p InstanceService) *Handlers { return &Handlers{tenants: t, platform: p} }

// notFound is the same for every missing or foreign object (§8.4 invariant 6).
func notFound() *problem.Error {
	return problem.New(gen.ProblemCodeNotFound, "The resource does not exist.")
}

// failure maps a service error: not found ⇒ 404, invalid list parameters ⇒ 422 naming the parameter group, anything
// else ⇒ 500 (the cause goes to the internal log only).
func failure(err error) *problem.Error {
	switch {
	case errors.Is(err, tenants.ErrNotFound), errors.Is(err, platform.ErrNotFound):
		return notFound()
	case errors.Is(err, tenants.ErrInvalid), errors.Is(err, platform.ErrInvalid):
		return problem.Validation("The request parameters are invalid.",
			problem.Field("query", "invalid", "a filter, the limit or the cursor is out of range"))
	}
	return problem.Internal(err)
}

func limitOf(p *gen.Limit) int {
	if p == nil {
		return 0
	}
	if *p == 0 {
		return -1 // an explicit 0 is out of range, not "default"
	}
	return *p
}

func str(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func cursorOf(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// etag is the strong ETag of a resource version (§6.1, If-Match of later write operations).
func etag(version int64) string { return strconv.Quote(strconv.FormatInt(version, 10)) }

// ListMyTenants implements GET /tenants: the tenants where the caller is an active member. Platform staff are members
// of no tenant (their access is a Support Access Grant — P4-T13): empty list.
func (h *Handlers) ListMyTenants(ctx context.Context, req gen.ListMyTenantsRequestObject) (gen.ListMyTenantsResponseObject, error) {
	sess, ok := identity.SessionFromContext(ctx)
	if !ok || sess.IdentityID == uuid.Nil {
		return nil, problem.New(gen.ProblemCodeUnauthenticated, "The session is missing, expired or revoked.")
	}
	page := tenants.Page{Limit: limitOf(req.Params.Limit), Cursor: str(req.Params.Cursor)}
	if sess.Scope != identity.ScopeTenant || sess.TenantID == nil {
		if _, err := h.tenants.ListMemberTenants(ctx, uuid.Nil, uuid.Nil, page); err != nil { // validates the page
			return nil, failure(err)
		}
		return gen.ListMyTenants200JSONResponse{Items: []gen.Tenant{}}, nil
	}
	p, err := h.tenants.ListMemberTenants(ctx, sess.IdentityID, *sess.TenantID, page)
	if err != nil {
		return nil, failure(err)
	}
	out := gen.ListMyTenants200JSONResponse{Items: make([]gen.Tenant, 0, len(p.Items)), NextCursor: cursorOf(p.NextCursor)}
	for _, t := range p.Items {
		out.Items = append(out.Items, toTenant(t))
	}
	return out, nil
}

// GetTenant implements GET /tenants/{tenantId}: read in the tenant's own scope.
func (h *Handlers) GetTenant(ctx context.Context, req gen.GetTenantRequestObject) (gen.GetTenantResponseObject, error) {
	t, err := h.tenants.GetTenant(ctx, req.TenantId)
	if err != nil {
		return nil, failure(err)
	}
	if t.ID != req.TenantId {
		return nil, notFound()
	}
	return gen.GetTenant200JSONResponse{Body: toTenant(t), Headers: gen.GetTenant200ResponseHeaders{ETag: etag(t.Version)}}, nil
}

// ListTenantUsers implements GET /tenants/{tenantId}/users.
func (h *Handlers) ListTenantUsers(ctx context.Context, req gen.ListTenantUsersRequestObject) (gen.ListTenantUsersResponseObject, error) {
	f := tenants.MemberFilter{Page: tenants.Page{Limit: limitOf(req.Params.Limit), Cursor: str(req.Params.Cursor)},
		Role: str(req.Params.Role), Status: str(req.Params.Status), Query: str(req.Params.Q)}
	p, err := h.tenants.ListMembers(ctx, req.TenantId, f)
	if err != nil {
		return nil, failure(err)
	}
	out := gen.ListTenantUsers200JSONResponse{Items: make([]gen.Membership, 0, len(p.Items)), NextCursor: cursorOf(p.NextCursor)}
	for _, m := range p.Items {
		if m.TenantID != req.TenantId {
			return nil, problem.Internal(errors.New("tenantsapi: membership of another tenant in the list"))
		}
		out.Items = append(out.Items, toMembership(m))
	}
	return out, nil
}

// GetTenantUser implements GET /tenants/{tenantId}/users/{membershipId}.
func (h *Handlers) GetTenantUser(ctx context.Context, req gen.GetTenantUserRequestObject) (gen.GetTenantUserResponseObject, error) {
	m, err := h.tenants.GetMember(ctx, req.TenantId, req.MembershipId)
	if err != nil {
		return nil, failure(err)
	}
	if m.TenantID != req.TenantId || m.ID != req.MembershipId {
		return nil, notFound()
	}
	return gen.GetTenantUser200JSONResponse{Body: toMembership(m),
		Headers: gen.GetTenantUser200ResponseHeaders{ETag: etag(m.Version)}}, nil
}

// ListPlatformTenants implements GET /platform/tenants: registry metadata only.
func (h *Handlers) ListPlatformTenants(ctx context.Context, req gen.ListPlatformTenantsRequestObject) (gen.ListPlatformTenantsResponseObject, error) {
	f := tenants.RegistryFilter{Page: tenants.Page{Limit: limitOf(req.Params.Limit), Cursor: str(req.Params.Cursor)},
		Query: str(req.Params.Q)}
	if req.Params.Status != nil {
		f.Status = string(*req.Params.Status)
	}
	p, err := h.tenants.ListRegistry(ctx, f)
	if err != nil {
		return nil, failure(err)
	}
	out := gen.ListPlatformTenants200JSONResponse{Items: make([]gen.Tenant, 0, len(p.Items)), NextCursor: cursorOf(p.NextCursor)}
	for _, t := range p.Items {
		out.Items = append(out.Items, toTenant(t))
	}
	return out, nil
}

// GetPlatformTenant implements GET /platform/tenants/{tenantId}: registry metadata of one tenant.
func (h *Handlers) GetPlatformTenant(ctx context.Context, req gen.GetPlatformTenantRequestObject) (gen.GetPlatformTenantResponseObject, error) {
	t, err := h.tenants.GetRegistry(ctx, req.TenantId)
	if err != nil {
		return nil, failure(err)
	}
	if t.ID != req.TenantId {
		return nil, notFound()
	}
	return gen.GetPlatformTenant200JSONResponse{Body: toTenant(t),
		Headers: gen.GetPlatformTenant200ResponseHeaders{ETag: etag(t.Version)}}, nil
}

// ListPlatformInstances implements GET /platform/instances.
func (h *Handlers) ListPlatformInstances(ctx context.Context, req gen.ListPlatformInstancesRequestObject) (gen.ListPlatformInstancesResponseObject, error) {
	f := platform.InstanceFilter{Limit: limitOf(req.Params.Limit), Cursor: str(req.Params.Cursor)}
	if req.Params.Status != nil {
		f.Status = string(*req.Params.Status)
	}
	if req.Params.Host != nil {
		f.HostID = *req.Params.Host
		if f.HostID == uuid.Nil {
			return nil, failure(platform.ErrInvalid)
		}
	}
	p, err := h.platform.ListInstances(ctx, f)
	if err != nil {
		return nil, failure(err)
	}
	out := gen.ListPlatformInstances200JSONResponse{Items: make([]gen.Instance, 0, len(p.Items)), NextCursor: cursorOf(p.NextCursor)}
	for _, i := range p.Items {
		out.Items = append(out.Items, toInstance(i))
	}
	return out, nil
}

// GetPlatformInstance implements GET /platform/instances/{instanceId}.
func (h *Handlers) GetPlatformInstance(ctx context.Context, req gen.GetPlatformInstanceRequestObject) (gen.GetPlatformInstanceResponseObject, error) {
	i, err := h.platform.GetInstance(ctx, req.InstanceId)
	if err != nil {
		return nil, failure(err)
	}
	if i.ID != req.InstanceId {
		return nil, notFound()
	}
	return gen.GetPlatformInstance200JSONResponse(toInstance(i)), nil
}

// toTenant maps the registry view to schema Tenant. Plans and subscriptions arrive with migration 0010 (P3-T06): until
// then a tenant has no plan key ("") and no limit (an empty PlanLimits — "a missing key means the plan sets no such
// limit", §13.3).
func toTenant(t tenants.Tenant) gen.Tenant {
	return gen.Tenant{
		Id: t.ID, Slug: t.Slug, Name: t.Name, Status: gen.TenantStatus(t.Status), DeploymentRegion: t.DeploymentRegion,
		Plan: "", Limits: gen.PlanLimits{}, ControlUrl: t.ControlURL, CreatedAt: t.CreatedAt.UTC(),
		UpdatedAt: t.UpdatedAt.UTC(), Version: t.Version,
	}
}

func toMembership(m tenants.Member) gen.Membership {
	out := gen.Membership{Id: m.ID, IdentityId: m.IdentityID, DisplayName: m.DisplayName, Role: m.Role,
		Status: m.Status, HeadscaleUsername: m.HeadscaleUsername, Version: m.Version}
	if m.Email != "" {
		e := m.Email
		out.Email = &e
	}
	return out
}

func toInstance(i platform.Instance) gen.Instance {
	out := gen.Instance{
		Id: i.ID, TenantId: i.TenantID, HostId: i.HostID, Status: gen.InstanceStatus(i.Status),
		HeadscaleVersion: i.HeadscaleVersion, ImageDigest: i.ImageDigest, ControlHostname: i.ControlHostname,
		ServerUrl: i.ServerURL, RunUid: int(i.RunUID), NetCidr: i.NetCIDR.String(), Health: instanceHealth(i),
		Version: i.Version, ApiKeyExpiresAt: utcPtr(i.APIKeyExpiresAt), NoiseKeyFingerprint: i.NoiseKeyFingerprint,
	}
	if i.DerpRegionID != nil {
		v := int(*i.DerpRegionID)
		out.DerpRegionId = &v
	}
	return out
}

// instanceHealth applies the health rule of the dashboards (monitoring.HealthOf) to the recorded probe of i.
func instanceHealth(i platform.Instance) gen.InstanceHealth {
	h := monitoring.HealthOf(i.Status, i.LastHealth, i.HealthCheckedAt, i.ReadAt, monitoring.DefaultStaleAfter)
	out := gen.InstanceHealth{Status: gen.HealthStatus(h.Status), CheckedAt: utcPtr(h.CheckedAt)}
	if h.Reason != "" {
		r := h.Reason
		out.Reason = &r
	}
	return out
}

func utcPtr(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	u := t.UTC()
	return &u
}
