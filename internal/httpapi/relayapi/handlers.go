// Package relayapi serves the relay operations of api/openapi.yaml built by P3-T05c (httpapi.RelayHandlers):
// getTenantRelay — GET /tenants/{tenantId}/relay (tenant.relay:read: TO TA TP TV, staff with a Support Access Grant) —
// and listPlatformRelayRegions — GET /platform/relay-regions (platform.relay:read: SA PO PS PV), both read-only. It only
// translates between the generated types and internal/relay, which builds both read models; it never imports
// internal/store nor apps/probe (§13.6, internal/archtest).
//
// Defence in depth for IT-12b (relay part) on top of the authorization hook and RLS: the handlers refuse to answer
// without a decision (500, never data); the tenant relay only for a decision about the tenant of the path — the tenant
// is the {tenantId} of the path and nothing else (the operation takes no query parameter) — and never for an own-only
// grant (the relay is the tenant's, not a member's: §8.6 has no ○ cell for it, a future one must not widen it); the
// platform list only for a decision of a platform route.
//
// Every health carries checked_at (the start of the last recorded probe, null when never probed); the figures the
// platform does not measure (§10.6) are listed in `unavailable` with their reason — no number is made up.
//
// Wiring (apps/internal/runner — api process, reads only; the worker probes):
//
//	relaySvc, _ := relay.New(apiStore, relay.Config{Logger: log, Registerer: promReg})
//	api, _ := httpapi.New(httpapi.Options{…, Handlers: httpapi.Handlers{…, Relay: relayapi.New(relaySvc)}})
package relayapi

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/authz"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/authzhook"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/gen"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/problem"
	"github.com/zhaduchanhzz/network-access-mesh/internal/platform"
	"github.com/zhaduchanhzz/network-access-mesh/internal/relay"
)

// Service is the part of *relay.Service the handlers need.
type Service interface {
	TenantRelay(ctx context.Context, tenantID uuid.UUID) (relay.TenantRelay, error)
	PlatformRegions(ctx context.Context, f relay.RegionFilter) (relay.RegionPage, error)
}

var _ Service = (*relay.Service)(nil)

// Handlers implements httpapi.RelayHandlers.
type Handlers struct {
	svc    Service
	labels Labeler
}

// Labeler names the owning tenants and the hosts of a page of the Platform Console (G4b-E12) — *platform.Service.
type Labeler interface {
	Labels(ctx context.Context, tenantIDs, hostIDs []uuid.UUID) (platform.Labels, error)
}

var _ Labeler = (*platform.Service)(nil)

// WithLabels adds the owning tenant's slug and name and the host's name to the regions of the platform lists; without
// it they carry the ids only.
func (h *Handlers) WithLabels(l Labeler) *Handlers {
	h.labels = l
	return h
}

var _ httpapi.RelayHandlers = (*Handlers)(nil)

// New returns the handlers of the relay operations.
func New(svc Service) *Handlers { return &Handlers{svc: svc} }

// ReasonOwnOnlyGrant is the audit reason of a tenant relay refused to an own-only grant.
const ReasonOwnOnlyGrant = "own_only_grant"

var (
	// errNoDecision: the handler runs without the authorization hook — fail closed (§8.4 invariant 4).
	errNoDecision = errors.New("relayapi: no authorization decision in the request context (Hooks.Authz missing)")
	// errWrongDecision: the decision is not about this route (another tenant, a tenant route on the platform one…).
	errWrongDecision = errors.New("relayapi: the authorization decision does not cover this request")
)

const invalidQuery = "The query parameters are invalid."

// GetTenantRelay implements GET /tenants/{tenantId}/relay.
func (h *Handlers) GetTenantRelay(ctx context.Context, req gen.GetTenantRelayRequestObject) (gen.GetTenantRelayResponseObject, error) {
	d, ok := authzhook.DecisionFrom(ctx)
	switch {
	case !ok:
		return nil, problem.Internal(errNoDecision)
	case req.TenantId == uuid.Nil || d.TenantID != req.TenantId:
		return nil, problem.Internal(errWrongDecision)
	case d.OwnOnly: // the relay belongs to the tenant: never for an own-only grant
		p := problem.New(gen.ProblemCodeForbidden, "The request is not allowed.")
		p.Cause = &authz.Denial{Kind: authz.ErrForbidden, Reason: ReasonOwnOnlyGrant} // for the audit, never sent
		return nil, p
	}
	r, err := h.svc.TenantRelay(ctx, req.TenantId)
	if err != nil {
		return nil, problem.Internal(err)
	}
	out := gen.GetTenantRelay200JSONResponse{Assignments: make([]gen.RelayAssignment, 0, len(r.Assignments)),
		Unavailable: unavailable(r.Unavailable)}
	for _, a := range r.Assignments {
		out.Assignments = append(out.Assignments, gen.RelayAssignment{Id: a.ID, Priority: a.Priority,
			Status: gen.RelayAdminStatus(a.Status), Region: region(a.Region), Health: health(a.Health)})
	}
	return out, nil
}

// ListPlatformRelayRegions implements GET /platform/relay-regions.
func (h *Handlers) ListPlatformRelayRegions(ctx context.Context, req gen.ListPlatformRelayRegionsRequestObject) (gen.ListPlatformRelayRegionsResponseObject, error) {
	out, err := h.platformRegions(ctx, req.Params.Limit, req.Params.Cursor, uuid.Nil)
	if err != nil {
		return nil, err
	}
	return gen.ListPlatformRelayRegions200JSONResponse(out), nil
}

// ListPlatformTenantRelayRegions implements GET /platform/tenants/{tenantId}/relay-regions (P4-T02 — the relay of the
// tenant detail of the Platform Console; mounted through httpapi.PlatformTenantView): the platform list filtered by the
// tenant of the path, which must exist (404). A region of another tenant is never sent (500).
func (h *Handlers) ListPlatformTenantRelayRegions(ctx context.Context, req gen.ListPlatformTenantRelayRegionsRequestObject) (gen.ListPlatformTenantRelayRegionsResponseObject, error) {
	if req.TenantId == uuid.Nil {
		return nil, problem.New(gen.ProblemCodeNotFound, "The resource does not exist.")
	}
	out, err := h.platformRegions(ctx, req.Params.Limit, req.Params.Cursor, req.TenantId)
	if err != nil {
		return nil, err
	}
	for _, r := range out.Items {
		if r.TenantId == nil || *r.TenantId != req.TenantId {
			return nil, problem.Internal(errForeignRegion)
		}
	}
	return gen.ListPlatformTenantRelayRegions200JSONResponse(out), nil
}

// errForeignRegion: the service answered a region of another tenant on a tenant-filtered list — never sent.
var errForeignRegion = errors.New("relayapi: a region of another tenant reached a tenant-filtered list")

// platformRegions answers the platform lists (a decision of a platform route only); tenant = uuid.Nil ⇒ every region.
func (h *Handlers) platformRegions(ctx context.Context, limit *gen.Limit, cursor *gen.Cursor, tenant uuid.UUID) (gen.RelayRegionList, error) {
	d, ok := authzhook.DecisionFrom(ctx)
	switch {
	case !ok:
		return gen.RelayRegionList{}, problem.Internal(errNoDecision)
	case d.TenantID != uuid.Nil:
		return gen.RelayRegionList{}, problem.Internal(errWrongDecision)
	}
	f := relay.RegionFilter{TenantID: tenant}
	if limit != nil {
		if *limit < 1 || *limit > relay.MaxLimit {
			return gen.RelayRegionList{}, problem.Validation(invalidQuery, problem.Field("limit", "out_of_range", "must be between 1 and 200"))
		}
		f.Limit = *limit
	}
	if cursor != nil {
		if *cursor == "" {
			return gen.RelayRegionList{}, problem.Validation(invalidQuery, problem.Field("cursor", "invalid", "not a cursor of this list"))
		}
		f.Cursor = *cursor
	}
	page, err := h.svc.PlatformRegions(ctx, f)
	switch {
	case errors.Is(err, relay.ErrNotFound):
		return gen.RelayRegionList{}, problem.New(gen.ProblemCodeNotFound, "The resource does not exist.")
	case errors.Is(err, relay.ErrInvalid):
		return gen.RelayRegionList{}, problem.Validation(invalidQuery, problem.Field("cursor", "invalid", "not a cursor of this list"))
	case err != nil:
		return gen.RelayRegionList{}, problem.Internal(err)
	}
	out := gen.RelayRegionList{Items: make([]gen.PlatformRelayRegion, 0, len(page.Items)),
		Unavailable: unavailable(page.Unavailable)}
	if page.NextCursor != "" {
		c := page.NextCursor
		out.NextCursor = &c
	}
	tids, hids := make([]uuid.UUID, 0, len(page.Items)), make([]uuid.UUID, 0, len(page.Items))
	for _, r := range page.Items {
		if r.TenantID != nil {
			tids = append(tids, *r.TenantID)
		}
		if r.HostID != nil {
			hids = append(hids, *r.HostID)
		}
	}
	var l platform.Labels
	if h.labels != nil {
		// labels only name what the region already identifies by UUID: a failed lookup leaves them out
		if got, err := h.labels.Labels(ctx, tids, hids); err == nil {
			l = got
		}
	}
	for _, r := range page.Items {
		g := gen.PlatformRelayRegion{Region: region(r.Region), HostId: r.HostID, TenantId: r.TenantID,
			Assignments: make([]gen.PlatformRelayAssignment, 0, len(r.Assignments)), Health: health(r.Health),
			CreatedAt: r.CreatedAt.UTC(), UpdatedAt: r.UpdatedAt.UTC(), Version: r.Version}
		for _, a := range r.Assignments {
			g.Assignments = append(g.Assignments, gen.PlatformRelayAssignment{Id: a.ID, TenantId: a.TenantID,
				InstanceId: a.InstanceID, Priority: a.Priority, Status: gen.RelayAdminStatus(a.Status),
				InstanceStatus: gen.InstanceStatus(a.InstanceStatus)})
		}
		if t, ok := l.Tenant(r.TenantID); ok {
			g.TenantSlug, g.TenantName = &t.Slug, &t.Name
		}
		if r.HostID != nil {
			if n, ok := l.Hosts[*r.HostID]; ok {
				g.HostName = &n
			}
		}
		out.Items = append(out.Items, g)
	}
	return out, nil
}

// region maps a region to the schema RelayRegion (absent addresses and ports are omitted, never zero values).
func region(r relay.Region) gen.RelayRegion {
	out := gen.RelayRegion{Id: r.ID, Code: r.Code, Name: r.Name, Kind: gen.RelayRegionKind(r.Kind),
		DerpRegionId: int(r.DERPRegionID), Hostname: r.Hostname, DerpPort: int(r.DERPPort),
		VerifyMode: gen.RelayRegionVerifyMode(r.VerifyMode), Status: gen.RelayAdminStatus(r.Status)}
	if r.IPv4.IsValid() {
		s := r.IPv4.String()
		out.Ipv4 = &s
	}
	if r.IPv6.IsValid() {
		s := r.IPv6.String()
		out.Ipv6 = &s
	}
	if r.STUNPort > 0 {
		p := int(r.STUNPort)
		out.StunPort = &p
	}
	return out
}

// health maps a health to the schema RelayHealth (times in UTC; checks only when a probe was recorded).
func health(h relay.Health) gen.RelayHealth {
	out := gen.RelayHealth{Status: gen.HealthStatus(h.Status), CheckedAt: utc(h.CheckedAt), Derp: check(h.DERP), Stun: check(h.STUN)}
	if h.Reason != "" {
		r := h.Reason
		out.Reason = &r
	}
	return out
}

func check(c *relay.CheckView) *gen.RelayCheck {
	if c == nil {
		return nil
	}
	out := &gen.RelayCheck{Ok: c.OK, DurationMs: c.DurationMS}
	if c.Status != 0 {
		s := c.Status
		out.Status = &s
	}
	if c.Code != "" {
		code := c.Code
		out.Code = &code
	}
	return out
}

func unavailable(us []relay.Unavailable) []gen.RelayUnavailable {
	out := make([]gen.RelayUnavailable, 0, len(us))
	for _, u := range us {
		g := gen.RelayUnavailable{Metric: u.Metric, Reason: u.Reason}
		if u.Detail != "" {
			d := u.Detail
			g.Detail = &d
		}
		out = append(out, g)
	}
	return out
}

func utc(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	u := t.UTC()
	return &u
}
