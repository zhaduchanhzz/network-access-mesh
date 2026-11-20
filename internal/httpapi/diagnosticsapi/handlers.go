// Package diagnosticsapi serves the Connectivity Diagnostics of api/openapi.yaml (P5-T08, httpapi.DiagnosticsHandlers):
// getTenantDiagnosticsInstance — GET /tenants/{tenantId}/diagnostics/instance (tenant.diagnostics:read: TO TA TP, staff
// with a Support Access Grant) — and runTenantConnectivityDiagnosis — POST /tenants/{tenantId}/diagnostics/connectivity
// (tenant.diagnostics:run: TO TA TP, End User on its own devices ○, staff with a grant). It only translates between the
// generated types and internal/monitoring, which builds both answers from the control plane's records; it never imports
// internal/store nor internal/headscale (§13.6, internal/archtest).
//
// Defence in depth on top of the authorization hook and RLS: the handlers refuse to answer without a decision (500,
// never data) and only for a decision about the tenant of the path — the tenant is the {tenantId} of the path and
// nothing else (no query parameter). The instance state aggregates the whole tenant: never for an own-only grant (§8.6
// has no ○ cell for it — a future one must not widen it). The diagnosis passes the own-only scope to the service:
// source and target must then be the caller's own untagged devices, anything else is 404 like an unknown id.
//
// Wiring (apps/internal/runner — api process): monitoring.Service built with Source (source.go) over the devices,
// network, relay and policies services:
//
//	monSvc, _ := monitoring.New(apiStore, monitoring.Config{…, Diagnostics: diagnosticsapi.NewSource(dev, netw, relays, versions)})
//	api, _ := httpapi.New(httpapi.Options{…, Handlers: httpapi.Handlers{…, Diagnostics: diagnosticsapi.New(monSvc)}})
package diagnosticsapi

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/authz"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/authzhook"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/gen"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/problem"
	"github.com/zhaduchanhzz/network-access-mesh/internal/monitoring"
)

// Service is the part of *monitoring.Service the handlers need.
type Service interface {
	InstanceDiagnostics(ctx context.Context, tenantID uuid.UUID) (monitoring.InstanceDiagnostics, error)
	Connectivity(ctx context.Context, tenantID uuid.UUID, scope monitoring.DeviceScope, req monitoring.ConnectivityRequest) (monitoring.ConnectivityReport, error)
}

var _ Service = (*monitoring.Service)(nil)

// Handlers implements httpapi.DiagnosticsHandlers.
type Handlers struct {
	svc Service
}

var _ httpapi.DiagnosticsHandlers = (*Handlers)(nil)

// New returns the handlers of the diagnostics operations.
func New(svc Service) *Handlers { return &Handlers{svc: svc} }

// ReasonOwnOnlyGrant is the audit reason of an instance state refused to an own-only grant.
const ReasonOwnOnlyGrant = "own_only_grant"

var (
	// errNoDecision: the handler runs without the authorization hook — fail closed (§8.4 invariant 4).
	errNoDecision = errors.New("diagnosticsapi: no authorization decision in the request context (Hooks.Authz missing)")
	// errWrongDecision: the decision is not about this route (another tenant, a platform decision…).
	errWrongDecision = errors.New("diagnosticsapi: the authorization decision does not cover this request")
)

const notFoundDetail = "The resource does not exist."

// GetTenantDiagnosticsInstance implements GET /tenants/{tenantId}/diagnostics/instance.
func (h *Handlers) GetTenantDiagnosticsInstance(ctx context.Context, req gen.GetTenantDiagnosticsInstanceRequestObject) (gen.GetTenantDiagnosticsInstanceResponseObject, error) {
	d, ok := authzhook.DecisionFrom(ctx)
	switch {
	case !ok:
		return nil, problem.Internal(errNoDecision)
	case req.TenantId == uuid.Nil || d.TenantID != req.TenantId:
		return nil, problem.Internal(errWrongDecision)
	case d.OwnOnly: // the state of the whole tenant: never for an own-only grant
		p := problem.New(gen.ProblemCodeForbidden, "The request is not allowed.")
		p.Cause = &authz.Denial{Kind: authz.ErrForbidden, Reason: ReasonOwnOnlyGrant} // for the audit, never sent
		return nil, p
	}
	out, err := h.svc.InstanceDiagnostics(ctx, req.TenantId)
	switch {
	case errors.Is(err, monitoring.ErrDiagNotFound):
		return nil, problem.New(gen.ProblemCodeNotFound, notFoundDetail)
	case err != nil:
		return nil, problem.Internal(err)
	}
	return gen.GetTenantDiagnosticsInstance200JSONResponse(instance(out)), nil
}

// RunTenantConnectivityDiagnosis implements POST /tenants/{tenantId}/diagnostics/connectivity.
func (h *Handlers) RunTenantConnectivityDiagnosis(ctx context.Context, req gen.RunTenantConnectivityDiagnosisRequestObject) (gen.RunTenantConnectivityDiagnosisResponseObject, error) {
	d, ok := authzhook.DecisionFrom(ctx)
	switch {
	case !ok:
		return nil, problem.Internal(errNoDecision)
	case req.TenantId == uuid.Nil || d.TenantID != req.TenantId:
		return nil, problem.Internal(errWrongDecision)
	case req.Body == nil:
		return nil, problem.Validation("The request body is invalid.", problem.Field("body", "required", "a JSON object is required"))
	}
	scope := monitoring.DeviceScope{OwnOnly: d.OwnOnly, MembershipID: d.MembershipID}
	in := monitoring.ConnectivityRequest{Source: req.Body.SourceDeviceId, TargetDevice: req.Body.TargetDeviceId,
		TargetResource: req.Body.TargetResourceId}
	if req.Body.Port != nil {
		if *req.Body.Port < 1 || *req.Body.Port > 65535 {
			return nil, problem.Validation("The request body is invalid.", problem.Field("port", "out_of_range", "must be between 1 and 65535"))
		}
		in.Port = *req.Body.Port
	}
	r, err := h.svc.Connectivity(ctx, req.TenantId, scope, in)
	var de *monitoring.DiagnosticsError
	switch {
	case errors.As(err, &de):
		return nil, problem.Validation("The request body is invalid.", problem.Field(de.Field, de.Reason, fieldMessage(de.Reason)))
	case errors.Is(err, monitoring.ErrDiagNotFound):
		p := problem.New(gen.ProblemCodeNotFound, notFoundDetail)
		if monitoring.NotFoundReason(err) == monitoring.ReasonNotOwnResource {
			p.Cause = &authz.Denial{Kind: authz.ErrNotFound, Reason: monitoring.ReasonNotOwnResource} // audit only
		}
		return nil, p
	case err != nil:
		return nil, problem.Internal(err)
	}
	return gen.RunTenantConnectivityDiagnosis200JSONResponse(report(r)), nil
}

func fieldMessage(reason string) string {
	switch reason {
	case "exactly_one_target":
		return "exactly one of target_device_id and target_resource_id is required"
	case "same_device":
		return "the target must differ from the source"
	case "required":
		return "required"
	}
	return "invalid"
}

// ------------------------------------------------------------------------------------------------ mapping

func instance(d monitoring.InstanceDiagnostics) gen.TenantDiagnostics {
	out := gen.TenantDiagnostics{
		CheckedAt:    d.CheckedAt.UTC(),
		TenantStatus: gen.TenantStatus(d.TenantStatus),
		Instance: gen.DiagnosticsInstance{Health: instanceHealth(d.Instance.Health),
			ApiKey: gen.DiagnosticsAPIKey{Status: gen.DiagnosticsAPIKeyStatus(d.Instance.APIKey.Status),
				ExpiresAt: utc(d.Instance.APIKey.ExpiresAt)}},
		Edge:   gen.DiagnosticsEdge{Status: gen.DiagnosticsEdgeStatus(d.Edge.Status), Reason: opt(d.Edge.Reason), CheckedAt: utc(d.Edge.CheckedAt)},
		Relays: make([]gen.DiagnosticsRelay, 0, len(d.Relays)),
		Policy: policy(d.Policy),
		Devices: gen.DiagnosticsDeviceCounts{Total: d.Devices.Total, Online: d.Devices.Online, Offline: d.Devices.Offline,
			Expired: d.Devices.Expired, SyncedAt: utc(d.Devices.SyncedAt)},
		Unavailable: make([]gen.UnavailableSection, 0, len(d.Unavailable)),
	}
	if d.Instance.Status != "" {
		st := gen.InstanceStatus(d.Instance.Status)
		out.Instance.Status = &st
	}
	for _, r := range d.Relays {
		out.Relays = append(out.Relays, relayOf(r))
	}
	for _, u := range d.Unavailable {
		out.Unavailable = append(out.Unavailable, gen.UnavailableSection{Section: u.Section, Reason: u.Reason, Detail: opt(u.Detail)})
	}
	return out
}

func instanceHealth(h monitoring.InstanceHealth) gen.InstanceHealth {
	out := gen.InstanceHealth{Status: gen.HealthStatus(h.Status), CheckedAt: utc(h.CheckedAt)}
	if h.Reason != "" {
		r := h.Reason
		out.Reason = &r
	}
	return out
}

func relayOf(r monitoring.DiagRelay) gen.DiagnosticsRelay {
	out := gen.DiagnosticsRelay{Code: r.Code, Name: r.Name, Hostname: r.Hostname, Status: gen.RelayAdminStatus(r.Status),
		Health: gen.HealthStatus(r.Health), Reason: opt(r.Reason), CheckedAt: utc(r.CheckedAt)}
	if r.DERP != nil {
		ok := r.DERP.OK
		out.DerpOk = &ok
	}
	if r.STUN != nil {
		ok := r.STUN.OK
		out.StunOk = &ok
	}
	return out
}

func policy(p monitoring.DiagPolicy) gen.DiagnosticsPolicy {
	out := gen.DiagnosticsPolicy{Applied: p.Applied, VersionId: p.VersionID, AppliedSha256: opt(p.SHA256),
		AppliedAt: utc(p.AppliedAt), Trigger: opt(p.Trigger), LatestState: opt(p.LatestState),
		LatestErrorCode: opt(p.LatestErrorCode), LatestAt: utc(p.LatestAt)}
	if p.Version > 0 {
		v := p.Version
		out.Version = &v
	}
	if p.DesiredVersion > 0 {
		v := p.DesiredVersion
		out.DesiredVersion = &v
	}
	if a := p.Access; a != nil {
		out.Access = &gen.DiagnosticsAccess{Decision: gen.DiagnosticsAccessDecision(a.Decision), Reason: opt(a.Reason),
			Grants: nonNil(a.Grants), Allowed: nonNil(a.Allowed), Unresolved: nonNil(a.Unresolved)}
	}
	return out
}

func report(r monitoring.ConnectivityReport) gen.ConnectivityDiagnosis {
	out := gen.ConnectivityDiagnosis{
		CheckedAt:      r.CheckedAt.UTC(),
		PathObservable: false,
		Verdict:        gen.ConnectivityDiagnosisVerdict(r.Verdict),
		Source:         device(r.Source),
		Target:         gen.DiagnosticsTarget{Routers: make([]gen.DiagnosticsRouter, 0, len(r.Target.Routers))},
		Checks:         make([]gen.DiagnosticsCheck, 0, len(r.Checks)),
		Policy:         policy(r.Policy),
		RelayCode:      opt(r.RelayCode),
		Commands:       make([]gen.DiagnosticsCommand, 0, len(r.Commands)),
	}
	if r.Port > 0 {
		p := r.Port
		out.Port = &p
	}
	switch {
	case r.Target.Device != nil:
		out.Target.Kind = gen.DiagnosticsTargetKindDevice
		dev := device(*r.Target.Device)
		out.Target.Device = &dev
	case r.Target.Resource != nil:
		out.Target.Kind = gen.DiagnosticsTargetKindResource
		res := r.Target.Resource
		addr := res.Address.String()
		if res.Address.IsSingleIP() {
			addr = res.Address.Addr().String()
		}
		out.Target.Resource = &gen.DiagnosticsResource{Id: res.ID, Name: res.Name, Address: addr, Ports: nonNil(res.Ports),
			Protocol: res.Protocol}
	}
	for _, rt := range r.Target.Routers {
		routes := make([]string, 0, len(rt.Approved))
		for _, p := range rt.Approved {
			routes = append(routes, p.String())
		}
		out.Target.Routers = append(out.Target.Routers, gen.DiagnosticsRouter{DeviceId: rt.DeviceID, Name: rt.Name,
			IpAddresses: addrs(rt.Addresses), Tags: nonNil(rt.Tags), Online: rt.Online, ApprovedRoutes: routes})
	}
	for _, c := range r.Checks {
		out.Checks = append(out.Checks, gen.DiagnosticsCheck{Id: gen.DiagnosticsCheckId(c.ID),
			Status: gen.DiagnosticsCheckStatus(c.Status), Reason: opt(c.Reason)})
	}
	for _, c := range r.Commands {
		out.Commands = append(out.Commands, gen.DiagnosticsCommand{Id: gen.DiagnosticsCommandId(c.ID),
			Os: gen.DiagnosticsCommandOs(c.OS), RunOn: gen.DiagnosticsCommandRunOn(c.RunOn), Command: c.Command})
	}
	return out
}

func device(d monitoring.DiagDevice) gen.DiagnosticsDevice {
	out := gen.DiagnosticsDevice{Id: d.ID, Name: d.Name, GivenName: d.GivenName, IpAddresses: addrs(d.Addresses),
		Tags: nonNil(d.Tags), Online: d.Online, LastSeen: utc(d.LastSeen), Expiry: utc(d.Expiry),
		RevocationState: gen.DiagnosticsDeviceRevocationState(d.Revocation), SyncedAt: d.SyncedAt.UTC()}
	if out.RevocationState == "" {
		out.RevocationState = gen.DiagnosticsDeviceRevocationStateNone
	}
	if d.Owner != uuid.Nil && len(d.Tags) == 0 {
		o := d.Owner
		out.OwnerMembershipId = &o
	}
	return out
}

func addrs(as []netip.Addr) []string {
	out := make([]string, 0, len(as))
	for _, a := range as {
		out = append(out, a.String())
	}
	return out
}

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

func opt(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func utc(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	u := t.UTC()
	return &u
}
