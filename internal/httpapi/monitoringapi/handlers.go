// Package monitoringapi serves the monitoring operations of api/openapi.yaml (P2-T13a): getTenantDashboard and
// getPlatformHealth. It only translates between the generated types and internal/monitoring, which builds both read
// models; it never imports internal/store nor internal/headscale (§13.6, internal/archtest).
//
// The authorization hook (authzhook.Authz, Hooks.Authz) decides every operation before it runs. The handlers also
// refuse to answer without that decision (500, never data), the tenant dashboard only for a decision about the tenant
// of the path with a grant on every resource of it (an own-only grant would see other members' figures), and the
// platform health only for a decision of a platform route — defence in depth for T-01 / IT-12b: the tenant is the
// {tenantId} of the path, nothing else, and the operations take no query parameter at all.
//
// Wiring (P2-T16, apps/internal/runner — api process):
//
//	monSvc, _ := monitoring.New(apiStore, monitoring.Config{Logger: log, Registerer: promReg,
//		Devices: monitoring.DeviceCounterFunc(func(ctx context.Context, t uuid.UUID) (monitoring.DeviceCounts, error) {
//			s, err := devicesSvc.Summary(ctx, t)
//			return monitoring.DeviceCounts(s), err
//		})})
//	api, _ := httpapi.New(httpapi.Options{…, Hooks: hooks, Handlers: httpapi.Handlers{…, Monitoring: monitoringapi.New(monSvc)}})
//
// and in the worker process (same Service type, worker store, plus the Prober over the adapter):
//
//	monWrk, _ := monitoring.New(workerStore, monitoring.Config{Devices: …, Prober: <ProberFunc over reg.Probe>, …})
//	_ = monWrk.Register(worker)
//	go monWrk.NewScheduler(monitoring.SchedulerConfig{}).Run(ctx)
package monitoringapi

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
	"github.com/zhaduchanhzz/network-access-mesh/internal/monitoring"
)

// Service is the part of *monitoring.Service the handlers need.
type Service interface {
	TenantDashboard(ctx context.Context, tenantID uuid.UUID) (monitoring.TenantDashboard, error)
	PlatformHealth(ctx context.Context) (monitoring.PlatformHealth, error)
}

var _ Service = (*monitoring.Service)(nil)

// Handlers implements httpapi.MonitoringHandlers.
type Handlers struct {
	svc Service
}

var _ httpapi.MonitoringHandlers = (*Handlers)(nil)

// New returns the handlers of the monitoring operations.
func New(svc Service) *Handlers { return &Handlers{svc: svc} }

// ReasonOwnOnlyGrant is the audit reason of a dashboard refused to an own-only grant.
const ReasonOwnOnlyGrant = "own_only_grant"

var (
	// errNoDecision: the handler runs without the authorization hook — fail closed (§8.4 invariant 4).
	errNoDecision = errors.New("monitoringapi: no authorization decision in the request context (Hooks.Authz missing)")
	// errWrongDecision: the decision is not about this route (another tenant, a tenant route on the platform one…).
	errWrongDecision = errors.New("monitoringapi: the authorization decision does not cover this request")
)

// GetTenantDashboard implements GET /tenants/{tenantId}/dashboard.
func (h *Handlers) GetTenantDashboard(ctx context.Context, req gen.GetTenantDashboardRequestObject) (gen.GetTenantDashboardResponseObject, error) {
	d, ok := authzhook.DecisionFrom(ctx)
	switch {
	case !ok:
		return nil, problem.Internal(errNoDecision)
	case d.TenantID != req.TenantId:
		return nil, problem.Internal(errWrongDecision)
	case d.OwnOnly: // the dashboard aggregates every member's devices: never for an own-only grant
		p := problem.New(gen.ProblemCodeForbidden, "The request is not allowed.")
		p.Cause = &authz.Denial{Kind: authz.ErrForbidden, Reason: ReasonOwnOnlyGrant} // for the audit, never sent
		return nil, p
	}
	dash, err := h.svc.TenantDashboard(ctx, req.TenantId)
	if err != nil {
		return nil, problem.Internal(err)
	}
	return gen.GetTenantDashboard200JSONResponse(dashboard(dash)), nil
}

// GetPlatformHealth implements GET /platform/health.
func (h *Handlers) GetPlatformHealth(ctx context.Context, _ gen.GetPlatformHealthRequestObject) (gen.GetPlatformHealthResponseObject, error) {
	d, ok := authzhook.DecisionFrom(ctx)
	switch {
	case !ok:
		return nil, problem.Internal(errNoDecision)
	case d.TenantID != uuid.Nil:
		return nil, problem.Internal(errWrongDecision)
	}
	ph, err := h.svc.PlatformHealth(ctx)
	if err != nil {
		return nil, problem.Internal(err)
	}
	return gen.GetPlatformHealth200JSONResponse(platformHealth(ph)), nil
}

// dashboard maps the tenant dashboard to the schema TenantDashboard.
func dashboard(d monitoring.TenantDashboard) gen.TenantDashboard {
	out := gen.TenantDashboard{
		Devices:     gen.DeviceCounts{Total: d.Devices.Total, Online: d.Devices.Online, SyncedAt: utc(d.Devices.SyncedAt)},
		Instance:    instanceHealth(d.Instance),
		Unavailable: make([]gen.UnavailableSection, 0, len(d.Unavailable)),
	}
	for _, u := range d.Unavailable {
		s := gen.UnavailableSection{Section: u.Section, Reason: u.Reason}
		if u.Detail != "" {
			detail := u.Detail
			s.Detail = &detail
		}
		out.Unavailable = append(out.Unavailable, s)
	}
	return out
}

// instanceHealth maps the health of an instance to the schema InstanceHealth (the version stays internal: the tenant
// view is status, time and reason).
func instanceHealth(h monitoring.InstanceHealth) gen.InstanceHealth {
	out := gen.InstanceHealth{Status: gen.HealthStatus(h.Status), CheckedAt: utc(h.CheckedAt)}
	if h.Reason != "" {
		r := h.Reason
		out.Reason = &r
	}
	return out
}

// platformHealth maps the platform health to the schema PlatformHealth.
func platformHealth(p monitoring.PlatformHealth) gen.PlatformHealth {
	out := gen.PlatformHealth{
		CheckedAt:  p.CheckedAt.UTC(),
		Components: make([]gen.ComponentHealth, 0, len(p.Components)),
		Tenants:    gen.TenantCounts{Total: p.Tenants.Total, ByStatus: counts(p.Tenants.ByStatus)},
		Instances: gen.InstanceCounts{Total: p.Instances.Total, ByStatus: counts(p.Instances.ByStatus),
			ByHealth: counts(p.Instances.ByHealth), ByVersion: counts(p.Instances.ByVersion), Unhealthy: p.Instances.Unhealthy},
		Jobs: gen.JobQueueHealth{CheckedAt: p.Jobs.CheckedAt.UTC(), Unfinished: counts(p.Jobs.Unfinished),
			FailedLast24h: p.Jobs.FailedLast24h},
	}
	for _, c := range p.Components {
		g := gen.ComponentHealth{Name: c.Name, Status: gen.HealthStatus(c.Status), CheckedAt: utc(c.CheckedAt)}
		if c.Reason != "" {
			r := c.Reason
			g.Reason = &r
		}
		out.Components = append(out.Components, g)
	}
	return out
}

func counts(m map[string]int) gen.StatusCounts {
	out := make(gen.StatusCounts, len(m))
	for k, v := range m {
		out[k] = v
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
