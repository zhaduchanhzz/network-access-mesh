package diagnosticsapi

import (
	"context"
	"slices"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/devices"
	"github.com/zhaduchanhzz/network-access-mesh/internal/monitoring"
	"github.com/zhaduchanhzz/network-access-mesh/internal/network"
	"github.com/zhaduchanhzz/network-access-mesh/internal/policies"
	"github.com/zhaduchanhzz/network-access-mesh/internal/relay"
)

// Source implements monitoring.DiagnosticsSource (P5-T08) over the services of the modules monitoring may not import
// (§13.6): the device register (devices — the caller's own-only scope enforced by devices.Access, the same rule as
// GET /devices/{id}), routers and the resource catalog (network), relays with their last probe (relay) and the applied
// policy evaluated by internal/policies on its own document. The api process (apps/internal/runner) and the
// authorization matrix (tests/security) build it with NewSource.
type Source struct {
	dev  DeviceReader
	netw NetworkReader
	rel  RelayReader
	pol  PolicyReader
}

// DeviceReader is the part of *devices.Service the source needs.
type DeviceReader interface {
	Get(ctx context.Context, tenantID, deviceID uuid.UUID, a devices.Access) (devices.Device, error)
}

// NetworkReader is the part of *network.Service the source needs.
type NetworkReader interface {
	GetResource(ctx context.Context, tenantID, id uuid.UUID) (network.Resource, error)
	ListRoutes(ctx context.Context, tenantID uuid.UUID) ([]network.RouteDevice, error)
}

// RelayReader is the part of *relay.Service the source needs.
type RelayReader interface {
	TenantRelay(ctx context.Context, tenantID uuid.UUID) (relay.TenantRelay, error)
}

// PolicyReader is the part of *policies.VersionService the source needs.
type PolicyReader interface {
	State(ctx context.Context, tenantID uuid.UUID) (policies.PolicyState, error)
}

var (
	_ DeviceReader  = (*devices.Service)(nil)
	_ NetworkReader = (*network.Service)(nil)
	_ RelayReader   = (*relay.Service)(nil)
	_ PolicyReader  = (*policies.VersionService)(nil)

	_ monitoring.DiagnosticsSource = Source{}
)

// NewSource returns the diagnostics source over the four services.
func NewSource(dev DeviceReader, netw NetworkReader, rel RelayReader, pol PolicyReader) Source {
	return Source{dev: dev, netw: netw, rel: rel, pol: pol}
}

func (s Source) Device(ctx context.Context, tenantID, deviceID uuid.UUID, scope monitoring.DeviceScope) (monitoring.DiagDevice, error) {
	d, err := s.dev.Get(ctx, tenantID, deviceID, devices.Access{OwnOnly: scope.OwnOnly, MembershipID: scope.MembershipID})
	if e, ok := devices.AsError(err); ok && e.Code == devices.CodeNotFound {
		reason := e.Reason
		if reason == devices.ReasonNotOwnResource {
			reason = monitoring.ReasonNotOwnResource
		}
		return monitoring.DiagDevice{}, monitoring.NotFound(reason)
	}
	if err != nil {
		return monitoring.DiagDevice{}, err
	}
	out := monitoring.DiagDevice{ID: d.ID, Name: d.Name, GivenName: d.GivenName, Addresses: slices.Clone(d.IPAddresses),
		Tags: slices.Clone(d.Tags), Online: d.Online, LastSeen: d.LastSeen, Expiry: d.Expiry, Revocation: d.Revocation.State,
		SyncedAt: d.SyncedAt}
	if d.Owner != nil {
		out.Owner = d.Owner.MembershipID
	}
	return out, nil
}

func (s Source) Resource(ctx context.Context, tenantID, resourceID uuid.UUID) (monitoring.DiagResource, error) {
	r, err := s.netw.GetResource(ctx, tenantID, resourceID)
	if e, ok := network.AsError(err); ok && e.Code == network.CodeNotFound {
		return monitoring.DiagResource{}, monitoring.NotFound(e.Reason)
	}
	if err != nil {
		return monitoring.DiagResource{}, err
	}
	return monitoring.DiagResource{ID: r.ID, Name: r.Name, Address: r.Address, Ports: slices.Clone(r.Ports), Protocol: r.Protocol}, nil
}

func (s Source) Routers(ctx context.Context, tenantID uuid.UUID) ([]monitoring.DiagRouter, error) {
	rs, err := s.netw.ListRoutes(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := make([]monitoring.DiagRouter, 0, len(rs))
	for _, r := range rs {
		if len(r.Approved) == 0 {
			continue
		}
		rt := monitoring.DiagRouter{DeviceID: r.DeviceID, Name: r.GivenName, Tags: slices.Clone(r.Tags), Online: r.Online,
			Approved: slices.Clone(r.Approved)}
		if rt.Name == "" {
			rt.Name = r.Name
		}
		// the router's tailnet address (the target of `tailscale ping` for a resource behind it)
		if d, err := s.dev.Get(ctx, tenantID, r.DeviceID, devices.Access{}); err == nil {
			rt.Addresses = slices.Clone(d.IPAddresses)
		}
		out = append(out, rt)
	}
	return out, nil
}

func (s Source) Relays(ctx context.Context, tenantID uuid.UUID) ([]monitoring.DiagRelay, error) {
	r, err := s.rel.TenantRelay(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := make([]monitoring.DiagRelay, 0, len(r.Assignments))
	for _, a := range r.Assignments {
		status := a.Status
		if a.Region.Status != "active" { // an assignment of a region that is not active is not used either
			status = a.Region.Status
		}
		d := monitoring.DiagRelay{Code: a.Region.Code, Name: a.Region.Name, Hostname: a.Region.Hostname, Status: status,
			Health: a.Health.Status, Reason: a.Health.Reason, CheckedAt: a.Health.CheckedAt}
		if c := a.Health.DERP; c != nil {
			d.DERP = &monitoring.DiagCheck{OK: c.OK, Code: c.Code}
		}
		if c := a.Health.STUN; c != nil {
			d.STUN = &monitoring.DiagCheck{OK: c.OK, Code: c.Code}
		}
		out = append(out, d)
	}
	return out, nil
}

func (s Source) Policy(ctx context.Context, tenantID uuid.UUID, check *monitoring.AccessCheck) (monitoring.DiagPolicy, error) {
	st, err := s.pol.State(ctx, tenantID)
	if err != nil {
		return monitoring.DiagPolicy{}, err
	}
	out := monitoring.DiagPolicy{DesiredVersion: st.DesiredVersion}
	if l := st.Latest; l != nil {
		out.LatestState, out.LatestAt = l.State, latestAt(*l)
		if l.ErrorCode != nil {
			out.LatestErrorCode = *l.ErrorCode
		}
	}
	a := st.Applied
	if a != nil {
		id := a.Application.PolicyVersionID
		out.Applied, out.VersionID, out.Version, out.SHA256, out.Trigger = true, &id, a.Version,
			a.Application.AppliedSHA256, a.Application.Trigger
		out.AppliedAt = a.Application.FinishedAt
	}
	if check == nil {
		return out, nil
	}
	if a == nil {
		out.Access = &monitoring.AccessVerdict{Decision: policies.AccessUnknown, Reason: policies.AccessReasonNoPolicy,
			Grants: []int{}, Allowed: []string{}, Unresolved: []string{}}
		return out, nil
	}
	q := policies.AccessQuery{Src: accessPeer(check.Src), Port: check.Port}
	switch {
	case check.Dst != nil:
		p := accessPeer(*check.Dst)
		q.Dst = &p
	case check.TargetResource:
		q.Resource = &policies.AccessResource{Name: check.ResourceName, Address: check.ResourceAddr,
			RouterTags: check.RouterTags}
	}
	r := policies.EvaluateAccess([]byte(a.Document), q)
	out.Access = &monitoring.AccessVerdict{Decision: r.Decision, Reason: r.Reason, Grants: r.Grants, Allowed: r.Allowed,
		Unresolved: r.Unresolved}
	return out, nil
}

func accessPeer(p monitoring.AccessPeer) policies.AccessPeer {
	return policies.AccessPeer{Owner: p.Owner, Tags: slices.Clone(p.Tags), Addresses: slices.Clone(p.Addresses)}
}

func latestAt(a policies.Application) *time.Time {
	if a.FinishedAt != nil {
		return a.FinishedAt
	}
	t := a.CreatedAt
	return &t
}
