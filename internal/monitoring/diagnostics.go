package monitoring

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// Connectivity Diagnostics (P5-T08 — §12.3, §13.2 "diagnostics", §9.5): two read models built from what the control
// plane records — never a measurement of the path between two devices, which the server cannot observe (direct or
// relay is decided between the clients):
//
//   - InstanceDiagnostics (GET /tenants/{t}/diagnostics/instance): the tenant's control plane with the time each part
//     was observed — instance health (health.probe), reachability of the edge on the tenant's hostname (the DERP check
//     of relay.probe goes through the same public listener and hostname as the clients' control connection), relays
//     with their DERP/STUN checks, the policy applied to Headscale and when, device counts (online, offline, expired)
//     with synced_at, the expiry of the instance's API key (a time only — never a secret);
//   - Connectivity (POST /tenants/{t}/diagnostics/connectivity): a verdict from those records for a source device and
//     a target device or catalog resource (both of the tenant, online, not expired, not revoked; a grant of the applied
//     policy for TCP to the port — internal/policies evaluates its own document; an approved subnet route for a
//     resource), plus the checklist of commands to run ON the devices (`tailscale status`, `ping`, `netcheck`,
//     `debug derp`, a real TCP connection — §9.5, HS-25/CL-09: `tailscale ping` never tests the policy).
//
// The module reaches devices, routes, resources, relays and policies only through DiagnosticsSource, implemented in
// apps/* over their services (§13.6: monitoring never imports policies nor devices, never reads their tables).

// Errors of the diagnostics.
var (
	// ErrDiagNotFound: the device or resource does not exist in the tenant, or the caller may not see it (own-only).
	ErrDiagNotFound = errors.New("monitoring: diagnostics: not found")
	// errNotWired: the service was built without a DiagnosticsSource.
	errNotWired = errors.New("monitoring: diagnostics: no source wired (Config.Diagnostics)")
)

// ReasonNotOwnResource is the reason of a device or resource an own-only caller may not see (the audit records the
// denial; the client sees the same 404 as for an unknown id).
const ReasonNotOwnResource = "not_own_resource"

type notFound struct{ reason string }

func (e *notFound) Error() string   { return "monitoring: diagnostics: not found (" + e.reason + ")" }
func (e *notFound) Is(t error) bool { return t == ErrDiagNotFound }

// NotFound returns an error that is ErrDiagNotFound, with its reason (DiagnosticsSource implementations).
func NotFound(reason string) error { return &notFound{reason: reason} }

// NotFoundReason returns the reason of an ErrDiagNotFound built by NotFound ("" otherwise).
func NotFoundReason(err error) string {
	var e *notFound
	if errors.As(err, &e) {
		return e.reason
	}
	return ""
}

// DiagnosticsError is a request the diagnostics refuse (422 on Field).
type DiagnosticsError struct {
	Field  string
	Reason string
}

func (e *DiagnosticsError) Error() string {
	return "monitoring: diagnostics: " + e.Field + ": " + e.Reason
}

// DeviceScope is what the caller may see of the register: an own-only caller (End User) only its own untagged devices.
type DeviceScope struct {
	OwnOnly      bool
	MembershipID uuid.UUID
}

// DiagDevice is a device of the register (cache of inventory.sync, with its synced_at).
type DiagDevice struct {
	ID         uuid.UUID
	Name       string
	GivenName  string
	Addresses  []netip.Addr
	Owner      uuid.UUID // membership owning an untagged device; uuid.Nil when tagged or unknown
	Tags       []string
	Online     bool
	LastSeen   *time.Time
	Expiry     *time.Time
	Revocation string // none, pending, applied, failed
	SyncedAt   time.Time
}

// DiagResource is a catalog resource.
type DiagResource struct {
	ID       uuid.UUID
	Name     string
	Address  netip.Prefix
	Ports    []string
	Protocol string
}

// DiagRouter is a device with approved routes.
type DiagRouter struct {
	DeviceID  uuid.UUID
	Name      string
	Addresses []netip.Addr
	Tags      []string
	Online    bool
	Approved  []netip.Prefix
}

// DiagCheck is one check of the last relay probe.
type DiagCheck struct {
	OK   bool
	Code string
}

// DiagRelay is a relay of the tenant with the health of its last probe.
type DiagRelay struct {
	Code      string // region_code shown by `tailscale status`/`ping` (relay "<code>")
	Name      string
	Hostname  string
	Status    string // administrative: pending, active, disabled
	Health    string // healthy, unhealthy, unknown
	Reason    string
	CheckedAt *time.Time
	DERP      *DiagCheck
	STUN      *DiagCheck
}

// AccessPeer / AccessCheck are the question asked to the policy (internal/policies.EvaluateAccess in apps/*).
type AccessPeer struct {
	Owner     uuid.UUID
	Tags      []string
	Addresses []netip.Addr
}

// AccessCheck is Src → Dst (a device) or Src → Resource (with the tags of each covering router), TCP Port (0 = any).
type AccessCheck struct {
	Src            AccessPeer
	Dst            *AccessPeer
	ResourceName   string
	ResourceAddr   netip.Prefix
	RouterTags     [][]string
	TargetResource bool
	Port           int
}

// AccessVerdict is the policy's answer.
type AccessVerdict struct {
	Decision   string // allowed, denied, unknown
	Reason     string
	Grants     []int
	Allowed    []string
	Unresolved []string
}

// DiagPolicy is the policy state of the tenant.
type DiagPolicy struct {
	Applied         bool
	VersionID       *uuid.UUID
	Version         int
	SHA256          string
	AppliedAt       *time.Time
	Trigger         string
	LatestState     string // "" when no application at all
	LatestErrorCode string
	LatestAt        *time.Time
	DesiredVersion  int // 0: none
	Access          *AccessVerdict
}

// DiagnosticsSource reads the other modules (implemented in apps/*).
type DiagnosticsSource interface {
	// Device returns a device of the tenant visible in scope (ErrDiagNotFound otherwise).
	Device(ctx context.Context, tenantID, deviceID uuid.UUID, scope DeviceScope) (DiagDevice, error)
	// Resource returns a catalog resource of the tenant (ErrDiagNotFound otherwise).
	Resource(ctx context.Context, tenantID, resourceID uuid.UUID) (DiagResource, error)
	// Routers returns the devices of the tenant with approved routes.
	Routers(ctx context.Context, tenantID uuid.UUID) ([]DiagRouter, error)
	// Relays returns the relays of the tenant's live instance.
	Relays(ctx context.Context, tenantID uuid.UUID) ([]DiagRelay, error)
	// Policy returns the policy state; with check, the applied policy's answer to it in Access.
	Policy(ctx context.Context, tenantID uuid.UUID, check *AccessCheck) (DiagPolicy, error)
}

// Statuses of a part of the diagnostics and of a check.
const (
	DiagReachable   = "reachable"
	DiagUnreachable = "unreachable"

	CheckPass          = "pass"
	CheckFail          = "fail"
	CheckWarn          = "warn"
	CheckUnknown       = "unknown"
	CheckNotApplicable = "not_applicable"

	VerdictAllowed = "allowed"
	VerdictBlocked = "blocked"
	VerdictUnknown = "unknown"

	APIKeyValid    = "valid"
	APIKeyExpiring = "expiring"
	APIKeyExpired  = "expired"
	APIKeyUnknown  = "unknown"
)

// Thresholds of the diagnostics.
const (
	// APIKeyAlertBefore: the instance's API key is reported expiring within this (§13.5/§16.3: 14 days).
	APIKeyAlertBefore = 14 * 24 * time.Hour
	// InventoryStaleAfter: a register older than this is flagged (the inventory.sync period is a few minutes).
	InventoryStaleAfter = 15 * time.Minute
)

// Unavailable parts of the diagnostics (section → reason).
const (
	SectionNoise   = "noise"
	SectionP2PPath = "p2p_path"
	SectionPolicy  = "policies"

	ReasonNotObservable = "not_observable"
	ReasonNeverApplied  = "never_applied"
	ReasonNoRelay       = "no_relay"
)

// APIKeyState is the expiry of the instance's Headscale API key (a time only).
type APIKeyState struct {
	Status    string
	ExpiresAt *time.Time
}

// InstanceDiag is the instance part.
type InstanceDiag struct {
	ID     *uuid.UUID
	Status string // instance status; "" when the tenant has no instance
	Health InstanceHealth
	APIKey APIKeyState
}

// EdgeState is the reachability of the edge on the tenant's hostname, from the DERP check of the last relay probe.
type EdgeState struct {
	Status    string // reachable, unreachable, unknown
	Reason    string
	CheckedAt *time.Time
}

// DeviceDiag is the device part (offline = total − online).
type DeviceDiag struct {
	Total, Online, Offline, Expired int
	SyncedAt                        *time.Time
}

// InstanceDiagnostics is GET /tenants/{t}/diagnostics/instance.
type InstanceDiagnostics struct {
	CheckedAt    time.Time
	TenantStatus string
	Instance     InstanceDiag
	Edge         EdgeState
	Relays       []DiagRelay
	Policy       DiagPolicy
	Devices      DeviceDiag
	Unavailable  []Unavailable
}

func (s *Service) source() (DiagnosticsSource, error) {
	if s.diag == nil {
		return nil, errNotWired
	}
	return s.diag, nil
}

type tenantState struct {
	tenant   string
	instance InstanceDiag
	now      time.Time
}

// readTenant reads the tenant and its instance on the tenant pool (RLS: the tenant of the path only).
func (s *Service) readTenant(ctx context.Context, tenantID uuid.UUID) (tenantState, error) {
	var out tenantState
	err := s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		r, err := q.GetTenantDiagnosticsInstance(ctx, tenantID)
		if errors.Is(err, store.ErrNoRows) {
			return ErrDiagNotFound
		}
		if err != nil {
			return err
		}
		out.tenant, out.now = r.TenantStatus, r.Now
		if r.InstanceID == nil || r.InstanceStatus == nil {
			out.instance = InstanceDiag{Health: InstanceHealth{Status: StatusUnknown, Reason: ReasonNoInstance},
				APIKey: APIKeyState{Status: APIKeyUnknown}}
			return nil
		}
		out.instance = InstanceDiag{ID: r.InstanceID, Status: *r.InstanceStatus,
			Health: HealthOf(*r.InstanceStatus, r.LastHealth, r.LastHealthAt, r.Now, s.staleAfter),
			APIKey: apiKeyState(r.ApiKeyExpiresAt, r.Now)}
		return nil
	})
	return out, err
}

func apiKeyState(exp *time.Time, now time.Time) APIKeyState {
	switch {
	case exp == nil:
		return APIKeyState{Status: APIKeyUnknown}
	case !exp.After(now):
		return APIKeyState{Status: APIKeyExpired, ExpiresAt: exp}
	case exp.Sub(now) <= APIKeyAlertBefore:
		return APIKeyState{Status: APIKeyExpiring, ExpiresAt: exp}
	}
	return APIKeyState{Status: APIKeyValid, ExpiresAt: exp}
}

// edgeOf derives the reachability of the edge from the relays (the first active one with a verdict).
func edgeOf(relays []DiagRelay) EdgeState {
	for _, r := range relays {
		if r.Status != "active" {
			continue
		}
		switch {
		case r.Health == StatusUnknown || r.DERP == nil:
			reason := r.Reason
			if reason == "" {
				reason = ReasonNeverChecked
			}
			return EdgeState{Status: StatusUnknown, Reason: reason, CheckedAt: r.CheckedAt}
		case r.DERP.OK:
			return EdgeState{Status: DiagReachable, CheckedAt: r.CheckedAt}
		default:
			reason := r.DERP.Code
			if reason == "" {
				reason = "derp_probe_failed"
			}
			return EdgeState{Status: DiagUnreachable, Reason: reason, CheckedAt: r.CheckedAt}
		}
	}
	return EdgeState{Status: StatusUnknown, Reason: ReasonNoRelay}
}

// InstanceDiagnostics builds the control-plane state of the tenant of the path.
func (s *Service) InstanceDiagnostics(ctx context.Context, tenantID uuid.UUID) (InstanceDiagnostics, error) {
	src, err := s.source()
	if err != nil {
		return InstanceDiagnostics{}, err
	}
	ts, err := s.readTenant(ctx, tenantID)
	if err != nil {
		return InstanceDiagnostics{}, fmt.Errorf("monitoring: diagnostics: instance: %w", err)
	}
	out := InstanceDiagnostics{CheckedAt: ts.now, TenantStatus: ts.tenant, Instance: ts.instance}
	if out.Relays, err = src.Relays(ctx, tenantID); err != nil {
		return InstanceDiagnostics{}, fmt.Errorf("monitoring: diagnostics: relays: %w", err)
	}
	if out.Relays == nil {
		out.Relays = []DiagRelay{}
	}
	out.Edge = edgeOf(out.Relays)
	if out.Policy, err = src.Policy(ctx, tenantID, nil); err != nil {
		return InstanceDiagnostics{}, fmt.Errorf("monitoring: diagnostics: policy: %w", err)
	}
	c, err := s.devices.DeviceCounts(ctx, tenantID)
	if err != nil {
		return InstanceDiagnostics{}, fmt.Errorf("monitoring: diagnostics: devices: %w", err)
	}
	out.Devices = DeviceDiag{Total: c.Total, Online: c.Online, Offline: c.Total - c.Online, Expired: c.Expired, SyncedAt: c.SyncedAt}
	out.Unavailable = []Unavailable{
		{SectionNoise, ReasonNoProbe, "The control connection (Noise, /ts2021) is not probed on its own; the edge " +
			"reachability comes from the relay probe on the same public hostname."},
		{SectionP2PPath, ReasonNotObservable, "The server cannot observe the path between two devices (direct or " +
			"relay); run the checklist on the devices."},
	}
	if c.SyncedAt == nil {
		out.Unavailable = append(out.Unavailable, Unavailable{SectionDevices, ReasonNeverSynced,
			"The device register of the tenant's control plane has never been synced."})
	}
	if !out.Policy.Applied {
		out.Unavailable = append(out.Unavailable, Unavailable{SectionPolicy, ReasonNeverApplied,
			"No policy is recorded as applied to the tenant's instance."})
	}
	if len(out.Relays) == 0 {
		out.Unavailable = append(out.Unavailable, Unavailable{SectionRelay, ReasonNoRelay,
			"The tenant has no relay in the registry."})
	}
	return out, nil
}

// ConnectivityRequest is the body of POST /tenants/{t}/diagnostics/connectivity.
type ConnectivityRequest struct {
	Source         uuid.UUID
	TargetDevice   *uuid.UUID
	TargetResource *uuid.UUID
	Port           int // 0: any port
}

// Check is one control-plane check of a connectivity diagnosis.
type Check struct {
	ID     string
	Status string // pass, fail, warn, unknown, not_applicable
	Reason string
}

// Check identifiers.
const (
	CheckTenantActive      = "tenant_active"
	CheckInstanceHealthy   = "instance_healthy"
	CheckInventoryFresh    = "inventory_fresh"
	CheckSourceOnline      = "source_online"
	CheckSourceNotExpired  = "source_not_expired"
	CheckSourceNotRevoked  = "source_not_revoked"
	CheckTargetOnline      = "target_online"
	CheckTargetNotExpired  = "target_not_expired"
	CheckTargetNotRevoked  = "target_not_revoked"
	CheckRouteApproved     = "route_approved"
	CheckPolicyApplied     = "policy_applied"
	CheckPolicyGrant       = "policy_grant"
	CheckRelayHealthy      = "relay_healthy"
	reasonOffline          = "offline"
	reasonExpired          = "expired"
	reasonRevocation       = "revocation_"
	reasonSuspended        = "tenant_"
	reasonNoRoute          = "no_approved_route"
	reasonRouterOffline    = "router_offline"
	reasonTailnetAddress   = "tailnet_address"
	reasonStaleInventory   = "stale_inventory"
	reasonLatestFailed     = "latest_application_failed"
	reasonUnhealthyRelay   = "relay_unhealthy"
	reasonNoRelayHealth    = "relay_unknown"
	reasonInstanceUnknown  = "instance_unknown"
	reasonInstanceUnhealth = "instance_unhealthy"
)

// Target is the target of a diagnosis.
type Target struct {
	Device   *DiagDevice
	Resource *DiagResource
	Routers  []DiagRouter // routers whose approved routes cover the resource address
}

// ConnectivityReport is the answer of POST /tenants/{t}/diagnostics/connectivity.
type ConnectivityReport struct {
	CheckedAt time.Time
	Source    DiagDevice
	Target    Target
	Port      int
	Verdict   string // allowed, blocked, unknown — from control-plane data only
	Checks    []Check
	Policy    DiagPolicy
	RelayCode string // "" when unknown
	Commands  []Command
}

var (
	tailnet4 = netip.MustParsePrefix("100.64.0.0/10")
	tailnet6 = netip.MustParsePrefix("fd7a:115c:a1e0::/48")
)

func inTailnet(p netip.Prefix) bool {
	return tailnet4.Contains(p.Addr()) || tailnet6.Contains(p.Addr())
}

func isExitRoute(p netip.Prefix) bool { return p.Bits() == 0 }

// Connectivity diagnoses source → target from the control plane's records.
func (s *Service) Connectivity(ctx context.Context, tenantID uuid.UUID, scope DeviceScope, req ConnectivityRequest) (ConnectivityReport, error) {
	src, err := s.source()
	if err != nil {
		return ConnectivityReport{}, err
	}
	switch {
	case req.Source == uuid.Nil:
		return ConnectivityReport{}, &DiagnosticsError{Field: "source_device_id", Reason: "required"}
	case (req.TargetDevice == nil) == (req.TargetResource == nil):
		return ConnectivityReport{}, &DiagnosticsError{Field: "target_device_id", Reason: "exactly_one_target"}
	case req.TargetDevice != nil && *req.TargetDevice == req.Source:
		return ConnectivityReport{}, &DiagnosticsError{Field: "target_device_id", Reason: "same_device"}
	case req.Port < 0 || req.Port > 65535:
		return ConnectivityReport{}, &DiagnosticsError{Field: "port", Reason: "out_of_range"}
	case req.TargetResource != nil && scope.OwnOnly:
		// an own-only caller sees its own devices only — a catalog resource is not one of them (same answer as unknown)
		return ConnectivityReport{}, NotFound(ReasonNotOwnResource)
	}
	ts, err := s.readTenant(ctx, tenantID)
	if err != nil {
		return ConnectivityReport{}, fmt.Errorf("monitoring: diagnostics: connectivity: %w", err)
	}
	out := ConnectivityReport{CheckedAt: ts.now, Port: req.Port}
	if out.Source, err = src.Device(ctx, tenantID, req.Source, scope); err != nil {
		return ConnectivityReport{}, err
	}
	check := &AccessCheck{Src: peerOf(out.Source), Port: req.Port}
	if req.TargetDevice != nil {
		d, err := src.Device(ctx, tenantID, *req.TargetDevice, scope)
		if err != nil {
			return ConnectivityReport{}, err
		}
		out.Target.Device = &d
		p := peerOf(d)
		check.Dst = &p
	} else {
		r, err := src.Resource(ctx, tenantID, *req.TargetResource)
		if err != nil {
			return ConnectivityReport{}, err
		}
		out.Target.Resource = &r
		check.TargetResource, check.ResourceName, check.ResourceAddr = true, r.Name, r.Address
		if !inTailnet(r.Address) {
			routers, err := src.Routers(ctx, tenantID)
			if err != nil {
				return ConnectivityReport{}, fmt.Errorf("monitoring: diagnostics: routers: %w", err)
			}
			for _, rt := range routers {
				if slices.ContainsFunc(rt.Approved, func(p netip.Prefix) bool {
					return !isExitRoute(p) && p.Bits() <= r.Address.Bits() && p.Contains(r.Address.Addr())
				}) {
					out.Target.Routers = append(out.Target.Routers, rt)
					check.RouterTags = append(check.RouterTags, slices.Clone(rt.Tags))
				}
			}
		}
	}
	if out.Target.Routers == nil {
		out.Target.Routers = []DiagRouter{}
	}
	if out.Policy, err = src.Policy(ctx, tenantID, check); err != nil {
		return ConnectivityReport{}, fmt.Errorf("monitoring: diagnostics: policy: %w", err)
	}
	relays, err := src.Relays(ctx, tenantID)
	if err != nil {
		return ConnectivityReport{}, fmt.Errorf("monitoring: diagnostics: relays: %w", err)
	}
	out.Checks = checksOf(ts, out, relays)
	out.Verdict = verdictOf(out.Checks)
	for _, r := range relays {
		if r.Status == "active" {
			out.RelayCode = r.Code
			break
		}
	}
	out.Commands = Checklist(out.Target, out.Port, out.RelayCode)
	return out, nil
}

func peerOf(d DiagDevice) AccessPeer {
	p := AccessPeer{Tags: slices.Clone(d.Tags), Addresses: slices.Clone(d.Addresses)}
	if len(d.Tags) == 0 {
		p.Owner = d.Owner
	}
	return p
}

// checksOf lists the control-plane checks of a diagnosis, in a fixed order.
func checksOf(ts tenantState, r ConnectivityReport, relays []DiagRelay) []Check {
	out := []Check{}
	add := func(id, status, reason string) { out = append(out, Check{ID: id, Status: status, Reason: reason}) }
	if ts.tenant == "active" {
		add(CheckTenantActive, CheckPass, "")
	} else {
		add(CheckTenantActive, CheckFail, reasonSuspended+ts.tenant)
	}
	switch ts.instance.Health.Status {
	case StatusHealthy:
		add(CheckInstanceHealthy, CheckPass, "")
	case StatusUnhealthy: // the data plane may keep working without the control plane for a while
		add(CheckInstanceHealthy, CheckWarn, reasonInstanceUnhealth)
	default:
		add(CheckInstanceHealthy, CheckUnknown, reasonInstanceUnknown)
	}
	oldest := r.Source.SyncedAt
	if r.Target.Device != nil && r.Target.Device.SyncedAt.Before(oldest) {
		oldest = r.Target.Device.SyncedAt
	}
	if ts.now.Sub(oldest) > InventoryStaleAfter {
		add(CheckInventoryFresh, CheckWarn, reasonStaleInventory)
	} else {
		add(CheckInventoryFresh, CheckPass, "")
	}
	deviceChecks(add, ts.now, r.Source, CheckSourceOnline, CheckSourceNotExpired, CheckSourceNotRevoked)
	switch {
	case r.Target.Device != nil:
		deviceChecks(add, ts.now, *r.Target.Device, CheckTargetOnline, CheckTargetNotExpired, CheckTargetNotRevoked)
		add(CheckRouteApproved, CheckNotApplicable, "")
	case r.Target.Resource != nil && inTailnet(r.Target.Resource.Address):
		add(CheckRouteApproved, CheckNotApplicable, reasonTailnetAddress)
	case len(r.Target.Routers) == 0:
		add(CheckRouteApproved, CheckFail, reasonNoRoute)
	case !slices.ContainsFunc(r.Target.Routers, func(rt DiagRouter) bool { return rt.Online }):
		add(CheckRouteApproved, CheckFail, reasonRouterOffline)
	default:
		add(CheckRouteApproved, CheckPass, "")
	}
	switch {
	case !r.Policy.Applied:
		add(CheckPolicyApplied, CheckUnknown, ReasonNeverApplied)
	case r.Policy.LatestState == "failed" && r.Policy.LatestAt != nil && r.Policy.AppliedAt != nil &&
		r.Policy.LatestAt.After(*r.Policy.AppliedAt):
		add(CheckPolicyApplied, CheckWarn, reasonLatestFailed)
	default:
		add(CheckPolicyApplied, CheckPass, "")
	}
	switch a := r.Policy.Access; {
	case a == nil:
		add(CheckPolicyGrant, CheckUnknown, "no_applied_policy")
	case a.Decision == "allowed":
		add(CheckPolicyGrant, CheckPass, "")
	case a.Decision == "denied":
		add(CheckPolicyGrant, CheckFail, a.Reason)
	default:
		add(CheckPolicyGrant, CheckUnknown, a.Reason)
	}
	relay := CheckUnknown
	reason := reasonNoRelayHealth
	for _, rl := range relays {
		if rl.Status != "active" {
			continue
		}
		switch rl.Health {
		case StatusHealthy:
			relay, reason = CheckPass, ""
		case StatusUnhealthy: // a direct path does not need the relay
			relay, reason = CheckWarn, reasonUnhealthyRelay
		}
		break
	}
	add(CheckRelayHealthy, relay, reason)
	return out
}

func deviceChecks(add func(id, status, reason string), now time.Time, d DiagDevice, online, notExpired, notRevoked string) {
	if d.Online {
		add(online, CheckPass, "")
	} else {
		add(online, CheckFail, reasonOffline)
	}
	if d.Expiry != nil && !d.Expiry.After(now) {
		add(notExpired, CheckFail, reasonExpired)
	} else {
		add(notExpired, CheckPass, "")
	}
	switch d.Revocation {
	case "pending", "applied":
		add(notRevoked, CheckFail, reasonRevocation+d.Revocation)
	default:
		add(notRevoked, CheckPass, "")
	}
}

// verdictOf: any failed check ⇒ blocked; otherwise an undecided check that the verdict depends on (the policy's
// answer, whether a policy is applied) ⇒ unknown; otherwise allowed — by the control plane: the path itself is not
// observed (a host firewall, the client's state or a network on the way can still block it).
func verdictOf(checks []Check) string {
	unknown := false
	for _, c := range checks {
		switch {
		case c.Status == CheckFail:
			return VerdictBlocked
		case c.Status == CheckUnknown && (c.ID == CheckPolicyGrant || c.ID == CheckPolicyApplied):
			unknown = true
		}
	}
	if unknown {
		return VerdictUnknown
	}
	return VerdictAllowed
}
