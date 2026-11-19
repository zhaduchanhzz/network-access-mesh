package network

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/config"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// Subnet routes and exit nodes (§12.3, §13.2 "routes", PL-10 double opt-in, T-08).

// Audit actions (x-audit-action) and the tenant approval action of a route approval under routes.four_eyes.
const (
	ActionRouteApprove = "route.approve"
	ActionRouteRevoke  = "route.revoke"
	// RouteApprovalAction is approval_requests.action of a route approval when the tenant turned routes.four_eyes on
	// (§8.6: the approver holds tenant.approval:decide and tenant.route:approve, is not the requester, stepped up).
	RouteApprovalAction = "tenant.route.approve"

	approveRoutesOperation = "approveTenantRoutes"
	resourceDevice         = "device"
	MaxRoutePrefixes       = 64
	maxWarnings            = 50
)

// Warning codes of the routes (§12.3 "cảnh báo chồng lấn", T-08).
const (
	WarnOverlap        = "overlap"         // a prefix overlaps a prefix of another device
	WarnUntaggedRouter = "untagged_router" // a router that is not a tagged node (it belongs to a user — T-08 convention)
	WarnExitNode       = "exit_node"       // the device advertises or is approved as an exit node
)

var (
	exit4 = netip.MustParsePrefix("0.0.0.0/0")
	exit6 = netip.MustParsePrefix("::/0")
)

// RouteWarning is one warning of a device's routes.
type RouteWarning struct {
	Code          string
	Prefix        string     // overlap: the device's prefix
	OtherDeviceID *uuid.UUID // overlap: the other device
	OtherPrefix   string     // overlap: the other device's prefix
}

// RouteDevice is the routes of one device (schema RouteDevice).
type RouteDevice struct {
	DeviceID       uuid.UUID
	Name           string
	GivenName      string
	Tags           []string
	Online         bool
	Advertised     []netip.Prefix // announced by the client
	Approved       []netip.Prefix
	Pending        []netip.Prefix // advertised, not approved
	ExitAdvertised bool
	ExitApproved   bool
	ETag           string // routes_etag: hash of the approved set — If-Match of approve/revoke
	SyncedAt       time.Time
	Warnings       []RouteWarning
}

// RoutesETag is the entity tag of an approved route set (order and duplicates do not matter) — the same value as the
// device's routes.etag (devices: hash of the set's canonical strings).
func RoutesETag(prefixes []netip.Prefix) string {
	s := make([]string, 0, len(prefixes))
	for _, p := range prefixes {
		s = append(s, p.String())
	}
	slices.Sort(s)
	s = slices.Compact(s)
	sum := sha256.Sum256([]byte(strings.Join(s, "\n")))
	return `"` + hex.EncodeToString(sum[:16]) + `"`
}

func sortedPrefixes(in []netip.Prefix) []netip.Prefix {
	out := slices.Clone(in)
	slices.SortFunc(out, netip.Prefix.Compare)
	out = slices.Compact(out)
	if out == nil {
		out = []netip.Prefix{}
	}
	return out
}

func hasExit(ps []netip.Prefix) bool { return slices.Contains(ps, exit4) || slices.Contains(ps, exit6) }

// routeDeviceOf builds the routes of one register row (warnings added by withWarnings).
func routeDeviceOf(r sqlcdb.DeviceInventoryCache) RouteDevice {
	adv, appr := sortedPrefixes(r.AvailableRoutes), sortedPrefixes(r.ApprovedRoutes)
	d := RouteDevice{DeviceID: r.ID, Tags: slices.Clone(r.Tags), Online: r.Online, Advertised: adv, Approved: appr,
		Pending: []netip.Prefix{}, ExitAdvertised: hasExit(adv), ExitApproved: hasExit(appr), ETag: RoutesETag(appr),
		SyncedAt: r.LastSyncedAt.UTC(), Warnings: []RouteWarning{}}
	if r.Name != nil {
		d.Name = *r.Name
	}
	if r.GivenName != nil {
		d.GivenName = *r.GivenName
	}
	if d.Tags == nil {
		d.Tags = []string{}
	}
	for _, p := range adv {
		if !slices.Contains(appr, p) {
			d.Pending = append(d.Pending, p)
		}
	}
	return d
}

func (d RouteDevice) isRouter() bool { return len(d.Advertised) > 0 || len(d.Approved) > 0 }

// subnetRoutes are the device's advertised or approved prefixes other than the exit routes.
func (d RouteDevice) subnetRoutes() []netip.Prefix {
	var out []netip.Prefix
	for _, p := range append(slices.Clone(d.Advertised), d.Approved...) {
		if !isExit(p) && !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	return out
}

// withWarnings adds the warnings of d against the other routers.
func withWarnings(d RouteDevice, all []RouteDevice) RouteDevice {
	w := []RouteWarning{}
	if len(d.Tags) == 0 {
		w = append(w, RouteWarning{Code: WarnUntaggedRouter})
	}
	if d.ExitAdvertised || d.ExitApproved {
		w = append(w, RouteWarning{Code: WarnExitNode})
	}
	mine := d.subnetRoutes()
	for _, o := range all {
		if o.DeviceID == d.DeviceID {
			continue
		}
		for _, p := range mine {
			for _, r := range o.subnetRoutes() {
				if p.Overlaps(r) && len(w) < maxWarnings {
					id := o.DeviceID
					w = append(w, RouteWarning{Code: WarnOverlap, Prefix: p.String(), OtherDeviceID: &id, OtherPrefix: r.String()})
				}
			}
		}
	}
	d.Warnings = w
	return d
}

func (s *Service) devices() (DeviceRegister, error) {
	if s.cfg.Devices == nil {
		return nil, &Error{Code: CodeInternal, Reason: ReasonNotWired, Err: errors.New("network: no device register wired")}
	}
	return s.cfg.Devices, nil
}

// routers reads the routers of the tenant (devices that advertise or have approved routes) with their warnings.
func (s *Service) routers(ctx context.Context, q *sqlcdb.Queries, reg DeviceRegister, tenantID uuid.UUID) ([]RouteDevice, error) {
	rows, err := reg.ListLive(ctx, q, tenantID)
	if err != nil {
		return nil, err
	}
	var all []RouteDevice
	for _, r := range rows {
		if d := routeDeviceOf(r); d.isRouter() {
			all = append(all, d)
		}
	}
	out := make([]RouteDevice, 0, len(all))
	for _, d := range all {
		out = append(out, withWarnings(d, all))
	}
	return out, nil
}

// ListRoutes is GET /tenants/{t}/routes: the routers of the register (cache of inventory.sync — each with its
// synced_at), advertised vs approved, the exit node and the warnings.
func (s *Service) ListRoutes(ctx context.Context, tenantID uuid.UUID) ([]RouteDevice, error) {
	reg, err := s.devices()
	if err != nil {
		return nil, err
	}
	var out []RouteDevice
	err = s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		var err error
		out, err = s.routers(ctx, q, reg, tenantID)
		return err
	})
	return out, err
}

// RouteChangeInput is the body of POST /routes/approve and /routes/revoke.
type RouteChangeInput struct {
	DeviceID        uuid.UUID
	Prefixes        []string
	ConfirmExitNode bool // approve: required when the prefixes name the exit node
}

// normalizeRoutePrefixes parses canonical prefixes (no host bits), 1..MaxRoutePrefixes; an exit route stands for both
// families (PL-10: approving either approves both — the platform always writes both).
func normalizeRoutePrefixes(in []string) ([]netip.Prefix, bool, error) {
	if len(in) < 1 || len(in) > MaxRoutePrefixes {
		return nil, false, invalid("prefixes", "invalid_count", fmt.Sprintf("between 1 and %d prefixes", MaxRoutePrefixes))
	}
	var out []netip.Prefix
	exit := false
	for _, s := range in {
		p, err := netip.ParsePrefix(strings.TrimSpace(s))
		if err != nil || p.Addr().Zone() != "" || p.Addr().Is4In6() {
			return nil, false, invalid("prefixes", "invalid_prefix", "prefixes are IPv4 or IPv6 prefixes such as 10.0.0.0/24")
		}
		if p.Masked() != p {
			return nil, false, invalid("prefixes", "prefix_not_canonical", "a prefix must have no host bits set (e.g. 10.0.0.0/24)")
		}
		if isExit(p) {
			exit = true
			out = append(out, exit4, exit6)
			continue
		}
		out = append(out, p)
	}
	return sortedPrefixes(out), exit, nil
}

// RouteApprovalPayload is the payload of an approval request tenant.route.approve: what the second person approves and
// the only input of the execution — the prefixes to add, the approved set it leads to and the ETag of the approved set
// the request was made on (the execution refuses when the device's routes changed since).
type RouteApprovalPayload struct {
	DeviceID uuid.UUID `json:"device_id"`
	Prefixes []string  `json:"prefixes"`
	Approved []string  `json:"approved"`
	IfMatch  string    `json:"if_match"`
	ExitNode bool      `json:"exit_node"`
}

// Validate implements approvals.Validator (shape only — the device's state is checked again at execution).
func (p RouteApprovalPayload) Validate() error {
	if p.DeviceID == uuid.Nil || p.IfMatch == "" || len(p.IfMatch) > 64 {
		return errors.New("route approval payload: device_id and if_match are required")
	}
	add, exit, err := normalizeRoutePrefixes(p.Prefixes)
	if err != nil {
		return err
	}
	if exit != p.ExitNode || len(add) != len(p.Prefixes) {
		return errors.New("route approval payload: prefixes must be canonical, sorted, the exit node as both families")
	}
	for i, q := range add {
		if q.String() != p.Prefixes[i] {
			return errors.New("route approval payload: prefixes must be canonical and sorted")
		}
	}
	for _, s := range p.Approved {
		if _, err := netip.ParsePrefix(s); err != nil {
			return errors.New("route approval payload: approved holds prefixes")
		}
	}
	return nil
}

// RouteResult is the answer to POST /routes/approve: the device's routes after the change (Device), or — under
// routes.four_eyes — the payload of the approval request the caller must make (Approval set, nothing changed).
type RouteResult struct {
	Device   *RouteDevice
	Approval *RouteApprovalPayload
}

// routeChange is one change of a device's approved set.
type routeChange struct {
	approve  bool           // approve (add) or revoke (remove)
	prefixes []netip.Prefix // to add or to remove
	exit     bool
}

func (c routeChange) action() string {
	if c.approve {
		return ActionRouteApprove
	}
	return ActionRouteRevoke
}

// headscaleRoutes reads the device's node DIRECTLY from Headscale (never the cache) and checks its identity: the node
// must still exist with the register's machine key.
func (s *Service) headscaleRoutes(ctx context.Context, tenantID uuid.UUID, row sqlcdb.DeviceInventoryCache) (headscale.Instance, headscale.Node, error) {
	if s.cfg.Registry == nil {
		return nil, headscale.Node{}, &Error{Code: CodeInternal, Reason: ReasonNotWired, Err: errors.New("network: no Headscale registry wired")}
	}
	inst, err := s.cfg.Registry.ForTenant(ctx, tenantID)
	if err != nil {
		return nil, headscale.Node{}, fromAdapter(err)
	}
	node, err := inst.GetNode(ctx, uint64(row.HeadscaleNodeID)) //nolint:gosec // CHECK headscale_node_id > 0
	switch {
	case errors.Is(err, headscale.ErrNotFound) || err == nil && node.MachineKey != row.MachineKey:
		return nil, headscale.Node{}, notFound(ReasonNodeGone)
	case err != nil:
		return nil, headscale.Node{}, fromAdapter(err)
	}
	return inst, node, nil
}

// plan checks a change against the node Headscale reports now and returns the new approved set: If-Match must be the
// hash of the approved set NOW (412); an approval only takes advertised prefixes (422 route_not_advertised), a
// revocation only approved ones (422 route_not_approved).
func plan(node headscale.Node, ifMatch string, c routeChange) ([]netip.Prefix, error) {
	cur := sortedPrefixes(node.ApprovedRoutes)
	if RoutesETag(cur) != ifMatch {
		return nil, stale(ReasonStaleRoutes, "The device's approved routes changed since they were read; read them again.")
	}
	adv := sortedPrefixes(node.AvailableRoutes)
	next := slices.Clone(cur)
	var missing []string
	for _, p := range c.prefixes {
		switch {
		case c.approve && !slices.Contains(adv, p):
			missing = append(missing, p.String())
		case c.approve:
			next = append(next, p)
		case !slices.Contains(cur, p):
			missing = append(missing, p.String())
		default:
			next = slices.DeleteFunc(next, func(x netip.Prefix) bool { return x == p })
		}
	}
	if len(missing) > 0 {
		if c.approve {
			return nil, invalid("prefixes", "route_not_advertised",
				"the device does not advertise these prefixes now: "+strings.Join(missing, ", "))
		}
		return nil, invalid("prefixes", "route_not_approved", "these prefixes are not approved on the device: "+strings.Join(missing, ", "))
	}
	return sortedPrefixes(next), nil
}

// readTenantFourEyes reads TenantSettings.routes.four_eyes.
func readTenantFourEyes(ctx context.Context, q *sqlcdb.Queries, tenantID uuid.UUID) (bool, error) {
	r, err := q.GetTenantSettingsRow(ctx, tenantID)
	if err != nil {
		return false, err
	}
	d, err := config.ParseSettingsDoc(r.Settings)
	if err != nil {
		return true, nil //nolint:nilerr // an unreadable document: the stricter reading (a second person)
	}
	return d.View().Routes.FourEyes, nil
}

// ApproveRoutes is POST /tenants/{t}/routes/approve (If-Match = the device's routes_etag; Idempotency-Key). Under
// routes.four_eyes nothing changes: after the same checks (advertised now, If-Match current) the result carries the
// payload of the tenant approval request (202). Otherwise the read–check–write runs under the device's row lock.
func (s *Service) ApproveRoutes(ctx context.Context, tenantID uuid.UUID, a Actor, ifMatch string, in RouteChangeInput, idem *Idempotency) (RouteResult, error) {
	add, exit, err := normalizeRoutePrefixes(in.Prefixes)
	if err != nil {
		return RouteResult{}, err
	}
	if exit && !in.ConfirmExitNode {
		return RouteResult{}, invalid("confirm_exit_node", "exit_node_confirmation_required",
			"approving an exit node (0.0.0.0/0 and ::/0) routes the clients' Internet traffic through the device: set confirm_exit_node")
	}
	match := normalizeIfMatch(ifMatch)
	if match == "" {
		return RouteResult{}, ifMatchRequired("device's routes_etag")
	}
	reg, err := s.devices()
	if err != nil {
		return RouteResult{}, err
	}
	c := routeChange{approve: true, prefixes: add, exit: exit}
	var (
		row      sqlcdb.DeviceInventoryCache
		fourEyes bool
	)
	err = s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		r, err := reg.LockLive(ctx, q, tenantID, in.DeviceID)
		if errors.Is(err, store.ErrNoRows) {
			return notFound(ReasonNoDevice)
		}
		if err != nil {
			return err
		}
		row = r
		fourEyes, err = readTenantFourEyes(ctx, q, tenantID)
		return err
	})
	if err != nil {
		return RouteResult{}, err
	}
	if fourEyes {
		_, node, err := s.headscaleRoutes(ctx, tenantID, row)
		if err != nil {
			return RouteResult{}, err
		}
		next, err := plan(node, match, c)
		if err != nil {
			return RouteResult{}, err
		}
		p := &RouteApprovalPayload{DeviceID: in.DeviceID, Prefixes: prefixStrings(add), Approved: prefixStrings(next),
			IfMatch: match, ExitNode: exit}
		return RouteResult{Approval: p}, nil
	}
	var key *jobsKey
	if idem != nil {
		key = s.newKey(tenantID, a, idem)
		var stored storedRoutes
		replayed, err := s.beginIdempotent(ctx, tenantID, key.k, key.hash, &stored)
		if err != nil {
			return RouteResult{}, err
		}
		if replayed {
			d, err := s.routeDevice(ctx, tenantID, stored.DeviceID)
			if err != nil {
				return RouteResult{}, err
			}
			return RouteResult{Device: &d}, nil
		}
	}
	d, err := s.changeRoutes(ctx, tenantID, a, in.DeviceID, match, c, key)
	if err != nil {
		if key != nil {
			s.failIdempotent(ctx, tenantID, key.k, key.hash)
		}
		return RouteResult{}, err
	}
	return RouteResult{Device: &d}, nil
}

// RevokeRoutes is POST /tenants/{t}/routes/revoke (If-Match): approved prefixes removed (the exit node: both
// families). A revocation narrows access: it never waits for a second person.
func (s *Service) RevokeRoutes(ctx context.Context, tenantID uuid.UUID, a Actor, ifMatch string, in RouteChangeInput) (RouteDevice, error) {
	remove, exit, err := normalizeRoutePrefixes(in.Prefixes)
	if err != nil {
		return RouteDevice{}, err
	}
	match := normalizeIfMatch(ifMatch)
	if match == "" {
		return RouteDevice{}, ifMatchRequired("device's routes_etag")
	}
	return s.changeRoutes(ctx, tenantID, a, in.DeviceID, match, routeChange{prefixes: remove, exit: exit}, nil)
}

func prefixStrings(ps []netip.Prefix) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, p.String())
	}
	return out
}

// storedRoutes is the replay body of an approval (the device's routes are read again).
type storedRoutes struct {
	DeviceID uuid.UUID `json:"device_id"`
}

// routeDevice reads one device's routes with its warnings.
func (s *Service) routeDevice(ctx context.Context, tenantID, deviceID uuid.UUID) (RouteDevice, error) {
	reg, err := s.devices()
	if err != nil {
		return RouteDevice{}, err
	}
	var out RouteDevice
	err = s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		var err error
		out, err = s.routeDeviceTx(ctx, q, reg, tenantID, deviceID)
		return err
	})
	return out, err
}

func (s *Service) routeDeviceTx(ctx context.Context, q *sqlcdb.Queries, reg DeviceRegister, tenantID, deviceID uuid.UUID) (RouteDevice, error) {
	rows, err := reg.ListLive(ctx, q, tenantID)
	if err != nil {
		return RouteDevice{}, err
	}
	var all []RouteDevice
	var mine *RouteDevice
	for _, r := range rows {
		d := routeDeviceOf(r)
		if d.isRouter() {
			all = append(all, d)
		}
		if r.ID == deviceID {
			mine = &d
		}
	}
	if mine == nil {
		return RouteDevice{}, notFound(ReasonNoDevice)
	}
	return withWarnings(*mine, all), nil
}

// changeRoutes is the read–check–write of PL-10 on one device: route.<action>.requested commits first (the device must
// exist and If-Match be present); then, in ONE transaction holding the device row FOR UPDATE — a concurrent change of
// the same device waits for it —, the node is read directly from Headscale, If-Match checked against its approved set
// (412), the new set computed and written with SetApprovedRoutes (it replaces the whole set), the read-back compared
// with the new set, the register updated and route.<action>.succeeded written. A failure after the requested event
// writes route.<action>.failed.
func (s *Service) changeRoutes(ctx context.Context, tenantID uuid.UUID, a Actor, deviceID uuid.UUID, match string, c routeChange, key *jobsKey) (RouteDevice, error) {
	reg, err := s.devices()
	if err != nil {
		return RouteDevice{}, err
	}
	var op audit.Operation
	err = s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		r, err := reg.LockLive(ctx, q, tenantID, deviceID)
		if errors.Is(err, store.ErrNoRows) {
			return notFound(ReasonNoDevice)
		}
		if err != nil {
			return err
		}
		if match == "" {
			return ifMatchRequired("device's routes_etag")
		}
		t := tenantID
		op, err = audit.Requested(ctx, q, audit.Event{Action: c.action(), TenantID: &t, ResourceType: resourceDevice,
			ResourceID: deviceID.String(), Details: audit.Details{"prefixes": prefixStrings(c.prefixes), "exit_node": c.exit,
				"approved_before": prefixStrings(r.ApprovedRoutes), "node_id": r.HeadscaleNodeID, "tagged": len(r.Tags) > 0}})
		return err
	})
	if err != nil {
		return RouteDevice{}, err
	}
	var out RouteDevice
	err = s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		d, details, err := s.applyRoutes(ctx, q, reg, tenantID, deviceID, match, c)
		if err != nil {
			return err
		}
		if err := op.Succeeded(ctx, q, details); err != nil {
			return err
		}
		out = d
		if key != nil {
			return completeIdempotent(ctx, q, key.k, key.hash, 200, storedRoutes{DeviceID: deviceID},
				nil)
		}
		return nil
	})
	if err != nil {
		reason := "internal"
		if e, ok := AsError(err); ok {
			reason = e.Reason
		}
		if ferr := s.st.WithTenantTx(context.WithoutCancel(ctx), tenantID, func(q *sqlcdb.Queries) error {
			return op.Failed(ctx, q, reason, audit.Details{})
		}); ferr != nil {
			s.log.WarnContext(ctx, "network: route operation not closed", "operation_id", op.ID, "error", ferr.Error())
		}
		return RouteDevice{}, err
	}
	return out, nil
}

// applyRoutes is the locked part of changeRoutes (q: the transaction that holds the row until it commits).
func (s *Service) applyRoutes(ctx context.Context, q *sqlcdb.Queries, reg DeviceRegister, tenantID, deviceID uuid.UUID, match string,
	c routeChange) (RouteDevice, audit.Details, error) {
	row, err := reg.LockLive(ctx, q, tenantID, deviceID)
	if errors.Is(err, store.ErrNoRows) {
		return RouteDevice{}, nil, notFound(ReasonNoDevice)
	}
	if err != nil {
		return RouteDevice{}, nil, err
	}
	inst, node, err := s.headscaleRoutes(ctx, tenantID, row)
	if err != nil {
		return RouteDevice{}, nil, err
	}
	next, err := plan(node, match, c)
	if err != nil {
		return RouteDevice{}, nil, err
	}
	cur := sortedPrefixes(node.ApprovedRoutes)
	approved, advertised := cur, sortedPrefixes(node.AvailableRoutes)
	if !slices.Equal(next, cur) {
		set, err := inst.SetApprovedRoutes(ctx, node.ID, next)
		if err != nil {
			return RouteDevice{}, nil, fromAdapter(err)
		}
		got := sortedPrefixes(set.ApprovedRoutes)
		if !slices.Equal(got, next) || set.MachineKey != row.MachineKey {
			return RouteDevice{}, nil, &Error{Code: CodeUpstreamRejected, Reason: ReasonReadbackMismatch,
				Detail: "the tenant's control plane did not apply the new routes"}
		}
		approved, advertised = got, sortedPrefixes(set.AvailableRoutes)
	}
	if err := reg.RecordRoutes(ctx, q, tenantID, deviceID, approved, advertised); err != nil {
		return RouteDevice{}, nil, err
	}
	d, err := s.routeDeviceTx(ctx, q, reg, tenantID, deviceID)
	if err != nil {
		return RouteDevice{}, nil, err
	}
	details := audit.Details{"approved": prefixStrings(approved), "advertised": prefixStrings(advertised),
		"changed": !slices.Equal(next, cur), "routes_etag": d.ETag}
	for _, w := range d.Warnings {
		switch w.Code {
		case WarnUntaggedRouter:
			details["untagged_router"] = true
		case WarnOverlap:
			details["overlap"] = true
		}
	}
	return d, details, nil
}

// jobsKey is a held Idempotency-Key of an approval.
type jobsKey struct {
	k    idemKey
	hash []byte
}

func (s *Service) newKey(tenantID uuid.UUID, a Actor, idem *Idempotency) *jobsKey {
	t := tenantID
	return &jobsKey{k: idemKey{TenantID: &t, IdentityID: a.IdentityID, OperationID: approveRoutesOperation, Key: idem.Key},
		hash: idem.Hash}
}

// ExecuteRouteApproval runs an approved tenant.route.approve request (the executor of P3-T04a, registered by apps/) in
// the approval's transaction tx: the device row is locked, the node read directly from Headscale, and the exact
// approved change applied only while the device's approved set still has the ETag the request was made on (otherwise
// nothing changes and the request stays approved). The approved prefixes must still be advertised. No job.
func (s *Service) ExecuteRouteApproval(ctx context.Context, tx *store.Tx, tenantID, approvalID uuid.UUID, resourceID string,
	requestedBy uuid.UUID, p RouteApprovalPayload) (*uuid.UUID, error) {
	if resourceID != p.DeviceID.String() {
		return nil, errors.New("network: route approval: the payload names another device than the request")
	}
	add, exit, err := normalizeRoutePrefixes(p.Prefixes)
	if err != nil {
		return nil, err
	}
	reg, err := s.devices()
	if err != nil {
		return nil, err
	}
	c := routeChange{approve: true, prefixes: add, exit: exit}
	t := tenantID
	op, err := audit.Requested(ctx, tx.Q, audit.Event{Action: ActionRouteApprove, TenantID: &t, ResourceType: resourceDevice,
		ResourceID: p.DeviceID.String(), Details: audit.Details{"prefixes": p.Prefixes, "exit_node": exit,
			"approval_id": approvalID, "requested_by_identity_id": requestedBy}})
	if err != nil {
		return nil, err
	}
	_, details, err := s.applyRoutes(ctx, tx.Q, reg, tenantID, p.DeviceID, p.IfMatch, c)
	if err != nil {
		return nil, err
	}
	details["approval_id"] = approvalID
	return nil, op.Succeeded(ctx, tx.Q, details)
}
