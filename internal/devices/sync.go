package devices

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// Job kinds of the module (§13.5).
const (
	KindSync   = "inventory.sync"
	KindRevoke = "device.revoke"
)

// SlotAPI is the dedupe slot of the syncs asked through POST …/devices/sync: a request while one is queued or running
// returns that job (§13.2).
const SlotAPI = "api"

// expiryWindow is how close a read-back expiry must be to the time sent (Headscale stores the time it was given).
const expiryWindow = time.Second

// SyncReport describes one sync (the output of an inventory.sync job).
type SyncReport struct {
	Generation  int64     `json:"generation"`
	SyncedAt    time.Time `json:"synced_at"`
	Nodes       int       `json:"nodes"`
	Inserted    int       `json:"inserted"`
	Updated     int       `json:"updated"`
	Removed     int       `json:"removed"`
	Reused      int       `json:"reused"` // node id handed out again to another machine key: old row removed, new row
	Clamped     int       `json:"clamped"`
	ClampFailed int       `json:"clamp_failed"`
	// ClampSkipped counts candidates left alone when the clamp looked again: the node is gone or already within the
	// limit or expired, or the device's revocation is pending (a clamp only ever shortens an expiry — T-17).
	ClampSkipped int `json:"clamp_skipped"`
	// ExpiryNotices counts the device.expiring notifications written after the sync (inventory.sync job only).
	ExpiryNotices int `json:"expiry_notices,omitempty"`
	// ClampLimit is node_expiry in hours (0: no limit known or never expires) and ClampSource where it came from
	// (tenant_settings, instance_config, none).
	ClampLimitHours float64 `json:"clamp_limit_hours"`
	ClampSource     string  `json:"clamp_source"`
	// Stale: a newer snapshot had already been applied; nothing was written.
	Stale bool `json:"stale"`
	// SettledRevocations counts pending revocations settled failed because their job had ended.
	SettledRevocations int `json:"settled_revocations"`
}

// Clamp sources.
const (
	ClampSourceTenant   = "tenant_settings"
	ClampSourceInstance = "instance_config"
	ClampSourceNone     = "none"
)

// clampCandidate is a user-owned node whose expiry exceeds the limit (§13.4).
type clampCandidate struct {
	deviceID   uuid.UUID
	nodeID     uint64
	machineKey string
	observed   *time.Time
	target     time.Time
}

// Sync brings the register of one instance in step with its Headscale (see the package documentation for the
// algorithm). It returns an error when the instance cannot be listed; failures of single clamps are counted in the
// report.
func (s *Service) Sync(ctx context.Context, tenantID, instanceID uuid.UUID) (SyncReport, error) {
	var (
		t0     time.Time
		limit  time.Duration
		source string
		owners map[string]uuid.UUID
	)
	err := s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		inst, err := q.GetLiveInstanceForTenant(ctx, tenantID)
		if errors.Is(err, store.ErrNoRows) {
			return unavailable(ReasonNoInstance, err)
		}
		if err != nil {
			return err
		}
		if inst.ID != instanceID {
			return &Error{Code: CodeConflict, Reason: "instance_changed",
				Detail: "the tenant's instance changed since the sync was requested"}
		}
		lim, err := q.GetDevicesNodeExpiry(ctx, sqlcdb.GetDevicesNodeExpiryParams{TenantID: tenantID, InstanceID: instanceID})
		if err != nil {
			return err
		}
		limit, source = s.nodeExpiry(ctx, lim)
		names, err := q.ListDeviceOwnerNames(ctx, tenantID)
		if err != nil {
			return err
		}
		owners = make(map[string]uuid.UUID, len(names))
		for _, n := range names {
			owners[n.HeadscaleUsername] = n.ID
		}
		t0, err = q.DevicesSnapshotTime(ctx)
		return err
	})
	if err != nil {
		s.m.syncs.WithLabelValues("failed").Inc()
		return SyncReport{}, err
	}
	inst, err := s.reg.ForTenant(ctx, tenantID)
	if err != nil {
		s.m.syncs.WithLabelValues("failed").Inc()
		return SyncReport{}, err
	}
	nodes, err := inst.ListNodes(ctx, "")
	if err != nil {
		s.m.syncs.WithLabelValues("failed").Inc()
		return SyncReport{}, err
	}
	rep := SyncReport{SyncedAt: t0.UTC(), Nodes: len(nodes), ClampLimitHours: limit.Hours(), ClampSource: source}
	clamps, reappeared, err := s.apply(ctx, tenantID, instanceID, t0, nodes, owners, limit, &rep)
	if err != nil {
		s.m.syncs.WithLabelValues("failed").Inc()
		return SyncReport{}, fmt.Errorf("devices: sync apply: %w", err)
	}
	if rep.Stale {
		s.m.syncs.WithLabelValues("stale").Inc()
		return rep, nil
	}
	s.m.syncs.WithLabelValues("applied").Inc()
	for _, r := range reappeared {
		s.raise(ctx, tenantID, r)
	}
	for _, c := range clamps {
		switch s.clamp(ctx, tenantID, inst, c, limit, source) {
		case clampDone:
			rep.Clamped++
		case clampFailed:
			rep.ClampFailed++
		default:
			rep.ClampSkipped++
		}
	}
	n, err := s.settleOrphans(ctx, tenantID, nil)
	if err != nil {
		s.log.ErrorContext(ctx, "devices: settling orphaned revocations failed", "tenant_id", tenantID, "error", err)
	}
	rep.SettledRevocations = n
	return rep, nil
}

// nodeExpiry resolves the clamp limit: TenantSettings.node_expiry, else node.expiry of the instance's rendered
// configuration; none known (or 0 = never) ⇒ no clamp.
func (s *Service) nodeExpiry(ctx context.Context, r sqlcdb.GetDevicesNodeExpiryRow) (time.Duration, string) {
	for _, c := range []struct{ raw, source string }{{r.TenantNodeExpiry, ClampSourceTenant}, {r.InstanceNodeExpiry, ClampSourceInstance}} {
		if c.raw == "" {
			continue
		}
		d, err := ParseNodeExpiry(c.raw)
		if err != nil {
			s.log.WarnContext(ctx, "devices: invalid node_expiry ignored", "source", c.source, "error", err)
			continue
		}
		return d, c.source
	}
	return 0, ClampSourceNone
}

// ParseNodeExpiry parses a node_expiry setting: a Go duration in whole hours as rendered for Headscale ("2160h"),
// or a number of days ("90d"); "0", "0s", "0h" mean "never expires" (no clamp).
func ParseNodeExpiry(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if days, ok := strings.CutSuffix(s, "d"); ok {
		n, err := strconv.Atoi(days)
		if err != nil || n < 0 || n > 36500 {
			return 0, fmt.Errorf("node_expiry %q: not a number of days", s)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	if s == "0" {
		return 0, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d < 0 || d > 100*365*24*time.Hour {
		return 0, fmt.Errorf("node_expiry %q: not a duration", s)
	}
	return d, nil
}

// reappearance is a node deleted by an applied revocation that the instance lists again.
type reappearance struct {
	oldDevice, newDevice uuid.UUID
	nodeID               int64
}

// apply writes one snapshot in a single transaction (step 3 of the package documentation) and returns the clamp
// candidates and the revoked nodes that reappeared.
func (s *Service) apply(ctx context.Context, tenantID, instanceID uuid.UUID, t0 time.Time, nodes []headscale.Node,
	owners map[string]uuid.UUID, limit time.Duration, rep *SyncReport,
) ([]clampCandidate, []reappearance, error) {
	var (
		clamps     []clampCandidate
		reappeared []reappearance
	)
	err := s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		if err := q.EnsureDeviceSyncState(ctx, sqlcdb.EnsureDeviceSyncStateParams{InstanceID: instanceID, TenantID: tenantID}); err != nil {
			return err
		}
		state, err := q.LockDeviceSyncState(ctx, sqlcdb.LockDeviceSyncStateParams{TenantID: tenantID, InstanceID: instanceID})
		if err != nil {
			return err
		}
		if state.SyncedAt != nil && !state.SyncedAt.Before(t0) {
			rep.Stale, rep.Generation = true, state.Generation
			return nil
		}
		gen := state.Generation + 1
		rep.Generation = gen
		live, err := q.LockLiveDevicesOfInstance(ctx, sqlcdb.LockLiveDevicesOfInstanceParams{TenantID: tenantID, InstanceID: instanceID})
		if err != nil {
			return err
		}
		byNode := make(map[int64]sqlcdb.DeviceInventoryCache, len(live))
		for _, r := range live {
			byNode[r.HeadscaleNodeID] = r
		}
		seen := make(map[int64]bool, len(nodes))
		for _, n := range nodes {
			if n.ID == 0 || n.ID > uint64(1<<63-1) || n.MachineKey == "" {
				continue // never written: the CHECK of 0005 and the identity rule need both
			}
			id := int64(n.ID)
			seen[id] = true
			c := normalise(n, owners)
			old, isLive := byNode[id]
			if isLive && old.MachineKey == n.MachineKey {
				p := c.update(tenantID, old.ID, t0, gen)
				predates := snapshotPredatesRevocation(old, t0)
				if predates {
					p.Expiry = old.Expiry // the revocation's read-back is newer than this snapshot's expiry
				}
				if err := q.UpdateSyncedDevice(ctx, p); err != nil {
					return err
				}
				rep.Updated++
				if cand, ok := clampOf(n, old.ID, t0, limit, false); ok && !predates {
					clamps = append(clamps, cand)
				}
				continue
			}
			// revoked: a device of this exact node that an applied revocation deleted.
			revoked := uuid.Nil
			if isLive {
				// §6.3: same node id, another machine key ⇒ the old device is gone, this is a new one.
				if err := q.MarkDeviceRemoved(ctx, sqlcdb.MarkDeviceRemovedParams{RemovedAt: &t0, SyncGeneration: gen,
					TenantID: tenantID, ID: old.ID}); err != nil {
					return err
				}
				rep.Reused++
				rep.Removed++
			} else {
				prev, err := q.LatestDeviceOfNode(ctx, sqlcdb.LatestDeviceOfNodeParams{TenantID: tenantID, InstanceID: instanceID,
					HeadscaleNodeID: id, MachineKey: n.MachineKey})
				switch {
				case errors.Is(err, store.ErrNoRows):
				case err != nil:
					return err
				case prev.RemovedAt != nil && !prev.RemovedAt.Before(t0):
					continue // removed after this snapshot was taken: the snapshot is older than the removal
				case prev.RevocationState == StateApplied && deref(prev.RevocationKind) == RevokeDelete:
					revoked = prev.ID
				}
			}
			row, err := q.InsertSyncedDevice(ctx, c.insert(tenantID, instanceID, id, n.MachineKey, t0, gen))
			if err != nil {
				return err
			}
			rep.Inserted++
			if revoked != uuid.Nil {
				reappeared = append(reappeared, reappearance{oldDevice: revoked, newDevice: row.ID, nodeID: id})
			}
			if cand, ok := clampOf(n, row.ID, t0, limit, true); ok {
				clamps = append(clamps, cand)
			}
		}
		for _, r := range live {
			if seen[r.HeadscaleNodeID] {
				continue
			}
			if err := q.MarkDeviceRemoved(ctx, sqlcdb.MarkDeviceRemovedParams{RemovedAt: &t0, SyncGeneration: gen,
				TenantID: tenantID, ID: r.ID}); err != nil {
				return err
			}
			rep.Removed++
		}
		return q.RecordDeviceSync(ctx, sqlcdb.RecordDeviceSyncParams{Generation: gen, SyncedAt: &t0,
			NodeCount: int32(min(len(nodes), 1<<31-1)), TenantID: tenantID, InstanceID: instanceID}) //nolint:gosec // bounded
	})
	return clamps, reappeared, err
}

// snapshotPredatesRevocation reports whether a snapshot taken at t0 may be older than the revocation of device r: one
// is pending (its job owns the node's expiry until it settles), or one was settled applied at or after t0 (its
// read-back may be newer than what ListNodes reported). Such a snapshot neither writes the cached expiry nor yields an
// expiry-clamp candidate. Both times come from the database clock: verified_at is the start of the settling
// transaction, which begins after the read-back, so verified_at < t0 means the node was listed after the revocation.
func snapshotPredatesRevocation(r sqlcdb.DeviceInventoryCache, t0 time.Time) bool {
	return r.RevocationState == StatePending || r.RevocationVerifiedAt != nil && !r.RevocationVerifiedAt.Before(t0)
}

// columns are the cache columns of a node, normalised from ListNodes (§13.4 "Đọc node").
type columns struct {
	nodeKey, name, givenName, method *string
	userID                           *int64
	setOwner                         bool
	owner                            *uuid.UUID
	n                                headscale.Node
}

func normalise(n headscale.Node, owners map[string]uuid.UUID) columns {
	c := columns{n: n, nodeKey: nonEmpty(n.NodeKey), name: nonEmpty(n.Name), givenName: nonEmpty(n.GivenName),
		method: nonEmpty(string(n.RegisterMethod))}
	if !n.IsTagged() && n.User != nil && n.User.Name != headscale.TaggedDevicesUser {
		// A user-owned node: Headscale's user is the truth; mg-<membership_uuid> names the membership (§6.3). A user
		// the platform did not create (no membership) leaves the owner empty.
		c.setOwner = true
		if id, ok := owners[n.User.Name]; ok {
			c.owner = &id
		}
		if n.User.ID > 0 && n.User.ID <= 1<<63-1 {
			c.userID = ptr(int64(n.User.ID))
		}
	}
	return c
}

func nonEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func (c columns) update(tenantID, id uuid.UUID, t0 time.Time, gen int64) sqlcdb.UpdateSyncedDeviceParams {
	n := c.n
	return sqlcdb.UpdateSyncedDeviceParams{
		NodeKey: c.nodeKey, Name: c.name, GivenName: c.givenName, IpAddresses: nonNil(n.IPAddresses),
		HeadscaleUserID: c.userID, SetOwner: c.setOwner, OwnerMembershipID: c.owner, Tags: nonNil(n.Tags),
		RegisterMethod: c.method, Online: n.Online, LastSeen: n.LastSeen, Expiry: n.Expiry,
		ApprovedRoutes: nonNil(n.ApprovedRoutes), AvailableRoutes: nonNil(n.AvailableRoutes), SubnetRoutes: nonNil(n.SubnetRoutes),
		HsCreatedAt: timeOrNil(n.CreatedAt), SyncedAt: t0, SyncGeneration: gen, TenantID: tenantID, ID: id,
	}
}

func (c columns) insert(tenantID, instanceID uuid.UUID, nodeID int64, machineKey string, t0 time.Time, gen int64) sqlcdb.InsertSyncedDeviceParams {
	n := c.n
	return sqlcdb.InsertSyncedDeviceParams{
		TenantID: tenantID, InstanceID: instanceID, HeadscaleNodeID: nodeID, MachineKey: machineKey,
		NodeKey: c.nodeKey, Name: c.name, GivenName: c.givenName, IpAddresses: nonNil(n.IPAddresses),
		HeadscaleUserID: c.userID, OwnerMembershipID: c.owner, Tags: nonNil(n.Tags), RegisterMethod: c.method,
		Online: n.Online, LastSeen: n.LastSeen, Expiry: n.Expiry, ApprovedRoutes: nonNil(n.ApprovedRoutes),
		AvailableRoutes: nonNil(n.AvailableRoutes), SubnetRoutes: nonNil(n.SubnetRoutes), HsCreatedAt: timeOrNil(n.CreatedAt),
		SyncedAt: t0, SyncGeneration: gen,
	}
}

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

func timeOrNil(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

// clampOf applies the rule of §13.4 to one node. The registration time Headscale does not report after a re-auth
// (created_at never changes), so: a node seen for the first time, registered less than node_expiry ago, is measured
// from its created_at (strict — this is the client-requested expiry of V-21 right after registration); any other
// node from the snapshot time (lenient — a legitimate re-auth sets now + node_expiry and is never clamped, an override
// is still cut to at most now + node_expiry).
func clampOf(n headscale.Node, deviceID uuid.UUID, t0 time.Time, limit time.Duration, firstSeen bool) (clampCandidate, bool) {
	if limit <= 0 {
		return clampCandidate{}, false
	}
	registered := t0
	if firstSeen && !n.CreatedAt.IsZero() && n.CreatedAt.Add(limit).After(t0) {
		registered = n.CreatedAt
	}
	target, need := headscale.ExpiryClamp(n, registered, limit)
	if !need {
		return clampCandidate{}, false
	}
	return clampCandidate{deviceID: deviceID, nodeID: n.ID, machineKey: n.MachineKey, observed: n.Expiry, target: target}, true
}

// clampResult is what one clamp candidate came to.
type clampResult int

const (
	clampSkipped clampResult = iota // nothing to shorten any more, or a revocation owns the node's expiry: no call, no audit
	clampDone                       // expired at the target and read back
	clampFailed                     // refused, not read back, or superseded by a revocation started meanwhile
)

// ReasonRevocationStarted: a revocation of the device started while its expiry clamp was in flight; the clamp is
// recorded failed and the revocation's own expiry is applied again.
const ReasonRevocationStarted = "revocation_started"

// clamp expires one node at the clamp target and records the audit pair and the security event (§13.4). A clamp only
// ever shortens the expiry of a device no revocation is working on (T-17):
//
//  1. the device is read under its row lock: removed or a revocation pending ⇒ skipped. The revocation job is
//     remembered, and the database clock is "now";
//  2. the node is read again (GetNode: expiry, tags and machine key, never written to the register): only the same
//     machine's user-owned node that never expires, or expires after the target and not yet, is clamped — the
//     snapshot of the sync may predate a revocation, an operator's expire, a tag or a node id handed out again;
//  3. device.expiry_clamp.requested commits, then ExpireNode(target);
//  4. a revocation started since step 1 (another revocation job on the row) may have expired the node before this
//     write landed: no transaction is held across a Headscale call (§13.5 d), so instead its explicit expiry
//     (requested_at, §13.4 rule 3) is applied again before the outcome is recorded. The clamp is then .failed with
//     reason revocation_started, and a security event of severity high is raised if applying it again failed.
func (s *Service) clamp(ctx context.Context, tenantID uuid.UUID, inst headscale.Instance, c clampCandidate,
	limit time.Duration, source string,
) clampResult {
	sctx := systemContext(ctx)
	var (
		now  time.Time
		job  *uuid.UUID // revocation job of the device at step 1
		skip bool
	)
	err := s.st.WithTenantTx(sctx, tenantID, func(q *sqlcdb.Queries) error {
		row, err := q.LockLiveDevice(sctx, sqlcdb.LockLiveDeviceParams{TenantID: tenantID, ID: c.deviceID})
		if errors.Is(err, store.ErrNoRows) || err == nil && row.RevocationState == StatePending {
			skip = true
			return nil
		}
		if err != nil {
			return err
		}
		job = row.RevocationJobID
		now, err = q.DevicesSnapshotTime(sctx)
		return err
	})
	if err != nil {
		s.log.ErrorContext(ctx, "devices: expiry clamp not started (device)", "device_id", c.deviceID, "sqlstate", store.SQLState(err))
		s.m.clamps.WithLabelValues("failed").Inc()
		return clampFailed
	}
	if skip {
		s.m.clamps.WithLabelValues("skipped").Inc()
		return clampSkipped
	}
	current, err := inst.GetNode(ctx, c.nodeID)
	if isGone(err) || err == nil && (current.MachineKey != c.machineKey || !shortens(current, c.target, now)) {
		s.m.clamps.WithLabelValues("skipped").Inc()
		return clampSkipped
	}
	readErr := err // the instance did not answer: recorded as a failed clamp like a refused ExpireNode

	observed := "never"
	if c.observed != nil {
		observed = c.observed.UTC().Format(time.RFC3339)
	}
	details := audit.Details{"node_id": c.nodeID, "observed_expiry": observed,
		"clamped_to": c.target.UTC().Format(time.RFC3339), "limit_hours": limit.Hours(), "limit_source": source}
	var op audit.Operation
	err = s.st.WithTenantTx(sctx, tenantID, func(q *sqlcdb.Queries) error {
		var err error
		op, err = audit.Requested(sctx, q, audit.Event{Action: ActionClamp, ActorType: audit.ActorSystem, TenantID: &tenantID,
			ResourceType: resourceDevice, ResourceID: c.deviceID.String(), Details: details})
		return err
	})
	if err != nil {
		s.log.ErrorContext(ctx, "devices: expiry clamp not started (audit)", "device_id", c.deviceID, "sqlstate", store.SQLState(err))
		s.m.clamps.WithLabelValues("failed").Inc()
		return clampFailed
	}
	var node headscale.Node
	err = readErr
	target := c.target
	if readErr == nil {
		node, err = inst.ExpireNode(ctx, c.nodeID, &target)
	}
	ok := err == nil && node.MachineKey == c.machineKey && node.Expiry != nil && absDuration(node.Expiry.Sub(target)) <= expiryWindow
	reason := ""
	switch {
	case err != nil:
		reason = fromAdapter(err).Reason
	case !ok:
		reason = ReasonReadbackMismatch
	}
	wctx, cancel := s.detached(sctx)
	defer cancel()
	superseded, reapplied := false, (*bool)(nil)
	if readErr == nil { // ExpireNode was sent: it may have landed even when it failed
		superseded, reapplied = s.reapplyRevocation(ctx, wctx, tenantID, inst, c, job)
	}
	if superseded {
		ok, reason = false, ReasonRevocationStarted
	}
	err = s.st.WithTenantTx(wctx, tenantID, func(q *sqlcdb.Queries) error {
		outcome := audit.Details{}
		if reapplied != nil {
			outcome["revocation_reapplied"] = *reapplied
		}
		if ok {
			if err := q.SetDeviceExpiry(wctx, sqlcdb.SetDeviceExpiryParams{Expiry: node.Expiry, TenantID: tenantID, ID: c.deviceID}); err != nil {
				return err
			}
			if err := op.Succeeded(wctx, q, audit.Details{"expiry": node.Expiry.UTC().Format(time.RFC3339)}); err != nil {
				return err
			}
		} else if err := op.Failed(wctx, q, reason, outcome); err != nil {
			return err
		}
		ev := details
		ev["device_id"] = c.deviceID.String()
		ev["clamped"] = ok
		severity := audit.SeverityMedium
		if reapplied != nil {
			ev["revocation_reapplied"] = *reapplied
			if !*reapplied {
				severity = audit.SeverityHigh // the revocation may no longer hold
			}
		}
		_, err := audit.RecordSecurityEvent(wctx, q, audit.SecurityEvent{TenantID: &tenantID, Kind: SecurityExpiryOverridden,
			Severity: severity, Source: SecuritySource, Details: ev,
			DedupeKey: "expiry_overridden:" + c.deviceID.String() + ":" + observed + ":" + strconv.FormatBool(ok), DedupeWindow: 24 * time.Hour})
		return err
	})
	if err != nil {
		s.log.ErrorContext(ctx, "devices: recording an expiry clamp failed", "device_id", c.deviceID, "sqlstate", store.SQLState(err))
	}
	if ok {
		s.m.clamps.WithLabelValues("clamped").Inc()
		s.log.WarnContext(ctx, "devices: node expiry clamped", "tenant_id", tenantID, "device_id", c.deviceID,
			"node_id", c.nodeID, "observed_expiry", observed, "clamped_to", c.target.UTC())
		return clampDone
	}
	s.m.clamps.WithLabelValues("failed").Inc()
	s.log.ErrorContext(ctx, "devices: node expiry clamp failed", "tenant_id", tenantID, "device_id", c.deviceID,
		"node_id", c.nodeID, "reason", reason, "alert", reapplied != nil && !*reapplied)
	return clampFailed
}

// shortens reports whether ExpireNode(target) can only bring the expiry of node n earlier: a user-owned node that never
// expires, or that expires later than target (beyond the slack of the clamp rule) and is not expired at now. A node
// already expired — by a revocation, by an operator — is never touched, and a clamp never extends an expiry.
func shortens(n headscale.Node, target, now time.Time) bool {
	if n.IsTagged() {
		return false
	}
	if n.Expiry == nil {
		return true
	}
	return n.Expiry.After(now) && n.Expiry.After(target.Add(headscale.ExpiryClampSlack))
}

// reapplyRevocation is step 4 of clamp: once the clamp's ExpireNode was sent, it reads the device again and reports
// whether a revocation started since step 1 (its job is no longer job); for one of kind expire it calls
// ExpireNode(requested_at) again and reports whether the answer shows it (nil when nothing had to be applied). A
// delete needs nothing: the node is gone or will be.
func (s *Service) reapplyRevocation(ctx, wctx context.Context, tenantID uuid.UUID, inst headscale.Instance,
	c clampCandidate, job *uuid.UUID,
) (bool, *bool) {
	var row sqlcdb.DeviceInventoryCache
	err := s.st.WithTenantTx(wctx, tenantID, func(q *sqlcdb.Queries) error {
		var err error
		row, err = q.LockDevice(wctx, sqlcdb.LockDeviceParams{TenantID: tenantID, ID: c.deviceID})
		return err
	})
	if err != nil {
		s.log.ErrorContext(ctx, "devices: expiry clamp could not re-read the device", "alert", true, "device_id", c.deviceID,
			"sqlstate", store.SQLState(err))
		return false, nil
	}
	if sameID(row.RevocationJobID, job) {
		return false, nil
	}
	if deref(row.RevocationKind) != RevokeExpire || row.RevocationRequestedAt == nil {
		return true, nil
	}
	at := *row.RevocationRequestedAt
	back, err := inst.ExpireNode(wctx, c.nodeID, &at)
	done := isGone(err) || err == nil && (back.MachineKey != c.machineKey || back.Expiry != nil && !back.Expiry.After(at.Add(expiryWindow)))
	return true, &done
}

func sameID(a, b *uuid.UUID) bool {
	return a == nil && b == nil || a != nil && b != nil && *a == *b
}

func absDuration(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

// raise records the reappearance of a node a revocation had deleted (restore of an older database, §17.2).
func (s *Service) raise(ctx context.Context, tenantID uuid.UUID, r reappearance) {
	wctx, cancel := s.detached(ctx)
	defer cancel()
	err := s.st.WithTenantTx(wctx, tenantID, func(q *sqlcdb.Queries) error {
		_, err := audit.RecordSecurityEvent(wctx, q, audit.SecurityEvent{TenantID: &tenantID, Kind: SecurityRevokedReappeared,
			Severity: audit.SeverityHigh, Source: SecuritySource,
			Details:   audit.Details{"revoked_device_id": r.oldDevice.String(), "device_id": r.newDevice.String(), "node_id": r.nodeID},
			DedupeKey: "revoked_reappeared:" + r.oldDevice.String(), DedupeWindow: 24 * time.Hour})
		return err
	})
	if err != nil {
		s.log.ErrorContext(ctx, "devices: recording a reappeared revoked node failed", "sqlstate", store.SQLState(err))
	}
	s.log.WarnContext(ctx, "devices: a node deleted by a revocation is listed again", "tenant_id", tenantID,
		"revoked_device_id", r.oldDevice, "device_id", r.newDevice, "node_id", r.nodeID)
}

// syncInput is the input of an inventory.sync job: the audit operation of the request that asked for it (nil for
// the schedule).
type syncInput struct {
	Operation *audit.Operation `json:"operation,omitempty"`
}

// RequestSync enqueues an inventory.sync of the tenant's live instance (POST /tenants/{t}/devices/sync): the request
// is audited device.sync.requested and handed off to the job, which closes the pair. While a requested sync is queued
// or running, the same job is returned; a replayed Idempotency-Key returns its job.
func (s *Service) RequestSync(ctx context.Context, tenantID uuid.UUID, a Access, requestKey string) (jobs.Job, error) {
	var (
		job    jobs.Job
		op     audit.Operation
		reused bool
	)
	errReused := errors.New("devices: existing sync job")
	err := s.st.WithTenantJobTx(ctx, tenantID, func(tx *store.Tx) error {
		inst, err := tx.Q.GetLiveInstanceForTenant(ctx, tenantID)
		if errors.Is(err, store.ErrNoRows) {
			return unavailable(ReasonNoInstance, err)
		}
		if err != nil {
			return err
		}
		op, err = audit.Requested(ctx, tx.Q, audit.Event{Action: ActionSync, TenantID: &tenantID, ResourceType: resourceDevice})
		if err != nil {
			return err
		}
		enq, err := jobs.Enqueue(ctx, tx, jobs.Spec{Kind: KindSync, TenantID: &tenantID, InstanceID: &inst.ID, Slot: SlotAPI,
			Input: syncInput{Operation: &op}, RequestKey: requestKey, RequestedBy: a.requestedBy()})
		switch {
		case errors.Is(err, jobs.ErrRequestKeyReuse) && enq.Job.ID != uuid.Nil && enq.Job.Kind == KindSync:
			job, reused = enq.Job, true // the same request again (its input differs only by the new operation id)
			return errReused
		case errors.Is(err, jobs.ErrRequestKeyReuse):
			return &Error{Code: CodeIdempotencyKeyReuse, Reason: "idempotency_key_reuse", Err: err,
				Detail: "The Idempotency-Key was used for another request."}
		case err != nil:
			return err
		case !enq.Created:
			job, reused = enq.Job, true
			return errReused
		}
		job = enq.Job
		return nil
	})
	if reused && errors.Is(err, errReused) {
		return job, nil
	}
	if err != nil {
		if e, ok := AsError(err); ok {
			return jobs.Job{}, e
		}
		return jobs.Job{}, fmt.Errorf("devices: request sync: %w", err)
	}
	audit.HandOff(ctx, op)
	return job, nil
}

// runSync is the handler of inventory.sync: level-triggered, it syncs the job's instance as it is now.
func (s *Service) runSync(ctx context.Context, run *jobs.Run) error {
	var in syncInput
	if err := run.DecodeInput(&in); err != nil {
		return jobs.Permanent("invalid_input", err)
	}
	if run.TenantID == nil || run.InstanceID == nil {
		return jobs.Permanent("invalid_input", errors.New("inventory.sync needs a tenant and an instance"))
	}
	tenantID := *run.TenantID
	rep, err := s.Sync(ctx, tenantID, *run.InstanceID)
	if err != nil {
		e := fromAdapter(err)
		final := !transient(err) || run.Attempt >= run.MaxAttempts
		if final {
			s.closeFailed(ctx, tenantID, in.Operation, e.Code)
		}
		if !transient(err) {
			return jobs.Permanent(codeOf(e), err)
		}
		return jobs.Transient(codeOf(e), err)
	}
	// device.expiring (P3-T05b): best effort — a failure is logged, never a reason to retry the sync.
	if n, err := s.notifyExpiring(ctx, tenantID, *run.InstanceID); err != nil {
		s.log.ErrorContext(ctx, "devices: expiry notifications not written", "tenant_id", tenantID, "sqlstate",
			store.SQLState(err), "error", err.Error())
	} else {
		rep.ExpiryNotices = n
	}
	if err := run.SetOutput(rep); err != nil {
		return jobs.Permanent("invalid_output", err)
	}
	if in.Operation != nil {
		wctx, cancel := s.detached(ctx)
		defer cancel()
		if err := s.st.WithTenantTx(wctx, tenantID, func(q *sqlcdb.Queries) error {
			return in.Operation.Succeeded(wctx, q, audit.Details{"generation": rep.Generation, "nodes": rep.Nodes,
				"inserted": rep.Inserted, "removed": rep.Removed, "clamped": rep.Clamped, "stale": rep.Stale})
		}); err != nil {
			return jobs.Transient("audit_write_failed", err)
		}
	}
	return nil
}

// codeOf is the job error code of a failure (CHECK ^[a-z][a-z0-9_]{0,63}$ of provisioning_jobs.error).
func codeOf(e *Error) string {
	if e == nil {
		return jobs.CodeHandlerError
	}
	return e.Code
}
