package devices

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/notifications"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// Audit actions and security events of the module.
const (
	ActionRename = "device.rename"
	ActionExpire = "device.expire"
	ActionDelete = "device.delete"
	ActionSync   = "device.sync"
	// ActionClamp is the expiry clamp of inventory.sync (actor system) — §7.4, §13.4.
	ActionClamp = "device.expiry_clamp"

	// SecurityExpiryOverridden: a user-owned node had an expiry empty or beyond registration + node_expiry (HS-19,
	// V-21) — §13.4 "Kẹp hạn node".
	SecurityExpiryOverridden = "expiry_overridden"
	// SecurityRevokedReappeared: a node deleted by a revocation is listed again (restore of an older database).
	SecurityRevokedReappeared = "device.revoked_reappeared"
	// SecuritySource is the source of the module's security events.
	SecuritySource = "devices"

	resourceDevice = "device"
)

// Config are the collaborators and settings of a Service. Registry is required.
type Config struct {
	// Registry is the ONLY way to reach a tenant's Headscale (§13.4): production uses
	// headscale.NewRegistry(<locator of P2-T11>, …).
	Registry headscale.Registry
	Logger   *slog.Logger
	// Registerer exports the module's metrics; nil keeps them unexported.
	Registerer prometheus.Registerer
	// FreshTimeout bounds the sync run by GET …/devices?fresh=true (§13.1); default 10 s.
	FreshTimeout time.Duration
	// Now is the clock of the module's own decisions (pre-auth key expiry); default time.Now. Times written to the
	// database come from the database clock.
	Now func() time.Time
	// ExpiryNotice is how long before a node key expires its device gets the device.expiring notification (P3-T05b),
	// sent after each inventory.sync of the worker; default 7 days, negative = off.
	ExpiryNotice time.Duration
	// Notifier receives the device.expiring events in the transaction that looks for them; default
	// notifications.Default.
	Notifier notifications.Enqueuer
}

// Service is the device inventory of every tenant: API operations, the inventory.sync and device.revoke handlers
// (Register), the schedule of inventory.sync (Scheduler) and the settlement of revocations whose job failed
// (JobAlert).
type Service struct {
	st      *store.Store
	reg     headscale.Registry
	log     *slog.Logger
	m       *metrics
	fresh   time.Duration
	now     func() time.Time
	sysWait time.Duration // bound of the detached writes that settle a job's outcome
	notice  time.Duration
	notify  notifications.Enqueuer
}

// New returns the service of the process whose store is st (api: mg_api_*, worker: mg_worker_*).
func New(st *store.Store, cfg Config) (*Service, error) {
	if st == nil || cfg.Registry == nil {
		return nil, errors.New("devices: a store and a headscale registry are required")
	}
	s := &Service{st: st, reg: cfg.Registry, log: cfg.Logger, m: newMetrics(cfg.Registerer), fresh: cfg.FreshTimeout,
		now: cfg.Now, sysWait: 10 * time.Second, notice: cfg.ExpiryNotice, notify: cfg.Notifier}
	if s.notice == 0 {
		s.notice = 7 * 24 * time.Hour
	}
	if s.notify == nil {
		s.notify = notifications.Default
	}
	if s.log == nil {
		s.log = slog.New(slog.DiscardHandler)
	}
	if s.fresh <= 0 {
		s.fresh = 10 * time.Second
	}
	if s.now == nil {
		s.now = time.Now
	}
	return s, nil
}

// detached returns a context that survives the cancellation of ctx (a request that went away, a job past its
// deadline) for the writes that record an outcome — bounded by sysWait.
func (s *Service) detached(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), s.sysWait)
}

// systemContext is ctx without the request's audit scope: events written with it are the system's (actor_type
// system), not the caller's — the expiry clamp run by a sync that a request triggered.
func systemContext(ctx context.Context) context.Context { return audit.WithRequest(ctx, nil) }

// List returns one page of the tenant's devices (GET /tenants/{t}/devices). Fresh runs a bounded sync first and
// answers page 1; Fresh with a cursor is refused (§13.1: the Headscale list has no pages).
func (s *Service) List(ctx context.Context, tenantID uuid.UUID, a Access, q ListQuery) (Page, error) {
	if q.Limit == 0 {
		q.Limit = DefaultLimit
	}
	switch {
	case q.Limit < 1 || q.Limit > MaxLimit:
		return Page{}, invalid("limit", "limit must be between 1 and 200")
	case q.Fresh && q.Cursor != "":
		return Page{}, invalid("fresh", "fresh=true answers the first page: it cannot be combined with a cursor")
	case q.Tag != "" && !tagRE.MatchString(q.Tag):
		return Page{}, invalid("tag", "tag must look like tag:<name>")
	case q.Search != "" && (len([]rune(q.Search)) > 64):
		return Page{}, invalid("q", "q must be at most 64 characters")
	}
	bind := binding(tenantID, a, q)
	p := sqlcdb.ListDevicesPageParams{TenantID: tenantID, Owner: q.Owner, Online: q.Online, Tagged: q.Tagged,
		HasExpiry: q.HasExpiry, RowLimit: int32(q.Limit + 1)} //nolint:gosec // 1–201
	if a.OwnOnly {
		m := a.MembershipID
		p.OwnMembership = &m
	}
	if q.Tag != "" {
		p.Tag = &q.Tag
	}
	if q.Search != "" {
		p.Search = &q.Search
	}
	if q.Cursor != "" {
		c, ok := decodeCursor(q.Cursor, bind)
		if !ok {
			return Page{}, invalid("cursor", "the cursor is invalid for this list")
		}
		p.AfterSeen, p.AfterID = &c.seen, &c.id
	}
	if q.Fresh {
		if err := s.freshSync(ctx, tenantID); err != nil {
			return Page{}, err
		}
	}
	var rows []sqlcdb.ListDevicesPageRow
	if err := s.st.WithTenantTx(ctx, tenantID, func(qq *sqlcdb.Queries) error {
		var err error
		rows, err = qq.ListDevicesPage(ctx, p)
		return err
	}); err != nil {
		return Page{}, fmt.Errorf("devices: list: %w", err)
	}
	page := Page{Items: make([]Device, 0, min(len(rows), q.Limit))}
	for i, r := range rows {
		if i == q.Limit {
			last := rows[i-1].DeviceInventoryCache
			page.NextCursor = encodeCursor(cursor{seen: last.FirstSeenAt, id: last.ID}, bind)
			break
		}
		page.Items = append(page.Items, deviceOf(r.DeviceInventoryCache, r.OwnerDisplay))
	}
	return page, nil
}

// freshSync runs one sync of the tenant's live instance, bounded by FreshTimeout.
func (s *Service) freshSync(ctx context.Context, tenantID uuid.UUID) error {
	instance, err := s.liveInstance(ctx, tenantID)
	if err != nil {
		return err
	}
	sctx, cancel := context.WithTimeout(ctx, s.fresh)
	defer cancel()
	if _, err := s.Sync(sctx, tenantID, instance); err != nil {
		return fromAdapter(err)
	}
	return nil
}

// liveInstance returns the ID of the tenant's instance that is not removed (MVP: at most one — §6.3).
func (s *Service) liveInstance(ctx context.Context, tenantID uuid.UUID) (uuid.UUID, error) {
	var id uuid.UUID
	err := s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		inst, err := q.GetLiveInstanceForTenant(ctx, tenantID)
		id = inst.ID
		return err
	})
	if errors.Is(err, store.ErrNoRows) {
		return uuid.Nil, unavailable(ReasonNoInstance, err)
	}
	if err != nil {
		return uuid.Nil, fmt.Errorf("devices: live instance: %w", err)
	}
	return id, nil
}

// Get returns one device (GET /tenants/{t}/devices/{id}).
func (s *Service) Get(ctx context.Context, tenantID, deviceID uuid.UUID, a Access) (Device, error) {
	var d Device
	err := s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		var err error
		d, err = s.loadVisible(ctx, q, tenantID, deviceID, a)
		return err
	})
	return d, err
}

// loadVisible reads a live device the access covers.
func (s *Service) loadVisible(ctx context.Context, q *sqlcdb.Queries, tenantID, deviceID uuid.UUID, a Access) (Device, error) {
	r, err := q.GetLiveDevice(ctx, sqlcdb.GetLiveDeviceParams{TenantID: tenantID, ID: deviceID})
	if errors.Is(err, store.ErrNoRows) {
		return Device{}, notFound(ReasonNoDevice)
	}
	if err != nil {
		return Device{}, fmt.Errorf("devices: get: %w", err)
	}
	if !a.owns(r.DeviceInventoryCache) {
		return Device{}, notFound(ReasonNotOwnResource)
	}
	return deviceOf(r.DeviceInventoryCache, r.OwnerDisplay), nil
}

// Rename changes the given name of a device (PATCH /tenants/{t}/devices/{id}): the name is checked locally as a DNS
// label (§13.4), device.rename.requested commits before Headscale is called, the node's identity (node id + machine
// key) is checked, RenameNode runs, and the cache and device.rename.succeeded commit together; any failure after the
// request closes the pair with device.rename.failed.
func (s *Service) Rename(ctx context.Context, tenantID, deviceID uuid.UUID, a Access, givenName string) (Device, error) {
	if err := headscale.ValidateGivenName(givenName); err != nil {
		return Device{}, invalid("given_name", "given_name must be a DNS label: lowercase letters, digits and hyphens, at most 63 characters")
	}
	var (
		row sqlcdb.DeviceInventoryCache
		op  audit.Operation
	)
	err := s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		r, err := q.LockLiveDevice(ctx, sqlcdb.LockLiveDeviceParams{TenantID: tenantID, ID: deviceID})
		if errors.Is(err, store.ErrNoRows) {
			return notFound(ReasonNoDevice)
		}
		if err != nil {
			return err
		}
		if !a.owns(r) {
			return notFound(ReasonNotOwnResource)
		}
		row = r
		op, err = audit.Requested(ctx, q, audit.Event{Action: ActionRename, TenantID: &tenantID, ResourceType: resourceDevice,
			ResourceID: deviceID.String(), Details: audit.Details{"given_name": givenName, "previous": deref(r.GivenName),
				"node_id": r.HeadscaleNodeID}})
		return err
	})
	if err != nil {
		return Device{}, err
	}
	fail := func(err error) (Device, error) {
		e := fromAdapter(err)
		s.closeFailed(ctx, tenantID, &op, e.Code)
		return Device{}, e
	}
	inst, err := s.reg.ForTenant(ctx, tenantID)
	if err != nil {
		return fail(err)
	}
	nodeID := uint64(row.HeadscaleNodeID) //nolint:gosec // CHECK headscale_node_id > 0
	node, err := inst.GetNode(ctx, nodeID)
	switch {
	case isGone(err) || err == nil && node.MachineKey != row.MachineKey:
		return fail(notFound(ReasonNodeGone))
	case err != nil:
		return fail(err)
	}
	renamed, err := inst.RenameNode(ctx, nodeID, givenName)
	if err != nil {
		if e := fromAdapter(err); e.Code == CodeValidationFailed {
			e.Field = "given_name"
			return fail(e)
		}
		return fail(err)
	}
	if renamed.GivenName != givenName || renamed.MachineKey != row.MachineKey {
		return fail(&Error{Code: CodeUpstreamRejected, Reason: ReasonReadbackMismatch,
			Detail: "the tenant's control plane did not apply the new name"})
	}
	var d Device
	err = s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		if err := q.SetDeviceGivenName(ctx, sqlcdb.SetDeviceGivenNameParams{GivenName: &givenName, TenantID: tenantID, ID: deviceID}); err != nil {
			return err
		}
		if err := op.Succeeded(ctx, q, audit.Details{"given_name": givenName}); err != nil {
			return err
		}
		r, err := q.GetLiveDevice(ctx, sqlcdb.GetLiveDeviceParams{TenantID: tenantID, ID: deviceID})
		if errors.Is(err, store.ErrNoRows) { // a sync removed it meanwhile: the rename happened, report it
			d = deviceOf(row, "")
			d.GivenName = givenName
			return nil
		}
		d = deviceOf(r.DeviceInventoryCache, r.OwnerDisplay)
		return err
	})
	if err != nil {
		s.closeFailed(ctx, tenantID, &op, "cache_update_failed")
		return Device{}, fmt.Errorf("devices: rename: record: %w", err)
	}
	return d, nil
}

// closeFailed writes "<action>.failed" for op in a transaction of its own (detached from the request), unless the
// pair is already complete. When it cannot, the audit middleware of the request closes the pair (P2-T08).
func (s *Service) closeFailed(ctx context.Context, tenantID uuid.UUID, op *audit.Operation, reason string) {
	if op == nil || op.ID == uuid.Nil {
		return
	}
	if reason == "" {
		reason = "failed"
	}
	wctx, cancel := s.detached(ctx)
	defer cancel()
	err := s.st.WithTenantTx(wctx, tenantID, func(q *sqlcdb.Queries) error {
		st, err := q.OperationState(wctx, op.ID)
		if err != nil || !st.Requested || st.Finished {
			return err
		}
		return op.Failed(wctx, q, reason, nil)
	})
	if err != nil {
		s.log.ErrorContext(ctx, "devices: closing an audit operation failed", "operation_id", op.ID, "action", op.Action,
			"sqlstate", store.SQLState(err))
	}
}

// Summary is the device part of the tenant dashboard (P2-T13a): counts of the register and the last applied sync of
// the live instance (nil: never synced) — no number without its synced_at (§12.3).
type Summary struct {
	Total    int
	Online   int
	SyncedAt *time.Time
}

// Summary returns the dashboard figures of the tenant's devices.
func (s *Service) Summary(ctx context.Context, tenantID uuid.UUID) (Summary, error) {
	var out Summary
	err := s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		c, err := q.CountDevices(ctx, tenantID)
		if err != nil {
			return err
		}
		out.Total, out.Online = int(c.Total), int(c.Online)
		inst, err := q.GetLiveInstanceForTenant(ctx, tenantID)
		if errors.Is(err, store.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		st, err := q.GetDeviceSyncState(ctx, sqlcdb.GetDeviceSyncStateParams{TenantID: tenantID, InstanceID: inst.ID})
		if errors.Is(err, store.ErrNoRows) {
			return nil
		}
		out.SyncedAt = st.SyncedAt
		return err
	})
	if err != nil {
		return Summary{}, fmt.Errorf("devices: summary: %w", err)
	}
	return out, nil
}
