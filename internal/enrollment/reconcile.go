package enrollment

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/notifications"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// Failure codes written by reconcile.
const (
	FailureIssueUnfinished = "issue_unfinished" // a key issuance never recorded its key (process died)
	FailureKeyMissing      = "key_missing"      // the issued key is gone from Headscale
	FailureNodeGone        = "node_gone"        // the key was used but its node no longer exists
)

// ReconcileReport is the output of one enrollment.reconcile job.
type ReconcileReport struct {
	Open     int   `json:"open"`
	Expired  int   `json:"expired"`
	Consumed int   `json:"consumed"`
	Failed   int   `json:"failed"`
	Linked   int64 `json:"linked"`
	Skipped  int   `json:"skipped"` // issued keys left for the next run: the instance did not answer
	// NewDevices counts the devices of pre-auth keys that entered the inventory (or got their link) in this run, each
	// notified once (device.new).
	NewDevices int `json:"new_devices"`
}

// reusableGrace is how long after its expiry a consumed reusable key is still looked at: a node it registered before
// expiring may reach the next run late (the schedule runs every 2 minutes).
const reusableGrace = 30 * time.Minute

// Register registers the handler of enrollment.reconcile on the worker.
func (s *Service) Register(w *jobs.Worker) error {
	return w.Register(KindReconcile, jobs.HandlerFunc(s.runReconcile))
}

func (s *Service) runReconcile(ctx context.Context, run *jobs.Run) error {
	if run.TenantID == nil {
		return jobs.Permanent("invalid_input", errors.New("enrollment.reconcile: no tenant"))
	}
	rep, err := s.Reconcile(ctx, *run.TenantID)
	if oerr := run.SetOutput(rep); oerr != nil && err == nil {
		err = oerr
	}
	if err != nil {
		return jobs.Transient("reconcile_failed", err)
	}
	return nil
}

// Reconcile converges the open enrollment requests of a tenant (§13.5 enrollment.reconcile): expired decisions, codes
// and keys ⇒ expired; used keys ⇒ consumed with their node; unfinished issuances and claims ⇒ failed; device rows of
// consumed/verified requests get their enrollment link. The nodes a pre-auth key registered enter the inventory with
// that link and are notified once (device.new — adoptKeyNodes): at the consumed transition, then for a reusable key
// while it is live (and reusableGrace after). Headscale is asked only when an issued or live reusable key is open; when
// it does not answer, the keys wait for the next run and the error is returned (the job retries).
func (s *Service) Reconcile(ctx context.Context, tenantID uuid.UUID) (ReconcileReport, error) {
	var (
		rep      ReconcileReport
		open     []sqlcdb.EnrollmentRequest
		reusable []sqlcdb.EnrollmentRequest
	)
	now := s.now()
	if err := s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		var err error
		if open, err = q.ListOpenEnrollmentRequests(ctx, tenantID); err != nil {
			return err
		}
		reusable, err = q.ListLiveReusableEnrollmentKeys(ctx, sqlcdb.ListLiveReusableEnrollmentKeysParams{
			TenantID: tenantID, ExpiredAfter: now.Add(-reusableGrace)})
		return err
	}); err != nil {
		return rep, err
	}
	rep.Open = len(open)
	var (
		keys   map[uint64]headscale.PreAuthKey
		nodes  map[uint64][]headscale.Node // by pre-auth key id, first registered first
		hsErr  error
		loaded bool
	)
	loadHS := func() {
		if loaded {
			return
		}
		loaded = true
		inst, err := s.reg.ForTenant(ctx, tenantID)
		if err != nil {
			hsErr = err
			return
		}
		ks, err := inst.ListPreAuthKeys(ctx)
		if err != nil {
			hsErr = err
			return
		}
		ns, err := inst.ListNodes(ctx, "")
		if err != nil {
			hsErr = err
			return
		}
		keys, nodes = map[uint64]headscale.PreAuthKey{}, map[uint64][]headscale.Node{}
		for _, k := range ks {
			keys[k.ID] = k
		}
		for _, n := range ns {
			if n.PreAuthKeyID != 0 {
				nodes[n.PreAuthKeyID] = append(nodes[n.PreAuthKeyID], n)
			}
		}
		for _, list := range nodes {
			slices.SortFunc(list, func(a, b headscale.Node) int { // the first node the key registered first
				if c := a.CreatedAt.Compare(b.CreatedAt); c != 0 {
					return c
				}
				return cmp.Compare(a.ID, b.ID)
			})
		}
	}
	for _, r := range open {
		out := outcome{}
		switch r.Status {
		case StatusRequested:
			if now.Sub(r.CreatedAt) > stuckAfter {
				out = outcome{status: StatusFailed, failure: FailureIssueUnfinished}
			}
		case StatusPendingApproval:
			if now.Sub(r.CreatedAt) >= DecisionWindow {
				out = outcome{status: StatusExpired}
			}
		case StatusApproved:
			since := r.CreatedAt
			if r.ApprovedAt != nil {
				since = *r.ApprovedAt
			}
			if now.Sub(since) >= DecisionWindow {
				out = outcome{status: StatusExpired}
			}
		case StatusAwaitingDevice:
			if r.CredentialExpiresAt != nil && !now.Before(*r.CredentialExpiresAt) {
				out = outcome{status: StatusExpired}
			}
		case StatusClaimed, StatusRegistered:
			if r.ClaimedAt == nil || now.Sub(*r.ClaimedAt) > stuckAfter {
				out = outcome{status: StatusFailed, failure: FailureClaimUnfinished}
			}
		case StatusCredentialIssued:
			loadHS()
			if hsErr != nil {
				rep.Skipped++
				continue
			}
			out = s.keyOutcome(r, keys, nodes, now)
		}
		if out.status == "" {
			continue
		}
		adopted, err := s.settle(ctx, tenantID, r, out)
		if err != nil {
			return rep, err
		}
		rep.NewDevices += adopted
		switch out.status {
		case StatusExpired:
			rep.Expired++
		case StatusConsumed:
			rep.Consumed++
		case StatusFailed:
			rep.Failed++
		}
	}
	// a live reusable key may register more nodes after its consumed transition: each one enters the inventory once
	for _, r := range reusable {
		loadHS()
		if hsErr != nil {
			rep.Skipped++
			continue
		}
		kid := uint64(*r.HeadscalePreauthkeyID) //nolint:gosec // CHECK > 0; the query selects non-null ids
		if len(nodes[kid]) == 0 {
			continue
		}
		adopted := 0
		err := s.st.WithTenantJobTx(ctx, tenantID, func(tx *store.Tx) error {
			cur, err := tx.Q.LockEnrollmentRequest(ctx, sqlcdb.LockEnrollmentRequestParams{TenantID: tenantID, ID: r.ID})
			switch {
			case errors.Is(err, store.ErrNoRows):
				return nil
			case err != nil:
				return err
			case cur.Status != StatusConsumed:
				return nil // revoked meanwhile
			}
			adopted, err = s.adoptKeyNodes(ctx, tx, tenantID, cur, nodes[kid])
			return err
		})
		if err != nil {
			return rep, err
		}
		rep.NewDevices += adopted
	}
	if err := s.st.WithTenantJobTx(ctx, tenantID, func(tx *store.Tx) error {
		rows, err := tx.Q.LinkConsumedEnrollmentDevices(ctx, tenantID)
		if err != nil {
			return err
		}
		rep.Linked = int64(len(rows))
		for _, d := range rows {
			// a device of a pre-auth key whose row inventory.sync wrote after the consumed transition could not adopt it
			// (a reused node id): notified at this link, once; a web-auth device was notified by its claim
			if d.Method != MethodPreauthKey {
				continue
			}
			name := d.ID.String()
			if d.GivenName != nil && *d.GivenName != "" {
				name = *d.GivenName
			} else if d.Name != nil && *d.Name != "" {
				name = *d.Name
			}
			at := now.UTC()
			if d.HsCreatedAt != nil {
				at = d.HsCreatedAt.UTC()
			}
			if _, err := notifications.Enqueue(ctx, tx, notifications.DeviceNew(tenantID, d.ID, d.OwnerMembershipID, name,
				at)); err != nil {
				return err
			}
			rep.NewDevices++
		}
		return nil
	}); err != nil {
		return rep, err
	}
	return rep, hsErr
}

// outcome is the end reconcile found for a request.
type outcome struct {
	status  string
	failure string
	node    *headscale.Node  // consumed: the first node the key registered
	nodes   []headscale.Node // consumed: every node of the key (a reusable key registers several)
}

// keyOutcome reads the state of an issued key at Headscale.
func (s *Service) keyOutcome(r sqlcdb.EnrollmentRequest, keys map[uint64]headscale.PreAuthKey,
	nodes map[uint64][]headscale.Node, now time.Time,
) outcome {
	if r.HeadscalePreauthkeyID == nil {
		return outcome{status: StatusFailed, failure: FailureKeyMissing}
	}
	kid := uint64(*r.HeadscalePreauthkeyID) //nolint:gosec // CHECK > 0
	k, ok := keys[kid]
	ns := nodes[kid]
	used := len(ns) > 0
	switch {
	case used:
		return outcome{status: StatusConsumed, node: &ns[0], nodes: ns}
	case ok && k.Used:
		return outcome{status: StatusFailed, failure: FailureNodeGone} // ephemeral node gone, or deleted at once
	case !ok && (r.CredentialExpiresAt == nil || now.Before(*r.CredentialExpiresAt)):
		return outcome{status: StatusFailed, failure: FailureKeyMissing}
	case !ok, r.CredentialExpiresAt != nil && !now.Before(*r.CredentialExpiresAt), !k.Expiration.After(now):
		return outcome{status: StatusExpired}
	}
	return outcome{}
}

// settle writes the outcome of one request (worker columns of 0020) if it is still open in the same status; a consumed
// key brings its nodes into the inventory in the same transaction (adoptKeyNodes — the devices it reports).
func (s *Service) settle(ctx context.Context, tenantID uuid.UUID, r sqlcdb.EnrollmentRequest, out outcome) (int, error) {
	adopted := 0
	err := s.st.WithTenantJobTx(ctx, tenantID, func(tx *store.Tx) error {
		q := tx.Q
		cur, err := q.LockEnrollmentRequest(ctx, sqlcdb.LockEnrollmentRequestParams{TenantID: tenantID, ID: r.ID})
		if errors.Is(err, store.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if cur.Status != r.Status || cur.Version != r.Version { // moved meanwhile (claim, revoke…): next run
			return nil
		}
		p := sqlcdb.SetEnrollmentRequestOutcomeParams{Status: out.status, RegisteredMachineKey: cur.RegisteredMachineKey,
			ReportedHostname: cur.ReportedHostname, ConsumedNodeID: cur.ConsumedNodeID, FailureCode: cur.FailureCode,
			TenantID: tenantID, ID: r.ID}
		if out.failure != "" {
			p.FailureCode = &out.failure
		}
		if n := out.node; n != nil {
			nid := int64(n.ID) //nolint:gosec // small ids
			p.ConsumedNodeID = &nid
			if n.MachineKey != "" {
				mk := clip(n.MachineKey, 200)
				p.RegisteredMachineKey = &mk
			}
			if n.Name != "" {
				h := clip(n.Name, 255)
				p.ReportedHostname = &h
			}
		}
		row, err := q.SetEnrollmentRequestOutcome(ctx, p)
		if err != nil {
			return err
		}
		if out.status != StatusConsumed {
			return nil
		}
		t := tenantID
		if err := audit.Record(ctx, q, audit.Event{Action: ActionConsume, ActorType: audit.ActorSystem, TenantID: &t,
			ResourceType: resourceType, ResourceID: r.ID.String(), Details: audit.Details{"node_id": *p.ConsumedNodeID,
				"nodes": len(out.nodes)}}); err != nil {
			return err
		}
		adopted, err = s.adoptKeyNodes(ctx, tx, tenantID, row, out.nodes)
		return err
	})
	if err != nil {
		return 0, err
	}
	return adopted, nil
}

// adoptKeyNodes brings the nodes a platform-issued pre-auth key registered into the inventory with the link to their
// enrollment request, and notifies each NEW device once (device.new — §6.3: its owner + the Tenant Owners; T-06 "thông
// báo thiết bị mới"), in the caller's job transaction tx (the consumed transition, or a later run for a live reusable
// key):
//   - a live row of the node with the same machine key and no link yet (inventory.sync came first): linked;
//   - no live row: the device enters the inventory now (InsertEnrolledDevice, as a verified claim does) and inventory.sync
//     is enqueued — it clamps the node's expiry (V-21: a client asks for any expiry with a pre-auth key too);
//   - a row already linked (an earlier run, a claim) or of another machine key (a reused node id — inventory.sync
//     replaces it and the final link step of Reconcile notifies it): nothing.
//
// The owner is the key's target membership, none for a tagged node. Only rows this call links or inserts are notified,
// and the ref device:<id>:new makes a repeated attempt write nothing: one notification per device.
func (s *Service) adoptKeyNodes(ctx context.Context, tx *store.Tx, tenantID uuid.UUID, r sqlcdb.EnrollmentRequest,
	nodes []headscale.Node,
) (int, error) {
	q := tx.Q
	adopted, inserted := 0, false
	for _, n := range nodes {
		if n.ID == 0 || n.ID > 1<<63-1 || n.MachineKey == "" {
			continue // never written: the CHECK of 0005 and the identity rule need both
		}
		var owner *uuid.UUID
		if !n.IsTagged() && r.TargetMembershipID != nil {
			o := *r.TargetMembershipID
			owner = &o
		}
		dev, err := q.LockLiveDeviceOfNode(ctx, sqlcdb.LockLiveDeviceOfNodeParams{TenantID: tenantID,
			InstanceID: r.InstanceID, HeadscaleNodeID: int64(n.ID)}) //nolint:gosec // bounded just above
		switch {
		case err == nil && (dev.MachineKey != n.MachineKey || dev.EnrollmentRequestID != nil):
			continue
		case err == nil:
			if err := q.LinkDeviceEnrollment(ctx, sqlcdb.LinkDeviceEnrollmentParams{EnrollmentRequestID: &r.ID,
				OwnerMembershipID: owner, TenantID: tenantID, ID: dev.ID}); err != nil {
				return adopted, err
			}
			if dev.OwnerMembershipID != nil {
				owner = dev.OwnerMembershipID // COALESCE of LinkDeviceEnrollment: the row's owner stays
			}
		case errors.Is(err, store.ErrNoRows):
			if dev, err = q.InsertEnrolledDevice(ctx, deviceParams(tenantID, r.InstanceID, n, owner, r.ID)); err != nil {
				return adopted, err
			}
			inserted = true
		default:
			return adopted, err
		}
		name := n.GivenName
		if name == "" {
			name = n.Name
		}
		if name == "" {
			name = dev.ID.String()
		}
		at := n.CreatedAt
		if at.IsZero() {
			at = s.now()
		}
		if _, err := notifications.Enqueue(ctx, tx, notifications.DeviceNew(tenantID, dev.ID, owner, name, at.UTC())); err != nil {
			return adopted, err
		}
		adopted++
	}
	if inserted {
		inst := r.InstanceID
		if _, err := jobs.Enqueue(ctx, tx, jobs.Spec{Kind: KindSync, TenantID: &tenantID, InstanceID: &inst,
			Slot: slotEnroll}); err != nil {
			return adopted, err
		}
	}
	return adopted, nil
}

// ------------------------------------------------------------------------------------------------- schedule

// SchedulerConfig configures the schedule of enrollment.reconcile.
type SchedulerConfig struct {
	Interval time.Duration // between two runs for one tenant; default 2 minutes
	Tick     time.Duration // default 30 s (≤ Interval)
}

// Scheduler enqueues enrollment.reconcile for every tenant with a running instance AND an open enrollment request or a
// live reusable key (its later nodes are adopted — adoptKeyNodes), once per Interval, each tenant at its own offset (a
// hash of its id). Worker process (workerSchedules in apps/).
type Scheduler struct {
	svc  *Service
	cfg  SchedulerConfig
	mu   sync.Mutex
	last map[uuid.UUID]int64
}

// NewScheduler returns the schedule of enrollment.reconcile (worker: mg_worker_*).
func (s *Service) NewScheduler(cfg SchedulerConfig) *Scheduler {
	if cfg.Interval <= 0 {
		cfg.Interval = 2 * time.Minute
	}
	if cfg.Tick <= 0 || cfg.Tick > cfg.Interval {
		cfg.Tick = min(30*time.Second, cfg.Interval)
	}
	return &Scheduler{svc: s, cfg: cfg, last: map[uuid.UUID]int64{}}
}

// Run ticks until ctx is cancelled.
func (sc *Scheduler) Run(ctx context.Context) error {
	t := time.NewTicker(sc.cfg.Tick)
	defer t.Stop()
	for {
		if _, err := sc.Tick(ctx, time.Now()); err != nil && ctx.Err() == nil {
			sc.svc.log.ErrorContext(ctx, "enrollment: enrollment.reconcile schedule failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

func (sc *Scheduler) slot(tenant uuid.UUID, now time.Time) int64 {
	sum := sha256.Sum256(tenant[:])
	offset := int64(binary.BigEndian.Uint64(sum[:8]) % uint64(sc.cfg.Interval)) //nolint:gosec // interval > 0
	return (now.UnixNano() - offset) / int64(sc.cfg.Interval)
}

// Tick enqueues the runs whose period started since the previous tick; it returns how many it enqueued.
func (sc *Scheduler) Tick(ctx context.Context, now time.Time) (int, error) {
	var instances []sqlcdb.ListRunningInstancesRow
	if err := sc.svc.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		var err error
		instances, err = q.ListRunningInstances(ctx)
		return err
	}); err != nil {
		return 0, err
	}
	n := 0
	seen := map[uuid.UUID]bool{}
	for _, in := range instances {
		tenant := in.TenantID
		if seen[tenant] {
			continue
		}
		seen[tenant] = true
		slot := sc.slot(tenant, now)
		sc.mu.Lock()
		prev, known := sc.last[tenant]
		sc.last[tenant] = slot
		sc.mu.Unlock()
		if !known || slot <= prev {
			continue
		}
		err := sc.svc.st.WithTenantJobTx(ctx, tenant, func(tx *store.Tx) error {
			open, err := tx.Q.ListOpenEnrollmentRequests(ctx, tenant)
			if err != nil {
				return err
			}
			if len(open) == 0 {
				live, err := tx.Q.ListLiveReusableEnrollmentKeys(ctx, sqlcdb.ListLiveReusableEnrollmentKeysParams{
					TenantID: tenant, ExpiredAfter: sc.svc.now().Add(-reusableGrace)})
				if err != nil || len(live) == 0 {
					return err
				}
			}
			_, err = jobs.Enqueue(ctx, tx, jobs.Spec{Kind: KindReconcile, TenantID: &tenant,
				Slot: strconv.FormatInt(slot, 10)})
			if err == nil {
				n++
			}
			return err
		})
		if err != nil {
			sc.svc.log.ErrorContext(ctx, "enrollment: enqueue enrollment.reconcile failed", "tenant_id", tenant,
				"error", err)
		}
	}
	return n, nil
}
