package enrollment

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
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
}

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
// consumed/verified requests get their enrollment link. Headscale is asked only when an issued key is open; when it does
// not answer, the keys wait for the next run and the error is returned (the job retries).
func (s *Service) Reconcile(ctx context.Context, tenantID uuid.UUID) (ReconcileReport, error) {
	var (
		rep  ReconcileReport
		open []sqlcdb.EnrollmentRequest
	)
	if err := s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		var err error
		open, err = q.ListOpenEnrollmentRequests(ctx, tenantID)
		return err
	}); err != nil {
		return rep, err
	}
	rep.Open = len(open)
	now := s.now()
	var (
		keys   map[uint64]headscale.PreAuthKey
		nodes  map[uint64]headscale.Node // by pre-auth key id
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
		keys, nodes = map[uint64]headscale.PreAuthKey{}, map[uint64]headscale.Node{}
		for _, k := range ks {
			keys[k.ID] = k
		}
		for _, n := range ns {
			if n.PreAuthKeyID != 0 {
				if prev, ok := nodes[n.PreAuthKeyID]; !ok || n.CreatedAt.Before(prev.CreatedAt) {
					nodes[n.PreAuthKeyID] = n // the first node the key registered
				}
			}
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
		if err := s.settle(ctx, tenantID, r, out); err != nil {
			return rep, err
		}
		switch out.status {
		case StatusExpired:
			rep.Expired++
		case StatusConsumed:
			rep.Consumed++
		case StatusFailed:
			rep.Failed++
		}
	}
	if err := s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		var err error
		rep.Linked, err = q.LinkConsumedEnrollmentDevices(ctx, tenantID)
		return err
	}); err != nil {
		return rep, err
	}
	return rep, hsErr
}

// outcome is the end reconcile found for a request.
type outcome struct {
	status  string
	failure string
	node    *headscale.Node
}

// keyOutcome reads the state of an issued key at Headscale.
func (s *Service) keyOutcome(r sqlcdb.EnrollmentRequest, keys map[uint64]headscale.PreAuthKey,
	nodes map[uint64]headscale.Node, now time.Time,
) outcome {
	if r.HeadscalePreauthkeyID == nil {
		return outcome{status: StatusFailed, failure: FailureKeyMissing}
	}
	kid := uint64(*r.HeadscalePreauthkeyID) //nolint:gosec // CHECK > 0
	k, ok := keys[kid]
	n, used := nodes[kid]
	switch {
	case used:
		return outcome{status: StatusConsumed, node: &n}
	case ok && k.Used:
		return outcome{status: StatusFailed, failure: FailureNodeGone} // ephemeral node gone, or deleted at once
	case !ok && (r.CredentialExpiresAt == nil || now.Before(*r.CredentialExpiresAt)):
		return outcome{status: StatusFailed, failure: FailureKeyMissing}
	case !ok, r.CredentialExpiresAt != nil && !now.Before(*r.CredentialExpiresAt), !k.Expiration.After(now):
		return outcome{status: StatusExpired}
	}
	return outcome{}
}

// settle writes the outcome of one request (worker columns of 0020) if it is still open in the same status.
func (s *Service) settle(ctx context.Context, tenantID uuid.UUID, r sqlcdb.EnrollmentRequest, out outcome) error {
	return s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
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
		if _, err := q.SetEnrollmentRequestOutcome(ctx, p); err != nil {
			return err
		}
		if out.status != StatusConsumed {
			return nil
		}
		t := tenantID
		return audit.Record(ctx, q, audit.Event{Action: ActionConsume, ActorType: audit.ActorSystem, TenantID: &t,
			ResourceType: resourceType, ResourceID: r.ID.String(), Details: audit.Details{"node_id": *p.ConsumedNodeID}})
	})
}

// ------------------------------------------------------------------------------------------------- schedule

// SchedulerConfig configures the schedule of enrollment.reconcile.
type SchedulerConfig struct {
	Interval time.Duration // between two runs for one tenant; default 2 minutes
	Tick     time.Duration // default 30 s (≤ Interval)
}

// Scheduler enqueues enrollment.reconcile for every tenant with a running instance AND an open enrollment request, once
// per Interval, each tenant at its own offset (a hash of its id). Worker process (workerSchedules in apps/).
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
			if err != nil || len(open) == 0 {
				return err
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
