package policies

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
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

// The drift check (§7.3 "Drift detection", §13.5 policy.drift_check, P4-T10): on a schedule, every running instance of
// an active or suspended tenant is read (GetPolicy) and its sha256 compared with the applied_sha256 of its current
// application — under the tenant's policy lock, so an application in flight is never mistaken for a drift.
//
//	same                 ok
//	another policy       security_event High policy.drift (changed out of band) + policy.apply (trigger
//	                     drift_repair) enqueued: the desired state applied again
//	no policy            ErrNoPolicy — the instance is (or will be after a restart) allow-all: security_event Critical
//	                     instance.policy_missing and the edge detached (§13.4 — handled like the post-start gate of
//	                     §11.4); the job fails (alert)
//	API key refused      after the adapter reloaded it: the instance's database was probably replaced (§13.4):
//	                     security_event Critical instance.database_replaced; apikey.bootstrap is NEVER run and the
//	                     edge is left to the operator (the automatic detach belongs to the post-start gate only)

// KindDriftCheck is the job kind (jobs.DefaultKinds: dedupe tenant:{tenant}:policy.drift:{slot}).
const KindDriftCheck = "policy.drift_check"

// DefaultDriftInterval is the period of the drift check of one instance.
const DefaultDriftInterval = 15 * time.Minute

// Security events of the drift check (the same kinds as the post-start gate of instance operations — §11.4).
const (
	SecPolicyDrift      = "instance.policy_drift"      // High: the policy read is not the applied one
	SecPolicyMissing    = "instance.policy_missing"    // Critical: no policy (allow-all)
	SecDatabaseReplaced = "instance.database_replaced" // Critical: the platform's API key is refused
	driftSource         = "policies"
	driftDedupeWindow   = time.Hour
)

// EdgeDetacher detaches the edge of an instance (Host Agent RemoveEdgeAttachment, reason policy drift — wired in
// apps/: policies does not import the agent client).
type EdgeDetacher interface {
	DetachEdge(ctx context.Context, tenantID, instanceID, jobID uuid.UUID) error
}

// DriftOutput is the output of a policy.drift_check job.
type DriftOutput struct {
	InstanceID     uuid.UUID `json:"instance_id,omitzero"`
	State          string    `json:"state"` // in_sync | drift | no_policy | api_key_rejected | skipped
	Skipped        string    `json:"skipped,omitempty"`
	ApplicationID  uuid.UUID `json:"application_id,omitzero"`
	AppliedSHA256  string    `json:"applied_sha256,omitempty"`
	ReadSHA256     string    `json:"read_sha256,omitempty"`
	RepairJobID    uuid.UUID `json:"repair_job_id,omitzero"`
	EdgeDetached   bool      `json:"edge_detached,omitempty"`
	SecurityEvents []string  `json:"security_events,omitempty"`
}

// Drift states.
const (
	DriftInSync         = "in_sync"
	DriftDrift          = "drift"
	DriftNoPolicy       = "no_policy"
	DriftAPIKeyRejected = "api_key_rejected"
	DriftSkipped        = "skipped"
)

// RegisterDrift registers the policy.drift_check handler on the worker.
func (s *Service) RegisterDrift(w *jobs.Worker) error {
	return w.Register(KindDriftCheck, jobs.HandlerFunc(s.runDriftJob))
}

// driftTarget is what the check compares.
type driftTarget struct {
	status   string
	instance uuid.UUID
	current  *sqlcdb.PolicyApplication
}

func (s *Service) runDriftJob(ctx context.Context, run *jobs.Run) error {
	if run.TenantID == nil {
		return jobs.Permanent(codeInvalidInput, errors.New("policy.drift_check needs a tenant"))
	}
	tenantID := *run.TenantID
	out := DriftOutput{State: DriftSkipped}
	var jobErr error
	err := s.st.WithTenantLock(ctx, tenantID, lockName, s.lockWait, func(ctx context.Context) error {
		t, err := s.driftTarget(ctx, tenantID)
		if err != nil {
			return err
		}
		out.InstanceID = t.instance
		switch {
		case t.status != "active" && t.status != "suspended":
			out.Skipped = SkipTenantNotActive
			return nil
		case t.instance == uuid.Nil:
			out.Skipped = SkipNoInstance
			return nil
		case t.current == nil:
			out.Skipped = "no_applied_policy"
			return nil
		}
		out.ApplicationID, out.AppliedSHA256 = t.current.ID, t.current.AppliedSha256
		reg := s.reg
		if t.status == "suspended" {
			reg = s.susReg
		}
		inst, err := reg.ForTenant(ctx, tenantID)
		if err != nil {
			return jobs.Transient(codeOf(err), fmt.Errorf("reach the instance: %w", err))
		}
		p, err := inst.GetPolicy(ctx)
		switch {
		case errors.Is(err, headscale.ErrNoPolicy):
			out.State = DriftNoPolicy
			s.securityEvent(ctx, tenantID, t.instance, run.ID, SecPolicyMissing, audit.SeverityCritical, &out,
				audit.Details{"applied_sha256": t.current.AppliedSha256})
			if s.edge != nil {
				dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
				derr := s.edge.DetachEdge(dctx, tenantID, t.instance, run.ID)
				cancel()
				if derr != nil {
					jobErr = jobs.Transient("edge_detach_failed", fmt.Errorf("the instance serves no policy and the edge "+
						"could not be detached: %w", derr))
					return nil
				}
				out.EdgeDetached = true
			}
			jobErr = jobs.Permanent("no_policy", errors.New("the instance serves no policy (allow-all)"))
			return nil
		case isAPIKeyRejected(err):
			out.State = DriftAPIKeyRejected
			s.securityEvent(ctx, tenantID, t.instance, run.ID, SecDatabaseReplaced, audit.SeverityCritical, &out,
				audit.Details{"where": KindDriftCheck, "apikey_bootstrap": false})
			jobErr = jobs.Permanent("database_replaced", errors.New("the instance refuses the platform's API key "+
				"(database replaced?): no automatic apikey.bootstrap — an operator verifies and restores (§13.4)"))
			return nil
		case err != nil:
			return jobs.Transient(codeOf(err), fmt.Errorf("GetPolicy: %w", err))
		}
		out.ReadSHA256 = SHA256Hex(p.Data)
		if out.ReadSHA256 == t.current.AppliedSha256 {
			out.State = DriftInSync
			return nil
		}
		out.State = DriftDrift
		s.securityEvent(ctx, tenantID, t.instance, run.ID, SecPolicyDrift, audit.SeverityHigh, &out,
			audit.Details{"applied_sha256": t.current.AppliedSha256, "read_sha256": out.ReadSHA256})
		id, err := s.enqueueRepair(ctx, tenantID)
		if err != nil {
			return jobs.Transient("store", fmt.Errorf("enqueue policy.apply (drift_repair): %w", err))
		}
		out.RepairJobID = id
		return nil
	})
	if errors.Is(err, store.ErrLockTimeout) {
		return jobs.Transient("policy_lock_timeout", err) // an application in progress: the next attempt checks
	}
	if err != nil {
		var je *jobs.Error
		if errors.As(err, &je) {
			return err
		}
		if errors.Is(err, store.ErrNoRows) {
			return jobs.Permanent("no_tenant", err)
		}
		return jobs.Transient("store", fmt.Errorf("drift check: sqlstate %q", store.SQLState(err)))
	}
	if serr := run.SetOutput(out); serr != nil {
		return serr
	}
	s.log.InfoContext(ctx, "policies: drift check", "tenant_id", tenantID, "state", out.State, "skipped", out.Skipped)
	return jobErr
}

func isAPIKeyRejected(err error) bool {
	he, ok := headscale.AsError(err)
	return ok && he.Kind == headscale.KindAPIKeyRejected
}

// driftTarget reads the tenant's status, live instance and the instance's current application.
func (s *Service) driftTarget(ctx context.Context, tenantID uuid.UUID) (driftTarget, error) {
	var t driftTarget
	err := s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		ten, err := q.GetTenant(ctx, tenantID)
		if err != nil {
			return err
		}
		t.status = ten.Status
		inst, err := q.GetLiveInstanceForTenant(ctx, tenantID)
		if errors.Is(err, store.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		t.instance = inst.ID
		cur, err := q.GetCurrentPolicyApplication(ctx, sqlcdb.GetCurrentPolicyApplicationParams{TenantID: tenantID,
			InstanceID: inst.ID})
		switch {
		case err == nil:
			t.current = &cur
		case !errors.Is(err, store.ErrNoRows):
			return err
		}
		return nil
	})
	return t, err
}

// enqueueRepair enqueues policy.apply (trigger drift_repair) — an unfinished job of the tenant is reused (dedupe).
func (s *Service) enqueueRepair(ctx context.Context, tenantID uuid.UUID) (uuid.UUID, error) {
	var id uuid.UUID
	err := s.st.WithTenantJobTx(ctx, tenantID, func(tx *store.Tx) error {
		e, err := jobs.Enqueue(ctx, tx, jobs.Spec{Kind: KindApply, TenantID: &tenantID,
			Input: ApplyJobInput{Trigger: TriggerDriftRepair}})
		if err != nil {
			return err
		}
		id = e.Job.ID
		return nil
	})
	return id, err
}

// securityEvent records a security event of the tenant (deduplicated per instance and kind for an hour) and logs the
// alert; a failure to record it is logged, never hidden.
func (s *Service) securityEvent(ctx context.Context, tenantID, instanceID, jobID uuid.UUID, kind, severity string,
	out *DriftOutput, d audit.Details) {
	s.log.ErrorContext(ctx, "policies: security event", "kind", kind, "severity", severity, "tenant_id", tenantID,
		"instance_id", instanceID, "job_id", jobID, "alert", true)
	details := audit.Details{"instance_id": instanceID, "job_id": jobID, "operation": KindDriftCheck}
	for k, v := range d {
		details[k] = v
	}
	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.sysWait)
	defer cancel()
	tenant := tenantID
	err := s.st.WithTenantTx(wctx, tenantID, func(q *sqlcdb.Queries) error {
		_, err := audit.RecordSecurityEvent(wctx, q, audit.SecurityEvent{TenantID: &tenant, Kind: kind, Severity: severity,
			Source: driftSource, Details: details, DedupeKey: kind + ":" + instanceID.String(), DedupeWindow: driftDedupeWindow})
		return err
	})
	if err != nil {
		s.log.ErrorContext(ctx, "policies: the security event was NOT recorded", "kind", kind, "sqlstate", store.SQLState(err))
		return
	}
	out.SecurityEvents = append(out.SecurityEvents, kind)
}

// DriftSchedulerConfig configures the schedule of policy.drift_check.
type DriftSchedulerConfig struct {
	Interval time.Duration // per instance; default DefaultDriftInterval
	Tick     time.Duration // how often the schedule looks; default 30 s (≤ Interval)
}

// DriftScheduler enqueues policy.drift_check for every running instance of an active or suspended tenant with a desired
// version once per Interval, each at its own offset (a hash of the instance id — §13.5 "Giãn tải"); the first time an
// instance is seen only its current period is noted. Dedupe tenant:<id>:policy.drift:<slot>.
type DriftScheduler struct {
	svc  *Service
	cfg  DriftSchedulerConfig
	mu   sync.Mutex
	last map[uuid.UUID]int64
}

// NewDriftScheduler returns the schedule on the service's store (worker).
func (s *Service) NewScheduler(cfg DriftSchedulerConfig) *DriftScheduler {
	if cfg.Interval <= 0 {
		cfg.Interval = DefaultDriftInterval
	}
	if cfg.Tick <= 0 || cfg.Tick > cfg.Interval {
		cfg.Tick = min(30*time.Second, cfg.Interval)
	}
	return &DriftScheduler{svc: s, cfg: cfg, last: map[uuid.UUID]int64{}}
}

// Run ticks until ctx is cancelled.
func (sc *DriftScheduler) Run(ctx context.Context) error {
	t := time.NewTicker(sc.cfg.Tick)
	defer t.Stop()
	for {
		if _, err := sc.Tick(ctx, time.Now()); err != nil && ctx.Err() == nil {
			sc.svc.log.ErrorContext(ctx, "policies: drift schedule failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

func (sc *DriftScheduler) slot(instance uuid.UUID, now time.Time) int64 {
	sum := sha256.Sum256(append([]byte(KindDriftCheck+":"), instance[:]...))
	offset := int64(binary.BigEndian.Uint64(sum[:8]) % uint64(sc.cfg.Interval)) //nolint:gosec // interval > 0, offset < interval
	return (now.UnixNano() - offset) / int64(sc.cfg.Interval)
}

// Tick enqueues the checks whose period started since the previous tick and returns how many it enqueued.
func (sc *DriftScheduler) Tick(ctx context.Context, now time.Time) (int, error) {
	var targets []sqlcdb.ListPolicyDriftTargetsRow
	if err := sc.svc.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		var err error
		targets, err = q.ListPolicyDriftTargets(ctx)
		return err
	}); err != nil {
		return 0, err
	}
	n := 0
	seen := make(map[uuid.UUID]bool, len(targets))
	for _, tg := range targets {
		seen[tg.InstanceID] = true
		slot := sc.slot(tg.InstanceID, now)
		sc.mu.Lock()
		prev, known := sc.last[tg.InstanceID]
		sc.last[tg.InstanceID] = slot
		sc.mu.Unlock()
		if !known || slot <= prev {
			continue
		}
		tenant, instance := tg.TenantID, tg.InstanceID
		err := sc.svc.st.WithTenantJobTx(ctx, tenant, func(tx *store.Tx) error {
			_, err := jobs.Enqueue(ctx, tx, jobs.Spec{Kind: KindDriftCheck, TenantID: &tenant, InstanceID: &instance,
				Slot: strconv.FormatInt(slot, 10)})
			return err
		})
		if err != nil {
			sc.svc.log.ErrorContext(ctx, "policies: enqueue policy.drift_check failed", "tenant_id", tenant, "error", err)
			continue
		}
		n++
	}
	sc.mu.Lock()
	for id := range sc.last {
		if !seen[id] {
			delete(sc.last, id)
		}
	}
	sc.mu.Unlock()
	return n, nil
}
