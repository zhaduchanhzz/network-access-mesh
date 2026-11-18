package postrestore

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/idp/console"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/logx"
	"github.com/zhaduchanhzz/network-access-mesh/internal/platform"
	"github.com/zhaduchanhzz/network-access-mesh/internal/policies"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/apikey"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/reconcile"
	"github.com/zhaduchanhzz/network-access-mesh/internal/secrets"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
)

// Names shared with the rest of the platform.
const (
	// ActionReconcile is the audit operation platform.restore.reconcile.requested → .succeeded / .failed.
	ActionReconcile = "platform.restore.reconcile"
	// ActionGap is the audit event naming the window a restore lost (§17.2 step 6): one platform event and one per
	// tenant, details from/to (restore point, start of the run) and restore_point_unix.
	ActionGap = "audit.gap"
	// InventorySyncKind is the job kind of the device register sync (devices.KindSync — §13.5; the devices module is not
	// a dependency of provisioning, §13.6: apps/worker checks the two are equal).
	InventorySyncKind = "inventory.sync"
	// SecuritySource is the source of the security events of this package.
	SecuritySource = "postrestore"
)

// Errors returned before anything is written.
var (
	// ErrInvalidRequest: no restore point, or one in the future of the database clock.
	ErrInvalidRequest = errors.New("postrestore: invalid request")
	// ErrUnsupportedSchema: the schema holds support_access_grants (P4-T05) and this version cannot revoke them.
	ErrUnsupportedSchema = errors.New("postrestore: the schema has support_access_grants, which this version cannot revoke — update the command (P4-T05)")
)

// KeyRotator is the API key rotation of P3-T10 (*apikey.Service).
type KeyRotator interface {
	Rotate(ctx context.Context, req apikey.Request) (apikey.Result, error)
}

// PolicyReviewer is the policy step (*policies.Service).
type PolicyReviewer interface {
	ReviewRunning(ctx context.Context, req policies.RunningReview) (policies.RunningResult, error)
}

// SecurityRecorder writes a security event (platform transaction of the worker's store).
type SecurityRecorder interface {
	RecordSecurityEvent(ctx context.Context, ev audit.SecurityEvent) (bool, error)
}

// Config are the collaborators of a Service.
type Config struct {
	// Agent of the host (GetInstanceStatus, ListInstances only); nil = not configured: the instance step is incomplete.
	Agent reconcile.Agent
	// Headscale reaches an instance with its stored key — the read-only key probe of a dry run (a registry over a
	// locator built with apikey.TenantStatuses). Required.
	Headscale headscale.Registry
	// Keys rotates or re-issues an instance's key (required); Policies reviews the running policy (required).
	Keys     KeyRotator
	Policies PolicyReviewer
	// Security records the security events of the inventory (reconcile.*) — required.
	Security SecurityRecorder
	// Actor is the display name of the actor in the audit (default "meshguard admin post-restore-reconcile").
	Actor        string
	AgentTimeout time.Duration // one agent call; 0 = reconcile.DefaultAgentTimeout
	Logger       *slog.Logger
}

// Service runs the reconcile on the worker's store (mg_worker_*).
type Service struct {
	st  *store.Store
	cfg Config
	log *slog.Logger
}

// New returns the service.
func New(st *store.Store, cfg Config) (*Service, error) {
	if st == nil || cfg.Headscale == nil || cfg.Keys == nil || cfg.Policies == nil || cfg.Security == nil {
		return nil, errors.New("postrestore: a store, a Headscale registry, the key rotation, the policy core and a security recorder are required")
	}
	if cfg.Actor == "" {
		cfg.Actor = "meshguard admin post-restore-reconcile"
	}
	if cfg.AgentTimeout <= 0 {
		cfg.AgentTimeout = reconcile.DefaultAgentTimeout
	}
	log := cfg.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Service{st: st, cfg: cfg, log: log}, nil
}

// Request is one run.
type Request struct {
	// RestorePoint is when the restored dump was taken (manifest started_at of mg-backup): the start of the gap.
	RestorePoint time.Time
	DryRun       bool
}

// run is the state of one run.
type run struct {
	req     Request
	rep     *Report
	cutoff  time.Time
	op      audit.Operation
	marker  platform.PostRestore
	tenants []sqlcdb.ListTenantsForPostRestoreRow
	lost    map[uuid.UUID]bool
	review  map[string]*ReviewItem // tenant id (or "instance:<id>") → item
	order   []string
}

// Run reconciles once (see the package documentation). The report is returned even when an error stops the run (its
// Status is then failed); an error before the first write leaves the database untouched.
func (s *Service) Run(ctx context.Context, req Request) (Report, error) {
	rep := Report{Schema: ReportSchema, DryRun: req.DryRun, RestorePoint: req.RestorePoint.UTC(), Incomplete: []string{},
		ReviewRequired: []ReviewItem{}, APIKeys: []APIKeyResult{}, Policies: []policies.RunningResult{}, OpenJobs: []OpenJob{},
		Approvals: ApprovalsStep{ByScopeStatus: map[string]int64{}}, Invitations: InvitationsStep{ByTenant: map[string]int64{}},
		Instances:     InstancesStep{Orphans: []OrphanInstance{}, Lost: []LostInstance{}, Other: []Finding{}},
		InventorySync: InventorySyncStep{Skipped: []string{}}, SupportGrants: SupportGrantsStep{Status: "not_in_schema"}}
	id, err := uuid.NewV7()
	if err != nil {
		return rep, err
	}
	rep.RunID = id
	r := &run{req: req, rep: &rep, lost: map[uuid.UUID]bool{}, review: map[string]*ReviewItem{}}
	if err := s.preflight(ctx, r); err != nil {
		rep.Status, rep.Error = StatusFailed, err.Error()
		return rep, err
	}
	if !req.DryRun {
		if err := s.begin(ctx, r); err != nil {
			rep.Status, rep.Error = StatusFailed, err.Error()
			return rep, err
		}
	}
	err = s.steps(ctx, r)
	rep.ReviewRequired = r.items()
	switch {
	case err != nil:
		rep.Status, rep.Error = StatusFailed, logx.RedactString(err.Error())
	case len(rep.Incomplete) > 0:
		rep.Status = StatusIncomplete
	default:
		rep.Status = StatusCompleted
	}
	if !req.DryRun {
		if ferr := s.finish(context.WithoutCancel(ctx), r, err); ferr != nil && err == nil {
			rep.Status, rep.Error, err = StatusFailed, ferr.Error(), ferr
		}
	}
	return rep, err
}

// preflight reads the clock, checks the request and the schema; nothing is written.
func (s *Service) preflight(ctx context.Context, r *run) error {
	if r.req.RestorePoint.IsZero() {
		return fmt.Errorf("%w: a restore point is required (the started_at of the dump's manifest)", ErrInvalidRequest)
	}
	return s.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		now, err := q.PostRestoreNow(ctx)
		if err != nil {
			return err
		}
		if r.req.RestorePoint.After(now) {
			return fmt.Errorf("%w: the restore point %s is after the database clock %s", ErrInvalidRequest,
				r.req.RestorePoint.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339))
		}
		present, err := q.SupportGrantsTablePresent(ctx)
		if err != nil {
			return err
		}
		if present {
			return ErrUnsupportedSchema
		}
		r.cutoff = now
		r.rep.StartedAt = now.UTC()
		r.rep.Gap = Gap{From: r.req.RestorePoint.UTC(), To: now.UTC(), Seconds: int64(now.Sub(r.req.RestorePoint).Seconds())}
		m, err := platform.ReadMaintenance(ctx, q)
		if err != nil && !m.Enabled { // an unreadable flag counts as ON: step 1 writes a valid one
			return err
		}
		r.rep.Maintenance.Previous = m.Enabled
		r.rep.Maintenance.Persisted = m.Enabled
		if m.PostRestore != nil && m.PostRestore.RestorePoint.Equal(r.req.RestorePoint) {
			r.marker = *m.PostRestore
		}
		r.tenants, err = q.ListTenantsForPostRestore(ctx)
		return err
	})
}

// begin is step 1: the flag ON with the post_restore record (running) and the audit request, one transaction.
func (s *Service) begin(ctx context.Context, r *run) error {
	return s.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		if err := platform.LockMaintenance(ctx, q); err != nil {
			return err
		}
		m, err := platform.ReadMaintenance(ctx, q)
		if err != nil && !m.Enabled {
			return err
		}
		pr := platform.PostRestore{RestorePoint: r.req.RestorePoint.UTC(), Runs: 1}
		if m.PostRestore != nil && m.PostRestore.RestorePoint.Equal(r.req.RestorePoint) {
			pr = *m.PostRestore
			pr.Runs++
		}
		pr.RunID, pr.Status, pr.StartedAt, pr.FinishedAt, pr.Incomplete = r.rep.RunID, platform.PostRestoreRunning, r.cutoff.UTC(), nil, nil
		set := !m.Enabled
		if set {
			m.Enabled, m.Reason, m.Since, m.By = true, platform.ReasonPostRestore, &r.cutoff, s.cfg.Actor
		}
		m.PostRestore = &pr
		if err := platform.WriteMaintenance(ctx, q, m); err != nil {
			return err
		}
		if set {
			if err := audit.Record(ctx, q, s.event(platform.ActionMaintenanceEnable, "system_setting", platform.MaintenanceKey,
				audit.Details{"reason": platform.ReasonPostRestore, "run_id": r.rep.RunID})); err != nil {
				return err
			}
		}
		r.op, err = audit.Requested(ctx, q, s.event(ActionReconcile, "restore", r.rep.RunID.String(), audit.Details{
			"restore_point": r.req.RestorePoint.UTC(), "restore_point_unix": r.req.RestorePoint.Unix(), "cutoff": r.cutoff.UTC(),
			"run": pr.Runs, "gap_seconds": r.rep.Gap.Seconds}))
		if err != nil {
			return err
		}
		r.marker = pr
		r.rep.Maintenance = MaintenanceStep{Persisted: true, SetByRun: set, Run: pr.Runs, Previous: r.rep.Maintenance.Previous}
		return nil
	})
}

// steps runs steps 2–8; the first database error stops the run (a step that cannot reach a subject is incomplete).
func (s *Service) steps(ctx context.Context, r *run) error {
	for _, step := range []func(context.Context, *run) error{s.sessions, s.approvals, s.invitations, s.instances, s.apiKeys,
		s.policies, s.inventorySync, s.openJobs, s.auditGap} {
		if err := step(ctx, r); err != nil {
			return err
		}
	}
	return nil
}

// sessions: every session of the dump (and of the maintenance window before the run) revoked; auth requests deleted.
func (s *Service) sessions(ctx context.Context, r *run) error {
	return s.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		c, err := q.CountSessionsToRevoke(ctx, r.cutoff)
		if err != nil {
			return err
		}
		r.rep.Sessions.LiveAtCutoff = c.Live
		if r.req.DryRun {
			r.rep.Sessions.Revoked = c.Total
			r.rep.Sessions.AuthRequestsDeleted, err = q.CountAuthRequestsBefore(ctx, r.cutoff)
			return err
		}
		if r.rep.Sessions.Revoked, err = q.RevokeSessionsBefore(ctx, r.cutoff); err != nil {
			return fmt.Errorf("revoke sessions: %w", err)
		}
		r.rep.Sessions.AuthRequestsDeleted, err = q.DeleteAuthRequestsBefore(ctx, r.cutoff)
		return err
	})
}

// approvals: open approval requests and console session grants expired.
func (s *Service) approvals(ctx context.Context, r *run) error {
	since := r.cutoff.Add(-console.MaxDuration - time.Minute)
	return s.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		rows, err := q.CountOpenApprovals(ctx, r.cutoff)
		if err != nil {
			return err
		}
		var total int64
		for _, row := range rows {
			r.rep.Approvals.ByScopeStatus[row.Scope+"/"+row.Status] = row.Requests
			total += row.Requests
		}
		grants := sqlcdb.CountConsoleGrantsParams{Action: console.Action, Since: since, Cutoff: r.cutoff}
		if r.req.DryRun {
			r.rep.Approvals.Expired = total
			r.rep.Approvals.ConsoleGrantsExpired, err = q.CountConsoleGrants(ctx, grants)
			return err
		}
		if r.rep.Approvals.Expired, err = q.ExpireOpenApprovals(ctx, r.cutoff); err != nil {
			return fmt.Errorf("expire approval requests: %w", err)
		}
		r.rep.Approvals.ConsoleGrantsExpired, err = q.ExpireConsoleGrants(ctx, sqlcdb.ExpireConsoleGrantsParams(grants))
		return err
	})
}

// invitations: pending invitations revoked, tenant by tenant (tenant pool — the table has no platform branch).
func (s *Service) invitations(ctx context.Context, r *run) error {
	for _, t := range r.tenants {
		var n int64
		err := s.st.WithTenantTx(ctx, t.ID, func(q *sqlcdb.Queries) error {
			var err error
			if r.req.DryRun {
				n, err = q.CountPendingInvitations(ctx, sqlcdb.CountPendingInvitationsParams{TenantID: t.ID, Cutoff: r.cutoff})
				return err
			}
			n, err = q.RevokePendingInvitations(ctx, sqlcdb.RevokePendingInvitationsParams{TenantID: t.ID, Cutoff: r.cutoff})
			return err
		})
		if err != nil {
			return fmt.Errorf("invitations of %s: %w", t.Slug, err)
		}
		if n > 0 {
			r.rep.Invitations.ByTenant[t.Slug] = n
			r.rep.Invitations.Revoked += n
		}
	}
	return nil
}

// instances: the agent's inventory against the registry (report-only inspector of P3-T12); lost instances failed.
func (s *Service) instances(ctx context.Context, r *run) error {
	var rows []sqlcdb.ListInstancesForHostReconcileRow
	if err := s.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		var err error
		rows, err = q.ListInstancesForHostReconcile(ctx)
		return err
	}); err != nil {
		return err
	}
	regs := make([]reconcile.Registered, 0, len(rows))
	byID := map[uuid.UUID]reconcile.Registered{}
	for _, row := range rows {
		g := reconcile.Registered{InstanceID: row.ID, TenantID: row.TenantID, Slug: row.Slug, Status: row.Status}
		regs = append(regs, g)
		byID[row.ID] = g
	}
	in := &reconcile.Inspector{Agent: s.cfg.Agent, AgentTimeout: s.cfg.AgentTimeout, EventWindow: reconcile.DefaultEventWindow,
		Now: func() time.Time { return r.cutoff }}
	rep, events := in.Host(ctx, regs)
	r.rep.Instances.Registry = len(regs)
	for _, c := range rep.Checks {
		if (c.Name == reconcile.CheckInventory || c.Name == reconcile.CheckAgent) && c.Outcome == reconcile.OutcomeUnavailable {
			r.rep.Instances.Inventory, r.rep.Instances.Reason = "unavailable", c.Reason
		}
		if c.Name == reconcile.CheckInventory && c.Note != "" {
			if h, _, ok := cutNote(c.Note); ok {
				r.rep.Instances.Host = h
			}
		}
	}
	if r.rep.Instances.Inventory == "unavailable" {
		r.incomplete("instances", "host", r.rep.Instances.Reason)
		return nil
	}
	r.rep.Instances.Inventory = "checked"
	details := map[string]audit.Details{}
	for _, ev := range events {
		if id, ok := ev.Details["instance_id"].(string); ok {
			details[id] = ev.Details
		}
	}
	for _, f := range rep.Findings {
		switch f.Kind {
		case reconcile.DriftUnknownInstance:
			o := OrphanInstance{InstanceID: f.Subject, Objects: f.Items,
				Action: "report only — adopt it (meshguard admin adopt-instance) or deprovision it after a 2P decision"}
			if d := details[f.Subject]; d != nil {
				o.TenantLabel, _ = d["tenant_label"].(string)
				o.Slug, _ = d["slug"].(string)
			}
			if o.Objects == nil {
				o.Objects = []string{}
			}
			r.rep.Instances.Orphans = append(r.rep.Instances.Orphans, o)
			if id, err := uuid.Parse(f.Subject); err == nil {
				r.flag("instance:"+f.Subject, nil, o.Slug, &id, ReviewOrphan)
			}
		case reconcile.DriftRegisteredMissing:
			id, err := uuid.Parse(f.Subject)
			if err != nil {
				continue
			}
			g := byID[id]
			l := LostInstance{InstanceID: id, TenantID: g.TenantID, Slug: g.Slug}
			if !r.req.DryRun {
				if err := s.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
					n, err := q.MarkInstanceLost(ctx, sqlcdb.MarkInstanceLostParams{ID: id, TenantID: g.TenantID})
					if err != nil {
						return err
					}
					l.MarkedFailed = n == 1
					if n == 1 {
						return audit.Record(ctx, q, s.event("platform.instance.lost", "instance", id.String(), audit.Details{
							"tenant_id": g.TenantID, "slug": g.Slug, "previous_status": g.Status, "run_id": r.rep.RunID}))
					}
					return nil
				}); err != nil {
					return fmt.Errorf("mark instance %s failed: %w", id, err)
				}
			}
			r.lost[id] = true
			r.rep.Instances.Lost = append(r.rep.Instances.Lost, l)
			tenant := g.TenantID
			r.flag(tenant.String(), &tenant, g.Slug, &id, ReviewInstanceLost)
		default:
			r.rep.Instances.Other = append(r.rep.Instances.Other, Finding{Kind: f.Kind, Subject: f.Subject, Expected: f.Expected,
				Actual: f.Actual})
		}
	}
	if !r.req.DryRun {
		for _, ev := range events {
			if _, err := s.cfg.Security.RecordSecurityEvent(ctx, ev); err != nil {
				return fmt.Errorf("record %s: %w", ev.Kind, err)
			}
		}
	}
	return nil
}

// apiKeys: the rotation of P3-T10 with AllowBootstrap for every running instance (dry run: a read-only probe).
func (s *Service) apiKeys(ctx context.Context, r *run) error {
	rows, err := s.liveInstances(ctx)
	if err != nil {
		return err
	}
	for _, row := range rows {
		res := APIKeyResult{TenantID: row.TenantID, Slug: row.Slug, InstanceID: row.ID}
		switch {
		case r.lost[row.ID]:
			res.Outcome, res.Reason = KeySkipped, "instance_lost"
		case row.Status != tenants.InstanceRunning && row.Status != tenants.InstanceStarting:
			res.Outcome, res.Reason = KeySkipped, "instance_"+row.Status
		case !slices.Contains(apikey.TenantStatuses, row.TenantStatus):
			res.Outcome, res.Reason = KeySkipped, "tenant_"+row.TenantStatus
		case r.req.DryRun:
			s.probeKey(ctx, row, &res)
		default:
			s.rotateKey(ctx, r, row, &res)
		}
		switch res.Outcome {
		case KeyFailed, KeyUnavailable:
			r.incomplete("api_key", row.Slug, firstNonEmpty(res.ErrorCode, res.Reason))
			tenant := row.TenantID
			r.flag(tenant.String(), &tenant, row.Slug, nil, ReviewKeyFailed)
		}
		r.rep.APIKeys = append(r.rep.APIKeys, res)
	}
	return nil
}

func (s *Service) probeKey(ctx context.Context, row sqlcdb.ListInstancesForPostRestoreRow, res *APIKeyResult) {
	inst, err := s.cfg.Headscale.ForTenant(ctx, row.TenantID)
	if err == nil {
		_, err = inst.ListAPIKeys(ctx)
	}
	switch {
	case err == nil:
		res.Outcome = KeyOK
	case errors.Is(err, headscale.ErrAPIKeyRejected):
		res.Outcome, res.Reason = KeyWouldReissue, apikey.ReasonKeyRejected
	case errors.Is(err, secrets.ErrNotFound) || errors.Is(err, secrets.ErrDestroyed):
		res.Outcome, res.Reason = KeyWouldReissue, apikey.ReasonKeyLost
	default:
		res.Outcome, res.Reason = KeyUnavailable, "instance_unreachable"
		if he, ok := headscale.AsError(err); ok {
			res.ErrorCode = "headscale_" + string(he.Kind)
		}
	}
}

func (s *Service) rotateKey(ctx context.Context, r *run, row sqlcdb.ListInstancesForPostRestoreRow, res *APIKeyResult) {
	out, err := s.cfg.Keys.Rotate(ctx, apikey.Request{TenantID: row.TenantID, InstanceID: row.ID, AllowBootstrap: true,
		Trigger: apikey.TriggerRestore, JobID: r.rep.RunID, Actor: s.cfg.Actor})
	res.PreviousPrefix, res.KeyPrefix = out.PreviousPrefix, out.KeyPrefix
	res.ExpiredKeys = len(out.ExpiredPrefixes) + int(out.AgentExpired)
	switch {
	case err != nil:
		res.Outcome, res.ErrorCode = KeyFailed, jobs.CodeHandlerError
		var je *jobs.Error
		if errors.As(err, &je) {
			res.ErrorCode = je.Code
		}
		s.log.WarnContext(ctx, "postrestore: API key step failed", "slug", row.Slug, "code", res.ErrorCode,
			"error", logx.RedactString(err.Error()))
	case out.Outcome == apikey.OutcomeSkipped && out.SkipReason == apikey.SkipNotDue:
		res.Outcome = KeyOK
	case out.Outcome == apikey.OutcomeSkipped:
		res.Outcome, res.Reason = KeySkipped, out.SkipReason
	case out.Outcome == apikey.OutcomeBootstrapped:
		res.Outcome, res.Reason = KeyReissued, out.BootstrapReason
	default:
		res.Outcome = KeyRotated
	}
}

// policies: the running policy of every tenant with a running instance against its current application.
func (s *Service) policies(ctx context.Context, r *run) error {
	rows, err := s.liveInstances(ctx)
	if err != nil {
		return err
	}
	for _, row := range rows {
		if r.lost[row.ID] || row.Status != tenants.InstanceRunning || !slices.Contains(apikey.TenantStatuses, row.TenantStatus) {
			continue
		}
		res, err := s.cfg.Policies.ReviewRunning(ctx, policies.RunningReview{TenantID: row.TenantID, RunID: r.rep.RunID,
			RestorePoint: r.req.RestorePoint, DryRun: r.req.DryRun, Actor: s.cfg.Actor})
		if err != nil {
			return fmt.Errorf("policy of %s: %w", row.Slug, err)
		}
		tenant := row.TenantID
		switch res.Outcome {
		case policies.RunningAdopted, policies.RunningWouldAdopt:
			r.flag(tenant.String(), &tenant, row.Slug, nil, ReviewPolicyDiffers)
		case policies.RunningNoPolicy:
			r.flag(tenant.String(), &tenant, row.Slug, nil, ReviewNoPolicy)
		case policies.RunningUnavailable, policies.RunningLocked:
			r.incomplete("policy", row.Slug, firstNonEmpty(res.ErrorCode, res.Outcome))
		}
		if len(res.UnmappedUsers) > 0 {
			r.flag(tenant.String(), &tenant, row.Slug, nil, ReviewUnmappedUsers)
		}
		r.rep.Policies = append(r.rep.Policies, res)
	}
	return nil
}

// inventorySync enqueues inventory.sync for every running instance (slot of the restore point: a second run finds the
// unfinished job of the first one).
func (s *Service) inventorySync(ctx context.Context, r *run) error {
	rows, err := s.liveInstances(ctx)
	if err != nil {
		return err
	}
	slot := "post-restore-" + strconv.FormatInt(r.req.RestorePoint.Unix(), 10)
	for _, row := range rows {
		if r.lost[row.ID] || row.Status != tenants.InstanceRunning {
			r.rep.InventorySync.Skipped = append(r.rep.InventorySync.Skipped, row.Slug)
			continue
		}
		if r.req.DryRun {
			r.rep.InventorySync.Enqueued++
			continue
		}
		tenant, instance := row.TenantID, row.ID
		var created bool
		if err := s.st.WithTenantJobTx(ctx, tenant, func(tx *store.Tx) error {
			enq, err := jobs.Enqueue(ctx, tx, jobs.Spec{Kind: InventorySyncKind, TenantID: &tenant, InstanceID: &instance, Slot: slot})
			created = enq.Created
			return err
		}); err != nil {
			return fmt.Errorf("enqueue inventory.sync of %s: %w", row.Slug, err)
		}
		if created {
			r.rep.InventorySync.Enqueued++
		} else {
			r.rep.InventorySync.Existing++
		}
	}
	return nil
}

// openJobs lists the jobs still open in the restored database.
func (s *Service) openJobs(ctx context.Context, r *run) error {
	return s.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		rows, err := q.ListOpenJobsBefore(ctx, r.cutoff)
		if err != nil {
			return err
		}
		for _, j := range rows {
			r.rep.OpenJobs = append(r.rep.OpenJobs, OpenJob{ID: j.ID, Kind: j.Kind, Status: j.Status, TenantID: j.TenantID,
				CreatedAt: j.CreatedAt.UTC()})
		}
		return nil
	})
}

// auditGap writes audit.gap for every tenant and the platform, once per restore point.
func (s *Service) auditGap(ctx context.Context, r *run) error {
	unix := strconv.FormatInt(r.req.RestorePoint.Unix(), 10)
	details := func() audit.Details {
		return audit.Details{"from": r.req.RestorePoint.UTC(), "to": r.cutoff.UTC(), "gap_seconds": r.rep.Gap.Seconds,
			"restore_point_unix": r.req.RestorePoint.Unix(), "run_id": r.rep.RunID, "source": "postgres_restore",
			"reason": "the database was restored to an older point: writes of this window are lost"}
	}
	for _, t := range r.tenants {
		tenant := t.ID
		var wrote bool
		err := s.st.WithTenantTx(ctx, tenant, func(q *sqlcdb.Queries) error {
			done, err := q.AuditGapRecorded(ctx, sqlcdb.AuditGapRecordedParams{TenantID: &tenant, RestorePointUnix: unix})
			if err != nil || done || r.req.DryRun {
				return err
			}
			wrote = true
			ev := s.event(ActionGap, "tenant", tenant.String(), details())
			ev.TenantID = &tenant
			return audit.Record(ctx, q, ev)
		})
		if err != nil {
			return fmt.Errorf("audit.gap of %s: %w", t.Slug, err)
		}
		if !r.req.DryRun {
			r.rep.AuditGap.Tenants++
		}
		if wrote {
			r.rep.AuditGap.Written++
		}
	}
	return s.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		done, err := q.AuditGapRecorded(ctx, sqlcdb.AuditGapRecordedParams{RestorePointUnix: unix})
		if err != nil || r.req.DryRun {
			return err
		}
		if !done {
			if err := audit.Record(ctx, q, s.event(ActionGap, "restore", r.rep.RunID.String(), details())); err != nil {
				return err
			}
			r.rep.AuditGap.Written++
		}
		r.rep.AuditGap.Platform = true
		return nil
	})
}

// finish records the outcome: the post_restore record and the closing audit event, one transaction.
func (s *Service) finish(ctx context.Context, r *run, runErr error) error {
	return s.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		if err := platform.LockMaintenance(ctx, q); err != nil {
			return err
		}
		m, err := platform.ReadMaintenance(ctx, q)
		if err != nil && !m.Enabled {
			return err
		}
		now, err := q.PostRestoreNow(ctx)
		if err != nil {
			return err
		}
		pr := r.marker
		pr.FinishedAt, pr.Incomplete, pr.ReviewRequired = &now, r.rep.Incomplete, len(r.rep.ReviewRequired)
		pr.GapRecorded = pr.GapRecorded || r.rep.AuditGap.Platform
		pr.Status = platform.PostRestoreReconciled
		if runErr != nil {
			pr.Status = platform.PostRestoreFailed
		}
		m.PostRestore = &pr
		if err := platform.WriteMaintenance(ctx, q, m); err != nil {
			return err
		}
		t := now.UTC()
		r.rep.FinishedAt = &t
		summary := audit.Details{"status": r.rep.Status, "sessions_revoked": r.rep.Sessions.Revoked,
			"approvals_expired":   r.rep.Approvals.Expired + r.rep.Approvals.ConsoleGrantsExpired,
			"invitations_revoked": r.rep.Invitations.Revoked, "orphans": len(r.rep.Instances.Orphans),
			"lost": len(r.rep.Instances.Lost), "keys_reissued": count(r.rep.APIKeys, KeyReissued),
			"policies_adopted": countPolicies(r.rep.Policies, policies.RunningAdopted), "syncs": r.rep.InventorySync.Enqueued,
			"open_jobs": len(r.rep.OpenJobs), "review_required": len(r.rep.ReviewRequired), "incomplete": len(r.rep.Incomplete)}
		if runErr != nil {
			return r.op.Failed(ctx, q, "post_restore_failed", summary)
		}
		return r.op.Succeeded(ctx, q, summary)
	})
}

// liveInstances are the registry's instances that are not removed (read again after the lost ones were failed).
func (s *Service) liveInstances(ctx context.Context) ([]sqlcdb.ListInstancesForPostRestoreRow, error) {
	var rows []sqlcdb.ListInstancesForPostRestoreRow
	err := s.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		var err error
		rows, err = q.ListInstancesForPostRestore(ctx)
		return err
	})
	return rows, err
}

func (s *Service) event(action, resourceType, resourceID string, d audit.Details) audit.Event {
	return audit.Event{ActorType: audit.ActorSystem, ActorDisplay: s.cfg.Actor, Action: action, ResourceType: resourceType,
		ResourceID: resourceID, Details: d}
}

func (r *run) incomplete(step, subject, reason string) {
	r.rep.Incomplete = append(r.rep.Incomplete, step+":"+subject+":"+reason)
}

func (r *run) flag(key string, tenant *uuid.UUID, slug string, instance *uuid.UUID, reason string) {
	it, ok := r.review[key]
	if !ok {
		it = &ReviewItem{TenantID: tenant, Slug: slug, InstanceID: instance}
		r.review[key] = it
		r.order = append(r.order, key)
	}
	if it.InstanceID == nil {
		it.InstanceID = instance
	}
	if !slices.Contains(it.Reasons, reason) {
		it.Reasons = append(it.Reasons, reason)
	}
}

func (r *run) items() []ReviewItem {
	out := make([]ReviewItem, 0, len(r.order))
	for _, k := range r.order {
		out = append(out, *r.review[k])
	}
	return out
}

// cutNote reads "host=<n>,registry=<m>" of the inventory check.
func cutNote(note string) (host, registry int, ok bool) {
	_, err := fmt.Sscanf(note, "host=%d,registry=%d", &host, &registry)
	return host, registry, err == nil
}

func firstNonEmpty(s ...string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}

func count(keys []APIKeyResult, outcome string) int {
	n := 0
	for _, k := range keys {
		if k.Outcome == outcome {
			n++
		}
	}
	return n
}

func countPolicies(ps []policies.RunningResult, outcome string) int {
	n := 0
	for _, p := range ps {
		if p.Outcome == outcome {
			n++
		}
	}
	return n
}
