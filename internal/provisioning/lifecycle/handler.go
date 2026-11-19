package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/infrastructure/headscale/templates"
	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/notifications"
	"github.com/zhaduchanhzz/network-access-mesh/internal/policies"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
)

// ReachableStatuses are the tenant statuses under which the Headscale registry of the Handler (and of its policy core)
// must reach the instance — locator.Options.TenantStatuses: the instance of a suspended tenant keeps running (§11.4)
// and the jobs still call it (pre-auth keys, the desired policy again on resume).
var ReachableStatuses = []string{tenants.StatusActive, tenants.StatusSuspended}

// PolicyApplier is the policy core (*policies.Service — P3-T08a) over a Headscale registry that reaches suspended
// tenants.
type PolicyApplier interface {
	Apply(ctx context.Context, req policies.ApplyRequest) (policies.Result, error)
	// ApplyDesired renders the desired version (typed or HuJSON — P4-T10) with the tables of now and applies it.
	ApplyDesired(ctx context.Context, req policies.DesiredRequest) (policies.Result, error)
}

var _ PolicyApplier = (*policies.Service)(nil)

// Config are the collaborators and settings of a Handler.
type Config struct {
	Store *store.Store // the worker's store (mg_worker_tenant / mg_worker_platform)
	// Policies applies the suspension policy and the desired version again.
	Policies PolicyApplier
	// Headscale lists and expires the pre-auth keys. It must reach the instance of a SUSPENDED tenant (locator
	// TenantStatuses active + suspended) — the registry of the other jobs refuses it.
	Headscale headscale.Registry
	Notifier  notifications.Enqueuer // nil ⇒ notifications.Default
	Logger    *slog.Logger
	// SuspensionPolicy is the HuJSON of the suspension (deny-all); "" ⇒ templates.SuspensionPolicy.
	SuspensionPolicy string
	// Timing (§11.3); zero values take the defaults of tenant.provision.
	StepRetries int           // 5
	RetryBase   time.Duration // 2 s
	RetryMax    time.Duration // 60 s
	CallTimeout time.Duration // one Headscale call: 2 min
	Now         func() time.Time
}

// Handler runs tenant.suspend and tenant.resume in the worker.
type Handler struct {
	cfg Config
}

// New checks the configuration and returns the handler of both kinds.
func New(cfg Config) (*Handler, error) {
	if cfg.Store == nil || cfg.Policies == nil || cfg.Headscale == nil {
		return nil, errors.New("lifecycle: a store, the policy core and a Headscale registry are required")
	}
	if cfg.Notifier == nil {
		cfg.Notifier = notifications.Default
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	if cfg.SuspensionPolicy == "" {
		cfg.SuspensionPolicy = templates.SuspensionPolicy
	}
	if _, err := policies.Lint(cfg.SuspensionPolicy); err != nil {
		return nil, fmt.Errorf("lifecycle: the suspension policy: %w", err)
	}
	if cfg.StepRetries == 0 {
		cfg.StepRetries = 5
	}
	if cfg.RetryBase == 0 {
		cfg.RetryBase = 2 * time.Second
	}
	if cfg.RetryMax == 0 {
		cfg.RetryMax = time.Minute
	}
	if cfg.CallTimeout == 0 {
		cfg.CallTimeout = 2 * time.Minute
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.StepRetries < 0 || cfg.RetryMax < cfg.RetryBase {
		return nil, errors.New("lifecycle: invalid retry settings")
	}
	return &Handler{cfg: cfg}, nil
}

// Register registers the handlers of tenant.suspend and tenant.resume on the worker.
func (h *Handler) Register(w *jobs.Worker) error {
	if err := w.Register(KindSuspend, suspendJob{h}); err != nil {
		return err
	}
	return w.Register(KindResume, resumeJob{h})
}

// suspendJob is tenant.suspend: jobs.Handler + jobs.Compensator (run only by /rollback — Run never returns a
// permanent error).
type suspendJob struct{ h *Handler }

// resumeJob is tenant.resume: jobs.Handler + jobs.Compensator (also after a permanent error).
type resumeJob struct{ h *Handler }

var (
	_ jobs.Compensator = suspendJob{}
	_ jobs.Compensator = resumeJob{}
)

// Run implements jobs.Handler. A permanent error stops the job failed_resumable instead of compensating: undoing a
// suspension returns the tenant to `active`, which only an operator decides (/rollback).
func (j suspendJob) Run(ctx context.Context, run *jobs.Run) error {
	err := j.h.suspend(ctx, run)
	if jobs.IsPermanent(err) {
		return jobs.Resumable(jobs.CodeOf(err), err)
	}
	return err
}

// Compensate implements jobs.Compensator.
func (j suspendJob) Compensate(ctx context.Context, run *jobs.Run, cause error) error {
	return j.h.undoSuspend(ctx, run, cause)
}

// Run implements jobs.Handler.
func (j resumeJob) Run(ctx context.Context, run *jobs.Run) error { return j.h.resume(ctx, run) }

// Compensate implements jobs.Compensator.
func (j resumeJob) Compensate(ctx context.Context, run *jobs.Run, cause error) error {
	return j.h.undoResume(ctx, run, cause)
}

// ---------------------------------------------------------------------------------------------------- tenant.suspend

// policyResources is created_resources of policy.suspend / policy.resume: the version the step applies or restores.
type policyResources struct {
	RestoreVersionID uuid.UUID `json:"restore_version_id,omitempty"` // policy.suspend: the desired version kept
	VersionID        uuid.UUID `json:"version_id,omitempty"`         // policy.resume: the version applied again
}

// statusResources is created_resources of registry.suspend / registry.resume: the status the step moved the tenant
// from ("" when it found the tenant already in the target status on its first attempt — nothing to undo).
type statusResources struct {
	From string `json:"from"`
}

func (h *Handler) suspend(ctx context.Context, run *jobs.Run) error {
	in, err := h.input(run)
	if err != nil {
		return err
	}
	t, err := h.tenant(ctx, in.TenantID)
	if err != nil {
		return err
	}
	if t.Status != tenants.StatusActive && t.Status != tenants.StatusSuspended {
		return jobs.Permanent("registry_state", fmt.Errorf("tenant %s is %s", t.ID, t.Status))
	}
	run.SetResource("tenant", t.ID.String())
	if err := h.step(ctx, run, StepPolicySuspend, func(ctx context.Context, s *jobs.StepRun) error {
		if err := record(ctx, s, policyResources{RestoreVersionID: in.RestoreVersionID}); err != nil {
			return err
		}
		res, err := h.cfg.Policies.Apply(ctx, policies.ApplyRequest{TenantID: t.ID, Kind: policies.KindSuspension,
			HuJSON: h.cfg.SuspensionPolicy, Trigger: policies.TriggerSuspend, Actor: KindSuspend})
		setDetail(s, applied(res, map[string]any{"restore_version_id": in.RestoreVersionID}))
		return applyErr(err)
	}); err != nil {
		return err
	}
	if err := h.step(ctx, run, StepRegistrySuspend, func(ctx context.Context, s *jobs.StepRun) error {
		return h.moveStatus(ctx, s, t.ID, tenants.StatusActive, tenants.StatusSuspended)
	}); err != nil {
		return err
	}
	var expired int
	if err := h.step(ctx, run, StepPreAuthExpire, func(ctx context.Context, s *jobs.StepRun) error {
		n, err := h.expirePreAuthKeys(ctx, s, t.ID)
		expired = n
		return err
	}); err != nil {
		return err
	}
	if err := h.step(ctx, run, StepNotify, func(ctx context.Context, s *jobs.StepRun) error {
		return h.finish(ctx, s, in, notifications.TenantSuspended(t.ID, run.ID), audit.Details{"job_id": run.ID,
			"restore_version_id": in.RestoreVersionID})
	}); err != nil {
		return err
	}
	return run.SetOutput(map[string]any{"tenant_id": t.ID, "status": tenants.StatusSuspended,
		"restore_version_id": in.RestoreVersionID, "preauth_keys_expired": expired})
}

// undoSuspend is the compensation of tenant.suspend (/rollback): the tenant back to `active` behind its desired
// policy, in reverse order; the expired pre-auth keys stay expired. Then the audit pair closes with .failed.
func (h *Handler) undoSuspend(ctx context.Context, run *jobs.Run, cause error) error {
	in, err := h.input(run)
	if err != nil {
		return err
	}
	if err := run.CompensateSteps(ctx, map[string]jobs.CompensateFunc{
		StepRegistrySuspend: h.retried(func(ctx context.Context, s jobs.CompensationStep) error {
			return h.undoStatus(ctx, s, in.TenantID, tenants.StatusSuspended, tenants.StatusActive)
		}),
		StepPolicySuspend: h.retried(func(ctx context.Context, _ jobs.CompensationStep) error {
			return h.applyDesired(ctx, in.TenantID, policies.TriggerResume, KindSuspend+" (rollback)")
		}),
	}); err != nil {
		return err
	}
	return h.closeFailed(ctx, in, cause, run.ID)
}

// ---------------------------------------------------------------------------------------------------- tenant.resume

func (h *Handler) resume(ctx context.Context, run *jobs.Run) error {
	in, err := h.input(run)
	if err != nil {
		return err
	}
	t, err := h.tenant(ctx, in.TenantID)
	if err != nil {
		return err
	}
	if t.Status != tenants.StatusSuspended && t.Status != tenants.StatusActive {
		return jobs.Permanent("registry_state", fmt.Errorf("tenant %s is %s", t.ID, t.Status))
	}
	run.SetResource("tenant", t.ID.String())
	var version uuid.UUID
	if err := h.step(ctx, run, StepPolicyResume, func(ctx context.Context, s *jobs.StepRun) error {
		v, err := h.desired(ctx, t.ID)
		if err != nil {
			return err
		}
		version = v
		if err := record(ctx, s, policyResources{VersionID: v}); err != nil {
			return err
		}
		// the desired version rendered with the tables of now (typed or HuJSON — P4-T10), applied as it is: no new
		// version, the desired one stays; the tenant is still suspended here (Suspended registry)
		res, err := h.cfg.Policies.ApplyDesired(ctx, policies.DesiredRequest{TenantID: t.ID, Trigger: policies.TriggerResume,
			Actor: KindResume, Suspended: true})
		setDetail(s, applied(res, map[string]any{"desired_version_id": v, "requested_version_id": in.RestoreVersionID,
			"version_created": res.VersionCreated}))
		return applyErr(err)
	}); err != nil {
		return err
	}
	if err := h.step(ctx, run, StepRegistryResume, func(ctx context.Context, s *jobs.StepRun) error {
		return h.moveStatus(ctx, s, t.ID, tenants.StatusSuspended, tenants.StatusActive)
	}); err != nil {
		return err
	}
	if err := h.step(ctx, run, StepNotify, func(ctx context.Context, s *jobs.StepRun) error {
		return h.finish(ctx, s, in, notifications.TenantResumed(t.ID, run.ID), audit.Details{"job_id": run.ID,
			"version_id": version})
	}); err != nil {
		return err
	}
	return run.SetOutput(map[string]any{"tenant_id": t.ID, "status": tenants.StatusActive, "version_id": version})
}

// undoResume is the compensation of tenant.resume (after a permanent error, or /rollback): the tenant back to
// `suspended` behind the suspension policy, in reverse order; then .failed.
func (h *Handler) undoResume(ctx context.Context, run *jobs.Run, cause error) error {
	in, err := h.input(run)
	if err != nil {
		return err
	}
	if err := run.CompensateSteps(ctx, map[string]jobs.CompensateFunc{
		StepRegistryResume: h.retried(func(ctx context.Context, s jobs.CompensationStep) error {
			return h.undoStatus(ctx, s, in.TenantID, tenants.StatusActive, tenants.StatusSuspended)
		}),
		StepPolicyResume: h.retried(func(ctx context.Context, _ jobs.CompensationStep) error {
			res, err := h.cfg.Policies.Apply(ctx, policies.ApplyRequest{TenantID: in.TenantID,
				Kind: policies.KindSuspension, HuJSON: h.cfg.SuspensionPolicy, Trigger: policies.TriggerSuspend,
				Actor: KindResume + " (rollback)"})
			h.cfg.Logger.Info("tenant.resume compensation: suspension policy applied again", "tenant_id", in.TenantID,
				"application_id", res.ApplicationID, "state", res.State)
			return applyErr(err)
		}),
	}); err != nil {
		return err
	}
	return h.closeFailed(ctx, in, cause, run.ID)
}

// ---------------------------------------------------------------------------------------------------- steps

// moveStatus moves the tenant from → to in one platform transaction, recording BEFORE the change the status it moves
// it from. Already in `to`: done — by an earlier attempt of this step (its record says so), or before the job.
func (h *Handler) moveStatus(ctx context.Context, s *jobs.StepRun, tenantID uuid.UUID, from, to string) error {
	var res statusResources
	found, err := s.Previous(&res)
	if err != nil {
		return err
	}
	t, err := h.tenant(ctx, tenantID)
	if err != nil {
		return err
	}
	switch {
	case t.Status == to:
		if !found {
			res.From = "" // not this job's change: nothing to undo
			if err := record(ctx, s, res); err != nil {
				return err
			}
		}
		setDetail(s, map[string]any{"from": res.From, "to": to, "changed": false})
		return nil
	case t.Status != from:
		return jobs.Permanent("registry_state", fmt.Errorf("tenant %s is %s, not %s", tenantID, t.Status, from))
	}
	if err := record(ctx, s, statusResources{From: from}); err != nil {
		return err
	}
	err = h.cfg.Store.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		_, err := q.TransitionTenantStatus(ctx, sqlcdb.TransitionTenantStatusParams{Status: to, ID: tenantID, FromStatus: from})
		return err
	})
	if errors.Is(err, store.ErrNoRows) {
		return jobs.Transient("registry_changed", fmt.Errorf("tenant %s changed status meanwhile", tenantID))
	}
	if err != nil {
		return dbErr("move the tenant status", err)
	}
	setDetail(s, map[string]any{"from": from, "to": to, "changed": true})
	return nil
}

// undoStatus undoes moveStatus: only a change this job made (its record), only from the status it set.
func (h *Handler) undoStatus(ctx context.Context, s jobs.CompensationStep, tenantID uuid.UUID, current, back string) error {
	var res statusResources
	found, err := s.Decode(&res)
	if err != nil || !found || res.From != back {
		return err
	}
	err = h.cfg.Store.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		_, err := q.TransitionTenantStatus(ctx, sqlcdb.TransitionTenantStatusParams{Status: back, ID: tenantID,
			FromStatus: current})
		return err
	})
	if errors.Is(err, store.ErrNoRows) {
		t, terr := h.tenant(ctx, tenantID)
		switch {
		case terr != nil:
			return terr
		case t.Status == back:
			return nil // undone by an earlier, interrupted compensation
		}
		return jobs.Permanent("registry_state", fmt.Errorf("tenant %s is %s, not %s", tenantID, t.Status, current))
	}
	if err != nil {
		return dbErr("restore the tenant status", err)
	}
	return nil
}

// expirePreAuthKeys expires every pre-auth key of the instance that can still register a node — not expired, and not
// a single-use key already used — then lists them again: none may remain (§11.4). It returns how many it expired.
func (h *Handler) expirePreAuthKeys(ctx context.Context, s *jobs.StepRun, tenantID uuid.UUID) (int, error) {
	cctx, cancel := context.WithTimeout(ctx, h.cfg.CallTimeout)
	defer cancel()
	inst, err := h.cfg.Headscale.ForTenant(cctx, tenantID)
	if err != nil {
		return 0, headscaleErr("ForTenant", err)
	}
	keys, err := inst.ListPreAuthKeys(cctx)
	if err != nil {
		return 0, headscaleErr("ListPreAuthKeys", err)
	}
	now := h.cfg.Now()
	valid := ValidPreAuthKeys(keys, now)
	expired := make([]uint64, 0, len(valid))
	for _, k := range valid {
		if err := inst.ExpirePreAuthKey(cctx, k.ID); err != nil {
			setDetail(s, map[string]any{"listed": len(keys), "valid": len(valid), "expired_ids": expired})
			return len(expired), headscaleErr("ExpirePreAuthKey", err)
		}
		expired = append(expired, k.ID)
	}
	again, err := inst.ListPreAuthKeys(cctx)
	if err != nil {
		return len(expired), headscaleErr("ListPreAuthKeys", err)
	}
	left := ValidPreAuthKeys(again, h.cfg.Now())
	setDetail(s, map[string]any{"listed": len(keys), "valid": len(valid), "expired_ids": expired,
		"still_valid": len(left)})
	if len(left) > 0 {
		// a key issued meanwhile (the status already refuses it at the API) or an expiry not applied: retried
		return len(expired), jobs.Transient("preauthkeys_still_valid",
			fmt.Errorf("%d pre-auth key(s) still valid after expiring %d", len(left), len(expired)))
	}
	return len(expired), nil
}

// ValidPreAuthKeys returns the keys that can still register a node at now: not expired (a key without an expiration
// counts as valid — fail closed), and reusable or not used yet.
func ValidPreAuthKeys(keys []headscale.PreAuthKey, now time.Time) []headscale.PreAuthKey {
	var out []headscale.PreAuthKey
	for _, k := range keys {
		if (k.Expiration.IsZero() || k.Expiration.After(now)) && (k.Reusable || !k.Used) {
			out = append(out, k)
		}
	}
	return out
}

// finish is the last step: the notification of the tenant (deduplicated by its ref — the job), then the audit pair
// closes with .succeeded (once: a re-run finds it finished).
func (h *Handler) finish(ctx context.Context, s *jobs.StepRun, in Input, ev notifications.Event, d audit.Details) error {
	var notified int
	if err := h.cfg.Store.WithTenantJobTx(ctx, in.TenantID, func(tx *store.Tx) error {
		r, err := h.cfg.Notifier.Enqueue(ctx, tx, ev)
		notified = len(r.Notifications)
		return err
	}); err != nil {
		if errors.Is(err, notifications.ErrInvalidEvent) || errors.Is(err, notifications.ErrNoTenant) {
			return jobs.Permanent("notification_invalid", err)
		}
		return dbErr("write the notification", err)
	}
	if err := h.cfg.Store.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		st, err := q.OperationState(ctx, in.Operation.ID)
		if err != nil || st.Finished {
			return err
		}
		return in.Operation.Succeeded(ctx, q, d)
	}); err != nil {
		return dbErr("close the audit operation", err)
	}
	setDetail(s, map[string]any{"notifications": notified, "kind": string(ev.Kind)})
	return nil
}

// closeFailed closes the audit pair with .failed after a compensation (once).
func (h *Handler) closeFailed(ctx context.Context, in Input, cause error, job uuid.UUID) error {
	err := h.cfg.Store.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		st, err := q.OperationState(ctx, in.Operation.ID)
		if err != nil || st.Finished {
			return err
		}
		return in.Operation.Failed(ctx, q, jobs.CodeOf(cause), audit.Details{"job_id": job, "rolled_back": true})
	})
	if err != nil {
		return dbErr("close the audit operation", err)
	}
	return nil
}

// applyDesired applies the tenant's desired version again (the compensation of policy.suspend).
func (h *Handler) applyDesired(ctx context.Context, tenantID uuid.UUID, trigger, actor string) error {
	if _, err := h.desired(ctx, tenantID); err != nil {
		return err
	}
	_, err := h.cfg.Policies.ApplyDesired(ctx, policies.DesiredRequest{TenantID: tenantID, Trigger: trigger, Actor: actor,
		Suspended: true})
	return applyErr(err)
}

// desired reads the tenant's desired policy version (typed or HuJSON — the policy module renders it, P4-T10).
func (h *Handler) desired(ctx context.Context, tenantID uuid.UUID) (uuid.UUID, error) {
	var id uuid.UUID
	err := h.cfg.Store.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		d, err := q.GetTenantPolicyState(ctx, tenantID)
		if err != nil {
			return err
		}
		if d == nil {
			return jobs.Permanent("no_policy_to_restore", fmt.Errorf("tenant %s has no desired policy version", tenantID))
		}
		v, err := q.GetPolicyVersion(ctx, sqlcdb.GetPolicyVersionParams{TenantID: tenantID, ID: *d})
		if err != nil {
			return err
		}
		id = v.ID
		return nil
	})
	var je *jobs.Error
	switch {
	case errors.As(err, &je):
		return id, err
	case errors.Is(err, store.ErrNoRows):
		return id, jobs.Permanent("registry_state", fmt.Errorf("tenant %s or its desired version not found", tenantID))
	case err != nil:
		return id, dbErr("read the desired policy", err)
	}
	return id, nil
}

// ---------------------------------------------------------------------------------------------------- helpers

func (h *Handler) input(run *jobs.Run) (Input, error) {
	var in Input
	if err := run.DecodeInput(&in); err != nil {
		return in, jobs.Permanent("invalid_input", fmt.Errorf("job input unreadable: %w", err))
	}
	if err := in.validate(); err != nil {
		return in, jobs.Permanent("invalid_input", err)
	}
	if run.TenantID == nil || *run.TenantID != in.TenantID {
		return in, jobs.Permanent("invalid_input", errors.New("the job's tenant is not the input's"))
	}
	return in, nil
}

func (h *Handler) tenant(ctx context.Context, id uuid.UUID) (sqlcdb.Tenant, error) {
	var t sqlcdb.Tenant
	err := h.cfg.Store.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		var err error
		t, err = q.GetTenant(ctx, id)
		return err
	})
	if errors.Is(err, store.ErrNoRows) {
		return t, jobs.Permanent("registry_state", fmt.Errorf("tenant %s not found", id))
	}
	if err != nil {
		return t, dbErr("read the tenant", err)
	}
	return t, nil
}

// step runs one step with the retry policy of §11.3 (as tenant.provision): a transient failure is retried in place up
// to StepRetries times with exponential backoff — every try is one attempt of the step —; spent ⇒ jobs.Resumable
// (failed_resumable, no compensation). A permanent failure, a cancellation or the end of ctx is returned at once.
func (h *Handler) step(ctx context.Context, run *jobs.Run, name string, fn func(ctx context.Context, s *jobs.StepRun) error) error {
	for try := 0; ; try++ {
		err := run.Step(ctx, name, fn)
		switch {
		case err == nil:
			return nil
		case jobs.IsPermanent(err), jobs.IsResumable(err), ctx.Err() != nil:
			return err
		case try >= h.cfg.StepRetries:
			return jobs.Resumable(jobs.CodeOf(err), fmt.Errorf("step %s: %d retries spent: %w", name, try, err))
		}
		if serr := sleep(ctx, h.backoff(try+1)); serr != nil {
			return err
		}
	}
}

// retried wraps a compensation with the retry policy of the steps.
func (h *Handler) retried(fn jobs.CompensateFunc) jobs.CompensateFunc {
	return func(ctx context.Context, s jobs.CompensationStep) error {
		for try := 0; ; try++ {
			err := fn(ctx, s)
			switch {
			case err == nil:
				return nil
			case jobs.IsPermanent(err), ctx.Err() != nil, try >= h.cfg.StepRetries:
				return err
			}
			if serr := sleep(ctx, h.backoff(try+1)); serr != nil {
				return err
			}
		}
	}
}

// backoff is the delay before try n (n ≥ 1): RetryBase·2^(n−1), capped at RetryMax, ± 20 %.
func (h *Handler) backoff(n int) time.Duration {
	d := h.cfg.RetryBase
	for i := 1; i < n && d < h.cfg.RetryMax; i++ {
		d *= 2
	}
	d = min(d, h.cfg.RetryMax)
	return time.Duration(float64(d) * (0.8 + 0.4*rand.Float64())) //nolint:gosec // scheduling jitter
}

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// record stores created_resources BEFORE the step acts (§11.3).
func record(ctx context.Context, s *jobs.StepRun, v any) error {
	if err := s.RecordCreated(ctx, v); err != nil {
		var je *jobs.Error
		if errors.As(err, &je) {
			return err
		}
		return jobs.Transient("step_bookkeeping", err)
	}
	return nil
}

// setDetail sets the raw detail of a step (identifiers, codes, hashes — never a secret); a detail that cannot be
// encoded is dropped, never the step.
func setDetail(s *jobs.StepRun, v map[string]any) { _ = s.SetDetail(v) }

// applied is the step detail of a policy application.
func applied(r policies.Result, extra map[string]any) map[string]any {
	d := map[string]any{"application_id": r.ApplicationID, "version_id": r.VersionID, "version": r.Version,
		"state": r.State, "applied_sha256": r.AppliedSHA256, "readback_sha256": r.ReadbackSHA256}
	if r.ErrorCode != "" {
		d["error_code"] = r.ErrorCode
	}
	for k, v := range extra {
		d[k] = v
	}
	return d
}

// applyErr classifies an error of the policy core: refused by Headscale or by the lint, no instance, an invalid
// request ⇒ permanent; unavailable, unknown outcome (re-asserted), lock busy, database ⇒ transient.
func applyErr(err error) error {
	if err == nil {
		return nil
	}
	if le, ok := policies.IsLint(err); ok {
		return jobs.Permanent("policy_lint", fmt.Errorf("lint %s: %s", le.Rule, le.Detail))
	}
	var ae *policies.ApplyError
	if errors.As(err, &ae) {
		switch ae.Code {
		case policies.CodePolicyRejected:
			return jobs.Permanent(ae.Code, err)
		case policies.CodeNoInstance:
			return jobs.Permanent(ae.Code, err)
		}
		return jobs.Transient(ae.Code, err)
	}
	switch {
	case errors.Is(err, policies.ErrNoInstance):
		return jobs.Permanent(policies.CodeNoInstance, err)
	case errors.Is(err, policies.ErrNoDesired):
		return jobs.Permanent("no_policy_to_restore", err)
	case errors.Is(err, policies.ErrDesiredNotApproved):
		return jobs.Permanent("desired_not_approved", err)
	case errors.Is(err, policies.ErrDesiredChanged):
		return jobs.Transient("desired_changed", err)
	case errors.Is(err, policies.ErrInvalidRequest):
		return jobs.Permanent("invalid_request", err)
	case errors.Is(err, store.ErrLockTimeout):
		return jobs.Transient("policy_locked", err)
	}
	return jobs.Transient("policy_unavailable", err)
}

// headscaleErr classifies an adapter error: unavailable, circuit open or no reachable instance ⇒ transient; the rest
// permanent (code headscale_<kind>).
func headscaleErr(op string, err error) error {
	var he *headscale.Error
	switch {
	case errors.As(err, &he) && (he.Kind == headscale.KindUnavailable || he.Kind == headscale.KindCircuitOpen):
		return jobs.Transient("instance_unavailable", fmt.Errorf("%s: %s", op, he.Kind))
	case errors.Is(err, headscale.ErrNoInstance):
		return jobs.Transient("instance_unavailable", fmt.Errorf("%s: no reachable instance", op))
	case errors.As(err, &he):
		return jobs.Permanent("headscale_"+string(he.Kind), fmt.Errorf("%s: %s", op, he.Kind))
	}
	return jobs.Transient("instance_unavailable", fmt.Errorf("%s: %s", op, err.Error()))
}

// dbErr classifies a database error: transient (an error that already carries a job code keeps it).
func dbErr(what string, err error) error {
	var je *jobs.Error
	if errors.As(err, &je) {
		return err
	}
	return jobs.Transient("registry_unavailable", fmt.Errorf("%s: sqlstate %q", what, store.SQLState(err)))
}
