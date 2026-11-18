package orchestrator

// The request side of instance.restart and instance.upgrade (P3-T13a): POST /platform/instances/{instanceId}/restart
// (platform.instance:operate) and /upgrade (platform.instance:upgrade — §8.5) through InstanceOpsService, the internal
// entry points EnqueueRestart / EnqueueUpgrade (a transaction of the caller), and the upgrade wave of
// `meshguard-worker admin upgrade-wave` (RunUpgradeWave: a canary first, then the rest with a bounded number of
// unfinished upgrades, stopping at the first failure — §11.4 "canary trước, rồi từng nhóm").

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
)

// Operation ids of the API (Idempotency-Key scope).
const (
	RestartOperation = "restartPlatformInstance"
	UpgradeOperation = "upgradePlatformInstance"
)

// OpsRequest is one restart or upgrade to enqueue.
type OpsRequest struct {
	TenantID, InstanceID uuid.UUID  // TenantID nil: any tenant (a platform caller)
	ImageDigest          string     // upgrade: the target (sha256:<64 hex>)
	RequestedBy          *uuid.UUID // the identity that asked (nil = system: the upgrade wave)
	RequestKey           string     // the Idempotency-Key of the API request ("" = none)
	Source               string     // SourcePlatform or SourceWave
	Wave                 string     // the wave id (SourceWave)
}

// EnqueueRestart is the internal entry point of instance.restart: in the caller's transaction it checks the instance —
// running (quarantined ⇒ conflict), tenant active or suspended —, returns the unfinished restart of the instance
// (created = false — §13.5 (b): two requests in a row while one waits are one restart; a request after it finished is
// a second restart), otherwise opens the audit operation and enqueues the job (lifecycle group).
func EnqueueRestart(ctx context.Context, tx *store.Tx, req OpsRequest) (jobs.Job, bool, error) {
	return enqueueOps(ctx, tx, RestartKind, req)
}

// EnqueueUpgrade is the internal entry point of instance.upgrade: as EnqueueRestart, plus a configuration version
// recorded by the orchestrator (no_config_version), a target other than the running image (already_on_target); the
// unfinished upgrade of the instance towards the same image is returned, towards another ⇒ conflict upgrade_in_progress.
func EnqueueUpgrade(ctx context.Context, tx *store.Tx, req OpsRequest) (jobs.Job, bool, error) {
	if !digestRE.MatchString(req.ImageDigest) {
		return jobs.Job{}, false, invalid("image_digest", "invalid_digest")
	}
	return enqueueOps(ctx, tx, UpgradeKind, req)
}

func enqueueOps(ctx context.Context, tx *store.Tx, kind string, req OpsRequest) (jobs.Job, bool, error) {
	inst, err := tx.Q.GetTenantInstance(ctx, req.InstanceID)
	if errors.Is(err, store.ErrNoRows) || (err == nil && req.TenantID != uuid.Nil && inst.TenantID != req.TenantID) {
		return jobs.Job{}, false, ErrNotFound
	}
	if err != nil {
		return jobs.Job{}, false, err
	}
	switch {
	case inst.Status == tenants.InstanceQuarantined:
		return jobs.Job{}, false, conflict("instance_quarantined")
	case inst.Status != tenants.InstanceRunning:
		return jobs.Job{}, false, conflict("instance_not_running")
	case kind == UpgradeKind && inst.ConfigVersionID == nil:
		return jobs.Job{}, false, conflict("no_config_version")
	case kind == UpgradeKind && inst.ImageDigest == req.ImageDigest:
		return jobs.Job{}, false, conflict("already_on_target")
	}
	t, err := tx.Q.GetTenant(ctx, inst.TenantID)
	if err != nil {
		return jobs.Job{}, false, notFound(err)
	}
	if t.Status != tenants.StatusActive && t.Status != tenants.StatusSuspended {
		return jobs.Job{}, false, conflict("tenant_not_active")
	}
	spec := jobs.Spec{Kind: kind, TenantID: &inst.TenantID, InstanceID: &inst.ID, RequestKey: req.RequestKey,
		RequestedBy: req.RequestedBy, Resource: &jobs.Resource{Type: "instance", ID: inst.ID.String()}}
	dedupe, err := jobs.DedupeKey(spec)
	if err != nil {
		return jobs.Job{}, false, err
	}
	active, err := tx.Q.GetActiveJobByDedupeKey(ctx, dedupe)
	switch {
	case err == nil:
		var prev OpsInput
		if active.Kind == kind && json.Unmarshal(active.Input, &prev) == nil && prev.ImageDigest == req.ImageDigest {
			j, err := jobs.ProjectTx(ctx, tx.Q, active.ID)
			return j, false, err
		}
		return jobs.Job{}, false, conflict("upgrade_in_progress")
	case !errors.Is(err, store.ErrNoRows):
		return jobs.Job{}, false, err
	}
	action, details := ActionInstanceRestart, audit.Details{}
	if kind == UpgradeKind {
		action = ActionInstanceUpgrade
		details["image_digest"], details["previous_image_digest"] = req.ImageDigest, inst.ImageDigest
	}
	source := req.Source
	if source == "" {
		source = SourcePlatform
	}
	details["tenant_id"], details["instance_id"], details["source"] = inst.TenantID, inst.ID, source
	if req.Wave != "" {
		details["wave"] = req.Wave
	}
	op, err := audit.Requested(ctx, tx.Q, audit.Event{Action: action, ResourceType: "instance", ResourceID: inst.ID.String(),
		Details: details})
	if err != nil {
		return jobs.Job{}, false, err
	}
	spec.Input = OpsInput{TenantID: inst.TenantID, InstanceID: inst.ID, ImageDigest: req.ImageDigest, Source: source,
		RequestedBy: req.RequestedBy, Wave: req.Wave, Operation: op}
	enq, err := jobs.Enqueue(ctx, tx, spec)
	if err != nil {
		if errors.Is(err, jobs.ErrRequestKeyReuse) {
			return jobs.Job{}, false, &CreateError{Kind: ErrIdempotencyKeyReuse, Reason: "idempotency_key_reuse"}
		}
		return jobs.Job{}, false, err
	}
	if !enq.Created {
		// another request enqueued the same kind between the check and the insert: this transaction rolls back
		return jobs.Job{}, false, conflict("operation_in_progress")
	}
	audit.HandOff(ctx, op)
	j, err := jobs.ProjectTx(ctx, tx.Q, enq.Job.ID)
	return j, true, err
}

// InstanceOpsService serves POST /platform/instances/{instanceId}/restart and /upgrade in the api process.
type InstanceOpsService struct {
	st *store.Store
}

// NewInstanceOpsService returns the API side of instance.restart and instance.upgrade on the api's store.
func NewInstanceOpsService(st *store.Store) *InstanceOpsService { return &InstanceOpsService{st: st} }

// Restart enqueues the restart of an instance under the request's Idempotency-Key (§13.1).
func (s *InstanceOpsService) Restart(ctx context.Context, actor, instanceID uuid.UUID, idem *Idempotency) (Reconfigured, error) {
	return s.request(ctx, RestartOperation, actor, idem, func(tx *store.Tx, req OpsRequest) (jobs.Job, bool, error) {
		req.InstanceID = instanceID
		return EnqueueRestart(ctx, tx, req)
	})
}

// Upgrade enqueues the upgrade of an instance to an image of the Host Agent's allowlist (§11.4) under the request's
// Idempotency-Key.
func (s *InstanceOpsService) Upgrade(ctx context.Context, actor, instanceID uuid.UUID, digest string, idem *Idempotency) (Reconfigured, error) {
	if !digestRE.MatchString(digest) {
		return Reconfigured{}, invalid("image_digest", "invalid_digest")
	}
	return s.request(ctx, UpgradeOperation, actor, idem, func(tx *store.Tx, req OpsRequest) (jobs.Job, bool, error) {
		req.InstanceID, req.ImageDigest = instanceID, digest
		return EnqueueUpgrade(ctx, tx, req)
	})
}

func (s *InstanceOpsService) request(ctx context.Context, operation string, actor uuid.UUID, idem *Idempotency,
	enqueue func(tx *store.Tx, req OpsRequest) (jobs.Job, bool, error)) (Reconfigured, error) {
	if actor == uuid.Nil {
		return Reconfigured{}, errors.New("orchestrator: " + operation + ": no actor")
	}
	var key *jobs.IdempotencyKey
	if idem != nil {
		key = &jobs.IdempotencyKey{IdentityID: actor, OperationID: operation, Key: idem.Key}
		replay, err := beginIdempotent(ctx, s.st, *key, idem.Hash)
		if err != nil {
			return Reconfigured{}, err
		}
		if replay != nil {
			return Reconfigured{Job: *replay, Replayed: true}, nil
		}
	}
	var out Reconfigured
	err := s.st.WithPlatformJobTx(ctx, func(tx *store.Tx) error {
		req := OpsRequest{RequestedBy: &actor, Source: SourcePlatform}
		if idem != nil {
			req.RequestKey = idem.Key
		}
		j, created, err := enqueue(tx, req)
		if err != nil {
			return err
		}
		out = Reconfigured{Job: j, Created: created}
		if key == nil {
			return nil
		}
		body, err := json.Marshal(j)
		if err != nil {
			return err
		}
		return jobs.CompleteIdempotent(ctx, tx.Q, *key, idem.Hash, jobs.StoredResponse{Status: 202, Body: body,
			Resource: &jobs.Resource{Type: "job", ID: j.ID.String()}})
	})
	if err != nil && key != nil {
		_ = s.st.WithPlatformTx(context.WithoutCancel(ctx), func(q *sqlcdb.Queries) error {
			return jobs.FailIdempotent(ctx, q, *key, idem.Hash)
		})
	}
	if err != nil {
		return Reconfigured{}, err
	}
	return out, nil
}

// failCancelledOps closes the audit operation of a restart or upgrade cancelled before it ran (Control.Cancel).
func failCancelledOps(ctx context.Context, tx *store.Tx, rec sqlcdb.ProvisioningJob) error {
	var in OpsInput
	if err := json.Unmarshal(rec.Input, &in); err != nil || in.Operation.ID == uuid.Nil {
		return nil //nolint:nilerr // an unreadable input has no operation to close
	}
	done, err := operationFinished(ctx, tx.Q, in.Operation)
	if err != nil || done {
		return err
	}
	return in.Operation.Failed(ctx, tx.Q, jobs.CodeCancelled, audit.Details{"job_id": rec.ID, "cancelled": true,
		"instance_id": in.InstanceID, "tenant_id": in.TenantID})
}

// ---------------------------------------------------------------------------------------------------- upgrade wave

// WaveConfig is one upgrade wave (`meshguard-worker admin upgrade-wave`).
type WaveConfig struct {
	Store *store.Store
	// ImageDigest is the target of every upgrade of the wave.
	ImageDigest string
	// Canary is upgraded first, alone; the wave goes on only when it succeeded (uuid.Nil: the first instance of the list).
	Canary uuid.UUID
	// Instances are the instances of the wave after the canary; All selects every running instance (not quarantined)
	// whose image is not the target yet, in the order of their id.
	Instances []uuid.UUID
	All       bool
	// MaxParallel bounds the unfinished upgrades of the wave (1..20; default 1); Poll the interval of the status checks
	// (default 5 s); JobTimeout how long one upgrade may stay unfinished (default 20 min).
	MaxParallel int
	Poll        time.Duration
	JobTimeout  time.Duration
	// ID names the wave in the jobs' input and the audit (default a new UUID); DryRun lists the plan and enqueues nothing.
	ID     string
	DryRun bool
	// Progress receives one line per event (enqueued, finished, skipped); nil: discarded.
	Progress func(WaveEvent)
	Now      func() time.Time
}

// WaveEvent is one event of a wave.
type WaveEvent struct {
	Instance uuid.UUID `json:"instance_id"`
	Phase    string    `json:"phase"` // canary | wave
	Event    string    `json:"event"` // planned | skipped | enqueued | succeeded | failed | refused
	JobID    uuid.UUID `json:"job_id,omitzero"`
	Status   string    `json:"status,omitempty"`
	Code     string    `json:"code,omitempty"`
}

// WaveReport is the outcome of a wave.
type WaveReport struct {
	Wave      string      `json:"wave"`
	Image     string      `json:"image_digest"`
	Canary    uuid.UUID   `json:"canary"`
	Planned   int         `json:"planned"`
	Succeeded int         `json:"succeeded"`
	Skipped   int         `json:"skipped"`
	Stopped   bool        `json:"stopped"` // a failure stopped the wave: the instances after it were not enqueued
	Failed    []WaveEvent `json:"failed,omitempty"`
}

// ErrWaveStopped is the error of a wave stopped by a failed (or refused) upgrade.
var ErrWaveStopped = errors.New("orchestrator: the upgrade wave stopped at a failure")

// RunUpgradeWave runs a wave: the canary alone, then the rest with at most MaxParallel unfinished upgrades; the first
// upgrade that does not succeed (or cannot be enqueued) stops the wave — no further instance is enqueued, the ones in
// flight are awaited. An instance already on the target is skipped. Each upgrade is an ordinary instance.upgrade job
// run by the workers (source admin_wave, audit actor system "upgrade-wave").
func RunUpgradeWave(ctx context.Context, cfg WaveConfig) (WaveReport, error) {
	if cfg.Store == nil || !digestRE.MatchString(cfg.ImageDigest) {
		return WaveReport{}, errors.New("orchestrator: a wave needs the store and a target digest sha256:<64 hex>")
	}
	if cfg.MaxParallel <= 0 {
		cfg.MaxParallel = 1
	}
	if cfg.MaxParallel > 20 {
		return WaveReport{}, errors.New("orchestrator: --max-parallel is at most 20")
	}
	if cfg.Poll <= 0 {
		cfg.Poll = 5 * time.Second
	}
	if cfg.JobTimeout <= 0 {
		cfg.JobTimeout = 20 * time.Minute
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.ID == "" {
		cfg.ID = uuid.NewString()
	}
	emit := func(e WaveEvent) {
		if cfg.Progress != nil {
			cfg.Progress(e)
		}
	}
	list, err := waveList(ctx, cfg)
	if err != nil {
		return WaveReport{}, err
	}
	rep := WaveReport{Wave: cfg.ID, Image: cfg.ImageDigest}
	if len(list) == 0 {
		return rep, nil
	}
	canary := list[0]
	if cfg.Canary != uuid.Nil {
		canary = cfg.Canary
		list = slices.DeleteFunc(list, func(id uuid.UUID) bool { return id == canary })
	} else {
		list = list[1:]
	}
	rep.Canary, rep.Planned = canary, 1+len(list)
	if cfg.DryRun {
		emit(WaveEvent{Instance: canary, Phase: "canary", Event: "planned"})
		for _, id := range list {
			emit(WaveEvent{Instance: id, Phase: "wave", Event: "planned"})
		}
		return rep, nil
	}
	w := &wave{cfg: cfg, rep: &rep, emit: emit}
	if !w.one(ctx, canary, "canary") {
		rep.Stopped = rep.Stopped || len(list) > 0
		return rep, ErrWaveStopped
	}
	if err := w.rest(ctx, list); err != nil {
		return rep, err
	}
	return rep, nil
}

type wave struct {
	cfg  WaveConfig
	rep  *WaveReport
	emit func(WaveEvent)
}

type inflight struct {
	instance uuid.UUID
	job      uuid.UUID
	since    time.Time
}

// one upgrades one instance and waits for its job: true when it succeeded (or was skipped).
func (w *wave) one(ctx context.Context, id uuid.UUID, phase string) bool {
	job, skipped, ev := w.enqueue(ctx, id, phase)
	if skipped {
		return true
	}
	if job == uuid.Nil {
		w.rep.Failed = append(w.rep.Failed, ev)
		return false
	}
	f := inflight{instance: id, job: job, since: w.cfg.Now()}
	for {
		done, ev := w.check(ctx, f, phase)
		if done {
			return ev.Event == "succeeded"
		}
		if err := sleep(ctx, w.cfg.Poll); err != nil {
			w.rep.Failed = append(w.rep.Failed, WaveEvent{Instance: id, Phase: phase, Event: "failed", JobID: job, Code: "interrupted"})
			return false
		}
	}
}

// rest runs the instances after the canary with at most MaxParallel unfinished upgrades, stopping at the first failure.
func (w *wave) rest(ctx context.Context, list []uuid.UUID) error {
	var running []inflight
	next, stopped := 0, false
	for next < len(list) || len(running) > 0 {
		for !stopped && next < len(list) && len(running) < w.cfg.MaxParallel {
			id := list[next]
			next++
			job, skipped, ev := w.enqueue(ctx, id, "wave")
			switch {
			case skipped:
			case job == uuid.Nil:
				w.rep.Failed, stopped = append(w.rep.Failed, ev), true
			default:
				running = append(running, inflight{instance: id, job: job, since: w.cfg.Now()})
			}
		}
		if len(running) == 0 {
			break
		}
		if err := sleep(ctx, w.cfg.Poll); err != nil {
			return err
		}
		kept := running[:0]
		for _, f := range running {
			done, ev := w.check(ctx, f, "wave")
			switch {
			case !done:
				kept = append(kept, f)
			case ev.Event != "succeeded":
				stopped = true
			}
		}
		running = kept
	}
	if stopped {
		w.rep.Stopped = next < len(list) || w.rep.Stopped
		return ErrWaveStopped
	}
	return nil
}

// enqueue enqueues the upgrade of one instance (system actor, source admin_wave): skipped when it already runs the
// target; job uuid.Nil with a refused event when it cannot be enqueued.
func (w *wave) enqueue(ctx context.Context, id uuid.UUID, phase string) (uuid.UUID, bool, WaveEvent) {
	actx := audit.WithRequest(ctx, &audit.Request{Action: ActionInstanceUpgrade, ActorType: audit.ActorSystem,
		ActorDisplay: "meshguard-worker admin upgrade-wave", RequestID: "wave-" + w.cfg.ID})
	var job jobs.Job
	err := w.cfg.Store.WithPlatformJobTx(actx, func(tx *store.Tx) error {
		var err error
		job, _, err = EnqueueUpgrade(actx, tx, OpsRequest{InstanceID: id, ImageDigest: w.cfg.ImageDigest, Source: SourceWave, Wave: w.cfg.ID})
		return err
	})
	var ce *CreateError
	switch {
	case err == nil:
		ev := WaveEvent{Instance: id, Phase: phase, Event: "enqueued", JobID: job.ID, Status: job.Status}
		w.emit(ev)
		return job.ID, false, ev
	case errors.As(err, &ce) && ce.Reason == "already_on_target":
		w.rep.Skipped++
		ev := WaveEvent{Instance: id, Phase: phase, Event: "skipped", Code: ce.Reason}
		w.emit(ev)
		return uuid.Nil, true, ev
	case errors.As(err, &ce):
		ev := WaveEvent{Instance: id, Phase: phase, Event: "refused", Code: ce.Reason}
		w.emit(ev)
		return uuid.Nil, false, ev
	case errors.Is(err, ErrNotFound):
		ev := WaveEvent{Instance: id, Phase: phase, Event: "refused", Code: "instance_not_found"}
		w.emit(ev)
		return uuid.Nil, false, ev
	}
	ev := WaveEvent{Instance: id, Phase: phase, Event: "refused", Code: "enqueue_failed"}
	w.emit(ev)
	return uuid.Nil, false, ev
}

// check reads the job of one in-flight upgrade: done when it finished (succeeded, or anything else — a failure), or
// when it stayed unfinished longer than JobTimeout (failed_resumable counts as a failure: the wave stops).
func (w *wave) check(ctx context.Context, f inflight, phase string) (bool, WaveEvent) {
	var rec sqlcdb.ProvisioningJob
	err := w.cfg.Store.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		var err error
		rec, err = q.GetJob(ctx, f.job)
		return err
	})
	ev := WaveEvent{Instance: f.instance, Phase: phase, JobID: f.job}
	switch {
	case err != nil:
		return false, ev // read again at the next poll
	case rec.Status == jobs.StatusSucceeded:
		w.rep.Succeeded++
		ev.Event, ev.Status = "succeeded", rec.Status
		w.emit(ev)
		return true, ev
	case rec.Status == jobs.StatusQueued || rec.Status == jobs.StatusRunning || rec.Status == jobs.StatusCompensating:
		if w.cfg.Now().Sub(f.since) < w.cfg.JobTimeout {
			return false, ev
		}
		ev.Code = "timeout"
	}
	ev.Event, ev.Status = "failed", rec.Status
	if ev.Code == "" {
		var e struct {
			Code string `json:"code"`
		}
		if len(rec.Error) > 0 && json.Unmarshal(rec.Error, &e) == nil {
			ev.Code = e.Code
		}
	}
	w.rep.Failed = append(w.rep.Failed, ev)
	w.emit(ev)
	return true, ev
}

// waveList is the explicit list (deduplicated, in order) or, with All, every running instance not on the target.
func waveList(ctx context.Context, cfg WaveConfig) ([]uuid.UUID, error) {
	if !cfg.All {
		var out []uuid.UUID
		if cfg.Canary != uuid.Nil {
			out = append(out, cfg.Canary)
		}
		for _, id := range cfg.Instances {
			if !slices.Contains(out, id) {
				out = append(out, id)
			}
		}
		if len(out) == 0 {
			return nil, errors.New("orchestrator: a wave needs --canary, --instances or --all")
		}
		return out, nil
	}
	var out []uuid.UUID
	err := cfg.Store.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		rows, err := q.ListUpgradeCandidates(ctx, cfg.ImageDigest)
		if err != nil {
			return err
		}
		out = rows
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("orchestrator: list the instances of the wave: %w", err)
	}
	if cfg.Canary != uuid.Nil && !slices.Contains(out, cfg.Canary) {
		out = append([]uuid.UUID{cfg.Canary}, out...)
	}
	return out, nil
}
