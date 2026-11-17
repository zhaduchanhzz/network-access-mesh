// Package jobs is the background job framework of the Management Plane (§4.2 module `jobs`, §11.3, §13.5; P2-T12).
//
// A job is a row of provisioning_jobs — the business record and the read model of GET /jobs for every job kind —
// carried by a River job that holds nothing but its ID and kind. Enqueue writes both in the caller's transaction
// (store.WithTenantJobTx / WithPlatformJobTx), atomically with the business change. Four keys stay separate (§13.5):
//
//   - request_key — the client's Idempotency-Key: UNIQUE (requested_by, kind, request_key) returns the same job on replay;
//   - dedupe_key — one unfinished job per key (partial unique index on queued/running/compensating/failed_resumable),
//     so a finished job never blocks a new one; the library's own unique jobs are not relied on for this;
//   - lock_key — tenant:<id>:lifecycle for the lifecycle group: taken by the queued → running update itself (partial
//     unique index on running/compensating/failed_resumable); a job that collides snoozes and retries. No advisory lock,
//     no transaction held across Agent/Headscale calls;
//   - the Idempotency-Key store of the API (idempotency_keys, §13.1) — idempotency.go.
//
// The Worker runs the handlers that modules register (jobs imports no business module — §13.6), with explicit timeouts,
// retry with exponential backoff and jitter, failure states per §11.3, alerts (§16.3) and the built-in jobs job.reaper,
// retention.sweep and partition.maintain. Service answers GET /tenants/{t}/jobs[/{id}] and GET /platform/jobs[/{id}].
package jobs

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/riverqueue/river"

	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// Job statuses (provisioning_jobs.status, §6.3).
const (
	StatusQueued          = "queued"
	StatusRunning         = "running"
	StatusFailedResumable = "failed_resumable"
	StatusCompensating    = "compensating"
	StatusRolledBack      = "rolled_back"
	StatusSucceeded       = "succeeded"
	StatusFailed          = "failed"
	StatusCancelled       = "cancelled"
)

// Statuses lists every job status; the first four are unfinished (they hold the dedupe key).
var Statuses = []string{StatusQueued, StatusRunning, StatusCompensating, StatusFailedResumable, StatusSucceeded,
	StatusFailed, StatusCancelled, StatusRolledBack}

// Step statuses (provisioning_job_steps.status — the set fixed by P2-T12).
const (
	StepRunning   = "running"
	StepSucceeded = "succeeded"
	StepFailed    = "failed"
	StepSkipped   = "skipped"
)

// River queues. The lifecycle queue has its own worker slots so a burst of short jobs never delays a lifecycle job.
const (
	QueueLifecycle   = "lifecycle"
	QueueDefault     = "default"
	QueueMaintenance = "maintenance"
)

// Scope says which identifiers a job of a kind carries.
type Scope int

const (
	ScopePlatform Scope = iota // tenant_id NULL (platform job)
	ScopeTenant                // tenant_id required
	ScopeInstance              // tenant_id and instance_id required
	ScopeAny                   // tenant_id optional (notification.send: tenant or platform outbox rows)
)

// LockPolicy is how a kind uses the lifecycle lock tenant:<id>:lifecycle (§11.3, §13.5 (d)).
type LockPolicy int

const (
	LockNone LockPolicy = iota
	// LockHold: lifecycle group (tenant.*, instance.reconfigure/restart/upgrade/restore). A failure ends in
	// failed_resumable, which keeps the lock until /retry or /rollback.
	LockHold
	// LockRelease: instance.backup takes the same lock (no backup while the instance is stopped or changing data) but a
	// failure ends in failed and releases it at once.
	LockRelease
)

// Kind describes one job kind of §13.5. Timeout and WorkerTimeout are worker settings (Config.Kinds may override
// them); the rest is fixed at enqueue time.
type Kind struct {
	Name  string
	Scope Scope
	// Dedupe is the template of dedupe_key: {tenant}, {instance}, {object} (device, IdP or outbox row ID), {slot}
	// (schedule slot, period or date) and {kind} are replaced from the Spec.
	Dedupe      string
	Lock        LockPolicy
	Queue       string
	MaxAttempts int // runs of the handler, the first one included
	// Timeout is the whole-job timeout: timeout_at = first start + Timeout, the handler's context deadline across
	// retries; job.reaper settles a job still running past it (§11.3).
	Timeout time.Duration
	// WorkerTimeout is River's timeout for one attempt — a backstop longer than Timeout. For the lifecycle group it
	// equals RescueStuckJobsAfter (≈ 15 min, §11.3).
	WorkerTimeout time.Duration
}

// LifecycleTimeout is the whole-job timeout of the lifecycle group and LifecycleWorkerTimeout the worker timeout of
// the lifecycle queue, equal to the queue's stuck-job rescue threshold (§11.3: 10 min; ≈ 15 min, set explicitly).
const (
	LifecycleTimeout       = 10 * time.Minute
	LifecycleWorkerTimeout = 15 * time.Minute
)

// DefaultKinds returns the registry of §13.5 with explicit timeouts and attempt limits.
func DefaultKinds() map[string]Kind {
	life := func(name, dedupe string, scope Scope) Kind {
		return Kind{Name: name, Scope: scope, Dedupe: dedupe, Lock: LockHold, Queue: QueueLifecycle, MaxAttempts: 6,
			Timeout: LifecycleTimeout, WorkerTimeout: LifecycleWorkerTimeout}
	}
	other := func(name, dedupe string, scope Scope, queue string, attempts int, timeout time.Duration) Kind {
		return Kind{Name: name, Scope: scope, Dedupe: dedupe, Queue: queue, MaxAttempts: attempts, Timeout: timeout,
			WorkerTimeout: timeout + time.Minute}
	}
	ks := []Kind{
		// lifecycle group: one at a time per tenant (§11.3); 1 run + up to 5 retries with backoff 2 s → 60 s
		life("tenant.provision", "tenant:{tenant}:lifecycle", ScopeTenant),
		life("tenant.suspend", "tenant:{tenant}:lifecycle", ScopeTenant),
		life("tenant.resume", "tenant:{tenant}:lifecycle", ScopeTenant),
		life("tenant.deprovision", "tenant:{tenant}:lifecycle", ScopeTenant),
		life("instance.reconfigure", "instance:{instance}:{kind}", ScopeInstance),
		life("instance.restart", "instance:{instance}:{kind}", ScopeInstance),
		life("instance.upgrade", "instance:{instance}:{kind}", ScopeInstance),
		life("instance.restore", "instance:{instance}:restore", ScopeInstance),
		other("instance.quarantine", "instance:{instance}:quarantine", ScopeInstance, QueueDefault, 6, 5*time.Minute),
		other("instance.release", "instance:{instance}:quarantine", ScopeInstance, QueueDefault, 6, LifecycleTimeout),
		other("apikey.rotate", "instance:{instance}:apikey:{slot}", ScopeInstance, QueueDefault, 5, 5*time.Minute),
		other("backup.purge", "instance:{instance}:purge", ScopeInstance, QueueDefault, 5, 5*time.Minute),
		other("inventory.sync", "instance:{instance}:sync:{slot}", ScopeInstance, QueueDefault, 3, 5*time.Minute),
		other("device.revoke", "device:{object}:revoke", ScopeTenant, QueueDefault, 8, 2*time.Minute),
		other("policy.apply", "tenant:{tenant}:policy.apply", ScopeTenant, QueueDefault, 6, 5*time.Minute),
		other("policy.drift_check", "tenant:{tenant}:policy.drift:{slot}", ScopeTenant, QueueDefault, 3, 2*time.Minute),
		other("instance.reconcile", "instance:{instance}:reconcile:{slot}", ScopeInstance, QueueDefault, 3, 5*time.Minute),
		other("host.reconcile", "host.reconcile:{slot}", ScopePlatform, QueueDefault, 3, 5*time.Minute),
		other("instance.oidc_check", "instance:{instance}:oidc:{slot}", ScopeInstance, QueueDefault, 3, 2*time.Minute),
		other("partition.maintain", "partition.maintain:{slot}", ScopePlatform, QueueMaintenance, 3, 5*time.Minute),
		other("notification.send", "notification:{object}", ScopeAny, QueueDefault, 8, 2*time.Minute),
		other("idp.audit_sync", "idp:{object}:audit:{slot}", ScopeTenant, QueueDefault, 3, 5*time.Minute),
		other("enrollment.reconcile", "tenant:{tenant}:enroll:{slot}", ScopeTenant, QueueDefault, 3, 2*time.Minute),
		other("usage.collect", "tenant:{tenant}:usage:{slot}", ScopeTenant, QueueDefault, 3, 5*time.Minute),
		other("health.probe", "instance:{instance}:health:{slot}", ScopeInstance, QueueDefault, 1, time.Minute),
		other("job.reaper", "job.reaper:{slot}", ScopePlatform, QueueMaintenance, 1, 50*time.Second),
		other("grant.expire", "grant.expire:{slot}", ScopePlatform, QueueMaintenance, 3, 2*time.Minute),
		other("session.gc", "session.gc:{slot}", ScopePlatform, QueueMaintenance, 3, 2*time.Minute),
		other("retention.sweep", "retention.sweep:{slot}", ScopePlatform, QueueMaintenance, 3, 10*time.Minute),
	}
	// instance.backup: holds the lifecycle lock while it runs, releases it on failure (§13.5 (d)).
	backup := other("instance.backup", "instance:{instance}:backup:{slot}", ScopeInstance, QueueDefault, 3, LifecycleTimeout)
	backup.Lock = LockRelease
	ks = append(ks, backup)
	out := make(map[string]Kind, len(ks))
	for _, k := range ks {
		out[k.Name] = k
	}
	return out
}

// registry is the immutable kind table used at enqueue time.
var registry = DefaultKinds()

// KindNames returns the registered kind names, sorted.
func KindNames() []string {
	names := make([]string, 0, len(registry))
	for n := range registry {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// LockKey is the lifecycle lock key of a tenant (§13.5 (d)).
func LockKey(tenantID uuid.UUID) string { return "tenant:" + tenantID.String() + ":lifecycle" }

// Spec is one job to enqueue.
type Spec struct {
	Kind       string
	TenantID   *uuid.UUID // the tenant of the job; nil only for platform kinds
	InstanceID *uuid.UUID // instance kinds
	Object     string     // {object} of the dedupe key: device, IdP or outbox row ID
	Slot       string     // {slot} of the dedupe key: schedule slot, period or date
	// Input is the job's parameters as a JSON object: identifiers and settings, never a secret (only secret references —
	// §11.3, ADR-21). nil ⇒ {}.
	Input       any
	RequestKey  string     // the Idempotency-Key of the API request ("" = none)
	RequestedBy *uuid.UUID // identity that asked (nil = system)
	Resource    *Resource  // the resource the job creates or acts on (Job.resource)
	MaxAttempts int        // 0 ⇒ the kind's default
}

// Enqueued is the result of Enqueue.
type Enqueued struct {
	Job Job
	// Created is false when no new job was written: the job of the same request key (a replayed request), or the
	// unfinished job of the same kind holding the dedupe key, was returned instead.
	Created bool
}

var (
	// ErrUnknownKind: the kind is not in the §13.5 registry.
	ErrUnknownKind = errors.New("jobs: unknown job kind")
	// ErrInvalidSpec: identifiers missing for the kind's scope, or an input that is not a JSON object.
	ErrInvalidSpec = errors.New("jobs: invalid job spec")
	// ErrDedupeConflict: an unfinished job of another kind holds the dedupe key — for example tenant.suspend while a
	// tenant.provision of the same tenant is still unfinished (one lifecycle job per tenant, §13.5) ⇒ 409.
	ErrDedupeConflict = errors.New("jobs: an unfinished job of another kind holds the same dedupe key")
	// ErrRequestKeyReuse: the request key already names a job with other parameters ⇒ 422 idempotency_key_reuse.
	ErrRequestKeyReuse = errors.New("jobs: request key already used for a different job")
)

// queueSlack is how many more attempts River allows than the business limit, for rescues and no-op deliveries: the
// framework itself decides when a job has failed for good (and cancels its River job).
const queueSlack = 2

// Enqueue writes the job and its River job in tx — the caller's transaction, so the job exists if and only if the
// business change commits (§13.5).
func Enqueue(ctx context.Context, tx *store.Tx, s Spec) (Enqueued, error) {
	k, ok := registry[s.Kind]
	if !ok {
		return Enqueued{}, fmt.Errorf("%w: %q", ErrUnknownKind, s.Kind)
	}
	if err := checkScope(k, s); err != nil {
		return Enqueued{}, err
	}
	dedupe, err := k.dedupeKey(s)
	if err != nil {
		return Enqueued{}, err
	}
	input, err := marshalObject(s.Input)
	if err != nil {
		return Enqueued{}, err
	}
	p := sqlcdb.InsertJobParams{
		TenantID: s.TenantID, InstanceID: s.InstanceID, Kind: k.Name, DedupeKey: &dedupe,
		MaxAttempts: int32(k.MaxAttempts), Input: input, RequestedBy: s.RequestedBy, //nolint:gosec // small registry values
	}
	if s.MaxAttempts > 0 {
		p.MaxAttempts = int32(min(s.MaxAttempts, 100)) //nolint:gosec // bounded
	}
	if s.RequestKey != "" {
		p.RequestKey = &s.RequestKey
	}
	if k.Lock != LockNone {
		lk := LockKey(*s.TenantID)
		p.LockKey = &lk
	}
	if s.Resource != nil {
		p.ResourceType, p.ResourceID = &s.Resource.Type, &s.Resource.ID
	}
	for range 3 {
		row, err := tx.Q.InsertJob(ctx, p)
		if err == nil {
			qid, err := tx.InsertQueueJob(ctx, queueArgs{JobID: row.ID, JobKind: k.Name},
				&river.InsertOpts{Queue: k.Queue, MaxAttempts: int(p.MaxAttempts) + queueSlack})
			if err != nil {
				return Enqueued{}, err
			}
			if err := tx.Q.SetJobQueueID(ctx, sqlcdb.SetJobQueueIDParams{QueueJobID: qid, ID: row.ID}); err != nil {
				return Enqueued{}, fmt.Errorf("jobs: enqueue %s: %w", k.Name, err)
			}
			return Enqueued{Job: project(row, nil), Created: true}, nil
		}
		if !errors.Is(err, store.ErrNoRows) {
			return Enqueued{}, fmt.Errorf("jobs: enqueue %s: %w", k.Name, err)
		}
		// Conflict. The request key first: a replayed request gets the job it created.
		if s.RequestKey != "" && s.RequestedBy != nil {
			prev, err := tx.Q.GetJobByRequestKey(ctx, sqlcdb.GetJobByRequestKeyParams{
				RequestedBy: *s.RequestedBy, Kind: k.Name, RequestKey: s.RequestKey})
			switch {
			case err == nil && sameRequest(prev, p):
				return Enqueued{Job: project(prev, nil)}, nil
			case err == nil:
				return Enqueued{Job: project(prev, nil)}, ErrRequestKeyReuse
			case !errors.Is(err, store.ErrNoRows):
				return Enqueued{}, fmt.Errorf("jobs: enqueue %s: %w", k.Name, err)
			}
		}
		active, err := tx.Q.GetActiveJobByDedupeKey(ctx, dedupe)
		switch {
		case err == nil && active.Kind == k.Name:
			return Enqueued{Job: project(active, nil)}, nil
		case err == nil:
			return Enqueued{Job: project(active, nil)}, fmt.Errorf("%w (%s, job %s)", ErrDedupeConflict, active.Kind, active.ID)
		case !errors.Is(err, store.ErrNoRows):
			return Enqueued{}, fmt.Errorf("jobs: enqueue %s: %w", k.Name, err)
		}
		// The conflicting job finished in between: try again.
	}
	if s.RequestKey != "" {
		return Enqueued{}, ErrRequestKeyReuse // held by a job this scope cannot see
	}
	return Enqueued{}, fmt.Errorf("jobs: enqueue %s: conflicting job not visible in this scope", k.Name)
}

func checkScope(k Kind, s Spec) error {
	switch {
	case k.Scope == ScopePlatform && (s.TenantID != nil || s.InstanceID != nil):
		return fmt.Errorf("%w: %s is a platform job (no tenant)", ErrInvalidSpec, k.Name)
	case (k.Scope == ScopeTenant || k.Scope == ScopeInstance) && (s.TenantID == nil || *s.TenantID == uuid.Nil):
		return fmt.Errorf("%w: %s needs a tenant", ErrInvalidSpec, k.Name)
	case k.Scope == ScopeInstance && (s.InstanceID == nil || *s.InstanceID == uuid.Nil):
		return fmt.Errorf("%w: %s needs an instance", ErrInvalidSpec, k.Name)
	case s.Resource != nil && (s.Resource.Type == "" || s.Resource.ID == ""):
		return fmt.Errorf("%w: resource needs a type and an id", ErrInvalidSpec)
	}
	return nil
}

// dedupeKey fills the kind's template; every placeholder it uses must have a value.
func (k Kind) dedupeKey(s Spec) (string, error) {
	vals := map[string]string{"{kind}": k.Name, "{object}": s.Object, "{slot}": s.Slot}
	if s.TenantID != nil {
		vals["{tenant}"] = s.TenantID.String()
	}
	if s.InstanceID != nil {
		vals["{instance}"] = s.InstanceID.String()
	}
	key := k.Dedupe
	for _, ph := range []string{"{kind}", "{tenant}", "{instance}", "{object}", "{slot}"} {
		if !strings.Contains(key, ph) {
			continue
		}
		v := vals[ph]
		if v == "" || strings.ContainsAny(v, " \t\n") || len(v) > 128 {
			return "", fmt.Errorf("%w: %s needs a valid %s for its dedupe key", ErrInvalidSpec, k.Name, ph)
		}
		key = strings.ReplaceAll(key, ph, v)
	}
	return key, nil
}

// marshalObject encodes v as a JSON object (nil ⇒ {}).
func marshalObject(v any) ([]byte, error) {
	if v == nil {
		return []byte(`{}`), nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("%w: input: %w", ErrInvalidSpec, err)
	}
	if t := bytes.TrimSpace(b); len(t) == 0 || t[0] != '{' {
		return nil, fmt.Errorf("%w: input must be a JSON object", ErrInvalidSpec)
	}
	return b, nil
}

// sameRequest reports whether an existing job was created by the same request: same tenant, instance and input (JSON
// compared by value — jsonb reorders keys).
func sameRequest(prev sqlcdb.ProvisioningJob, p sqlcdb.InsertJobParams) bool {
	if !equalUUID(prev.TenantID, p.TenantID) || !equalUUID(prev.InstanceID, p.InstanceID) {
		return false
	}
	var a, b any
	if json.Unmarshal(prev.Input, &a) != nil || json.Unmarshal(p.Input, &b) != nil {
		return false
	}
	return reflect.DeepEqual(a, b)
}

func equalUUID(a, b *uuid.UUID) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}
