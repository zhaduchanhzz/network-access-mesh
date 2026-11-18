package quarantine

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
)

// Job kinds (§13.5).
const (
	KindQuarantine = "instance.quarantine"
	KindRelease    = "instance.release"
	// KindDeprovision is not stopped by the step gate (Gate).
	KindDeprovision = "tenant.deprovision"
)

// Steps (provisioning_job_steps.name).
const (
	StepValidate = "validate"
	StepRegistry = "registry.quarantine"
	StepIsolate  = "instance.isolate"
	StepVerify   = "instance.verify"
	StepNotify   = "notify"
	StepPrepare  = "release.prepare"
	StepRelease  = "instance.release"
	StepStarting = "registry.starting"
	StepAttach   = "edge.attach"
	StepGate     = "poststart.gate"
	StepRunning  = "registry.release"
)

// QuarantineSteps and ReleaseSteps list the steps of each kind in order (the first two of a quarantine and the first
// of a release run in the API).
var (
	QuarantineSteps = []string{StepValidate, StepRegistry, StepIsolate, StepVerify, StepNotify}
	ReleaseSteps    = []string{StepValidate, StepPrepare, StepRelease, StepStarting, StepAttach, StepGate, StepRunning, StepNotify}
)

// Audit actions (x-audit-action): the paired operations .requested → .succeeded / .failed.
const (
	ActionQuarantine = "platform.instance.quarantine"
	ActionRelease    = "platform.instance.release"
)

// Approval of a release (§8.5: platform.instance:release is 2P for every role).
const (
	ReleaseApprovalAction = "platform.instance.release" // approval_requests.action
	ReleaseResourceType   = "instance"
	ReleasePermission     = "platform.instance:release"
)

// Operation ids of the API (Idempotency-Key scope — §13.1).
const (
	QuarantineOperation = "quarantinePlatformInstance"
	ReleaseOperation    = "releasePlatformInstance"
)

// Security event kinds (platform scope) and their source.
const (
	EventQuarantined          = "instance.quarantined"           // critical — at the request (API)
	EventQuarantineIncomplete = "instance.quarantine_incomplete" // critical — the job could not isolate the instance
	EventReleased             = "instance.released"              // high — the instance serves again
	EventReleaseFailed        = "instance.release_failed"        // high — the release stopped, isolated again
	EventStartGuard           = "instance.start_guard_failed"    // critical — the start guard refused the release
	EventPostStartGate        = "instance.post_start_gate_failed"
	Source                    = "quarantine"
)

// MaxReason bounds the reason of a quarantine (characters).
const MaxReason = 1000

// Input is the input of instance.quarantine: identifiers, the status before the quarantine, the reason, the audit
// operation the job closes.
type Input struct {
	TenantID   uuid.UUID       `json:"tenant_id"`
	InstanceID uuid.UUID       `json:"instance_id"`
	Slug       string          `json:"slug"`
	From       string          `json:"from"`
	Reason     string          `json:"reason"`
	Operation  audit.Operation `json:"operation"`
}

func (in Input) validate() error {
	if in.TenantID == uuid.Nil || in.InstanceID == uuid.Nil || in.Slug == "" || in.Operation.ID == uuid.Nil {
		return errors.New("tenant, instance, slug or audit operation missing")
	}
	return nil
}

// ReleaseInput is the input of instance.release.
type ReleaseInput struct {
	TenantID   uuid.UUID       `json:"tenant_id"`
	InstanceID uuid.UUID       `json:"instance_id"`
	Slug       string          `json:"slug"`
	ApprovalID uuid.UUID       `json:"approval_id"`
	Operation  audit.Operation `json:"operation"`
}

func (in ReleaseInput) validate() error {
	if in.TenantID == uuid.Nil || in.InstanceID == uuid.Nil || in.Slug == "" || in.ApprovalID == uuid.Nil ||
		in.Operation.ID == uuid.Nil {
		return errors.New("tenant, instance, slug, approval or audit operation missing")
	}
	return nil
}

// ReleasePayload is the payload of a release approval request (canonical JSON shown to the approver, the only input of
// the execution — §6.3 approval_requests).
type ReleasePayload struct {
	InstanceID uuid.UUID `json:"instance_id"`
	TenantID   uuid.UUID `json:"tenant_id"`
}

// Validate implements approvals.Validator.
func (p ReleasePayload) Validate() error {
	if p.InstanceID == uuid.Nil || p.TenantID == uuid.Nil || p.InstanceID == p.TenantID {
		return errors.New("instance_id and tenant_id are required")
	}
	return nil
}

// ---------------------------------------------------------------------------------------------------- shared helpers

// IsQuarantined reports whether the instance is quarantined in the registry (§11.4) — the check every job that
// restarts, reconfigures, backs up or otherwise acts on an instance makes before it starts (the step gate also stops
// it at its next step). For the schedulers of P3-T11 (backup) and P3-T13 (reconfigure): use it, or filter
// status <> tenants.InstanceQuarantined in their selection query, like reconcile and apikey do.
func IsQuarantined(ctx context.Context, q *sqlcdb.Queries, instanceID uuid.UUID) (bool, error) {
	row, err := q.GetInstanceForQuarantine(ctx, instanceID)
	if err != nil {
		return false, err
	}
	return row.Status == tenants.InstanceQuarantined, nil
}

// CodeInstanceQuarantined is the error code of a job stopped by the step gate.
const CodeInstanceQuarantined = "instance_quarantined"

// CodeQuarantineRequested is the error code of a release stopped because the instance is quarantined again.
const CodeQuarantineRequested = "quarantine_requested"

// Gate is the step gate of the worker (jobs.Options.StepGate — §11.4 "mọi job … bỏ qua instance đang quarantine"): a
// job of a tenant whose live instance (instance-scoped job: whose instance) is quarantined stops before its next step
// and before every step of its compensation, with Resumable instance_quarantined — no compensation, nothing of the
// instance undone or deleted: a lifecycle job ends failed_resumable (it keeps the tenant's lifecycle lock: /retry once
// released, or /rollback), any other ends failed. instance.quarantine is never stopped; instance.release (which runs on
// a quarantined instance by design) stops when a quarantine of its instance is in progress or was requested after it;
// tenant.deprovision (itself 2P — P3-T09) is not stopped: removing a compromised tenant must stay possible (the agent
// still refuses to delete the data of an instance that carries meta/quarantined). Platform jobs carry no tenant: never
// stopped.
func Gate(ctx context.Context, q *sqlcdb.Queries, run jobs.GateRun) error {
	if run.Kind == KindQuarantine || run.Kind == KindDeprovision || run.TenantID == nil {
		return nil
	}
	row, err := q.QuarantineGate(ctx, sqlcdb.QuarantineGateParams{TenantID: *run.TenantID, InstanceID: run.InstanceID, JobID: run.ID})
	if err != nil {
		return jobs.Transient("step_bookkeeping", fmt.Errorf("quarantine gate: sqlstate %q", store.SQLState(err)))
	}
	switch {
	case run.Kind == KindRelease && row.QuarantineRequested:
		return jobs.Resumable(CodeQuarantineRequested, errors.New("a quarantine of the instance was requested during the release"))
	case run.Kind != KindRelease && row.Quarantined:
		return jobs.Resumable(CodeInstanceQuarantined, errors.New("the instance is quarantined (§11.4): the job stops before its next step"))
	}
	return nil
}
