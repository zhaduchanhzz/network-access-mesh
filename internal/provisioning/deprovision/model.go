package deprovision

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"

	agentv1 "github.com/zhaduchanhzz/network-access-mesh/api/agent/v1"
	"github.com/zhaduchanhzz/network-access-mesh/infrastructure/headscale/templates"
	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/idp"
	"github.com/zhaduchanhzz/network-access-mesh/internal/notifications"
	"github.com/zhaduchanhzz/network-access-mesh/internal/policies"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/backup"
	"github.com/zhaduchanhzz/network-access-mesh/internal/secrets"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
)

// Job kinds (§13.5): the lifecycle job and the periodic crypto-shredding.
const (
	Kind            = "tenant.deprovision"
	KindKeysDestroy = "tenant.keys_destroy"
)

// The 15 steps of tenant.deprovision, in order (provisioning_job_steps.name). Step 1 runs in the API.
const (
	StepValidate     = "validate"
	StepFinalBackup  = "backup.final"
	StepPolicy       = "policy.suspend"
	StepDeprovision  = "registry.deprovision"
	StepNodesExpire  = "nodes.expire" // the point of no return (jobs.Kind.PointOfNoReturn)
	StepAccessRevoke = "access.revoke"
	StepTargets      = "targets.remove"
	StepEdgeDetach   = "edge.detach"
	StepInstance     = "instance.remove"
	StepStorage      = "storage.remove"
	StepIdP          = "idp.disable"
	StepRelay        = "relay.remove"
	StepDelete       = "registry.delete"
	StepKeysSchedule = "keys.schedule"
	StepNotify       = "notify"
)

// Steps lists the steps of tenant.deprovision in order.
var Steps = []string{StepValidate, StepFinalBackup, StepPolicy, StepDeprovision, StepNodesExpire, StepAccessRevoke,
	StepTargets, StepEdgeDetach, StepInstance, StepStorage, StepIdP, StepRelay, StepDelete, StepKeysSchedule, StepNotify}

// PointOfNoReturn is the step from which a deprovision can no longer be rolled back.
const PointOfNoReturn = StepNodesExpire

// Approval action, audit actions, operation id and security events.
const (
	// Action is the dual-control action of DELETE /platform/tenants/{tenantId} (approval_requests.action, §8.5 2P) and
	// the base audit action of the deprovision (platform.tenant.delete.requested → .succeeded / .failed).
	Action = "platform.tenant.delete"
	// AuditKeysDestroyed is the platform audit event of the crypto-shredding of one tenant.
	AuditKeysDestroyed = "platform.tenant.keys_destroyed"
	// Operation is the operationId of the API (Idempotency-Key scope — §13.1).
	Operation = "deletePlatformTenant"
	// Permission of the operation and of its approver (§8.5: Super Admin, 2P).
	Permission = "platform.tenant:delete"

	SecuritySource = "deprovision"
	// EventNoFinalBackup: a tenant was deprovisioned without a final backup (the approved payload skipped it) — its data
	// directory is kept in place, the only copy (high).
	EventNoFinalBackup = "tenant.deprovision_without_backup"
)

// ReachableStatuses are the tenant statuses under which the Headscale registry of the handler (and of its policy core)
// reaches the instance — locator.Options.TenantStatuses: the suspension policy is applied while the tenant is active or
// suspended, the nodes are expired once it is deprovisioning.
var ReachableStatuses = []string{tenants.StatusActive, tenants.StatusSuspended, tenants.StatusDeprovisioning}

// FromStatuses are the tenant statuses a deprovision starts from: a serving tenant (active, suspended) or one whose
// provisioning was rolled back (failed — nothing of an instance is left; the deprovision deletes it for good).
var FromStatuses = []string{tenants.StatusActive, tenants.StatusSuspended, tenants.StatusFailed}

// DefaultKeyGrace is the default grace period between the deletion and the destruction of the tenant's keys
// (MG_DEPROVISION_KEY_GRACE).
const DefaultKeyGrace = 30 * 24 * time.Hour

var slugRE = regexp.MustCompile(`^[a-z][a-z0-9-]{1,30}[a-z0-9]$`)

// Payload is the payload of an approval request platform.tenant.delete — what the approver sees (and hashes) and the
// only input of the job besides the registry: the tenant, its slug (shown to the approver), and the explicit operator
// override that deletes without a final backup.
type Payload struct {
	TenantID        uuid.UUID `json:"tenant_id"`
	Slug            string    `json:"slug"`
	SkipFinalBackup bool      `json:"skip_final_backup"`
}

// Validate is called by the approval registry (approvals.Typed) at request, decision and execution.
func (p Payload) Validate() error {
	switch {
	case p.TenantID == uuid.Nil:
		return errors.New("tenant_id is required")
	case !slugRE.MatchString(p.Slug):
		return errors.New("slug is not a tenant slug")
	}
	return nil
}

// Input is the input of a tenant.deprovision job: identifiers only.
type Input struct {
	TenantID uuid.UUID `json:"tenant_id"`
	Slug     string    `json:"slug"`
	// FromStatus is the tenant's status when the job was enqueued (active, suspended or failed): what /rollback returns
	// it to before the point of no return.
	FromStatus string `json:"from_status"`
	// InstanceID is the tenant's live instance when the job was enqueued (none: a failed tenant).
	InstanceID *uuid.UUID `json:"instance_id,omitempty"`
	// RestoreVersionID is the desired policy version when the job was enqueued — what /rollback applies again.
	RestoreVersionID *uuid.UUID `json:"restore_version_id,omitempty"`
	// SkipFinalBackup is the approved operator override (Payload.SkipFinalBackup).
	SkipFinalBackup bool      `json:"skip_final_backup,omitempty"`
	ApprovalID      uuid.UUID `json:"approval_id"`
	RequestedBy     uuid.UUID `json:"requested_by"`
	// Operation is the audit operation platform.tenant.delete opened when the approval was executed; the job closes it.
	Operation audit.Operation `json:"operation"`
}

func (in Input) validate() error {
	switch {
	case in.TenantID == uuid.Nil || !slugRE.MatchString(in.Slug):
		return errors.New("tenant or slug missing")
	case in.FromStatus != tenants.StatusActive && in.FromStatus != tenants.StatusSuspended && in.FromStatus != tenants.StatusFailed:
		return fmt.Errorf("unexpected from_status %q", in.FromStatus)
	case in.ApprovalID == uuid.Nil || in.RequestedBy == uuid.Nil:
		return errors.New("approval or requester missing")
	case in.Operation.ID == uuid.Nil:
		return errors.New("audit operation missing")
	}
	return nil
}

// ---------------------------------------------------------------------------------------------------- collaborators

// Agent is the part of the Host Agent the job calls — typed RPCs only (§11.1); agentclient.Client implements it.
type Agent interface {
	RemoveEdgeAttachment(ctx context.Context, in *agentv1.RemoveEdgeAttachmentRequest, opts ...grpc.CallOption) (*agentv1.RemoveEdgeAttachmentResponse, error)
	RemoveInstance(ctx context.Context, in *agentv1.RemoveInstanceRequest, opts ...grpc.CallOption) (*agentv1.RemoveInstanceResponse, error)
}

// Backups takes the final backup (*backup.Service).
type Backups interface {
	FinalBackup(ctx context.Context, jobID, tenantID, instanceID uuid.UUID, keep time.Duration) (backup.BackupResult, error)
}

var _ Backups = (*backup.Service)(nil)

// SecretStore is the part of the SecretStore the jobs use (*secrets.Store).
type SecretStore interface {
	Latest(ctx context.Context, tenant uuid.UUID, name string) (secrets.Ref, error)
	Destroy(ctx context.Context, ref secrets.Ref) error
	DestroyTenantKeys(ctx context.Context, tenant uuid.UUID) (secrets.ShredReport, error)
}

var _ SecretStore = (*secrets.Store)(nil)

// IdPDrivers selects the IdP driver of a registration (*idp.Registry).
type IdPDrivers interface {
	Driver(name string) (idp.IdPDriver, error)
}

// PolicyApplier is the policy core (*policies.Service) over a Headscale registry that reaches ReachableStatuses.
type PolicyApplier interface {
	Apply(ctx context.Context, req policies.ApplyRequest) (policies.Result, error)
}

var _ PolicyApplier = (*policies.Service)(nil)

// SecurityRecorder records platform security events (*audit.Logger); nil ⇒ they are written in a platform
// transaction of the job's store.
type SecurityRecorder interface {
	RecordSecurityEvent(ctx context.Context, ev audit.SecurityEvent) (bool, error)
}

// Config are the collaborators and settings of a Handler (worker).
type Config struct {
	Store *store.Store // mg_worker_tenant / mg_worker_platform
	// Agent removes the edge attachment, the container, the network and the data directory. nil: a step that needs the
	// host stops the job (agent_not_configured) — a tenant without a live instance needs none.
	Agent Agent
	// Backups takes the final backup. nil: backup.final stops the job (backup_not_configured) unless the approved
	// payload skips it.
	Backups  Backups
	Secrets  SecretStore
	IdP      IdPDrivers
	Policies PolicyApplier
	// Headscale expires the nodes and pre-auth keys. It must reach a deprovisioning tenant (ReachableStatuses).
	Headscale headscale.Registry
	Notifier  notifications.Enqueuer // nil ⇒ notifications.Default
	Security  SecurityRecorder
	Logger    *slog.Logger
	// SuspensionPolicy is the HuJSON of the suspension (deny-all); "" ⇒ templates.SuspensionPolicy.
	SuspensionPolicy string
	// KeyGrace is the time between the deletion and the destruction of the tenant's keys (default DefaultKeyGrace); the
	// final backup is kept at least this long.
	KeyGrace time.Duration
	// Timing (§11.3); zero values take the defaults of the lifecycle jobs.
	StepRetries int           // 5
	RetryBase   time.Duration // 2 s
	RetryMax    time.Duration // 60 s
	CallTimeout time.Duration // one agent / Headscale / IdP call: 2 min
	Now         func() time.Time
}

func (c *Config) defaults() error {
	if c.Store == nil || c.Secrets == nil || c.IdP == nil || c.Policies == nil || c.Headscale == nil {
		return errors.New("deprovision: a store, the SecretStore, the IdP drivers, the policy core and a Headscale registry are required")
	}
	if c.Notifier == nil {
		c.Notifier = notifications.Default
	}
	if c.Logger == nil {
		c.Logger = slog.New(slog.DiscardHandler)
	}
	if c.SuspensionPolicy == "" {
		c.SuspensionPolicy = templates.SuspensionPolicy
	}
	if _, err := policies.Lint(c.SuspensionPolicy); err != nil {
		return fmt.Errorf("deprovision: the suspension policy: %w", err)
	}
	if c.KeyGrace == 0 {
		c.KeyGrace = DefaultKeyGrace
	}
	if c.StepRetries == 0 {
		c.StepRetries = 5
	}
	if c.RetryBase == 0 {
		c.RetryBase = 2 * time.Second
	}
	if c.RetryMax == 0 {
		c.RetryMax = time.Minute
	}
	if c.CallTimeout == 0 {
		c.CallTimeout = 2 * time.Minute
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.KeyGrace < 0 || c.StepRetries < 0 || c.RetryMax < c.RetryBase {
		return errors.New("deprovision: invalid grace or retry settings")
	}
	return nil
}
