package postrestore

import (
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/policies"
)

// ReportSchema is the version of the report document.
const ReportSchema = 1

// Run statuses (Report.Status).
const (
	StatusCompleted  = "completed"  // every step ran; findings may still need review (ReviewRequired)
	StatusIncomplete = "incomplete" // a step could not run for some subject (Incomplete says which) — run again
	StatusFailed     = "failed"     // the run stopped on an error (Error)
)

// Outcomes of the API key step (APIKeyResult.Outcome).
const (
	KeyOK           = "ok"            // the stored key works and is not due: nothing changed
	KeyRotated      = "rotated"       // it works but other valid keys existed (created in the gap): rotated, others expired
	KeyReissued     = "reissued"      // refused or lost: re-issued through the agent (BootstrapApiKey)
	KeyWouldReissue = "would_reissue" // dry run: refused or lost
	KeySkipped      = "skipped"       // instance not running, tenant unreachable…
	KeyUnavailable  = "unavailable"   // dry run: the instance could not be reached
	KeyFailed       = "failed"        // the rotation failed (ErrorCode)
)

// Review reasons (ReviewItem.Reasons).
const (
	ReviewPolicyDiffers = "policy_differs_from_restored_database"
	ReviewNoPolicy      = "instance_runs_no_policy"
	ReviewInstanceLost  = "instance_lost"
	ReviewKeyFailed     = "api_key_not_reissued"
	ReviewUnmappedUsers = "policy_names_unknown_members"
	ReviewOrphan        = "orphan_instance_on_host"
)

// Report is the JSON report of one run (stdout of the command).
type Report struct {
	Schema       int       `json:"schema"`
	RunID        uuid.UUID `json:"run_id"`
	DryRun       bool      `json:"dry_run"`
	RestorePoint time.Time `json:"restore_point"`
	// StartedAt is the database clock when the run started: the cutoff of every revocation and the end of the gap.
	StartedAt  time.Time  `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
	Gap        Gap        `json:"gap"`
	Status     string     `json:"status"`
	Error      string     `json:"error,omitempty"`
	// Incomplete names what could not be checked or done ("<step>:<subject>:<reason>").
	Incomplete []string `json:"incomplete"`
	// ReviewRequired lists the tenants (and the orphan instances) a person must look at before maintenance is turned off.
	ReviewRequired []ReviewItem             `json:"review_required"`
	Maintenance    MaintenanceStep          `json:"maintenance"`
	Sessions       SessionsStep             `json:"sessions"`
	Approvals      ApprovalsStep            `json:"approvals"`
	SupportGrants  SupportGrantsStep        `json:"support_grants"`
	Invitations    InvitationsStep          `json:"invitations"`
	Instances      InstancesStep            `json:"instances"`
	APIKeys        []APIKeyResult           `json:"api_keys"`
	Policies       []policies.RunningResult `json:"policies"`
	InventorySync  InventorySyncStep        `json:"inventory_sync"`
	OpenJobs       []OpenJob                `json:"open_jobs"`
	AuditGap       AuditGapStep             `json:"audit_gap"`
}

// Gap is the window whose writes the restore lost.
type Gap struct {
	From    time.Time `json:"from"`
	To      time.Time `json:"to"`
	Seconds int64     `json:"seconds"`
}

// ReviewItem is one subject to review.
type ReviewItem struct {
	TenantID   *uuid.UUID `json:"tenant_id,omitempty"`
	Slug       string     `json:"slug,omitempty"`
	InstanceID *uuid.UUID `json:"instance_id,omitempty"`
	Reasons    []string   `json:"reasons"`
}

// MaintenanceStep says what the run did with the maintenance flag.
type MaintenanceStep struct {
	Persisted bool `json:"persisted"`     // the flag is ON in the database after the step (always, outside a dry run)
	SetByRun  bool `json:"set_by_run"`    // this run turned it on
	Run       int  `json:"run,omitempty"` // number of the run for this restore point
	Previous  bool `json:"was_enabled"`   // the flag before the run
}

// SessionsStep counts the revoked sessions (dry run: the ones that would be).
type SessionsStep struct {
	Revoked             int64 `json:"revoked"`
	LiveAtCutoff        int64 `json:"live_at_cutoff"` // not yet expired among them
	AuthRequestsDeleted int64 `json:"auth_requests_deleted"`
}

// ApprovalsStep counts the expired approval requests.
type ApprovalsStep struct {
	Expired              int64            `json:"expired"`
	ByScopeStatus        map[string]int64 `json:"by_scope_status"` // "platform/pending" → n
	ConsoleGrantsExpired int64            `json:"console_grants_expired"`
}

// Statuses of the support grant step (SupportGrantsStep.Status).
const (
	SupportGrantsChecked     = "checked"       // the table exists: open grants of the dump closed (dry run: counted)
	SupportGrantsNotInSchema = "not_in_schema" // a dump of a schema before migration 0023 (P4-T05): nothing to close
)

// SupportGrantsStep counts the closed support access grants (dry run: the ones that would be): approved ⇒ revoked,
// pending ⇒ expired — a grant revoked or refused in the lost window must not come back.
type SupportGrantsStep struct {
	Status   string           `json:"status"`
	Revoked  int64            `json:"revoked"`
	Expired  int64            `json:"expired"`
	ByStatus map[string]int64 `json:"by_status"` // status before the run ("approved", "pending") → n
}

// InvitationsStep counts the revoked invitations.
type InvitationsStep struct {
	Revoked  int64            `json:"revoked"`
	ByTenant map[string]int64 `json:"by_tenant"` // slug → n (tenants with at least one)
}

// InstancesStep is the inventory comparison.
type InstancesStep struct {
	Inventory string           `json:"inventory"` // checked | unavailable
	Reason    string           `json:"reason,omitempty"`
	Host      int              `json:"host_entries"`
	Registry  int              `json:"registry_rows"`
	Orphans   []OrphanInstance `json:"orphans"`
	Lost      []LostInstance   `json:"lost"`
	// Other are the remaining findings of the inspector (identity mismatch, removed leftovers, edge aliases).
	Other []Finding `json:"other_findings"`
}

// OrphanInstance is an instance on the host the registry does not know (created in the gap): reported only.
type OrphanInstance struct {
	InstanceID  string   `json:"instance_id"`
	TenantLabel string   `json:"tenant_label,omitempty"`
	Slug        string   `json:"slug,omitempty"`
	Objects     []string `json:"objects"` // directory, container, network
	Action      string   `json:"action"`  // what a person decides (never done by the command)
}

// LostInstance is a registered instance with nothing on the host.
type LostInstance struct {
	InstanceID   uuid.UUID `json:"instance_id"`
	TenantID     uuid.UUID `json:"tenant_id"`
	Slug         string    `json:"slug"`
	MarkedFailed bool      `json:"marked_failed"`
}

// Finding is a finding of the inspector reported as is.
type Finding struct {
	Kind     string `json:"kind"`
	Subject  string `json:"subject,omitempty"`
	Expected string `json:"expected,omitempty"`
	Actual   string `json:"actual,omitempty"`
}

// APIKeyResult is the API key step of one instance (prefixes only).
type APIKeyResult struct {
	TenantID       uuid.UUID `json:"tenant_id"`
	Slug           string    `json:"slug"`
	InstanceID     uuid.UUID `json:"instance_id"`
	Outcome        string    `json:"outcome"`
	Reason         string    `json:"reason,omitempty"`
	PreviousPrefix string    `json:"previous_prefix,omitempty"`
	KeyPrefix      string    `json:"key_prefix,omitempty"`
	ExpiredKeys    int       `json:"expired_keys,omitempty"`
	ErrorCode      string    `json:"error_code,omitempty"`
}

// InventorySyncStep counts the enqueued syncs.
type InventorySyncStep struct {
	Enqueued int      `json:"enqueued"`
	Existing int      `json:"existing"` // an unfinished job of the same slot was already queued (a previous run)
	Skipped  []string `json:"skipped"`  // slugs of instances not running
}

// OpenJob is a job still open in the restored database.
type OpenJob struct {
	ID        uuid.UUID  `json:"id"`
	Kind      string     `json:"kind"`
	Status    string     `json:"status"`
	TenantID  *uuid.UUID `json:"tenant_id,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

// AuditGapStep says which audit.gap events were written.
type AuditGapStep struct {
	Platform bool `json:"platform"` // the platform event is recorded (now or by an earlier run)
	Tenants  int  `json:"tenants"`  // tenants whose event is recorded
	Written  int  `json:"written"`  // events written by this run
}
