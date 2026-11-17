package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
)

// Store is the registry side of the state machine (DBStore over PostgreSQL; an in-memory fake in the unit tests).
// Every write is idempotent: a step runs again after a retry, a worker restart or /retry.
type Store interface {
	// Tenant reads the tenant of the job and its effective plan limits.
	Tenant(ctx context.Context, tenantID uuid.UUID) (TenantRecord, error)
	// Instance reads the instance placement.allocate registered (with the host's public entry).
	Instance(ctx context.Context, tenantID, instanceID uuid.UUID) (InstanceRecord, error)
	// TransitionInstance moves the instance to `to` when its status is one of from; already in `to` or in another
	// status ⇒ no change. It returns the status found.
	TransitionInstance(ctx context.Context, tenantID, instanceID uuid.UUID, from []string, to string) (string, error)
	SetFingerprint(ctx context.Context, tenantID, instanceID uuid.UUID, fingerprint string) error
	SetRuntime(ctx context.Context, tenantID, instanceID uuid.UUID, version, digest string) error
	// RecordConfig stores the rendered configuration version (instance_config_versions) and points the instance at it;
	// the same config_sha256 again ⇒ the existing version.
	RecordConfig(ctx context.Context, tenantID, instanceID uuid.UUID, c ConfigRecord) (uuid.UUID, error)
	// SetAPIKey records the reference, public prefix and expiry of the instance API key ("" ref clears them).
	SetAPIKey(ctx context.Context, tenantID, instanceID uuid.UUID, ref, prefix string, expires *time.Time) error
	IdP(ctx context.Context, tenantID, idpID uuid.UUID) (IdPRecord, bool, error)
	// SaveIdP inserts the tenant's IdP `pending`, or updates driver_ref / client_secret_ref of the existing row.
	SaveIdP(ctx context.Context, r IdPRecord) error
	SetIdPStatus(ctx context.Context, tenantID, idpID uuid.UUID, from, to string) (bool, error)
	// RecordBaselinePolicy records step 15: policy_versions v1 (baseline, approved), tenants.desired_policy_version_id,
	// policy_applications (bootstrap, applied) with exactly the string that was set.
	RecordBaselinePolicy(ctx context.Context, tenantID, instanceID uuid.UUID, hujson string) error
	// Configure is step 16 (DB only): settings, IdP active, the Owner invitation and its notification. It returns the
	// invitation (uuid.Nil when the Owner is already a member).
	Configure(ctx context.Context, r ConfigureRequest) (uuid.UUID, error)
	RevokeInvitation(ctx context.Context, tenantID, invitationID uuid.UUID) error
	AssignRelay(ctx context.Context, r RelayRequest) error
	RemoveRelay(ctx context.Context, tenantID, instanceID uuid.UUID, code string) error
	// Activate is step 19: instance running, tenant active, audit "<op>.succeeded", notification tenant.activated.
	Activate(ctx context.Context, r ActivateRequest) error
	// Fail ends a rolled-back provisioning: tenant `failed` (kept for audit — §11.3 step 2) and "<op>.failed".
	Fail(ctx context.Context, tenantID uuid.UUID, op audit.Operation, reason string, details audit.Details) error
	// WithAPIKeyLock runs fn under the tenant's lock of every API-key operation on its instance (bootstrap, rotation —
	// P3-T10 —, the key check of reconcile): store.WithTenantLock(tenant, APIKeyLockName).
	WithAPIKeyLock(ctx context.Context, tenantID uuid.UUID, fn func(ctx context.Context) error) error
}

// APIKeyLockName is the tenant lock of every API-key operation on an instance.
// TODO(merge): apikey.LockName of internal/provisioning/apikey (P3-T10) — the same value, one lock name only.
const APIKeyLockName = "instance.apikey"

// TenantRecord is the tenant of a job.
type TenantRecord struct {
	ID       uuid.UUID
	Slug     string
	Name     string
	Status   string
	Region   string
	Settings json.RawMessage
	PlanKey  string
	// Instance are the instance limits of the plan ⊕ overrides (PlanLimits.instance — §13.3); zero = not set.
	Instance InstanceLimits
}

// InstanceLimits are PlanLimits.instance.
type InstanceLimits struct {
	CPUs     float64 `json:"cpus"`
	MemoryMB int64   `json:"memory_mb"`
	PIDs     int64   `json:"pids"`
}

// InstanceRecord is a tenant_instances row with the public entry of its host.
type InstanceRecord struct {
	ID, TenantID, HostID uuid.UUID
	HostName             string
	Status               string
	ImageDigest          string
	HeadscaleVersion     string
	ControlHostname      string
	BaseDomain           string
	RunUID               int32
	NetCIDR              netip.Prefix
	STUNPort             int32 // 0 = shared STUN
	DERPRegionID         int32 // 0 = not set yet
	PublicEntryIPv4      netip.Addr
	APIKeyRef            string
	APIKeyPrefix         string
	APIKeyExpiresAt      *time.Time
	NoiseFingerprint     string
}

// ConfigRecord is the configuration version of step 8.
type ConfigRecord struct {
	TemplateVersion uint32
	ConfigSHA256    string
	DERPRegionID    int32
	Params          map[string]any // the typed parameters sent to the agent — no secret
}

// IdPRecord is the tenant's identity provider row.
type IdPRecord struct {
	ID, TenantID        uuid.UUID
	Driver              string
	Issuer              string
	ClientID            string
	ClientSecretRef     string
	DriverRef           string
	Status              string
	RequiredClaims      map[string]any
	AllowedEmailDomains []string
}

// ConfigureRequest is step 16.
type ConfigureRequest struct {
	TenantID   uuid.UUID
	IdPID      uuid.UUID
	Settings   json.RawMessage
	OwnerEmail string
}

// RelayRequest is step 17: the tenant's embedded DERP region and its assignment to the instance.
type RelayRequest struct {
	TenantID, InstanceID, HostID uuid.UUID
	Code, Name, Hostname         string
	DERPRegionID                 int32
	IPv4                         netip.Addr
	STUNPort                     int32
}

// ActivateRequest is step 19.
type ActivateRequest struct {
	TenantID, InstanceID uuid.UUID
	Operation            audit.Operation
	OwnerEmail           string
	Details              audit.Details
}

// Errors of a Store.
var (
	// ErrNotFound: the tenant, instance or row does not exist (or is another tenant's).
	ErrNotFound = errors.New("orchestrator: not found")
	// ErrState: the row is in a status the step cannot work from (tenant not provisioning…).
	ErrState = errors.New("orchestrator: unexpected registry state")
)
