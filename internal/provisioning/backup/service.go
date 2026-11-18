package backup

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	agentv1 "github.com/zhaduchanhzz/network-access-mesh/api/agent/v1"
	"github.com/zhaduchanhzz/network-access-mesh/internal/agentclient"
	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/secrets"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// Job kinds (§13.5), the approval action of a restore (§8.5 platform.instance:restore — 2P), audit actions and the
// source of the security events.
const (
	KindBackup    = "instance.backup"
	KindRestore   = "instance.restore"
	ActionRestore = "platform.instance.restore"

	AuditBackup  = "instance.backup"
	AuditRestore = "instance.restore"

	SecuritySource = "backup"
	// Security event kinds (tenant scope).
	EventUnsafeData      = "backup.unsafe_data"      // a hostile data/ (IT-15): symlink, FIFO, device, oversized, unexpected file
	EventIntegrity       = "backup.integrity"        // a corrupt database, an archive that does not verify or decrypt
	EventManifestInvalid = "backup.manifest_invalid" // the agent returned a manifest the worker cannot verify
	EventRestoreReview   = "restore.owner_review"    // PostgreSQL older than the restored backup: Owner review required
	EventRestoreCheck    = "restore.check_failed"    // the restored instance failed a check over the API — edge detached

	// TriggerSchedule / TriggerAPI: who asked for a backup.
	TriggerSchedule = "schedule"
	TriggerAPI      = "api"
	// SlotAPI is the dedupe slot of the backups asked through the API: one queued or running at a time per instance.
	SlotAPI = "api"
	// SyncKind is the inventory.sync job a restore enqueues (internal/devices — not imported: provisioning does not
	// depend on devices, §13.6).
	SyncKind = "inventory.sync"
)

// Agent is the part of the Host Agent client the jobs use (*agentclient.Client).
type Agent interface {
	Backup(ctx context.Context, in *agentv1.BackupRequest, opts ...grpc.CallOption) (*agentv1.BackupResponse, error)
	Restore(ctx context.Context, in *agentv1.RestoreRequest, opts ...grpc.CallOption) (*agentv1.RestoreResponse, error)
	PostRestoreReconcile(ctx context.Context, in *agentv1.PostRestoreReconcileRequest, opts ...grpc.CallOption) (*agentv1.PostRestoreReconcileResponse, error)
	EnsureEdgeAttachment(ctx context.Context, in *agentv1.EnsureEdgeAttachmentRequest, opts ...grpc.CallOption) (*agentv1.EnsureEdgeAttachmentResponse, error)
	RemoveEdgeAttachment(ctx context.Context, in *agentv1.RemoveEdgeAttachmentRequest, opts ...grpc.CallOption) (*agentv1.RemoveEdgeAttachmentResponse, error)
	// GetInstanceStatus: the restore's check that the instance is activated (the Host Agent's view) before it is asked to
	// restore — and the proof that a restore of an older worker changed nothing (restore lock fix).
	GetInstanceStatus(ctx context.Context, in *agentv1.GetInstanceStatusRequest, opts ...grpc.CallOption) (*agentv1.GetInstanceStatusResponse, error)
}

// SecretStore is the part of the SecretStore the jobs use (*secrets.Store).
type SecretStore interface {
	Latest(ctx context.Context, tenant uuid.UUID, name string) (secrets.Ref, error)
	Put(ctx context.Context, ref secrets.Ref, value []byte, opts ...secrets.Option) error
	Rotate(ctx context.Context, ref secrets.Ref, value []byte, opts ...secrets.Option) (secrets.Ref, error)
	Get(ctx context.Context, ref secrets.Ref) (secrets.Plaintext, error)
	Destroy(ctx context.Context, ref secrets.Ref) error
}

// Registry reaches the tenant's instance over its API (the restore's checks) and forgets a cached key.
type Registry interface {
	headscale.Registry
	Invalidate(tenantID uuid.UUID)
}

// Config wires the service.
type Config struct {
	Agent    Agent
	Secrets  SecretStore
	Registry Registry
	// ManifestKeys verify every manifest (MG_BACKUP_MANIFEST_PUBKEY). Empty: backups are disabled (jobs refuse).
	ManifestKeys []ed25519.PublicKey
	// Interval is the schedule period (MG_BACKUP_INTERVAL); Retention how long a backup is kept (MG_BACKUP_RETENTION);
	// KeepLatest how many of the newest succeeded backups are kept whatever their age (default 3).
	Interval, Retention time.Duration
	KeepLatest          int
	// APIKeyTTL is the expiration of the API key created by the post-restore reconcile (default 90 days — §11.4).
	APIKeyTTL time.Duration
	// CallTimeout bounds one Backup or Restore call of the agent (default 8 min — below the job timeout of 10 min).
	CallTimeout time.Duration
	// APIKeyLockWait bounds the wait for the instance's API key lock (apikey.LockName — default 2 min).
	APIKeyLockWait time.Duration
	Now            func() time.Time
	Logger         *slog.Logger
}

// Service runs instance.backup and instance.restore and answers the API.
type Service struct {
	st  *store.Store
	cfg Config
	log *slog.Logger
}

// New returns the service on the worker's (or the api's) store.
func New(st *store.Store, cfg Config) *Service {
	if cfg.Interval <= 0 {
		cfg.Interval = time.Hour
	}
	if cfg.Retention <= 0 {
		cfg.Retention = 7 * 24 * time.Hour
	}
	if cfg.KeepLatest <= 0 {
		cfg.KeepLatest = 3
	}
	if cfg.APIKeyTTL <= 0 {
		cfg.APIKeyTTL = 2160 * time.Hour
	}
	if cfg.CallTimeout <= 0 {
		cfg.CallTimeout = 8 * time.Minute
	}
	if cfg.APIKeyLockWait <= 0 {
		cfg.APIKeyLockWait = 2 * time.Minute
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	return &Service{st: st, cfg: cfg, log: cfg.Logger}
}

// Register sets the handlers of instance.backup and instance.restore on the worker.
func (s *Service) Register(w *jobs.Worker) error {
	if err := w.Register(KindBackup, jobs.HandlerFunc(s.runBackup)); err != nil {
		return err
	}
	return w.Register(KindRestore, restoreJob{s})
}

func (s *Service) enabled() error {
	switch {
	case s.cfg.Agent == nil:
		return jobs.Permanent("agent_not_configured", errors.New("the worker has no Host Agent (MG_AGENT_SOCKET)"))
	case len(s.cfg.ManifestKeys) == 0:
		return jobs.Permanent("backup_not_configured", errors.New("no manifest key (MG_BACKUP_MANIFEST_PUBKEY): backups are disabled"))
	case s.cfg.Secrets == nil:
		return jobs.Permanent("secret_store_unavailable", errors.New("no SecretStore"))
	}
	return nil
}

// ---------------------------------------------------------------------------------------------------- registry

// instance is what a job knows of its instance.
type instance struct {
	sqlcdb.GetInstanceForBackupRow
}

func (i instance) ref() *agentv1.InstanceRef {
	return &agentv1.InstanceRef{InstanceId: i.ID.String(), TenantId: i.TenantID.String(), Slug: i.Slug}
}

// eligible: an instance whose data the agent may back up or restore (§11.4: never quarantined or removed; the tenant
// still served).
func (i instance) eligible() string {
	switch {
	case i.Status != "running" && i.Status != "stopped":
		return "instance_" + i.Status
	case i.TenantStatus != "active" && i.TenantStatus != "suspended" && i.TenantStatus != "provisioning":
		return "tenant_" + i.TenantStatus
	}
	return ""
}

func (s *Service) instance(ctx context.Context, tenantID, instanceID uuid.UUID) (instance, error) {
	var out instance
	err := s.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		r, err := q.GetInstanceForBackup(ctx, instanceID)
		if err != nil {
			return err
		}
		out = instance{r}
		return nil
	})
	switch {
	case errors.Is(err, store.ErrNoRows):
		return instance{}, jobs.Permanent("instance_not_found", errors.New("no such instance"))
	case err != nil:
		return instance{}, jobs.Transient("registry_unavailable", err)
	case out.TenantID != tenantID:
		return instance{}, jobs.Permanent("instance_not_found", errors.New("the instance is not the job's tenant's"))
	}
	return out, nil
}

// ---------------------------------------------------------------------------------------------------- errors

// agentErr classifies an error of the Host Agent (as the orchestrator does): unreachable, busy or deadline ⇒
// transient; a typed refusal ⇒ permanent, code agent_<reason>.
func agentErr(rpc string, err error) error {
	msg := rpc + ": " + status.Convert(err).Message()
	ref, hasRefusal := agentclient.RefusalOf(err)
	if hasRefusal {
		msg = fmt.Sprintf("%s: %s refused (%s): %s", rpc, ref.GetField(), refusalCode(ref.GetReason()), ref.GetMessage())
	}
	switch {
	case agentclient.Retryable(err):
		code := "agent_unavailable"
		if status.Code(err) == codes.Aborted {
			code = "agent_busy"
		}
		return jobs.Transient(code, errors.New(msg))
	case hasRefusal:
		return jobs.Permanent("agent_"+refusalCode(ref.GetReason()), errors.New(msg))
	}
	return jobs.Permanent("agent_error", errors.New(msg))
}

func refusalCode(r agentv1.RefusalReason) string {
	return strings.ToLower(strings.TrimPrefix(r.String(), "REFUSAL_REASON_"))
}

// securityEventOf maps a refusal of Backup/Restore to the tenant security event it raises (IT-15, T-15): "" when the
// error is not one.
func securityEventOf(err error) (kind string, sev string) {
	ref, ok := agentclient.RefusalOf(err)
	if !ok {
		return "", ""
	}
	switch ref.GetReason() {
	case agentv1.RefusalReason_REFUSAL_REASON_UNSAFE_PATH:
		return EventUnsafeData, audit.SeverityHigh
	case agentv1.RefusalReason_REFUSAL_REASON_INTEGRITY, agentv1.RefusalReason_REFUSAL_REASON_IDENTITY_MISMATCH:
		return EventIntegrity, audit.SeverityHigh
	}
	return "", ""
}

// raise records a tenant security event (best effort: logged when it cannot be written).
func (s *Service) raise(ctx context.Context, tenantID uuid.UUID, kind, severity, dedupe string, details audit.Details) {
	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	err := s.st.WithTenantTx(wctx, tenantID, func(q *sqlcdb.Queries) error {
		_, err := audit.RecordSecurityEvent(wctx, q, audit.SecurityEvent{TenantID: &tenantID, Kind: kind, Severity: severity,
			Source: SecuritySource, Details: details, DedupeKey: kind + ":" + dedupe, DedupeWindow: time.Hour})
		return err
	})
	if err != nil {
		s.log.ErrorContext(ctx, "backup: recording a security event failed", "kind", kind, "tenant_id", tenantID.String(),
			"sqlstate", store.SQLState(err))
	}
	s.log.WarnContext(ctx, "backup: security event", "kind", kind, "severity", severity, "tenant_id", tenantID.String())
}

// refusalDetails is what a security event keeps of a refusal (the agent's text never repeats a value).
func refusalDetails(err error) audit.Details {
	d := audit.Details{}
	if ref, ok := agentclient.RefusalOf(err); ok {
		d["refusal"] = refusalCode(ref.GetReason())
		m := ref.GetMessage()
		if len(m) > 300 {
			m = m[:300]
		}
		d["message"] = m
	}
	return d
}
