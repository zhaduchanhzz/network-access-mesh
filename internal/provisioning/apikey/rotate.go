package apikey

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/durationpb"

	agentv1 "github.com/zhaduchanhzz/network-access-mesh/api/agent/v1"
	"github.com/zhaduchanhzz/network-access-mesh/internal/agentclient"
	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/logx"
	"github.com/zhaduchanhzz/network-access-mesh/internal/secrets"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
)

// Names shared with the rest of the platform.
const (
	// Kind is the job kind of §13.5 (dedupe key instance:<id>:apikey:<period>).
	Kind = "apikey.rotate"
	// LockName is the instance's API key lock (store.WithTenantLock; one live instance per tenant): every operation on
	// the keys of an instance — this rotation, the API key check of reconcile, §11.3 step 13 — takes it.
	LockName = "instance.apikey"
	// SecretName is the SecretStore name of an instance API key: mgsec://<tenant_id>/headscale-api-key#<version> — the
	// scheme of adopt-instance (provisioning.APIKeySecretName) and of §11.3 step 13.
	SecretName = "headscale-api-key" //nolint:gosec // G101: the name of a SecretStore entry, not a credential
	// ActionRotate is the audit operation instance.apikey.rotate.requested → .succeeded / .failed (platform events).
	ActionRotate = "instance.apikey.rotate"
	// SecuritySource is the source of the security events of this package.
	SecuritySource = "apikey"
)

// Durations of §7.6, §13.5 and §16.3.
const (
	// MaxTTL: an instance API key lives at most 90 days (§7.6); it is also the default lifetime of a new key.
	MaxTTL = 90 * 24 * time.Hour
	// AlertBefore: the alert of §16.3 fires when a key expires in less than 14 days; a rotation must happen before.
	AlertBefore = 14 * 24 * time.Hour
	// DefaultRotateBefore: a key is due when it expires within 21 days — the 14 days of §13.5/§16.3 plus a week of
	// daily attempts before the alert fires.
	DefaultRotateBefore = 21 * 24 * time.Hour
	// DefaultLockWait bounds the wait for the instance's API key lock (reconcile holds it for one ListAPIKeys).
	DefaultLockWait = time.Minute
	// EventWindow deduplicates the security events of one instance and key prefix.
	EventWindow = 24 * time.Hour
	// expirySlack absorbs clock and rounding differences when the expiration Headscale recorded is compared with the
	// one requested.
	expirySlack = time.Hour
)

// Triggers (Request.Trigger, job input).
const (
	TriggerSchedule = "schedule"
	TriggerAdmin    = "admin"
	TriggerJob      = "job"
)

// Modes and outcomes of a rotation.
const (
	ModeAPI       = "api"       // CreateAPIKey with the current key
	ModeBootstrap = "bootstrap" // BootstrapApiKey through the Host Agent (§11.4 fallback)

	OutcomeRotated      = "rotated"
	OutcomeBootstrapped = "bootstrapped"
	OutcomeSkipped      = "skipped"
)

// Skip reasons (Result.SkipReason, job output).
const (
	SkipInstanceNotFound  = "instance_not_found"
	SkipQuarantined       = "instance_quarantined"
	SkipRemoved           = "instance_removed"
	SkipNotRunning        = "instance_not_running"
	SkipTenantUnreachable = "tenant_not_reachable"
	SkipLifecycleBusy     = "lifecycle_busy"
	SkipNoKey             = "key_not_recorded"
	SkipNotDue            = "not_due"
)

// Reasons of the agent fallback (Result.BootstrapReason).
const (
	ReasonKeyExpired  = "key_expired"  // the recorded expiry has passed
	ReasonKeyLost     = "key_lost"     // the SecretStore has no readable version behind the reference
	ReasonKeyRejected = "key_rejected" // refused although valid per the registry — only with AllowBootstrap
)

// Error codes of a failed rotation (jobs.Error codes; the admin command prints them).
const (
	CodeInvalid            = "invalid_input"
	CodeLockBusy           = "lock_busy"
	CodeRegistry           = "registry_unavailable"
	CodeForeignRef         = "foreign_reference"
	CodeInstanceUnavail    = "instance_unavailable"
	CodeKeyRejected        = "key_rejected"
	CodeAgentNotConfigured = "agent_not_configured"
	CodeAgentFailed        = "agent_failed"
	CodeAudit              = "audit_failed"
	CodeSecurityEvent      = "security_event_failed"
	CodeCreate             = "create_failed"
	CodeVerify             = "verify_failed"
	CodeStore              = "store_failed"
	CodeSwapConflict       = "swap_conflict"
	CodeSwap               = "swap_failed"
	CodeOldKeyNotExpired   = "old_key_not_expired"
)

// Security events (platform scope, deduplicated per instance and prefix for EventWindow).
const (
	// EventRejected: a key valid per the registry was refused by the instance — a replaced database is suspected
	// (§13.4); never followed by an automatic bootstrap.
	EventRejected = "apikey.rejected"
	// EventStray: a valid key other than the current one was found when a rotation started (a leftover of a failed
	// run, or a key the platform never created); the rotation expires it.
	EventStray = "apikey.stray"
	// EventLeftover: a valid key the rotation created or replaced could not be expired — the operator must expire it.
	EventLeftover = "apikey.leftover"
)

// TenantStatuses are the tenant statuses whose instance a rotation reaches: an instance of a suspended tenant keeps
// running (§11.4 Suspend) and its key must not expire. The rotation's locator is built with this list.
var TenantStatuses = []string{tenants.StatusProvisioning, tenants.StatusActive, tenants.StatusSuspended}

var fullKeyRE = regexp.MustCompile(`^hskey-api-[A-Za-z0-9_-]{12}-[A-Za-z0-9_-]{64}$`)

// validKey reports whether s has the shape of a Headscale API key (RT-12); it never says why.
func validKey(s string) bool { return fullKeyRE.MatchString(s) }

// Locator resolves a tenant to its instance with the CURRENT key (production: *locator.Locator built with
// TenantStatuses) and builds the target of a key that is not stored yet (the verification of step 5).
type Locator interface {
	headscale.Locator
	Candidate(instanceID uuid.UUID, slug string, apiKey headscale.Secret) (headscale.Target, error)
}

// SecretStore is the part of the SecretStore a rotation uses (*secrets.Store).
type SecretStore interface {
	Put(ctx context.Context, ref secrets.Ref, value []byte, opts ...secrets.Option) error
	Rotate(ctx context.Context, ref secrets.Ref, value []byte, opts ...secrets.Option) (secrets.Ref, error)
	Destroy(ctx context.Context, ref secrets.Ref) error
	Latest(ctx context.Context, tenant uuid.UUID, name string) (secrets.Ref, error)
}

// Agent is the one RPC of the Host Agent the fallback uses (*agentclient.Client).
type Agent interface {
	BootstrapApiKey(ctx context.Context, in *agentv1.BootstrapApiKeyRequest, opts ...grpc.CallOption) (*agentv1.BootstrapApiKeyResponse, error)
}

// SecurityRecorder writes a security event (dedupe per DedupeKey) — runner.platformSecurity in apps/worker.
type SecurityRecorder interface {
	RecordSecurityEvent(ctx context.Context, ev audit.SecurityEvent) (bool, error)
}

// Invalidator drops the cached target of a tenant (*headscale.CachingRegistry).
type Invalidator interface {
	Invalidate(tenantID uuid.UUID)
}

// Config are the collaborators and settings of a Service.
type Config struct {
	Locator  Locator          // required
	Secrets  SecretStore      // required
	Security SecurityRecorder // required
	// Agent of the host; nil = not configured: the fallback fails with agent_not_configured.
	Agent Agent
	// Invalidate lists the registries of this process whose cached target of the tenant is dropped as soon as the
	// new key is recorded (the worker's shared registry). Other processes reload at their first 401.
	Invalidate []Invalidator
	// Headscale are the options of the registries built here (timeout, retry, HTTP client, logger).
	Headscale headscale.Options
	// TTL is the lifetime of a new key: (RotateBefore + 1 day) … MaxTTL; 0 = MaxTTL. The agent fallback uses it in
	// whole hours.
	TTL time.Duration
	// RotateBefore: a key is due when its recorded expiry is within this; AlertBefore … TTL − 1 day; 0 = default.
	RotateBefore time.Duration
	// LockWait bounds the wait for the instance's API key lock; 0 = DefaultLockWait.
	LockWait   time.Duration
	Logger     *slog.Logger
	Registerer prometheus.Registerer
	Now        func() time.Time
}

// Service rotates instance API keys.
type Service struct {
	cfg Config
	db  backend
	reg *headscale.CachingRegistry // the rotation's own registry over Config.Locator (current key)
	log *slog.Logger
	m   *metrics
}

// New returns the rotation service on the worker's store (mg_worker_*).
func New(st *store.Store, cfg Config) (*Service, error) {
	if st == nil {
		return nil, errors.New("apikey: a store is required")
	}
	return newService(dbBackend{st: st}, cfg)
}

func newService(db backend, cfg Config) (*Service, error) {
	if cfg.Locator == nil || cfg.Secrets == nil || cfg.Security == nil {
		return nil, errors.New("apikey: a locator, a SecretStore and a security recorder are required")
	}
	if cfg.TTL == 0 {
		cfg.TTL = MaxTTL
	}
	if cfg.RotateBefore == 0 {
		cfg.RotateBefore = DefaultRotateBefore
	}
	if cfg.LockWait <= 0 {
		cfg.LockWait = DefaultLockWait
	}
	switch {
	case cfg.TTL > MaxTTL || cfg.TTL < 24*time.Hour:
		return nil, fmt.Errorf("apikey: TTL must be between 24h and %s (§7.6)", MaxTTL)
	case cfg.RotateBefore < AlertBefore:
		return nil, fmt.Errorf("apikey: RotateBefore must be at least %s (§13.5, §16.3)", AlertBefore)
	case cfg.RotateBefore > cfg.TTL-24*time.Hour:
		return nil, errors.New("apikey: RotateBefore must stay at least a day below TTL (a new key would be due at once)")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Headscale.Logger == nil {
		cfg.Headscale.Logger = cfg.Logger
	}
	if cfg.Headscale.Now == nil {
		cfg.Headscale.Now = cfg.Now
	}
	return &Service{cfg: cfg, db: db, reg: headscale.NewRegistry(cfg.Locator, cfg.Headscale), log: cfg.Logger,
		m: newMetrics(cfg.Registerer, cfg.Now)}, nil
}

// AgentConfigured reports whether the fallback has an agent.
func (s *Service) AgentConfigured() bool { return s.cfg.Agent != nil }

// Request is one rotation.
type Request struct {
	TenantID, InstanceID uuid.UUID
	// Force rotates a key that is not due yet (on demand).
	Force bool
	// AllowBootstrap lets the agent re-issue a key the instance refused although it is valid per the registry —
	// only after the operator verified the instance (§13.4); never set by the schedule.
	AllowBootstrap bool
	Trigger        string    // TriggerSchedule, TriggerAdmin, TriggerJob ("" = TriggerJob)
	JobID          uuid.UUID // the job running the rotation (the agent's job_id); zero = the audit operation's id
	Actor          string    // display name of the actor in the audit ("" = Kind)
}

// Result describes one rotation — no secret: prefixes, the reference version, times and counts. It is the job's output.
type Result struct {
	TenantID        uuid.UUID  `json:"tenant_id"`
	InstanceID      uuid.UUID  `json:"instance_id"`
	Slug            string     `json:"slug,omitempty"`
	Outcome         string     `json:"outcome"` // rotated | bootstrapped | skipped | "" (failed)
	SkipReason      string     `json:"skip_reason,omitempty"`
	Mode            string     `json:"mode,omitempty"`
	BootstrapReason string     `json:"bootstrap_reason,omitempty"`
	Trigger         string     `json:"trigger"`
	Forced          bool       `json:"forced"`
	PreviousPrefix  string     `json:"previous_prefix,omitempty"`
	KeyPrefix       string     `json:"key_prefix,omitempty"` // the instance's key after the run
	ExpiresAt       *time.Time `json:"expires_at,omitempty"`
	RefVersion      int32      `json:"ref_version,omitempty"`
	StrayPrefixes   []string   `json:"stray_prefixes,omitempty"`
	ExpiredPrefixes []string   `json:"expired_prefixes,omitempty"`
	AgentExpired    uint32     `json:"agent_expired_keys,omitempty"`
	ValidKeys       int        `json:"valid_keys,omitempty"` // valid keys of the instance after the run (1)
	DestroyedRefs   []int32    `json:"destroyed_ref_versions,omitempty"`
}

func (r Result) skip(reason string) Result {
	r.Outcome, r.SkipReason = OutcomeSkipped, reason
	return r
}

// Rotate runs one rotation of the instance under its API key lock (see the package documentation). A skipped run
// returns its reason in Result.SkipReason and no error. Errors are jobs.Transient / jobs.Permanent with a stable code
// (Code* constants) and a credential-free message.
func (s *Service) Rotate(ctx context.Context, req Request) (Result, error) {
	if req.Trigger == "" {
		req.Trigger = TriggerJob
	}
	if req.Actor == "" {
		req.Actor = Kind
	}
	res := Result{TenantID: req.TenantID, InstanceID: req.InstanceID, Trigger: req.Trigger, Forced: req.Force}
	if req.TenantID == uuid.Nil || req.InstanceID == uuid.Nil {
		return res, jobs.Permanent(CodeInvalid, errors.New("a tenant and an instance are required"))
	}
	err := s.db.lock(ctx, req.TenantID, s.cfg.LockWait, func(ctx context.Context) error {
		var e error
		res, e = s.rotateLocked(ctx, req, res)
		return e
	})
	var je *jobs.Error
	switch {
	case err == nil:
	case errors.Is(err, store.ErrLockTimeout):
		err = jobs.Transient(CodeLockBusy, errors.New("another operation on the instance's API keys holds the lock"))
	case !errors.As(err, &je):
		err = jobs.Transient(CodeRegistry, fmt.Errorf("instance API key lock: %s", logx.RedactString(err.Error())))
	}
	s.m.result(res, err)
	if err != nil {
		s.log.WarnContext(ctx, "apikey: rotation failed", "tenant_id", req.TenantID.String(),
			"instance_id", req.InstanceID.String(), "trigger", req.Trigger, "error", err.Error())
	} else {
		s.log.InfoContext(ctx, "apikey: rotation", "tenant_id", req.TenantID.String(), "instance_id", req.InstanceID.String(),
			"trigger", req.Trigger, "outcome", res.Outcome, "skip_reason", res.SkipReason, "mode", res.Mode,
			"key_prefix", res.KeyPrefix, "previous_prefix", res.PreviousPrefix)
	}
	return res, err
}

func (s *Service) rotateLocked(ctx context.Context, req Request, res Result) (Result, error) {
	st, err := s.db.load(ctx, req.TenantID, req.InstanceID)
	switch {
	case errors.Is(err, errNotFound):
		s.m.forget(req.InstanceID)
		return res.skip(SkipInstanceNotFound), nil
	case err != nil:
		return res, jobs.Transient(CodeRegistry, fmt.Errorf("read the registry: %s", logx.RedactString(err.Error())))
	}
	res.Slug, res.PreviousPrefix, res.KeyPrefix = st.Slug, st.Prefix, st.Prefix
	res.ExpiresAt = utcPtr(st.ExpiresAt)
	if reason := skipReason(st); reason != "" {
		if reason != SkipLifecycleBusy {
			s.m.forget(st.InstanceID)
		}
		return res.skip(reason), nil
	}
	if ref, err := secrets.ParseRef(st.Ref); err != nil || ref.Tenant != st.TenantID {
		// boundary 10 of §5.2: the key of a tenant is a secret of that tenant only (the locator refuses it too)
		return res, jobs.Permanent(CodeForeignRef, errors.New("the instance's API key reference is not a secret of its tenant"))
	}
	s.m.observe(st.TenantID, st.InstanceID, st.ExpiresAt)
	now := s.cfg.Now()
	if st.ExpiresAt != nil && !st.ExpiresAt.After(now) {
		return s.bootstrap(ctx, req, st, res, ReasonKeyExpired)
	}
	due := st.ExpiresAt == nil || st.ExpiresAt.Sub(now) <= s.cfg.RotateBefore
	s.reg.Invalidate(st.TenantID) // locate again: the current key as stored now
	inst, err := s.reg.ForTenant(ctx, st.TenantID)
	var keys []headscale.APIKey
	if err == nil {
		keys, err = inst.ListAPIKeys(ctx)
	}
	if err != nil {
		switch {
		case errors.Is(err, secrets.ErrNotFound) || errors.Is(err, secrets.ErrDestroyed):
			return s.bootstrap(ctx, req, st, res, ReasonKeyLost)
		case errors.Is(err, headscale.ErrAPIKeyRejected) && req.AllowBootstrap:
			return s.bootstrap(ctx, req, st, res, ReasonKeyRejected)
		case errors.Is(err, headscale.ErrAPIKeyRejected):
			s.raise(ctx, s.event(EventRejected, audit.SeverityCritical, st, st.Prefix, audit.Details{
				"expires": timeText(st.ExpiresAt), "trigger": req.Trigger}))
			return res, jobs.Permanent(CodeKeyRejected, errors.New("the instance refused the current API key although "+
				"it is valid per the registry — its database may have been replaced (§13.4): no automatic re-issue; verify "+
				"the instance, then run `meshguard-worker admin apikey-rotate --allow-bootstrap`"))
		}
		return res, jobs.Transient(CodeInstanceUnavail, fmt.Errorf("list the API keys with the current key: %s", describe(err)))
	}
	strays := validOthers(keys, st.Prefix, now)
	if !due && !req.Force && len(strays) == 0 {
		return res.skip(SkipNotDue), nil
	}
	return s.rotateAPI(ctx, req, st, res, inst, keys, strays)
}

// skipReason applies the skip rules of step 1.
func skipReason(st instanceState) string {
	switch {
	case st.Status == tenants.InstanceQuarantined:
		return SkipQuarantined
	case st.Status == tenants.InstanceRemoved:
		return SkipRemoved
	case st.Status != tenants.InstanceRunning && st.Status != tenants.InstanceStarting:
		return SkipNotRunning
	case !slices.Contains(TenantStatuses, st.TenantStatus):
		return SkipTenantUnreachable
	case st.LifecycleBusy:
		return SkipLifecycleBusy
	case st.Ref == "":
		return SkipNoKey
	}
	return ""
}

// rotateAPI is steps 3–10 with the current key.
func (s *Service) rotateAPI(ctx context.Context, req Request, st instanceState, res Result, inst headscale.Instance,
	keys []headscale.APIKey, strays []headscale.APIKey,
) (Result, error) {
	res.Mode = ModeAPI
	res.StrayPrefixes = prefixes(strays)
	now := s.cfg.Now()
	due := st.ExpiresAt == nil || st.ExpiresAt.Sub(now) <= s.cfg.RotateBefore
	op, err := s.db.requested(ctx, s.auditEvent(req, st, audit.Details{"mode": ModeAPI, "trigger": req.Trigger,
		"forced": req.Force, "due": due, "previous_prefix": st.Prefix, "stray_prefixes": res.StrayPrefixes}))
	if err != nil {
		return res, jobs.Transient(CodeAudit, fmt.Errorf("record %s.requested: %s", ActionRotate, logx.RedactString(err.Error())))
	}
	fail := func(code string, permanent bool, err error) (Result, error) {
		s.fail(ctx, op, code, res)
		return res, jobErr(code, permanent, err)
	}
	for _, k := range strays { // recorded before anything changes (a crash leaves the trace)
		if _, err := s.cfg.Security.RecordSecurityEvent(ctx, s.event(EventStray, audit.SeverityHigh, st, k.Prefix, keyDetails(k))); err != nil {
			return fail(CodeSecurityEvent, false, fmt.Errorf("record %s: %s", EventStray, logx.RedactString(err.Error())))
		}
		s.m.events.WithLabelValues(EventStray).Inc()
	}
	known := map[string]bool{}
	for _, k := range keys {
		known[k.Prefix] = true
	}

	// 4. the new key, created with the current key
	expires := now.Add(s.cfg.TTL).UTC().Truncate(time.Second)
	key, err := inst.CreateAPIKey(ctx, expires)
	prefix := headscale.APIKeyPrefix(key)
	if err == nil && (!validKey(key.Reveal()) || prefix == "") {
		err = errors.New("headscale answered a key of an unexpected shape")
	}
	if err != nil {
		if he, ok := headscale.AsError(err); !ok || he.Outcome == headscale.OutcomeUnknown {
			s.sweep(ctx, st, inst, known, "create_outcome_unknown") // a key may exist that nobody holds
		}
		return fail(CodeCreate, false, fmt.Errorf("CreateAPIKey: %s", describe(err)))
	}

	// 5. a real call with the new key; from here on, every failure before the swap expires it
	if _, err := s.verify(ctx, st, key, prefix, expires); err != nil {
		s.discard(ctx, st, inst, prefix, CodeVerify)
		return fail(CodeVerify, false, err)
	}
	// 6. the SecretStore
	ref, err := s.store(ctx, st, key)
	if err != nil {
		s.discard(ctx, st, inst, prefix, CodeStore)
		return fail(CodeStore, false, fmt.Errorf("store the new key: %s", logx.RedactString(err.Error())))
	}
	// 7. the registry + audit, one transaction
	res, err = s.swap(ctx, st, res, op, ref, prefix, expires, ModeAPI, func() { s.discard(ctx, st, inst, prefix, CodeSwap) })
	if err != nil {
		return res, err
	}
	res.Outcome = OutcomeRotated
	// 8.–10.
	expire := append(prefixes(strays), st.Prefix)
	return s.finish(ctx, st, res, ref, expire)
}

// bootstrap is the fallback of §11.4: the agent re-issues the key (every other valid key expired), then steps 5–10.
func (s *Service) bootstrap(ctx context.Context, req Request, st instanceState, res Result, reason string) (Result, error) {
	res.Mode, res.BootstrapReason = ModeBootstrap, reason
	if s.cfg.Agent == nil {
		s.log.ErrorContext(ctx, "apikey: the instance's API key must be re-issued through the Host Agent, which is not configured",
			"tenant_id", st.TenantID.String(), "instance_id", st.InstanceID.String(), "reason", reason)
		return res, jobs.Permanent(CodeAgentNotConfigured, fmt.Errorf("the current API key cannot be used (%s) and no Host "+
			"Agent is configured (MG_AGENT_SOCKET, MG_AGENT_TOKEN_FILE): apikey.bootstrap needs the agent (§11.4)", reason))
	}
	op, err := s.db.requested(ctx, s.auditEvent(req, st, audit.Details{"mode": ModeBootstrap, "reason": reason,
		"trigger": req.Trigger, "forced": req.Force, "previous_prefix": st.Prefix}))
	if err != nil {
		return res, jobs.Transient(CodeAudit, fmt.Errorf("record %s.requested: %s", ActionRotate, logx.RedactString(err.Error())))
	}
	fail := func(code string, permanent bool, err error) (Result, error) {
		s.fail(ctx, op, code, res)
		return res, jobErr(code, permanent, err)
	}
	jobID := req.JobID
	if jobID == uuid.Nil {
		jobID = op.ID
	}
	ttl := s.cfg.TTL.Truncate(time.Hour)
	resp, err := s.cfg.Agent.BootstrapApiKey(ctx, &agentv1.BootstrapApiKeyRequest{
		Instance: &agentv1.InstanceRef{InstanceId: st.InstanceID.String(), TenantId: st.TenantID.String(), Slug: st.Slug},
		JobId:    jobID.String(), Ttl: durationpb.New(ttl)}) // keep_prefix empty: every other valid key is expired
	if err != nil {
		return fail(CodeAgentFailed, !agentclient.Retryable(err), fmt.Errorf("BootstrapApiKey: %s", agentError(err)))
	}
	key := headscale.NewSecret(resp.GetApiKey())
	resp.ApiKey = ""
	prefix := resp.GetPrefix()
	res.AgentExpired = resp.GetExpiredKeys()
	if !resp.GetCreated() || !validKey(key.Reveal()) || headscale.APIKeyPrefix(key) != prefix || resp.GetExpiresAt() == nil {
		if resp.GetCreated() && headscale.APIKeyPrefix(key) == prefix && prefix != "" {
			s.raise(ctx, s.event(EventLeftover, audit.SeverityHigh, st, prefix, audit.Details{"reason": "agent_answer_unusable"}))
		}
		return fail(CodeAgentFailed, true, errors.New("the agent's answer holds no new key of the expected shape"))
	}
	now := s.cfg.Now()
	cand, err := s.verify(ctx, st, key, prefix, now.Add(ttl))
	if err != nil {
		s.discard(ctx, st, cand, prefix, CodeVerify)
		return fail(CodeVerify, false, err)
	}
	expires := resp.GetExpiresAt().AsTime().UTC()
	ref, err := s.store(ctx, st, key)
	if err != nil {
		s.discard(ctx, st, cand, prefix, CodeStore)
		return fail(CodeStore, false, fmt.Errorf("store the new key: %s", logx.RedactString(err.Error())))
	}
	res, err = s.swap(ctx, st, res, op, ref, prefix, expires, ModeBootstrap, func() { s.discard(ctx, st, cand, prefix, CodeSwap) })
	if err != nil {
		return res, err
	}
	res.Outcome = OutcomeBootstrapped
	return s.finish(ctx, st, res, ref, nil)
}

// swap is step 7. discard expires the new key when the swap certainly did not happen. A swap whose outcome is
// unknown (the commit's answer lost) is resolved by reading the reference back; when that fails too, both keys stay
// valid, the new prefix is reported (apikey.leftover) and the job's retry finds the other key as a stray.
func (s *Service) swap(ctx context.Context, st instanceState, res Result, op audit.Operation, ref secrets.Ref, prefix string,
	expires time.Time, mode string, discard func(),
) (Result, error) {
	details := audit.Details{"mode": mode, "key_prefix": prefix, "previous_prefix": st.Prefix, "ref_version": ref.Version,
		"expires_at": expires, "tenant_id": st.TenantID}
	err := s.db.swap(ctx, swapSpec{TenantID: st.TenantID, InstanceID: st.InstanceID, OldRef: st.Ref, NewRef: ref.String(),
		NewPrefix: prefix, NewExpiresAt: expires}, op, details)
	if err != nil {
		if errors.Is(err, errSwapConflict) {
			discard()
			s.destroy(ctx, ref)
			s.fail(ctx, op, CodeSwapConflict, res)
			return res, jobs.Transient(CodeSwapConflict, errors.New("the instance's key reference changed during the rotation"))
		}
		cur, rerr := s.db.currentRef(context.WithoutCancel(ctx), st.TenantID, st.InstanceID)
		switch {
		case rerr == nil && cur == ref.String(): // committed after all
		case rerr == nil && cur == st.Ref:
			discard()
			s.destroy(ctx, ref)
			s.fail(ctx, op, CodeSwap, res)
			return res, jobs.Transient(CodeSwap, fmt.Errorf("record the new key: %s", logx.RedactString(err.Error())))
		default:
			s.raise(ctx, s.event(EventLeftover, audit.SeverityHigh, st, prefix, audit.Details{"reason": "swap_outcome_unknown"}))
			return res, jobs.Transient(CodeSwap, fmt.Errorf("record the new key (outcome unknown): %s", logx.RedactString(err.Error())))
		}
	}
	res.KeyPrefix, res.ExpiresAt, res.RefVersion = prefix, &expires, ref.Version
	s.m.observe(st.TenantID, st.InstanceID, &expires)
	for _, r := range s.cfg.Invalidate { // step 8
		r.Invalidate(st.TenantID)
	}
	s.reg.Invalidate(st.TenantID)
	return res, nil
}

// finish is steps 9–10 after the swap: through the registry — the new key read back from the SecretStore — expire the
// named keys, then every other valid key, and list again: the new key must be the only valid one.
func (s *Service) finish(ctx context.Context, st instanceState, res Result, ref secrets.Ref, expire []string) (Result, error) {
	live, err := s.reg.ForTenant(ctx, st.TenantID)
	if err != nil {
		for _, p := range uniq(expire) {
			s.raise(ctx, s.event(EventLeftover, audit.SeverityHigh, st, p, audit.Details{"reason": "new_key_unusable"}))
		}
		return res, jobs.Transient(CodeOldKeyNotExpired, fmt.Errorf("reach the instance with the new key: %s", describe(err)))
	}
	var failed []string
	for _, p := range uniq(expire) {
		if p == "" || p == res.KeyPrefix {
			continue
		}
		if err := live.ExpireAPIKey(ctx, p); err != nil && !errors.Is(err, headscale.ErrNotFound) {
			failed = append(failed, p)
			continue
		}
		res.ExpiredPrefixes = append(res.ExpiredPrefixes, p)
	}
	keys, err := live.ListAPIKeys(ctx)
	if err != nil {
		for _, p := range failed {
			s.raise(ctx, s.event(EventLeftover, audit.SeverityHigh, st, p, audit.Details{"reason": "expire_failed"}))
		}
		return res, jobs.Transient(CodeOldKeyNotExpired, fmt.Errorf("list the API keys with the new key: %s", describe(err)))
	}
	now := s.cfg.Now()
	res.ValidKeys = 0
	var left []string
	for _, k := range keys {
		if !valid(k, now) {
			continue
		}
		res.ValidKeys++
		if k.Prefix == res.KeyPrefix {
			continue
		}
		if k.Prefix != "" && !slices.Contains(failed, k.Prefix) {
			// valid although not named: created meanwhile, or left by the agent — expire it and record it
			s.raise(ctx, s.event(EventStray, audit.SeverityHigh, st, k.Prefix, keyDetails(k)))
			if err := live.ExpireAPIKey(ctx, k.Prefix); err == nil || errors.Is(err, headscale.ErrNotFound) {
				res.ExpiredPrefixes = append(res.ExpiredPrefixes, k.Prefix)
				res.ValidKeys--
				continue
			}
		}
		left = append(left, label(k))
		s.raise(ctx, s.event(EventLeftover, audit.SeverityHigh, st, label(k), audit.Details{"reason": "still_valid",
			"expires": timeText(&k.Expiration)}))
	}
	if len(left) > 0 {
		return res, jobs.Transient(CodeOldKeyNotExpired, fmt.Errorf("keys still valid besides the new one: %s",
			strings.Join(left, ", ")))
	}
	res.DestroyedRefs = s.destroyOlder(ctx, ref, st.Ref)
	return res, nil
}

// verify is step 5: the new key, through the edge admin listener, lists itself valid with (at least) the requested
// expiration. It returns the candidate instance (usable to expire the key itself) whenever one could be built.
func (s *Service) verify(ctx context.Context, st instanceState, key headscale.Secret, prefix string, want time.Time) (headscale.Instance, error) {
	t, err := s.cfg.Locator.Candidate(st.InstanceID, st.Slug, key)
	if err != nil {
		return nil, fmt.Errorf("verify the new key: %s", logx.RedactString(err.Error()))
	}
	reg := headscale.NewRegistry(headscale.StaticLocator{st.TenantID: t}, s.cfg.Headscale)
	inst, err := reg.ForTenant(ctx, st.TenantID)
	if err != nil {
		return nil, fmt.Errorf("verify the new key: %s", describe(err))
	}
	keys, err := inst.ListAPIKeys(ctx)
	if err != nil {
		return inst, fmt.Errorf("verify the new key (ListAPIKeys with it): %s", describe(err))
	}
	i := slices.IndexFunc(keys, func(k headscale.APIKey) bool { return k.Prefix == prefix })
	switch now := s.cfg.Now(); {
	case i < 0:
		return inst, fmt.Errorf("verify the new key: the instance does not list prefix %s", prefix)
	case !valid(keys[i], now):
		return inst, fmt.Errorf("verify the new key: prefix %s is listed expired", prefix)
	case keys[i].Expiration.IsZero() || keys[i].Expiration.Before(want.Add(-expirySlack)):
		return inst, fmt.Errorf("verify the new key: prefix %s expires %s, requested %s", prefix,
			timeText(&keys[i].Expiration), want.UTC().Format(time.RFC3339))
	}
	return inst, nil
}

// store is step 6: the next version of the instance's secret (version 1 when the name has none — also after a run
// that stored a version and died before recording it).
func (s *Service) store(ctx context.Context, st instanceState, key headscale.Secret) (secrets.Ref, error) {
	name := SecretName
	if cur, err := secrets.ParseRef(st.Ref); err == nil && cur.Tenant == st.TenantID {
		name = cur.Name
	}
	value := []byte(key.Reveal())
	defer clear(value)
	latest, err := s.cfg.Secrets.Latest(ctx, st.TenantID, name)
	if errors.Is(err, secrets.ErrNotFound) {
		ref := secrets.TenantRef(st.TenantID, name, 1)
		return ref, s.cfg.Secrets.Put(ctx, ref, value)
	}
	if err != nil {
		return secrets.Ref{}, err
	}
	return s.cfg.Secrets.Rotate(ctx, latest, value)
}

// discard expires a new key that will not be recorded, with inst (the current key, or the new key itself); a key that
// cannot be expired is reported.
func (s *Service) discard(ctx context.Context, st instanceState, inst headscale.Instance, prefix, reason string) {
	ctx = context.WithoutCancel(ctx)
	if inst != nil {
		err := inst.ExpireAPIKey(ctx, prefix)
		if err == nil || errors.Is(err, headscale.ErrNotFound) {
			s.log.InfoContext(ctx, "apikey: the new key was expired", "instance_id", st.InstanceID.String(), "prefix", prefix,
				"reason", reason)
			return
		}
		s.log.ErrorContext(ctx, "apikey: the new key could not be expired", "instance_id", st.InstanceID.String(),
			"prefix", prefix, "reason", reason, "error", describe(err))
	}
	s.raise(ctx, s.event(EventLeftover, audit.SeverityHigh, st, prefix, audit.Details{"reason": reason}))
}

// sweep handles a CreateAPIKey whose outcome is unknown: list again with the current key and expire every valid key
// that was not there before (it may be the key the lost answer carried); one that cannot be expired is reported.
func (s *Service) sweep(ctx context.Context, st instanceState, inst headscale.Instance, known map[string]bool, reason string) {
	ctx = context.WithoutCancel(ctx)
	keys, err := inst.ListAPIKeys(ctx)
	if err != nil {
		s.log.ErrorContext(ctx, "apikey: after an unknown CreateAPIKey outcome the keys could not be listed — a key "+
			"nobody holds may be valid (the next run expires it as a stray)", "instance_id", st.InstanceID.String(),
			"error", describe(err))
		return
	}
	now := s.cfg.Now()
	for _, k := range keys {
		if known[k.Prefix] || !valid(k, now) || k.Prefix == "" {
			continue
		}
		s.discard(ctx, st, inst, k.Prefix, reason)
	}
}

// fail closes the audit pair with .failed (best effort: a failure is logged).
func (s *Service) fail(ctx context.Context, op audit.Operation, code string, res Result) {
	if err := s.db.failed(context.WithoutCancel(ctx), op, code, audit.Details{"mode": res.Mode, "trigger": res.Trigger,
		"previous_prefix": res.PreviousPrefix, "tenant_id": res.TenantID}); err != nil {
		s.log.ErrorContext(ctx, "apikey: audit event NOT recorded", "action", ActionRotate+audit.SuffixFailed,
			"error", logx.RedactString(err.Error()))
	}
}

// destroy erases a secret version that will not be used (best effort).
func (s *Service) destroy(ctx context.Context, ref secrets.Ref) {
	if err := s.cfg.Secrets.Destroy(context.WithoutCancel(ctx), ref); err != nil {
		s.log.WarnContext(ctx, "apikey: could not destroy an unused secret version", "ref", ref.String(),
			"error", logx.RedactString(err.Error()))
	}
}

// destroyOlder erases the versions from the one recorded before (its key is now expired) up to the new one — the range
// also covers versions stored by runs that died before recording them.
func (s *Service) destroyOlder(ctx context.Context, cur secrets.Ref, prevRaw string) []int32 {
	prev, err := secrets.ParseRef(prevRaw)
	if err != nil || prev.Tenant != cur.Tenant || prev.Name != cur.Name || prev.Version >= cur.Version {
		return nil
	}
	var out []int32
	for v := prev.Version; v < cur.Version; v++ {
		r := secrets.Ref{Tenant: cur.Tenant, Name: cur.Name, Version: v}
		if err := s.cfg.Secrets.Destroy(ctx, r); err != nil {
			if !errors.Is(err, secrets.ErrNotFound) {
				s.log.WarnContext(ctx, "apikey: could not destroy an older secret version", "ref", r.String(),
					"error", logx.RedactString(err.Error()))
			}
			continue
		}
		out = append(out, v)
	}
	return out
}

// auditEvent is the platform event of the operation (a platform transaction writes platform events only — 0004);
// the tenant is in the details.
func (s *Service) auditEvent(req Request, st instanceState, d audit.Details) audit.Event {
	d["tenant_id"] = st.TenantID
	return audit.Event{ActorType: audit.ActorSystem, ActorDisplay: req.Actor, Action: ActionRotate,
		ResourceType: "instance", ResourceID: st.InstanceID.String(), Details: d}
}

// event builds a security event of the instance about one key prefix (never the key).
func (s *Service) event(kind, severity string, st instanceState, prefix string, d audit.Details) audit.SecurityEvent {
	d["tenant_id"], d["instance_id"], d["slug"], d["prefix"] = st.TenantID.String(), st.InstanceID.String(), st.Slug, prefix
	return audit.SecurityEvent{Kind: kind, Severity: severity, Source: SecuritySource, Details: d,
		DedupeKey: kind + ":" + st.InstanceID.String() + ":" + prefix, DedupeWindow: EventWindow}
}

// raise records a security event; a failure is logged at ERROR (the caller is already on a failure path).
func (s *Service) raise(ctx context.Context, ev audit.SecurityEvent) {
	wrote, err := s.cfg.Security.RecordSecurityEvent(context.WithoutCancel(ctx), ev)
	if err != nil {
		s.log.ErrorContext(ctx, "apikey: security event NOT recorded", "kind", ev.Kind, "prefix", ev.Details["prefix"],
			"error", logx.RedactString(err.Error()))
		return
	}
	s.m.events.WithLabelValues(ev.Kind).Inc()
	if wrote {
		s.log.WarnContext(ctx, "apikey: security event", "kind", ev.Kind, "severity", ev.Severity, "prefix", ev.Details["prefix"])
	}
}

// ---------------------------------------------------------------------------------------------------- helpers

func valid(k headscale.APIKey, now time.Time) bool {
	return k.Expiration.IsZero() || k.Expiration.After(now)
}

// validOthers returns the valid keys other than the current one.
func validOthers(keys []headscale.APIKey, current string, now time.Time) []headscale.APIKey {
	var out []headscale.APIKey
	for _, k := range keys {
		if valid(k, now) && (k.Prefix != current || current == "") {
			out = append(out, k)
		}
	}
	return out
}

func prefixes(keys []headscale.APIKey) []string {
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, label(k))
	}
	return out
}

// label names a key in reports: its prefix, or its id when the prefix could not be read.
func label(k headscale.APIKey) string {
	if k.Prefix != "" {
		return k.Prefix
	}
	return fmt.Sprintf("id:%d", k.ID)
}

func uniq(s []string) []string {
	out := make([]string, 0, len(s))
	for _, v := range s {
		if v != "" && !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	return out
}

func keyDetails(k headscale.APIKey) audit.Details {
	d := audit.Details{"key_id": int64(k.ID), "created_at": k.CreatedAt.UTC(), "expires": timeText(&k.Expiration)} //nolint:gosec // ids of Headscale
	if k.LastSeen != nil {
		d["last_seen"] = k.LastSeen.UTC()
	}
	return d
}

func timeText(t *time.Time) string {
	if t == nil || t.IsZero() {
		return "never"
	}
	return t.UTC().Format(time.RFC3339)
}

func utcPtr(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	u := t.UTC()
	return &u
}

func jobErr(code string, permanent bool, err error) error {
	if permanent {
		return jobs.Permanent(code, err)
	}
	return jobs.Transient(code, err)
}

// describe is a short, credential-free description of an error of the adapter (or of the locator behind it).
func describe(err error) string {
	if he, ok := headscale.AsError(err); ok {
		s := string(he.Op) + ": " + string(he.Kind)
		if he.Status != 0 {
			s += fmt.Sprintf(" (HTTP %d)", he.Status)
		}
		if he.Err != nil && he.Kind == headscale.KindInternal {
			s += ": " + logx.RedactString(he.Err.Error())
		}
		return s
	}
	return logx.RedactString(err.Error())
}

// agentError describes an agent error by its status code and typed refusal — never its free text.
func agentError(err error) string {
	if r, ok := agentclient.RefusalOf(err); ok {
		return fmt.Sprintf("refused: %s (%s)", r.GetReason().String(), r.GetField())
	}
	return logx.RedactString(err.Error())
}
