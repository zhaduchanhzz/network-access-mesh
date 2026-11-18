package policies

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/notifications"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// Kinds of policy_versions.kind the core stores (P4-T10 adds the typed `user` kind).
const (
	KindUser       = "user"
	KindBaseline   = "baseline"
	KindSuspension = "suspension"
)

// Triggers of policy_applications.trigger the core accepts. tag_change comes with the tag catalog (P4-T15); the
// group and resource changes are accepted for the policy.apply job of their modules (P4-T09, P4-T12).
const (
	TriggerBootstrap   = "bootstrap"
	TriggerManual      = "manual"
	TriggerSuspend     = "suspend"
	TriggerResume      = "resume"
	TriggerRestore     = "restore"
	TriggerDriftRepair = "drift_repair"
	TriggerRollback    = "rollback"
	// TriggerGroupChange, TriggerResourceChange, TriggerTagChange: a change of the tables rendered at apply time
	// (§7.3) re-applies the desired version through the policy.apply job (P4-T09: groups; P4-T12/T15 the others).
	TriggerGroupChange    = "group_change"
	TriggerResourceChange = "resource_change"
	TriggerTagChange      = "tag_change"
)

var coreTriggers = map[string]bool{TriggerBootstrap: true, TriggerManual: true, TriggerSuspend: true,
	TriggerResume: true, TriggerRestore: true, TriggerDriftRepair: true, TriggerRollback: true,
	TriggerGroupChange: true, TriggerResourceChange: true, TriggerTagChange: true}

// Application states (policy_applications.state).
const (
	StatePending = "pending"
	StateApplied = "applied"
	StateFailed  = "failed"
	StateUnknown = "unknown"
)

// Audit actions and security events of the core.
const (
	// ActionApply is the paired operation policy.apply.requested → .succeeded / .failed (§6.1).
	ActionApply = "policy.apply"
	// ActionLintRejected: a policy refused by the lint — nothing stored, Headscale never called.
	ActionLintRejected = "policy.lint_rejected"
	// SecurityStateUnknown: an application ended with an unknown outcome and re-asserting the previous applied policy
	// failed too — what the instance enforces is not known (§7.3, V-26).
	SecurityStateUnknown = "policy.state_unknown"

	resourceApplication = "policy_application"
	resourceVersion     = "policy_version"
	lockName            = "policy"
)

// Error codes of a failed application (policy_applications.error_code, audit reason).
const (
	CodeNoInstance          = "no_instance"
	CodeInstanceUnavailable = "instance_unavailable"
	CodePolicyRejected      = "policy_rejected"
	CodeOutcomeUnknown      = "outcome_unknown"
	CodeReadbackFailed      = "readback_failed"
	CodeReadbackMismatch    = "readback_mismatch"
	CodeInternal            = "internal_error"
)

// Config are the collaborators of a Service. Registry is required.
type Config struct {
	// Registry is the ONLY way to reach a tenant's Headscale (§13.4).
	Registry headscale.Registry
	Logger   *slog.Logger
	// LockWait bounds the wait for the tenant's policy lock (another application in progress); default 2 min.
	LockWait time.Duration
	// Notifier receives the policy.applied event in the transaction that records the success; default
	// notifications.Default.
	Notifier notifications.Enqueuer
}

// Service is the minimal policy core (P3-T08a): versions from raw HuJSON, lint L1/L2, per-tenant advisory lock,
// CheckPolicy → SetPolicy → GetPolicy with a sha256 read-back, policy_applications.
type Service struct {
	st       *store.Store
	reg      headscale.Registry
	log      *slog.Logger
	lockWait time.Duration
	notify   notifications.Enqueuer
	sysWait  time.Duration
}

// New returns the core on the store of the process (worker: mg_worker_tenant — policy_applications are written by the
// worker only, 0013).
func New(st *store.Store, cfg Config) (*Service, error) {
	if st == nil || cfg.Registry == nil {
		return nil, errors.New("policies: a store and a headscale registry are required")
	}
	s := &Service{st: st, reg: cfg.Registry, log: cfg.Logger, lockWait: cfg.LockWait, notify: cfg.Notifier,
		sysWait: 15 * time.Second}
	if s.log == nil {
		s.log = slog.New(slog.DiscardHandler)
	}
	if s.lockWait <= 0 {
		s.lockWait = 2 * time.Minute
	}
	if s.notify == nil {
		s.notify = notifications.Default
	}
	return s, nil
}

// ApplyRequest is one application of a HuJSON policy.
type ApplyRequest struct {
	TenantID uuid.UUID
	// Kind of the version: KindBaseline (default — a platform-issued policy: the deny-all bootstrap, a test fixture)
	// or KindSuspension. Such versions are system-approved (§6.3: no reviewer). KindUser needs the typed model and
	// the review of P4-T10 and is refused here.
	Kind   string
	HuJSON string
	// Trigger of the application (default manual).
	Trigger string
	// RequestedBy is the identity that asked (nil = system: a command, a job).
	RequestedBy *uuid.UUID
	// Actor is the display name of the actor in the audit when there is no request scope (e.g. the command name).
	Actor string
}

// Result describes one application.
type Result struct {
	TenantID       uuid.UUID
	InstanceID     uuid.UUID
	VersionID      uuid.UUID
	Version        int
	VersionCreated bool // false: the content is already the desired version (or the same suspension) — reused
	ApplicationID  uuid.UUID
	State          string // applied | failed
	ContentSHA256  string
	AppliedSHA256  string
	InputsSHA256   string   // policy_applications.inputs_sha256 (content + rendered catalog — RenderCatalog)
	TagOwners      []string // the catalog rendered into "tagOwners" (nil: nothing rendered)
	ReadbackSHA256 string   // sha256 of GetPolicy after SetPolicy ("" when not read)
	ErrorCode      string
	// Reasserted: after an unknown outcome the previously applied policy was sent again and read back identical.
	Reasserted         bool
	HeadscaleUpdatedAt *time.Time
}

// ApplyError is an application that was recorded failed; Result describes it.
type ApplyError struct {
	Code   string
	Result Result
	Err    error
}

func (e *ApplyError) Error() string { return "policy apply failed (" + e.Code + "): " + e.Err.Error() }
func (e *ApplyError) Unwrap() error { return e.Err }

// Errors returned before anything is written.
var (
	ErrInvalidRequest = errors.New("policies: invalid request")
	ErrNoInstance     = errors.New("policies: the tenant has no live instance")
)

// Apply applies a HuJSON policy to the tenant's live instance (§7.3, P3-T08a):
//
//  1. Lint (L2 empty, syntax, L1 grants, decoder guard) — a refused policy writes nothing but the audit event
//     policy.lint_rejected and never reaches Headscale;
//  2. the tenant's policy lock (store.WithTenantLock, advisory, one per tenant): applications of a tenant never
//     interleave — SetPolicy is last-write-wins (§7.2); under it the tenant's tag catalog is read and rendered
//     (RenderCatalog — P4-T15): L6 refuses a tag referenced but not declared (policy.lint_rejected, nothing else), and
//     "tagOwners" becomes the catalog with empty owners;
//  3. one transaction: the version (reused when the content is already the desired version — or the same suspension
//     — otherwise version N+1, system-approved, source_hujson = the text as given), a pending policy_applications row
//     holding exactly the bytes to send, and policy.apply.requested — committed before any call;
//  4. CheckPolicy → SetPolicy (the adapter checks again) → GetPolicy; success = sha256 of what GetPolicy returns (as
//     returned, no trimming: the REST API returns the stored string byte for byte) equals applied_sha256;
//  5. success: one transaction supersedes the instance's current application, marks this one applied, makes a
//     baseline version the desired one (the previous desired version → superseded; a suspension never changes the
//     desired version — §7.3), writes policy.apply.succeeded and the policy.applied notification;
//  6. failure: a refusal before the swap (NotApplied) is recorded failed at once; an unknown outcome (SetPolicy
//     answered non-2xx after sending, the read-back failed or differs) is recorded unknown, the previously applied
//     policy is sent again and read back (§7.3: "luôn gửi lại bản applied gần nhất rồi mới ghi failed"), then the row
//     is failed — no partial application stays recorded as applied; if re-asserting fails as well a security event
//     policy.state_unknown is raised. policy.apply.failed closes the pair.
func (s *Service) Apply(ctx context.Context, req ApplyRequest) (Result, error) {
	if req.Kind == "" {
		req.Kind = KindBaseline
	}
	if req.Trigger == "" {
		req.Trigger = TriggerManual
	}
	switch {
	case req.TenantID == uuid.Nil:
		return Result{}, fmt.Errorf("%w: tenant required", ErrInvalidRequest)
	case req.Kind != KindBaseline && req.Kind != KindSuspension:
		return Result{}, fmt.Errorf("%w: the core applies kind baseline or suspension (user policies need P4-T10)", ErrInvalidRequest)
	case !coreTriggers[req.Trigger]:
		return Result{}, fmt.Errorf("%w: trigger %q", ErrInvalidRequest, req.Trigger)
	}
	doc, err := Lint(req.HuJSON)
	if err != nil {
		s.recordLintRejected(ctx, req, err)
		return Result{TenantID: req.TenantID}, err
	}
	var res Result
	err = s.st.WithTenantLock(ctx, req.TenantID, lockName, s.lockWait, func(ctx context.Context) error {
		rendered, e := s.renderCatalog(ctx, req.TenantID, doc)
		if e != nil {
			if _, lint := IsLint(e); lint {
				s.recordLintRejected(ctx, req, e)
			}
			res = Result{TenantID: req.TenantID}
			return e
		}
		res, e = s.applyLocked(ctx, req, rendered)
		return e
	})
	return res, err
}

// renderCatalog reads the tenant's tag catalog and renders it into the document (RenderCatalog: L6, "tagOwners").
func (s *Service) renderCatalog(ctx context.Context, tenantID uuid.UUID, doc Document) (Document, error) {
	var names []string
	err := s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		var err error
		names, err = q.ListTenantTagNames(ctx, tenantID)
		return err
	})
	if err != nil {
		return Document{}, fmt.Errorf("policies: read the tag catalog: %w", err)
	}
	return RenderCatalog(doc, names)
}

// started is what the first transaction recorded.
type started struct {
	res      Result
	version  sqlcdb.PolicyVersion
	desired  *uuid.UUID
	previous *sqlcdb.PolicyApplication // the instance's current application before this one
	op       audit.Operation
	trigger  string
}

func (s *Service) applyLocked(ctx context.Context, req ApplyRequest, doc Document) (Result, error) {
	st, err := s.begin(ctx, req, doc)
	if err != nil {
		return st.res, err
	}
	res := st.res
	inst, err := s.reg.ForTenant(ctx, req.TenantID)
	if err != nil {
		return s.fail(ctx, st, codeOf(err), false, err)
	}
	if err := inst.CheckPolicy(ctx, doc.Applied); err != nil {
		return s.fail(ctx, st, codeOf(err), false, err)
	}
	stored, err := inst.SetPolicy(ctx, doc.Applied)
	if err != nil {
		if he, ok := headscale.AsError(err); ok && he.Outcome == headscale.OutcomeNotApplied {
			return s.fail(ctx, st, codeOf(err), false, err)
		}
		return s.unknown(ctx, st, inst, CodeOutcomeUnknown, err)
	}
	read, err := inst.GetPolicy(ctx)
	if err != nil {
		return s.unknown(ctx, st, inst, CodeReadbackFailed, err)
	}
	res.ReadbackSHA256 = SHA256Hex(read.Data)
	st.res = res
	if res.ReadbackSHA256 != doc.AppliedSHA256 {
		return s.unknown(ctx, st, inst, CodeReadbackMismatch,
			fmt.Errorf("GetPolicy sha256 %s differs from the document sent (%s)", res.ReadbackSHA256, doc.AppliedSHA256))
	}
	at := read.UpdatedAt
	if at.IsZero() {
		at = stored.UpdatedAt
	}
	return s.succeed(ctx, st, at)
}

// begin resolves the instance and the version, writes the pending application and policy.apply.requested.
func (s *Service) begin(ctx context.Context, req ApplyRequest, doc Document) (started, error) {
	st := started{res: Result{TenantID: req.TenantID, ContentSHA256: doc.ContentSHA256, AppliedSHA256: doc.AppliedSHA256,
		InputsSHA256: doc.InputsSHA256, TagOwners: doc.TagOwners, State: StatePending}, trigger: req.Trigger}
	report, _ := json.Marshal(map[string]any{"engine": "p3-t08a", "lint": map[string]any{
		"result": "passed", "rules": []string{RuleL2, RuleSyntax, RuleL1, RuleDecoderGuard, RuleL6}}})
	err := s.st.WithTenantTx(ctx, req.TenantID, func(q *sqlcdb.Queries) error {
		inst, err := q.GetLiveInstanceForTenant(ctx, req.TenantID)
		if errors.Is(err, store.ErrNoRows) {
			return ErrNoInstance
		}
		if err != nil {
			return err
		}
		st.res.InstanceID = inst.ID
		if st.desired, err = q.GetTenantPolicyState(ctx, req.TenantID); err != nil {
			return err
		}
		v, reused, err := s.version(ctx, q, req, doc, st.desired, report)
		if err != nil {
			return err
		}
		st.version = v
		st.res.VersionID, st.res.Version, st.res.VersionCreated = v.ID, int(v.Version), !reused
		cur, err := q.GetCurrentPolicyApplication(ctx, sqlcdb.GetCurrentPolicyApplicationParams{TenantID: req.TenantID,
			InstanceID: inst.ID})
		switch {
		case err == nil:
			st.previous = &cur
		case !errors.Is(err, store.ErrNoRows):
			return err
		}
		app, err := q.InsertPolicyApplication(ctx, sqlcdb.InsertPolicyApplicationParams{TenantID: req.TenantID,
			InstanceID: inst.ID, PolicyVersionID: v.ID, Trigger: req.Trigger, InputsSha256: &doc.InputsSHA256,
			AppliedHujson: doc.Applied, AppliedSha256: doc.AppliedSHA256, RequestedByIdentityID: req.RequestedBy})
		if err != nil {
			return err
		}
		st.res.ApplicationID = app.ID
		st.op, err = audit.Requested(ctx, q, s.event(req, ActionApply, app.ID.String(), audit.Details{
			"version_id": v.ID, "version": v.Version, "version_created": !reused, "kind": req.Kind,
			"trigger": req.Trigger, "instance_id": inst.ID, "content_sha256": doc.ContentSHA256,
			"applied_sha256": doc.AppliedSHA256, "inputs_sha256": doc.InputsSHA256, "tag_owners": doc.TagOwners}))
		return err
	})
	if err != nil {
		if errors.Is(err, ErrNoInstance) {
			return st, err
		}
		return st, fmt.Errorf("policies: record the application: %w", err)
	}
	return st, nil
}

// version returns the version to apply: the desired version when it has exactly this content (baseline), the latest
// suspension version with this content, or a new system-approved version N+1.
func (s *Service) version(ctx context.Context, q *sqlcdb.Queries, req ApplyRequest, doc Document, desired *uuid.UUID,
	report []byte,
) (sqlcdb.PolicyVersion, bool, error) {
	switch {
	case req.Kind == KindBaseline && desired != nil:
		v, err := q.GetPolicyVersion(ctx, sqlcdb.GetPolicyVersionParams{TenantID: req.TenantID, ID: *desired})
		if err != nil {
			return sqlcdb.PolicyVersion{}, false, err
		}
		if v.Kind == KindBaseline && v.SourceHujson != nil && v.ContentSha256 == doc.ContentSHA256 && v.State == "approved" {
			return v, true, nil
		}
	case req.Kind == KindSuspension:
		v, err := q.LatestHuJSONPolicyVersion(ctx, sqlcdb.LatestHuJSONPolicyVersionParams{TenantID: req.TenantID,
			Kind: KindSuspension, ContentSha256: doc.ContentSHA256})
		if err == nil {
			return v, true, nil
		}
		if !errors.Is(err, store.ErrNoRows) {
			return sqlcdb.PolicyVersion{}, false, err
		}
	}
	n, err := q.NextPolicyVersionNumber(ctx, req.TenantID)
	if err != nil {
		return sqlcdb.PolicyVersion{}, false, err
	}
	p := sqlcdb.InsertHuJSONPolicyVersionParams{TenantID: req.TenantID, Version: n, Kind: req.Kind,
		SourceHujson: &doc.HuJSON, ContentSha256: doc.ContentSHA256, ValidationReport: report}
	if req.Kind == KindBaseline {
		p.ParentVersionID = desired
	}
	v, err := q.InsertHuJSONPolicyVersion(ctx, p)
	return v, false, err
}

// succeed records the success (step 5).
func (s *Service) succeed(ctx context.Context, st started, updatedAt time.Time) (Result, error) {
	res := st.res
	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.sysWait)
	defer cancel()
	var hsAt *time.Time
	if !updatedAt.IsZero() {
		u := updatedAt.UTC()
		hsAt = &u
	}
	record := func(withNotification bool) error {
		return s.st.WithTenantJobTx(wctx, res.TenantID, func(tx *store.Tx) error {
			q := tx.Q
			if _, err := q.SupersedeCurrentPolicyApplication(wctx, sqlcdb.SupersedeCurrentPolicyApplicationParams{
				TenantID: res.TenantID, InstanceID: res.InstanceID, KeepID: res.ApplicationID}); err != nil {
				return err
			}
			if _, err := q.FinishPolicyApplication(wctx, sqlcdb.FinishPolicyApplicationParams{State: StateApplied,
				HeadscaleUpdatedAt: hsAt, TenantID: res.TenantID, ID: res.ApplicationID}); err != nil {
				return err
			}
			if st.version.Kind == KindBaseline && (st.desired == nil || *st.desired != st.version.ID) {
				if err := q.SetTenantDesiredPolicy(wctx, sqlcdb.SetTenantDesiredPolicyParams{VersionID: &st.version.ID,
					TenantID: res.TenantID}); err != nil {
					return err
				}
				if st.desired != nil {
					if err := q.SetPolicyVersionState(wctx, sqlcdb.SetPolicyVersionStateParams{State: "superseded",
						TenantID: res.TenantID, ID: *st.desired}); err != nil {
						return err
					}
				}
			}
			if err := st.op.Succeeded(wctx, q, audit.Details{"applied_sha256": res.AppliedSHA256,
				"readback_sha256": res.ReadbackSHA256, "version": res.Version, "notified": withNotification}); err != nil {
				return err
			}
			if !withNotification {
				return nil
			}
			_, err := s.notify.Enqueue(wctx, tx, notifications.PolicyApplied(res.TenantID, res.ApplicationID,
				res.VersionID, res.Version, st.version.Kind, st.trigger, res.AppliedSHA256))
			return err
		})
	}
	err := record(true)
	if err != nil {
		// The policy IS on Headscale: never lose that record because of the notification — record it without.
		s.log.ErrorContext(ctx, "policies: recording the application with its notification failed; retrying without",
			"application_id", res.ApplicationID, "sqlstate", store.SQLState(err), "error", err.Error())
		err = record(false)
	}
	if err != nil {
		res.State, res.ErrorCode = StatePending, CodeInternal
		return res, fmt.Errorf("policies: the policy was applied (read-back %s) but recording it failed: %w",
			res.ReadbackSHA256, err)
	}
	res.State, res.HeadscaleUpdatedAt = StateApplied, hsAt
	s.log.InfoContext(ctx, "policies: applied", "tenant_id", res.TenantID, "application_id", res.ApplicationID,
		"version", res.Version, "applied_sha256", res.AppliedSHA256)
	return res, nil
}

// unknown handles an outcome that may have reached Headscale: record unknown, re-assert the previous applied policy,
// then fail.
func (s *Service) unknown(ctx context.Context, st started, inst headscale.Instance, code string, cause error) (Result, error) {
	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.sysWait)
	err := s.st.WithTenantTx(wctx, st.res.TenantID, func(q *sqlcdb.Queries) error {
		return q.MarkPolicyApplicationUnknown(wctx, sqlcdb.MarkPolicyApplicationUnknownParams{TenantID: st.res.TenantID,
			ID: st.res.ApplicationID})
	})
	cancel()
	if err != nil {
		s.log.ErrorContext(ctx, "policies: marking the application unknown failed", "application_id", st.res.ApplicationID,
			"sqlstate", store.SQLState(err))
	}
	reasserted := false
	if st.previous != nil {
		rctx, rcancel := context.WithTimeout(context.WithoutCancel(ctx), 2*s.sysWait)
		reasserted = s.reassert(rctx, inst, *st.previous)
		rcancel()
	}
	if !reasserted {
		s.raiseStateUnknown(ctx, st, code)
	}
	return s.fail(ctx, st, code, reasserted, cause)
}

// reassert sends the previously applied policy again and reads it back (§7.3, V-26).
func (s *Service) reassert(ctx context.Context, inst headscale.Instance, prev sqlcdb.PolicyApplication) bool {
	if _, err := inst.SetPolicy(ctx, prev.AppliedHujson); err != nil {
		s.log.ErrorContext(ctx, "policies: re-asserting the previous policy failed", "application_id", prev.ID, "error", err.Error())
		return false
	}
	read, err := inst.GetPolicy(ctx)
	if err != nil || SHA256Hex(read.Data) != prev.AppliedSha256 {
		s.log.ErrorContext(ctx, "policies: the re-asserted policy does not read back", "application_id", prev.ID)
		return false
	}
	return true
}

// raiseStateUnknown writes the security event of an application whose outcome stays unknown.
func (s *Service) raiseStateUnknown(ctx context.Context, st started, code string) {
	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.sysWait)
	defer cancel()
	tenant := st.res.TenantID
	err := s.st.WithTenantTx(wctx, tenant, func(q *sqlcdb.Queries) error {
		_, err := audit.RecordSecurityEvent(wctx, q, audit.SecurityEvent{TenantID: &tenant, Kind: SecurityStateUnknown,
			Severity: audit.SeverityHigh, Source: "policies", Details: audit.Details{"application_id": st.res.ApplicationID,
				"instance_id": st.res.InstanceID, "error_code": code, "had_previous": st.previous != nil}})
		return err
	})
	if err != nil {
		s.log.ErrorContext(ctx, "policies: the security event of an unknown policy state was NOT recorded",
			"application_id", st.res.ApplicationID, "sqlstate", store.SQLState(err))
	}
}

// fail records the application failed and closes the audit pair (detached from ctx).
func (s *Service) fail(ctx context.Context, st started, code string, reasserted bool, cause error) (Result, error) {
	res := st.res
	res.State, res.ErrorCode, res.Reasserted = StateFailed, code, reasserted
	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.sysWait)
	defer cancel()
	err := s.st.WithTenantTx(wctx, res.TenantID, func(q *sqlcdb.Queries) error {
		c := code
		if _, err := q.FinishPolicyApplication(wctx, sqlcdb.FinishPolicyApplicationParams{State: StateFailed,
			ErrorCode: &c, TenantID: res.TenantID, ID: res.ApplicationID}); err != nil {
			return err
		}
		return st.op.Failed(wctx, q, code, audit.Details{"reasserted": reasserted, "had_previous": st.previous != nil,
			"cause": causeKind(cause)})
	})
	if err != nil {
		s.log.ErrorContext(ctx, "policies: recording the failed application failed", "application_id", res.ApplicationID,
			"sqlstate", store.SQLState(err))
	}
	s.log.WarnContext(ctx, "policies: application failed", "tenant_id", res.TenantID, "application_id", res.ApplicationID,
		"code", code, "reasserted", reasserted, "error", cause.Error())
	return res, &ApplyError{Code: code, Result: res, Err: cause}
}

// codeOf maps an adapter error to the error code of the application.
func codeOf(err error) string {
	he, ok := headscale.AsError(err)
	if !ok {
		return CodeInternal
	}
	switch he.Kind {
	case headscale.KindValidation, headscale.KindPolicyRejected, headscale.KindUpstreamRejected, headscale.KindNoPolicy:
		return CodePolicyRejected
	case headscale.KindInternal:
		return CodeInternal
	}
	return CodeInstanceUnavailable
}

// causeKind is the adapter error kind of cause for the audit ("" for another error) — never the upstream message.
func causeKind(err error) string {
	if he, ok := headscale.AsError(err); ok {
		return string(he.Kind)
	}
	return ""
}

// event builds an audit event of the core: the request scope's actor when there is one, the system otherwise.
func (s *Service) event(req ApplyRequest, action, resourceID string, d audit.Details) audit.Event {
	tenant := req.TenantID
	ev := audit.Event{TenantID: &tenant, Action: action, ResourceType: resourceApplication, ResourceID: resourceID,
		Details: d, ActorDisplay: req.Actor}
	if req.RequestedBy != nil {
		ev.ActorType, ev.ActorIdentityID = audit.ActorIdentity, req.RequestedBy
	} else {
		ev.ActorType = audit.ActorSystem
	}
	return ev
}

// recordLintRejected writes policy.lint_rejected (outcome failure) for an existing tenant; nothing else is written.
func (s *Service) recordLintRejected(ctx context.Context, req ApplyRequest, lintErr error) {
	le, _ := IsLint(lintErr)
	if le == nil {
		return
	}
	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.sysWait)
	defer cancel()
	err := s.st.WithTenantTx(wctx, req.TenantID, func(q *sqlcdb.Queries) error {
		if _, err := q.GetTenantPolicyState(wctx, req.TenantID); err != nil {
			return err // unknown tenant in this scope: nothing to audit
		}
		d := audit.Details{"rule": le.Rule, "error_code": le.Code(), "kind": req.Kind, "trigger": req.Trigger,
			"bytes": len(req.HuJSON)}
		if len(le.Tags) > 0 {
			d["tags"] = le.Tags
		}
		ev := s.event(req, ActionLintRejected, "", d)
		ev.ResourceType, ev.Outcome = resourceVersion, audit.OutcomeFailure
		return audit.Record(wctx, q, ev)
	})
	if err != nil && !errors.Is(err, store.ErrNoRows) {
		s.log.ErrorContext(ctx, "policies: the audit event of a rejected policy was NOT recorded", "tenant_id", req.TenantID,
			"sqlstate", store.SQLState(err))
	}
}
