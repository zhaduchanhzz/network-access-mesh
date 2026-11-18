package policies

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// The policy step of the reconcile after a PostgreSQL restore to an older point (P3-T17, §17.2 step 4): Headscale is
// authoritative for the policy in force (§6.4); the restored database may know an OLDER one. The running policy is
// compared with the instance's current application and, when they differ, it is never overwritten: the running string
// is recorded as the instance's current application (trigger restore, state applied — the reference of the drift
// check and of the post-start gate from now on), imported as a new policy version of kind user in state validated
// (draft when it fails the lint) made the desired version, and the tenant is flagged for review (a tenant-scoped
// security event and the report of the command). Nothing applies a version that is not approved (§7.3): the policy in
// force stays until an Owner/Admin reviews and approves it.

// Outcomes of ReviewRunning.
const (
	RunningMatch       = "match"        // Headscale runs the current application recorded in the database
	RunningAdopted     = "adopted"      // a different policy runs: recorded and flagged for review, not overwritten
	RunningWouldAdopt  = "would_adopt"  // dry run of RunningAdopted
	RunningNoPolicy    = "no_policy"    // the instance stores no policy (allow-all at its next restart): flagged
	RunningUnavailable = "unavailable"  // the instance could not be read
	RunningNoInstance  = "no_instance"  // the tenant has no live instance
	RunningLocked      = "lock_timeout" // another policy operation of the tenant holds its lock
)

// Audit action and security event of the step.
const (
	// ActionRestoreAdopted: the running policy was recorded as current application and imported as a version.
	ActionRestoreAdopted = "policy.restore_adopted"
	// SecurityRestoreReview: a tenant whose running policy differs from what the restored database knows (or that runs
	// none) — an Owner/Admin must review it (tenant-scoped, so the tenant sees it too).
	SecurityRestoreReview = "policy.restore_review_required"
)

// usernameRE finds the Headscale user names the platform gives its members (mg-<membership uuid>, §6.3).
var usernameRE = regexp.MustCompile(`mg-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)

// RunningReview asks for the policy step of one tenant.
type RunningReview struct {
	TenantID     uuid.UUID
	RunID        uuid.UUID // the post-restore run (audit, security event)
	RestorePoint time.Time
	DryRun       bool
	Actor        string
}

// RunningResult is the outcome of the step for one tenant (no policy text: hashes, version numbers, user names).
type RunningResult struct {
	TenantID      uuid.UUID  `json:"tenant_id"`
	InstanceID    uuid.UUID  `json:"instance_id,omitzero"`
	Outcome       string     `json:"outcome"`
	RunningSHA256 string     `json:"running_sha256,omitempty"`
	RecordedSHA   string     `json:"recorded_sha256,omitempty"` // the current application of the database ("" none)
	VersionID     *uuid.UUID `json:"version_id,omitempty"`
	Version       int        `json:"version,omitempty"`
	VersionStatus string     `json:"version_status,omitempty"` // validated | draft
	LintRule      string     `json:"lint_rule,omitempty"`
	ApplicationID *uuid.UUID `json:"application_id,omitempty"`
	// UnmappedUsers are the mg-<uuid> users the running policy names that map to no active membership of the tenant.
	UnmappedUsers []string `json:"unmapped_users,omitempty"`
	ErrorCode     string   `json:"error_code,omitempty"`
	Review        bool     `json:"review_required"`
}

// ReviewRunning is the policy step of the post-restore reconcile for one tenant, under the tenant's policy lock (no
// application interleaves). It never calls SetPolicy.
func (s *Service) ReviewRunning(ctx context.Context, req RunningReview) (RunningResult, error) {
	res := RunningResult{TenantID: req.TenantID}
	if req.TenantID == uuid.Nil {
		return res, fmt.Errorf("%w: tenant required", ErrInvalidRequest)
	}
	err := s.st.WithTenantLock(ctx, req.TenantID, lockName, s.lockWait, func(ctx context.Context) error {
		var e error
		res, e = s.reviewLocked(ctx, req, res)
		return e
	})
	if errors.Is(err, store.ErrLockTimeout) {
		res.Outcome, res.ErrorCode = RunningLocked, RunningLocked
		return res, nil
	}
	return res, err
}

func (s *Service) reviewLocked(ctx context.Context, req RunningReview, res RunningResult) (RunningResult, error) {
	var cur *sqlcdb.PolicyApplication
	err := s.st.WithTenantTx(ctx, req.TenantID, func(q *sqlcdb.Queries) error {
		inst, err := q.GetLiveInstanceForTenant(ctx, req.TenantID)
		if err != nil {
			return err
		}
		res.InstanceID = inst.ID
		a, err := q.GetCurrentPolicyApplication(ctx, sqlcdb.GetCurrentPolicyApplicationParams{TenantID: req.TenantID,
			InstanceID: inst.ID})
		switch {
		case err == nil:
			cur = &a
			res.RecordedSHA = a.AppliedSha256
		case !errors.Is(err, store.ErrNoRows):
			return err
		}
		return nil
	})
	if errors.Is(err, store.ErrNoRows) {
		res.Outcome = RunningNoInstance
		return res, nil
	}
	if err != nil {
		return res, fmt.Errorf("policies: read the current application: %w", err)
	}
	inst, err := s.reg.ForTenant(ctx, req.TenantID)
	var running headscale.Policy
	if err == nil {
		running, err = inst.GetPolicy(ctx)
	}
	if err != nil {
		if he, ok := headscale.AsError(err); ok && he.Kind == headscale.KindNoPolicy {
			res.Outcome, res.Review = RunningNoPolicy, true
			if !req.DryRun {
				if err := s.flag(ctx, req, res, "no_policy"); err != nil {
					return res, err
				}
			}
			return res, nil
		}
		res.Outcome, res.ErrorCode = RunningUnavailable, "headscale_"+causeKind(err)
		if causeKind(err) == "" {
			res.ErrorCode = "headscale_error"
		}
		return res, nil
	}
	res.RunningSHA256 = SHA256Hex(running.Data)
	if cur != nil && cur.AppliedSha256 == res.RunningSHA256 {
		res.Outcome = RunningMatch
		return res, nil
	}
	res.Review = true
	users := uniqueUsers(running.Data)
	if req.DryRun {
		res.Outcome = RunningWouldAdopt
		res.UnmappedUsers, err = s.unmapped(ctx, req.TenantID, users)
		return res, err
	}
	return s.adopt(ctx, req, res, running, cur, users)
}

// adopt records the running policy (one tenant transaction): version (validated or draft), application (restore,
// applied, the previous current one superseded), desired version, audit event and security event.
func (s *Service) adopt(ctx context.Context, req RunningReview, res RunningResult, running headscale.Policy,
	cur *sqlcdb.PolicyApplication, users []string,
) (RunningResult, error) {
	status, report := "validated", map[string]any{"engine": "p3-t17", "source": "headscale_get_policy",
		"lint": map[string]any{"result": "passed", "rules": []string{RuleL2, RuleSyntax, RuleL1, RuleDecoderGuard}}}
	if _, err := Lint(running.Data); err != nil {
		le, _ := IsLint(err)
		status = "draft"
		rule := "unknown"
		if le != nil {
			rule = le.Rule
		}
		res.LintRule = rule
		report["lint"] = map[string]any{"result": "failed", "rule": rule}
	}
	raw, _ := json.Marshal(report)
	var hsAt *time.Time
	if !running.UpdatedAt.IsZero() {
		u := running.UpdatedAt.UTC()
		hsAt = &u
	}
	text, sha := running.Data, res.RunningSHA256
	err := s.st.WithTenantTx(ctx, req.TenantID, func(q *sqlcdb.Queries) error {
		desired, err := q.GetTenantPolicyState(ctx, req.TenantID)
		if err != nil {
			return err
		}
		n, err := q.NextPolicyVersionNumber(ctx, req.TenantID)
		if err != nil {
			return err
		}
		v, err := q.InsertImportedPolicyVersion(ctx, sqlcdb.InsertImportedPolicyVersionParams{TenantID: req.TenantID,
			Version: n, SourceHujson: &text, ContentSha256: sha, State: status, ValidationReport: raw,
			ParentVersionID: desired})
		if err != nil {
			return err
		}
		app, err := q.InsertPolicyApplication(ctx, sqlcdb.InsertPolicyApplicationParams{TenantID: req.TenantID,
			InstanceID: res.InstanceID, PolicyVersionID: v.ID, Trigger: TriggerRestore, InputsSha256: &sha,
			AppliedHujson: text, AppliedSha256: sha})
		if err != nil {
			return err
		}
		if _, err := q.SupersedeCurrentPolicyApplication(ctx, sqlcdb.SupersedeCurrentPolicyApplicationParams{
			TenantID: req.TenantID, InstanceID: res.InstanceID, KeepID: app.ID}); err != nil {
			return err
		}
		if _, err := q.FinishPolicyApplication(ctx, sqlcdb.FinishPolicyApplicationParams{State: StateApplied,
			HeadscaleUpdatedAt: hsAt, TenantID: req.TenantID, ID: app.ID}); err != nil {
			return err
		}
		if err := q.SetTenantDesiredPolicy(ctx, sqlcdb.SetTenantDesiredPolicyParams{VersionID: &v.ID,
			TenantID: req.TenantID}); err != nil {
			return err
		}
		known, err := q.ListActiveHeadscaleUsernames(ctx, sqlcdb.ListActiveHeadscaleUsernamesParams{TenantID: req.TenantID,
			Usernames: users})
		if err != nil {
			return err
		}
		res.UnmappedUsers = missing(users, known)
		res.VersionID, res.Version, res.VersionStatus, res.ApplicationID = &v.ID, int(v.Version), status, &app.ID
		previous := ""
		if cur != nil {
			previous = cur.ID.String()
		}
		tenant := req.TenantID
		if err := audit.Record(ctx, q, audit.Event{TenantID: &tenant, ActorType: audit.ActorSystem, ActorDisplay: req.Actor,
			Action: ActionRestoreAdopted, ResourceType: resourceVersion, ResourceID: v.ID.String(), Details: audit.Details{
				"run_id": req.RunID, "restore_point": req.RestorePoint.UTC(), "instance_id": res.InstanceID,
				"version": v.Version, "version_status": status, "running_sha256": sha, "recorded_sha256": res.RecordedSHA,
				"application_id": app.ID, "superseded_application_id": previous, "unmapped_users": len(res.UnmappedUsers),
				"lint_rule": res.LintRule}}); err != nil {
			return err
		}
		_, err = audit.RecordSecurityEvent(ctx, q, s.reviewEvent(req, res, "running_policy_differs"))
		return err
	})
	if err != nil {
		return res, fmt.Errorf("policies: record the running policy: %w", err)
	}
	res.Outcome = RunningAdopted
	s.log.WarnContext(ctx, "policies: the running policy differs from the restored database — recorded, not overwritten, "+
		"flagged for review", "tenant_id", req.TenantID, "version", res.Version, "version_status", status,
		"running_sha256", sha, "recorded_sha256", res.RecordedSHA)
	return res, nil
}

// flag records the review security event alone (no policy to import).
func (s *Service) flag(ctx context.Context, req RunningReview, res RunningResult, reason string) error {
	return s.st.WithTenantTx(ctx, req.TenantID, func(q *sqlcdb.Queries) error {
		_, err := audit.RecordSecurityEvent(ctx, q, s.reviewEvent(req, res, reason))
		return err
	})
}

func (s *Service) reviewEvent(req RunningReview, res RunningResult, reason string) audit.SecurityEvent {
	tenant := req.TenantID
	d := audit.Details{"reason": reason, "run_id": req.RunID, "restore_point": req.RestorePoint.UTC(),
		"instance_id": res.InstanceID, "running_sha256": res.RunningSHA256, "recorded_sha256": res.RecordedSHA,
		"unmapped_users": len(res.UnmappedUsers)}
	if res.VersionID != nil {
		d["version_id"], d["version"], d["version_status"] = *res.VersionID, res.Version, res.VersionStatus
	}
	return audit.SecurityEvent{TenantID: &tenant, Kind: SecurityRestoreReview, Severity: audit.SeverityHigh,
		Source: "policies", Details: d, DedupeKey: SecurityRestoreReview + ":" + req.TenantID.String() + ":" + req.RunID.String(),
		DedupeWindow: 24 * time.Hour}
}

// unmapped lists the users of the policy without an active membership (dry run: a read-only tenant transaction).
func (s *Service) unmapped(ctx context.Context, tenant uuid.UUID, users []string) ([]string, error) {
	if len(users) == 0 {
		return nil, nil
	}
	var known []string
	err := s.st.WithTenantTx(ctx, tenant, func(q *sqlcdb.Queries) error {
		var err error
		known, err = q.ListActiveHeadscaleUsernames(ctx, sqlcdb.ListActiveHeadscaleUsernamesParams{TenantID: tenant,
			Usernames: users})
		return err
	})
	return missing(users, known), err
}

func uniqueUsers(text string) []string {
	out := usernameRE.FindAllString(text, -1)
	slices.Sort(out)
	out = slices.Compact(out)
	if out == nil {
		out = []string{}
	}
	return out
}

func missing(want, have []string) []string {
	var out []string
	for _, u := range want {
		if !slices.Contains(have, u) {
			out = append(out, u)
		}
	}
	return out
}
