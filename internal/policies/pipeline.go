package policies

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// The full apply pipeline of P4-T10 (§7.3): the tenant's DESIRED version — typed (source) or HuJSON (a platform
// baseline, a policy imported by a restore and approved since) — rendered with the tables as they are now, linted, then
// applied by the core (CheckPolicy → SetPolicy → GetPolicy, sha256 read-back, one policy_applications row) on that same
// version: a re-application never creates a version.

// DesiredRequest is one application of the tenant's desired version.
type DesiredRequest struct {
	TenantID    uuid.UUID
	Trigger     string     // policy_applications.trigger (default manual)
	RequestedBy *uuid.UUID // nil = system
	Actor       string     // audit display name when there is no request scope
	// Suspended: the tenant is suspended (tenant.resume applies its desired version before the status moves) — the
	// instance is reached through the Suspended registry.
	Suspended bool
}

var (
	// ErrNoDesired: the tenant has no desired version (nothing was ever applied — provisioning applies the baseline).
	ErrNoDesired = errors.New("policies: the tenant has no desired policy version")
	// ErrDesiredNotApproved: the desired version is not approved (e.g. imported by a restore, waiting for review — §17.2).
	ErrDesiredNotApproved = errors.New("policies: the desired policy version is not approved")
)

// ApplyDesired renders the tenant's desired version with the current tables and applies it (§7.3 level-triggered):
// under the tenant's policy lock, the render and its lint first — a refusal is audited (policy.lint_rejected) and
// nothing reaches Headscale —, then the core's steps on the desired version itself.
func (s *Service) ApplyDesired(ctx context.Context, req DesiredRequest) (Result, error) {
	if req.Trigger == "" {
		req.Trigger = TriggerManual
	}
	switch {
	case req.TenantID == uuid.Nil:
		return Result{}, fmt.Errorf("%w: tenant required", ErrInvalidRequest)
	case !coreTriggers[req.Trigger]:
		return Result{}, fmt.Errorf("%w: trigger %q", ErrInvalidRequest, req.Trigger)
	}
	var res Result
	err := s.st.WithTenantLock(ctx, req.TenantID, lockName, s.lockWait, func(ctx context.Context) error {
		v, doc, err := s.renderDesired(ctx, req.TenantID)
		ar := ApplyRequest{TenantID: req.TenantID, Kind: v.Kind, HuJSON: doc.HuJSON, Trigger: req.Trigger,
			RequestedBy: req.RequestedBy, Actor: req.Actor, reachSuspended: req.Suspended}
		if err != nil {
			if _, lint := IsLint(err); lint {
				s.recordLintRejected(ctx, ar, err)
			}
			res = Result{TenantID: req.TenantID}
			return err
		}
		res, err = s.applyLocked(ctx, ar, doc, &v)
		return err
	})
	return res, err
}

// renderDesired reads the desired version and renders it (renderVersion).
func (s *Service) renderDesired(ctx context.Context, tenantID uuid.UUID) (sqlcdb.PolicyVersion, Document, error) {
	var (
		v   sqlcdb.PolicyVersion
		doc Document
	)
	err := s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		d, err := q.GetTenantPolicyState(ctx, tenantID)
		if err != nil {
			return err
		}
		if d == nil {
			return ErrNoDesired
		}
		if v, err = q.GetPolicyVersion(ctx, sqlcdb.GetPolicyVersionParams{TenantID: tenantID, ID: *d}); err != nil {
			return err
		}
		if v.State != "approved" {
			return ErrDesiredNotApproved
		}
		r, err := renderVersion(ctx, q, tenantID, v)
		if err != nil {
			return err
		}
		if le := r.Report.firstError(); le != nil {
			return le
		}
		doc = r.Document
		return nil
	})
	return v, doc, err
}

// renderVersion renders a version over the tables of q: a typed version through RenderTyped (L3–L13 + the output
// checks), a HuJSON version through Lint + RenderCatalog + OutputLint (the core's path — P3-T08a, P4-T15). The report
// is blocking when the version cannot be applied as it is.
func renderVersion(ctx context.Context, q *sqlcdb.Queries, tenantID uuid.UUID, v sqlcdb.PolicyVersion) (Rendered, error) {
	in, err := loadRenderInputs(ctx, q, tenantID)
	if err != nil {
		return Rendered{}, err
	}
	if v.Source != nil {
		src, err := ParseSource(v.Source)
		if err != nil {
			rep := newReport()
			rep.add(Finding{Rule: RuleL3, Severity: SeverityError, Code: "source_invalid", Message: err.Error()})
			rep.finish()
			return Rendered{Report: rep}, nil
		}
		return RenderTyped(src, v.ContentSha256, in), nil
	}
	return renderHuJSON(v, in), nil
}

// renderHuJSON is the core's path for a HuJSON version, as a report.
func renderHuJSON(v sqlcdb.PolicyVersion, in *RenderInputs) Rendered {
	rep := newReport()
	text := ""
	if v.SourceHujson != nil {
		text = *v.SourceHujson
	}
	doc, err := Lint(text)
	if err == nil {
		doc, err = RenderCatalog(doc, in.Catalog)
	}
	if err != nil {
		f := Finding{Rule: RuleSyntax, Severity: SeverityError, Code: "lint", Message: err.Error()}
		if le, ok := IsLint(err); ok {
			f.Rule, f.Code, f.Message = le.Rule, le.Code(), le.Detail
		}
		rep.add(f)
		rep.finish()
		return Rendered{Report: rep}
	}
	for _, f := range OutputLint(doc.Applied) {
		rep.add(f)
	}
	rep.RenderedSHA256 = doc.AppliedSHA256
	rep.finish()
	return Rendered{Document: doc, Report: rep}
}

// The lifecycle jobs of a tenant the policy.apply job reads (internal/provisioning/lifecycle — not imported: it
// imports this package).
const (
	lifecycleSuspend = "tenant.suspend"
	lifecycleResume  = "tenant.resume"
)

// Modes of one round of policy.apply.
const (
	modeSkip       = "skip"
	modeDesired    = "desired"
	modeSuspension = "suspension"
)

// plan is what one round of the policy.apply job applies.
type plan struct {
	mode    string
	skip    string
	trigger string
}

// planApply reads the tenant's state (level-triggered, §13.5): a tenant being suspended (an unfinished tenant.suspend
// that is not compensating) gets the suspension policy at once — the deny-all step of tenant.suspend no longer waits
// for the lifecycle lock (§11.4, P3-T08 "Còn lại"); a suspended tenant gets it again on a suspend or drift_repair
// trigger (never while a tenant.resume is unfinished: the resume owns the policy then); an active tenant gets its
// desired version; anything else is skipped with its reason.
func (s *Service) planApply(ctx context.Context, tenantID uuid.UUID, trigger string) (plan, error) {
	var p plan
	err := s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		t, err := q.GetTenant(ctx, tenantID)
		if err != nil {
			return err
		}
		var kind, status string
		if j, err := q.GetActiveJobByDedupeKey(ctx, jobs.LockKey(tenantID)); err == nil {
			kind, status = j.Kind, j.Status
		} else if !errors.Is(err, store.ErrNoRows) {
			return err
		}
		suspending := kind == lifecycleSuspend && status != "compensating"
		resuming := kind == lifecycleResume
		switch {
		case t.Status == "active" && suspending:
			p = plan{mode: modeSuspension, trigger: TriggerSuspend}
		case t.Status == "suspended" && !resuming && (trigger == TriggerSuspend || trigger == TriggerDriftRepair):
			p = plan{mode: modeSuspension, trigger: trigger}
		case t.Status != "active":
			p = plan{mode: modeSkip, skip: SkipTenantNotActive}
		case t.DesiredPolicyVersionID == nil:
			p = plan{mode: modeSkip, skip: SkipNoDesired}
		default:
			v, err := q.GetPolicyVersion(ctx, sqlcdb.GetPolicyVersionParams{TenantID: tenantID, ID: *t.DesiredPolicyVersionID})
			if err != nil {
				return err
			}
			if v.State != "approved" {
				p = plan{mode: modeSkip, skip: SkipNotApproved}
				return nil
			}
			tr := trigger
			if tr == TriggerSuspend { // the suspension is over (rolled back): the desired version again, as a resume
				tr = TriggerResume
			}
			p = plan{mode: modeDesired, trigger: tr}
		}
		return nil
	})
	return p, err
}

// appliedNow is the applied_sha256 the tenant would get now ("" when nothing would be applied or the render is
// refused — the next round decides and records it).
func (s *Service) appliedNow(ctx context.Context, tenantID uuid.UUID, trigger string) (string, error) {
	p, err := s.planApply(ctx, tenantID, trigger)
	if err != nil {
		return "", err
	}
	switch p.mode {
	case modeSuspension:
		doc, err := Lint(s.susText)
		if err != nil {
			return "", nil
		}
		r, err := s.renderCatalog(ctx, tenantID, doc)
		if err != nil {
			if _, lint := IsLint(err); lint {
				return "", nil
			}
			return "", err
		}
		return r.AppliedSHA256, nil
	case modeDesired:
		_, doc, err := s.renderDesired(ctx, tenantID)
		if err != nil {
			if _, lint := IsLint(err); lint || errors.Is(err, ErrNoDesired) || errors.Is(err, ErrDesiredNotApproved) {
				return "", nil
			}
			return "", err
		}
		return doc.AppliedSHA256, nil
	}
	return "", nil
}
