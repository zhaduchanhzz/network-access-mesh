package policies

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// The lifecycle of a policy version (§7.3, P4-T10) on the api's store (mg_api_tenant):
//
//	POST   /policies                 draft (typed source), version N+1, parent = the desired version unless given
//	PATCH  /policies/{v}             If-Match; back to draft, approval and report cleared (§6.3); never the desired
//	                                 version, a platform version or a closed one
//	POST   /policies/{v}/validate    If-Match; render + lint L1–L13 + CheckPolicy on the instance (dry run) ⇒ validated,
//	                                 or draft with the report
//	POST   /policies/{v}/submit      If-Match; validated → pending_approval (peer review)
//	POST   /policies/{v}/approve     If-Match + content_sha256 of what was reviewed; 4-eyes on ⇒ only from
//	                                 pending_approval, by someone who neither wrote nor submitted it (peer); off ⇒ from
//	                                 validated, review_mode self; an Owner-only acknowledgement (L4, L12) needs a
//	                                 Tenant Owner
//	POST   /policies/{v}/reject      If-Match + reason; pending_approval → rejected
//	POST   /policies/{v}/apply       202: an approved version becomes the desired one (its parent must be the current
//	                                 desired one — 409 stale_base), the previous desired one superseded, policy.apply
//	                                 (trigger manual) enqueued in the same transaction; step-up when 4-eyes is on
//	POST   /policies/{v}/rollback    202: version N+1 with the content of an earlier approved version (approval inherited
//	                                 — the content was approved), desired at once, policy.apply (trigger rollback)
//	GET    /policies[/{v}|/current|/{v}/diff]
//
// TenantSettings.policy.four_eyes is only read here (its writing path is PUT /settings/security — P4-T03a).

// Audit actions (x-audit-action of api/openapi.yaml).
const (
	ActionPolicyCreate   = "policy.create"
	ActionPolicyUpdate   = "policy.update"
	ActionPolicyValidate = "policy.validate"
	ActionPolicySubmit   = "policy.submit"
	ActionPolicyApproved = "policy.approved"
	ActionPolicyRejected = "policy.rejected"
	ActionPolicyDesired  = "policy.desired_set"
	ActionPolicyRollback = "policy.rollback"

	createPolicyOperation   = "createTenantPolicy"
	applyPolicyOperation    = "applyTenantPolicy"
	rollbackPolicyOperation = "rollbackTenantPolicy"
	policyIdempotencyLock   = 30 * time.Second
	maxRejectReason         = 2000
	DefaultPolicyLimit      = 50
	MaxPolicyLimit          = 200
	// StepUpWindow is the freshness of auth_time an apply or a rollback needs when 4-eyes is on (§8.3 step 7).
	StepUpWindow = 15 * time.Minute
)

// Review modes (policy_versions.review_mode).
const (
	ReviewPeer = "peer"
	ReviewSelf = "self"
)

// Version states (policy_versions.state).
const (
	VersionDraft           = "draft"
	VersionValidated       = "validated"
	VersionPendingApproval = "pending_approval"
	VersionApproved        = "approved"
	VersionRejected        = "rejected"
	VersionSuperseded      = "superseded"
)

// Kinds of PolicyError (errors.Is works through Unwrap).
var (
	ErrPolicyNotFound              = errors.New("policies: policy version not found")
	ErrPolicyInvalid               = errors.New("policies: invalid policy request")
	ErrPolicyConflict              = errors.New("policies: the policy version's state does not allow this request")
	ErrPolicyForbidden             = errors.New("policies: the review rule refuses this caller")
	ErrPolicyReauthRequired        = errors.New("policies: step-up required")
	ErrPolicyPreconditionRequired  = errors.New("policies: If-Match required")
	ErrPolicyPreconditionFailed    = errors.New("policies: If-Match does not match the version's revision")
	ErrPolicyInstanceUnavailable   = errors.New("policies: the tenant's instance does not answer")
	ErrPolicyIdempotencyInProgress = errors.New("policies: a request with this Idempotency-Key is in progress")
	ErrPolicyIdempotencyKeyReuse   = errors.New("policies: Idempotency-Key used for another request")
)

// PolicyError is a refusal of the policy lifecycle: Kind is one of the ErrPolicy… above; Reason a stable code;
// Field the invalid field (ErrPolicyInvalid); Report the lint report of a refused rollback.
type PolicyError struct {
	Kind       error
	Reason     string
	Field      string
	Report     *Report
	RetryAfter time.Duration
}

func (e *PolicyError) Error() string { return e.Kind.Error() + " (" + e.Reason + ")" }
func (e *PolicyError) Unwrap() error { return e.Kind }

func polErr(kind error, reason string) *PolicyError { return &PolicyError{Kind: kind, Reason: reason} }

// AsPolicyError returns the *PolicyError inside err.
func AsPolicyError(err error) (*PolicyError, bool) {
	var e *PolicyError
	ok := errors.As(err, &e)
	return e, ok
}

// Version is the API view of a policy version (schema PolicyVersion — never the application state).
type Version struct {
	ID               uuid.UUID     `json:"id"`
	Version          int           `json:"version"`
	Revision         int64         `json:"revision"`
	Kind             string        `json:"kind"`
	State            string        `json:"state"`
	ContentSHA256    string        `json:"content_sha256"`
	Source           *PolicySource `json:"source,omitempty"`
	HuJSON           *string       `json:"hujson,omitempty"`
	ValidationReport *Report       `json:"validation_report,omitempty"`
	ParentVersionID  *uuid.UUID    `json:"parent_version_id,omitempty"`
	RollbackOf       *uuid.UUID    `json:"rollback_of,omitempty"`
	CreatedBy        *uuid.UUID    `json:"created_by,omitempty"`
	SubmittedBy      *uuid.UUID    `json:"submitted_by,omitempty"`
	SubmittedAt      *time.Time    `json:"submitted_at,omitempty"`
	ApprovedBy       *uuid.UUID    `json:"approved_by,omitempty"`
	ApprovedAt       *time.Time    `json:"approved_at,omitempty"`
	ReviewMode       *string       `json:"review_mode,omitempty"`
	RejectedBy       *uuid.UUID    `json:"rejected_by,omitempty"`
	RejectedAt       *time.Time    `json:"rejected_at,omitempty"`
	RejectedReason   *string       `json:"rejected_reason,omitempty"`
	Desired          bool          `json:"desired"`
	CreatedAt        time.Time     `json:"created_at"`
	UpdatedAt        time.Time     `json:"updated_at"`
}

// ETag is the entity tag of the version: its revision (§6.3 — the If-Match of every change).
func (v Version) ETag() string { return `"` + strconv.FormatInt(v.Revision, 10) + `"` }

func versionView(r sqlcdb.PolicyVersion, desired *uuid.UUID) Version {
	v := Version{ID: r.ID, Version: int(r.Version), Revision: r.Revision, Kind: r.Kind, State: r.State,
		ContentSHA256: r.ContentSha256, HuJSON: r.SourceHujson, ParentVersionID: r.ParentVersionID, RollbackOf: r.RollbackOf,
		CreatedBy: r.CreatedBy, SubmittedBy: r.SubmittedBy, SubmittedAt: r.SubmittedAt, ApprovedBy: r.ApprovedBy,
		ApprovedAt: r.ApprovedAt, ReviewMode: r.ReviewMode, RejectedBy: r.RejectedBy, RejectedAt: r.RejectedAt,
		RejectedReason: r.RejectedReason, Desired: desired != nil && *desired == r.ID, CreatedAt: r.CreatedAt,
		UpdatedAt: r.UpdatedAt}
	if r.Source != nil {
		var s PolicySource
		if json.Unmarshal(r.Source, &s) == nil {
			s = s.normalized()
			v.Source = &s
		}
	}
	if r.ValidationReport != nil {
		var rep Report
		if json.Unmarshal(r.ValidationReport, &rep) == nil && rep.Engine != "" {
			v.ValidationReport = &rep
		}
	}
	return v
}

// Application is the API view of a policy application (schema PolicyApplication — §13.3).
type Application struct {
	ID                 uuid.UUID  `json:"id"`
	PolicyVersionID    uuid.UUID  `json:"policy_version_id"`
	Trigger            string     `json:"trigger"`
	State              string     `json:"state"`
	AppliedSHA256      string     `json:"applied_sha256"`
	HeadscaleUpdatedAt *time.Time `json:"headscale_updated_at,omitempty"`
	ErrorCode          *string    `json:"error_code,omitempty"`
	RequestedBy        *uuid.UUID `json:"requested_by,omitempty"`
	CreatedAt          time.Time  `json:"created_at"`
	FinishedAt         *time.Time `json:"finished_at,omitempty"`
}

func applicationView(a sqlcdb.PolicyApplication) Application {
	return Application{ID: a.ID, PolicyVersionID: a.PolicyVersionID, Trigger: a.Trigger, State: a.State,
		AppliedSHA256: a.AppliedSha256, HeadscaleUpdatedAt: a.HeadscaleUpdatedAt, ErrorCode: a.ErrorCode,
		RequestedBy: a.RequestedByIdentityID, CreatedAt: a.CreatedAt, FinishedAt: a.FinishedAt}
}

// Current is GET /policies/current: the desired version, the instance's current application ("applied to Headscale
// at …" — not "the clients converged", which is not observable, T-18) and the latest application whatever its state.
type Current struct {
	Desired     *Version     `json:"desired,omitempty"`
	Applied     *Application `json:"applied,omitempty"`
	Latest      *Application `json:"latest,omitempty"`
	FourEyes    bool         `json:"four_eyes"`
	ApplyStepUp bool         `json:"apply_step_up"`
}

// VersionPage is one page of versions.
type VersionPage struct {
	Items      []Version
	NextCursor string
}

// VersionActor is the caller of a lifecycle request.
type VersionActor struct {
	IdentityID uuid.UUID
	AuthTime   time.Time // the session's auth_time (step-up)
}

// NewVersion is the body of POST /policies.
type NewVersion struct {
	Source          json.RawMessage
	ParentVersionID *uuid.UUID
}

// Accepted is the answer of apply and rollback (202): the version that became desired and the policy.apply job.
type Accepted struct {
	Version Version
	Job     jobs.Job
}

// Diff is GET /policies/{v}/diff.
type Diff struct {
	VersionID      uuid.UUID  `json:"version_id"`
	AgainstID      *uuid.UUID `json:"against_id,omitempty"`
	FromSHA256     string     `json:"from_sha256,omitempty"`
	ToSHA256       string     `json:"to_sha256,omitempty"`
	Lines          []DiffLine `json:"lines"`
	LinesOmitted   bool       `json:"lines_omitted"`
	GrantsAdded    []string   `json:"grants_added"`
	GrantsRemoved  []string   `json:"grants_removed"`
	ReportBlocking bool       `json:"report_blocking"`
}

// VersionsConfig are the collaborators of a VersionService.
type VersionsConfig struct {
	// Registry reaches the tenant's instance for the dry run of validate (CheckPolicy — §7.3). Required.
	Registry headscale.Registry
	Now      func() time.Time
}

// VersionService is the policy lifecycle on the api's store.
type VersionService struct {
	st  *store.Store
	reg headscale.Registry
	now func() time.Time
}

// NewVersions returns the lifecycle service of the api process.
func NewVersions(st *store.Store, cfg VersionsConfig) (*VersionService, error) {
	if st == nil || cfg.Registry == nil {
		return nil, errors.New("policies: a store and a headscale registry are required")
	}
	s := &VersionService{st: st, reg: cfg.Registry, now: cfg.Now}
	if s.now == nil {
		s.now = time.Now
	}
	return s, nil
}

// ---------------------------------------------------------------------------------------------------- read

// List is GET /policies: newest first; the cursor is the version number of the last item.
func (s *VersionService) List(ctx context.Context, tenantID uuid.UUID, limit int, cursor string) (VersionPage, error) {
	switch {
	case limit == 0:
		limit = DefaultPolicyLimit
	case limit < 1 || limit > MaxPolicyLimit:
		return VersionPage{}, &PolicyError{Kind: ErrPolicyInvalid, Reason: "invalid_limit", Field: "limit"}
	}
	before := 0
	if cursor != "" {
		n, err := strconv.Atoi(cursor)
		if err != nil || n < 2 || strconv.Itoa(n) != cursor {
			return VersionPage{}, &PolicyError{Kind: ErrPolicyInvalid, Reason: "invalid_cursor", Field: "cursor"}
		}
		before = n
	}
	page := VersionPage{Items: []Version{}}
	err := s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		desired, err := q.GetTenantPolicyState(ctx, tenantID)
		if err != nil {
			return err
		}
		rows, err := q.ListPolicyVersions(ctx, sqlcdb.ListPolicyVersionsParams{TenantID: tenantID,
			BeforeVersion: int32(before), PageLimit: int32(limit + 1)}) //nolint:gosec // bounded above
		if err != nil {
			return err
		}
		if len(rows) > limit {
			rows = rows[:limit]
			page.NextCursor = strconv.Itoa(int(rows[limit-1].Version))
		}
		for _, r := range rows {
			page.Items = append(page.Items, versionView(r, desired))
		}
		return nil
	})
	return page, err
}

// Get returns one version (another tenant's reads ErrPolicyNotFound — §8.4 invariant 6).
func (s *VersionService) Get(ctx context.Context, tenantID, id uuid.UUID) (Version, error) {
	var out Version
	err := s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		desired, err := q.GetTenantPolicyState(ctx, tenantID)
		if err != nil {
			return err
		}
		r, err := q.GetPolicyVersion(ctx, sqlcdb.GetPolicyVersionParams{TenantID: tenantID, ID: id})
		if errors.Is(err, store.ErrNoRows) {
			return polErr(ErrPolicyNotFound, "version_not_found")
		}
		if err != nil {
			return err
		}
		out = versionView(r, desired)
		return nil
	})
	return out, err
}

// Current is GET /policies/current.
func (s *VersionService) Current(ctx context.Context, tenantID uuid.UUID) (Current, error) {
	var out Current
	err := s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		set, err := q.GetTenantPolicySettings(ctx, tenantID)
		if err != nil {
			return err
		}
		out.FourEyes, out.ApplyStepUp = set.FourEyes, set.FourEyes
		desired, err := q.GetTenantPolicyState(ctx, tenantID)
		if err != nil {
			return err
		}
		if desired != nil {
			r, err := q.GetPolicyVersion(ctx, sqlcdb.GetPolicyVersionParams{TenantID: tenantID, ID: *desired})
			if err != nil {
				return err
			}
			v := versionView(r, desired)
			out.Desired = &v
		}
		if inst, err := q.GetLiveInstanceForTenant(ctx, tenantID); err == nil {
			cur, err := q.GetCurrentPolicyApplication(ctx, sqlcdb.GetCurrentPolicyApplicationParams{TenantID: tenantID,
				InstanceID: inst.ID})
			if err == nil {
				a := applicationView(cur)
				out.Applied = &a
			} else if !errors.Is(err, store.ErrNoRows) {
				return err
			}
		} else if !errors.Is(err, store.ErrNoRows) {
			return err
		}
		last, err := q.GetLatestPolicyApplication(ctx, tenantID)
		if err == nil {
			a := applicationView(last)
			out.Latest = &a
		} else if !errors.Is(err, store.ErrNoRows) {
			return err
		}
		return nil
	})
	return out, err
}

// ---------------------------------------------------------------------------------------------------- changes

// matchRevision checks If-Match against the version's revision ("" or "*" ⇒ 428; another ⇒ 412).
func matchRevision(r sqlcdb.PolicyVersion, ifMatch string) error {
	m := strings.TrimSpace(ifMatch)
	switch {
	case m == "" || m == "*":
		return polErr(ErrPolicyPreconditionRequired, "if_match_required")
	case m != `"`+strconv.FormatInt(r.Revision, 10)+`"`:
		return polErr(ErrPolicyPreconditionFailed, "stale_etag")
	}
	return nil
}

// lockVersion reads and locks a version of the tenant.
func lockVersion(ctx context.Context, q *sqlcdb.Queries, tenantID, id uuid.UUID) (sqlcdb.PolicyVersion, error) {
	r, err := q.LockPolicyVersion(ctx, sqlcdb.LockPolicyVersionParams{TenantID: tenantID, ID: id})
	if errors.Is(err, store.ErrNoRows) {
		return r, polErr(ErrPolicyNotFound, "version_not_found")
	}
	return r, err
}

// parseSource maps a structural error of the body to 422 on its field.
func parseSource(raw []byte) (PolicySource, []byte, string, error) {
	src, err := ParseSource(raw)
	if err != nil {
		if se, ok := AsSourceError(err); ok {
			return PolicySource{}, nil, "", &PolicyError{Kind: ErrPolicyInvalid, Reason: se.Reason, Field: "source." + se.Field}
		}
		return PolicySource{}, nil, "", err
	}
	canon, sum, err := src.Canonical()
	return src, canon, sum, err
}

func idPtr(id uuid.UUID) *uuid.UUID {
	if id == uuid.Nil {
		return nil
	}
	return &id
}

// idempotent takes the Idempotency-Key of a create/apply/rollback in a transaction of its own: a replay returns the
// stored body (decoded into out), nil key ⇒ proceed without.
func (s *VersionService) idempotent(ctx context.Context, tenantID uuid.UUID, actor VersionActor, op string, idem *Idempotency,
	out any) (*jobs.IdempotencyKey, bool, error) {
	if idem == nil {
		return nil, false, nil
	}
	key := &jobs.IdempotencyKey{TenantID: &tenantID, IdentityID: actor.IdentityID, OperationID: op, Key: idem.Key}
	replayed := false
	err := s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		d, err := jobs.BeginIdempotent(ctx, q, *key, idem.Hash, policyIdempotencyLock)
		if err != nil {
			return err
		}
		switch d.Outcome {
		case jobs.IdempotencyReplay:
			if d.Response == nil || json.Unmarshal(d.Response.Body, out) != nil {
				return errors.New("policies: stored policy response unreadable")
			}
			replayed = true
		case jobs.IdempotencyInProgress:
			return &PolicyError{Kind: ErrPolicyIdempotencyInProgress, Reason: "idempotency_in_progress", RetryAfter: d.RetryAfter}
		case jobs.IdempotencyKeyReuse:
			return polErr(ErrPolicyIdempotencyKeyReuse, "idempotency_key_reuse")
		}
		return nil
	})
	return key, replayed, err
}

func (s *VersionService) failIdempotent(ctx context.Context, tenantID uuid.UUID, key *jobs.IdempotencyKey, idem *Idempotency) {
	if key == nil {
		return
	}
	_ = s.st.WithTenantTx(context.WithoutCancel(ctx), tenantID, func(q *sqlcdb.Queries) error {
		return jobs.FailIdempotent(ctx, q, *key, idem.Hash)
	})
}

// Create is POST /policies: a draft with the given typed source, version N+1; parent = the given version (of the
// tenant) or the current desired one.
func (s *VersionService) Create(ctx context.Context, tenantID uuid.UUID, actor VersionActor, in NewVersion, idem *Idempotency) (Version, error) {
	_, canon, sum, err := parseSource(in.Source)
	if err != nil {
		return Version{}, err
	}
	var replay Version
	key, replayed, err := s.idempotent(ctx, tenantID, actor, createPolicyOperation, idem, &replay)
	if err != nil {
		return Version{}, err
	}
	if replayed {
		return replay, nil
	}
	var out Version
	err = s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		desired, err := q.LockTenantDesiredPolicy(ctx, tenantID)
		if err != nil {
			return err
		}
		parent := desired
		if in.ParentVersionID != nil {
			if _, err := q.GetPolicyVersion(ctx, sqlcdb.GetPolicyVersionParams{TenantID: tenantID, ID: *in.ParentVersionID}); err != nil {
				if errors.Is(err, store.ErrNoRows) {
					return &PolicyError{Kind: ErrPolicyInvalid, Reason: "unknown_parent", Field: "parent_version_id"}
				}
				return err
			}
			parent = in.ParentVersionID
		}
		n, err := q.NextPolicyVersionNumber(ctx, tenantID)
		if err != nil {
			return err
		}
		r, err := q.InsertTypedPolicyVersion(ctx, sqlcdb.InsertTypedPolicyVersionParams{TenantID: tenantID, Version: n,
			Source: canon, ContentSha256: sum, State: VersionDraft, ParentVersionID: parent, CreatedBy: idPtr(actor.IdentityID)})
		if err != nil {
			return err
		}
		out = versionView(r, desired)
		if err := audit.Record(ctx, q, audit.Event{Action: ActionPolicyCreate, TenantID: &tenantID, ResourceType: resourceVersion,
			ResourceID: r.ID.String(), Details: audit.Details{"version_id": r.ID, "version": r.Version,
				"content_sha256": sum, "parent_version_id": text(uuidText(parent))}}); err != nil {
			return err
		}
		if key == nil {
			return nil
		}
		body, err := json.Marshal(out)
		if err != nil {
			return err
		}
		return jobs.CompleteIdempotent(ctx, q, *key, idem.Hash, jobs.StoredResponse{Status: 201, Body: body,
			Resource: &jobs.Resource{Type: resourceVersion, ID: r.ID.String()}})
	})
	if err != nil {
		s.failIdempotent(ctx, tenantID, key, idem)
		return Version{}, err
	}
	return out, nil
}

func uuidText(id *uuid.UUID) *string {
	if id == nil {
		return nil
	}
	s := id.String()
	return &s
}

// Update is PATCH /policies/{v}: a new source; the version returns to draft, its approval and report cleared.
func (s *VersionService) Update(ctx context.Context, tenantID, id uuid.UUID, actor VersionActor, ifMatch string, source json.RawMessage) (Version, error) {
	_, canon, sum, err := parseSource(source)
	if err != nil {
		return Version{}, err
	}
	var out Version
	err = s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		desired, err := q.GetTenantPolicyState(ctx, tenantID)
		if err != nil {
			return err
		}
		r, err := lockVersion(ctx, q, tenantID, id)
		if err != nil {
			return err
		}
		if err := matchRevision(r, ifMatch); err != nil {
			return err
		}
		switch {
		case r.Kind != KindUser:
			return polErr(ErrPolicyConflict, "platform_version")
		case r.Source == nil:
			return polErr(ErrPolicyConflict, "hujson_version")
		case desired != nil && *desired == r.ID:
			return polErr(ErrPolicyConflict, "version_is_desired")
		case r.State == VersionSuperseded || r.State == VersionRejected:
			return polErr(ErrPolicyConflict, "version_closed")
		}
		u, err := q.UpdatePolicyVersionSource(ctx, sqlcdb.UpdatePolicyVersionSourceParams{Source: canon, ContentSha256: sum,
			TenantID: tenantID, ID: id, Revision: r.Revision})
		if err != nil {
			return err
		}
		out = versionView(u, desired)
		return audit.Record(ctx, q, audit.Event{Action: ActionPolicyUpdate, TenantID: &tenantID, ResourceType: resourceVersion,
			ResourceID: id.String(), Details: audit.Details{"version_id": id, "version": u.Version, "content_sha256": sum,
				"previous_state": r.State, "approval_cleared": r.ApprovedBy != nil || r.State == VersionApproved}})
	})
	return out, err
}

// Validate is POST /policies/{v}/validate: render with the tables of now, lint, then CheckPolicy of the rendered
// policy on the tenant's instance (dry run). Passed ⇒ validated; otherwise draft with the report (200 either way). An
// instance that does not answer changes nothing (503).
func (s *VersionService) Validate(ctx context.Context, tenantID, id uuid.UUID, actor VersionActor, ifMatch string) (Version, error) {
	var (
		r       sqlcdb.PolicyVersion
		desired *uuid.UUID
		rend    Rendered
	)
	err := s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		var err error
		if desired, err = q.GetTenantPolicyState(ctx, tenantID); err != nil {
			return err
		}
		if r, err = q.GetPolicyVersion(ctx, sqlcdb.GetPolicyVersionParams{TenantID: tenantID, ID: id}); err != nil {
			if errors.Is(err, store.ErrNoRows) {
				return polErr(ErrPolicyNotFound, "version_not_found")
			}
			return err
		}
		if err := matchRevision(r, ifMatch); err != nil {
			return err
		}
		if r.Kind != KindUser {
			return polErr(ErrPolicyConflict, "platform_version")
		}
		if r.State != VersionDraft && r.State != VersionValidated {
			return polErr(ErrPolicyConflict, "invalid_state")
		}
		rend, err = renderVersion(ctx, q, tenantID, r)
		return err
	})
	if err != nil {
		return Version{}, err
	}
	rep := rend.Report
	rep.Check = "skipped"
	if !rep.Blocking() {
		cerr := s.check(ctx, tenantID, rend.Document.Applied)
		switch {
		case cerr == nil:
			rep.Check = ResultPassed
		case errors.Is(cerr, ErrPolicyInstanceUnavailable):
			return Version{}, cerr
		default:
			rep.Check = ResultFailed
			rep.add(Finding{Rule: RuleCheck, Severity: SeverityError, Code: "check_rejected",
				Message: "the tenant's Headscale refused the rendered policy (" + causeKind(cerr) + ")"})
		}
	}
	rep.finish()
	at := s.now().UTC()
	rep.Revision, rep.ValidatedAt = r.Revision+1, &at
	state := VersionValidated
	if rep.Blocking() {
		state = VersionDraft
	}
	body, err := json.Marshal(rep)
	if err != nil {
		return Version{}, err
	}
	var out Version
	err = s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		u, err := q.SetPolicyVersionValidation(ctx, sqlcdb.SetPolicyVersionValidationParams{State: state,
			ValidationReport: body, TenantID: tenantID, ID: id, Revision: r.Revision})
		if errors.Is(err, store.ErrNoRows) {
			return polErr(ErrPolicyPreconditionFailed, "stale_etag") // changed while it was checked
		}
		if err != nil {
			return err
		}
		out = versionView(u, desired)
		return audit.Record(ctx, q, audit.Event{Action: ActionPolicyValidate, TenantID: &tenantID, ResourceType: resourceVersion,
			ResourceID: id.String(), Details: audit.Details{"version_id": id, "version": u.Version, "state": state,
				"result": rep.Result, "check": rep.Check, "errors": len(rep.Errors), "warnings": len(rep.Warnings),
				"rendered_sha256": rep.RenderedSHA256}})
	})
	return out, err
}

// check is CheckPolicy of a rendered policy on the tenant's instance: nil, a refusal (the adapter's error), or
// ErrPolicyInstanceUnavailable.
func (s *VersionService) check(ctx context.Context, tenantID uuid.UUID, applied string) error {
	inst, err := s.reg.ForTenant(ctx, tenantID)
	if err != nil {
		return &PolicyError{Kind: ErrPolicyInstanceUnavailable, Reason: "instance_unavailable"}
	}
	err = inst.CheckPolicy(ctx, applied)
	if err == nil {
		return nil
	}
	if he, ok := headscale.AsError(err); ok {
		switch he.Kind {
		case headscale.KindValidation, headscale.KindPolicyRejected, headscale.KindUpstreamRejected:
			return err
		}
	}
	return &PolicyError{Kind: ErrPolicyInstanceUnavailable, Reason: "instance_unavailable"}
}

// Submit is POST /policies/{v}/submit: validated → pending_approval.
func (s *VersionService) Submit(ctx context.Context, tenantID, id uuid.UUID, actor VersionActor, ifMatch string) (Version, error) {
	var out Version
	err := s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		desired, err := q.GetTenantPolicyState(ctx, tenantID)
		if err != nil {
			return err
		}
		r, err := lockVersion(ctx, q, tenantID, id)
		if err != nil {
			return err
		}
		if err := matchRevision(r, ifMatch); err != nil {
			return err
		}
		if r.Kind != KindUser {
			return polErr(ErrPolicyConflict, "platform_version")
		}
		if r.State != VersionValidated {
			return polErr(ErrPolicyConflict, "not_validated")
		}
		u, err := q.SubmitPolicyVersion(ctx, sqlcdb.SubmitPolicyVersionParams{SubmittedBy: idPtr(actor.IdentityID),
			TenantID: tenantID, ID: id, Revision: r.Revision})
		if err != nil {
			return err
		}
		out = versionView(u, desired)
		return audit.Record(ctx, q, audit.Event{Action: ActionPolicySubmit, TenantID: &tenantID, ResourceType: resourceVersion,
			ResourceID: id.String(), Details: audit.Details{"version_id": id, "version": u.Version,
				"content_sha256": u.ContentSha256}})
	})
	return out, err
}

// Approve is POST /policies/{v}/approve (§7.3 review): contentSHA256 is the content the reviewer saw.
func (s *VersionService) Approve(ctx context.Context, tenantID, id uuid.UUID, actor VersionActor, ifMatch, contentSHA256 string) (Version, error) {
	var out Version
	err := s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		set, err := q.GetTenantPolicySettings(ctx, tenantID)
		if err != nil {
			return err
		}
		desired, err := q.GetTenantPolicyState(ctx, tenantID)
		if err != nil {
			return err
		}
		r, err := lockVersion(ctx, q, tenantID, id)
		if err != nil {
			return err
		}
		if err := matchRevision(r, ifMatch); err != nil {
			return err
		}
		if r.Kind != KindUser {
			return polErr(ErrPolicyConflict, "platform_version")
		}
		if strings.TrimSpace(contentSHA256) != r.ContentSha256 {
			return polErr(ErrPolicyConflict, "content_mismatch")
		}
		self := actor.IdentityID != uuid.Nil && ((r.SubmittedBy != nil && *r.SubmittedBy == actor.IdentityID) ||
			(r.CreatedBy != nil && *r.CreatedBy == actor.IdentityID))
		mode := ReviewSelf
		switch r.State {
		case VersionValidated:
			if set.FourEyes {
				return polErr(ErrPolicyConflict, "review_required") // 4-eyes: submit, a second person approves
			}
		case VersionPendingApproval:
			switch {
			case self && set.FourEyes:
				return polErr(ErrPolicyForbidden, "self_approval")
			case r.SubmittedBy != nil && *r.SubmittedBy != actor.IdentityID:
				mode = ReviewPeer
			}
		default:
			return polErr(ErrPolicyConflict, "not_validated")
		}
		var rep Report
		if r.ValidationReport != nil && json.Unmarshal(r.ValidationReport, &rep) == nil && rep.OwnerAcknowledged() {
			role, err := q.GetMembershipRoleKey(ctx, sqlcdb.GetMembershipRoleKeyParams{TenantID: tenantID,
				IdentityID: actor.IdentityID})
			if err != nil && !errors.Is(err, store.ErrNoRows) {
				return err
			}
			if role != "tenant_owner" {
				return polErr(ErrPolicyForbidden, "owner_acknowledgement_required")
			}
		}
		u, err := q.ApprovePolicyVersion(ctx, sqlcdb.ApprovePolicyVersionParams{ApprovedBy: idPtr(actor.IdentityID),
			ReviewMode: &mode, TenantID: tenantID, ID: id, Revision: r.Revision})
		if err != nil {
			return err
		}
		out = versionView(u, desired)
		return audit.Record(ctx, q, audit.Event{Action: ActionPolicyApproved, TenantID: &tenantID, ResourceType: resourceVersion,
			ResourceID: id.String(), Details: audit.Details{"version_id": id, "version": u.Version, "review_mode": mode,
				"four_eyes": set.FourEyes, "content_sha256": u.ContentSha256, "rendered_sha256": rep.RenderedSHA256}})
	})
	return out, err
}

// Reject is POST /policies/{v}/reject: pending_approval → rejected, with the reason.
func (s *VersionService) Reject(ctx context.Context, tenantID, id uuid.UUID, actor VersionActor, ifMatch, reason string) (Version, error) {
	reason = strings.TrimSpace(reason)
	if reason == "" || utf8.RuneCountInString(reason) > maxRejectReason || strings.ContainsRune(reason, 0) {
		return Version{}, &PolicyError{Kind: ErrPolicyInvalid, Reason: "invalid_reason", Field: "reason"}
	}
	var out Version
	err := s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		desired, err := q.GetTenantPolicyState(ctx, tenantID)
		if err != nil {
			return err
		}
		r, err := lockVersion(ctx, q, tenantID, id)
		if err != nil {
			return err
		}
		if err := matchRevision(r, ifMatch); err != nil {
			return err
		}
		if r.State != VersionPendingApproval {
			return polErr(ErrPolicyConflict, "not_pending_approval")
		}
		u, err := q.RejectPolicyVersion(ctx, sqlcdb.RejectPolicyVersionParams{RejectedBy: idPtr(actor.IdentityID),
			RejectedReason: &reason, TenantID: tenantID, ID: id, Revision: r.Revision})
		if err != nil {
			return err
		}
		out = versionView(u, desired)
		return audit.Record(ctx, q, audit.Event{Action: ActionPolicyRejected, TenantID: &tenantID, ResourceType: resourceVersion,
			ResourceID: id.String(), Details: audit.Details{"version_id": id, "version": u.Version}})
	})
	return out, err
}

// stepUp is §8.3 step 7 on the caller's session, required for apply and rollback when 4-eyes is on.
func (s *VersionService) stepUp(a VersionActor) error {
	now := s.now()
	const skew = time.Minute
	if a.AuthTime.IsZero() || now.Sub(a.AuthTime) > StepUpWindow || a.AuthTime.After(now.Add(skew)) {
		return polErr(ErrPolicyReauthRequired, "step_up_required")
	}
	return nil
}

// makeDesired sets v as the desired version (the previous one superseded) and enqueues policy.apply with trigger.
func makeDesired(ctx context.Context, tx *store.Tx, tenantID uuid.UUID, previous *uuid.UUID, v uuid.UUID, trigger string,
	actor VersionActor) (uuid.UUID, error) {
	q := tx.Q
	if previous == nil || *previous != v {
		if err := q.SetTenantDesiredPolicy(ctx, sqlcdb.SetTenantDesiredPolicyParams{VersionID: &v, TenantID: tenantID}); err != nil {
			return uuid.Nil, err
		}
		if previous != nil {
			if err := q.SupersedePolicyVersion(ctx, sqlcdb.SupersedePolicyVersionParams{TenantID: tenantID, ID: *previous}); err != nil {
				return uuid.Nil, err
			}
		}
	}
	e, err := jobs.Enqueue(ctx, tx, jobs.Spec{Kind: KindApply, TenantID: &tenantID, Input: ApplyJobInput{Trigger: trigger},
		RequestedBy: idPtr(actor.IdentityID)})
	if err != nil {
		return uuid.Nil, fmt.Errorf("policies: enqueue policy.apply: %w", err)
	}
	return e.Job.ID, nil
}

// Apply is POST /policies/{v}/apply (202): the approved version becomes the desired one and policy.apply runs.
func (s *VersionService) Apply(ctx context.Context, tenantID, id uuid.UUID, actor VersionActor, idem *Idempotency) (Accepted, error) {
	var replay acceptedBody
	key, replayed, err := s.idempotent(ctx, tenantID, actor, applyPolicyOperation, idem, &replay)
	if err != nil {
		return Accepted{}, err
	}
	if replayed {
		return replay.accepted(), nil
	}
	var out Accepted
	err = s.st.WithTenantJobTx(ctx, tenantID, func(tx *store.Tx) error {
		q := tx.Q
		set, err := q.GetTenantPolicySettings(ctx, tenantID)
		if err != nil {
			return err
		}
		if set.FourEyes {
			if err := s.stepUp(actor); err != nil {
				return err
			}
		}
		desired, err := q.LockTenantDesiredPolicy(ctx, tenantID)
		if err != nil {
			return err
		}
		r, err := lockVersion(ctx, q, tenantID, id)
		if err != nil {
			return err
		}
		if r.State != VersionApproved {
			return polErr(ErrPolicyConflict, "not_approved")
		}
		again := desired != nil && *desired == r.ID
		if !again && !sameID(r.ParentVersionID, desired) {
			return polErr(ErrPolicyConflict, "stale_base")
		}
		jobID, err := makeDesired(ctx, tx, tenantID, desired, r.ID, TriggerManual, actor)
		if err != nil {
			return err
		}
		j, err := jobs.ProjectTx(ctx, q, jobID)
		if err != nil {
			return err
		}
		out = Accepted{Version: versionView(r, &r.ID), Job: j}
		if err := audit.Record(ctx, q, audit.Event{Action: ActionPolicyDesired, TenantID: &tenantID, ResourceType: resourceVersion,
			ResourceID: id.String(), Details: audit.Details{"version_id": id, "version": r.Version,
				"previous_version_id": text(uuidText(desired)), "already_desired": again, "policy_apply_job_id": jobID,
				"step_up": set.FourEyes}}); err != nil {
			return err
		}
		return completeAccepted(ctx, q, key, idem, out)
	})
	if err != nil {
		s.failIdempotent(ctx, tenantID, key, idem)
		return Accepted{}, err
	}
	return out, nil
}

// Rollback is POST /policies/{v}/rollback (202): version N+1 with the content of v — which must have been approved
// (its approval is inherited: the same content was reviewed — §7.3) — linted over the tables of now (blocking ⇒ 422
// with the report), made desired at once (parent = the current desired version) and applied (trigger rollback).
func (s *VersionService) Rollback(ctx context.Context, tenantID, id uuid.UUID, actor VersionActor, idem *Idempotency) (Accepted, error) {
	var replay acceptedBody
	key, replayed, err := s.idempotent(ctx, tenantID, actor, rollbackPolicyOperation, idem, &replay)
	if err != nil {
		return Accepted{}, err
	}
	if replayed {
		return replay.accepted(), nil
	}
	var out Accepted
	err = s.st.WithTenantJobTx(ctx, tenantID, func(tx *store.Tx) error {
		q := tx.Q
		set, err := q.GetTenantPolicySettings(ctx, tenantID)
		if err != nil {
			return err
		}
		if set.FourEyes {
			if err := s.stepUp(actor); err != nil {
				return err
			}
		}
		desired, err := q.LockTenantDesiredPolicy(ctx, tenantID)
		if err != nil {
			return err
		}
		target, err := lockVersion(ctx, q, tenantID, id)
		if err != nil {
			return err
		}
		if target.Kind != KindUser || target.Source == nil {
			return polErr(ErrPolicyConflict, "not_typed")
		}
		prior, err := q.LatestApprovalOfContent(ctx, sqlcdb.LatestApprovalOfContentParams{TenantID: tenantID,
			ContentSha256: &target.ContentSha256})
		if errors.Is(err, store.ErrNoRows) {
			return polErr(ErrPolicyConflict, "never_approved")
		}
		if err != nil {
			return err
		}
		rend, err := renderVersion(ctx, q, tenantID, target)
		if err != nil {
			return err
		}
		if rend.Report.Blocking() {
			rep := rend.Report
			return &PolicyError{Kind: ErrPolicyInvalid, Reason: "lint_failed", Field: "source", Report: &rep}
		}
		report, err := json.Marshal(rend.Report)
		if err != nil {
			return err
		}
		n, err := q.NextPolicyVersionNumber(ctx, tenantID)
		if err != nil {
			return err
		}
		at := s.now().UTC()
		sum := target.ContentSha256
		v, err := q.InsertTypedPolicyVersion(ctx, sqlcdb.InsertTypedPolicyVersionParams{TenantID: tenantID, Version: n,
			Source: target.Source, ContentSha256: sum, State: VersionApproved, ParentVersionID: desired,
			RollbackOf: &target.ID, CreatedBy: idPtr(actor.IdentityID), SubmittedBy: prior.SubmittedBy,
			SubmittedAt: prior.SubmittedAt, ApprovedBy: prior.ApprovedBy, ApprovedAt: &at, ApprovedContentSha256: &sum,
			ReviewMode: prior.ReviewMode, ValidationReport: report})
		if err != nil {
			return err
		}
		jobID, err := makeDesired(ctx, tx, tenantID, desired, v.ID, TriggerRollback, actor)
		if err != nil {
			return err
		}
		j, err := jobs.ProjectTx(ctx, q, jobID)
		if err != nil {
			return err
		}
		out = Accepted{Version: versionView(v, &v.ID), Job: j}
		if err := audit.Record(ctx, q, audit.Event{Action: ActionPolicyRollback, TenantID: &tenantID, ResourceType: resourceVersion,
			ResourceID: v.ID.String(), Details: audit.Details{"version_id": v.ID, "version": v.Version, "rollback_of": target.ID,
				"inherited_from": prior.ID, "previous_version_id": text(uuidText(desired)), "policy_apply_job_id": jobID,
				"step_up": set.FourEyes}}); err != nil {
			return err
		}
		return completeAccepted(ctx, q, key, idem, out)
	})
	if err != nil {
		s.failIdempotent(ctx, tenantID, key, idem)
		return Accepted{}, err
	}
	return out, nil
}

func sameID(a, b *uuid.UUID) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

// acceptedBody is the stored answer of an apply/rollback (Idempotency-Key replay).
type acceptedBody struct {
	Version Version  `json:"version"`
	Job     jobs.Job `json:"job"`
}

func (b acceptedBody) accepted() Accepted { return Accepted(b) }

func completeAccepted(ctx context.Context, q *sqlcdb.Queries, key *jobs.IdempotencyKey, idem *Idempotency, out Accepted) error {
	if key == nil {
		return nil
	}
	body, err := json.Marshal(acceptedBody(out))
	if err != nil {
		return err
	}
	return jobs.CompleteIdempotent(ctx, q, *key, idem.Hash, jobs.StoredResponse{Status: 202, Body: body,
		Resource: &jobs.Resource{Type: "job", ID: out.Job.ID.String()}})
}

// Diff is GET /policies/{v}/diff?against=: both versions rendered with the tables of now (against defaults to the
// desired version; none ⇒ an empty base).
func (s *VersionService) Diff(ctx context.Context, tenantID, id uuid.UUID, against *uuid.UUID) (Diff, error) {
	out := Diff{VersionID: id}
	var from, to string
	err := s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		r, err := q.GetPolicyVersion(ctx, sqlcdb.GetPolicyVersionParams{TenantID: tenantID, ID: id})
		if errors.Is(err, store.ErrNoRows) {
			return polErr(ErrPolicyNotFound, "version_not_found")
		}
		if err != nil {
			return err
		}
		base := against
		if base == nil {
			if base, err = q.GetTenantPolicyState(ctx, tenantID); err != nil {
				return err
			}
		}
		rt, err := renderVersion(ctx, q, tenantID, r)
		if err != nil {
			return err
		}
		to, out.ToSHA256, out.ReportBlocking = rt.Document.Applied, rt.Document.AppliedSHA256, rt.Report.Blocking()
		if base != nil {
			b, err := q.GetPolicyVersion(ctx, sqlcdb.GetPolicyVersionParams{TenantID: tenantID, ID: *base})
			if errors.Is(err, store.ErrNoRows) {
				return &PolicyError{Kind: ErrPolicyInvalid, Reason: "unknown_version", Field: "against"}
			}
			if err != nil {
				return err
			}
			rf, err := renderVersion(ctx, q, tenantID, b)
			if err != nil {
				return err
			}
			out.AgainstID = &b.ID
			from, out.FromSHA256 = rf.Document.Applied, rf.Document.AppliedSHA256
		}
		return nil
	})
	if err != nil {
		return Diff{}, err
	}
	lines, ok := lineDiff(from, to)
	out.Lines, out.LinesOmitted = lines, !ok
	if out.Lines == nil {
		out.Lines = []DiffLine{}
	}
	out.GrantsAdded, out.GrantsRemoved = grantChanges(from, to)
	return out, nil
}
