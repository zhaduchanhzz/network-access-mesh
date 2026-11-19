package approvals

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/authz"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// Statuses of approval_requests (CHECK of 0009).
const (
	StatusPending  = "pending"
	StatusApproved = "approved"
	StatusRejected = "rejected"
	StatusExpired  = "expired"
	StatusExecuted = "executed"
)

// Statuses lists every status (enum ApprovalStatus of api/openapi.yaml).
var Statuses = []string{StatusPending, StatusApproved, StatusRejected, StatusExpired, StatusExecuted}

// Defaults (§8.3 step 7, §8.6).
const (
	DefaultStepUpWindow = 15 * time.Minute // auth_time of the session of both persons (identity.DefaultStepUpWindow)
	DefaultTTL          = 24 * time.Hour   // an unapproved request expires after 24 hours
	// TTLSetting is the system_settings key that overrides DefaultTTL: a JSON integer of hours, 1–168.
	TTLSetting = "approval.ttl_hours"
	clockSkew  = 2 * time.Minute // tolerated skew of auth_time against the clock (identity.DefaultClockSkew)
	maxReason  = 1000            // CHECK of 0009 (characters)
)

// Page sizes of §13.1.
const (
	DefaultLimit = 50
	MaxLimit     = 200
)

// Security event kinds raised by this package (security_events, §8.8).
const (
	// KindSelfApproval: someone tried to approve or reject their own request — a 2P bypass attempt (medium).
	KindSelfApproval = "approval.self_decision"
	// KindPayloadIntegrity: the stored payload no longer hashes to payload_sha256 — changed outside the application
	// after the request was made or approved (high): the request is never executed.
	KindPayloadIntegrity = "approval.payload_integrity"
)

// Errors. Every error of the service is an *Error whose Kind is one of these (errors.Is works through Unwrap).
var (
	ErrNotFound       = authz.ErrNotFound                                      // 404 (also another tenant's request)
	ErrForbidden      = authz.ErrForbidden                                     // 403 (self-approval, condition, permission)
	ErrInvalid        = authz.ErrInvalid                                       // 422
	ErrReauthRequired = errors.New("approvals: step-up required")              // 401 reauth_required
	ErrConflict       = errors.New("approvals: conflict with the request")     // 409 (not pending, expired, executed…)
	ErrPayloadChanged = errors.New("approvals: payload differs from review")   // 412 (the reviewed hash is stale)
	ErrUnavailable    = errors.New("approvals: action cannot be executed now") // 409 (no executor in this build)
)

// Refusal reasons (Error.Reason — audit and logs, never Problem.detail).
const (
	ReasonStepUp            = "step_up_required"
	ReasonNotFound          = "approval_not_found"
	ReasonSelfDecision      = "self_approval"
	ReasonActionUnavailable = "action_unavailable"
	ReasonDecideCondition   = "decide_condition_not_met"
	ReasonExpired           = "approval_expired"
	ReasonNotPending        = "approval_not_pending"
	ReasonExecuted          = "approval_already_executed"
	ReasonOtherApprover     = "approved_by_another_person"
	ReasonPayloadChanged    = "payload_changed_since_review"
	ReasonPayloadIntegrity  = "payload_integrity_mismatch"
	ReasonOpenRequest       = "open_request_exists"
	ReasonInvalidPayload    = "invalid_payload"
	ReasonInvalidInput      = "invalid_input"
	ReasonScopeMismatch     = "scope_mismatch"
	// Idempotency-Key of a 2P operation (§13.1, P3-T15): the same key is still being served (409 + Retry-After), or
	// was used for another request (422 idempotency_key_reuse).
	ReasonIdempotencyInProgress = "idempotency_in_progress"
	ReasonIdempotencyKeyReuse   = "idempotency_key_reuse"
	// ReasonTargetChanged: an action refuses to run because what it acts on changed since the request was made (its
	// version or ETag is in the payload — P4-T03a); nothing ran, the request stays approved until it expires.
	ReasonTargetChanged = "target_changed"
)

// TargetChanged is the refusal an Action returns when its target changed since the request (409, nothing written).
func TargetChanged() *Error { return refuse(ErrConflict, ReasonTargetChanged) }

// Error is a refusal of the service.
type Error struct {
	Kind   error
	Reason string
	// Existing names the open request of the same action and resource (ReasonOpenRequest).
	Existing uuid.UUID
	// RetryAfter is the wait of ReasonIdempotencyInProgress.
	RetryAfter time.Duration
	cause      error
}

func (e *Error) Error() string {
	s := "approvals: " + e.Kind.Error() + " (" + e.Reason + ")"
	if e.cause != nil {
		s += ": " + e.cause.Error()
	}
	return s
}

func (e *Error) Unwrap() error { return e.Kind }

// Cause is the underlying error, for the internal log only.
func (e *Error) Cause() error { return e.cause }

func refuse(kind error, reason string) *Error { return &Error{Kind: kind, Reason: reason} }

// Actor is the person acting, from the session of the request (§8.3: the session carries identity only).
type Actor struct {
	IdentityID uuid.UUID
	Scope      authz.Scope
	AuthTime   time.Time // auth_time of the session: the step-up of both persons (§8.3 step 7, §8.6)
	// Condition is the condition of the caller's :decide grant (authz.Decision.Condition of the approve/reject
	// operation); "" for an unconditional grant.
	Condition string
}

// Ref names one request in the scope of a route: a platform request (TenantID uuid.Nil) on /platform/approvals, a
// request of the tenant TenantID on /tenants/{tenantId}/approvals.
type Ref struct {
	Scope    authz.Scope
	TenantID uuid.UUID
	ID       uuid.UUID
}

// Person is the requester or the decider of a request with the display name read with it.
type Person struct {
	IdentityID uuid.UUID
	Display    string
}

// Request is an approval request as the approver sees it (schema ApprovalRequest).
type Request struct {
	ID            uuid.UUID
	Scope         authz.Scope
	TenantID      *uuid.UUID
	Action        string
	ResourceType  string
	ResourceID    string
	Payload       json.RawMessage // canonical — exactly what will be executed
	PayloadSHA256 string
	Status        string // effective: pending/approved past expires_at read as expired
	Reason        string
	RequestedBy   Person
	DecidedBy     *Person
	DecidedAt     *time.Time
	ExpiresAt     time.Time
	JobID         *uuid.UUID
	CreatedAt     time.Time
}

// Page is one page of requests.
type Page struct {
	Items      []Request
	NextCursor string
}

// Filter holds the query parameters of the list operations.
type Filter struct {
	Status string // one of Statuses (effective status)
	Action string
	Limit  int // 0 ⇒ DefaultLimit
	Cursor string
}

// NewRequest is a 2P operation turned into a request (§8.6: 202 + Location of /approvals/{id}).
type NewRequest struct {
	Action     string    // a registered action
	TenantID   uuid.UUID // tenant scope: the tenant of the path; platform scope: uuid.Nil
	ResourceID string    // the resource of the operation ("" when none)
	Payload    any       // the action's parameters — canonicalized; never a secret (only secret references)
	Reason     string    // why, shown to the approver (≤ 1000 characters)
	// AuditAction is the action of the success event; "" ⇒ the operation's x-audit-action from the request's audit
	// scope, else "platform.approval.request" / "approval.request".
	AuditAction string
}

// Approvers is the part of *authz.Authorizer the service needs: the decision for the second person.
type Approvers interface {
	RequireApprover(ctx context.Context, tenantID, requestedBy uuid.UUID, req authz.Requirement) (authz.Decision, error)
}

// SecurityRecorder raises security events in a transaction of their own (*audit.Logger).
type SecurityRecorder interface {
	RecordSecurityEvent(ctx context.Context, ev audit.SecurityEvent) (bool, error)
}

// Config configures the Service. Approvers is required.
type Config struct {
	Approvers    Approvers
	Registry     *Registry // nil ⇒ no action: requests can be read and rejected, never created nor approved
	Security     SecurityRecorder
	StepUpWindow time.Duration // 0 ⇒ DefaultStepUpWindow
	TTL          time.Duration // 0 ⇒ DefaultTTL (system_settings TTLSetting overrides it)
	Now          func() time.Time
	Logger       *slog.Logger
	// Notify, when set, runs in the transaction that creates a request — a job-capable transaction of the request's
	// scope — so the people who may decide it are told with the request (notification_outbox, P4-T03a: the approval
	// queue of the tenant). An error rolls the request back.
	Notify func(ctx context.Context, tx *store.Tx, r Request) error
}

// Service is dual control: requests, decisions and execution (P3-T04a).
type Service struct {
	st  *store.Store
	cfg Config
	log *slog.Logger
	now func() time.Time
}

// New returns the service on st (the api process's store).
func New(st *store.Store, cfg Config) (*Service, error) {
	if st == nil || cfg.Approvers == nil {
		return nil, errors.New("approvals: a store and an authorizer are required")
	}
	if cfg.StepUpWindow <= 0 {
		cfg.StepUpWindow = DefaultStepUpWindow
	}
	if cfg.TTL <= 0 {
		cfg.TTL = DefaultTTL
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Service{st: st, cfg: cfg, log: cfg.Logger.With("module", "approvals"), now: cfg.Now}, nil
}

// Location is the Location of the 202 answering a 2P operation, and the path of the request.
func Location(r Request) string {
	if r.Scope == authz.ScopeTenant && r.TenantID != nil {
		return "/api/v1/tenants/" + r.TenantID.String() + "/approvals/" + r.ID.String()
	}
	return "/api/v1/platform/approvals/" + r.ID.String()
}

// stepUp is the step-up check of §8.3 step 7 on the actor's session.
func (s *Service) stepUp(a Actor) error {
	now := s.now()
	if a.AuthTime.IsZero() || now.Sub(a.AuthTime) > s.cfg.StepUpWindow || a.AuthTime.After(now.Add(clockSkew)) {
		return refuse(ErrReauthRequired, ReasonStepUp)
	}
	return nil
}

// tx runs fn in the transaction of ref's scope: the tenant pool for a tenant request (RLS: that tenant's rows only),
// the platform pool otherwise.
func (s *Service) tx(ctx context.Context, ref Ref, fn func(q *sqlcdb.Queries) error) error {
	if ref.Scope == authz.ScopeTenant {
		return s.st.WithTenantTx(ctx, ref.TenantID, fn)
	}
	return s.st.WithPlatformTx(ctx, fn)
}

// jobTx is tx with a job-capable transaction (jobs.Enqueue).
func (s *Service) jobTx(ctx context.Context, ref Ref, fn func(tx *store.Tx) error) error {
	if ref.Scope == authz.ScopeTenant {
		return s.st.WithTenantJobTx(ctx, ref.TenantID, fn)
	}
	return s.st.WithPlatformJobTx(ctx, fn)
}

func checkRef(ref Ref) error {
	switch {
	case ref.Scope == authz.ScopeTenant && ref.TenantID != uuid.Nil:
	case ref.Scope == authz.ScopePlatform && ref.TenantID == uuid.Nil:
	default:
		return refuse(ErrNotFound, ReasonScopeMismatch)
	}
	return nil
}

func (r Ref) tenantPtr() *uuid.UUID {
	if r.Scope == authz.ScopeTenant {
		t := r.TenantID
		return &t
	}
	return nil
}

// actionPrefix is the prefix of this package's audit actions: platform requests are platform events.
func (r Ref) actionPrefix() string {
	if r.Scope == authz.ScopePlatform {
		return "platform.approval."
	}
	return "approval."
}

// ttl is the lifetime of a new request: system_settings TTLSetting (hours) when set and valid, else Config.TTL.
func (s *Service) ttl(ctx context.Context) time.Duration {
	var raw []byte
	err := s.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		row, err := q.GetSystemSetting(ctx, TTLSetting)
		if err != nil {
			return err
		}
		raw = row.Value
		return nil
	})
	if err != nil {
		if !errors.Is(err, store.ErrNoRows) {
			s.log.WarnContext(ctx, "approval ttl setting unreadable, using the default", "error", err.Error())
		}
		return s.cfg.TTL
	}
	h, err := strconv.Atoi(string(raw))
	if err != nil || h < 1 || h > 168 {
		s.log.WarnContext(ctx, "approval ttl setting out of range (1–168 hours), using the default", "setting", TTLSetting)
		return s.cfg.TTL
	}
	return time.Duration(h) * time.Hour
}

// Idempotency is the Idempotency-Key of the 2P operation that creates a request (§13.1: a POST answering 202 takes
// one): the operationId, the key and jobs.RequestHash of the request.
type Idempotency struct {
	Operation string
	Key       string
	Hash      []byte
}

// idempotencyLock bounds how long a request holds its key while in progress.
const idempotencyLock = 30 * time.Second

// RequestIdempotent is Request under an Idempotency-Key: a replay of the same request returns the request the first
// one created (as it is now), the key used for another request is refused (ReasonIdempotencyKeyReuse), a request still
// in progress answers ReasonIdempotencyInProgress. The key is taken in a transaction of its own, completed in the
// transaction that creates the request, released when creating it fails.
func (s *Service) RequestIdempotent(ctx context.Context, actor Actor, in NewRequest, idem Idempotency) (Request, error) {
	if err := s.stepUp(actor); err != nil {
		return Request{}, err
	}
	act, ok := s.cfg.Registry.Lookup(in.Action)
	if !ok {
		return Request{}, refuse(ErrUnavailable, ReasonActionUnavailable)
	}
	ref := Ref{Scope: act.Spec().Scope, TenantID: in.TenantID}
	if err := checkRef(ref); err != nil {
		return Request{}, refuse(ErrInvalid, ReasonScopeMismatch)
	}
	key := jobs.IdempotencyKey{TenantID: ref.tenantPtr(), IdentityID: actor.IdentityID, OperationID: idem.Operation,
		Key: idem.Key}
	var replay uuid.UUID
	err := s.tx(ctx, ref, func(q *sqlcdb.Queries) error {
		d, err := jobs.BeginIdempotent(ctx, q, key, idem.Hash, idempotencyLock)
		if errors.Is(err, jobs.ErrInvalidIdempotencyKey) {
			return refuse(ErrInvalid, ReasonInvalidInput)
		}
		if err != nil {
			return err
		}
		switch d.Outcome {
		case jobs.IdempotencyReplay:
			var stored struct {
				ID uuid.UUID `json:"id"`
			}
			if d.Response == nil || json.Unmarshal(d.Response.Body, &stored) != nil || stored.ID == uuid.Nil {
				return errors.New("approvals: stored response of the Idempotency-Key unreadable")
			}
			replay = stored.ID
		case jobs.IdempotencyInProgress:
			return &Error{Kind: ErrConflict, Reason: ReasonIdempotencyInProgress, RetryAfter: d.RetryAfter}
		case jobs.IdempotencyKeyReuse:
			return refuse(ErrInvalid, ReasonIdempotencyKeyReuse)
		}
		return nil
	})
	if err != nil {
		return Request{}, s.fail(err)
	}
	if replay != uuid.Nil {
		return s.Get(ctx, Ref{Scope: ref.Scope, TenantID: ref.TenantID, ID: replay})
	}
	r, err := s.request(ctx, actor, in, func(q *sqlcdb.Queries, id uuid.UUID) error {
		body, err := json.Marshal(map[string]uuid.UUID{"id": id})
		if err != nil {
			return err
		}
		return jobs.CompleteIdempotent(ctx, q, key, idem.Hash, jobs.StoredResponse{Status: 202, Body: body,
			Resource: &jobs.Resource{Type: "approval", ID: id.String()}})
	})
	if err != nil {
		if ferr := s.tx(context.WithoutCancel(ctx), ref, func(q *sqlcdb.Queries) error {
			return jobs.FailIdempotent(ctx, q, key, idem.Hash)
		}); ferr != nil && !errors.Is(ferr, jobs.ErrIdempotencyLost) {
			s.log.WarnContext(ctx, "approval request: Idempotency-Key not released", "error", ferr.Error())
		}
		return Request{}, err
	}
	return r, nil
}

// Request turns a 2P operation into an approval request (§8.6): the requester must have stepped up; the payload is
// validated by the action and stored in canonical form with its SHA-256; an open request of the same action on the
// same resource is not duplicated (ReasonOpenRequest, Error.Existing). The calling operation has authorized the
// requester already (layer 1 with x-dual-control). The success event is written in the same transaction.
func (s *Service) Request(ctx context.Context, actor Actor, in NewRequest) (Request, error) {
	return s.request(ctx, actor, in, nil)
}

// request is Request; done (when set) runs in the creating transaction with the new request's id.
func (s *Service) request(ctx context.Context, actor Actor, in NewRequest, done func(q *sqlcdb.Queries, id uuid.UUID) error) (Request, error) {
	if err := s.stepUp(actor); err != nil {
		return Request{}, err
	}
	act, ok := s.cfg.Registry.Lookup(in.Action)
	if !ok {
		return Request{}, refuse(ErrUnavailable, ReasonActionUnavailable)
	}
	spec := act.Spec()
	ref := Ref{Scope: spec.Scope, TenantID: in.TenantID}
	if err := checkRef(ref); err != nil || actor.Scope != spec.Scope {
		return Request{}, refuse(ErrInvalid, ReasonScopeMismatch)
	}
	if len(in.ResourceID) > 128 || len(in.Reason) > 4*maxReason || utf8.RuneCountInString(in.Reason) > maxReason ||
		!utf8.ValidString(in.Reason) {
		return Request{}, refuse(ErrInvalid, ReasonInvalidInput)
	}
	payload, err := Canonical(in.Payload)
	if err == nil {
		err = act.Validate(payload)
	}
	if err != nil {
		e := refuse(ErrInvalid, ReasonInvalidPayload)
		e.cause = err
		return Request{}, e
	}
	sum := Hash(payload)
	now := s.now()
	expires := now.Add(s.ttl(ctx))
	var row sqlcdb.ApprovalRequest
	err = s.jobTx(ctx, ref, func(tx *store.Tx) error {
		q := tx.Q
		open, err := q.FindOpenApprovalRequest(ctx, sqlcdb.FindOpenApprovalRequestParams{Scope: string(ref.Scope),
			TenantID: ref.tenantPtr(), Action: spec.Name, ResourceType: spec.ResourceType, ResourceID: optional(in.ResourceID),
			Now: now})
		switch {
		case err == nil:
			return &Error{Kind: ErrConflict, Reason: ReasonOpenRequest, Existing: open}
		case !errors.Is(err, store.ErrNoRows):
			return err
		}
		row, err = q.InsertApprovalRequest(ctx, sqlcdb.InsertApprovalRequestParams{
			Scope: string(ref.Scope), TenantID: ref.tenantPtr(), Action: spec.Name, ResourceType: spec.ResourceType,
			ResourceID: optional(in.ResourceID), Payload: payload, PayloadSha256: sum,
			RequestedByIdentityID: actor.IdentityID, Reason: optional(in.Reason), ExpiresAt: expires, CreatedAt: now,
		})
		if err != nil {
			return err
		}
		action := in.AuditAction
		if action == "" {
			if r := audit.RequestFrom(ctx); r != nil && r.Action != "" {
				action = r.Action
			} else {
				action = ref.actionPrefix() + "request"
			}
		}
		id := actor.IdentityID
		if err := audit.Record(ctx, q, audit.Event{Action: action, TenantID: ref.tenantPtr(), ActorIdentityID: &id,
			ResourceType: "approval", ResourceID: row.ID.String(), Details: audit.Details{
				"approval_id": row.ID, "approval_action": spec.Name, "target_type": spec.ResourceType,
				"target_id": in.ResourceID, "payload_sha256": sum, "expires_at": expires, "status": StatusPending,
				"requested_by_identity_id": actor.IdentityID,
			}}); err != nil {
			return err
		}
		if s.cfg.Notify != nil {
			if err := s.cfg.Notify(ctx, tx, s.view(row, "", "")); err != nil {
				return err
			}
		}
		if done != nil {
			return done(q, row.ID)
		}
		return nil
	})
	if err != nil {
		return Request{}, s.fail(err)
	}
	return s.Get(ctx, Ref{Scope: ref.Scope, TenantID: ref.TenantID, ID: row.ID})
}

// fail returns a refusal as is — an *Error of this package or the *authz.Denial of the decider's authorization — and
// wraps anything else (an internal failure).
func (s *Service) fail(err error) error {
	var (
		e *Error
		d *authz.Denial
	)
	switch {
	case errors.As(err, &e):
		return e
	case errors.As(err, &d):
		return d
	}
	return fmt.Errorf("approvals: %w", err)
}

// Get returns one request of ref's scope (404 for a request of another scope or tenant — §8.4 invariant 6).
func (s *Service) Get(ctx context.Context, ref Ref) (Request, error) {
	if err := checkRef(ref); err != nil {
		return Request{}, err
	}
	var out Request
	err := s.tx(ctx, ref, func(q *sqlcdb.Queries) error {
		row, err := q.GetApprovalRequestView(ctx, sqlcdb.GetApprovalRequestViewParams{ID: ref.ID, Scope: string(ref.Scope),
			TenantID: ref.tenantPtr()})
		if errors.Is(err, store.ErrNoRows) {
			return refuse(ErrNotFound, ReasonNotFound)
		}
		if err != nil {
			return err
		}
		out = s.view(row.ApprovalRequest, row.RequestedByDisplay, row.DecidedByDisplay)
		return nil
	})
	if err != nil {
		return Request{}, s.fail(err)
	}
	return out, nil
}

// List returns one page of the requests of ref's scope (ref.ID is ignored), newest first.
func (s *Service) List(ctx context.Context, ref Ref, f Filter) (Page, error) {
	ref.ID = uuid.Nil
	if err := checkRef(ref); err != nil {
		return Page{}, err
	}
	limit := f.Limit
	if limit == 0 {
		limit = DefaultLimit
	}
	if limit < 1 || limit > MaxLimit || (f.Status != "" && !slices.Contains(Statuses, f.Status)) ||
		(f.Action != "" && (len(f.Action) > 100 || !actionRE.MatchString(f.Action))) {
		return Page{}, refuse(ErrInvalid, ReasonInvalidInput)
	}
	before, beforeID := time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC), uuid.Max
	if f.Cursor != "" {
		var ok bool
		if before, beforeID, ok = decodeCursor(f.Cursor); !ok {
			return Page{}, refuse(ErrInvalid, ReasonInvalidInput)
		}
	}
	page := Page{Items: []Request{}}
	err := s.tx(ctx, ref, func(q *sqlcdb.Queries) error {
		rows, err := q.ListApprovalRequests(ctx, sqlcdb.ListApprovalRequestsParams{
			Scope: string(ref.Scope), TenantID: ref.tenantPtr(), Status: optional(f.Status), Now: s.now(),
			Action: optional(f.Action), BeforeCreatedAt: before, BeforeID: beforeID,
			PageLimit: int32(limit + 1), //nolint:gosec // limit ≤ MaxLimit
		})
		if err != nil {
			return err
		}
		if len(rows) > limit {
			rows = rows[:limit]
			last := rows[limit-1].ApprovalRequest
			page.NextCursor = encodeCursor(last.CreatedAt, last.ID)
		}
		for _, r := range rows {
			page.Items = append(page.Items, s.view(r.ApprovalRequest, r.RequestedByDisplay, r.DecidedByDisplay))
		}
		return nil
	})
	if err != nil {
		return Page{}, s.fail(err)
	}
	return page, nil
}

// view projects a row; the status is the effective one at the service clock.
func (s *Service) view(r sqlcdb.ApprovalRequest, requestedBy, decidedBy string) Request {
	out := Request{
		ID: r.ID, Scope: authz.Scope(r.Scope), TenantID: r.TenantID, Action: r.Action, ResourceType: r.ResourceType,
		Payload: canonicalOrRaw(r.Payload), PayloadSHA256: r.PayloadSha256, Status: s.effective(r),
		RequestedBy: Person{IdentityID: r.RequestedByIdentityID, Display: requestedBy}, DecidedAt: r.DecidedAt,
		ExpiresAt: r.ExpiresAt, JobID: r.JobID, CreatedAt: r.CreatedAt,
	}
	if r.ResourceID != nil {
		out.ResourceID = *r.ResourceID
	}
	if r.Reason != nil {
		out.Reason = *r.Reason
	}
	if r.ApprovedByIdentityID != nil {
		out.DecidedBy = &Person{IdentityID: *r.ApprovedByIdentityID, Display: decidedBy}
	}
	return out
}

// canonicalOrRaw shows the stored payload in canonical form — the form that is hashed and executed. A payload that
// cannot be canonicalized any more (changed outside the application) is shown as stored; it is never executed.
func canonicalOrRaw(raw []byte) json.RawMessage {
	if c, err := CanonicalJSON(raw); err == nil {
		return c
	}
	return json.RawMessage(raw)
}

func (s *Service) effective(r sqlcdb.ApprovalRequest) string {
	if (r.Status == StatusPending || r.Status == StatusApproved) && !s.now().Before(r.ExpiresAt) {
		return StatusExpired
	}
	return r.Status
}

// integrity reports whether the stored payload still hashes to payload_sha256, and returns its canonical form.
func integrity(r sqlcdb.ApprovalRequest) (json.RawMessage, bool) {
	c, err := CanonicalJSON(r.Payload)
	if err != nil || Hash(c) != r.PayloadSha256 {
		return nil, false
	}
	return c, true
}

// authorizeDecider checks the second person (§8.5/§8.6 2P rule): not the requester, holding the permission of the
// action itself, and — when the caller's :decide grant is conditional — an action that satisfies the condition.
func (s *Service) authorizeDecider(ctx context.Context, ref Ref, actor Actor, r sqlcdb.ApprovalRequest, act Action) error {
	if actor.IdentityID == r.RequestedByIdentityID {
		s.securityEvent(ctx, ref, audit.SecurityEvent{Kind: KindSelfApproval, Severity: audit.SeverityMedium,
			Details: audit.Details{"approval_id": r.ID, "approval_action": r.Action, "identity_id": actor.IdentityID}})
		return refuse(ErrForbidden, ReasonSelfDecision)
	}
	if act == nil {
		// unknown action (only a rejection gets here): the :decide grant of layer 1 decides, unconditionally only
		if actor.Condition != "" {
			return refuse(ErrForbidden, ReasonDecideCondition)
		}
		return nil
	}
	spec := act.Spec()
	if actor.Condition != "" && !slices.Contains(spec.DecideConditions, actor.Condition) {
		return refuse(ErrForbidden, ReasonDecideCondition)
	}
	if p, ok := authz.PrincipalFrom(ctx); !ok || p.IdentityID != actor.IdentityID {
		// outside the API chain (tests, commands): the principal is the actor, on the origin of its scope (§8.3)
		origin := authz.OriginApp
		if actor.Scope == authz.ScopePlatform {
			origin = authz.OriginAdmin
		}
		ctx = authz.WithPrincipal(ctx, authz.Principal{IdentityID: actor.IdentityID, Scope: actor.Scope, Origin: origin})
	}
	need := authz.Need(spec.Permission)
	need.Conditions = spec.ApproverConditions
	if _, err := s.cfg.Approvers.RequireApprover(ctx, ref.TenantID, r.RequestedByIdentityID, need); err != nil {
		return err // *authz.Denial: 403/404 as decided for the caller
	}
	return nil
}

func (s *Service) securityEvent(ctx context.Context, ref Ref, ev audit.SecurityEvent) {
	ev.TenantID = ref.tenantPtr()
	ev.Source = "approvals"
	if s.cfg.Security == nil {
		s.log.WarnContext(ctx, "security event", "kind", ev.Kind, "severity", ev.Severity)
		return
	}
	if _, err := s.cfg.Security.RecordSecurityEvent(context.WithoutCancel(ctx), ev); err != nil {
		s.log.ErrorContext(ctx, "security event not recorded", "kind", ev.Kind, "error", err.Error())
	}
}

// expire marks a request past its expiry as expired (its own transaction: the refusal must not roll it back).
func (s *Service) expire(ctx context.Context, ref Ref, id uuid.UUID) {
	err := s.tx(ctx, ref, func(q *sqlcdb.Queries) error {
		_, err := q.ExpireApprovalRequest(ctx, id)
		if errors.Is(err, store.ErrNoRows) {
			return nil
		}
		return err
	})
	if err != nil {
		s.log.WarnContext(ctx, "approval request not marked expired", "approval_id", id.String(), "error", err.Error())
	}
}

// authorizeRequest reads the request (no lock: its action, requester and scope never change — §6.3) and authorizes the
// caller as its second person before any row is locked; the transaction that follows re-reads the status under lock.
// approve also requires an action this process can execute (an unknown one can only be rejected).
func (s *Service) authorizeRequest(ctx context.Context, ref Ref, actor Actor, approve bool) error {
	var r sqlcdb.ApprovalRequest
	err := s.tx(ctx, ref, func(q *sqlcdb.Queries) error {
		row, err := q.GetApprovalRequestView(ctx, sqlcdb.GetApprovalRequestViewParams{ID: ref.ID, Scope: string(ref.Scope),
			TenantID: ref.tenantPtr()})
		if errors.Is(err, store.ErrNoRows) {
			return refuse(ErrNotFound, ReasonNotFound)
		}
		r = row.ApprovalRequest
		return err
	})
	if err != nil {
		return err
	}
	act, ok := s.cfg.Registry.Lookup(r.Action)
	if approve && !ok && actor.IdentityID != r.RequestedByIdentityID {
		return refuse(ErrUnavailable, ReasonActionUnavailable)
	}
	return s.authorizeDecider(ctx, ref, actor, r, act)
}

// Approve is POST …/approvals/{id}/approve: the second person approves the request whose payload hashes to
// reviewedSHA256 — the payload_sha256 they were shown — and the action runs at once (Execute). Order of the checks:
// step-up (401), the request in this scope and tenant (404), not the requester (403 + security event), an action this
// process can execute (409), the action's permission and the :decide condition (403/404), still pending and not
// expired (409; an expired request is marked expired), the reviewed hash (412), the stored payload still hashing to
// it (409 + security event). The approval commits on its own, then Execute runs: when execution fails, the request
// stays approved and the same approver may call Approve again to retry the execution (no second approval).
func (s *Service) Approve(ctx context.Context, actor Actor, ref Ref, reviewedSHA256 string) (Request, error) {
	if err := s.stepUp(actor); err != nil {
		return Request{}, err
	}
	if err := checkRef(ref); err != nil {
		return Request{}, err
	}
	if !ValidHash(reviewedSHA256) {
		return Request{}, refuse(ErrInvalid, ReasonInvalidInput)
	}
	if err := s.authorizeRequest(ctx, ref, actor, true); err != nil {
		return Request{}, s.fail(err)
	}
	var expired, tampered bool
	err := s.tx(ctx, ref, func(q *sqlcdb.Queries) error {
		r, err := q.LockApprovalRequest(ctx, sqlcdb.LockApprovalRequestParams{ID: ref.ID, Scope: string(ref.Scope),
			TenantID: ref.tenantPtr()})
		if errors.Is(err, store.ErrNoRows) {
			return refuse(ErrNotFound, ReasonNotFound)
		}
		if err != nil {
			return err
		}
		switch {
		case r.Status == StatusExecuted:
			return refuse(ErrConflict, ReasonExecuted)
		case (r.Status == StatusPending || r.Status == StatusApproved) && !s.now().Before(r.ExpiresAt):
			expired = true
			return refuse(ErrConflict, ReasonExpired)
		case r.Status == StatusApproved && r.ApprovedByIdentityID != nil && *r.ApprovedByIdentityID == actor.IdentityID:
			// approved by this person before, execution failed: Execute below retries it (checks again)
			if r.PayloadSha256 != reviewedSHA256 {
				return refuse(ErrPayloadChanged, ReasonPayloadChanged)
			}
			return nil
		case r.Status == StatusApproved:
			return refuse(ErrConflict, ReasonOtherApprover)
		case r.Status != StatusPending:
			return refuse(ErrConflict, ReasonNotPending)
		case r.PayloadSha256 != reviewedSHA256:
			return refuse(ErrPayloadChanged, ReasonPayloadChanged)
		}
		if _, ok := integrity(r); !ok {
			tampered = true
			return refuse(ErrConflict, ReasonPayloadIntegrity)
		}
		dec, err := q.DecideApprovalRequest(ctx, sqlcdb.DecideApprovalRequestParams{Status: StatusApproved,
			DecidedBy: &actor.IdentityID, Now: s.now(), ID: r.ID})
		if err != nil {
			return err
		}
		return s.record(ctx, q, ref, actor, dec, "approve", nil)
	})
	switch {
	case expired:
		s.expire(ctx, ref, ref.ID)
	case tampered:
		s.securityEvent(ctx, ref, audit.SecurityEvent{Kind: KindPayloadIntegrity, Severity: audit.SeverityHigh,
			Details: audit.Details{"approval_id": ref.ID, "stage": "approve", "identity_id": actor.IdentityID}})
	}
	if err != nil {
		return Request{}, s.fail(err)
	}
	return s.Execute(ctx, actor, ref, reviewedSHA256)
}

// Execute runs an approved request once (§6.3): only its approver, only before it expires, only when payload_sha256
// is still the hash the approver approved (approvedSHA256) and the stored payload still hashes to it, and only when the
// action accepts the payload. The action runs in the transaction that marks the request executed and records its job
// (a job it enqueues exists if and only if the request is executed); an executed request is never run again.
func (s *Service) Execute(ctx context.Context, actor Actor, ref Ref, approvedSHA256 string) (Request, error) {
	if err := s.stepUp(actor); err != nil {
		return Request{}, err
	}
	if err := checkRef(ref); err != nil {
		return Request{}, err
	}
	if !ValidHash(approvedSHA256) {
		return Request{}, refuse(ErrInvalid, ReasonInvalidInput)
	}
	var expired, tampered bool
	err := s.jobTx(ctx, ref, func(tx *store.Tx) error {
		q := tx.Q
		r, err := q.LockApprovalRequest(ctx, sqlcdb.LockApprovalRequestParams{ID: ref.ID, Scope: string(ref.Scope),
			TenantID: ref.tenantPtr()})
		if errors.Is(err, store.ErrNoRows) {
			return refuse(ErrNotFound, ReasonNotFound)
		}
		if err != nil {
			return err
		}
		switch {
		case r.Status == StatusExecuted:
			return refuse(ErrConflict, ReasonExecuted)
		case r.Status != StatusApproved:
			return refuse(ErrConflict, ReasonNotPending)
		case r.ApprovedByIdentityID == nil || *r.ApprovedByIdentityID != actor.IdentityID:
			return refuse(ErrConflict, ReasonOtherApprover)
		case !s.now().Before(r.ExpiresAt):
			expired = true
			return refuse(ErrConflict, ReasonExpired)
		}
		act, ok := s.cfg.Registry.Lookup(r.Action)
		if !ok {
			return refuse(ErrUnavailable, ReasonActionUnavailable)
		}
		if r.PayloadSha256 != approvedSHA256 {
			return refuse(ErrPayloadChanged, ReasonPayloadChanged)
		}
		payload, ok := integrity(r)
		if !ok {
			tampered = true
			return refuse(ErrConflict, ReasonPayloadIntegrity)
		}
		if err := act.Validate(payload); err != nil {
			e := refuse(ErrConflict, ReasonInvalidPayload)
			e.cause = err
			return e
		}
		view := s.view(r, "", "")
		jobID, err := act.Execute(ctx, tx, Execution{Request: view, Payload: payload})
		if err != nil {
			return err
		}
		done, err := q.MarkApprovalExecuted(ctx, sqlcdb.MarkApprovalExecutedParams{JobID: jobID, ID: r.ID})
		if err != nil {
			return err
		}
		return s.record(ctx, q, ref, actor, done, "execute", jobID)
	})
	switch {
	case expired:
		s.expire(ctx, ref, ref.ID)
	case tampered:
		s.securityEvent(ctx, ref, audit.SecurityEvent{Kind: KindPayloadIntegrity, Severity: audit.SeverityHigh,
			Details: audit.Details{"approval_id": ref.ID, "stage": "execute", "identity_id": actor.IdentityID}})
	}
	if err != nil {
		return Request{}, s.fail(err)
	}
	return s.Get(ctx, ref)
}

// Reject is POST …/approvals/{id}/reject: the second person refuses a pending request (step-up, not the requester,
// the action's permission and the :decide condition when the action is known). Nothing runs.
func (s *Service) Reject(ctx context.Context, actor Actor, ref Ref) (Request, error) {
	if err := s.stepUp(actor); err != nil {
		return Request{}, err
	}
	if err := checkRef(ref); err != nil {
		return Request{}, err
	}
	if err := s.authorizeRequest(ctx, ref, actor, false); err != nil {
		return Request{}, s.fail(err)
	}
	var expired bool
	err := s.tx(ctx, ref, func(q *sqlcdb.Queries) error {
		r, err := q.LockApprovalRequest(ctx, sqlcdb.LockApprovalRequestParams{ID: ref.ID, Scope: string(ref.Scope),
			TenantID: ref.tenantPtr()})
		if errors.Is(err, store.ErrNoRows) {
			return refuse(ErrNotFound, ReasonNotFound)
		}
		if err != nil {
			return err
		}
		switch {
		case r.Status == StatusExecuted:
			return refuse(ErrConflict, ReasonExecuted)
		case (r.Status == StatusPending || r.Status == StatusApproved) && !s.now().Before(r.ExpiresAt):
			expired = true
			return refuse(ErrConflict, ReasonExpired)
		case r.Status != StatusPending:
			return refuse(ErrConflict, ReasonNotPending)
		}
		dec, err := q.DecideApprovalRequest(ctx, sqlcdb.DecideApprovalRequestParams{Status: StatusRejected,
			DecidedBy: &actor.IdentityID, Now: s.now(), ID: r.ID})
		if err != nil {
			return err
		}
		return s.record(ctx, q, ref, actor, dec, "reject", nil)
	})
	if expired {
		s.expire(ctx, ref, ref.ID)
	}
	if err != nil {
		return Request{}, s.fail(err)
	}
	return s.Get(ctx, ref)
}

// record writes the success event of a decision or an execution in its transaction: the actor is the decider, the
// details name both persons (§8.6 — audit ghi cả hai actor) and the payload hash.
func (s *Service) record(ctx context.Context, q *sqlcdb.Queries, ref Ref, actor Actor, r sqlcdb.ApprovalRequest,
	verb string, jobID *uuid.UUID) error {
	id := actor.IdentityID
	d := audit.Details{
		"approval_id": r.ID, "approval_action": r.Action, "target_type": r.ResourceType,
		"requested_by_identity_id": r.RequestedByIdentityID, "decided_by_identity_id": actor.IdentityID,
		"payload_sha256": r.PayloadSha256, "status": r.Status,
	}
	if r.ResourceID != nil {
		d["target_id"] = *r.ResourceID
	}
	if jobID != nil {
		d["job_id"] = *jobID
	}
	return audit.Record(ctx, q, audit.Event{Action: ref.actionPrefix() + verb, TenantID: ref.tenantPtr(),
		ActorIdentityID: &id, ResourceType: "approval", ResourceID: r.ID.String(), Details: d})
}

func optional(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// cursorVersion prefixes the opaque cursor: version | created_at (µs) | id.
const cursorVersion = 1

var b64 = base64.RawURLEncoding

func encodeCursor(t time.Time, id uuid.UUID) string {
	b := make([]byte, 0, 1+8+16)
	b = append(b, cursorVersion)
	b = binary.BigEndian.AppendUint64(b, uint64(t.UnixMicro())) //nolint:gosec // timestamps after 1970
	b = append(b, id[:]...)
	return b64.EncodeToString(b)
}

func decodeCursor(s string) (time.Time, uuid.UUID, bool) {
	b, err := b64.Strict().DecodeString(s)
	if err != nil || len(b) != 1+8+16 || b[0] != cursorVersion {
		return time.Time{}, uuid.Nil, false
	}
	micros := binary.BigEndian.Uint64(b[1:9])
	if micros > 1<<62 {
		return time.Time{}, uuid.Nil, false
	}
	id, err := uuid.FromBytes(b[9:])
	if err != nil {
		return time.Time{}, uuid.Nil, false
	}
	return time.UnixMicro(int64(micros)).UTC(), id, true
}
