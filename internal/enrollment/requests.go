package enrollment

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/config"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
	"github.com/zhaduchanhzz/network-access-mesh/internal/usage"
)

// Operation ids of the creates (Idempotency-Key scope).
const (
	createRequestOperation = "createEnrollmentRequest"
	createKeyOperation     = "createEnrollmentKey"
	lockName               = "enrollment" // tenant lock of /start and /revoke (a key is issued or expired once)
	lockWait               = 15 * time.Second
)

// NewRequest is POST /enrollment/requests: a device of the caller itself.
type NewRequest struct {
	Method      string
	DeviceLabel *string
	TTLMinutes  int // preauth_key only; 0 = default
}

// NewKey is POST /enrollment/keys: a privileged pre-auth key.
type NewKey struct {
	Target      *uuid.UUID // nil: tag-only key (Tags required)
	Tags        []string
	Reusable    bool
	Ephemeral   bool
	DeviceLabel *string
	TTLMinutes  int
}

// plan is a request to create, after validation.
type plan struct {
	operation  string
	action     string
	method     string
	target     *uuid.UUID
	label      *string
	tags       []string
	reusable   bool
	ephemeral  bool
	ttlMinutes int
	privileged bool
}

func checkLabel(label *string) error {
	if label != nil && headscale.ValidateGivenName(*label) != nil {
		return invalid("device_label", "invalid_device_label",
			"device_label must be a DNS label: lowercase letters, digits and hyphens, at most 63 characters")
	}
	return nil
}

func checkTTL(minutes int) error {
	if minutes != 0 && (minutes < 1 || minutes > int(MaxKeyTTL/time.Minute)) {
		return invalid("ttl_minutes", "invalid_ttl", "ttl_minutes must be between 1 and 15")
	}
	return nil
}

// Create is POST /tenants/{t}/enrollment/requests (§7.4 steps 3–4).
func (s *Service) Create(ctx context.Context, tenantID uuid.UUID, a Actor, in NewRequest, idem *Idempotency) (Issue, error) {
	switch {
	case in.Method != MethodWebAuth && in.Method != MethodPreauthKey:
		return Issue{}, invalid("method", "invalid_method", "method must be web_auth or preauth_key")
	case in.Method == MethodWebAuth && in.TTLMinutes != 0:
		return Issue{}, invalid("ttl_minutes", "ttl_web_auth", "ttl_minutes applies to preauth_key only")
	}
	if err := checkLabel(in.DeviceLabel); err != nil {
		return Issue{}, err
	}
	if err := checkTTL(in.TTLMinutes); err != nil {
		return Issue{}, err
	}
	target := a.MembershipID
	return s.create(ctx, tenantID, a, plan{operation: createRequestOperation, action: ActionRequest, method: in.Method,
		target: &target, label: in.DeviceLabel, ttlMinutes: in.TTLMinutes}, idem)
}

// CreateKey is POST /tenants/{t}/enrollment/keys (tenant.enrollment:issue_privileged — §7.4 method B).
func (s *Service) CreateKey(ctx context.Context, tenantID uuid.UUID, a Actor, in NewKey, idem *Idempotency) (Issue, error) {
	if in.Target == nil && len(in.Tags) == 0 {
		return Issue{}, invalid("tags", "tags_required", "a key without target_membership_id (tag-only key) needs tags")
	}
	if len(in.Tags) > 64 {
		return Issue{}, invalid("tags", "too_many_tags", "at most 64 tags")
	}
	if err := checkLabel(in.DeviceLabel); err != nil {
		return Issue{}, err
	}
	if err := checkTTL(in.TTLMinutes); err != nil {
		return Issue{}, err
	}
	return s.create(ctx, tenantID, a, plan{operation: createKeyOperation, action: ActionKeyCreate, method: MethodPreauthKey,
		target: in.Target, label: in.DeviceLabel, tags: in.Tags, reusable: in.Reusable, ephemeral: in.Ephemeral,
		ttlMinutes: in.TTLMinutes, privileged: true}, idem)
}

// tagRefusal maps a refusal of the TagGate: the caller's input ⇒ 422 on the field; anything else as it is.
func tagRefusal(err error) error {
	var v interface {
		Validation() (field, reason string, tags []string, ok bool)
	}
	if errors.As(err, &v) {
		if field, reason, tags, ok := v.Validation(); ok {
			if field == "" {
				field = "tags"
			}
			detail := "tags must be names of the form tag:<lowercase name>"
			if len(tags) > 0 {
				detail = "these tags are not in the tenant's tag catalog: " + strings.Join(tags, ", ")
			}
			return invalid(field, reason, detail)
		}
	}
	return err
}

func (s *Service) create(ctx context.Context, tenantID uuid.UUID, a Actor, p plan, idem *Idempotency) (Issue, error) {
	key, replay, err := s.beginIdempotent(ctx, tenantID, a, p.operation, idem)
	if err != nil {
		return Issue{}, err
	}
	if replay != nil {
		return *replay, nil
	}
	out, err := s.createOnce(ctx, tenantID, a, p)
	if err != nil {
		s.abandonIdempotent(ctx, tenantID, key, idem)
		return Issue{}, err
	}
	if err := s.finishIdempotent(ctx, tenantID, key, idem, out); err != nil {
		s.log.ErrorContext(ctx, "enrollment: storing the response for replays failed", "request_id", out.Request.ID,
			"error", err)
		s.abandonIdempotent(ctx, tenantID, key, idem)
	}
	return out, nil
}

func (s *Service) createOnce(ctx context.Context, tenantID uuid.UUID, a Actor, p plan) (Issue, error) {
	var (
		row   sqlcdb.EnrollmentRequest
		tc    tenantContext
		cred  *Credential
		kp    keyPlan
		op    audit.Operation
		issue bool
	)
	err := s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		var err error
		if tc, err = loadContext(ctx, q, tenantID); err != nil {
			return err
		}
		if err := checkSelfEnroll(a, tc); err != nil {
			return err
		}
		set := tc.settings.Enrollment
		if p.method == MethodWebAuth && !set.WebAuthEnabled {
			return invalid("method", "web_auth_disabled", "This tenant does not accept web-auth enrollment: use a pre-auth key.")
		}
		if p.target != nil && set.IdentityMode == config.IdentityModeHeadscaleOIDC {
			return conflict("identity_mode_headscale_oidc",
				"Devices of members enroll through the tenant's own OIDC login (identity mode headscale_oidc).")
		}
		var owner *member
		if p.target != nil {
			field := "target_membership_id"
			if !p.privileged {
				field = "membership"
			}
			m, err := loadMember(ctx, q, tenantID, *p.target, field)
			if err != nil {
				return err
			}
			owner = &m
		}
		tags := []string{}
		if len(p.tags) > 0 {
			if s.tags == nil {
				return errors.New("enrollment: no tag catalog wired (fail closed)")
			}
			if tags, err = s.tags(ctx, q, tenantID, p.tags, "tags"); err != nil {
				return tagRefusal(err)
			}
		}
		if p.method == MethodPreauthKey {
			ttl, err := keyTTL(p.ttlMinutes, tc.settings)
			if err != nil {
				return err
			}
			kp = keyPlan{owner: owner, ttl: ttl, tags: tags, reusable: p.reusable, ephemeral: p.ephemeral}
		}
		// approval before the device step (§7.4): a member who cannot approve waits for a decider; privileged keys
		// already need issue_privileged
		issue = p.privileged || !set.RequiresApproval || a.CanApprove
		if _, err := usage.EnrollmentTx(ctx, q, tenantID, true, issue); err != nil {
			return err
		}
		status := StatusRequested
		if !issue {
			status = StatusPendingApproval
		}
		row, err = q.InsertEnrollmentRequest(ctx, sqlcdb.InsertEnrollmentRequestParams{TenantID: tenantID,
			InstanceID: tc.instance, RequestedByMembershipID: a.MembershipID, Method: p.method, TargetMembershipID: p.target,
			DeviceLabel: p.label, RequestedTags: tags, Ephemeral: p.ephemeral, Reusable: p.reusable, Status: status})
		if err != nil {
			return err
		}
		ev := audit.Event{Action: p.action, TenantID: &tenantID, ResourceType: resourceType, ResourceID: row.ID.String(),
			Details: audit.Details{"method": p.method, "status": status, "tags": tags, "reusable": p.reusable,
				"ephemeral": p.ephemeral, "tag_only": p.target == nil}}
		if p.target != nil {
			ev.Details["target_membership_id"] = p.target.String()
		}
		switch {
		case issue && p.method == MethodWebAuth:
			if row, cred, err = s.issueCode(ctx, q, row, a, tc.loginServer); err != nil {
				return err
			}
			ev.Details["status"] = row.Status
			ev.Details["expires_at"] = *row.CredentialExpiresAt
			return audit.Record(ctx, q, ev)
		case issue:
			op, err = audit.Requested(ctx, q, ev) // the key is created at Headscale after this commits
			return err
		}
		return audit.Record(ctx, q, ev)
	})
	if err != nil {
		return Issue{}, err
	}
	if issue && p.method == MethodPreauthKey {
		if row, cred, err = s.issueKey(ctx, tenantID, row, kp, tc.loginServer, op); err != nil {
			return Issue{}, err
		}
	}
	return Issue{Request: view(row, tc.loginServer), Credential: cred}, nil
}

// visible applies an own-only grant to a request: the caller's own requests (made by it or for its device) only.
func visible(a Actor, r sqlcdb.EnrollmentRequest) bool {
	if !a.OwnOnly {
		return true
	}
	return r.RequestedByMembershipID == a.MembershipID ||
		(r.TargetMembershipID != nil && *r.TargetMembershipID == a.MembershipID)
}

// Get is GET /enrollment/requests/{id}.
func (s *Service) Get(ctx context.Context, tenantID, id uuid.UUID, a Actor) (Request, error) {
	var out Request
	err := s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		r, err := q.GetEnrollmentRequest(ctx, sqlcdb.GetEnrollmentRequestParams{TenantID: tenantID, ID: id})
		if errors.Is(err, store.ErrNoRows) {
			return notFound("no_request")
		}
		if err != nil {
			return err
		}
		if !visible(a, r) {
			return notFound("not_own_resource")
		}
		ls, err := loginServerOf(ctx, q, tenantID)
		out = view(r, ls)
		return err
	})
	return out, err
}

// Page is a page of requests.
type Page struct {
	Items      []Request
	NextCursor string
}

// Limits of the list.
const (
	DefaultLimit = 50
	MaxLimit     = 200
)

// List is GET /enrollment/requests (newest first; own-only callers see their own requests).
func (s *Service) List(ctx context.Context, tenantID uuid.UUID, a Actor, limit int, cursor, status string) (Page, error) {
	switch {
	case limit == 0:
		limit = DefaultLimit
	case limit < 1 || limit > MaxLimit:
		return Page{}, invalid("limit", "invalid_limit", "limit must be between 1 and 200")
	}
	p := sqlcdb.ListEnrollmentRequestsPageParams{TenantID: tenantID, RowLimit: int32(limit + 1)} //nolint:gosec // ≤ 201
	if a.OwnOnly {
		m := a.MembershipID
		p.Member = &m
	}
	if status != "" {
		if !slices.Contains(APIStatuses, status) {
			return Page{}, invalid("status", "invalid_status", "unknown status")
		}
		p.Statuses = columnStatuses(status)
	}
	if cursor != "" {
		at, id, ok := decodeCursor(cursor)
		if !ok {
			return Page{}, invalid("cursor", "invalid_cursor", "the cursor is not valid")
		}
		p.AfterCreated, p.AfterID = &at, &id
	}
	var out Page
	err := s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		rows, err := q.ListEnrollmentRequestsPage(ctx, p)
		if err != nil {
			return err
		}
		ls, err := loginServerOf(ctx, q, tenantID)
		if err != nil {
			return err
		}
		out.Items = make([]Request, 0, min(len(rows), limit))
		for i, r := range rows {
			if i == limit {
				last := rows[limit-1]
				out.NextCursor = encodeCursor(last.CreatedAt, last.ID)
				break
			}
			out.Items = append(out.Items, view(r, ls))
		}
		return nil
	})
	return out, err
}

func encodeCursor(at time.Time, id uuid.UUID) string {
	b := make([]byte, 8, 24)
	binary.BigEndian.PutUint64(b, uint64(at.UnixMicro())) //nolint:gosec // timestamps after 1970
	b = append(b, id[:]...)
	return base64.RawURLEncoding.EncodeToString(b)
}

func decodeCursor(s string) (time.Time, uuid.UUID, bool) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(b) != 24 {
		return time.Time{}, uuid.Nil, false
	}
	id, err := uuid.FromBytes(b[8:])
	if err != nil {
		return time.Time{}, uuid.Nil, false
	}
	return time.UnixMicro(int64(binary.BigEndian.Uint64(b[:8]))).UTC(), id, true //nolint:gosec // our own encoding
}

// errCommitted carries a refusal whose state change must still commit (a request found expired on the way).
type errCommitted struct{ err error }

func (e errCommitted) Error() string { return e.err.Error() }

// inTx runs fn in a tenant transaction; a refusal wrapped in errCommitted commits what fn wrote, then is returned.
func (s *Service) inTx(ctx context.Context, tenantID uuid.UUID, fn func(q *sqlcdb.Queries) error) error {
	var after error
	err := s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		err := fn(q)
		var c errCommitted
		if errors.As(err, &c) {
			after = c.err
			return nil
		}
		return err
	})
	if err != nil {
		return err
	}
	return after
}

// expireStale ends a request whose decision window passed (§7.4: 24 hours waiting for a decision or for /start).
func (s *Service) expireStale(ctx context.Context, q *sqlcdb.Queries, r sqlcdb.EnrollmentRequest) (bool, error) {
	since := r.CreatedAt
	if r.Status == StatusApproved && r.ApprovedAt != nil {
		since = *r.ApprovedAt
	}
	if (r.Status != StatusPendingApproval && r.Status != StatusApproved) || s.now().Sub(since) < DecisionWindow {
		return false, nil
	}
	p := stateOf(r)
	p.Status = StatusExpired
	if _, err := q.SetEnrollmentRequestState(ctx, p); err != nil {
		return false, err
	}
	return true, nil
}

// decide is /approve and /reject.
func (s *Service) decide(ctx context.Context, tenantID, id uuid.UUID, a Actor, approve bool) (Request, error) {
	var out Request
	err := s.inTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		r, err := q.LockEnrollmentRequest(ctx, sqlcdb.LockEnrollmentRequestParams{TenantID: tenantID, ID: id})
		if errors.Is(err, store.ErrNoRows) {
			return notFound("no_request")
		}
		if err != nil {
			return err
		}
		if r.Status != StatusPendingApproval {
			return conflict("not_pending_approval", "Only a request waiting for approval can be approved or rejected.")
		}
		if r.RequestedByMembershipID == a.MembershipID {
			return forbidden("self_approval", "The requester cannot decide its own request.")
		}
		if expired, err := s.expireStale(ctx, q, r); err != nil || expired {
			if err != nil {
				return err
			}
			return errCommitted{conflict("request_expired", "The request waited more than 24 hours and expired.")}
		}
		now := s.now().UTC()
		p := stateOf(r)
		p.ApproverMembershipID = &a.MembershipID
		action := ActionReject
		if approve {
			p.Status, p.ApprovedAt, action = StatusApproved, &now, ActionApprove
		} else {
			p.Status = StatusRejected
		}
		row, err := q.SetEnrollmentRequestState(ctx, p)
		if err != nil {
			return err
		}
		if err := audit.Record(ctx, q, audit.Event{Action: action, TenantID: &tenantID, ResourceType: resourceType,
			ResourceID: id.String(), Details: audit.Details{"requested_by": r.RequestedByMembershipID.String(),
				"method": r.Method}}); err != nil {
			return err
		}
		ls, err := loginServerOf(ctx, q, tenantID)
		out = view(row, ls)
		return err
	})
	return out, err
}

// Approve is POST /enrollment/requests/{id}/approve.
func (s *Service) Approve(ctx context.Context, tenantID, id uuid.UUID, a Actor) (Request, error) {
	return s.decide(ctx, tenantID, id, a, true)
}

// Reject is POST /enrollment/requests/{id}/reject.
func (s *Service) Reject(ctx context.Context, tenantID, id uuid.UUID, a Actor) (Request, error) {
	return s.decide(ctx, tenantID, id, a, false)
}

// Start is POST /enrollment/requests/{id}/start: the requester receives the code or the key of its approved request.
func (s *Service) Start(ctx context.Context, tenantID, id uuid.UUID, a Actor) (Issue, error) {
	var out Issue
	err := s.st.WithTenantLock(ctx, tenantID, lockName, lockWait, func(ctx context.Context) error {
		var err error
		out, err = s.start(ctx, tenantID, id, a)
		return err
	})
	if errors.Is(err, store.ErrLockTimeout) {
		return Issue{}, &Error{Code: CodeConflict, Reason: "busy", RetryAfter: 5 * time.Second,
			Detail: "Another enrollment operation of this tenant is in progress; try again."}
	}
	return out, err
}

func (s *Service) start(ctx context.Context, tenantID, id uuid.UUID, a Actor) (Issue, error) {
	var (
		row  sqlcdb.EnrollmentRequest
		tc   tenantContext
		cred *Credential
		kp   keyPlan
		op   audit.Operation
	)
	err := s.inTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		var err error
		r, err := q.LockEnrollmentRequest(ctx, sqlcdb.LockEnrollmentRequestParams{TenantID: tenantID, ID: id})
		if errors.Is(err, store.ErrNoRows) {
			return notFound("no_request")
		}
		if err != nil {
			return err
		}
		if r.RequestedByMembershipID != a.MembershipID {
			return conflict("not_requester", "Only the member who made the request can start it.")
		}
		switch r.Status {
		case StatusApproved:
		case StatusAwaitingDevice, StatusCredentialIssued, StatusClaimed, StatusRegistered, StatusVerified, StatusConsumed:
			return conflict("already_started", "The credential of this request was already issued: it is shown once.")
		default:
			return conflict("not_approved", "Only an approved request can be started.")
		}
		if expired, err := s.expireStale(ctx, q, r); err != nil || expired {
			if err != nil {
				return err
			}
			return errCommitted{conflict("request_expired", "The approval was not used within 24 hours and expired.")}
		}
		if tc, err = loadContext(ctx, q, tenantID); err != nil {
			return err
		}
		if err := checkSelfEnroll(a, tc); err != nil {
			return err
		}
		if r.Method == MethodWebAuth && !tc.settings.Enrollment.WebAuthEnabled {
			return invalid("method", "web_auth_disabled", "This tenant does not accept web-auth enrollment any more.")
		}
		if _, err := usage.EnrollmentTx(ctx, q, tenantID, false, true); err != nil {
			return err
		}
		ev := audit.Event{Action: ActionStart, TenantID: &tenantID, ResourceType: resourceType, ResourceID: id.String(),
			Details: audit.Details{"method": r.Method}}
		if r.Method == MethodWebAuth {
			if row, cred, err = s.issueCode(ctx, q, r, a, tc.loginServer); err != nil {
				return err
			}
			ev.Details["expires_at"] = *row.CredentialExpiresAt
			return audit.Record(ctx, q, ev)
		}
		ttl, err := keyTTL(0, tc.settings)
		if err != nil {
			return err
		}
		kp = keyPlan{ttl: ttl, tags: r.RequestedTags, reusable: r.Reusable, ephemeral: r.Ephemeral}
		if r.TargetMembershipID != nil {
			m, err := loadMember(ctx, q, tenantID, *r.TargetMembershipID, "target_membership_id")
			if err != nil {
				return err
			}
			kp.owner = &m
		}
		row = r
		op, err = audit.Requested(ctx, q, ev)
		return err
	})
	if err != nil {
		return Issue{}, err
	}
	if row.Method == MethodPreauthKey {
		if row, cred, err = s.issueKey(ctx, tenantID, row, kp, tc.loginServer, op); err != nil {
			return Issue{}, err
		}
	}
	return Issue{Request: view(row, tc.loginServer), Credential: cred}, nil
}

// liveKey reports whether a request holds a pre-auth key that may still register a node.
func (s *Service) liveKey(r sqlcdb.EnrollmentRequest) bool {
	if r.HeadscalePreauthkeyID == nil {
		return false
	}
	return r.Status == StatusCredentialIssued ||
		(r.Status == StatusConsumed && r.Reusable && r.CredentialExpiresAt != nil && r.CredentialExpiresAt.After(s.now()))
}

// Revoke is POST /enrollment/requests/{id}/revoke.
func (s *Service) Revoke(ctx context.Context, tenantID, id uuid.UUID, a Actor) (Request, error) {
	var out Request
	err := s.st.WithTenantLock(ctx, tenantID, lockName, lockWait, func(ctx context.Context) error {
		var err error
		out, err = s.revoke(ctx, tenantID, id, a)
		return err
	})
	if errors.Is(err, store.ErrLockTimeout) {
		return Request{}, &Error{Code: CodeConflict, Reason: "busy", RetryAfter: 5 * time.Second,
			Detail: "Another enrollment operation of this tenant is in progress; try again."}
	}
	return out, err
}

func (s *Service) revoke(ctx context.Context, tenantID, id uuid.UUID, a Actor) (Request, error) {
	var (
		out    Request
		base   sqlcdb.EnrollmentRequest // the row the revocation locked first
		op     audit.Operation
		ls     string
		remote bool
	)
	err := s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		r, err := q.LockEnrollmentRequest(ctx, sqlcdb.LockEnrollmentRequestParams{TenantID: tenantID, ID: id})
		if errors.Is(err, store.ErrNoRows) {
			return notFound("no_request")
		}
		if err != nil {
			return err
		}
		if !visible(a, r) {
			return notFound("not_own_resource")
		}
		if ls, err = loginServerOf(ctx, q, tenantID); err != nil {
			return err
		}
		live := s.liveKey(r)
		switch {
		case r.Status == StatusClaimed || r.Status == StatusRegistered:
			return conflict("claim_in_progress", "The device of this request is registering; revoke the device instead.")
		case final(r.Status) && !live:
			return conflict("already_final", "The request already ended; a registered device is revoked with DELETE /devices/{id}.")
		}
		ev := audit.Event{Action: ActionRevoke, TenantID: &tenantID, ResourceType: resourceType, ResourceID: id.String(),
			Details: audit.Details{"status_before": r.Status, "method": r.Method}}
		if live {
			base, remote = r, true
			ev.Details["key_id"] = *r.HeadscalePreauthkeyID
			op, err = audit.Requested(ctx, q, ev)
			return err
		}
		p := stateOf(r)
		p.Status = StatusRevoked
		row, err := q.SetEnrollmentRequestState(ctx, p)
		if err != nil {
			return err
		}
		out = view(row, ls)
		return audit.Record(ctx, q, ev)
	})
	if err != nil || !remote {
		return out, err
	}
	fail := func(err error) (Request, error) {
		e := fromAdapter(err)
		wctx, cancel := detached(ctx)
		defer cancel()
		_ = s.st.WithTenantTx(wctx, tenantID, func(q *sqlcdb.Queries) error { return s.closeOp(wctx, q, &op, failureCode(e)) })
		return Request{}, e
	}
	keyID := *base.HeadscalePreauthkeyID
	got, err := s.expireKey(ctx, tenantID, base)
	if err != nil {
		return fail(err)
	}
	err = s.inTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		r, err := q.LockEnrollmentRequest(ctx, sqlcdb.LockEnrollmentRequestParams{TenantID: tenantID, ID: id})
		if err != nil {
			return err
		}
		// moved while the key was expired (reconcile settled it): a request that ended keeps its state; one that still
		// holds the same live key (a reusable key found used meanwhile) is revoked
		if (r.Status != base.Status || r.Version != base.Version) && (!s.liveKey(r) || *r.HeadscalePreauthkeyID != keyID) {
			if err := s.closeOp(ctx, q, &op, "already_final"); err != nil {
				return err
			}
			return errCommitted{conflict("already_final",
				"The request ended while it was being revoked; a registered device is revoked with DELETE /devices/{id}.")}
		}
		if got.used && !r.Reusable && r.Status == StatusCredentialIssued {
			// the single-use key registered a device before reconcile saw it: the request is never revoked — it stays
			// for reconcile, which settles it consumed with its node (or failed node_gone) as for any used key; the
			// device is revoked through /devices (what a revocation after reconcile answers)
			if err := s.closeOp(ctx, q, &op, "already_final"); err != nil {
				return err
			}
			return errCommitted{conflict("already_final",
				"The key was already used by a device; the device is revoked with DELETE /devices/{id}.")}
		}
		p := stateOf(r)
		p.Status = StatusRevoked
		if n := got.node; n != nil && p.ConsumedNodeID == nil { // a reusable key: the device it registered stays known
			setNode(&p, *n)
		}
		row, err := q.SetEnrollmentRequestState(ctx, p)
		if err != nil {
			return err
		}
		out = view(row, ls)
		return op.Succeeded(ctx, q, audit.Details{"key_id": keyID})
	})
	if err != nil {
		return fail(err)
	}
	return out, nil
}

// keyState is what a revocation found at Headscale for the key of a request.
type keyState struct {
	used bool            // the key registered a node before it was expired
	node *headscale.Node // the first node it registered (nil: none left, or already on the request)
}

// expireKey expires the pre-auth key of request r at Headscale and reads it back (T-17: "đã áp dụng" only after a
// verified read). A used key is reported with its first node.
func (s *Service) expireKey(ctx context.Context, tenantID uuid.UUID, r sqlcdb.EnrollmentRequest) (keyState, error) {
	inst, err := s.reg.ForTenant(ctx, tenantID)
	if err != nil {
		return keyState{}, err
	}
	kid := uint64(*r.HeadscalePreauthkeyID) //nolint:gosec // CHECK headscale_preauthkey_id > 0
	find := func(keys []headscale.PreAuthKey) (headscale.PreAuthKey, bool) {
		for _, k := range keys {
			if k.ID == kid {
				return k, true
			}
		}
		return headscale.PreAuthKey{}, false
	}
	if err := inst.ExpirePreAuthKey(ctx, kid); err != nil && !errors.Is(err, headscale.ErrNotFound) {
		return keyState{}, err
	}
	keys, err := inst.ListPreAuthKeys(ctx)
	if err != nil {
		return keyState{}, err
	}
	k, ok := find(keys)
	if ok && k.Expiration.After(s.now().Add(headscale.ExpiryClampSlack)) {
		return keyState{}, &Error{Code: CodeUpstreamRejected, Reason: "readback_mismatch",
			Detail: "The tenant's control plane did not expire the key."}
	}
	if (ok && !k.Used) || r.ConsumedNodeID != nil { // unused, or its device is already on the request
		return keyState{used: ok && k.Used}, nil
	}
	nodes, err := inst.ListNodes(ctx, "")
	if err != nil {
		return keyState{}, err
	}
	var first *headscale.Node
	for i := range nodes {
		if n := &nodes[i]; n.PreAuthKeyID == kid && (first == nil || n.CreatedAt.Before(first.CreatedAt)) {
			first = n // the first node the key registered (as reconcile)
		}
	}
	return keyState{used: (ok && k.Used) || first != nil, node: first}, nil
}

// setNode records on p the node a pre-auth key registered (the columns reconcile's settle writes).
func setNode(p *sqlcdb.SetEnrollmentRequestStateParams, n headscale.Node) {
	nid := int64(n.ID) //nolint:gosec // small ids
	p.ConsumedNodeID = &nid
	if n.MachineKey != "" {
		mk := clip(n.MachineKey, 200)
		p.RegisteredMachineKey = &mk
	}
	if n.Name != "" {
		h := clip(n.Name, 255)
		p.ReportedHostname = &h
	}
}
