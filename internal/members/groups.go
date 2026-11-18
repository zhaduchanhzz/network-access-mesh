package members

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// Limits of the groups.
const (
	MaxGroupMembers   = 1000 // one PUT /groups/{id}/members (and one approval payload — 8 KiB canonical: ~200 ids)
	MaxApprovalMember = 200
	maxDescription    = 1000 // CHECK of 0021
	DefaultLimit      = 50
	MaxLimit          = 200
	createOperation   = "createTenantGroup"
	idempotencyLock   = 30 * time.Second
)

var groupNameRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,49}$`) // CHECK of 0021: renders as group:<name> (§7.2)

// Group is the API view of a group (schema Group).
type Group struct {
	ID          uuid.UUID     `json:"id"`
	TenantID    uuid.UUID     `json:"tenant_id"`
	Name        string        `json:"name"`
	Description string        `json:"description,omitempty"`
	Source      string        `json:"source"`
	Sensitive   bool          `json:"sensitive"`
	MemberCount int           `json:"member_count"`
	Members     []GroupMember `json:"members,omitempty"` // GET /groups/{id}, PUT …/members only
	Version     int64         `json:"version"`
	CreatedAt   time.Time     `json:"created_at"`
	UpdatedAt   time.Time     `json:"updated_at"`
}

// GroupMember is one member of a group with its identity.
type GroupMember struct {
	MembershipID uuid.UUID `json:"membership_id"`
	DisplayName  string    `json:"display_name"`
	Email        string    `json:"email,omitempty"`
	Role         string    `json:"role"`
	Status       string    `json:"status"`
}

// GroupPage is one page of groups.
type GroupPage struct {
	Items      []Group
	NextCursor string
}

// GroupFilter holds the query parameters of GET /tenants/{t}/groups.
type GroupFilter struct {
	Limit  int
	Cursor string
	Query  string // part of the name
}

// NewGroup is the body of POST /groups.
type NewGroup struct {
	Name        string
	Description string
}

// GroupPatch is the body of PATCH /groups/{id}: nil fields are unchanged; an empty description clears it.
type GroupPatch struct {
	Name        *string
	Description *string
}

// Idempotency is the Idempotency-Key of POST /groups and the SHA-256 of the request (jobs.RequestHash).
type Idempotency struct {
	Key  string
	Hash []byte
}

// GroupMembersPayload is the payload of an approval request tenant.group.set_members (the exact member set the
// approver sees and the executor applies — P3-T04a canonical JSON).
type GroupMembersPayload struct {
	GroupID       uuid.UUID   `json:"group_id"`
	MembershipIDs []uuid.UUID `json:"membership_ids"`
}

// Validate implements approvals.Validator: a group, sorted distinct members, at most MaxApprovalMember.
func (p GroupMembersPayload) Validate() error {
	switch {
	case p.GroupID == uuid.Nil:
		return errors.New("group_id required")
	case p.MembershipIDs == nil:
		return errors.New("membership_ids required (an empty list removes every member)")
	case len(p.MembershipIDs) > MaxApprovalMember:
		return fmt.Errorf("at most %d members in one approval", MaxApprovalMember)
	}
	for i, id := range p.MembershipIDs {
		if id == uuid.Nil || i > 0 && bytes.Compare(p.MembershipIDs[i-1][:], id[:]) >= 0 {
			return errors.New("membership_ids must be distinct and sorted")
		}
	}
	return nil
}

// SetMembersResult is the answer to PUT /groups/{id}/members: the group as changed (Group set), or — for a sensitive
// group — the payload of the approval request the caller must make (Approval set, nothing changed).
type SetMembersResult struct {
	Group    *Group
	Approval *GroupMembersPayload
	// PolicyJob is the policy.apply job that carries the change (nil when the member set did not change).
	PolicyJob *uuid.UUID
}

func groupEvent(tenantID, id uuid.UUID, action string, d audit.Details) audit.Event {
	t := tenantID
	return audit.Event{Action: action, TenantID: &t, ResourceType: "group", ResourceID: id.String(), Details: d}
}

// sensitiveGroups reads TenantSettings.policy.sensitive_groups (§13.3): group ids; anything else is ignored.
func sensitiveGroups(ctx context.Context, q *sqlcdb.Queries, tenantID uuid.UUID) (map[uuid.UUID]bool, error) {
	raw, err := q.GetTenantSensitiveGroups(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	var list []any
	out := map[uuid.UUID]bool{}
	if json.Unmarshal(raw, &list) != nil {
		return out, nil
	}
	for _, v := range list {
		if s, ok := v.(string); ok {
			if id, err := uuid.Parse(s); err == nil {
				out[id] = true
			}
		}
	}
	return out, nil
}

func groupView(g sqlcdb.Group, sensitive map[uuid.UUID]bool, count int) Group {
	out := Group{ID: g.ID, TenantID: g.TenantID, Name: g.Name, Source: g.Source, Sensitive: sensitive[g.ID],
		MemberCount: count, Version: g.Version, CreatedAt: g.CreatedAt.UTC(), UpdatedAt: g.UpdatedAt.UTC()}
	if g.Description != nil {
		out.Description = *g.Description
	}
	return out
}

func memberView(r sqlcdb.ListGroupMembersRow) GroupMember {
	m := GroupMember{MembershipID: r.MembershipID, Role: r.RoleKey, Status: r.Status}
	if r.Email != nil {
		m.Email = *r.Email
	}
	switch {
	case r.DisplayName != nil && strings.TrimSpace(*r.DisplayName) != "":
		m.DisplayName = *r.DisplayName
	case m.Email != "":
		m.DisplayName = m.Email
	default:
		m.DisplayName = r.Subject
	}
	return m
}

// loadGroup reads a group with its members and sensitivity (q: a transaction of the tenant).
func loadGroup(ctx context.Context, q *sqlcdb.Queries, tenantID uuid.UUID, g sqlcdb.Group) (Group, error) {
	sens, err := sensitiveGroups(ctx, q, tenantID)
	if err != nil {
		return Group{}, err
	}
	rows, err := q.ListGroupMembers(ctx, sqlcdb.ListGroupMembersParams{TenantID: tenantID, GroupID: g.ID})
	if err != nil {
		return Group{}, err
	}
	out := groupView(g, sens, len(rows))
	out.Members = make([]GroupMember, 0, len(rows))
	for _, r := range rows {
		out.Members = append(out.Members, memberView(r))
	}
	return out, nil
}

func checkName(name string) error {
	if !groupNameRE.MatchString(name) {
		return invalid("name", "invalid_name")
	}
	return nil
}

func description(s string) (*string, error) {
	s = strings.TrimSpace(s)
	if !utf8.ValidString(s) || utf8.RuneCountInString(s) > maxDescription {
		return nil, invalid("description", "invalid_description")
	}
	if s == "" {
		return nil, nil
	}
	return &s, nil
}

// ListGroups is GET /tenants/{t}/groups.
func (s *Service) ListGroups(ctx context.Context, tenantID uuid.UUID, f GroupFilter) (GroupPage, error) {
	limit := f.Limit
	if limit == 0 {
		limit = DefaultLimit
	}
	if limit < 1 || limit > MaxLimit {
		return GroupPage{}, invalid("limit", "invalid_limit")
	}
	p := sqlcdb.ListGroupsPageParams{TenantID: tenantID, RowLimit: int32(limit + 1)} //nolint:gosec // ≤ MaxLimit+1
	if f.Cursor != "" {
		t, id, ok := decodeCursor(f.Cursor)
		if !ok {
			return GroupPage{}, invalid("cursor", "invalid_cursor")
		}
		p.AfterCreatedAt, p.AfterID = &t, &id
	}
	if f.Query != "" {
		if utf8.RuneCountInString(f.Query) > 64 {
			return GroupPage{}, invalid("q", "invalid_query")
		}
		pat := "%" + strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(f.Query) + "%"
		p.Pattern = &pat
	}
	page := GroupPage{Items: []Group{}}
	err := s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		sens, err := sensitiveGroups(ctx, q, tenantID)
		if err != nil {
			return err
		}
		rows, err := q.ListGroupsPage(ctx, p)
		if err != nil {
			return err
		}
		for i, r := range rows {
			if i == limit {
				last := page.Items[limit-1]
				page.NextCursor = encodeCursor(last.CreatedAt, last.ID)
				break
			}
			if r.Group.TenantID != tenantID {
				return fmt.Errorf("members: group %s of another tenant in the page of %s", r.Group.ID, tenantID)
			}
			page.Items = append(page.Items, groupView(r.Group, sens, int(r.MemberCount)))
		}
		return nil
	})
	return page, err
}

// GetGroup is GET /tenants/{t}/groups/{id}: with its members (another tenant's group ⇒ ErrNotFound).
func (s *Service) GetGroup(ctx context.Context, tenantID, id uuid.UUID) (Group, error) {
	var out Group
	err := s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		g, err := q.GetGroup(ctx, sqlcdb.GetGroupParams{TenantID: tenantID, ID: id})
		if errors.Is(err, store.ErrNoRows) {
			return refuse(ErrNotFound, ReasonGroupNotFound)
		}
		if err != nil {
			return err
		}
		out, err = loadGroup(ctx, q, tenantID, g)
		return err
	})
	return out, err
}

// CreateGroup is POST /tenants/{t}/groups (Idempotency-Key: a replay answers the group the first request created). A
// new group has no member: nothing renders differently, no policy.apply.
func (s *Service) CreateGroup(ctx context.Context, tenantID uuid.UUID, a Actor, in NewGroup, idem *Idempotency) (Group, error) {
	if err := checkName(in.Name); err != nil {
		return Group{}, err
	}
	desc, err := description(in.Description)
	if err != nil {
		return Group{}, err
	}
	var key *jobs.IdempotencyKey
	if idem != nil {
		key = &jobs.IdempotencyKey{TenantID: &tenantID, IdentityID: a.IdentityID, OperationID: createOperation, Key: idem.Key}
		var replay *Group
		err := s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
			d, err := jobs.BeginIdempotent(ctx, q, *key, idem.Hash, idempotencyLock)
			if errors.Is(err, jobs.ErrInvalidIdempotencyKey) {
				return invalid("Idempotency-Key", "invalid_idempotency_key")
			}
			if err != nil {
				return err
			}
			switch d.Outcome {
			case jobs.IdempotencyReplay:
				var g Group
				if d.Response == nil || json.Unmarshal(d.Response.Body, &g) != nil {
					return errors.New("members: stored group response unreadable")
				}
				replay = &g
				return audit.Record(ctx, q, groupEvent(tenantID, g.ID, ActionGroupCreate, audit.Details{"replay": true}))
			case jobs.IdempotencyInProgress:
				return &Error{Kind: ErrIdempotencyInProgress, Reason: "idempotency_in_progress", RetryAfter: d.RetryAfter}
			case jobs.IdempotencyKeyReuse:
				return refuse(ErrIdempotencyKeyReuse, "idempotency_key_reuse")
			}
			return nil
		})
		if err != nil {
			return Group{}, err
		}
		if replay != nil {
			return *replay, nil
		}
	}
	var out Group
	err = s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		g, err := q.InsertGroup(ctx, sqlcdb.InsertGroupParams{TenantID: tenantID, Name: in.Name, Description: desc})
		if store.SQLState(err) == "23505" {
			return refuse(ErrConflict, ReasonGroupNameTaken)
		}
		if err != nil {
			return err
		}
		if err := audit.Record(ctx, q, groupEvent(tenantID, g.ID, ActionGroupCreate, audit.Details{"name": g.Name})); err != nil {
			return err
		}
		out = groupView(g, nil, 0)
		out.Members = []GroupMember{}
		if key != nil {
			body, err := json.Marshal(out)
			if err != nil {
				return err
			}
			return jobs.CompleteIdempotent(ctx, q, *key, idem.Hash, jobs.StoredResponse{Status: 201, Body: body,
				Resource: &jobs.Resource{Type: "group", ID: g.ID.String()}})
		}
		return nil
	})
	if err != nil {
		if key != nil {
			_ = s.st.WithTenantTx(context.WithoutCancel(ctx), tenantID, func(q *sqlcdb.Queries) error {
				return jobs.FailIdempotent(ctx, q, *key, idem.Hash)
			})
		}
		return Group{}, err
	}
	return out, nil
}

// lockGroup locks a group of the tenant and checks If-Match.
func lockGroup(ctx context.Context, q *sqlcdb.Queries, tenantID, id uuid.UUID, ifMatch string) (sqlcdb.Group, error) {
	g, err := q.LockGroup(ctx, sqlcdb.LockGroupParams{TenantID: tenantID, ID: id})
	if errors.Is(err, store.ErrNoRows) {
		return g, refuse(ErrNotFound, ReasonGroupNotFound)
	}
	if err != nil {
		return g, err
	}
	return g, checkIfMatch(ifMatch, g.Version)
}

// UpdateGroup is PATCH /groups/{id} (If-Match): name and description. A new name renders as another policy key:
// policy.apply (group_change).
func (s *Service) UpdateGroup(ctx context.Context, tenantID, id uuid.UUID, a Actor, ifMatch string, p GroupPatch) (Group, error) {
	if p.Name != nil {
		if err := checkName(*p.Name); err != nil {
			return Group{}, err
		}
	}
	var desc *string
	if p.Description != nil {
		var err error
		if desc, err = description(*p.Description); err != nil {
			return Group{}, err
		}
	}
	var out Group
	err := s.st.WithTenantJobTx(ctx, tenantID, func(tx *store.Tx) error {
		q := tx.Q
		g, err := lockGroup(ctx, q, tenantID, id, ifMatch)
		if err != nil {
			return err
		}
		name := g.Name
		if p.Name != nil {
			name = *p.Name
		}
		if p.Description == nil {
			desc = g.Description
		}
		ng, err := q.UpdateGroup(ctx, sqlcdb.UpdateGroupParams{Name: name, Description: desc, TenantID: tenantID, ID: id})
		if store.SQLState(err) == "23505" {
			return refuse(ErrConflict, ReasonGroupNameTaken)
		}
		if err != nil {
			return err
		}
		d := audit.Details{"name_before": g.Name, "name": ng.Name}
		if ng.Name != g.Name {
			if _, err := enqueuePolicyApply(ctx, tx, tenantID, &a.IdentityID); err != nil {
				return err
			}
			d["policy_apply"] = true
		}
		if err := audit.Record(ctx, q, groupEvent(tenantID, id, ActionGroupUpdate, d)); err != nil {
			return err
		}
		out, err = loadGroup(ctx, q, tenantID, ng)
		return err
	})
	return out, err
}

// DeleteGroup is DELETE /groups/{id} (If-Match). Refused (409) while a network resource names the group as owner, and
// for a sensitive group that still has members (emptying it goes through the approval — §7.3: deleting must not be a
// way around it). A group with members enqueues policy.apply.
func (s *Service) DeleteGroup(ctx context.Context, tenantID, id uuid.UUID, a Actor, ifMatch string) error {
	return s.st.WithTenantJobTx(ctx, tenantID, func(tx *store.Tx) error {
		q := tx.Q
		g, err := lockGroup(ctx, q, tenantID, id, ifMatch)
		if err != nil {
			return err
		}
		n, err := q.CountGroupResources(ctx, sqlcdb.CountGroupResourcesParams{TenantID: tenantID, GroupID: &id})
		if err != nil {
			return err
		}
		if n > 0 {
			return refuse(ErrConflict, ReasonGroupInUse)
		}
		ids, err := q.ListGroupMemberIDs(ctx, sqlcdb.ListGroupMemberIDsParams{TenantID: tenantID, GroupID: id})
		if err != nil {
			return err
		}
		sens, err := sensitiveGroups(ctx, q, tenantID)
		if err != nil {
			return err
		}
		if sens[id] && len(ids) > 0 {
			return refuse(ErrConflict, ReasonSensitiveNotEmpty)
		}
		if _, err := q.DeleteGroup(ctx, sqlcdb.DeleteGroupParams{TenantID: tenantID, ID: id}); err != nil {
			return err
		}
		if len(ids) > 0 {
			if _, err := enqueuePolicyApply(ctx, tx, tenantID, &a.IdentityID); err != nil {
				return err
			}
		}
		return audit.Record(ctx, q, groupEvent(tenantID, id, ActionGroupDelete, audit.Details{"name": g.Name,
			"members": len(ids)}))
	})
}

// normalizeMembers sorts and de-duplicates the requested member set.
func normalizeMembers(ids []uuid.UUID) ([]uuid.UUID, error) {
	if len(ids) > MaxGroupMembers {
		return nil, invalid("membership_ids", ReasonTooManyMembers)
	}
	out := make([]uuid.UUID, 0, len(ids))
	for _, id := range ids {
		if id == uuid.Nil {
			return nil, invalid("membership_ids", "invalid_id")
		}
		out = append(out, id)
	}
	slices.SortFunc(out, func(a, b uuid.UUID) int { return bytes.Compare(a[:], b[:]) })
	return slices.Compact(out), nil
}

// SetGroupMembers is PUT /groups/{id}/members (If-Match): the group's members become exactly ids — active members of
// the tenant (another tenant's membership, an offboarded or locked one ⇒ 422). The change enqueues policy.apply
// (group_change) on the desired version. A sensitive group is not changed here: the result carries the payload of the
// approval request to make (202 + /approvals/{id} — §7.3, §8.6).
func (s *Service) SetGroupMembers(ctx context.Context, tenantID, id uuid.UUID, a Actor, ifMatch string, ids []uuid.UUID) (SetMembersResult, error) {
	want, err := normalizeMembers(ids)
	if err != nil {
		return SetMembersResult{}, err
	}
	var res SetMembersResult
	err = s.st.WithTenantJobTx(ctx, tenantID, func(tx *store.Tx) error {
		g, err := lockGroup(ctx, tx.Q, tenantID, id, ifMatch)
		if err != nil {
			return err
		}
		sens, err := sensitiveGroups(ctx, tx.Q, tenantID)
		if err != nil {
			return err
		}
		if sens[id] {
			if len(want) > MaxApprovalMember {
				return invalid("membership_ids", ReasonTooManyMembers)
			}
			if err := checkActive(ctx, tx.Q, tenantID, want); err != nil {
				return err
			}
			res.Approval = &GroupMembersPayload{GroupID: id, MembershipIDs: want}
			return nil
		}
		job, gv, err := applyMembers(ctx, tx, tenantID, g, want, &a.IdentityID, audit.Details{})
		if err != nil {
			return err
		}
		res.Group, res.PolicyJob = &gv, job
		return nil
	})
	if err != nil {
		return SetMembersResult{}, err
	}
	return res, nil
}

// checkActive refuses a member set that holds a membership that is not an active member of the tenant (FOR SHARE: not
// offboarded meanwhile).
func checkActive(ctx context.Context, q *sqlcdb.Queries, tenantID uuid.UUID, ids []uuid.UUID) error {
	if len(ids) == 0 {
		return nil
	}
	n, err := q.CountActiveMemberships(ctx, sqlcdb.CountActiveMembershipsParams{TenantID: tenantID, Ids: ids})
	if err != nil {
		return err
	}
	if n != int64(len(ids)) {
		return invalid("membership_ids", ReasonMemberNotActive)
	}
	return nil
}

// applyMembers replaces the members of the locked group g by want in tx: when the set changes, the group's version
// grows, policy.apply (group_change) is enqueued and group.members.set is written.
func applyMembers(ctx context.Context, tx *store.Tx, tenantID uuid.UUID, g sqlcdb.Group, want []uuid.UUID, by *uuid.UUID,
	d audit.Details,
) (*uuid.UUID, Group, error) {
	q := tx.Q
	if err := checkActive(ctx, q, tenantID, want); err != nil {
		return nil, Group{}, err
	}
	removed, err := q.DeleteGroupMembersExcept(ctx, sqlcdb.DeleteGroupMembersExceptParams{TenantID: tenantID, GroupID: g.ID,
		Keep: want})
	if err != nil {
		return nil, Group{}, err
	}
	added, err := q.InsertGroupMembers(ctx, sqlcdb.InsertGroupMembersParams{TenantID: tenantID, GroupID: g.ID, Ids: want})
	if err != nil {
		return nil, Group{}, err
	}
	var job *uuid.UUID
	if removed+added > 0 {
		if g, err = q.BumpGroupVersion(ctx, sqlcdb.BumpGroupVersionParams{TenantID: tenantID, ID: g.ID}); err != nil {
			return nil, Group{}, err
		}
		enq, err := enqueuePolicyApply(ctx, tx, tenantID, by)
		if err != nil {
			return nil, Group{}, err
		}
		job = &enq.Job.ID
		d["policy_job_id"] = enq.Job.ID
	}
	d["added"], d["removed"], d["members"] = added, removed, len(want)
	if err := audit.Record(ctx, q, groupEvent(tenantID, g.ID, ActionGroupMembers, d)); err != nil {
		return nil, Group{}, err
	}
	out, err := loadGroup(ctx, q, tenantID, g)
	return job, out, err
}

// ExecuteGroupMembers runs an approved tenant.group.set_members request (the executor of P3-T04a, registered by
// apps/*): in the approval's transaction tx, the exact approved member set replaces the group's members — the group
// must still exist and every member still be active (otherwise nothing changes and the request stays approved). It
// returns the policy.apply job.
func (s *Service) ExecuteGroupMembers(ctx context.Context, tx *store.Tx, tenantID, approvalID uuid.UUID, resourceID string,
	requestedBy uuid.UUID, p GroupMembersPayload,
) (*uuid.UUID, error) {
	if resourceID != p.GroupID.String() {
		return nil, errApprovalPayloadInvalid
	}
	g, err := tx.Q.LockGroup(ctx, sqlcdb.LockGroupParams{TenantID: tenantID, ID: p.GroupID})
	if errors.Is(err, store.ErrNoRows) {
		return nil, refuse(ErrNotFound, ReasonGroupNotFound)
	}
	if err != nil {
		return nil, err
	}
	job, _, err := applyMembers(ctx, tx, tenantID, g, p.MembershipIDs, &requestedBy, audit.Details{
		"approval_id": approvalID, "requested_by_identity_id": requestedBy})
	return job, err
}

// The cursor is opaque to clients: base64url of "<created_at RFC 3339>|<id>" of the last item of the page.
func encodeCursor(t time.Time, id uuid.UUID) string {
	return base64.RawURLEncoding.EncodeToString([]byte(t.UTC().Format(time.RFC3339Nano) + "|" + id.String()))
}

func decodeCursor(s string) (time.Time, uuid.UUID, bool) {
	if len(s) > 512 {
		return time.Time{}, uuid.Nil, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return time.Time{}, uuid.Nil, false
	}
	ts, idStr, ok := strings.Cut(string(raw), "|")
	if !ok {
		return time.Time{}, uuid.Nil, false
	}
	t, err := time.Parse(time.RFC3339Nano, ts)
	if err != nil {
		return time.Time{}, uuid.Nil, false
	}
	id, err := uuid.Parse(idStr)
	if err != nil {
		return time.Time{}, uuid.Nil, false
	}
	return t, id, true
}
