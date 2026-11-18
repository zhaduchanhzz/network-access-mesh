package policies

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// Tag catalog of a tenant (P4-T15 — §6.3 tenant_tags, §7.2 "tagOwners", §8.6 tenant.tag:*, §13.2 "tags"): the only
// tags a policy, a device (PUT /devices/{id}/tags) or an enrollment key (requested_tags — P4-T06) may carry. Every
// change of the catalog — a tag added, its description changed, a tag deleted — enqueues the level-triggered
// policy.apply job (trigger tag_change) in the same transaction: the job renders "tagOwners" from the catalog (empty
// owners) onto the policy the tenant should run. A tag still carried by a device, an enrollment key, a network resource
// or a policy that can still be applied is not deleted (409). Tags the platform manages (platform_managed — router and
// exit, §7.2 autoApprovers) are read-only here (and RESTRICTIVE at the database — 0021).

// Audit actions (x-audit-action of api/openapi.yaml), the job and the resource of the catalog.
const (
	ActionTagCreate = "tag.create"
	ActionTagUpdate = "tag.update"
	ActionTagDelete = "tag.delete"

	resourceTag        = "tag"
	createTagOperation = "createTenantTag"
	tagIdempotencyLock = 30 * time.Second
)

// Tag purposes (CHECK of tenant_tags.purpose). A tenant declares server and custom tags; router and exit are the
// platform's (§7.2: the only tags autoApprovers may name) — created by the platform, never through this API.
const (
	PurposeRouter = "router"
	PurposeExit   = "exit"
	PurposeServer = "server"
	PurposeCustom = "custom"
)

// TagPurposes is the set of tenant_tags.purpose (enum TagPurpose of api/openapi.yaml); TenantTagPurposes the ones a
// tenant may declare.
var (
	TagPurposes       = []string{PurposeRouter, PurposeExit, PurposeServer, PurposeCustom}
	TenantTagPurposes = []string{PurposeServer, PurposeCustom}
)

// Limits of the catalog API.
const (
	MaxTagDescription = 1000 // characters (CHECK of 0021)
	MaxTagsPerRequest = 64   // a device or a key carries at most 64 tags (CHECK of enrollment_requests.requested_tags)
	DefaultTagLimit   = 50
	MaxTagLimit       = 200
)

// Kinds of TagError (errors.Is works through Unwrap).
var (
	ErrTagNotFound              = errors.New("policies: tag not found")
	ErrTagInvalid               = errors.New("policies: invalid tag request")
	ErrTagNotInCatalog          = errors.New("policies: tag not in the tenant's catalog")
	ErrTagConflict              = errors.New("policies: tag conflict")
	ErrTagPreconditionRequired  = errors.New("policies: If-Match required")
	ErrTagPreconditionFailed    = errors.New("policies: If-Match does not match the tag's version")
	ErrTagIdempotencyInProgress = errors.New("policies: a request with this Idempotency-Key is in progress")
	ErrTagIdempotencyKeyReuse   = errors.New("policies: Idempotency-Key used for another request")
)

// TagReferenceCounts are the references that keep a tag from being deleted (409 tag_in_use).
type TagReferenceCounts struct {
	Devices   int64 `json:"devices"`
	Keys      int64 `json:"keys"`
	Resources int64 `json:"resources"`
	Policies  int64 `json:"policies"`
}

func (c TagReferenceCounts) total() int64 { return c.Devices + c.Keys + c.Resources + c.Policies }

// TagError is a refusal of the catalog: Kind is one of the Err… above; Reason a stable code (audit, logs); Field the
// invalid field (ErrTagInvalid, ErrTagNotInCatalog); Tags the names outside the catalog (ErrTagNotInCatalog).
type TagError struct {
	Kind       error
	Reason     string
	Field      string
	Tags       []string
	References *TagReferenceCounts // ErrTagConflict tag_in_use
	RetryAfter time.Duration       // ErrTagIdempotencyInProgress
}

func (e *TagError) Error() string { return e.Kind.Error() + " (" + e.Reason + ")" }
func (e *TagError) Unwrap() error { return e.Kind }

func tagErr(kind error, reason, field string) *TagError {
	return &TagError{Kind: kind, Reason: reason, Field: field}
}

// AsTagError returns the *TagError inside err.
func AsTagError(err error) (*TagError, bool) {
	var e *TagError
	ok := errors.As(err, &e)
	return e, ok
}

// Tag is the API view of a catalog entry (schema Tag).
type Tag struct {
	ID              uuid.UUID `json:"id"`
	Name            string    `json:"name"`
	Purpose         string    `json:"purpose"`
	PlatformManaged bool      `json:"platform_managed"`
	Description     *string   `json:"description,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
	Version         int64     `json:"version"`
}

// ETag is the entity tag of the tag (its version — §6.1): the If-Match of PATCH and DELETE.
func (t Tag) ETag() string { return `"` + strconv.FormatInt(t.Version, 10) + `"` }

func tagView(r sqlcdb.TenantTag) Tag {
	return Tag{ID: r.ID, Name: r.Name, Purpose: r.Purpose, PlatformManaged: r.PlatformManaged, Description: r.Description,
		CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt, Version: r.Version}
}

// TagChange is the outcome of a catalog change: the tag (after the change; the deleted one for a delete) and the
// policy.apply job that renders it (an unfinished job of the tenant is reused — §13.5 dedupe).
type TagChange struct {
	Tag   Tag
	JobID uuid.UUID
}

// TagPage is one page of the catalog.
type TagPage struct {
	Items      []Tag
	NextCursor string
}

// NewTag is the body of POST /tenants/{t}/tags.
type NewTag struct {
	Name        string
	Purpose     string // "" ⇒ custom
	Description *string
}

// TagActor is the caller of a catalog change.
type TagActor struct {
	IdentityID uuid.UUID
}

// Idempotency is the Idempotency-Key of a create request and the SHA-256 of the request (jobs.RequestHash).
type Idempotency struct {
	Key  string
	Hash []byte
}

// TagsConfig are the settings of a TagService.
type TagsConfig struct {
	// Now is the clock of the idempotency bookkeeping; default time.Now.
	Now func() time.Time
}

// TagService is the tag catalog on the api's store (mg_api_tenant: CRUD of tenant_tags, 0021).
type TagService struct {
	st  *store.Store
	now func() time.Time
}

// NewTags returns the catalog service of the process whose store is st (api).
func NewTags(st *store.Store, cfg TagsConfig) (*TagService, error) {
	if st == nil {
		return nil, errors.New("policies: a store is required")
	}
	s := &TagService{st: st, now: cfg.Now}
	if s.now == nil {
		s.now = time.Now
	}
	return s, nil
}

// ---------------------------------------------------------------------------------------------------- read

// List is GET /tenants/{t}/tags: the catalog in its stable order (created_at, id). limit 0 ⇒ DefaultTagLimit; out of
// [1, MaxTagLimit] or a cursor that is not ours ⇒ ErrTagInvalid.
func (s *TagService) List(ctx context.Context, tenantID uuid.UUID, limit int, cursor string) (TagPage, error) {
	switch {
	case limit == 0:
		limit = DefaultTagLimit
	case limit < 1 || limit > MaxTagLimit:
		return TagPage{}, tagErr(ErrTagInvalid, "invalid_limit", "limit")
	}
	after, afterID := time.Unix(0, 0).UTC(), uuid.Nil
	if cursor != "" {
		t, id, ok := decodeTagCursor(cursor)
		if !ok {
			return TagPage{}, tagErr(ErrTagInvalid, "invalid_cursor", "cursor")
		}
		after, afterID = t, id
	}
	page := TagPage{Items: []Tag{}}
	err := s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		rows, err := q.ListTenantTags(ctx, sqlcdb.ListTenantTagsParams{TenantID: tenantID, AfterCreatedAt: after,
			AfterID: afterID, PageLimit: int32(limit + 1)}) //nolint:gosec // limit ≤ MaxTagLimit
		if err != nil {
			return err
		}
		if len(rows) > limit {
			rows = rows[:limit]
			last := rows[limit-1]
			page.NextCursor = encodeTagCursor(last.CreatedAt, last.ID)
		}
		for _, r := range rows {
			page.Items = append(page.Items, tagView(r))
		}
		return nil
	})
	return page, err
}

// Get returns one tag of the catalog (another tenant's reads ErrTagNotFound — §8.4 invariant 6).
func (s *TagService) Get(ctx context.Context, tenantID, id uuid.UUID) (Tag, error) {
	var out Tag
	err := s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		r, err := q.GetTenantTag(ctx, sqlcdb.GetTenantTagParams{TenantID: tenantID, ID: id})
		if errors.Is(err, store.ErrNoRows) {
			return tagErr(ErrTagNotFound, "tag_not_found", "")
		}
		if err != nil {
			return err
		}
		out = tagView(r)
		return nil
	})
	return out, err
}

// ---------------------------------------------------------------------------------------------------- catalog checks

// normalizeTags checks the format of names and returns them sorted without duplicates; none, more than
// MaxTagsPerRequest or a name that is not a tag ⇒ ErrTagInvalid on field.
func normalizeTags(names []string, field string) ([]string, error) {
	if len(names) == 0 {
		return nil, tagErr(ErrTagInvalid, "tags_empty", field)
	}
	if len(names) > MaxTagsPerRequest {
		return nil, tagErr(ErrTagInvalid, "too_many_tags", field)
	}
	for _, n := range names {
		if !ValidTagName(n) {
			return nil, tagErr(ErrTagInvalid, "invalid_tag_name", field)
		}
	}
	out := slices.Clone(names)
	sort.Strings(out)
	return slices.Compact(out), nil
}

// RequireTags checks, in the caller's transaction q (a role of tenant scope), that every name has the format of a tag
// and is in the tenant's catalog — the rule of §6.3 for PUT /devices/{id}/tags and the requested_tags of an
// enrollment request (P4-T06) — then locks the tags the tenant declared FOR SHARE until the transaction ends (a
// concurrent delete waits, then sees the new reference). It returns the names sorted, without duplicates; a name
// outside the catalog ⇒ *TagError ErrTagNotInCatalog (Tags = the missing names), a malformed one ⇒ ErrTagInvalid.
// field names the request field for the 422 (e.g. "tags", "requested_tags").
func RequireTags(ctx context.Context, q *sqlcdb.Queries, tenantID uuid.UUID, names []string, field string) ([]string, error) {
	norm, err := normalizeTags(names, field)
	if err != nil {
		return nil, err
	}
	have, err := q.TenantTagsByName(ctx, sqlcdb.TenantTagsByNameParams{TenantID: tenantID, Names: norm})
	if err != nil {
		return nil, err
	}
	if missing := undeclared(norm, have); len(missing) > 0 {
		return nil, &TagError{Kind: ErrTagNotInCatalog, Reason: "tag_not_in_catalog", Field: field, Tags: missing}
	}
	if _, err := q.LockTenantTagsByName(ctx, sqlcdb.LockTenantTagsByNameParams{TenantID: tenantID, Names: norm}); err != nil {
		return nil, err
	}
	return norm, nil
}

// CheckTags is RequireTags in a transaction of its own (the service interface for modules that may not share a
// transaction with policies — devices: PUT /devices/{id}/tags; enrollment: requested_tags, P4-T06 — wired in apps/).
func (s *TagService) CheckTags(ctx context.Context, tenantID uuid.UUID, names []string, field string) ([]string, error) {
	var out []string
	err := s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		var err error
		out, err = RequireTags(ctx, q, tenantID, names, field)
		return err
	})
	return out, err
}

// ---------------------------------------------------------------------------------------------------- changes

func checkDescription(d *string) (*string, error) {
	if d == nil {
		return nil, nil
	}
	v := strings.TrimSpace(*d)
	switch {
	case v == "":
		return nil, nil
	case !utf8.ValidString(v) || strings.ContainsRune(v, 0) || utf8.RuneCountInString(v) > MaxTagDescription:
		return nil, tagErr(ErrTagInvalid, "invalid_description", "description")
	}
	return &v, nil
}

// text is the audit value of an optional text ("" when absent — audit details take plain values only).
func text(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// enqueueApply enqueues policy.apply (trigger tag_change) in tx — the job is written if and only if the change commits.
func enqueueApply(ctx context.Context, tx *store.Tx, tenantID uuid.UUID, actor TagActor) (uuid.UUID, error) {
	var by *uuid.UUID
	if actor.IdentityID != uuid.Nil {
		id := actor.IdentityID
		by = &id
	}
	e, err := jobs.Enqueue(ctx, tx, jobs.Spec{Kind: KindApply, TenantID: &tenantID,
		Input: ApplyJobInput{Trigger: TriggerTagChange}, RequestedBy: by})
	if err != nil {
		return uuid.Nil, fmt.Errorf("policies: enqueue policy.apply: %w", err)
	}
	return e.Job.ID, nil
}

// Create is POST /tenants/{t}/tags: a tenant tag (purpose server or custom — router and exit are the platform's), name
// unique in the tenant (409), tag.create and policy.apply (tag_change) in one transaction. With an Idempotency-Key, a
// replay of the same request returns the tag the first one created (§13.1).
func (s *TagService) Create(ctx context.Context, tenantID uuid.UUID, actor TagActor, in NewTag, idem *Idempotency) (TagChange, error) {
	if !ValidTagName(in.Name) {
		return TagChange{}, tagErr(ErrTagInvalid, "invalid_tag_name", "name")
	}
	purpose := in.Purpose
	if purpose == "" {
		purpose = PurposeCustom
	}
	switch {
	case !slices.Contains(TagPurposes, purpose):
		return TagChange{}, tagErr(ErrTagInvalid, "invalid_purpose", "purpose")
	case !slices.Contains(TenantTagPurposes, purpose):
		return TagChange{}, tagErr(ErrTagInvalid, "purpose_platform_only", "purpose")
	}
	desc, err := checkDescription(in.Description)
	if err != nil {
		return TagChange{}, err
	}
	var key *jobs.IdempotencyKey
	if idem != nil {
		key = &jobs.IdempotencyKey{TenantID: &tenantID, IdentityID: actor.IdentityID, OperationID: createTagOperation, Key: idem.Key}
		var replay *TagChange
		err := s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
			d, err := jobs.BeginIdempotent(ctx, q, *key, idem.Hash, tagIdempotencyLock)
			if err != nil {
				return err
			}
			switch d.Outcome {
			case jobs.IdempotencyReplay:
				var t Tag
				if d.Response == nil || json.Unmarshal(d.Response.Body, &t) != nil {
					return errors.New("policies: stored tag response unreadable")
				}
				replay = &TagChange{Tag: t}
				// the replay changes nothing, but it is a request like any other: no write without its event
				return audit.Record(ctx, q, audit.Event{Action: ActionTagCreate, TenantID: &tenantID, ResourceType: resourceTag,
					ResourceID: t.ID.String(), Details: audit.Details{"tag_id": t.ID, "name": t.Name, "replay": true}})
			case jobs.IdempotencyInProgress:
				return &TagError{Kind: ErrTagIdempotencyInProgress, Reason: "idempotency_in_progress", RetryAfter: d.RetryAfter}
			case jobs.IdempotencyKeyReuse:
				return tagErr(ErrTagIdempotencyKeyReuse, "idempotency_key_reuse", "")
			}
			return nil
		})
		if err != nil {
			return TagChange{}, err
		}
		if replay != nil {
			return *replay, nil
		}
	}
	var out TagChange
	err = s.st.WithTenantJobTx(ctx, tenantID, func(tx *store.Tx) error {
		q := tx.Q
		row, err := q.InsertTenantTag(ctx, sqlcdb.InsertTenantTagParams{TenantID: tenantID, Name: in.Name, Purpose: purpose,
			Description: desc})
		if err != nil {
			if store.SQLState(err) == "23505" {
				return tagErr(ErrTagConflict, "tag_exists", "name")
			}
			return err
		}
		jobID, err := enqueueApply(ctx, tx, tenantID, actor)
		if err != nil {
			return err
		}
		if err := audit.Record(ctx, q, audit.Event{Action: ActionTagCreate, TenantID: &tenantID, ResourceType: resourceTag,
			ResourceID: row.ID.String(), Details: audit.Details{"tag_id": row.ID, "name": row.Name, "purpose": row.Purpose,
				"description": text(row.Description), "policy_apply_job_id": jobID}}); err != nil {
			return err
		}
		out = TagChange{Tag: tagView(row), JobID: jobID}
		if key != nil {
			body, err := json.Marshal(out.Tag)
			if err != nil {
				return err
			}
			return jobs.CompleteIdempotent(ctx, q, *key, idem.Hash, jobs.StoredResponse{Status: 201, Body: body,
				Resource: &jobs.Resource{Type: resourceTag, ID: row.ID.String()}})
		}
		return nil
	})
	if err != nil {
		if key != nil {
			_ = s.st.WithTenantTx(context.WithoutCancel(ctx), tenantID, func(q *sqlcdb.Queries) error {
				return jobs.FailIdempotent(ctx, q, *key, idem.Hash)
			})
		}
		return TagChange{}, err
	}
	return out, nil
}

// lockForChange reads the tag, refuses a platform tag (409 — read-only through this API, RESTRICTIVE at the database),
// checks If-Match (required ⇒ "" is 428; a stale one 412) and locks the row.
func lockForChange(ctx context.Context, q *sqlcdb.Queries, tenantID, id uuid.UUID, ifMatch string, required bool) (sqlcdb.TenantTag, error) {
	r, err := q.GetTenantTag(ctx, sqlcdb.GetTenantTagParams{TenantID: tenantID, ID: id})
	if errors.Is(err, store.ErrNoRows) {
		return r, tagErr(ErrTagNotFound, "tag_not_found", "")
	}
	if err != nil {
		return r, err
	}
	if r.PlatformManaged {
		return r, tagErr(ErrTagConflict, "tag_platform_managed", "")
	}
	r, err = q.LockTenantTag(ctx, sqlcdb.LockTenantTagParams{TenantID: tenantID, ID: id})
	if errors.Is(err, store.ErrNoRows) {
		return r, tagErr(ErrTagNotFound, "tag_not_found", "")
	}
	if err != nil {
		return r, err
	}
	m := strings.TrimSpace(ifMatch)
	switch {
	case m == "" || m == "*":
		if required {
			return r, tagErr(ErrTagPreconditionRequired, "if_match_required", "")
		}
	case m != tagView(r).ETag():
		return r, tagErr(ErrTagPreconditionFailed, "stale_etag", "")
	}
	return r, nil
}

// Update is PATCH /tenants/{t}/tags/{id}: the description only (name and purpose never change — a device on Headscale
// carries the name). If-Match = the tag's ETag is required. tag.update and policy.apply (tag_change) in one
// transaction.
func (s *TagService) Update(ctx context.Context, tenantID, id uuid.UUID, actor TagActor, ifMatch string, description *string) (TagChange, error) {
	desc, err := checkDescription(description)
	if err != nil {
		return TagChange{}, err
	}
	var out TagChange
	err = s.st.WithTenantJobTx(ctx, tenantID, func(tx *store.Tx) error {
		q := tx.Q
		prev, err := lockForChange(ctx, q, tenantID, id, ifMatch, true)
		if err != nil {
			return err
		}
		row, err := q.UpdateTenantTagDescription(ctx, sqlcdb.UpdateTenantTagDescriptionParams{Description: desc,
			TenantID: tenantID, ID: id})
		if err != nil {
			return err
		}
		jobID, err := enqueueApply(ctx, tx, tenantID, actor)
		if err != nil {
			return err
		}
		if err := audit.Record(ctx, q, audit.Event{Action: ActionTagUpdate, TenantID: &tenantID, ResourceType: resourceTag,
			ResourceID: id.String(), Details: audit.Details{"tag_id": id, "name": row.Name, "previous": text(prev.Description),
				"description": text(row.Description), "version": row.Version, "policy_apply_job_id": jobID}}); err != nil {
			return err
		}
		out = TagChange{Tag: tagView(row), JobID: jobID}
		return nil
	})
	if err != nil {
		return TagChange{}, err
	}
	return out, nil
}

// Delete is DELETE /tenants/{t}/tags/{id}: refused (409 tag_in_use, with the counts) while a live device carries the
// tag, an enrollment request can still issue or use a key with it, a network resource carries it, or a policy that can
// still be applied (a version not superseded or rejected, the desired one, the one applied now) references it outside
// "tagOwners". If-Match is optional (checked when given). tag.delete and policy.apply (tag_change) in one transaction.
func (s *TagService) Delete(ctx context.Context, tenantID, id uuid.UUID, actor TagActor, ifMatch string) (TagChange, error) {
	var out TagChange
	err := s.st.WithTenantJobTx(ctx, tenantID, func(tx *store.Tx) error {
		q := tx.Q
		row, err := lockForChange(ctx, q, tenantID, id, ifMatch, false)
		if err != nil {
			return err
		}
		refs, err := tagReferences(ctx, q, tenantID, row)
		if err != nil {
			return err
		}
		if refs.total() > 0 {
			e := tagErr(ErrTagConflict, "tag_in_use", "")
			e.References = &refs
			return e
		}
		n, err := q.DeleteTenantTag(ctx, sqlcdb.DeleteTenantTagParams{TenantID: tenantID, ID: id})
		if err != nil {
			return err
		}
		if n != 1 {
			return tagErr(ErrTagNotFound, "tag_not_found", "")
		}
		jobID, err := enqueueApply(ctx, tx, tenantID, actor)
		if err != nil {
			return err
		}
		if err := audit.Record(ctx, q, audit.Event{Action: ActionTagDelete, TenantID: &tenantID, ResourceType: resourceTag,
			ResourceID: id.String(), Details: audit.Details{"tag_id": id, "name": row.Name, "purpose": row.Purpose,
				"policy_apply_job_id": jobID}}); err != nil {
			return err
		}
		out = TagChange{Tag: tagView(row), JobID: jobID}
		return nil
	})
	if err != nil {
		return TagChange{}, err
	}
	return out, nil
}

// tagReferences counts what still refers to the tag (the row is locked FOR UPDATE: a concurrent RequireTags waits).
func tagReferences(ctx context.Context, q *sqlcdb.Queries, tenantID uuid.UUID, tag sqlcdb.TenantTag) (TagReferenceCounts, error) {
	var c TagReferenceCounts
	var err error
	if c.Devices, err = q.CountDevicesWithTag(ctx, sqlcdb.CountDevicesWithTagParams{TenantID: tenantID, Name: tag.Name}); err != nil {
		return c, err
	}
	if c.Keys, err = q.CountEnrollmentKeysWithTag(ctx, sqlcdb.CountEnrollmentKeysWithTagParams{TenantID: tenantID, Name: tag.Name}); err != nil {
		return c, err
	}
	if c.Resources, err = q.CountResourcesWithTag(ctx, sqlcdb.CountResourcesWithTagParams{TenantID: tenantID, Name: tag.Name}); err != nil {
		return c, err
	}
	rows, err := q.ListReferencingPolicyContents(ctx, tenantID)
	if err != nil {
		return c, err
	}
	for _, r := range rows {
		if policyReferences(r, tag) {
			c.Policies++
		}
	}
	return c, nil
}

// policyReferences reports whether one policy content refers to the tag outside "tagOwners": a HuJSON version (linted,
// then scanned — a text the lint refuses is scanned conservatively for the name), the typed source of P4-T10 (any string
// equal to the tag's ID or a reference to its name), or an applied document.
func policyReferences(r sqlcdb.ListReferencingPolicyContentsRow, tag sqlcdb.TenantTag) bool {
	scan := func(applied string) bool {
		refs, err := TagReferences(applied)
		if err != nil {
			return strings.Contains(applied, `"`+tag.Name)
		}
		_, found := slices.BinarySearch(refs, tag.Name)
		return found
	}
	switch {
	case r.AppliedHujson != nil:
		return scan(*r.AppliedHujson)
	case r.SourceHujson != nil:
		doc, err := Lint(*r.SourceHujson)
		if err != nil {
			return strings.Contains(*r.SourceHujson, `"`+tag.Name)
		}
		return scan(doc.Applied)
	case len(r.Source) > 0:
		var v any
		if json.Unmarshal(r.Source, &v) != nil {
			return true // unreadable typed source: keep the tag
		}
		return typedReferences(v, tag)
	}
	return false
}

// typedReferences walks a typed PolicySource (§13.3 — principals {type: tag, tag_id}): a string equal to the tag's ID,
// or a tag reference to its name.
func typedReferences(v any, tag sqlcdb.TenantTag) bool {
	switch t := v.(type) {
	case map[string]any:
		for k, x := range t {
			if k == tagOwnersKey {
				continue
			}
			if typedReferences(x, tag) {
				return true
			}
		}
	case []any:
		for _, x := range t {
			if typedReferences(x, tag) {
				return true
			}
		}
	case string:
		if t == tag.ID.String() {
			return true
		}
		if name, ok := tagOf(t); ok && name == tag.Name {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------------------------------- cursor

// tagCursorVersion prefixes the opaque cursor: version | created_at (µs) | id.
const tagCursorVersion = 1

func encodeTagCursor(t time.Time, id uuid.UUID) string {
	b := make([]byte, 0, 1+8+16)
	b = append(b, tagCursorVersion)
	b = binary.BigEndian.AppendUint64(b, uint64(t.UnixMicro())) //nolint:gosec // timestamps after 1970
	b = append(b, id[:]...)
	return base64.RawURLEncoding.EncodeToString(b)
}

func decodeTagCursor(s string) (time.Time, uuid.UUID, bool) {
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil || len(b) != 1+8+16 || b[0] != tagCursorVersion {
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

// Validation describes a refusal that is the caller's input (422 validation_failed): the field, the reason and the
// names outside the catalog — ok is false for any other refusal. Modules that only know the catalog through an
// interface (devices, enrollment — §13.6) read it with errors.As on interface{ Validation() (…) }.
func (e *TagError) Validation() (field, reason string, tags []string, ok bool) {
	if errors.Is(e.Kind, ErrTagInvalid) || errors.Is(e.Kind, ErrTagNotInCatalog) {
		return e.Field, e.Reason, e.Tags, true
	}
	return "", "", nil, false
}
