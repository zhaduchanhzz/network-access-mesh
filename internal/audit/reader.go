package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"regexp"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// Page sizes of §13.1 ("?limit=50&cursor=<opaque> (tối đa 200)").
const (
	DefaultLimit = 50
	MaxLimit     = 200
	maxCursorLen = 512 // maxLength of the Cursor parameter in api/openapi.yaml
	maxFilterLen = 128 // maxLength of the action filter
)

// Query selects one page of events: newest first, ordered by (occurred_at, id) — §13.1, filters of §13.2.
type Query struct {
	Limit  int        // 0 = DefaultLimit; otherwise 1–MaxLimit
	Cursor string     // next_cursor of the previous page; "" = first page
	Actor  *uuid.UUID // actor_identity_id
	// ActorType: ActorIdentity, ActorSystem or ActorSupport (P4-T13 — the actions of platform staff under a Support Access
	// Grant, §8.7); "" = any
	ActorType string
	Action    string     // exact action
	Outcome   string     // OutcomeSuccess, OutcomeDenied or OutcomeFailure
	From      *time.Time // occurred_at ≥ From
	To        *time.Time // occurred_at < To
}

// QueryError is an invalid query parameter: the API answers 422 validation_failed naming Field (the message never
// quotes the value).
type QueryError struct {
	Field   string
	Code    string // out_of_range, invalid_format, invalid
	Message string
}

func (e *QueryError) Error() string { return "audit: query " + e.Field + ": " + e.Message }

// Entry is one event as the list endpoints return it (AuditEvent of §13.3): no client address, no target tenant.
type Entry struct {
	ID              uuid.UUID
	OccurredAt      time.Time
	ActorType       string
	ActorIdentityID *uuid.UUID
	ActorDisplay    string
	SupportGrantID  *uuid.UUID
	Action          string
	ResourceType    string
	ResourceID      string
	Outcome         string
	RequestID       string
	OperationID     *uuid.UUID
	Details         map[string]any
}

// Page is one page; NextCursor is "" on the last one.
type Page struct {
	Items      []Entry
	NextCursor string
}

// Reader serves the two list endpoints on the application pools — the RLS of the tenant pool shows one tenant, that of
// the platform pool only platform events — with the scope also written in each query (two layers, §8.8 layers 3–4).
type Reader struct {
	st *store.Store
}

// NewReader returns a Reader on st.
func NewReader(st *store.Store) *Reader { return &Reader{st: st} }

// ListTenant returns a page of the events of tenantID (GET /tenants/{tenantId}/audit): the events of its members and of
// support staff in it — never a denial of another tenant's actor, which is recorded under that actor's tenant (§6.1).
func (r *Reader) ListTenant(ctx context.Context, tenantID uuid.UUID, q Query) (Page, error) {
	c, err := q.compile("tenant", tenantID)
	if err != nil {
		return Page{}, err
	}
	var rows []sqlcdb.AuditEvent
	err = r.st.WithTenantTx(ctx, tenantID, func(qs *sqlcdb.Queries) error {
		var err error
		rows, err = qs.ListTenantAuditEvents(ctx, sqlcdb.ListTenantAuditEventsParams{
			TenantID: tenantID, FromAt: c.from, ToAt: c.to, BeforeAt: c.beforeAt, BeforeID: c.beforeID, Actor: q.Actor,
			ActorType: optional(q.ActorType),
			Action:    optional(q.Action), Outcome: optional(q.Outcome), RowLimit: c.limit + 1,
		})
		return err
	})
	if err != nil {
		return Page{}, fmt.Errorf("audit: list tenant events: %w", err)
	}
	return c.page(rows), nil
}

// ListPlatform returns a page of the platform events (GET /platform/audit): tenant_id NULL only — actions of platform
// staff, their denials (also on tenant routes), platform-level system events (§6.3 "P (sự kiện platform)", §8.5).
func (r *Reader) ListPlatform(ctx context.Context, q Query) (Page, error) {
	c, err := q.compile("platform", uuid.Nil)
	if err != nil {
		return Page{}, err
	}
	var rows []sqlcdb.AuditEvent
	err = r.st.WithPlatformTx(ctx, func(qs *sqlcdb.Queries) error {
		var err error
		rows, err = qs.ListPlatformAuditEvents(ctx, sqlcdb.ListPlatformAuditEventsParams{
			FromAt: c.from, ToAt: c.to, BeforeAt: c.beforeAt, BeforeID: c.beforeID, Actor: q.Actor,
			ActorType: optional(q.ActorType), Action: optional(q.Action), Outcome: optional(q.Outcome), RowLimit: c.limit + 1,
		})
		return err
	})
	if err != nil {
		return Page{}, fmt.Errorf("audit: list platform events: %w", err)
	}
	return c.page(rows), nil
}

// Bounds used when the query sets none: always passing a range keeps one plan with partition pruning and the index
// (tenant_id, occurred_at DESC, id DESC).
var (
	farPast   = time.Date(1, time.January, 1, 0, 0, 0, 0, time.UTC)
	farFuture = time.Date(9999, time.December, 31, 0, 0, 0, 0, time.UTC)
	maxUUID   = uuid.UUID{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	filterRE  = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$`) // pattern of the action filter (spec)
)

// compiled is a validated query.
type compiled struct {
	limit              int32
	from, to, beforeAt time.Time
	beforeID           uuid.UUID
	binding            [8]byte
}

func (q Query) compile(scope string, tenant uuid.UUID) (compiled, error) {
	c := compiled{limit: DefaultLimit, from: farPast, to: farFuture, beforeAt: farFuture, beforeID: maxUUID}
	switch {
	case q.Limit < 0 || q.Limit > MaxLimit:
		return c, &QueryError{"limit", "out_of_range", fmt.Sprintf("must be between 1 and %d", MaxLimit)}
	case q.Limit > 0:
		c.limit = int32(q.Limit) //nolint:gosec // ≤ MaxLimit
	}
	if q.Action != "" && (len(q.Action) > maxFilterLen || !filterRE.MatchString(q.Action)) {
		return c, &QueryError{"action", "invalid_format", "must be a dotted lowercase action"}
	}
	if q.ActorType != "" && q.ActorType != ActorIdentity && q.ActorType != ActorSystem && q.ActorType != ActorSupport {
		return c, &QueryError{"actor_type", "invalid", "must be identity, system or support"}
	}
	if q.Outcome != "" && q.Outcome != OutcomeSuccess && q.Outcome != OutcomeDenied && q.Outcome != OutcomeFailure {
		return c, &QueryError{"outcome", "invalid", "must be success, denied or failure"}
	}
	if q.From != nil {
		c.from = q.From.UTC()
	}
	if q.To != nil {
		c.to = q.To.UTC()
	}
	if !c.from.Before(c.to) {
		return c, &QueryError{"to", "out_of_range", "must be after from"}
	}
	c.binding = cursorBinding(scope, tenant, q)
	if q.Cursor != "" {
		at, id, ok := decodeCursor(q.Cursor, c.binding)
		if !ok {
			return c, &QueryError{"cursor", "invalid", "is not a cursor of this list and filter set"}
		}
		c.beforeAt, c.beforeID = at, id
	}
	return c, nil
}

// page turns limit+1 rows into a page.
func (c compiled) page(rows []sqlcdb.AuditEvent) Page {
	p := Page{Items: make([]Entry, 0, min(len(rows), int(c.limit)))}
	for i, e := range rows {
		if i == int(c.limit) {
			last := rows[i-1]
			p.NextCursor = encodeCursor(last.OccurredAt, last.ID, c.binding)
			break
		}
		p.Items = append(p.Items, entryOf(e))
	}
	return p
}

func entryOf(e sqlcdb.AuditEvent) Entry {
	d := map[string]any{}
	if len(e.Details) > 0 {
		_ = json.Unmarshal(e.Details, &d) // a JSON object by the CHECK of 0004
	}
	return Entry{
		ID: e.ID, OccurredAt: e.OccurredAt.UTC(), ActorType: e.ActorType, ActorIdentityID: e.ActorIdentityID,
		ActorDisplay: deref(e.ActorDisplay), SupportGrantID: e.SupportGrantID, Action: e.Action,
		ResourceType: e.ResourceType, ResourceID: deref(e.ResourceID), Outcome: e.Outcome, RequestID: deref(e.RequestID),
		OperationID: e.OperationID, Details: d,
	}
}

// The cursor is opaque to clients: base64url of version | occurred_at (µs, big endian) | id | binding, where binding is
// the first 8 bytes of SHA-256 over the list (tenant or platform, tenant id) and the filters — a cursor is refused on
// another list or with other filters (the page size may change). Positions are exact: PostgreSQL keeps microseconds.
const cursorVersion byte = 1

const cursorLen = 1 + 8 + 16 + 8

func cursorBinding(scope string, tenant uuid.UUID, q Query) [8]byte {
	actor := ""
	if q.Actor != nil {
		actor = q.Actor.String()
	}
	stamp := func(t *time.Time) string {
		if t == nil {
			return ""
		}
		return fmt.Sprint(t.UnixMicro())
	}
	raw := fmt.Appendf(nil, "mg-audit-cursor/v1|%s|%s|%s|%s|%s|%s|%s", scope, tenant, actor, q.Action,
		q.Outcome, stamp(q.From), stamp(q.To))
	if q.ActorType != "" { // appended only when set: the cursors of the lists without it (P2-T08) stay valid
		raw = fmt.Appendf(raw, "|actor_type=%s", q.ActorType)
	}
	sum := sha256.Sum256(raw)
	var b [8]byte
	copy(b[:], sum[:8])
	return b
}

func encodeCursor(at time.Time, id uuid.UUID, binding [8]byte) string {
	b := make([]byte, 0, cursorLen)
	b = append(b, cursorVersion)
	b = binary.BigEndian.AppendUint64(b, uint64(at.UnixMicro())) //nolint:gosec // events are after 1970
	b = append(b, id[:]...)
	b = append(b, binding[:]...)
	return base64.RawURLEncoding.EncodeToString(b)
}

func decodeCursor(s string, binding [8]byte) (time.Time, uuid.UUID, bool) {
	if len(s) > maxCursorLen {
		return time.Time{}, uuid.Nil, false
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil || len(b) != cursorLen || b[0] != cursorVersion || !bytes.Equal(b[25:], binding[:]) {
		return time.Time{}, uuid.Nil, false
	}
	micros := binary.BigEndian.Uint64(b[1:9])
	if micros > uint64(farFuture.UnixMicro()) {
		return time.Time{}, uuid.Nil, false
	}
	id, err := uuid.FromBytes(b[9:25])
	if err != nil {
		return time.Time{}, uuid.Nil, false
	}
	return time.UnixMicro(int64(micros)).UTC(), id, true //nolint:gosec // bounded above
}
