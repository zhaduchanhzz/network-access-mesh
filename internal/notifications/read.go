package notifications

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// Page bounds of GET /tenants/{t}/notifications (§13.1).
const (
	DefaultLimit = 50
	MaxLimit     = 200
)

// Notification is the Portal view of one outbox row addressed to the caller (schema Notification of the API).
type Notification struct {
	ID        uuid.UUID
	Kind      string
	Payload   map[string]any // the kind's fields + tenant_name/tenant_slug/locale (no internal key, no secret)
	CreatedAt time.Time
	ReadAt    *time.Time
}

// ListQuery filters the caller's notifications.
type ListQuery struct {
	Limit  int    // 0 ⇒ DefaultLimit
	Cursor string // next_cursor of the previous page
	Unread *bool  // true: unread only; false: read only
}

// Page is one page of notifications, newest first.
type Page struct {
	Items      []Notification
	NextCursor string
}

// ErrInvalidQuery: limit out of range or a cursor that does not belong to this list.
var ErrInvalidQuery = errors.New("notifications: invalid query")

// Reader answers GET /tenants/{t}/notifications (api process, tenant pool).
type Reader struct{ st *store.Store }

// NewReader returns the reader over the api's store.
func NewReader(st *store.Store) *Reader { return &Reader{st: st} }

// ListMine returns the notifications addressed to membership in tenant — never another member's: the membership comes
// from the caller's authorization decision (own-only for every role — §8.6), the tenant from the path, and RLS keeps
// the read inside the tenant.
func (r *Reader) ListMine(ctx context.Context, tenantID, membershipID uuid.UUID, q ListQuery) (Page, error) {
	if q.Limit == 0 {
		q.Limit = DefaultLimit
	}
	if q.Limit < 1 || q.Limit > MaxLimit {
		return Page{}, fmt.Errorf("%w: limit must be between 1 and %d", ErrInvalidQuery, MaxLimit)
	}
	if membershipID == uuid.Nil {
		return Page{}, errors.New("notifications: the caller has no membership in this tenant")
	}
	p := sqlcdb.ListMyNotificationsPageParams{TenantID: tenantID, MembershipID: membershipID, Unread: q.Unread,
		RowLimit: int32(q.Limit + 1)} //nolint:gosec // 2–201
	if q.Cursor != "" {
		c, ok := decodeCursor(q.Cursor, tenantID, membershipID)
		if !ok {
			return Page{}, fmt.Errorf("%w: the cursor is invalid for this list", ErrInvalidQuery)
		}
		p.AfterCreatedAt, p.AfterID = &c.At, &c.ID
	}
	var rows []sqlcdb.NotificationOutbox
	if err := r.st.WithTenantTx(ctx, tenantID, func(qq *sqlcdb.Queries) error {
		var err error
		rows, err = qq.ListMyNotificationsPage(ctx, p)
		return err
	}); err != nil {
		return Page{}, fmt.Errorf("notifications: list: %w", err)
	}
	page := Page{Items: make([]Notification, 0, min(len(rows), q.Limit))}
	for i, row := range rows {
		if i == q.Limit {
			last := rows[i-1]
			page.NextCursor = encodeCursor(cursor{At: last.CreatedAt, ID: last.ID}, tenantID, membershipID)
			break
		}
		var payload map[string]any
		if err := json.Unmarshal(row.Payload, &payload); err != nil || payload == nil {
			payload = map[string]any{}
		}
		delete(payload, "ref") // internal dedupe key of the producer
		page.Items = append(page.Items, Notification{ID: row.ID, Kind: row.Kind, Payload: payload,
			CreatedAt: row.CreatedAt, ReadAt: row.ReadAt})
	}
	return page, nil
}

// cursor is the position after the last item of a page, bound to the list it came from.
type cursor struct {
	At         time.Time `json:"t"`
	ID         uuid.UUID `json:"i"`
	Tenant     uuid.UUID `json:"x"`
	Membership uuid.UUID `json:"m"`
}

func encodeCursor(c cursor, tenantID, membershipID uuid.UUID) string {
	c.Tenant, c.Membership = tenantID, membershipID
	b, _ := json.Marshal(c)
	return base64.RawURLEncoding.EncodeToString(b)
}

func decodeCursor(s string, tenantID, membershipID uuid.UUID) (cursor, bool) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(b) > 512 {
		return cursor{}, false
	}
	var c cursor
	if json.Unmarshal(b, &c) != nil || c.ID == uuid.Nil || c.At.IsZero() || c.Tenant != tenantID || c.Membership != membershipID {
		return cursor{}, false
	}
	return c, true
}
