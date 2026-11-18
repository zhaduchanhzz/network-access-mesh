// Package notificationsapi serves the notification operations of api/openapi.yaml (tag notifications):
// listNotifications — GET /tenants/{tenantId}/notifications, the caller's own Portal notifications (P3-T05b) — and
// markNotificationRead — POST /tenants/{tenantId}/notifications/{notificationId}/read (P4-T04). It only translates
// between the generated types and internal/notifications (Reader.ListMine, Reader.MarkRead), which reads and updates
// notification_outbox in the tenant's scope (RLS); it never imports internal/store (§13.6, internal/archtest).
//
// Defence in depth (§8.6 "chỉ thông báo gửi cho chính mình", T-01) on top of the authorization hook and RLS:
//   - no decision in the context, a decision about another tenant, or a decision without the caller's membership ⇒ 500
//     (fail closed, never data);
//   - the list is ALWAYS restricted to the caller's own membership (tenant.notification:read is own-only for every
//     role), whatever the scope of the grant;
//   - every item returned must be one the service read for that membership of that tenant — the reader filters in SQL;
//     the handler does not widen it;
//   - a notification marked read is always the caller's own: another member's (or another tenant's, or a missing one)
//     is 404 not_found, audited with the reason not_own_resource for another member's (§8.4 invariants 3b and 6).
//
// The two operations belong to two building tasks (x-task), hence two handler interfaces of httpapi; one *Handlers
// implements both. Wiring (apps/internal/runner — api process):
//
//	h := notificationsapi.New(notifications.NewReader(apiStore))
//	api, _ := httpapi.New(httpapi.Options{…, Handlers: httpapi.Handlers{…, Notifications: h, Portal: h}})
package notificationsapi

import (
	"context"
	"errors"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/authz"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/authzhook"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/gen"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/problem"
	"github.com/zhaduchanhzz/network-access-mesh/internal/notifications"
)

// Service is the part of *notifications.Reader the handlers need.
type Service interface {
	ListMine(ctx context.Context, tenantID, membershipID uuid.UUID, q notifications.ListQuery) (notifications.Page, error)
	MarkRead(ctx context.Context, tenantID, membershipID, id uuid.UUID) (notifications.Notification, error)
}

var _ Service = (*notifications.Reader)(nil)

// Handlers implements httpapi.NotificationHandlers (P3-T05b) and httpapi.PortalHandlers (P4-T04).
type Handlers struct{ svc Service }

var (
	_ httpapi.NotificationHandlers = (*Handlers)(nil)
	_ httpapi.PortalHandlers       = (*Handlers)(nil)
)

// New returns the handlers of the notification operations.
func New(svc Service) *Handlers { return &Handlers{svc: svc} }

var (
	// errNoDecision: the handler runs without the authorization hook — fail closed (§8.4 invariant 4).
	errNoDecision = errors.New("notificationsapi: no authorization decision in the request context (Hooks.Authz missing)")
	// errWrongDecision: the decision is not about this tenant, or carries no membership of the caller.
	errWrongDecision = errors.New("notificationsapi: the authorization decision does not cover this request")
)

const invalidQuery = "The query parameters are invalid."

// caller returns the caller's membership in tenant from the authorization decision (fail closed without one).
func caller(ctx context.Context, tenant uuid.UUID) (uuid.UUID, error) {
	d, ok := authzhook.DecisionFrom(ctx)
	switch {
	case !ok:
		return uuid.Nil, problem.Internal(errNoDecision)
	case tenant == uuid.Nil || d.TenantID != tenant || d.MembershipID == uuid.Nil:
		return uuid.Nil, problem.Internal(errWrongDecision)
	}
	return d.MembershipID, nil
}

// notification maps the Portal view to the schema Notification.
func notification(n notifications.Notification) gen.Notification {
	payload := n.Payload
	if payload == nil {
		payload = map[string]any{}
	}
	return gen.Notification{Id: n.ID, Kind: n.Kind, Payload: payload, CreatedAt: n.CreatedAt, ReadAt: n.ReadAt}
}

// ListNotifications implements GET /tenants/{tenantId}/notifications.
func (h *Handlers) ListNotifications(ctx context.Context, req gen.ListNotificationsRequestObject) (gen.ListNotificationsResponseObject, error) {
	member, err := caller(ctx, req.TenantId)
	if err != nil {
		return nil, err
	}
	p := req.Params
	q := notifications.ListQuery{Unread: p.Unread}
	if p.Limit != nil {
		if *p.Limit < 1 || *p.Limit > notifications.MaxLimit {
			return nil, problem.Validation(invalidQuery, problem.Field("limit", "out_of_range", "must be between 1 and 200"))
		}
		q.Limit = *p.Limit
	}
	if p.Cursor != nil {
		if *p.Cursor == "" {
			return nil, problem.Validation(invalidQuery, problem.Field("cursor", "invalid", "not a cursor of this list"))
		}
		q.Cursor = *p.Cursor
	}
	page, err := h.svc.ListMine(ctx, req.TenantId, member, q)
	if errors.Is(err, notifications.ErrInvalidQuery) {
		return nil, problem.Validation(invalidQuery, problem.Field("cursor", "invalid", "not a cursor of this list"))
	}
	if err != nil {
		return nil, problem.Internal(err)
	}
	out := gen.NotificationList{Items: make([]gen.Notification, 0, len(page.Items))}
	for _, n := range page.Items {
		out.Items = append(out.Items, notification(n))
	}
	if page.NextCursor != "" {
		c := page.NextCursor
		out.NextCursor = &c
	}
	return gen.ListNotifications200JSONResponse(out), nil
}

// notFound is the uniform answer for a notification that is not the caller's (§8.4 invariant 6).
const notFound = "The notification was not found."

// MarkNotificationRead implements POST /tenants/{tenantId}/notifications/{notificationId}/read (P4-T04).
func (h *Handlers) MarkNotificationRead(ctx context.Context, req gen.MarkNotificationReadRequestObject) (gen.MarkNotificationReadResponseObject, error) {
	member, err := caller(ctx, req.TenantId)
	if err != nil {
		return nil, err
	}
	n, err := h.svc.MarkRead(ctx, req.TenantId, member, req.NotificationId)
	switch {
	case errors.Is(err, notifications.ErrNotOwnNotification):
		return nil, &problem.Error{Code: gen.ProblemCodeNotFound, Detail: notFound,
			Cause: &authz.Denial{Kind: authz.ErrNotFound, Reason: "not_own_resource"}}
	case errors.Is(err, notifications.ErrNotificationNotFound):
		return nil, &problem.Error{Code: gen.ProblemCodeNotFound, Detail: notFound, Cause: err}
	case err != nil:
		return nil, problem.Internal(err)
	}
	return gen.MarkNotificationRead200JSONResponse(notification(n)), nil
}
