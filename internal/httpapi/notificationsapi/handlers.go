// Package notificationsapi serves the notification operation of api/openapi.yaml (tag notifications, P3-T05b):
// listNotifications — GET /tenants/{tenantId}/notifications, the caller's own Portal notifications. It only translates
// between the generated types and internal/notifications (Reader.ListMine), which reads notification_outbox in the
// tenant's scope (RLS); it never imports internal/store (§13.6, internal/archtest).
//
// Defence in depth (§8.6 "chỉ thông báo gửi cho chính mình", T-01) on top of the authorization hook and RLS:
//   - no decision in the context, a decision about another tenant, or a decision without the caller's membership ⇒ 500
//     (fail closed, never data);
//   - the list is ALWAYS restricted to the caller's own membership (tenant.notification:read is own-only for every
//     role), whatever the scope of the grant;
//   - every item returned must be one the service read for that membership of that tenant — the reader filters in SQL;
//     the handler does not widen it.
//
// Wiring (apps/internal/runner — api process):
//
//	api, _ := httpapi.New(httpapi.Options{…, Handlers: httpapi.Handlers{…,
//		Notifications: notificationsapi.New(notifications.NewReader(apiStore))}})
package notificationsapi

import (
	"context"
	"errors"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/authzhook"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/gen"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/problem"
	"github.com/zhaduchanhzz/network-access-mesh/internal/notifications"
)

// Service is the part of *notifications.Reader the handlers need.
type Service interface {
	ListMine(ctx context.Context, tenantID, membershipID uuid.UUID, q notifications.ListQuery) (notifications.Page, error)
}

var _ Service = (*notifications.Reader)(nil)

// Handlers implements httpapi.NotificationHandlers.
type Handlers struct{ svc Service }

var _ httpapi.NotificationHandlers = (*Handlers)(nil)

// New returns the handlers of the notification operations.
func New(svc Service) *Handlers { return &Handlers{svc: svc} }

var (
	// errNoDecision: the handler runs without the authorization hook — fail closed (§8.4 invariant 4).
	errNoDecision = errors.New("notificationsapi: no authorization decision in the request context (Hooks.Authz missing)")
	// errWrongDecision: the decision is not about this tenant, or carries no membership of the caller.
	errWrongDecision = errors.New("notificationsapi: the authorization decision does not cover this request")
)

const invalidQuery = "The query parameters are invalid."

// ListNotifications implements GET /tenants/{tenantId}/notifications.
func (h *Handlers) ListNotifications(ctx context.Context, req gen.ListNotificationsRequestObject) (gen.ListNotificationsResponseObject, error) {
	d, ok := authzhook.DecisionFrom(ctx)
	switch {
	case !ok:
		return nil, problem.Internal(errNoDecision)
	case req.TenantId == uuid.Nil || d.TenantID != req.TenantId || d.MembershipID == uuid.Nil:
		return nil, problem.Internal(errWrongDecision)
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
	page, err := h.svc.ListMine(ctx, req.TenantId, d.MembershipID, q)
	if errors.Is(err, notifications.ErrInvalidQuery) {
		return nil, problem.Validation(invalidQuery, problem.Field("cursor", "invalid", "not a cursor of this list"))
	}
	if err != nil {
		return nil, problem.Internal(err)
	}
	out := gen.NotificationList{Items: make([]gen.Notification, 0, len(page.Items))}
	for _, n := range page.Items {
		payload := n.Payload
		if payload == nil {
			payload = map[string]any{}
		}
		out.Items = append(out.Items, gen.Notification{Id: n.ID, Kind: n.Kind, Payload: payload, CreatedAt: n.CreatedAt,
			ReadAt: n.ReadAt})
	}
	if page.NextCursor != "" {
		c := page.NextCursor
		out.NextCursor = &c
	}
	return gen.ListNotifications200JSONResponse(out), nil
}
