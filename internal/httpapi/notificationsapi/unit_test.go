package notificationsapi

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/authz"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/authzhook"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/gen"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/logx"
	"github.com/zhaduchanhzz/network-access-mesh/internal/notifications"
)

type fakeService struct {
	tenants, members []uuid.UUID
	queries          []notifications.ListQuery
	page             notifications.Page
	err              error
}

func (f *fakeService) ListMine(_ context.Context, t, m uuid.UUID, q notifications.ListQuery) (notifications.Page, error) {
	f.tenants, f.members, f.queries = append(f.tenants, t), append(f.members, m), append(f.queries, q)
	return f.page, f.err
}

// fakeAuthorizer answers with a fixed decision, completed with the tenant of the path like authz does.
type fakeAuthorizer struct {
	d           authz.Decision
	wrongTenant bool
}

func (a fakeAuthorizer) RequireOperation(_ context.Context, _ string, tenantID uuid.UUID) (authz.Decision, error) {
	d := a.d
	d.TenantID = tenantID
	if a.wrongTenant {
		d.TenantID = uuid.New()
	}
	return d, nil
}

func noSession(next http.Handler) http.Handler                        { return next }
func noAudit(f gen.StrictHandlerFunc, _ string) gen.StrictHandlerFunc { return f }

func serve(t *testing.T, svc Service, a fakeAuthorizer, path string) *httptest.ResponseRecorder {
	t.Helper()
	h, err := httpapi.New(httpapi.Options{Logger: logx.New(io.Discard, slog.LevelInfo, "api"),
		Handlers: httpapi.Handlers{Notifications: New(svc)},
		Hooks:    httpapi.Hooks{Authz: authzhook.Authz(a), Session: noSession, Audit: noAudit}})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://app.mg.test/api/v1"+path, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

// TestListNotifications: the caller's membership from the decision is the only one asked (whatever the grant scope),
// the tenant of the path is the only tenant, query parameters reach the reader, the items are mapped unchanged.
func TestListNotifications(t *testing.T) {
	tenant, member := uuid.New(), uuid.New()
	read := time.Date(2026, 11, 18, 1, 2, 3, 0, time.UTC)
	svc := &fakeService{page: notifications.Page{NextCursor: "c2", Items: []notifications.Notification{{ID: uuid.New(),
		Kind: "policy.applied", Payload: map[string]any{"version": 2.0, "tenant_slug": "acme"}, CreatedAt: read, ReadAt: &read}}}}
	for _, own := range []bool{true, false} {
		rec := serve(t, svc, fakeAuthorizer{d: authz.Decision{OwnOnly: own, MembershipID: member}},
			"/tenants/"+tenant.String()+"/notifications?limit=5&cursor=c1&unread=true")
		if rec.Code != http.StatusOK {
			t.Fatalf("own=%v: %d %s", own, rec.Code, rec.Body)
		}
		var list gen.NotificationList
		if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil || len(list.Items) != 1 || list.NextCursor == nil ||
			*list.NextCursor != "c2" || list.Items[0].Kind != "policy.applied" || list.Items[0].ReadAt == nil ||
			list.Items[0].Payload["tenant_slug"] != "acme" {
			t.Fatalf("body %s", rec.Body)
		}
	}
	for i := range svc.tenants {
		q := svc.queries[i]
		if svc.tenants[i] != tenant || svc.members[i] != member || q.Limit != 5 || q.Cursor != "c1" || q.Unread == nil || !*q.Unread {
			t.Fatalf("asked %v %v %+v", svc.tenants[i], svc.members[i], q)
		}
	}
}

// TestListNotificationsFailsClosed: no membership in the decision, a decision about another tenant ⇒ 500 and the reader
// is never asked; bad limit / empty cursor / a cursor of another list ⇒ 422.
func TestListNotificationsFailsClosed(t *testing.T) {
	tenant := uuid.New()
	svc := &fakeService{}
	if rec := serve(t, svc, fakeAuthorizer{d: authz.Decision{OwnOnly: true}}, "/tenants/"+tenant.String()+"/notifications"); rec.Code != http.StatusInternalServerError {
		t.Fatalf("no membership: %d", rec.Code)
	}
	if rec := serve(t, svc, fakeAuthorizer{d: authz.Decision{MembershipID: uuid.New()}, wrongTenant: true},
		"/tenants/"+tenant.String()+"/notifications"); rec.Code != http.StatusInternalServerError {
		t.Fatalf("wrong tenant: %d", rec.Code)
	}
	if len(svc.tenants) != 0 {
		t.Fatal("the reader was asked without a valid decision")
	}
	a := fakeAuthorizer{d: authz.Decision{OwnOnly: true, MembershipID: uuid.New()}}
	for _, q := range []string{"limit=0", "limit=201", "cursor="} {
		if rec := serve(t, svc, a, "/tenants/"+tenant.String()+"/notifications?"+q); rec.Code != http.StatusUnprocessableEntity {
			t.Errorf("%s: %d %s", q, rec.Code, rec.Body)
		}
	}
	svc.err = notifications.ErrInvalidQuery
	if rec := serve(t, svc, a, "/tenants/"+tenant.String()+"/notifications?cursor=x"); rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("foreign cursor: %d", rec.Code)
	}
}
