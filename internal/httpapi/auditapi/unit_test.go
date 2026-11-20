package auditapi

// Tests that need no database: parameter mapping and page mapping of the handlers, the classification and the audit
// scope of the middleware, the identity adapter.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/authz"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/gen"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/problem"
	"github.com/zhaduchanhzz/network-access-mesh/internal/identity"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/requestid"
)

type fakeReader struct {
	q        audit.Query
	tenant   uuid.UUID
	platform bool
	page     audit.Page
	err      error
}

func (f *fakeReader) ListTenant(_ context.Context, tenantID uuid.UUID, q audit.Query) (audit.Page, error) {
	f.tenant, f.q = tenantID, q
	return f.page, f.err
}

func (f *fakeReader) ListPlatform(_ context.Context, q audit.Query) (audit.Page, error) {
	f.platform, f.q = true, q
	return f.page, f.err
}

func TestHandlersMapQueryAndPage(t *testing.T) {
	actor, tenant, op := uuid.New(), uuid.New(), uuid.New()
	at := time.Date(2026, 11, 17, 9, 0, 0, 0, time.UTC)
	fr := &fakeReader{page: audit.Page{NextCursor: "next", Items: []audit.Entry{
		{ID: uuid.New(), OccurredAt: at, ActorType: audit.ActorIdentity, ActorIdentityID: &actor, ActorDisplay: "Alice",
			Action: "device.expire.requested", ResourceType: "device", ResourceID: "d1", Outcome: audit.OutcomeSuccess,
			RequestID: "r1", OperationID: &op, Details: map[string]any{"reason": "x"}},
		{ID: uuid.New(), OccurredAt: at, ActorType: audit.ActorSystem, Action: "device.sync", ResourceType: "device",
			Outcome: audit.OutcomeFailure},
	}}}
	h := New(fr)
	limit, cursor, action, outcome := 7, "c", "device.list", gen.AuditOutcomeDenied
	from, to := at.Add(-time.Hour), at
	resp, err := h.ListTenantAuditEvents(t.Context(), gen.ListTenantAuditEventsRequestObject{TenantId: tenant,
		Params: gen.ListTenantAuditEventsParams{Limit: &limit, Cursor: &cursor, Actor: &actor, Action: &action,
			Outcome: &outcome, From: &from, To: &to}})
	if err != nil {
		t.Fatal(err)
	}
	want := audit.Query{Limit: 7, Cursor: "c", Actor: &actor, Action: "device.list", Outcome: "denied", From: &from, To: &to}
	if fr.tenant != tenant || fr.q.Limit != want.Limit || fr.q.Cursor != want.Cursor || *fr.q.Actor != actor ||
		fr.q.Action != want.Action || fr.q.Outcome != want.Outcome || !fr.q.From.Equal(from) || !fr.q.To.Equal(to) {
		t.Errorf("query %+v for tenant %s, want %+v for %s", fr.q, fr.tenant, want, tenant)
	}
	list, ok := resp.(gen.ListTenantAuditEvents200JSONResponse)
	if !ok || len(list.Items) != 2 || list.NextCursor == nil || *list.NextCursor != "next" {
		t.Fatalf("response %#v", resp)
	}
	e0, e1 := list.Items[0], list.Items[1]
	if e0.Actor.DisplayName == nil || *e0.Actor.DisplayName != "Alice" || *e0.Actor.IdentityId != actor ||
		e0.Resource.Type != "device" || e0.Resource.Id != "d1" || *e0.OperationId != op || e0.Details["reason"] != "x" ||
		e0.Outcome != gen.AuditOutcomeSuccess || e0.RequestId != "r1" {
		t.Errorf("first item %+v", e0)
	}
	if e1.Actor.DisplayName != nil || e1.Actor.IdentityId != nil || e1.Details == nil || e1.Actor.Type != gen.AuditActorTypeSystem {
		t.Errorf("second item %+v: no display name, no identity, details {}", e1)
	}

	fr.page = audit.Page{}
	presp, err := h.ListPlatformAuditEvents(t.Context(), gen.ListPlatformAuditEventsRequestObject{})
	if err != nil || !fr.platform || fr.q.Limit != 0 {
		t.Fatalf("platform list: %v, called %v, query %+v", err, fr.platform, fr.q)
	}
	if pl := presp.(gen.ListPlatformAuditEvents200JSONResponse); pl.Items == nil || len(pl.Items) != 0 || pl.NextCursor != nil {
		t.Errorf("empty platform page %+v: items [] and next_cursor null", pl)
	}
}

// TestActorKindNameAndEmail — G4b-E13: one name per person (the identity's current name, else the snapshot; e-mail
// apart) and a stable kind per actor so that the Portal labels system actors in the reader's language.
func TestActorKindNameAndEmail(t *testing.T) {
	alice, staff := uuid.New(), uuid.New()
	at := time.Date(2026, 11, 20, 9, 0, 0, 0, time.UTC)
	entry := func(e audit.Entry) audit.Entry {
		e.ID, e.OccurredAt, e.Action, e.ResourceType, e.Outcome = uuid.New(), at, "x.y", "z", audit.OutcomeSuccess
		return e
	}
	fr := &fakeReader{page: audit.Page{Items: []audit.Entry{
		// auth.login: no snapshot, the identity's current name and e-mail
		entry(audit.Entry{ActorType: audit.ActorIdentity, ActorIdentityID: &alice, ActorName: "Alice", ActorEmail: "alice@a.test"}),
		// invitation.accept recorded the e-mail as the snapshot: the current name wins
		entry(audit.Entry{ActorType: audit.ActorIdentity, ActorIdentityID: &alice, ActorDisplay: "alice@a.test", ActorName: "Alice", ActorEmail: "alice@a.test"}),
		// an identity the scope cannot read: the snapshot
		entry(audit.Entry{ActorType: audit.ActorSupport, ActorIdentityID: &staff, ActorDisplay: "Staff One"}),
		entry(audit.Entry{ActorType: audit.ActorSystem, ActorDisplay: "Keycloak administrator (master realm)"}),
		entry(audit.Entry{ActorType: audit.ActorSystem, ActorDisplay: "Keycloak master: admin"}),
		entry(audit.Entry{ActorType: audit.ActorSystem, ActorDisplay: "IdP provisioning identity (platform)",
			Details: map[string]any{"idp_actor_kind": "idp_driver"}}),
		entry(audit.Entry{ActorType: audit.ActorSystem, ActorDisplay: "member.idp_invite"}),
		entry(audit.Entry{ActorType: audit.ActorSystem, ActorDisplay: "meshguard admin seed-membership"}),
		entry(audit.Entry{ActorType: audit.ActorSystem}),
	}}}
	resp, err := New(fr).ListTenantAuditEvents(t.Context(), gen.ListTenantAuditEventsRequestObject{TenantId: uuid.New()})
	if err != nil {
		t.Fatal(err)
	}
	items := resp.(gen.ListTenantAuditEvents200JSONResponse).Items
	want := []struct{ kind, name, email string }{
		{"user", "Alice", "alice@a.test"}, {"user", "Alice", "alice@a.test"}, {"support", "Staff One", ""},
		{"idp_admin", "Keycloak administrator (master realm)", ""}, {"idp_admin", "Keycloak master: admin", ""},
		{"idp_driver", "IdP provisioning identity (platform)", ""}, {"job", "member.idp_invite", ""},
		{"admin_command", "meshguard admin seed-membership", ""}, {"system", "", ""},
	}
	str := func(p *string) string {
		if p == nil {
			return ""
		}
		return *p
	}
	for i, w := range want {
		a := items[i].Actor
		if str(a.Kind) != w.kind || str(a.DisplayName) != w.name || str(a.Email) != w.email {
			t.Errorf("item %d: kind %q name %q email %q, want %+v", i, str(a.Kind), str(a.DisplayName), str(a.Email), w)
		}
	}
}

func TestHandlersRefuseBadParameters(t *testing.T) {
	fr := &fakeReader{}
	h := New(fr)
	field := func(err error) string {
		var p *problem.Error
		if !errors.As(err, &p) || p.Code != gen.ProblemCodeValidationFailed || len(p.Fields) != 1 {
			return "not a validation problem: " + errFmt(err)
		}
		return p.Fields[0].Field
	}
	for _, v := range []int{0, -1, 201} {
		_, err := h.ListTenantAuditEvents(t.Context(), gen.ListTenantAuditEventsRequestObject{
			Params: gen.ListTenantAuditEventsParams{Limit: &v}})
		if f := field(err); f != "limit" {
			t.Errorf("limit %d: %s", v, f)
		}
	}
	bad := gen.AuditOutcome("maybe")
	if _, err := h.ListPlatformAuditEvents(t.Context(), gen.ListPlatformAuditEventsRequestObject{
		Params: gen.ListPlatformAuditEventsParams{Outcome: &bad}}); field(err) != "outcome" {
		t.Errorf("outcome maybe: %v", err)
	}
	fr.err = &audit.QueryError{Field: "cursor", Code: "invalid", Message: "is not a cursor of this list and filter set"}
	if _, err := h.ListPlatformAuditEvents(t.Context(), gen.ListPlatformAuditEventsRequestObject{}); field(err) != "cursor" {
		t.Errorf("reader query error: %v", err)
	}
	fr.err = errors.New("database is down")
	_, err := h.ListTenantAuditEvents(t.Context(), gen.ListTenantAuditEventsRequestObject{})
	var p *problem.Error
	if !errors.As(err, &p) || p.Code != gen.ProblemCodeInternalError || p.Detail == "" || p.Cause == nil {
		t.Errorf("reader failure: %v, want internal_error with the cause kept for the log", err)
	}
}

func errFmt(err error) string {
	if err == nil {
		return "<nil>"
	}
	return err.Error()
}

// fakeFinisher records the Finish calls.
type fakeFinisher struct {
	mu    sync.Mutex
	calls []finishCall
}

type finishCall struct {
	req *audit.Request
	res audit.Result
}

func (f *fakeFinisher) Finish(_ context.Context, r *audit.Request, res audit.Result) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, finishCall{r, res})
}

func denial(code gen.ProblemCode, kind error, reason string) error {
	return &problem.Error{Code: code, Detail: "x", Cause: &authz.Denial{Kind: kind, Reason: reason}}
}

func TestMiddlewareClassifies(t *testing.T) {
	tenant, device := uuid.New(), uuid.New()
	for _, c := range []struct {
		name string
		err  error
		want audit.Result
	}{
		{"success", nil, audit.Result{}},
		{"authz forbidden", denial(gen.ProblemCodeForbidden, authz.ErrForbidden, "no_grant"),
			audit.Result{Outcome: audit.OutcomeDenied, Reason: "no_grant", Status: 403}},
		{"authz not found", denial(gen.ProblemCodeNotFound, authz.ErrNotFound, "not_a_member"),
			audit.Result{Outcome: audit.OutcomeDenied, Reason: "not_a_member", Status: 404}},
		{"service not found", problem.New(gen.ProblemCodeNotFound, "x"),
			audit.Result{Outcome: audit.OutcomeDenied, Reason: "not_found", Status: 404}},
		{"suspended", problem.New(gen.ProblemCodeTenantSuspended, "x"),
			audit.Result{Outcome: audit.OutcomeDenied, Reason: "tenant_suspended", Status: 403}},
		{"reauth", problem.New(gen.ProblemCodeReauthRequired, "x"),
			audit.Result{Outcome: audit.OutcomeDenied, Reason: "reauth_required", Status: 401}},
		{"anonymous", denial(gen.ProblemCodeUnauthenticated, authz.ErrUnauthenticated, "no_principal"),
			audit.Result{Outcome: audit.OutcomeDenied, Reason: "no_principal", Status: 401, Skip: true}},
		{"no handler", problem.NotImplemented("GetDevice"), audit.Result{Reason: "not_implemented", Status: 501, Skip: true}},
		{"validation", problem.Validation("x"), audit.Result{Outcome: audit.OutcomeFailure, Reason: "validation_failed", Status: 422}},
		{"upstream", problem.New(gen.ProblemCodeUpstreamRejected, "x"),
			audit.Result{Outcome: audit.OutcomeFailure, Reason: "upstream_rejected", Status: 502}},
		{"plain error", errors.New("boom"), audit.Result{Outcome: audit.OutcomeFailure, Reason: "internal_error", Status: 500}},
	} {
		fin := &fakeFinisher{}
		var seen *audit.Request
		h := Middleware(fin)(func(ctx context.Context, _ http.ResponseWriter, _ *http.Request, _ any) (any, error) {
			seen = audit.RequestFrom(ctx)
			return nil, c.err
		}, "GetDevice")
		r := httptest.NewRequestWithContext(requestid.With(t.Context(), "req-1"), http.MethodGet,
			"/api/v1/tenants/"+tenant.String()+"/devices/"+device.String(), nil)
		r.SetPathValue("tenantId", tenant.String())
		r.SetPathValue("deviceId", device.String())
		if _, err := h(r.Context(), httptest.NewRecorder(), r, nil); !errors.Is(err, c.err) {
			t.Errorf("%s: the error was not passed through: %v", c.name, err)
		}
		if len(fin.calls) != 1 || fin.calls[0].res != c.want {
			t.Errorf("%s: Finish %+v, want %+v", c.name, fin.calls, c.want)
			continue
		}
		req := fin.calls[0].req
		if seen != req || req.Action != "device.read" || req.Operation != "GetDevice" || !req.ReadOnly ||
			req.TenantID == nil || *req.TenantID != tenant || req.ResourceType != "device" || req.ResourceID != device.String() ||
			req.RequestID != "req-1" || req.ActorIdentityID != nil || req.ActorType != audit.ActorIdentity {
			t.Errorf("%s: audit scope %+v (handler saw %p)", c.name, req, seen)
		}
	}
}

func TestMiddlewareSkipsAuthAndRecoversPanics(t *testing.T) {
	fin := &fakeFinisher{}
	called := false
	next := func(context.Context, http.ResponseWriter, *http.Request, any) (any, error) {
		called = true
		return nil, problem.New(gen.ProblemCodeUnauthenticated, "x")
	}
	for _, op := range []string{"AuthLogin", "AuthCallback", "AuthLogout", "GetAuthSession", "ListAuthSessions", "RevokeAuthSession"} {
		h := Middleware(fin)(next, op)
		r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/auth/logout", nil)
		_, _ = h(r.Context(), httptest.NewRecorder(), r, nil)
	}
	if !called || len(fin.calls) != 0 {
		t.Errorf("auth operations: Finish called %d times (identity audits them itself)", len(fin.calls))
	}

	h := Middleware(fin)(func(context.Context, http.ResponseWriter, *http.Request, any) (any, error) {
		panic("handler bug")
	}, "SyncDevices")
	r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/tenants/x/devices/sync", nil)
	func() {
		defer func() {
			if v := recover(); v != "handler bug" {
				t.Errorf("recovered %v, want the handler's panic re-raised", v)
			}
		}()
		_, _ = h(r.Context(), httptest.NewRecorder(), r, nil)
	}()
	want := audit.Result{Outcome: audit.OutcomeFailure, Reason: "panic", Status: 500}
	if len(fin.calls) != 1 || fin.calls[0].res != want || fin.calls[0].req.ReadOnly || fin.calls[0].req.Action != "device.sync" {
		t.Errorf("panic: Finish %+v", fin.calls)
	}

	fin.calls = nil
	h = Middleware(fin)(func(context.Context, http.ResponseWriter, *http.Request, any) (any, error) {
		return nil, errors.New("x")
	}, "NoSuchOperation")
	_, _ = h(r.Context(), httptest.NewRecorder(), r, nil)
	if len(fin.calls) != 1 || fin.calls[0].req.Action != unknownAction || fin.calls[0].req.ResourceType != "api" {
		t.Errorf("unknown operation: %+v", fin.calls)
	}
}

func TestResourceOfPath(t *testing.T) {
	tenant, id := uuid.New().String(), uuid.New().String()
	for _, c := range []struct{ op, action, rtype, rid string }{
		{"GetTenant", "tenant.read", "tenant", tenant},
		{"ListDevices", "device.list", "device", ""},
		{"ExpireDevice", "device.expire", "device", id},
		{"GetTenantUser", "user.read", "user", id},
		{"GetPlatformTenant", "platform.tenant.read", "tenant", tenant},
		{"GetPlatformJob", "platform.job.read", "job", id},
		{"ListPlatformAuditEvents", "platform.audit.list", "audit", ""},
	} {
		op, ok := authz.OperationByID(c.op)
		if !ok || op.AuditAction != c.action {
			t.Errorf("%s: action %q, want %q", c.op, op.AuditAction, c.action)
			continue
		}
		r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
		for _, p := range []string{"tenantId", "deviceId", "membershipId", "jobId"} {
			if p == "tenantId" {
				r.SetPathValue(p, tenant)
			} else {
				r.SetPathValue(p, id)
			}
		}
		if got := resourceType(op.AuditAction); got != c.rtype {
			t.Errorf("%s: resource type %q, want %q", c.op, got, c.rtype)
		}
		if got := resourceID(op, r); got != c.rid {
			t.Errorf("%s: resource id %q, want %q", c.op, got, c.rid)
		}
	}
	if resourceType("x") != "api" {
		t.Error("an action without dot")
	}
}

// fakeRecorder records the identity adapter's writes.
type fakeRecorder struct {
	detached, committed, anonymous []audit.Event
	security                       []audit.SecurityEvent
}

func (f *fakeRecorder) RecordDetached(_ context.Context, ev audit.Event) error {
	f.detached = append(f.detached, ev)
	return nil
}

func (f *fakeRecorder) RecordCommitted(_ context.Context, ev audit.Event) error {
	f.committed = append(f.committed, ev)
	return nil
}

func (f *fakeRecorder) RecordAnonymousDenial(_ context.Context, ev audit.Event) error {
	f.anonymous = append(f.anonymous, ev)
	return nil
}

func (f *fakeRecorder) RecordSecurityEvent(_ context.Context, ev audit.SecurityEvent) (bool, error) {
	f.security = append(f.security, ev)
	return true, nil
}

func TestIdentityAuditor(t *testing.T) {
	rec := &fakeRecorder{}
	a := IdentityAuditor(rec)
	tenant, ident, idp, sess := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	a.Record(t.Context(), identity.AuditEvent{Action: identity.ActionLogin, Outcome: identity.OutcomeSuccess,
		IdentityID: ident, TenantID: &tenant, IdPID: idp, SessionID: sess, Origin: identity.OriginApp,
		ClientIP: "192.0.2.10", RequestID: "req-login"})
	a.Record(t.Context(), identity.AuditEvent{Action: identity.ActionLogin, Outcome: identity.OutcomeDenied,
		Reason: "idp_mismatch", IdPID: idp, ClientIP: "not an ip"})
	a.Record(t.Context(), identity.AuditEvent{Action: identity.ActionLogout, Outcome: identity.OutcomeFailure,
		Reason: "revoke_failed", IdentityID: ident})
	a.Record(t.Context(), identity.AuditEvent{Action: identity.ActionSessionCheck, Outcome: "weird"})
	a.Record(t.Context(), identity.AuditEvent{Action: identity.ActionLogin, Outcome: identity.OutcomeFailure,
		Reason: "client_secret_ref_not_owned", IdPID: idp, TenantID: &tenant, Origin: identity.OriginApp, RequestID: "req-ref",
		Security: "idp.client_secret_ref_not_owned"})
	// G2 F2: a refusal without identity is an anonymous denial (aggregated by the Logger); with an identity, one row.
	if len(rec.committed) != 1 || len(rec.detached) != 1 || len(rec.anonymous) != 3 {
		t.Fatalf("committed %d, detached %d, anonymous %d: want success committed, the refusal of an identity detached, "+
			"the three refusals without identity anonymous", len(rec.committed), len(rec.detached), len(rec.anonymous))
	}
	if len(rec.security) != 1 {
		t.Fatalf("security events %d, want 1 (only the event that asks for one)", len(rec.security))
	}
	if s := rec.security[0]; s.Kind != "idp.client_secret_ref_not_owned" || s.Severity != audit.SeverityHigh || s.TenantID != nil ||
		s.Source != "identity" || s.Details["idp_id"] != idp || s.Details["idp_tenant_id"] != tenant ||
		s.DedupeKey != "idp.client_secret_ref_not_owned:"+idp.String() || s.DedupeWindow != time.Hour {
		t.Errorf("security event %+v", s)
	}
	ok := rec.committed[0]
	if ok.TenantID == nil || ok.ActorIdentityID == nil {
		t.Fatalf("login success without tenant or actor: %+v", ok)
	}
	if ok.Action != "auth.login" || ok.Outcome != audit.OutcomeSuccess || *ok.TenantID != tenant || *ok.ActorIdentityID != ident ||
		ok.ResourceType != "session" || ok.ResourceID != sess.String() || ok.ActorIP != netip.MustParseAddr("192.0.2.10") ||
		ok.RequestID != "req-login" || ok.Details["idp_id"] != idp || ok.Details["origin"] != "app" || ok.ActorType != audit.ActorIdentity {
		t.Errorf("login success: %+v", ok)
	}
	d := rec.anonymous[0]
	if d.Outcome != audit.OutcomeDenied || d.TenantID != nil || d.ActorIdentityID != nil || d.ActorIP.IsValid() ||
		d.Details["reason"] != "idp_mismatch" || d.ResourceID != "" {
		t.Errorf("login denied: %+v", d)
	}
	if rec.detached[0].Outcome != audit.OutcomeFailure || rec.detached[0].ActorIdentityID == nil ||
		rec.anonymous[1].Outcome != audit.OutcomeFailure {
		t.Errorf("failure and unknown outcome: %+v %+v", rec.detached[0], rec.anonymous[1])
	}
}
