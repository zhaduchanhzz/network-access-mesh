//go:build mgtestfixture

// Package approvalsauthz drives dual control (P3-T04a) and invitations (P3-T05a) through the composed API — identity
// session layer, authorization (authz, with the x-conditions of the spec), audit middleware, approvalsapi and
// invitationsapi — with sessions minted by the fixture of P2-T15a: the 2P rules of §8.5/§8.6 as a client meets them
// (self-approval 403, step-up 401 reauth_required, stale reviewed hash 412, executed once, Platform Operator only for
// restores, the approver needs the action's own permission, another tenant's request 404) and the invitation rules
// (role rule 3a, Idempotency-Key, duplicates, revoke/resend, another tenant 404), with their audit trail.
package approvalsauthz

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/authz"
	"github.com/zhaduchanhzz/network-access-mesh/internal/authz/approvals"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/approvalsapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/auditapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/gen"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/invitationsapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/storetest"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
	"github.com/zhaduchanhzz/network-access-mesh/tests/security/sessionfixture"
)

func TestMain(m *testing.M) {
	code := m.Run()
	storetest.Cleanup()
	os.Exit(code)
}

type restorePayload struct {
	BackupID   string `json:"backup_id"`
	InstanceID string `json:"instance_id"`
}

type deletePayload struct {
	TenantID string `json:"tenant_id"`
}

type settingPayload struct {
	Setting string `json:"setting"`
}

// env is the composed api process of the test with the approval and invitation handler sets.
type env struct {
	w        *sessionfixture.World
	svc      *approvals.Service
	executed []json.RawMessage
}

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{}
	platformJob := func(ctx context.Context, tx *store.Tx, x approvals.Execution) (*uuid.UUID, error) {
		e.executed = append(e.executed, x.Payload)
		enq, err := jobs.Enqueue(ctx, tx, jobs.Spec{Kind: "partition.maintain", Slot: x.Request.ID.String()})
		if err != nil {
			return nil, err
		}
		return &enq.Job.ID, nil
	}
	reg, err := approvals.NewRegistry(
		approvals.Typed(approvals.Spec{Name: "platform.test_restore", Scope: authz.ScopePlatform, ResourceType: "instance",
			Permission: "platform.instance:restore", DecideConditions: []string{authz.CondRestoreOnly}},
			func(ctx context.Context, tx *store.Tx, x approvals.Execution, _ restorePayload) (*uuid.UUID, error) {
				return platformJob(ctx, tx, x)
			}),
		approvals.Typed(approvals.Spec{Name: "platform.test_delete", Scope: authz.ScopePlatform, ResourceType: "tenant",
			Permission: "platform.tenant:delete"},
			func(ctx context.Context, tx *store.Tx, x approvals.Execution, _ deletePayload) (*uuid.UUID, error) {
				return platformJob(ctx, tx, x)
			}),
		approvals.Typed(approvals.Spec{Name: "tenant.test_disable_four_eyes", Scope: authz.ScopeTenant, ResourceType: "settings",
			Permission: "tenant.settings:update_security"},
			func(ctx context.Context, tx *store.Tx, x approvals.Execution, _ settingPayload) (*uuid.UUID, error) {
				e.executed = append(e.executed, x.Payload)
				enq, err := jobs.Enqueue(ctx, tx, jobs.Spec{Kind: "policy.apply", TenantID: x.Request.TenantID})
				if err != nil {
					return nil, err
				}
				return &enq.Job.ID, nil
			}),
	)
	if err != nil {
		t.Fatal(err)
	}
	e.w = sessionfixture.New(t, sessionfixture.Options{Mount: func(w *sessionfixture.World) sessionfixture.Mount {
		logger, err := audit.New(w.Store, storetest.Require(t).OpenAuditWriter(t, w.DB),
			audit.Config{Registerer: prometheus.NewRegistry()})
		if err != nil {
			t.Fatal(err)
		}
		e.svc, err = approvals.New(w.Store, approvals.Config{Approvers: authz.New(w.Store), Registry: reg, Security: logger,
			Logger: slog.New(slog.DiscardHandler)})
		if err != nil {
			t.Fatal(err)
		}
		return sessionfixture.Mount{
			Handlers: httpapi.Handlers{
				Approvals:   approvalsapi.New(e.svc),
				Invitations: invitationsapi.New(tenants.New(w.Store, tenants.Options{}), authz.GuardInvitationRole),
			},
			Audit: auditapi.Middleware(logger),
		}
	}})
	return e
}

func (e *env) do(t *testing.T, s *sessionfixture.Session, method, path, body string, hdr ...string) *httptest.ResponseRecorder {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	h := http.Header{}
	for i := 0; i+1 < len(hdr); i += 2 {
		h.Set(hdr[i], hdr[i+1])
	}
	return e.w.Do(t, s, method, path, rd, h)
}

func want(t *testing.T, what string, rec *httptest.ResponseRecorder, status int, code gen.ProblemCode) {
	t.Helper()
	if rec.Code != status {
		t.Fatalf("%s: HTTP %d, want %d: %s", what, rec.Code, status, rec.Body.String())
	}
	if code != "" {
		var p gen.Problem
		if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil || p.Code != code {
			t.Fatalf("%s: problem %s, want %s", what, rec.Body.String(), code)
		}
	}
}

func decode[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode %T: %v: %s", v, err, rec.Body.String())
	}
	return v
}

func (e *env) count(t *testing.T, sql string, args ...any) int {
	t.Helper()
	var n int
	e.w.Scan(t, sql, args, &n)
	return n
}

func actorOf(a *sessionfixture.Actor) approvals.Actor {
	return approvals.Actor{IdentityID: a.IdentityID, Scope: authz.Scope(a.Scope), AuthTime: time.Now()}
}

func decision(hash string) string { return `{"payload_sha256":"` + hash + `"}` }

// TestApprovalsAndInvitations runs the API tests on one composed API and database (one migration instead of three);
// the order matters only for the actions run so far (platform first).
func TestApprovalsAndInvitations(t *testing.T) {
	e := newEnv(t)
	for _, tc := range []struct {
		name string
		fn   func(*testing.T, *env)
	}{
		{"PlatformApprovals", testPlatformApprovalsThroughTheAPI},
		{"TenantApprovals", testTenantApprovalsThroughTheAPI},
		{"Invitations", testInvitationsThroughTheAPI},
	} {
		t.Run(tc.name, func(t *testing.T) { tc.fn(t, e) })
	}
}

// testPlatformApprovalsThroughTheAPI — /platform/approvals with the roles of §8.5.
func testPlatformApprovalsThroughTheAPI(t *testing.T, e *env) {
	w := e.w
	ctx := context.Background()
	sa1 := w.Actor(t, authz.RoleSuperAdmin, nil)
	sa2 := w.NewActor(t, authz.RoleSuperAdmin, nil)
	po, ps, pv := w.Actor(t, authz.RolePlatformOperator, nil), w.Actor(t, authz.RolePlatformSupport, nil), w.Actor(t, authz.RolePlatformViewer, nil)
	backup := uuid.NewString()
	restore, err := e.svc.Request(ctx, actorOf(sa1), approvals.NewRequest{Action: "platform.test_restore",
		ResourceID: uuid.NewString(), Payload: restorePayload{BackupID: backup, InstanceID: uuid.NewString()}})
	if err != nil {
		t.Fatal(err)
	}
	del, err := e.svc.Request(ctx, actorOf(sa1), approvals.NewRequest{Action: "platform.test_delete",
		ResourceID: w.A.ID.String(), Payload: deletePayload{TenantID: w.A.ID.String()}})
	if err != nil {
		t.Fatal(err)
	}
	path := "/platform/approvals/" + restore.ID.String()

	// read: SA, PO, PV ✔, PS — (§8.5); the approver sees the payload that will run and its hash
	sSA2 := w.Login(t, sa2)
	got := decode[gen.ApprovalRequest](t, e.do(t, sSA2, http.MethodGet, path, ""))
	var p restorePayload
	if err := json.Unmarshal(got.Payload, &p); err != nil || p.BackupID != backup || got.PayloadSha256 != restore.PayloadSHA256 ||
		got.Status != gen.ApprovalStatusPending || got.RequestedBy.IdentityId != sa1.IdentityID {
		t.Fatalf("review %+v (%v)", got, err)
	}
	for _, a := range []*sessionfixture.Actor{po, pv} {
		list := decode[gen.ApprovalList](t, e.do(t, w.Login(t, a), http.MethodGet, "/platform/approvals?status=pending", ""))
		if len(list.Items) != 2 {
			t.Fatalf("%s lists %d pending requests", a, len(list.Items))
		}
	}
	want(t, "PS reads", e.do(t, w.Login(t, ps), http.MethodGet, path, ""), http.StatusForbidden, gen.ProblemCodeForbidden)

	// decide
	want(t, "self-approval", e.do(t, w.Login(t, sa1), http.MethodPost, path+"/approve", decision(restore.PayloadSHA256)),
		http.StatusForbidden, gen.ProblemCodeForbidden)
	stale := w.Login(t, sa2, sessionfixture.WithAuthTime(time.Now().Add(-20*time.Minute)))
	want(t, "approval without step-up", e.do(t, stale, http.MethodPost, path+"/approve", decision(restore.PayloadSHA256)),
		http.StatusUnauthorized, gen.ProblemCodeReauthRequired)
	want(t, "stale reviewed hash", e.do(t, sSA2, http.MethodPost, path+"/approve", decision(strings.Repeat("0", 64))),
		http.StatusPreconditionFailed, gen.ProblemCodePreconditionFailed)
	want(t, "malformed hash", e.do(t, sSA2, http.MethodPost, path+"/approve", `{"payload_sha256":"x"}`),
		http.StatusUnprocessableEntity, gen.ProblemCodeValidationFailed)
	want(t, "PV decides", e.do(t, w.Login(t, pv), http.MethodPost, path+"/approve", decision(restore.PayloadSHA256)),
		http.StatusForbidden, gen.ProblemCodeForbidden)
	sPO := w.Login(t, po)
	want(t, "PO approves a deletion", e.do(t, sPO, http.MethodPost, "/platform/approvals/"+del.ID.String()+"/approve",
		decision(del.PayloadSHA256)), http.StatusForbidden, gen.ProblemCodeForbidden)
	done := decode[gen.ApprovalRequest](t, e.do(t, sPO, http.MethodPost, path+"/approve", decision(restore.PayloadSHA256)))
	if done.Status != gen.ApprovalStatusExecuted || done.JobId == nil || done.DecidedBy == nil || done.DecidedBy.IdentityId != po.IdentityID {
		t.Fatalf("PO approves the restore: %+v", done)
	}
	if len(e.executed) != 1 || string(e.executed[0]) != string(got.Payload) {
		t.Fatalf("executed %s, reviewed %s", e.executed, got.Payload)
	}
	want(t, "approve again", e.do(t, sSA2, http.MethodPost, path+"/approve", decision(restore.PayloadSHA256)),
		http.StatusConflict, gen.ProblemCodeConflict)
	rej := decode[gen.ApprovalRequest](t, e.do(t, sSA2, http.MethodPost, "/platform/approvals/"+del.ID.String()+"/reject", ""))
	if rej.Status != gen.ApprovalStatusRejected {
		t.Fatalf("reject %+v", rej)
	}
	want(t, "missing request", e.do(t, sSA2, http.MethodGet, "/platform/approvals/"+uuid.NewString(), ""),
		http.StatusNotFound, gen.ProblemCodeNotFound)

	// audit: the denials with their reason, the decisions with both persons
	if n := e.count(t, `SELECT count(*) FROM audit_events WHERE tenant_id IS NULL AND action = 'platform.approval.approve'
		AND outcome = 'denied' AND details ->> 'reason' = 'self_approval' AND actor_identity_id = $1`, sa1.IdentityID); n != 1 {
		t.Errorf("self-approval denial events: %d", n)
	}
	if n := e.count(t, `SELECT count(*) FROM audit_events WHERE action = 'platform.approval.approve' AND outcome = 'denied'
		AND details ->> 'reason' = 'step_up_required'`); n != 1 {
		t.Errorf("step-up denial events: %d", n)
	}
	if n := e.count(t, `SELECT count(*) FROM audit_events WHERE action IN ('platform.approval.approve', 'platform.approval.execute')
		AND outcome = 'success' AND actor_identity_id = $1 AND details ->> 'requested_by_identity_id' = $2`, po.IdentityID,
		sa1.IdentityID.String()); n != 2 {
		t.Errorf("approve + execute events naming both persons: %d", n)
	}
}

// testTenantApprovalsThroughTheAPI — /tenants/{t}/approvals with the roles of §8.6; another tenant reads 404.
func testTenantApprovalsThroughTheAPI(t *testing.T, e *env) {
	w := e.w
	to1 := w.Actor(t, authz.RoleTenantOwner, w.A)
	to2 := w.NewActor(t, authz.RoleTenantOwner, w.A)
	req, err := e.svc.Request(context.Background(), actorOf(to1), approvals.NewRequest{Action: "tenant.test_disable_four_eyes",
		TenantID: w.A.ID, ResourceID: "policy", Payload: settingPayload{Setting: "policy.four_eyes"}, Reason: "pilot ended"})
	if err != nil {
		t.Fatal(err)
	}
	path := "/tenants/" + w.A.ID.String() + "/approvals/" + req.ID.String()
	taB := w.Login(t, w.Actor(t, authz.RoleTenantAdmin, w.B))
	want(t, "B's Admin on A's path", e.do(t, taB, http.MethodGet, path, ""), http.StatusNotFound, gen.ProblemCodeNotFound)
	want(t, "B's Admin on its own path", e.do(t, taB, http.MethodGet, "/tenants/"+w.B.ID.String()+"/approvals/"+req.ID.String(), ""),
		http.StatusNotFound, gen.ProblemCodeNotFound)
	want(t, "B's Admin approves on its own path", e.do(t, taB, http.MethodPost, "/tenants/"+w.B.ID.String()+"/approvals/"+
		req.ID.String()+"/approve", decision(req.PayloadSHA256)), http.StatusNotFound, gen.ProblemCodeNotFound)
	want(t, "staff on the platform path", e.do(t, w.Login(t, w.Actor(t, authz.RoleSuperAdmin, nil)), http.MethodGet,
		"/platform/approvals/"+req.ID.String(), ""), http.StatusNotFound, gen.ProblemCodeNotFound)
	if list := decode[gen.ApprovalList](t, e.do(t, taB, http.MethodGet, "/tenants/"+w.B.ID.String()+"/approvals", "")); len(list.Items) != 0 {
		t.Fatalf("B lists %d requests", len(list.Items))
	}

	tv := w.Login(t, w.Actor(t, authz.RoleTenantViewer, w.A))
	if got := decode[gen.ApprovalRequest](t, e.do(t, tv, http.MethodGet, path, "")); got.Reason == nil || *got.Reason != "pilot ended" {
		t.Fatalf("TV reads %+v", got)
	}
	want(t, "TV decides", e.do(t, tv, http.MethodPost, path+"/approve", decision(req.PayloadSHA256)), http.StatusForbidden, gen.ProblemCodeForbidden)
	want(t, "TP reads", e.do(t, w.Login(t, w.Actor(t, authz.RoleTenantOperator, w.A)), http.MethodGet, path, ""),
		http.StatusForbidden, gen.ProblemCodeForbidden)
	want(t, "self-approval", e.do(t, w.Login(t, to1), http.MethodPost, path+"/approve", decision(req.PayloadSHA256)),
		http.StatusForbidden, gen.ProblemCodeForbidden)
	want(t, "TA lacks the action's permission", e.do(t, w.Login(t, w.Actor(t, authz.RoleTenantAdmin, w.A)), http.MethodPost,
		path+"/approve", decision(req.PayloadSHA256)), http.StatusForbidden, gen.ProblemCodeForbidden)
	want(t, "second Owner without step-up", e.do(t, w.Login(t, to2, sessionfixture.WithAuthTime(time.Now().Add(-16*time.Minute))),
		http.MethodPost, path+"/approve", decision(req.PayloadSHA256)), http.StatusUnauthorized, gen.ProblemCodeReauthRequired)
	done := decode[gen.ApprovalRequest](t, e.do(t, w.Login(t, to2), http.MethodPost, path+"/approve", decision(req.PayloadSHA256)))
	if done.Status != gen.ApprovalStatusExecuted || done.JobId == nil {
		t.Fatalf("second Owner approves: %+v", done)
	}
	if n := e.count(t, `SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND action IN ('approval.approve', 'approval.execute')
		AND outcome = 'success' AND actor_identity_id = $2 AND details ->> 'requested_by_identity_id' = $3`, w.A.ID,
		to2.IdentityID, to1.IdentityID.String()); n != 2 {
		t.Errorf("tenant approve + execute events: %d", n)
	}
	if n := e.count(t, `SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND action = 'approval.approve'
		AND outcome = 'denied' AND details ->> 'reason' = 'self_approval'`, w.A.ID); n != 1 {
		t.Errorf("tenant self-approval denial: %d", n)
	}
}

// testInvitationsThroughTheAPI — /tenants/{t}/invitations: §8.6 (TO, TA), rule 3a, Idempotency-Key, duplicates,
// revoke/resend, another tenant 404.
func testInvitationsThroughTheAPI(t *testing.T, e *env) {
	w := e.w
	base := "/tenants/" + w.A.ID.String() + "/invitations"
	to, ta := w.Login(t, w.Actor(t, authz.RoleTenantOwner, w.A)), w.Login(t, w.Actor(t, authz.RoleTenantAdmin, w.A))
	key := "inv-" + uuid.NewString()
	body := `{"email":"newcomer@example.test","role":"tenant_viewer"}`
	first := e.do(t, ta, http.MethodPost, base, body, "Idempotency-Key", key)
	want(t, "TA invites a viewer", first, http.StatusCreated, "")
	inv := decode[gen.Invitation](t, first)
	if inv.Status != gen.InvitationStatusPending || inv.Role != "tenant_viewer" || inv.InvitedBy == nil {
		t.Fatalf("invitation %+v", inv)
	}
	if strings.Contains(first.Body.String(), "token") {
		t.Fatal("the answer mentions a token")
	}
	replay := e.do(t, ta, http.MethodPost, base, body, "Idempotency-Key", key)
	if replay.Code != http.StatusCreated || decode[gen.Invitation](t, replay).Id != inv.Id {
		t.Fatalf("replay HTTP %d %s", replay.Code, replay.Body.String())
	}
	want(t, "key reuse", e.do(t, ta, http.MethodPost, base, `{"email":"other@example.test","role":"tenant_viewer"}`,
		"Idempotency-Key", key), http.StatusUnprocessableEntity, gen.ProblemCodeIdempotencyKeyReuse)
	want(t, "missing key", e.do(t, ta, http.MethodPost, base, body), http.StatusUnprocessableEntity, gen.ProblemCodeValidationFailed)
	want(t, "TA invites an Admin", e.do(t, ta, http.MethodPost, base, `{"email":"chief@example.test","role":"tenant_admin"}`,
		"Idempotency-Key", uuid.NewString()), http.StatusForbidden, gen.ProblemCodeForbidden)
	want(t, "Owner role", e.do(t, to, http.MethodPost, base, `{"email":"chief@example.test","role":"tenant_owner"}`,
		"Idempotency-Key", uuid.NewString()), http.StatusUnprocessableEntity, gen.ProblemCodeValidationFailed)
	adm := e.do(t, to, http.MethodPost, base, `{"email":"chief@example.test","role":"tenant_admin","expires_in_hours":24}`,
		"Idempotency-Key", uuid.NewString())
	want(t, "TO invites an Admin", adm, http.StatusCreated, "")
	admInv := decode[gen.Invitation](t, adm)
	want(t, "duplicate address", e.do(t, to, http.MethodPost, base, `{"email":"NEWCOMER@example.test","role":"end_user"}`,
		"Idempotency-Key", uuid.NewString()), http.StatusConflict, gen.ProblemCodeConflict)
	want(t, "TV manages invitations", e.do(t, w.Login(t, w.Actor(t, authz.RoleTenantViewer, w.A)), http.MethodGet, base, ""),
		http.StatusForbidden, gen.ProblemCodeForbidden)
	taB := w.Login(t, w.Actor(t, authz.RoleTenantAdmin, w.B))
	want(t, "B on A's invitations", e.do(t, taB, http.MethodGet, base, ""), http.StatusNotFound, gen.ProblemCodeNotFound)
	want(t, "B revokes A's invitation on its path", e.do(t, taB, http.MethodDelete, "/tenants/"+w.B.ID.String()+"/invitations/"+
		inv.Id.String(), ""), http.StatusNotFound, gen.ProblemCodeNotFound)
	if list := decode[gen.InvitationList](t, e.do(t, ta, http.MethodGet, base+"?status=pending", "")); len(list.Items) != 2 {
		t.Fatalf("pending invitations %d", len(list.Items))
	}

	want(t, "TA revokes the Admin invitation", e.do(t, ta, http.MethodDelete, base+"/"+admInv.Id.String(), ""),
		http.StatusForbidden, gen.ProblemCodeForbidden)
	want(t, "TO revokes it", e.do(t, to, http.MethodDelete, base+"/"+admInv.Id.String(), ""), http.StatusNoContent, "")
	want(t, "revoke again", e.do(t, to, http.MethodDelete, base+"/"+admInv.Id.String(), ""), http.StatusConflict, gen.ProblemCodeConflict)
	re := e.do(t, ta, http.MethodPost, base+"/"+inv.Id.String()+"/resend", `{"expires_in_hours":2}`)
	want(t, "TA re-sends the viewer invitation", re, http.StatusOK, "")
	if r := decode[gen.Invitation](t, re); time.Until(r.ExpiresAt) > 2*time.Hour+time.Minute {
		t.Fatalf("resend expiry %s", r.ExpiresAt)
	}
	want(t, "resend without body", e.do(t, ta, http.MethodPost, base+"/"+inv.Id.String()+"/resend", ""), http.StatusOK, "")
	want(t, "missing invitation", e.do(t, ta, http.MethodDelete, base+"/"+uuid.NewString(), ""), http.StatusNotFound, gen.ProblemCodeNotFound)
	// invitation.create: 2 invitations + 1 event of the Idempotency-Key replay (details.replay — no audit gap)
	for action, n := range map[string]int{"invitation.create": 3, "invitation.revoke": 1, "invitation.resend": 2} {
		if got := e.count(t, `SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND action = $2 AND outcome = 'success'`,
			w.A.ID, action); got != n {
			t.Errorf("%s success events: %d, want %d", action, got, n)
		}
	}
	if n := e.count(t, `SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND action = 'invitation.create'
		AND outcome = 'success' AND details->>'replay' = 'true' AND resource_id = $2`, w.A.ID, inv.Id.String()); n != 1 {
		t.Errorf("replayed invitation.create events: %d, want 1", n)
	}
	if n := e.count(t, `SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND action = 'invitation.create'
		AND outcome = 'denied'`, w.A.ID); n != 1 {
		t.Errorf("denied invitation.create events: %d (TA → Admin)", n)
	}
}
