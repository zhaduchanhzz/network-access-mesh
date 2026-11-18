//go:build mgtestfixture

// Package membersauthz drives the user and group operations of P4-T09 through the composed API — identity session
// layer, authorization (authz), audit middleware, membersapi with authz.GuardMembershipChange and the approvals of
// P3-T04a — with sessions minted by the fixture of P2-T15a: rule 3a as a Tenant Admin meets it (no lock, offboard,
// role change or invitation at Admin or Owner — 403, audited denied with the guard's reason), the admin-role and
// ownership-transfer operations (Owner only, step-up), the two-phase offboarding (202 + Location, the person's
// session refused at its next request), another tenant's member and group (404), and a sensitive group changed only
// through a second person's approval.
package membersauthz

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
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/membersapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/tenantsapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/members"
	"github.com/zhaduchanhzz/network-access-mesh/internal/platform"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/storetest"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
	"github.com/zhaduchanhzz/network-access-mesh/tests/security/sessionfixture"
)

func TestMain(m *testing.M) {
	code := m.Run()
	storetest.Cleanup()
	os.Exit(code)
}

func guard(ctx context.Context, q *sqlcdb.Queries, tenantID uuid.UUID, c members.Change) error {
	return authz.GuardMembershipChange(ctx, q, tenantID, authz.MembershipChange{Actor: c.Actor, Target: c.Target,
		NewRole: c.NewRole, Deactivate: c.Deactivate, OwnershipTransfer: c.OwnershipTransfer})
}

type env struct{ w *sessionfixture.World }

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{}
	e.w = sessionfixture.New(t, sessionfixture.Options{Mount: func(w *sessionfixture.World) sessionfixture.Mount {
		logger, err := audit.New(w.Store, storetest.Require(t).OpenAuditWriter(t, w.DB),
			audit.Config{Registerer: prometheus.NewRegistry()})
		if err != nil {
			t.Fatal(err)
		}
		ten := tenants.New(w.Store, tenants.Options{})
		mem, err := members.New(w.Store, members.Config{Tenants: ten, Guard: guard})
		if err != nil {
			t.Fatal(err)
		}
		reg, err := approvals.NewRegistry(approvals.Typed(approvals.Spec{Name: members.ApprovalAction,
			Scope: authz.ScopeTenant, ResourceType: "group", Permission: "tenant.group:manage"},
			func(ctx context.Context, tx *store.Tx, x approvals.Execution, p members.GroupMembersPayload) (*uuid.UUID, error) {
				return mem.ExecuteGroupMembers(ctx, tx, *x.Request.TenantID, x.Request.ID, x.Request.ResourceID,
					x.Request.RequestedBy.IdentityID, p)
			}))
		if err != nil {
			t.Fatal(err)
		}
		appr, err := approvals.New(w.Store, approvals.Config{Approvers: authz.New(w.Store), Registry: reg, Security: logger,
			Logger: slog.New(slog.DiscardHandler)})
		if err != nil {
			t.Fatal(err)
		}
		return sessionfixture.Mount{
			Handlers: httpapi.Handlers{
				Tenants:     tenantsapi.New(ten, platform.New(w.Store)),
				Members:     membersapi.New(mem, appr),
				Approvals:   approvalsapi.New(appr),
				Invitations: invitationsapi.New(ten, authz.GuardInvitationRole),
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

func (e *env) etag(t *testing.T, s *sessionfixture.Session, path string) string {
	t.Helper()
	rec := e.do(t, s, http.MethodGet, path, "")
	want(t, "GET "+path, rec, http.StatusOK, "")
	return rec.Header().Get("ETag")
}

func (e *env) deniedReason(t *testing.T, actor *sessionfixture.Actor, action string) string {
	t.Helper()
	var r string
	e.w.Scan(t, `SELECT COALESCE(details ->> 'reason', '') FROM audit_events WHERE actor_identity_id = $1 AND action = $2
		AND outcome = 'denied' ORDER BY occurred_at DESC LIMIT 1`, []any{actor.IdentityID, action}, &r)
	return r
}

// TestMembersThroughTheAPI — §20 P4-T09: rule 3a for a Tenant Admin (lock, offboard, role, admin-role, invitation at
// Admin or Owner — all refused and audited), the Owner's admin-role and ownership-transfer with step-up, the two-phase
// offboarding with the person's session refused at once, 404 for another tenant's member and group, the sensitive
// group through a second person's approval.
func TestMembersThroughTheAPI(t *testing.T) {
	e := newEnv(t)
	w := e.w
	a := w.A
	owner := w.Actor(t, authz.RoleTenantOwner, a)
	admin := w.Actor(t, authz.RoleTenantAdmin, a)
	admin2 := w.NewActor(t, authz.RoleTenantAdmin, a)
	viewer := w.Actor(t, authz.RoleTenantViewer, a)
	user := w.NewActor(t, authz.RoleEndUser, a)
	sOwner, sAdmin := w.Login(t, owner), w.Login(t, admin)
	users := "/tenants/" + a.ID.String() + "/users/"

	// rule 3a: a Tenant Admin acts on no Owner and no other Admin, gives no Admin role
	for _, tc := range []struct {
		name, method, path, body, action string
	}{
		{"lock the Owner", http.MethodPatch, users + owner.MembershipID.String(), `{"status":"locked"}`, "user.update"},
		{"lock another Admin", http.MethodPatch, users + admin2.MembershipID.String(), `{"status":"locked"}`, "user.update"},
		{"offboard the Owner", http.MethodDelete, users + owner.MembershipID.String(), "", "user.offboard"},
		{"offboard another Admin", http.MethodDelete, users + admin2.MembershipID.String(), "", "user.offboard"},
		{"demote another Admin", http.MethodPut, users + admin2.MembershipID.String() + "/role", `{"role":"tenant_viewer"}`, "user.role.set"},
		{"revoke the Owner's sessions", http.MethodDelete, users + owner.MembershipID.String() + "/sessions", "", "user.sessions.revoke"},
	} {
		rec := e.do(t, sAdmin, tc.method, tc.path, tc.body, "If-Match", `"1"`)
		want(t, tc.name, rec, http.StatusForbidden, gen.ProblemCodeForbidden)
		if r := e.deniedReason(t, admin, tc.action); r != "target_not_lower" {
			t.Errorf("%s: audited reason %q, want target_not_lower", tc.name, r)
		}
	}
	want(t, "admin-role by a Tenant Admin (no assign_admin)", e.do(t, sAdmin, http.MethodPut,
		users+viewer.MembershipID.String()+"/admin-role", `{"role":"tenant_admin"}`, "If-Match", `"1"`),
		http.StatusForbidden, gen.ProblemCodeForbidden)
	want(t, "ownership transfer by a Tenant Admin", e.do(t, sAdmin, http.MethodPost, "/tenants/"+a.ID.String()+"/ownership-transfer",
		`{"membership_id":"`+viewer.MembershipID.String()+`"}`), http.StatusForbidden, gen.ProblemCodeForbidden)
	want(t, "invite an Admin as a Tenant Admin", e.do(t, sAdmin, http.MethodPost, "/tenants/"+a.ID.String()+"/invitations",
		`{"email":"new-admin@example.test","role":"tenant_admin"}`, "Idempotency-Key", "k-"+uuid.NewString()),
		http.StatusForbidden, gen.ProblemCodeForbidden)
	want(t, "Admin role through the role operation", e.do(t, sOwner, http.MethodPut, users+viewer.MembershipID.String()+"/role",
		`{"role":"tenant_admin"}`, "If-Match", e.etag(t, sOwner, users+viewer.MembershipID.String())),
		http.StatusUnprocessableEntity, gen.ProblemCodeValidationFailed)

	// If-Match, another tenant's member
	want(t, "lock without If-Match", e.do(t, sOwner, http.MethodPatch, users+viewer.MembershipID.String(), `{"status":"locked"}`),
		http.StatusPreconditionRequired, gen.ProblemCodePreconditionRequired)
	want(t, "lock with a stale If-Match", e.do(t, sOwner, http.MethodPatch, users+viewer.MembershipID.String(),
		`{"status":"locked"}`, "If-Match", `"999"`), http.StatusPreconditionFailed, gen.ProblemCodePreconditionFailed)
	bViewer := w.Actor(t, authz.RoleTenantViewer, w.B)
	want(t, "B's member on A's path", e.do(t, sOwner, http.MethodDelete, users+bViewer.MembershipID.String(), ""),
		http.StatusNotFound, gen.ProblemCodeNotFound)

	// the Owner: admin-role with step-up, then the Tenant Admin lowers the promoted member back? no — 3a; the Owner does
	stale := w.Login(t, owner, sessionfixture.WithAuthTime(time.Now().Add(-20*time.Minute)))
	path := users + viewer.MembershipID.String()
	want(t, "admin-role without step-up", e.do(t, stale, http.MethodPut, path+"/admin-role", `{"role":"tenant_admin"}`,
		"If-Match", e.etag(t, sOwner, path)), http.StatusUnauthorized, gen.ProblemCodeReauthRequired)
	sViewer := w.Login(t, viewer)
	m := decode[gen.Membership](t, e.do(t, sOwner, http.MethodPut, path+"/admin-role", `{"role":"tenant_admin"}`,
		"If-Match", e.etag(t, sOwner, path)))
	if m.Role != authz.RoleTenantAdmin {
		t.Fatalf("promoted: %+v", m)
	}
	want(t, "the promoted member's old session", e.do(t, sViewer, http.MethodGet, path, ""), http.StatusUnauthorized,
		gen.ProblemCodeUnauthenticated)
	m = decode[gen.Membership](t, e.do(t, sOwner, http.MethodPut, path+"/admin-role", `{"role":"tenant_viewer"}`,
		"If-Match", e.etag(t, sOwner, path)))
	if m.Role != authz.RoleTenantViewer {
		t.Fatalf("demoted: %+v", m)
	}

	// offboarding: 202 + Location of the job, the person's session refused at its next request, B sees nothing
	sUser := w.Login(t, user)
	want(t, "the member before", e.do(t, sUser, http.MethodGet, "/tenants/"+a.ID.String(), ""), http.StatusOK, "")
	rec := e.do(t, sAdmin, http.MethodDelete, users+user.MembershipID.String(), "")
	want(t, "offboard", rec, http.StatusAccepted, "")
	off := decode[gen.Membership](t, rec)
	if off.Status != "offboarded" || off.Offboarding == nil || off.Offboarding.State != gen.MembershipOffboardingStatePending ||
		rec.Header().Get("Location") != "/api/v1/tenants/"+a.ID.String()+"/jobs/"+off.Offboarding.JobId.String() {
		t.Fatalf("offboarded %+v %v, Location %s", off, off.Offboarding, rec.Header().Get("Location"))
	}
	want(t, "the offboarded member's session", e.do(t, sUser, http.MethodGet, "/tenants/"+a.ID.String(), ""),
		http.StatusUnauthorized, gen.ProblemCodeUnauthenticated)
	again := e.do(t, sOwner, http.MethodDelete, users+user.MembershipID.String(), "")
	want(t, "offboard again", again, http.StatusAccepted, "")
	if again.Header().Get("Location") != rec.Header().Get("Location") {
		t.Fatal("a second offboarding started another job")
	}
	var reqs int
	w.Scan(t, `SELECT count(*) FROM audit_events WHERE action = 'user.offboard.requested' AND resource_id = $1`,
		[]any{user.MembershipID.String()}, &reqs)
	if reqs != 1 {
		t.Fatalf("%d offboarding requests audited, want 1", reqs)
	}

	// groups: CRUD, another tenant's group 404, a sensitive group only through a second person's approval
	groups := "/tenants/" + a.ID.String() + "/groups"
	g := decode[gen.Group](t, e.do(t, sAdmin, http.MethodPost, groups, `{"name":"sec-ops"}`, "Idempotency-Key", "k-"+uuid.NewString()))
	gpath := groups + "/" + g.Id.String()
	bOwner := w.Login(t, w.Actor(t, authz.RoleTenantOwner, w.B))
	want(t, "A's group on B's path", e.do(t, bOwner, http.MethodGet, "/tenants/"+w.B.ID.String()+"/groups/"+g.Id.String(), ""),
		http.StatusNotFound, gen.ProblemCodeNotFound)
	want(t, "A's group with B's identity", e.do(t, bOwner, http.MethodGet, gpath, ""), http.StatusNotFound, gen.ProblemCodeNotFound)
	w.Exec(t, `UPDATE tenants SET settings = jsonb_build_object('policy', jsonb_build_object('sensitive_groups',
		jsonb_build_array($2::text))) WHERE id = $1`, a.ID, g.Id.String())
	body := `{"membership_ids":["` + viewer.MembershipID.String() + `"]}`
	want(t, "sensitive change without step-up", e.do(t, w.Login(t, admin, sessionfixture.WithAuthTime(time.Now().Add(-time.Hour))),
		http.MethodPut, gpath+"/members", body, "If-Match", e.etag(t, sAdmin, gpath)), http.StatusUnauthorized,
		gen.ProblemCodeReauthRequired)
	rec = e.do(t, sAdmin, http.MethodPut, gpath+"/members", body, "If-Match", e.etag(t, sAdmin, gpath))
	want(t, "sensitive change", rec, http.StatusAccepted, "")
	req := decode[gen.ApprovalRequest](t, rec)
	if req.Status != gen.ApprovalStatusPending || rec.Header().Get("Location") != "/api/v1/tenants/"+a.ID.String()+"/approvals/"+req.Id.String() {
		t.Fatalf("approval %+v, Location %s", req, rec.Header().Get("Location"))
	}
	if got := decode[gen.Group](t, e.do(t, sAdmin, http.MethodGet, gpath, "")); got.MemberCount != 0 || !got.Sensitive {
		t.Fatalf("group changed before the approval: %+v", got)
	}
	appr := "/tenants/" + a.ID.String() + "/approvals/" + req.Id.String()
	decision := `{"payload_sha256":"` + req.PayloadSha256 + `"}`
	want(t, "self-approval", e.do(t, sAdmin, http.MethodPost, appr+"/approve", decision), http.StatusForbidden, gen.ProblemCodeForbidden)
	done := decode[gen.ApprovalRequest](t, e.do(t, sOwner, http.MethodPost, appr+"/approve", decision))
	if done.Status != gen.ApprovalStatusExecuted || done.JobId == nil {
		t.Fatalf("approved: %+v", done)
	}
	got := decode[gen.Group](t, e.do(t, sAdmin, http.MethodGet, gpath, ""))
	if got.MemberCount != 1 || got.Members == nil || (*got.Members)[0].MembershipId != viewer.MembershipID {
		t.Fatalf("group after the approval: %+v", got)
	}
	var kind string
	w.Scan(t, `SELECT kind FROM provisioning_jobs WHERE id = $1`, []any{*done.JobId}, &kind)
	if kind != "policy.apply" {
		t.Fatalf("job of the approval %s, want policy.apply", kind)
	}
	want(t, "delete the sensitive group with members", e.do(t, sOwner, http.MethodDelete, gpath, "", "If-Match", e.etag(t, sOwner, gpath)),
		http.StatusConflict, gen.ProblemCodeConflict)

	// ownership transfer (step-up; the former Owner becomes Admin)
	stale = w.Login(t, owner, sessionfixture.WithAuthTime(time.Now().Add(-20*time.Minute)))
	transfer := "/tenants/" + a.ID.String() + "/ownership-transfer"
	want(t, "transfer without step-up", e.do(t, stale, http.MethodPost, transfer, `{"membership_id":"`+admin2.MembershipID.String()+`"}`),
		http.StatusUnauthorized, gen.ProblemCodeReauthRequired)
	m = decode[gen.Membership](t, e.do(t, sOwner, http.MethodPost, transfer, `{"membership_id":"`+admin2.MembershipID.String()+`"}`))
	if m.Role != authz.RoleTenantOwner {
		t.Fatalf("new Owner: %+v", m)
	}
	former := decode[gen.Membership](t, e.do(t, w.Login(t, admin2), http.MethodGet, users+owner.MembershipID.String(), ""))
	if former.Role != authz.RoleTenantAdmin {
		t.Fatalf("former Owner: %+v", former)
	}
	want(t, "the former Owner's session", e.do(t, sOwner, http.MethodGet, users+owner.MembershipID.String(), ""),
		http.StatusUnauthorized, gen.ProblemCodeUnauthenticated)
}
