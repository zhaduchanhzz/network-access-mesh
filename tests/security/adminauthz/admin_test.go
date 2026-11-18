//go:build mgtestfixture

// Package adminauthz drives the administration operations of P4-T03a through the composed API — identity session layer,
// authorization (authz, with the conditional cells excludes_super_admin and tenant_idp_dual_control), audit middleware,
// adminapi over internal/platform and internal/tenants, and the approvals of P3-T04a with the actions of P4-T03a — with
// sessions minted by the fixture of P2-T15a. The verification of §20 P4-T03a: a PATCH that names issuer/client_id is
// 422; a change of a tenant's IdP row initiated by the platform is 202 + an approval request, NOT in effect before a
// second Super Admin approves, and audited in the tenant's own audit (requested and applied) with the Owners notified;
// plus the Super Admin role through 2P only, the tenant's security settings (lifting a second-person control through a
// tenant approval decided by another Owner or Admin), If-Match, step-up, another tenant (404).
package adminauthz

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/authz"
	"github.com/zhaduchanhzz/network-access-mesh/internal/authz/approvals"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/adminapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/approvalsapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/auditapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/gen"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/tenantsapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/platform"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/storetest"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
	"github.com/zhaduchanhzz/network-access-mesh/tests/security/sessionfixture"
)

func TestMain(m *testing.M) {
	code := m.Run()
	storetest.Cleanup()
	os.Exit(code)
}

// fakeSecret is the client secret the test sends (built at run time: not a literal credential).
var fakeSecret = "canary-" + strings.Repeat("xy", 8)

// fakeSecrets records the client secrets PATCH /identity-provider stores (the SecretStore adapter is apps/*).
type fakeSecrets struct {
	mu        sync.Mutex
	stored    map[string][]byte
	destroyed []string
	n         int
}

func (f *fakeSecrets) Store(_ context.Context, tenantID, idpID uuid.UUID, secret []byte) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.n++
	ref := "mgsec://" + tenantID.String() + "/idp-client-secret." + idpID.String() + "#" + strconv.Itoa(f.n)
	f.stored[ref] = append([]byte(nil), secret...)
	return ref, nil
}

func (f *fakeSecrets) Destroy(_ context.Context, ref string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.destroyed = append(f.destroyed, ref)
	return nil
}

// current is the world of the running test (its internal log is printed with an unexpected 500).
var current *sessionfixture.World

type env struct {
	w   *sessionfixture.World
	sec *fakeSecrets
}

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{sec: &fakeSecrets{stored: map[string][]byte{}}}
	e.w = sessionfixture.New(t, sessionfixture.Options{Mount: func(w *sessionfixture.World) sessionfixture.Mount {
		logger, err := audit.New(w.Store, storetest.Require(t).OpenAuditWriter(t, w.DB),
			audit.Config{Registerer: prometheus.NewRegistry()})
		if err != nil {
			t.Fatal(err)
		}
		ten := tenants.New(w.Store, tenants.Options{ClientSecrets: e.sec})
		plat := platform.New(w.Store)
		reg, err := approvals.NewRegistry(adminActions(plat, ten)...)
		if err != nil {
			t.Fatal(err)
		}
		appr, err := approvals.New(w.Store, approvals.Config{Approvers: authz.New(w.Store), Registry: reg, Security: logger,
			Logger: slog.New(slog.DiscardHandler), Notify: notifyDeciders})
		if err != nil {
			t.Fatal(err)
		}
		return sessionfixture.Mount{
			Handlers: httpapi.Handlers{
				Tenants:   tenantsapi.New(ten, plat),
				Admin:     adminapi.New(plat, ten, appr),
				Approvals: approvalsapi.New(appr),
				Audit:     auditapi.New(audit.NewReader(w.Store)),
			},
			Audit: auditapi.Middleware(logger),
		}
	}})
	current = e.w
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
		logs := ""
		if rec.Code == http.StatusInternalServerError && current != nil {
			logs = current.Logs()
			if len(logs) > 4000 {
				logs = logs[len(logs)-4000:]
			}
		}
		t.Fatalf("%s: HTTP %d, want %d: %s%s", what, rec.Code, status, rec.Body.String(), logs)
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

func (e *env) count(t *testing.T, sql string, args ...any) int {
	t.Helper()
	var n int
	e.w.Scan(t, sql, args, &n)
	return n
}

func aged(w *sessionfixture.World, t *testing.T, a *sessionfixture.Actor) *sessionfixture.Session {
	return w.Login(t, a, sessionfixture.WithAuthTime(time.Now().Add(-20*time.Minute)))
}

// TestPlatformChangeOfATenantIdP — §20 P4-T03a: issuer ⇒ 422; a platform change of a tenant row ⇒ 202 + approval, not
// in effect before the second Super Admin, in the tenant's audit (requested, then applied) with the Owners notified; a
// change of the platform's own row applies at once.
func TestPlatformChangeOfATenantIdP(t *testing.T) {
	e := newEnv(t)
	w := e.w
	a := w.A
	sa1, sa2 := w.Actor(t, authz.RoleSuperAdmin, nil), w.NewActor(t, authz.RoleSuperAdmin, nil)
	po := w.Actor(t, authz.RolePlatformOperator, nil)
	owner := w.Actor(t, authz.RoleTenantOwner, a)
	s1, s2, sPO, sOwner := w.Login(t, sa1), w.Login(t, sa2), w.Login(t, po), w.Login(t, owner)
	path := "/platform/identity-providers/" + a.IdP.String()
	tag := e.etag(t, s1, path)

	for _, field := range []string{`"issuer":"https://evil.example/realms/x"`, `"client_id":"other"`, `"driver":"external"`} {
		rec := e.do(t, s1, http.MethodPatch, path, `{`+field+`,"allowed_email_domains":["acme.example"]}`, "If-Match", tag)
		want(t, "PATCH with "+field, rec, http.StatusUnprocessableEntity, gen.ProblemCodeValidationFailed)
	}
	want(t, "PATCH by a Platform Operator", e.do(t, sPO, http.MethodPatch, path, `{"allowed_email_domains":["acme.example"]}`,
		"If-Match", tag), http.StatusForbidden, gen.ProblemCodeForbidden)
	want(t, "PATCH without If-Match", e.do(t, s1, http.MethodPatch, path, `{"allowed_email_domains":["acme.example"]}`),
		http.StatusPreconditionRequired, gen.ProblemCodePreconditionRequired)
	want(t, "PATCH without step-up", e.do(t, aged(w, t, sa1), http.MethodPatch, path,
		`{"allowed_email_domains":["acme.example"]}`, "If-Match", tag), http.StatusUnauthorized, gen.ProblemCodeReauthRequired)
	want(t, "PATCH of a missing IdP", e.do(t, s1, http.MethodPatch, "/platform/identity-providers/"+uuid.NewString(),
		`{"allowed_email_domains":["acme.example"]}`, "If-Match", tag), http.StatusNotFound, gen.ProblemCodeNotFound)

	rec := e.do(t, s1, http.MethodPatch, path, `{"allowed_email_domains":["Acme.Example"],"required_claims":{"hd":"acme.example"}}`,
		"If-Match", tag)
	want(t, "PATCH of tenant A's IdP", rec, http.StatusAccepted, "")
	r := decode[gen.ApprovalRequest](t, rec)
	if loc := rec.Header().Get("Location"); loc != "/api/v1/platform/approvals/"+r.Id.String() || r.Action != tenants.PlatformIdPChangeApprovalAction ||
		r.Scope != "platform" {
		t.Fatalf("202: Location %q, request %+v", loc, r)
	}
	// not in effect: the tenant's IdP is unchanged, the row too
	idp := decode[gen.IdentityProvider](t, e.do(t, sOwner, http.MethodGet, "/tenants/"+a.ID.String()+"/identity-provider", ""))
	if len(idp.AllowedEmailDomains) != 0 || string(idp.RequiredClaims) != "{}" {
		t.Fatalf("the change is in effect before the approval: %+v", idp)
	}
	// visible to the tenant: its audit and its Owners' notification
	if n := e.count(t, `SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND action = 'identity_provider.platform_change.request'
		AND details ->> 'approval_id' = $2`, a.ID, r.Id.String()); n != 1 {
		t.Fatalf("tenant audit of the request: %d events", n)
	}
	aud := e.do(t, sOwner, http.MethodGet, "/tenants/"+a.ID.String()+"/audit?action=identity_provider.platform_change.request", "")
	want(t, "the tenant reads its audit", aud, http.StatusOK, "")
	if !strings.Contains(aud.Body.String(), r.Id.String()) {
		t.Fatalf("the tenant's audit does not list the request: %s", aud.Body.String())
	}
	if n := e.count(t, `SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND action LIKE 'identity_provider.%'`, w.B.ID); n != 0 {
		t.Fatalf("tenant B's audit lists %d events of A's IdP", n)
	}
	if n := e.count(t, `SELECT count(*) FROM notification_outbox WHERE tenant_id = $1 AND kind = 'idp.config_changed'
		AND recipient_membership_id = $2 AND payload ->> 'stage' = 'requested'`, a.ID, owner.MembershipID); n != 1 {
		t.Fatalf("Owner notifications of the request: %d", n)
	}

	// the second person: never the requester, never without platform.idp:manage, a Super Admin with step-up
	approve := "/platform/approvals/" + r.Id.String() + "/approve"
	body := `{"payload_sha256":"` + r.PayloadSha256 + `"}`
	want(t, "self-approval", e.do(t, s1, http.MethodPost, approve, body), http.StatusForbidden, gen.ProblemCodeForbidden)
	want(t, "approval by a Platform Operator", e.do(t, sPO, http.MethodPost, approve, body), http.StatusForbidden, gen.ProblemCodeForbidden)
	want(t, "approval without step-up", e.do(t, aged(w, t, sa2), http.MethodPost, approve, body), http.StatusUnauthorized,
		gen.ProblemCodeReauthRequired)
	rec = e.do(t, s2, http.MethodPost, approve, body)
	want(t, "approval by the second Super Admin", rec, http.StatusOK, "")
	if got := decode[gen.ApprovalRequest](t, rec); got.Status != gen.ApprovalStatusExecuted {
		t.Fatalf("status after approval: %s", got.Status)
	}
	idp = decode[gen.IdentityProvider](t, e.do(t, sOwner, http.MethodGet, "/tenants/"+a.ID.String()+"/identity-provider", ""))
	if len(idp.AllowedEmailDomains) != 1 || idp.AllowedEmailDomains[0] != "acme.example" || !strings.Contains(string(idp.RequiredClaims), `"hd"`) {
		t.Fatalf("the approved change is not in effect: %+v", idp)
	}
	if n := e.count(t, `SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND action = 'identity_provider.platform_change.apply'
		AND details ->> 'requested_by_identity_id' = $2 AND details ->> 'decided_by_identity_id' = $3`,
		a.ID, sa1.IdentityID.String(), sa2.IdentityID.String()); n != 1 {
		t.Fatalf("tenant audit of the execution with both persons: %d", n)
	}
	want(t, "approve again", e.do(t, s2, http.MethodPost, approve, body), http.StatusConflict, gen.ProblemCodeConflict)

	// a stale request: approved after the row changed ⇒ 409 target_changed, nothing written
	tag = e.etag(t, s1, path)
	rec = e.do(t, s1, http.MethodPatch, path, `{"claim_mapping":{"name":"preferred_username"}}`, "If-Match", tag)
	want(t, "second PATCH", rec, http.StatusAccepted, "")
	r2 := decode[gen.ApprovalRequest](t, rec)
	ownerTag := e.etag(t, sOwner, "/tenants/"+a.ID.String()+"/identity-provider")
	want(t, "the Owner changes the IdP meanwhile", e.do(t, sOwner, http.MethodPatch, "/tenants/"+a.ID.String()+"/identity-provider",
		`{"allowed_email_domains":["acme.example","acme.test"]}`, "If-Match", ownerTag), http.StatusOK, "")
	want(t, "approve a stale request", e.do(t, s2, http.MethodPost, "/platform/approvals/"+r2.Id.String()+"/approve",
		`{"payload_sha256":"`+r2.PayloadSha256+`"}`), http.StatusConflict, gen.ProblemCodeConflict)
	idp = decode[gen.IdentityProvider](t, e.do(t, sOwner, http.MethodGet, "/tenants/"+a.ID.String()+"/identity-provider", ""))
	if len(idp.ClaimMapping) != 0 {
		t.Fatalf("a stale approval was executed: %+v", idp.ClaimMapping)
	}

	// the platform's own IdP: at once, platform audit only
	ppath := "/platform/identity-providers/" + w.PlatformIdP.String()
	rec = e.do(t, s1, http.MethodPatch, ppath, `{"claim_mapping":{"name":"preferred_username"}}`, "If-Match", e.etag(t, s1, ppath))
	want(t, "PATCH of the platform IdP", rec, http.StatusOK, "")
	if got := decode[gen.IdentityProvider](t, rec); got.ClaimMapping["name"] != "preferred_username" || got.Version != 2 {
		t.Fatalf("platform IdP after PATCH: %+v", got)
	}
}

// TestTenantIdentityProvider — PATCH /tenants/{t}/identity-provider: Tenant Owner only, step-up, issuer immutable,
// client secret of an external IdP only (stored, reference recorded, never returned), another tenant 404.
func TestTenantIdentityProvider(t *testing.T) {
	e := newEnv(t)
	w := e.w
	a := w.A
	owner, admin := w.Actor(t, authz.RoleTenantOwner, a), w.Actor(t, authz.RoleTenantAdmin, a)
	sOwner, sAdmin := w.Login(t, owner), w.Login(t, admin)
	path := "/tenants/" + a.ID.String() + "/identity-provider"
	tag := e.etag(t, sAdmin, path) // TA reads (tenant.idp:read)
	want(t, "PATCH by a Tenant Admin", e.do(t, sAdmin, http.MethodPatch, path, `{"allowed_email_domains":["a.test"]}`, "If-Match", tag),
		http.StatusForbidden, gen.ProblemCodeForbidden)
	want(t, "PATCH with issuer", e.do(t, sOwner, http.MethodPatch, path, `{"issuer":"https://x.test"}`, "If-Match", tag),
		http.StatusUnprocessableEntity, gen.ProblemCodeValidationFailed)
	want(t, "PATCH without step-up", e.do(t, aged(w, t, owner), http.MethodPatch, path, `{"allowed_email_domains":["a.test"]}`,
		"If-Match", tag), http.StatusUnauthorized, gen.ProblemCodeReauthRequired)
	want(t, "an invalid required claim", e.do(t, sOwner, http.MethodPatch, path, `{"required_claims":{"hd":{"x":1}}}`, "If-Match", tag),
		http.StatusUnprocessableEntity, gen.ProblemCodeValidationFailed)
	want(t, "a client secret of a platform-hosted IdP", e.do(t, sOwner, http.MethodPatch, path,
		`{"client_secret":"`+strings.Repeat("ab", 10)+`"}`, "If-Match", tag), http.StatusUnprocessableEntity, gen.ProblemCodeValidationFailed)
	bOwner := w.Login(t, w.Actor(t, authz.RoleTenantOwner, w.B))
	want(t, "B's Owner on A", e.do(t, bOwner, http.MethodPatch, path, `{"allowed_email_domains":["a.test"]}`, "If-Match", tag),
		http.StatusNotFound, gen.ProblemCodeNotFound)
	rec := e.do(t, sOwner, http.MethodPatch, path, `{"allowed_email_domains":["a.test"]}`, "If-Match", tag)
	want(t, "PATCH by the Owner", rec, http.StatusOK, "")
	want(t, "the same If-Match again", e.do(t, sOwner, http.MethodPatch, path, `{"allowed_email_domains":["b.test"]}`, "If-Match", tag),
		http.StatusPreconditionFailed, gen.ProblemCodePreconditionFailed)

	// an external IdP: the client secret goes to the SecretStore, the reference to the row, never to a response
	w.Exec(t, `UPDATE identity_providers SET driver = 'external' WHERE id = $1`, a.IdP)
	rec = e.do(t, sOwner, http.MethodPatch, path, `{"client_secret":"`+fakeSecret+`"}`, "If-Match", e.etag(t, sOwner, path))
	want(t, "client secret of an external IdP", rec, http.StatusOK, "")
	if strings.Contains(rec.Body.String(), fakeSecret) || !decode[gen.IdentityProvider](t, rec).ClientSecretSet {
		t.Fatalf("client secret answer: %s", rec.Body.String())
	}
	var ref string
	w.Scan(t, `SELECT client_secret_ref FROM identity_providers WHERE id = $1`, []any{a.IdP}, &ref)
	if string(e.sec.stored[ref]) != fakeSecret {
		t.Fatalf("the reference %q does not name the stored secret", ref)
	}
	if n := e.count(t, `SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND details::text LIKE '%' || $2 || '%'`, a.ID, fakeSecret); n != 0 {
		t.Fatal("the secret reached the audit")
	}
	if n := e.count(t, `SELECT count(*) FROM notification_outbox WHERE tenant_id = $1 AND kind = 'idp.config_changed'
		AND payload ->> 'origin' = 'tenant'`, a.ID); n != 2 {
		t.Fatalf("Owner notifications of the two changes: %d", n)
	}
}

// TestSecuritySettings — PUT /settings/security: Owner only, step-up; tightening applies at once; lifting a
// second-person control is a tenant approval request decided by ANOTHER Owner or Admin; PATCH /settings refuses the
// security keys.
func TestSecuritySettings(t *testing.T) {
	e := newEnv(t)
	w := e.w
	a := w.A
	owner, admin, op := w.Actor(t, authz.RoleTenantOwner, a), w.Actor(t, authz.RoleTenantAdmin, a), w.Actor(t, authz.RoleTenantOperator, a)
	sOwner, sAdmin, sOp := w.Login(t, owner), w.Login(t, admin), w.Login(t, op)
	base := "/tenants/" + a.ID.String() + "/settings"
	group := uuid.Must(uuid.NewV7())
	w.Exec(t, `INSERT INTO groups (id, tenant_id, name) VALUES ($1, $2, 'finance')`, group, a.ID)
	sec := func(fourEyes bool, groups string) string {
		fe := "false"
		if fourEyes {
			fe = "true"
		}
		return `{"enrollment":{"identity_mode":"portal","web_auth_enabled":true,"self_enroll":false,"requires_approval":false},` +
			`"node_expiry":"90d","policy":{"four_eyes":` + fe + `,"sensitive_groups":[` + groups + `]},"routes":{"four_eyes":false}}`
	}
	tag := e.etag(t, sOp, base) // TP reads (tenant.settings:read)
	want(t, "PUT by a Tenant Admin", e.do(t, sAdmin, http.MethodPut, base+"/security", sec(true, ""), "If-Match", tag),
		http.StatusForbidden, gen.ProblemCodeForbidden)
	want(t, "PUT without step-up", e.do(t, aged(w, t, owner), http.MethodPut, base+"/security", sec(true, ""), "If-Match", tag),
		http.StatusUnauthorized, gen.ProblemCodeReauthRequired)
	want(t, "an unknown sensitive group", e.do(t, sOwner, http.MethodPut, base+"/security", sec(true, `"`+uuid.NewString()+`"`),
		"If-Match", tag), http.StatusUnprocessableEntity, gen.ProblemCodeValidationFailed)
	want(t, "headscale_oidc (not in this build)", e.do(t, sOwner, http.MethodPut, base+"/security",
		strings.Replace(sec(true, ""), `"portal"`, `"headscale_oidc"`, 1), "If-Match", tag), http.StatusUnprocessableEntity,
		gen.ProblemCodeValidationFailed)
	rec := e.do(t, sOwner, http.MethodPut, base+"/security", sec(true, `"`+group.String()+`"`), "If-Match", tag)
	want(t, "tightening (4-eyes on, a sensitive group)", rec, http.StatusOK, "")
	v := decode[gen.TenantSettingsView](t, rec)
	if !v.Settings.Policy.FourEyes || len(v.Settings.Policy.SensitiveGroups) != 1 || *v.Settings.NodeExpiry != "90d" {
		t.Fatalf("settings after tightening: %+v", v.Settings)
	}
	want(t, "PATCH /settings with a security key", e.do(t, sAdmin, http.MethodPatch, base, `{"policy":{"four_eyes":false},"notifications":{"new_device":false}}`,
		"If-Match", v.Etag), http.StatusUnprocessableEntity, gen.ProblemCodeValidationFailed)
	want(t, "PATCH /settings with sensitive_groups", e.do(t, sAdmin, http.MethodPatch, base,
		`{"policy":{"sensitive_groups":[]},"notifications":{"new_device":false}}`, "If-Match", v.Etag), http.StatusUnprocessableEntity, gen.ProblemCodeValidationFailed)
	// a refused key never lets the rest of the patch through: nothing was written
	if got := decode[gen.TenantSettingsView](t, e.do(t, sOp, http.MethodGet, base, "")); got.Etag != v.Etag {
		t.Fatal("a PATCH carrying a security key changed the settings")
	}

	// lifting 4-eyes and the sensitive group: an approval request, nothing written
	rec = e.do(t, sOwner, http.MethodPut, base+"/security", sec(false, ""), "If-Match", v.Etag)
	want(t, "lifting 4-eyes", rec, http.StatusAccepted, "")
	r := decode[gen.ApprovalRequest](t, rec)
	if loc := rec.Header().Get("Location"); loc != "/api/v1/tenants/"+a.ID.String()+"/approvals/"+r.Id.String() ||
		r.Action != tenants.SecuritySettingsApprovalAction || r.Scope != "tenant" {
		t.Fatalf("202: Location %q, request %+v", loc, r)
	}
	if got := decode[gen.TenantSettingsView](t, e.do(t, sOp, http.MethodGet, base, "")); !got.Settings.Policy.FourEyes {
		t.Fatal("4-eyes lifted before the approval")
	}
	if n := e.count(t, `SELECT count(*) FROM notification_outbox WHERE tenant_id = $1 AND kind = 'approval.requested'
		AND recipient_membership_id = $2`, a.ID, admin.MembershipID); n != 1 {
		t.Fatalf("the Tenant Admin (a decider) was notified %d times", n)
	}
	approve := "/tenants/" + a.ID.String() + "/approvals/" + r.Id.String() + "/approve"
	body := `{"payload_sha256":"` + r.PayloadSha256 + `"}`
	want(t, "self-approval by the Owner", e.do(t, sOwner, http.MethodPost, approve, body), http.StatusForbidden, gen.ProblemCodeForbidden)
	want(t, "approval by a Tenant Operator", e.do(t, sOp, http.MethodPost, approve, body), http.StatusForbidden, gen.ProblemCodeForbidden)
	bAdmin := w.Login(t, w.Actor(t, authz.RoleTenantAdmin, w.B))
	want(t, "B's Admin on A's request", e.do(t, bAdmin, http.MethodPost, approve, body), http.StatusNotFound, gen.ProblemCodeNotFound)
	want(t, "approval by the Admin", e.do(t, sAdmin, http.MethodPost, approve, body), http.StatusOK, "")
	got := decode[gen.TenantSettingsView](t, e.do(t, sOp, http.MethodGet, base, ""))
	if got.Settings.Policy.FourEyes || len(got.Settings.Policy.SensitiveGroups) != 0 {
		t.Fatalf("settings after the approval: %+v", got.Settings)
	}
	if n := e.count(t, `SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND action = 'tenant.settings.security_update'
		AND details ->> 'approval_id' = $2 AND details ->> 'decided_by_identity_id' = $3`, a.ID, r.Id.String(),
		admin.IdentityID.String()); n != 1 {
		t.Fatalf("audit of the executed change: %d", n)
	}

	// regular settings: Tenant Admin, If-Match
	rec = e.do(t, sAdmin, http.MethodPatch, base, `{"notifications":{"new_device":false},"enrollment":{"preauth_key_ttl_max":"30m"}}`,
		"If-Match", got.Etag)
	want(t, "PATCH /settings by the Admin", rec, http.StatusOK, "")
	if p := decode[gen.TenantSettingsView](t, rec); p.Settings.Notifications.NewDevice || *p.Settings.Enrollment.PreauthKeyTtlMax != "30m" {
		t.Fatalf("settings after PATCH: %+v", p.Settings)
	}
	want(t, "PATCH /settings by a Tenant Operator", e.do(t, sOp, http.MethodPatch, base, `{"notifications":{"new_device":true}}`,
		"If-Match", got.Etag), http.StatusForbidden, gen.ProblemCodeForbidden)
	want(t, "PATCH /settings stale", e.do(t, sAdmin, http.MethodPatch, base, `{"notifications":{"new_device":true}}`,
		"If-Match", got.Etag), http.StatusPreconditionFailed, gen.ProblemCodePreconditionFailed)
}

// TestSuperAdminRoleAndPlatformUsers — the Super Admin role only through 2P; platform.user:assign never touches it.
func TestSuperAdminRoleAndPlatformUsers(t *testing.T) {
	e := newEnv(t)
	w := e.w
	sa1, sa2 := w.Actor(t, authz.RoleSuperAdmin, nil), w.NewActor(t, authz.RoleSuperAdmin, nil)
	po := w.Actor(t, authz.RolePlatformOperator, nil)
	viewer := w.NewActor(t, authz.RolePlatformViewer, nil)
	s1, s2, sPO := w.Login(t, sa1), w.Login(t, sa2), w.Login(t, po)
	sViewer := w.Login(t, viewer)
	vpath := "/platform/users/" + viewer.PlatformUserID.String()

	want(t, "create a Super Admin directly", e.do(t, s1, http.MethodPost, "/platform/users",
		`{"subject":"`+uuid.NewString()+`","role":"super_admin"}`, "Idempotency-Key", "k-"+uuid.NewString()),
		http.StatusForbidden, gen.ProblemCodeForbidden)
	want(t, "PATCH a Super Admin", e.do(t, s1, http.MethodPatch, "/platform/users/"+sa2.PlatformUserID.String(), `{"status":"disabled"}`,
		"If-Match", e.etag(t, s1, "/platform/users/"+sa2.PlatformUserID.String())), http.StatusForbidden, gen.ProblemCodeForbidden)
	want(t, "PATCH oneself", e.do(t, s1, http.MethodPatch, "/platform/users/"+sa1.PlatformUserID.String(), `{"role":"platform_viewer"}`,
		"If-Match", `"1"`), http.StatusForbidden, gen.ProblemCodeForbidden)
	want(t, "PATCH by a Platform Operator", e.do(t, sPO, http.MethodPatch, vpath, `{"role":"platform_support"}`, "If-Match", `"1"`),
		http.StatusForbidden, gen.ProblemCodeForbidden)
	want(t, "super-admin-role by a Platform Operator", e.do(t, sPO, http.MethodPut, vpath+"/super-admin-role",
		`{"super_admin":true,"reason":"x"}`), http.StatusForbidden, gen.ProblemCodeForbidden)

	// create (sub of the platform IdP), change the role (the person's sessions are revoked)
	sub := uuid.NewString()
	rec := e.do(t, s1, http.MethodPost, "/platform/users", `{"subject":"`+sub+`","role":"platform_viewer","display_name":"New Staff"}`,
		"Idempotency-Key", "k-create")
	want(t, "create a Platform Viewer", rec, http.StatusCreated, "")
	created := decode[gen.PlatformUser](t, rec)
	want(t, "create the same identity again", e.do(t, s1, http.MethodPost, "/platform/users",
		`{"subject":"`+sub+`","role":"platform_support"}`, "Idempotency-Key", "k-again"), http.StatusConflict, gen.ProblemCodeConflict)
	want(t, "a subject that is not the Keycloak user id", e.do(t, s1, http.MethodPost, "/platform/users",
		`{"subject":"alice@example.test","role":"platform_viewer"}`, "Idempotency-Key", "k-bad"), http.StatusUnprocessableEntity,
		gen.ProblemCodeValidationFailed)
	want(t, "PATCH the viewer", e.do(t, s1, http.MethodPatch, vpath, `{"role":"platform_support"}`, "If-Match", e.etag(t, s1, vpath)),
		http.StatusOK, "")
	want(t, "the viewer's old session", e.do(t, sViewer, http.MethodGet, "/platform/users", ""), http.StatusUnauthorized,
		gen.ProblemCodeUnauthenticated)

	// grant the Super Admin role: 202, the second Super Admin approves, the role changes under the bootstrap lock
	cpath := "/platform/users/" + created.Id.String()
	rec = e.do(t, s1, http.MethodPut, cpath+"/super-admin-role", `{"super_admin":true,"reason":"third SA"}`)
	want(t, "request the Super Admin role", rec, http.StatusAccepted, "")
	r := decode[gen.ApprovalRequest](t, rec)
	if got := decode[gen.PlatformUser](t, e.do(t, s1, http.MethodGet, cpath, "")); got.Role != gen.PlatformRolePlatformViewer {
		t.Fatalf("role before the approval: %s", got.Role)
	}
	want(t, "self-approval", e.do(t, s1, http.MethodPost, "/platform/approvals/"+r.Id.String()+"/approve",
		`{"payload_sha256":"`+r.PayloadSha256+`"}`), http.StatusForbidden, gen.ProblemCodeForbidden)
	want(t, "approval by a Platform Operator", e.do(t, sPO, http.MethodPost, "/platform/approvals/"+r.Id.String()+"/approve",
		`{"payload_sha256":"`+r.PayloadSha256+`"}`), http.StatusForbidden, gen.ProblemCodeForbidden)
	want(t, "approval by the second Super Admin", e.do(t, s2, http.MethodPost, "/platform/approvals/"+r.Id.String()+"/approve",
		`{"payload_sha256":"`+r.PayloadSha256+`"}`), http.StatusOK, "")
	if got := decode[gen.PlatformUser](t, e.do(t, s1, http.MethodGet, cpath, "")); got.Role != gen.PlatformRoleSuperAdmin {
		t.Fatalf("role after the approval: %s", got.Role)
	}
	want(t, "request what already is", e.do(t, s1, http.MethodPut, cpath+"/super-admin-role", `{"super_admin":true,"reason":"x"}`),
		http.StatusConflict, gen.ProblemCodeConflict)
	want(t, "revoke without role_after", e.do(t, s1, http.MethodPut, cpath+"/super-admin-role", `{"super_admin":false,"reason":"x"}`),
		http.StatusUnprocessableEntity, gen.ProblemCodeValidationFailed)
	if n := e.count(t, `SELECT count(*) FROM audit_events WHERE tenant_id IS NULL AND action = 'platform.user.super_admin.execute'
		AND details ->> 'decided_by_identity_id' = $1`, sa2.IdentityID.String()); n != 1 {
		t.Fatalf("platform audit of the execution: %d", n)
	}
}

// TestSettingsPlansTenantAndDeletion — system settings (closed set, read-only flag, cursors never served), plans,
// PATCH of a tenant, the deletion request.
func TestSettingsPlansTenantAndDeletion(t *testing.T) {
	e := newEnv(t)
	w := e.w
	sa, po, pv := w.Actor(t, authz.RoleSuperAdmin, nil), w.Actor(t, authz.RolePlatformOperator, nil), w.Actor(t, authz.RolePlatformViewer, nil)
	sSA, sPO, sPV := w.Login(t, sa), w.Login(t, po), w.Login(t, pv)
	w.Exec(t, `INSERT INTO system_settings (key, value) VALUES ('idp.audit_sync.admin.platform', '{"at":"x"}') ON CONFLICT DO NOTHING`)

	list := e.do(t, sPV, http.MethodGet, "/platform/settings", "")
	want(t, "list settings", list, http.StatusOK, "")
	if strings.Contains(list.Body.String(), "idp.audit_sync") || !strings.Contains(list.Body.String(), "approval.ttl_hours") {
		t.Fatalf("served settings: %s", list.Body.String())
	}
	want(t, "an internal cursor", e.do(t, sSA, http.MethodGet, "/platform/settings/idp.audit_sync.admin.platform", ""),
		http.StatusNotFound, gen.ProblemCodeNotFound)
	tag := e.etag(t, sSA, "/platform/settings/approval.ttl_hours")
	want(t, "PUT by a Platform Operator", e.do(t, sPO, http.MethodPut, "/platform/settings/approval.ttl_hours", `{"value":48}`,
		"If-Match", tag), http.StatusForbidden, gen.ProblemCodeForbidden)
	want(t, "PUT out of range", e.do(t, sSA, http.MethodPut, "/platform/settings/approval.ttl_hours", `{"value":500}`, "If-Match", tag),
		http.StatusUnprocessableEntity, gen.ProblemCodeValidationFailed)
	want(t, "PUT the maintenance flag", e.do(t, sSA, http.MethodPut, "/platform/settings/maintenance", `{"value":{"enabled":true}}`,
		"If-Match", `"0"`), http.StatusUnprocessableEntity, gen.ProblemCodeValidationFailed)
	rec := e.do(t, sSA, http.MethodPut, "/platform/settings/approval.ttl_hours", `{"value":48}`, "If-Match", tag)
	want(t, "PUT approval.ttl_hours", rec, http.StatusOK, "")
	if s := decode[gen.SystemSetting](t, rec); string(s.Value) != "48" {
		t.Fatalf("value after PUT: %s", s.Value)
	}

	// plans
	rec = e.do(t, sSA, http.MethodPost, "/platform/plans", `{"key":"pro","name":"Pro","limits":{"max_devices":10,"max_users":10}}`,
		"Idempotency-Key", "k-p1")
	want(t, "a plan without the four quota keys", rec, http.StatusUnprocessableEntity, gen.ProblemCodeValidationFailed)
	rec = e.do(t, sSA, http.MethodPost, "/platform/plans", `{"key":"pro","name":"Pro","limits":{"max_devices":10,"max_users":10,`+
		`"max_tagged_devices":2,"max_live_enrollment_credentials":2}}`, "Idempotency-Key", "k-p2")
	want(t, "create plan pro", rec, http.StatusCreated, "")
	plan := decode[gen.Plan](t, rec)
	want(t, "create plan by a Platform Support", e.do(t, w.Login(t, w.Actor(t, authz.RolePlatformSupport, nil)), http.MethodPost,
		"/platform/plans", `{"key":"x","name":"X","limits":{}}`, "Idempotency-Key", "k-p3"), http.StatusForbidden, gen.ProblemCodeForbidden)

	// PATCH a tenant: name and the plan of its live subscription
	a := w.A
	w.Exec(t, `INSERT INTO subscriptions (tenant_id, plan_id) SELECT $1, id FROM subscription_plans WHERE key = 'standard'`, a.ID)
	tpath := "/platform/tenants/" + a.ID.String()
	want(t, "PATCH a tenant without If-Match", e.do(t, sPO, http.MethodPatch, tpath, `{"name":"A2"}`),
		http.StatusPreconditionRequired, gen.ProblemCodePreconditionRequired)
	rec = e.do(t, sPO, http.MethodPatch, tpath, `{"name":"A2","plan_key":"pro","limits_override":{"max_devices":20}}`,
		"If-Match", e.etag(t, sPO, tpath))
	want(t, "PATCH a tenant", rec, http.StatusOK, "")
	tn := decode[gen.Tenant](t, rec)
	if tn.Name != "A2" || tn.Plan != "pro" || tn.Limits.MaxDevices == nil || *tn.Limits.MaxDevices != 20 || *tn.Limits.MaxUsers != 10 {
		t.Fatalf("tenant after PATCH: %+v", tn)
	}
	want(t, "PATCH a tenant to a closed plan", e.do(t, sSA, http.MethodPatch, "/platform/plans/"+plan.Id.String(),
		`{"is_active":false}`, "If-Match", plan.Etag), http.StatusOK, "")

	// the deletion request
	owner, admin := w.Actor(t, authz.RoleTenantOwner, a), w.Actor(t, authz.RoleTenantAdmin, a)
	sOwner := w.Login(t, owner)
	del := "/tenants/" + a.ID.String() + "/request-deletion"
	want(t, "deletion by a Tenant Admin", e.do(t, w.Login(t, admin), http.MethodPost, del, `{"confirm_slug":"`+a.Slug+`","reason":"x"}`),
		http.StatusForbidden, gen.ProblemCodeForbidden)
	want(t, "deletion with the wrong slug", e.do(t, sOwner, http.MethodPost, del, `{"confirm_slug":"other","reason":"x"}`),
		http.StatusUnprocessableEntity, gen.ProblemCodeValidationFailed)
	want(t, "deletion without step-up", e.do(t, aged(w, t, owner), http.MethodPost, del, `{"confirm_slug":"`+a.Slug+`","reason":"x"}`),
		http.StatusUnauthorized, gen.ProblemCodeReauthRequired)
	rec = e.do(t, sOwner, http.MethodPost, del, `{"confirm_slug":"`+a.Slug+`","reason":"closing the company"}`)
	want(t, "deletion request", rec, http.StatusOK, "")
	if d := decode[gen.TenantDeletionRequest](t, rec); !d.PlatformNotified {
		t.Fatalf("first request: %+v", d)
	}
	rec = e.do(t, sOwner, http.MethodPost, del, `{"confirm_slug":"`+a.Slug+`","reason":"again"}`)
	if d := decode[gen.TenantDeletionRequest](t, rec); d.PlatformNotified {
		t.Fatalf("second request the same day notified the platform again: %+v", d)
	}
	if n := e.count(t, `SELECT count(*) FROM audit_events WHERE tenant_id IS NULL AND action = 'platform.tenant.deletion_requested'
		AND resource_id = $1`, a.ID.String()); n != 2 {
		t.Fatalf("platform audit of the requests: %d", n)
	}
	if n := e.count(t, `SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND action = 'tenant.deletion.request'
		AND outcome = 'success'`, a.ID); n != 2 {
		t.Fatalf("tenant audit of the requests: %d", n)
	}
	var status string
	w.Scan(t, `SELECT status FROM tenants WHERE id = $1`, []any{a.ID}, &status)
	if status != "active" {
		t.Fatalf("the deletion request changed the tenant: %s", status)
	}
}
