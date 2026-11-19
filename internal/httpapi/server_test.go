package httpapi

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/gen"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/problem"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/ratelimit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/requestid"
)

// operations has one request per operation of api/openapi.yaml, as sent by a well-behaved client.
var operations = []struct {
	method, target, body, operation string
	mods                            []func(*http.Request)
}{
	{http.MethodGet, "/api/v1/auth/login?scope=tenant&tenant=tenant-a", "", "AuthLogin", nil},
	{http.MethodGet, "/api/v1/auth/callback/" + itemID + "?state=s&code=c", "", "AuthCallback", nil},
	{http.MethodPost, "/api/v1/auth/logout", "", "AuthLogout", nil},
	{http.MethodGet, "/api/v1/auth/session", "", "GetAuthSession", nil},
	{http.MethodGet, "/api/v1/auth/sessions?limit=10", "", "ListAuthSessions", nil},
	{http.MethodDelete, "/api/v1/auth/sessions/" + itemID, "", "RevokeAuthSession", nil},
	{http.MethodGet, "/api/v1/tenants", "", "ListMyTenants", nil},
	{http.MethodGet, "/api/v1/tenants/" + tenantID, "", "GetTenant", nil},
	{http.MethodGet, "/api/v1/tenants/" + tenantID + "/dashboard", "", "GetTenantDashboard", nil},
	{http.MethodGet, "/api/v1/tenants/" + tenantID + "/devices?online=true&tag=tag:server&limit=50", "", "ListDevices", nil},
	{http.MethodPost, "/api/v1/tenants/" + tenantID + "/devices/sync", "", "SyncDevices", []func(*http.Request){idempotency}},
	{http.MethodGet, "/api/v1/tenants/" + tenantID + "/devices/" + itemID, "", "GetDevice", nil},
	{http.MethodPatch, "/api/v1/tenants/" + tenantID + "/devices/" + itemID, `{"given_name":"laptop-1"}`, "RenameDevice", nil},
	{http.MethodDelete, "/api/v1/tenants/" + tenantID + "/devices/" + itemID, "", "DeleteDevice", nil},
	{http.MethodPost, "/api/v1/tenants/" + tenantID + "/devices/" + itemID + "/expire", "", "ExpireDevice", []func(*http.Request){idempotency}},
	{http.MethodGet, "/api/v1/tenants/" + tenantID + "/users", "", "ListTenantUsers", nil},
	{http.MethodGet, "/api/v1/tenants/" + tenantID + "/users/" + itemID, "", "GetTenantUser", nil},
	{http.MethodGet, "/api/v1/tenants/" + tenantID + "/audit?outcome=denied", "", "ListTenantAuditEvents", nil},
	{http.MethodGet, "/api/v1/tenants/" + tenantID + "/jobs?status=running", "", "ListTenantJobs", nil},
	{http.MethodGet, "/api/v1/tenants/" + tenantID + "/jobs/" + itemID, "", "GetTenantJob", nil},
	{http.MethodGet, "/api/v1/tenants/" + tenantID + "/notifications?unread=true", "", "ListNotifications", nil},
	{http.MethodPost, "/api/v1/tenants/" + tenantID + "/notifications/" + itemID + "/read", "", "MarkNotificationRead", nil}, // P4-T04
	// relay (P3-T05c)
	{http.MethodGet, "/api/v1/tenants/" + tenantID + "/relay", "", "GetTenantRelay", nil},
	{http.MethodGet, "/api/v1/platform/relay-regions?limit=10", "", "ListPlatformRelayRegions", nil},
	{http.MethodGet, "/api/v1/platform/tenants?status=active", "", "ListPlatformTenants", nil},
	{http.MethodPost, "/api/v1/platform/instances/" + itemID + "/backup", "", "BackupPlatformInstance", []func(*http.Request){idempotency}},
	{http.MethodPost, "/api/v1/platform/instances/" + itemID + "/restore", `{"backup_id":"` + itemID + `","reason":"incident 7"}`, "RestorePlatformInstance", []func(*http.Request){idempotency}},
	{http.MethodGet, "/api/v1/platform/backups", "", "ListPlatformBackups", nil},
	{http.MethodGet, "/api/v1/platform/tenants/" + tenantID, "", "GetPlatformTenant", nil},
	{http.MethodGet, "/api/v1/platform/instances", "", "ListPlatformInstances", nil},
	{http.MethodGet, "/api/v1/platform/tenants/" + tenantID + "/jobs?limit=5&status=queued", "", "ListPlatformTenantJobs", nil},
	{http.MethodGet, "/api/v1/platform/tenants/" + tenantID + "/instances", "", "ListPlatformTenantInstances", nil},
	{http.MethodGet, "/api/v1/platform/tenants/" + tenantID + "/relay-regions", "", "ListPlatformTenantRelayRegions", nil},
	{http.MethodGet, "/api/v1/platform/instances/" + itemID, "", "GetPlatformInstance", nil},
	// instance.reconfigure (P3-T13)
	{http.MethodPost, "/api/v1/platform/instances/" + itemID + "/reconfigure", `{"node_expiry_days":30}`, "ReconfigurePlatformInstance", []func(*http.Request){idempotency}},
	// instance.restart, instance.upgrade (P3-T13a)
	{http.MethodPost, "/api/v1/platform/instances/" + itemID + "/restart", "", "RestartPlatformInstance", []func(*http.Request){idempotency}},
	{http.MethodPost, "/api/v1/platform/instances/" + itemID + "/upgrade", `{"image_digest":"sha256:` + strings.Repeat("e", 64) + `"}`, "UpgradePlatformInstance", []func(*http.Request){idempotency}},
	// quarantine / release (P3-T18)
	{http.MethodPost, "/api/v1/platform/instances/" + itemID + "/quarantine", `{"reason":"suspected compromise"}`, "QuarantinePlatformInstance", []func(*http.Request){idempotency}},
	{http.MethodPost, "/api/v1/platform/instances/" + itemID + "/release", `{"reason":"investigation closed"}`, "ReleasePlatformInstance", []func(*http.Request){idempotency}},
	// platform hosts (P3-T04)
	{http.MethodGet, "/api/v1/platform/hosts?status=active", "", "ListPlatformHosts", nil},
	{http.MethodPost, "/api/v1/platform/hosts", `{"name":"h1","region":"lab","run_uid_range":{"first":30000,"last":39999},"tenant_net_pool":"10.250.0.0/16"}`, "CreatePlatformHost", []func(*http.Request){idempotency}},
	{http.MethodGet, "/api/v1/platform/hosts/" + itemID, "", "GetPlatformHost", nil},
	{http.MethodPatch, "/api/v1/platform/hosts/" + itemID, `{"capacity":{"max_instances":10}}`, "UpdatePlatformHost", nil},
	{http.MethodGet, "/api/v1/platform/health", "", "GetPlatformHealth", nil},
	{http.MethodGet, "/api/v1/platform/audit", "", "ListPlatformAuditEvents", nil},
	{http.MethodGet, "/api/v1/platform/jobs?kind=inventory.sync", "", "ListPlatformJobs", nil},
	{http.MethodGet, "/api/v1/platform/jobs/" + itemID, "", "GetPlatformJob", nil},
	// dual control (P3-T04a) and invitations (P3-T05a)
	{http.MethodGet, "/api/v1/platform/approvals?status=pending&action=platform.instance.restore", "", "ListPlatformApprovals", nil},
	{http.MethodGet, "/api/v1/platform/approvals/" + itemID, "", "GetPlatformApproval", nil},
	{http.MethodPost, "/api/v1/platform/approvals/" + itemID + "/approve", `{"payload_sha256":"` + strings.Repeat("a", 64) + `"}`, "ApprovePlatformApproval", nil},
	{http.MethodPost, "/api/v1/platform/approvals/" + itemID + "/reject", "", "RejectPlatformApproval", nil},
	{http.MethodGet, "/api/v1/tenants/" + tenantID + "/approvals?status=executed", "", "ListTenantApprovals", nil},
	{http.MethodGet, "/api/v1/tenants/" + tenantID + "/approvals/" + itemID, "", "GetTenantApproval", nil},
	{http.MethodPost, "/api/v1/tenants/" + tenantID + "/approvals/" + itemID + "/approve", `{"payload_sha256":"` + strings.Repeat("b", 64) + `"}`, "ApproveTenantApproval", nil},
	{http.MethodPost, "/api/v1/tenants/" + tenantID + "/approvals/" + itemID + "/reject", "", "RejectTenantApproval", nil},
	{http.MethodGet, "/api/v1/tenants/" + tenantID + "/invitations?status=pending", "", "ListTenantInvitations", nil},
	{http.MethodPost, "/api/v1/tenants/" + tenantID + "/invitations", `{"email":"a@example.test","role":"tenant_viewer"}`, "CreateTenantInvitation", []func(*http.Request){idempotency}},
	{http.MethodDelete, "/api/v1/tenants/" + tenantID + "/invitations/" + itemID, "", "RevokeTenantInvitation", nil},
	{http.MethodPut, "/api/v1/tenants/" + tenantID + "/devices/" + itemID + "/tags", `{"tags":["tag:web"]}`, "SetDeviceTags", nil},
	{http.MethodGet, "/api/v1/tenants/" + tenantID + "/tags", "", "ListTenantTags", nil},
	{http.MethodPost, "/api/v1/tenants/" + tenantID + "/tags", `{"name":"tag:web"}`, "CreateTenantTag", []func(*http.Request){idempotency}},
	{http.MethodPatch, "/api/v1/tenants/" + tenantID + "/tags/" + itemID, `{"description":"web"}`, "UpdateTenantTag", nil},
	{http.MethodDelete, "/api/v1/tenants/" + tenantID + "/tags/" + itemID, "", "DeleteTenantTag", nil},
	{http.MethodGet, "/api/v1/tenants/" + tenantID + "/policies", "", "ListTenantPolicies", nil},
	{http.MethodPost, "/api/v1/tenants/" + tenantID + "/policies", `{"source":{"grants":[]}}`, "CreateTenantPolicy", []func(*http.Request){idempotency}},
	{http.MethodGet, "/api/v1/tenants/" + tenantID + "/policies/current", "", "GetCurrentTenantPolicy", nil},
	{http.MethodGet, "/api/v1/tenants/" + tenantID + "/policies/" + itemID, "", "GetTenantPolicy", nil},
	{http.MethodPatch, "/api/v1/tenants/" + tenantID + "/policies/" + itemID, `{"source":{"grants":[]}}`, "UpdateTenantPolicy", nil},
	{http.MethodPost, "/api/v1/tenants/" + tenantID + "/policies/" + itemID + "/validate", "", "ValidateTenantPolicy", nil},
	{http.MethodPost, "/api/v1/tenants/" + tenantID + "/policies/" + itemID + "/submit", "", "SubmitTenantPolicy", nil},
	{http.MethodPost, "/api/v1/tenants/" + tenantID + "/policies/" + itemID + "/approve", `{"content_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`, "ApproveTenantPolicy", nil},
	{http.MethodPost, "/api/v1/tenants/" + tenantID + "/policies/" + itemID + "/reject", `{"reason":"no"}`, "RejectTenantPolicy", nil},
	{http.MethodPost, "/api/v1/tenants/" + tenantID + "/policies/" + itemID + "/apply", "", "ApplyTenantPolicy", []func(*http.Request){idempotency}},
	{http.MethodPost, "/api/v1/tenants/" + tenantID + "/policies/" + itemID + "/rollback", "", "RollbackTenantPolicy", []func(*http.Request){idempotency}},
	{http.MethodGet, "/api/v1/tenants/" + tenantID + "/policies/" + itemID + "/diff", "", "DiffTenantPolicy", nil},
	{http.MethodPost, "/api/v1/tenants/" + tenantID + "/invitations/" + itemID + "/resend", "", "ResendTenantInvitation", nil},
	// administration (P4-T03a)
	{http.MethodPatch, "/api/v1/platform/tenants/" + tenantID, `{"name":"Acme 2"}`, "UpdatePlatformTenant", nil},
	{http.MethodGet, "/api/v1/tenants/" + tenantID + "/settings", "", "GetTenantSettings", nil},
	{http.MethodPatch, "/api/v1/tenants/" + tenantID + "/settings", `{"notifications":{"new_device":false}}`, "UpdateTenantSettings", nil},
	{http.MethodPut, "/api/v1/tenants/" + tenantID + "/settings/security", `{"enrollment":{"identity_mode":"portal","web_auth_enabled":true,"self_enroll":false,"requires_approval":false},"node_expiry":null,"policy":{"four_eyes":true,"sensitive_groups":[]},"routes":{"four_eyes":false}}`, "PutTenantSecuritySettings", nil},
	{http.MethodGet, "/api/v1/tenants/" + tenantID + "/identity-provider", "", "GetTenantIdentityProvider", nil},
	{http.MethodPatch, "/api/v1/tenants/" + tenantID + "/identity-provider", `{"allowed_email_domains":["acme.example"]}`, "UpdateTenantIdentityProvider", nil},
	{http.MethodPost, "/api/v1/tenants/" + tenantID + "/request-deletion", `{"confirm_slug":"acme","reason":"closing"}`, "RequestTenantDeletion", nil},
	{http.MethodGet, "/api/v1/platform/users?status=active&role=platform_viewer&limit=5", "", "ListPlatformUsers", nil},
	{http.MethodPost, "/api/v1/platform/users", `{"subject":"0194f3a2-7c1e-7d40-8a55-0d1b2c3e4f52","role":"platform_viewer"}`, "CreatePlatformUser", []func(*http.Request){idempotency}},
	{http.MethodGet, "/api/v1/platform/users/" + itemID, "", "GetPlatformUser", nil},
	{http.MethodPatch, "/api/v1/platform/users/" + itemID, `{"status":"disabled"}`, "UpdatePlatformUser", nil},
	{http.MethodDelete, "/api/v1/platform/users/" + itemID, "", "DeletePlatformUser", nil},
	{http.MethodPut, "/api/v1/platform/users/" + itemID + "/super-admin-role", `{"super_admin":true,"reason":"second SA"}`, "SetPlatformUserSuperAdminRole", nil},
	{http.MethodGet, "/api/v1/platform/settings", "", "ListPlatformSettings", nil},
	{http.MethodGet, "/api/v1/platform/settings/approval.ttl_hours", "", "GetPlatformSetting", nil},
	{http.MethodPut, "/api/v1/platform/settings/approval.ttl_hours", `{"value":48}`, "PutPlatformSetting", nil},
	{http.MethodGet, "/api/v1/platform/identity-providers?scope=tenant&limit=5", "", "ListPlatformIdentityProviders", nil},
	{http.MethodGet, "/api/v1/platform/identity-providers/" + itemID, "", "GetPlatformIdentityProvider", nil},
	{http.MethodPatch, "/api/v1/platform/identity-providers/" + itemID, `{"required_claims":{"hd":"acme.example"}}`, "UpdatePlatformIdentityProvider", nil},
	{http.MethodGet, "/api/v1/platform/plans", "", "ListPlatformPlans", nil},
	{http.MethodPost, "/api/v1/platform/plans", `{"key":"pro","name":"Pro","limits":{"max_devices":10,"max_users":10,"max_tagged_devices":1,"max_live_enrollment_credentials":1}}`, "CreatePlatformPlan", []func(*http.Request){idempotency}},
	{http.MethodGet, "/api/v1/platform/plans/" + itemID, "", "GetPlatformPlan", nil},
	{http.MethodPatch, "/api/v1/platform/plans/" + itemID, `{"is_active":false}`, "UpdatePlatformPlan", nil},
	// users (write) and groups (P4-T09)
	{http.MethodPatch, "/api/v1/tenants/" + tenantID + "/users/" + itemID, `{"status":"locked"}`, "UpdateTenantUser", nil},
	{http.MethodDelete, "/api/v1/tenants/" + tenantID + "/users/" + itemID, "", "OffboardTenantUser", nil},
	{http.MethodPut, "/api/v1/tenants/" + tenantID + "/users/" + itemID + "/role", `{"role":"tenant_viewer"}`, "SetTenantUserRole", nil},
	{http.MethodPut, "/api/v1/tenants/" + tenantID + "/users/" + itemID + "/admin-role", `{"role":"tenant_admin"}`, "SetTenantUserAdminRole", nil},
	{http.MethodDelete, "/api/v1/tenants/" + tenantID + "/users/" + itemID + "/sessions", "", "RevokeTenantUserSessions", nil},
	{http.MethodPost, "/api/v1/tenants/" + tenantID + "/ownership-transfer", `{"membership_id":"` + itemID + `"}`, "TransferTenantOwnership", nil},
	{http.MethodGet, "/api/v1/tenants/" + tenantID + "/groups?q=ops", "", "ListTenantGroups", nil},
	{http.MethodPost, "/api/v1/tenants/" + tenantID + "/groups", `{"name":"ops"}`, "CreateTenantGroup", []func(*http.Request){idempotency}},
	{http.MethodGet, "/api/v1/tenants/" + tenantID + "/groups/" + itemID, "", "GetTenantGroup", nil},
	{http.MethodPatch, "/api/v1/tenants/" + tenantID + "/groups/" + itemID, `{"description":"x"}`, "UpdateTenantGroup", nil},
	{http.MethodDelete, "/api/v1/tenants/" + tenantID + "/groups/" + itemID, "", "DeleteTenantGroup", nil},
	{http.MethodPut, "/api/v1/tenants/" + tenantID + "/groups/" + itemID + "/members", `{"membership_ids":[]}`, "SetTenantGroupMembers", nil},
	{http.MethodGet, "/api/v1/platform/idp-console/sessions?limit=5", "", "ListIdpConsoleSessions", nil},
	{http.MethodPost, "/api/v1/platform/idp-console/sessions", `{"reason":"ticket 1","duration_minutes":15}`, "RequestIdpConsoleSession", []func(*http.Request){idempotency}},
	{http.MethodPost, "/api/v1/platform/tenants", `{"slug":"acme","name":"Acme","plan_key":"standard","owner_email":"owner@acme.example","identity_provider":{"driver":"keycloak"}}`, "CreatePlatformTenant", []func(*http.Request){idempotency}},
	{http.MethodPost, "/api/v1/platform/jobs/" + itemID + "/retry", "", "RetryPlatformJob", []func(*http.Request){idempotency}},
	{http.MethodPost, "/api/v1/platform/jobs/" + itemID + "/cancel", "", "CancelPlatformJob", []func(*http.Request){idempotency}},
	{http.MethodPost, "/api/v1/platform/jobs/" + itemID + "/rollback", "", "RollbackPlatformJob", []func(*http.Request){idempotency}},
	// enrollment (P4-T06)
	{http.MethodGet, "/api/v1/tenants/" + tenantID + "/enrollment/requests?status=issued", "", "ListEnrollmentRequests", nil},
	{http.MethodPost, "/api/v1/tenants/" + tenantID + "/enrollment/requests", `{"method":"web_auth"}`, "CreateEnrollmentRequest", []func(*http.Request){idempotency}},
	{http.MethodGet, "/api/v1/tenants/" + tenantID + "/enrollment/requests/" + itemID, "", "GetEnrollmentRequest", nil},
	{http.MethodPost, "/api/v1/tenants/" + tenantID + "/enrollment/requests/" + itemID + "/approve", "", "ApproveEnrollmentRequest", nil},
	{http.MethodPost, "/api/v1/tenants/" + tenantID + "/enrollment/requests/" + itemID + "/reject", "", "RejectEnrollmentRequest", nil},
	{http.MethodPost, "/api/v1/tenants/" + tenantID + "/enrollment/requests/" + itemID + "/start", "", "StartEnrollmentRequest", nil},
	{http.MethodPost, "/api/v1/tenants/" + tenantID + "/enrollment/requests/" + itemID + "/revoke", "", "RevokeEnrollmentRequest", nil},
	{http.MethodPost, "/api/v1/tenants/" + tenantID + "/enrollment/keys", `{"tags":["tag:web"]}`, "CreateEnrollmentKey", []func(*http.Request){idempotency}},
	{http.MethodPost, "/api/v1/tenants/" + tenantID + "/enrollment/web-auth/claim", `{"auth_id":"hskey-authreq-` + strings.Repeat("a", 24) + `"}`, "ClaimEnrollmentWebAuth", nil},
	{http.MethodGet, "/api/v1/tenants/" + tenantID + "/enrollment/instructions?os=linux", "", "GetEnrollmentInstructions", nil},
	// suspend / resume (P3-T08)
	{http.MethodPost, "/api/v1/platform/tenants/" + tenantID + "/suspend", "", "SuspendPlatformTenant", []func(*http.Request){idempotency}},
	{http.MethodPost, "/api/v1/platform/tenants/" + tenantID + "/resume", "", "ResumePlatformTenant", []func(*http.Request){idempotency}},
	// deprovision (P3-T09)
	{http.MethodDelete, "/api/v1/platform/tenants/" + tenantID, `{"confirm_slug":"acme","reason":"ticket 1"}`, "DeletePlatformTenant", []func(*http.Request){idempotency}},
}

// TestEveryOperationAnswers501: with no handler set mounted, every operation of the spec is routed under /api/v1
// through the whole chain and answers 501 not_implemented naming the operation.
func TestEveryOperationAnswers501(t *testing.T) {
	e := newEnv(t, Options{})
	for _, op := range operations {
		w := e.do(op.method, op.target, op.body, op.mods...)
		if w.Code != http.StatusNotImplemented {
			t.Errorf("%s %s: status %d: %s", op.method, op.target, w.Code, w.Body.String())
			continue
		}
		p := problemOf(t, w)
		path, _, _ := strings.Cut(op.target, "?")
		if p.Code != gen.ProblemCodeNotImplemented || p.Detail == nil || !strings.Contains(*p.Detail, op.operation) ||
			p.Instance == nil || *p.Instance != path {
			t.Errorf("%s %s: problem %+v", op.method, op.target, p)
		}
		line := e.accessLine(p.RequestId)
		route, _ := line["route"].(string)
		if line["operation"] != op.operation || !strings.HasPrefix(route, op.method+" /api/v1/") ||
			line["problem"] != string(gen.ProblemCodeNotImplemented) || line["status"] != float64(501) || line["level"] != "INFO" {
			t.Errorf("%s %s: access log %v", op.method, op.target, line)
		}
	}
	var want, got []string
	iface := reflect.TypeFor[gen.StrictServerInterface]()
	for i := range iface.NumMethod() {
		want = append(want, iface.Method(i).Name)
	}
	for _, op := range operations {
		got = append(got, op.operation)
	}
	slices.Sort(want)
	slices.Sort(got)
	if !slices.Equal(want, got) {
		t.Fatalf("operation table out of date:\n spec  %v\n table %v", want, got)
	}
}

// TestUnknownRoutes: anything the spec does not declare — path, method, `:action` suffix, the internal endpoints —
// answers 404 not_found as a problem (never ServeMux's plain-text 404/405).
func TestUnknownRoutes(t *testing.T) {
	e := newEnv(t, Options{})
	for _, c := range []struct{ method, target string }{
		{http.MethodGet, "/api/v1/nope"},
		{http.MethodGet, "/api/v1"},
		{http.MethodGet, "/"},
		{http.MethodGet, "/healthz"},
		{http.MethodGet, "/metrics"},
		{http.MethodGet, "/api/v1/internal/edge/ask?domain=x"},
		{http.MethodPut, "/api/v1/tenants/" + tenantID},
		{http.MethodPost, "/api/v1/tenants/" + tenantID + "/devices/" + itemID + ":expire"},
		{http.MethodOptions, "/api/v1/tenants"},
		{"PROPFIND", "/api/v1/tenants"},
	} {
		w := e.do(c.method, c.target, "")
		if w.Code != http.StatusNotFound {
			t.Errorf("%s %s: status %d: %s", c.method, c.target, w.Code, w.Body.String())
			continue
		}
		p := problemOf(t, w)
		line := e.accessLine(p.RequestId)
		if p.Code != gen.ProblemCodeNotFound || w.Header().Get("Allow") != "" || line["route"] != nil || line["operation"] != nil {
			t.Errorf("%s %s: problem %+v, Allow %q, log %v", c.method, c.target, p, w.Header().Get("Allow"), line)
		}
		if c.method == "PROPFIND" && line["method"] != "OTHER" {
			t.Errorf("unknown method logged as %v", line["method"])
		}
	}
}

// probe is a handler set that records what the chain made available to the handler.
type probe struct {
	NotImplemented
	mu        sync.Mutex
	requestID string
	operation string
	clientIP  string
	respond   func(ctx context.Context) error
}

func (p *probe) ListMyTenants(ctx context.Context, _ gen.ListMyTenantsRequestObject) (gen.ListMyTenantsResponseObject, error) {
	p.mu.Lock()
	p.requestID, p.operation, p.clientIP = requestid.From(ctx), Operation(ctx), ClientIP(ctx).String()
	respond := p.respond
	p.mu.Unlock()
	if respond != nil {
		if err := respond(ctx); err != nil {
			return nil, err
		}
	}
	return gen.ListMyTenants200JSONResponse{Items: []gen.Tenant{}}, nil
}

// TestRequestID: a well-formed X-Request-Id is reused, anything else is replaced by a UUIDv7; the same id is in the
// response header, the problem, the access log, the handler context and every log line written with that context.
func TestRequestID(t *testing.T) {
	set := &probe{}
	e := newEnv(t, Options{Handlers: Handlers{Tenants: set}, Hooks: Hooks{Authz: passAuthz}})
	set.respond = func(ctx context.Context) error {
		e.log.InfoContext(ctx, "inside handler") // any code logging with the request context gets its id
		return nil
	}
	cases := []struct {
		sent  string
		reuse bool
	}{
		{"", false},
		{"edge-7f3a.42:x_y", true},
		{"0194f3a2-7c1e-7d40-8a55-0d1b2c3e4f59", true},
		{"has space", false},
		{strings.Repeat("a", requestid.MaxLen+1), false},
		{"hskey-api-planted", false},
	}
	for _, c := range cases {
		var mods []func(*http.Request)
		if c.sent != "" {
			mods = append(mods, header(requestid.Header, c.sent))
		}
		w := e.do(http.MethodGet, "/api/v1/tenants", "", mods...)
		id := w.Header().Get(requestid.Header)
		if w.Code != http.StatusOK || (c.reuse && id != c.sent) || (!c.reuse && id == c.sent) {
			t.Errorf("sent %q: status %d, id %q", c.sent, w.Code, id)
			continue
		}
		if !c.reuse {
			if u, err := uuid.Parse(id); err != nil || u.Version() != 7 {
				t.Errorf("sent %q: generated id %q is not a UUIDv7", c.sent, id)
			}
		}
		set.mu.Lock()
		if set.requestID != id || set.operation != "ListMyTenants" || set.clientIP != "192.0.2.1" {
			t.Errorf("handler context: id %q op %q ip %q (want %s)", set.requestID, set.operation, set.clientIP, id)
		}
		set.mu.Unlock()
		inside := 0
		for _, rec := range e.lines() {
			if rec["msg"] == "inside handler" && rec["request_id"] == id {
				inside++
			}
		}
		if line := e.accessLine(id); inside != 1 || line["status"] != float64(200) || line["route"] != "GET /api/v1/tenants" {
			t.Errorf("sent %q: %d handler lines, access line %v", c.sent, inside, line)
		}
	}
	// The problem of an error carries the same id as the header.
	w := e.do(http.MethodGet, "/api/v1/nope", "", header(requestid.Header, "rid-404"))
	if p := problemOf(t, w); p.RequestId != "rid-404" {
		t.Errorf("problem request_id %q", p.RequestId)
	}
}

// TestParamBindingErrors: invalid path, query or header parameters answer 422 naming the parameter, before any hook
// of the strict layer or handler runs.
func TestParamBindingErrors(t *testing.T) {
	authzCalls := 0
	e := newEnv(t, Options{Handlers: Handlers{Tenants: &probe{}}, Hooks: Hooks{Authz: func(f gen.StrictHandlerFunc, op string) gen.StrictHandlerFunc {
		authzCalls++
		return f
	}}})
	authzCalls = 0 // New does not call the hook; requests do
	for _, c := range []struct {
		method, target string
		mods           []func(*http.Request)
		field, code    string
	}{
		{http.MethodGet, "/api/v1/tenants/not-a-uuid/devices", nil, "tenantId", "invalid_format"},
		{http.MethodGet, "/api/v1/tenants/" + tenantID + "/devices/42", nil, "deviceId", "invalid_format"},
		{http.MethodPost, "/api/v1/tenants/" + tenantID + "/devices/sync", nil, "Idempotency-Key", "required"},
		{http.MethodGet, "/api/v1/auth/login", nil, "scope", "required"},
		{http.MethodGet, "/api/v1/tenants/" + tenantID + "/devices?limit=abc", nil, "limit", "invalid_format"},
	} {
		w := e.do(c.method, c.target, "", c.mods...)
		p := problemOf(t, w)
		if w.Code != http.StatusUnprocessableEntity || p.Code != gen.ProblemCodeValidationFailed || p.Errors == nil ||
			len(*p.Errors) != 1 || (*p.Errors)[0].Field != c.field || (*p.Errors)[0].Code != c.code {
			t.Errorf("%s %s: %d %+v", c.method, c.target, w.Code, p)
			continue
		}
		if line := e.accessLine(p.RequestId); line["route"] == nil || line["operation"] != nil {
			t.Errorf("%s %s: binding errors happen after routing, before the strict layer: %v", c.method, c.target, line)
		}
	}
	if authzCalls != 0 {
		t.Errorf("the authz hook ran %d times for requests rejected by binding", authzCalls)
	}
}

// TestBodyErrors: request bodies above the limit (declared or streamed), malformed or mistyped JSON answer 422.
func TestBodyErrors(t *testing.T) {
	e := newEnv(t, Options{MaxBodyBytes: 64})
	target := "/api/v1/tenants/" + tenantID + "/devices/" + itemID
	big := `{"given_name":"` + strings.Repeat("a", 100) + `"}`
	unknownLength := func(r *http.Request) { r.ContentLength = -1 }
	for _, c := range []struct {
		name, body  string
		mods        []func(*http.Request)
		field, code string
	}{
		{"declared too large", big, nil, "body", "too_large"},
		{"streamed too large", big, []func(*http.Request){unknownLength}, "body", "too_large"},
		{"malformed", `{"given_name":`, nil, "body", "invalid_json"},
		{"wrong type", `{"given_name":42}`, nil, "given_name", "invalid_type"},
		{"empty", "", nil, "body", "required"},
	} {
		w := e.do(http.MethodPatch, target, c.body, c.mods...)
		p := problemOf(t, w)
		if w.Code != http.StatusUnprocessableEntity || p.Errors == nil || len(*p.Errors) != 1 ||
			(*p.Errors)[0].Field != c.field || (*p.Errors)[0].Code != c.code {
			t.Errorf("%s: %d %+v", c.name, w.Code, p)
		}
	}
	// A body within the limit reaches the (not implemented) handler.
	if w := e.do(http.MethodPatch, target, `{"given_name":"ok"}`); w.Code != http.StatusNotImplemented {
		t.Errorf("small body: status %d", w.Code)
	}
}

// panicky is a handler set whose operations panic.
type panicky struct{ NotImplemented }

func (panicky) ListMyTenants(context.Context, gen.ListMyTenantsRequestObject) (gen.ListMyTenantsResponseObject, error) {
	panic("boom: token " + canary)
}

func (panicky) GetTenant(_ context.Context, req gen.GetTenantRequestObject) (gen.GetTenantResponseObject, error) {
	// one word, then an index past its end: runtime error "index out of range [2] with length 1"
	words := strings.Fields(req.TenantId.String())
	return nil, fmt.Errorf("unreachable %s", words[len(words)+1])
}

func (panicky) ListPlatformTenants(context.Context, gen.ListPlatformTenantsRequestObject) (gen.ListPlatformTenantsResponseObject, error) {
	panic(fmt.Errorf("wrapped: %w", errors.New(canary)))
}

// TestPanicRecovery: a panic answers 500 internal_error; the log keeps type and stack but never the panic value
// (runtime errors excepted); the server keeps serving.
func TestPanicRecovery(t *testing.T) {
	e := newEnv(t, Options{Handlers: Handlers{Tenants: panicky{}}, Hooks: Hooks{Authz: passAuthz}})
	for _, c := range []struct{ target, panicType, message string }{
		{"/api/v1/tenants", "string", ""},
		{"/api/v1/tenants/" + tenantID, "runtime.boundsError", "runtime error: index out of range [2] with length 1"},
		{"/api/v1/platform/tenants", "*fmt.wrapError", ""},
	} {
		w := e.do(http.MethodGet, c.target, "")
		p := problemOf(t, w)
		if w.Code != 500 || p.Code != gen.ProblemCodeInternalError || strings.Contains(w.Body.String(), canary) ||
			strings.Contains(w.Body.String(), "runtime") || strings.Contains(w.Body.String(), "goroutine") {
			t.Errorf("%s: %d %s", c.target, w.Code, w.Body.String())
		}
		var panicLine map[string]any
		for _, rec := range e.lines() {
			if rec["msg"] == "panic recovered" && rec["request_id"] == p.RequestId {
				panicLine = rec
			}
		}
		if panicLine == nil || panicLine["panic_type"] != c.panicType || !strings.Contains(fmt.Sprint(panicLine["stack"]), "goroutine") {
			t.Errorf("%s: panic log %v", c.target, panicLine)
		} else if msg, _ := panicLine["panic"].(string); msg != c.message {
			t.Errorf("%s: logged panic message %q, want %q", c.target, msg, c.message)
		}
		if line := e.accessLine(p.RequestId); line["level"] != "ERROR" || line["status"] != float64(500) || line["problem"] != "internal_error" {
			t.Errorf("%s: access log %v", c.target, line)
		}
	}
	if strings.Contains(e.logs.String(), canary) {
		t.Fatalf("panic value logged:\n%s", e.logs.String())
	}
	if w := e.do(http.MethodGet, "/api/v1/platform/health", ""); w.Code != http.StatusNotImplemented {
		t.Fatalf("server stopped serving after panics: %d", w.Code)
	}
}

// TestPanicAfterResponseStarted: the connection is aborted (the client sees a truncated response, never a problem
// glued to a partial body) and the access log marks the request aborted.
func TestPanicAfterResponseStarted(t *testing.T) {
	logs := &syncBuffer{}
	half := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"items":[`))
			_ = http.NewResponseController(w).Flush()
			panic("late: " + canary)
		})
	}
	h, err := New(Options{Logger: newLogger(logs), Hooks: Hooks{CSRF: half}})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	defer srv.Close()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/api/v1/tenants", nil)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err == nil || resp.StatusCode != http.StatusOK || strings.Contains(string(body), "problem") {
		t.Fatalf("status %d, body %q, read error %v: want a truncated 200", resp.StatusCode, body, err)
	}
	srv.Close() // waits for the handler, so the access line is written
	out := logs.String()
	if !strings.Contains(out, `"aborted":true`) || !strings.Contains(out, `"msg":"panic recovered"`) || strings.Contains(out, canary) {
		t.Fatalf("log:\n%s", out)
	}
}

// codeSet answers GetTenant with the problem chosen by the test.
type codeSet struct {
	NotImplemented
	err error
}

func (c *codeSet) GetTenant(context.Context, gen.GetTenantRequestObject) (gen.GetTenantResponseObject, error) {
	return nil, c.err
}

// TestProblemsEndToEnd: every code a handler can return reaches the client with its §13.1 status, the problem+json
// content type and the RFC 9457 fields; wrapped problems are found; other errors become a generic 500 whose text goes
// to the access log only (redacted).
func TestProblemsEndToEnd(t *testing.T) {
	set := &codeSet{}
	e := newEnv(t, Options{Handlers: Handlers{Tenants: set}, Hooks: Hooks{Authz: passAuthz}})
	target := "/api/v1/tenants/" + tenantID
	codes := []gen.ProblemCode{
		gen.ProblemCodeUnauthenticated, gen.ProblemCodeReauthRequired, gen.ProblemCodeForbidden, gen.ProblemCodeTenantSuspended,
		gen.ProblemCodeQuotaExceeded, gen.ProblemCodeNotFound, gen.ProblemCodeConflict, gen.ProblemCodePreconditionFailed,
		gen.ProblemCodePreconditionRequired, gen.ProblemCodeValidationFailed, gen.ProblemCodeIdempotencyKeyReuse,
		gen.ProblemCodeRateLimited, gen.ProblemCodeUpstreamRejected, gen.ProblemCodeInstanceUnavailable,
		gen.ProblemCodeInternalError, gen.ProblemCodeNotImplemented,
	}
	statuses := map[int]bool{}
	levels := map[gen.ProblemCode]string{ // access log level: only an internal error is an incident
		gen.ProblemCodeInternalError: "ERROR", gen.ProblemCodeUpstreamRejected: "WARN",
		gen.ProblemCodeInstanceUnavailable: "WARN", gen.ProblemCodeRateLimited: "WARN",
	}
	for _, code := range codes {
		set.err = problem.New(code, "detail of "+string(code))
		w := e.do(http.MethodGet, target, "")
		p := problemOf(t, w)
		statuses[w.Code] = true
		if w.Code != problem.Status(code) || p.Code != code || p.Detail == nil || *p.Detail != "detail of "+string(code) ||
			p.Instance == nil || *p.Instance != target || w.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("%s: %d %+v", code, w.Code, p)
		}
		want := levels[code]
		if want == "" {
			want = "INFO"
		}
		if line := e.accessLine(p.RequestId); line["level"] != want || line["problem"] != string(code) || line["error"] != nil {
			t.Errorf("%s: access line %v, want level %s and no error text for a bare problem", code, line, want)
		}
	}
	for _, st := range []int{401, 403, 404, 409, 412, 422, 428, 429, 500, 501, 502, 503} {
		if !statuses[st] {
			t.Errorf("status %d not exercised", st)
		}
	}

	// Wrapped problem, with Retry-After.
	set.err = fmt.Errorf("devices: %w", &problem.Error{Code: gen.ProblemCodeConflict, Detail: "in flight", RetryAfter: 3 * time.Second})
	if w := e.do(http.MethodGet, target, ""); w.Code != http.StatusConflict || w.Header().Get("Retry-After") != "3" {
		t.Errorf("wrapped conflict: %d Retry-After %q", w.Code, w.Header().Get("Retry-After"))
	}

	// Any other error: generic 500; the cause is logged on the access line, redacted.
	set.err = errors.New("headscale said 401 for hskey-api-abcdef-" + canary + " (Authorization: Bearer " + canary + ")")
	w := e.do(http.MethodGet, target, "")
	p := problemOf(t, w)
	if w.Code != 500 || p.Code != gen.ProblemCodeInternalError || strings.Contains(w.Body.String(), "headscale") {
		t.Errorf("plain error: %d %s", w.Code, w.Body.String())
	}
	line := e.accessLine(p.RequestId)
	if errText, _ := line["error"].(string); line["level"] != "ERROR" || !strings.Contains(errText, "headscale said 401") ||
		strings.Contains(errText, canary) {
		t.Errorf("access line of a plain error: %v", line)
	}

	// A canceled request is not an incident.
	set.err = context.Canceled
	w = e.do(http.MethodGet, target, "")
	if line := e.accessLine(problemOf(t, w).RequestId); line["level"] != "INFO" || line["canceled"] != true {
		t.Errorf("canceled: %v", line)
	}
}

// TestHooks: order of the slots, authz denial, a session hook answering by itself, and deny-by-default when handler
// sets are mounted without an authz hook.
func TestHooks(t *testing.T) {
	if _, err := New(Options{Logger: discardLogger(), Handlers: Handlers{Tenants: &probe{}}}); err == nil {
		t.Fatal("New accepted mounted handlers without Hooks.Authz")
	}
	// P2-T16 (G2 wiring review): Session and Audit are required as well once handlers are mounted.
	for name, h := range map[string]Hooks{
		"Hooks.Session": {Authz: passAuthz, Audit: passAuthz},
		"Hooks.Audit":   {Authz: passAuthz, Session: passSession},
		"Hooks.Authz":   {Session: passSession, Audit: passAuthz},
	} {
		_, err := New(Options{Logger: discardLogger(), Handlers: Handlers{Tenants: &probe{}}, Hooks: h})
		if err == nil || !strings.Contains(err.Error(), name+" is nil") {
			t.Errorf("without %s: %v", name, err)
		}
	}
	if _, err := New(Options{Logger: discardLogger(), Handlers: Handlers{Tenants: &probe{}},
		Hooks: Hooks{Authz: passAuthz, Session: passSession, Audit: passAuthz}}); err != nil {
		t.Errorf("all three hooks: %v", err)
	}
	if _, err := New(Options{Logger: discardLogger()}); err != nil {
		t.Errorf("no handler mounted (bare process): %v", err)
	}

	var (
		mu    sync.Mutex
		trace []string
	)
	note := func(s string) {
		mu.Lock()
		trace = append(trace, s)
		mu.Unlock()
	}
	set := &probe{respond: func(context.Context) error { note("handler"); return nil }}
	hooks := Hooks{
		Session: func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				note("session")
				switch r.Header.Get("X-Test-Session") {
				case "invalid":
					WriteProblem(w, r, problem.New(gen.ProblemCodeUnauthenticated, "session expired"))
					return
				case "":
				default:
					SetIdentity(r.Context(), r.Header.Get("X-Test-Session"))
				}
				next.ServeHTTP(w, r)
			})
		},
		CSRF: func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { note("csrf"); next.ServeHTTP(w, r) })
		},
		Authz: func(f gen.StrictHandlerFunc, op string) gen.StrictHandlerFunc {
			return func(ctx context.Context, w http.ResponseWriter, r *http.Request, req any) (any, error) {
				note("authz:" + op + ":" + Operation(ctx))
				if r.Header.Get("X-Test-Deny") != "" {
					return nil, problem.New(gen.ProblemCodeForbidden, "missing permission")
				}
				return f(ctx, w, r, req)
			}
		},
	}
	e := newEnv(t, Options{Handlers: Handlers{Tenants: set}, Hooks: hooks})

	w := e.do(http.MethodGet, "/api/v1/tenants", "", header("X-Test-Session", "identity-1"))
	if want := []string{"session", "csrf", "authz:ListMyTenants:ListMyTenants", "handler"}; w.Code != 200 || !slices.Equal(trace, want) {
		t.Errorf("order %v (status %d), want %v", trace, w.Code, want)
	}
	if line := e.accessLine(w.Header().Get(requestid.Header)); line["identity"] != "identity-1" {
		t.Errorf("identity not logged: %v", line)
	}

	trace = nil
	w = e.do(http.MethodGet, "/api/v1/tenants", "", header("X-Test-Deny", "1"))
	if p := problemOf(t, w); w.Code != http.StatusForbidden || p.Code != gen.ProblemCodeForbidden || slices.Contains(trace, "handler") {
		t.Errorf("authz denial: %d %+v, trace %v", w.Code, p, trace)
	}

	trace = nil
	w = e.do(http.MethodGet, "/api/v1/tenants", "", header("X-Test-Session", "invalid"))
	p := problemOf(t, w)
	if w.Code != http.StatusUnauthorized || !slices.Equal(trace, []string{"session"}) || e.accessLine(p.RequestId)["problem"] != "unauthenticated" {
		t.Errorf("session hook answering 401: %d, trace %v", w.Code, trace)
	}
}

func TestInvalidOptions(t *testing.T) {
	for name, opts := range map[string]Options{
		"no logger":     {},
		"bad limit":     {Logger: discardLogger(), RateLimits: RateLimits{ClassAuth: {PerIP: ratelimit.Limit{}, PerIdentity: ratelimit.Limit{Every: 1, Burst: 1}}}},
		"unknown class": {Logger: discardLogger(), RateLimits: RateLimits{"admin": {}}},
	} {
		if _, err := New(opts); err == nil {
			t.Errorf("%s: New accepted it", name)
		}
	}
}
