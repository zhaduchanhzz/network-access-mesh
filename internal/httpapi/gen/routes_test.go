package gen_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/gen"
)

// stub satisfies StrictServerInterface; its methods are never called because the recording middleware answers every
// request before the operation handler runs.
type stub struct{ gen.StrictServerInterface }

const (
	tenantID = "0194f3a2-7c1e-7d40-8a55-0d1b2c3e4f50"
	itemID   = "0194f3a2-7c1e-7d40-8a55-0d1b2c3e4f51"
)

var idempotency = map[string]string{"Idempotency-Key": "test-key-0001"}

// routes has one request per operation of api/openapi.yaml. TestEveryOperationIsRouted fails when the spec gains an
// operation without a row here.
var routes = []struct {
	method, target, body, operation string
	header                          map[string]string
}{
	{http.MethodGet, "/api/v1/auth/login?scope=tenant&tenant=tenant-a", "", "AuthLogin", nil},
	{http.MethodGet, "/api/v1/auth/callback/" + itemID + "?state=s&code=c", "", "AuthCallback", nil},
	{http.MethodPost, "/api/v1/auth/logout", "", "AuthLogout", nil},
	{http.MethodGet, "/api/v1/auth/session", "", "GetAuthSession", nil},
	{http.MethodGet, "/api/v1/auth/sessions?limit=10", "", "ListAuthSessions", nil},
	{http.MethodDelete, "/api/v1/auth/sessions/" + itemID, "", "RevokeAuthSession", nil},
	{http.MethodGet, "/api/v1/tenants", "", "ListMyTenants", nil},
	{http.MethodGet, "/api/v1/tenants/" + tenantID + "/enrollment/requests?status=issued", "", "ListEnrollmentRequests", nil},
	{http.MethodPost, "/api/v1/tenants/" + tenantID + "/enrollment/requests", `{"method":"web_auth"}`, "CreateEnrollmentRequest", idempotency},
	{http.MethodGet, "/api/v1/tenants/" + tenantID + "/enrollment/requests/" + itemID, "", "GetEnrollmentRequest", nil},
	{http.MethodPost, "/api/v1/tenants/" + tenantID + "/enrollment/requests/" + itemID + "/approve", "", "ApproveEnrollmentRequest", nil},
	{http.MethodPost, "/api/v1/tenants/" + tenantID + "/enrollment/requests/" + itemID + "/reject", "", "RejectEnrollmentRequest", nil},
	{http.MethodPost, "/api/v1/tenants/" + tenantID + "/enrollment/requests/" + itemID + "/start", "", "StartEnrollmentRequest", nil},
	{http.MethodPost, "/api/v1/tenants/" + tenantID + "/enrollment/requests/" + itemID + "/revoke", "", "RevokeEnrollmentRequest", nil},
	{http.MethodPost, "/api/v1/tenants/" + tenantID + "/enrollment/keys", `{"tags":["tag:web"]}`, "CreateEnrollmentKey", idempotency},
	{http.MethodPost, "/api/v1/tenants/" + tenantID + "/enrollment/web-auth/claim", `{"auth_id":"hskey-authreq-` + strings.Repeat("a", 24) + `"}`, "ClaimEnrollmentWebAuth", nil},
	{http.MethodGet, "/api/v1/tenants/" + tenantID + "/enrollment/instructions?os=linux", "", "GetEnrollmentInstructions", nil},
	{http.MethodGet, "/api/v1/tenants/" + tenantID, "", "GetTenant", nil},
	{http.MethodGet, "/api/v1/tenants/" + tenantID + "/dashboard", "", "GetTenantDashboard", nil},
	{http.MethodGet, "/api/v1/tenants/" + tenantID + "/devices?online=true&tag=tag:server&tagged=true&has_expiry=false&limit=50", "", "ListDevices", nil},
	{http.MethodPost, "/api/v1/tenants/" + tenantID + "/devices/sync", "", "SyncDevices", idempotency},
	{http.MethodGet, "/api/v1/tenants/" + tenantID + "/devices/" + itemID, "", "GetDevice", nil},
	{http.MethodPatch, "/api/v1/tenants/" + tenantID + "/devices/" + itemID, `{"given_name":"laptop-1"}`, "RenameDevice", nil},
	{http.MethodDelete, "/api/v1/tenants/" + tenantID + "/devices/" + itemID, "", "DeleteDevice", nil},
	{http.MethodPost, "/api/v1/tenants/" + tenantID + "/devices/" + itemID + "/expire", "", "ExpireDevice", idempotency},
	{http.MethodGet, "/api/v1/tenants/" + tenantID + "/users", "", "ListTenantUsers", nil},
	{http.MethodGet, "/api/v1/tenants/" + tenantID + "/users/" + itemID, "", "GetTenantUser", nil},
	{http.MethodGet, "/api/v1/tenants/" + tenantID + "/audit?outcome=denied", "", "ListTenantAuditEvents", nil},
	{http.MethodGet, "/api/v1/tenants/" + tenantID + "/jobs?status=running", "", "ListTenantJobs", nil},
	{http.MethodGet, "/api/v1/tenants/" + tenantID + "/jobs/" + itemID, "", "GetTenantJob", nil},
	{http.MethodGet, "/api/v1/tenants/" + tenantID + "/notifications?unread=true&limit=20", "", "ListNotifications", nil},
	{http.MethodPost, "/api/v1/tenants/" + tenantID + "/notifications/" + itemID + "/read", "", "MarkNotificationRead", nil}, // P4-T04
	// relay (P3-T05c)
	{http.MethodGet, "/api/v1/tenants/" + tenantID + "/relay", "", "GetTenantRelay", nil},
	{http.MethodGet, "/api/v1/platform/relay-regions?limit=10", "", "ListPlatformRelayRegions", nil},
	{http.MethodGet, "/api/v1/platform/tenants?status=active", "", "ListPlatformTenants", nil},
	{http.MethodPost, "/api/v1/platform/instances/" + itemID + "/backup", "", "BackupPlatformInstance", idempotency},
	{http.MethodPost, "/api/v1/platform/instances/" + itemID + "/restore", `{"backup_id":"` + itemID + `","reason":"incident 7"}`, "RestorePlatformInstance", idempotency},
	{http.MethodGet, "/api/v1/platform/backups?instance=" + itemID + "&status=succeeded", "", "ListPlatformBackups", nil},
	{http.MethodGet, "/api/v1/platform/tenants/" + tenantID, "", "GetPlatformTenant", nil},
	{http.MethodGet, "/api/v1/platform/instances", "", "ListPlatformInstances", nil},
	{http.MethodGet, "/api/v1/platform/instances/" + itemID, "", "GetPlatformInstance", nil},
	// instance.reconfigure (P3-T13)
	{http.MethodPost, "/api/v1/platform/instances/" + itemID + "/reconfigure", `{"log_level":"warn"}`, "ReconfigurePlatformInstance", idempotency},
	{http.MethodPost, "/api/v1/platform/instances/" + itemID + "/restart", "", "RestartPlatformInstance", idempotency},
	{http.MethodPost, "/api/v1/platform/instances/" + itemID + "/upgrade", `{"image_digest":"sha256:` + strings.Repeat("e", 64) + `"}`, "UpgradePlatformInstance", idempotency},
	// quarantine / release (P3-T18)
	{http.MethodPost, "/api/v1/platform/instances/" + itemID + "/quarantine", `{"reason":"suspected compromise"}`, "QuarantinePlatformInstance", idempotency},
	{http.MethodPost, "/api/v1/platform/instances/" + itemID + "/release", `{"reason":"investigation closed"}`, "ReleasePlatformInstance", idempotency},
	// platform hosts (P3-T04)
	{http.MethodGet, "/api/v1/platform/hosts?status=draining&region=lab", "", "ListPlatformHosts", nil},
	{http.MethodPost, "/api/v1/platform/hosts", `{"name":"h1","region":"lab","run_uid_range":{"first":30000,"last":39999},"tenant_net_pool":"10.250.0.0/16"}`, "CreatePlatformHost", idempotency},
	{http.MethodGet, "/api/v1/platform/hosts/" + itemID, "", "GetPlatformHost", nil},
	{http.MethodPatch, "/api/v1/platform/hosts/" + itemID, `{"status":"draining"}`, "UpdatePlatformHost", map[string]string{"If-Match": `"0123"`}},
	{http.MethodGet, "/api/v1/platform/health", "", "GetPlatformHealth", nil},
	{http.MethodGet, "/api/v1/platform/audit", "", "ListPlatformAuditEvents", nil},
	{http.MethodGet, "/api/v1/platform/jobs?kind=inventory.sync", "", "ListPlatformJobs", nil},
	{http.MethodGet, "/api/v1/platform/jobs/" + itemID, "", "GetPlatformJob", nil},
	// dual control (P3-T04a) and invitations (P3-T05a)
	{http.MethodGet, "/api/v1/platform/approvals?status=pending", "", "ListPlatformApprovals", nil},
	{http.MethodGet, "/api/v1/platform/approvals/" + itemID, "", "GetPlatformApproval", nil},
	{http.MethodPost, "/api/v1/platform/approvals/" + itemID + "/approve", `{"payload_sha256":"` + strings.Repeat("a", 64) + `"}`, "ApprovePlatformApproval", nil},
	{http.MethodPost, "/api/v1/platform/approvals/" + itemID + "/reject", "", "RejectPlatformApproval", nil},
	{http.MethodGet, "/api/v1/tenants/" + tenantID + "/approvals?status=approved", "", "ListTenantApprovals", nil},
	{http.MethodGet, "/api/v1/tenants/" + tenantID + "/approvals/" + itemID, "", "GetTenantApproval", nil},
	{http.MethodPost, "/api/v1/tenants/" + tenantID + "/approvals/" + itemID + "/approve", `{"payload_sha256":"` + strings.Repeat("b", 64) + `"}`, "ApproveTenantApproval", nil},
	{http.MethodPost, "/api/v1/tenants/" + tenantID + "/approvals/" + itemID + "/reject", "", "RejectTenantApproval", nil},
	{http.MethodPatch, "/api/v1/tenants/" + tenantID + "/users/" + itemID, `{"status":"locked"}`, "UpdateTenantUser", map[string]string{"If-Match": `"1"`}},
	{http.MethodDelete, "/api/v1/tenants/" + tenantID + "/users/" + itemID, "", "OffboardTenantUser", nil},
	{http.MethodPut, "/api/v1/tenants/" + tenantID + "/users/" + itemID + "/role", `{"role":"end_user"}`, "SetTenantUserRole", map[string]string{"If-Match": `"1"`}},
	{http.MethodPut, "/api/v1/tenants/" + tenantID + "/users/" + itemID + "/admin-role", `{"role":"tenant_admin"}`, "SetTenantUserAdminRole", map[string]string{"If-Match": `"1"`}},
	{http.MethodDelete, "/api/v1/tenants/" + tenantID + "/users/" + itemID + "/sessions", "", "RevokeTenantUserSessions", nil},
	{http.MethodPost, "/api/v1/tenants/" + tenantID + "/ownership-transfer", `{"membership_id":"` + itemID + `"}`, "TransferTenantOwnership", nil},
	{http.MethodGet, "/api/v1/tenants/" + tenantID + "/groups", "", "ListTenantGroups", nil},
	{http.MethodPost, "/api/v1/tenants/" + tenantID + "/groups", `{"name":"ops"}`, "CreateTenantGroup", idempotency},
	{http.MethodGet, "/api/v1/tenants/" + tenantID + "/groups/" + itemID, "", "GetTenantGroup", nil},
	{http.MethodPatch, "/api/v1/tenants/" + tenantID + "/groups/" + itemID, `{"name":"ops-2"}`, "UpdateTenantGroup", map[string]string{"If-Match": `"1"`}},
	{http.MethodDelete, "/api/v1/tenants/" + tenantID + "/groups/" + itemID, "", "DeleteTenantGroup", map[string]string{"If-Match": `"1"`}},
	{http.MethodPut, "/api/v1/tenants/" + tenantID + "/groups/" + itemID + "/members", `{"membership_ids":["` + itemID + `"]}`, "SetTenantGroupMembers", map[string]string{"If-Match": `"1"`}},
	{http.MethodGet, "/api/v1/tenants/" + tenantID + "/invitations", "", "ListTenantInvitations", nil},
	{http.MethodPost, "/api/v1/tenants/" + tenantID + "/invitations", `{"email":"a@example.test","role":"end_user"}`, "CreateTenantInvitation", idempotency},
	{http.MethodDelete, "/api/v1/tenants/" + tenantID + "/invitations/" + itemID, "", "RevokeTenantInvitation", nil},
	{http.MethodPut, "/api/v1/tenants/" + tenantID + "/devices/" + itemID + "/tags", `{"tags":["tag:web"]}`, "SetDeviceTags", nil},
	{http.MethodGet, "/api/v1/tenants/" + tenantID + "/tags", "", "ListTenantTags", nil},
	{http.MethodPost, "/api/v1/tenants/" + tenantID + "/tags", `{"name":"tag:web"}`, "CreateTenantTag", idempotency},
	{http.MethodPatch, "/api/v1/tenants/" + tenantID + "/tags/" + itemID, `{"description":"web"}`, "UpdateTenantTag", nil},
	{http.MethodDelete, "/api/v1/tenants/" + tenantID + "/tags/" + itemID, "", "DeleteTenantTag", nil},
	{http.MethodPost, "/api/v1/tenants/" + tenantID + "/invitations/" + itemID + "/resend", `{"expires_in_hours":24}`, "ResendTenantInvitation", nil},
	// administration (P4-T03a)
	{http.MethodPatch, "/api/v1/platform/tenants/" + tenantID, `{"name":"Acme 2"}`, "UpdatePlatformTenant", map[string]string{"If-Match": `"1"`}},
	{http.MethodGet, "/api/v1/tenants/" + tenantID + "/settings", "", "GetTenantSettings", nil},
	{http.MethodPatch, "/api/v1/tenants/" + tenantID + "/settings", `{"notifications":{"new_device":false}}`, "UpdateTenantSettings", map[string]string{"If-Match": `"1"`}},
	{http.MethodPut, "/api/v1/tenants/" + tenantID + "/settings/security", `{"enrollment":{"identity_mode":"portal","web_auth_enabled":true,"self_enroll":false,"requires_approval":false},"node_expiry":null,"policy":{"four_eyes":true,"sensitive_groups":[]},"routes":{"four_eyes":false}}`, "PutTenantSecuritySettings", map[string]string{"If-Match": `"1"`}},
	{http.MethodGet, "/api/v1/tenants/" + tenantID + "/identity-provider", "", "GetTenantIdentityProvider", nil},
	{http.MethodPatch, "/api/v1/tenants/" + tenantID + "/identity-provider", `{"allowed_email_domains":["acme.example"]}`, "UpdateTenantIdentityProvider", map[string]string{"If-Match": `"1"`}},
	{http.MethodPost, "/api/v1/tenants/" + tenantID + "/request-deletion", `{"confirm_slug":"acme","reason":"closing"}`, "RequestTenantDeletion", nil},
	{http.MethodGet, "/api/v1/platform/users?status=active&role=platform_viewer&limit=5", "", "ListPlatformUsers", nil},
	{http.MethodPost, "/api/v1/platform/users", `{"subject":"0194f3a2-7c1e-7d40-8a55-0d1b2c3e4f52","role":"platform_viewer"}`, "CreatePlatformUser", idempotency},
	{http.MethodGet, "/api/v1/platform/users/" + itemID, "", "GetPlatformUser", nil},
	{http.MethodPatch, "/api/v1/platform/users/" + itemID, `{"status":"disabled"}`, "UpdatePlatformUser", map[string]string{"If-Match": `"1"`}},
	{http.MethodDelete, "/api/v1/platform/users/" + itemID, "", "DeletePlatformUser", map[string]string{"If-Match": `"1"`}},
	{http.MethodPut, "/api/v1/platform/users/" + itemID + "/super-admin-role", `{"super_admin":true,"reason":"second SA"}`, "SetPlatformUserSuperAdminRole", nil},
	{http.MethodGet, "/api/v1/platform/settings", "", "ListPlatformSettings", nil},
	{http.MethodGet, "/api/v1/platform/settings/approval.ttl_hours", "", "GetPlatformSetting", nil},
	{http.MethodPut, "/api/v1/platform/settings/approval.ttl_hours", `{"value":48}`, "PutPlatformSetting", map[string]string{"If-Match": `"1"`}},
	{http.MethodGet, "/api/v1/platform/identity-providers?scope=tenant&limit=5", "", "ListPlatformIdentityProviders", nil},
	{http.MethodGet, "/api/v1/platform/identity-providers/" + itemID, "", "GetPlatformIdentityProvider", nil},
	{http.MethodPatch, "/api/v1/platform/identity-providers/" + itemID, `{"required_claims":{"hd":"acme.example"}}`, "UpdatePlatformIdentityProvider", map[string]string{"If-Match": `"1"`}},
	{http.MethodGet, "/api/v1/platform/plans", "", "ListPlatformPlans", nil},
	{http.MethodPost, "/api/v1/platform/plans", `{"key":"pro","name":"Pro","limits":{"max_devices":10,"max_users":10,"max_tagged_devices":1,"max_live_enrollment_credentials":1}}`, "CreatePlatformPlan", idempotency},
	{http.MethodGet, "/api/v1/platform/plans/" + itemID, "", "GetPlatformPlan", nil},
	{http.MethodPatch, "/api/v1/platform/plans/" + itemID, `{"is_active":false}`, "UpdatePlatformPlan", map[string]string{"If-Match": `"1"`}},
	// Keycloak console session (P3-T15)
	{http.MethodGet, "/api/v1/platform/idp-console/sessions?limit=5", "", "ListIdpConsoleSessions", nil},
	{http.MethodPost, "/api/v1/platform/idp-console/sessions", `{"reason":"ticket 1","source_cidr":"203.0.113.7/32"}`, "RequestIdpConsoleSession", idempotency},
	{http.MethodPost, "/api/v1/platform/tenants", `{"slug":"acme","name":"Acme","plan_key":"standard","owner_email":"owner@acme.example","identity_provider":{"driver":"keycloak"}}`, "CreatePlatformTenant", idempotency},
	{http.MethodPost, "/api/v1/platform/jobs/" + itemID + "/retry", "", "RetryPlatformJob", idempotency},
	{http.MethodPost, "/api/v1/platform/jobs/" + itemID + "/cancel", "", "CancelPlatformJob", idempotency},
	{http.MethodPost, "/api/v1/platform/jobs/" + itemID + "/rollback", "", "RollbackPlatformJob", idempotency},
	// suspend / resume (P3-T08)
	{http.MethodPost, "/api/v1/platform/tenants/" + tenantID + "/suspend", "", "SuspendPlatformTenant", idempotency},
	{http.MethodPost, "/api/v1/platform/tenants/" + tenantID + "/resume", "", "ResumePlatformTenant", idempotency},
	// deprovision (P3-T09)
	{http.MethodDelete, "/api/v1/platform/tenants/" + tenantID, `{"confirm_slug":"acme","reason":"ticket 1"}`, "DeletePlatformTenant", idempotency},
}

// recorder mounts the generated routes on a plain net/http ServeMux (§4.3) under /api/v1. A strict middleware records
// the operation and answers 204 without calling the handler; request-binding errors are recorded and answered 422.
type recorder struct {
	operations []string
	errs       []error
}

func (rec *recorder) handler() http.Handler {
	record := func(_ gen.StrictHandlerFunc, operationID string) gen.StrictHandlerFunc {
		return func(_ context.Context, w http.ResponseWriter, _ *http.Request, _ any) (any, error) {
			rec.operations = append(rec.operations, operationID)
			w.WriteHeader(http.StatusNoContent)
			return nil, nil
		}
	}
	return gen.HandlerWithOptions(gen.NewStrictHandler(stub{}, []gen.StrictMiddlewareFunc{record}), gen.StdHTTPServerOptions{
		BaseURL:    "/api/v1",
		BaseRouter: http.NewServeMux(),
		ErrorHandlerFunc: func(w http.ResponseWriter, _ *http.Request, err error) {
			rec.errs = append(rec.errs, err)
			w.WriteHeader(http.StatusUnprocessableEntity)
		},
	})
}

func (rec *recorder) do(t *testing.T, h http.Handler, method, target, body string, header map[string]string) int {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), method, target, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range header {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w.Code
}

// TestEveryOperationIsRouted proves that every operation of the spec is routable by the standard ServeMux at its
// /…/{id}/<action> path (§13.1 — the reason action paths are child segments) and that the table above is complete.
func TestEveryOperationIsRouted(t *testing.T) {
	rec := &recorder{}
	h := rec.handler()
	for _, r := range routes {
		rec.operations, rec.errs = nil, nil
		code := rec.do(t, h, r.method, r.target, r.body, r.header)
		if code != http.StatusNoContent || len(rec.operations) != 1 || rec.operations[0] != r.operation {
			t.Errorf("%s %s: status %d, operations %v, binding errors %v; want %s", r.method, r.target, code,
				rec.operations, rec.errs, r.operation)
		}
	}
	iface := reflect.TypeFor[gen.StrictServerInterface]()
	var want, got []string
	for i := range iface.NumMethod() {
		want = append(want, iface.Method(i).Name)
	}
	for _, r := range routes {
		got = append(got, r.operation)
	}
	sort.Strings(want)
	sort.Strings(got)
	if strings.Join(want, ",") != strings.Join(got, ",") {
		t.Fatalf("route table out of date:\n spec operations %v\n table          %v", want, got)
	}
}

// TestBadRequestsNeverReachHandlers: a path ID that is not a UUID, a missing Idempotency-Key and a missing required
// query parameter are rejected by the generated binding before any handler (or authz middleware) runs.
func TestBadRequestsNeverReachHandlers(t *testing.T) {
	cases := []struct {
		name, method, target string
		header               map[string]string
		wantErr              any
	}{
		{"tenant id not a UUID", http.MethodGet, "/api/v1/tenants/tenant-a/devices", nil, new(*gen.InvalidParamFormatError)},
		{"device id not a UUID", http.MethodGet, "/api/v1/tenants/" + tenantID + "/devices/42", nil, new(*gen.InvalidParamFormatError)},
		{"missing Idempotency-Key", http.MethodPost, "/api/v1/tenants/" + tenantID + "/devices/sync", nil, new(*gen.RequiredHeaderError)},
		{"missing required query", http.MethodGet, "/api/v1/auth/login", nil, new(*gen.RequiredParamError)},
	}
	for _, c := range cases {
		rec := &recorder{}
		code := rec.do(t, rec.handler(), c.method, c.target, "", c.header)
		if code != http.StatusUnprocessableEntity || len(rec.operations) != 0 || len(rec.errs) != 1 {
			t.Errorf("%s: status %d, operations %v, errors %v", c.name, code, rec.operations, rec.errs)
			continue
		}
		if !errors.As(rec.errs[0], c.wantErr) {
			t.Errorf("%s: error %T (%v), want %T", c.name, rec.errs[0], rec.errs[0], c.wantErr)
		}
	}
}

// TestUnknownRoutes: a ':action' suffix (the form §13.1 forbids) and a method the spec does not declare are not routed.
func TestUnknownRoutes(t *testing.T) {
	rec := &recorder{}
	h := rec.handler()
	if code := rec.do(t, h, http.MethodPost, "/api/v1/tenants/"+tenantID+"/devices/"+itemID+":expire", "", idempotency); code != http.StatusMethodNotAllowed {
		t.Errorf("POST …/{deviceId}:expire: status %d, want 405", code)
	}
	if code := rec.do(t, h, http.MethodPut, "/api/v1/tenants/"+tenantID+"/devices/"+itemID, "", nil); code != http.StatusMethodNotAllowed {
		t.Errorf("PUT …/devices/{deviceId}: status %d, want 405", code)
	}
	if code := rec.do(t, h, http.MethodGet, "/api/v1/internal/edge/ask", "", nil); code != http.StatusNotFound {
		t.Errorf("GET /api/v1/internal/edge/ask: status %d, want 404", code)
	}
	if len(rec.operations) != 0 {
		t.Errorf("handlers reached: %v", rec.operations)
	}
}
