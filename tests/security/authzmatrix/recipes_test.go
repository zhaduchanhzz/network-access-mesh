//go:build mgtestfixture

package authzmatrix_test

// How to send each operation of the spec — what the generated parameter binding requires before authorization runs
// (required query parameters, Idempotency-Key, a body that decodes) — and what a granted request is expected to get
// from a mounted handler. TestEveryOperationHasAnExpectation fails when the spec gains an operation without a recipe.

import (
	"net/http"

	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/gen"
)

// answer is a fixed answer: status and problem code ("" for a success).
type answer struct {
	status int
	code   gen.ProblemCode
}

// recipe of one operation.
type recipe struct {
	// query returns the query string (no "?") of a call; nil ⇒ none.
	query func(c *call) string
	// body is the JSON body ("" ⇒ none).
	body string
	// idempotent adds Idempotency-Key (required by the binding of the operation).
	idempotent bool
	// endsSession: the request revokes the session it is sent with (logout) — sent with a throwaway session.
	endsSession bool
	// ok is the answer a mounted handler gives to a granted request on an own object; zero ⇒ any answer that is not a
	// refusal (401/403/404), not 500/501 — for the device writes, whose answer depends on the order of the parallel
	// requests on the same device (202, 409 revocation in progress) or on Headscale (unreachable here ⇒ 503).
	ok answer
	// public is the handler's answer to everyone for a public operation (authorization lets every caller through).
	public answer
}

// recipes, by operationId (authz.Operations).
var recipes = map[string]recipe{
	// auth (P2-T06, identityapi — mounted)
	"authLogin": {query: func(c *call) string {
		if c.host == hostAdmin {
			return "scope=platform"
		}
		return "scope=tenant&tenant=" + c.loginSlug
	}, public: answer{http.StatusBadGateway, gen.ProblemCodeUpstreamRejected}}, // the fixture's IdPs are never reachable
	"authCallback": {query: func(c *call) string { return "state=" + c.state },
		public: answer{http.StatusUnauthorized, gen.ProblemCodeUnauthenticated}}, // no such login in progress
	"authLogout":        {endsSession: true, ok: answer{status: http.StatusOK}}, // 200 {"redirect_to"} — G2 round 2, A-1
	"getAuthSession":    {ok: answer{status: http.StatusOK}},
	"listAuthSessions":  {ok: answer{status: http.StatusOK}},
	"revokeAuthSession": {ok: answer{status: http.StatusNoContent}},
	// tenants / platform registry (P2-T11, tenantsapi — mounted)
	"listMyTenants":         {ok: answer{status: http.StatusOK}},
	"getTenant":             {ok: answer{status: http.StatusOK}},
	"listTenantUsers":       {ok: answer{status: http.StatusOK}},
	"getTenantUser":         {ok: answer{status: http.StatusOK}},
	"listPlatformTenants":   {ok: answer{status: http.StatusOK}},
	"getPlatformTenant":     {ok: answer{status: http.StatusOK}},
	"listPlatformInstances": {ok: answer{status: http.StatusOK}},
	"getPlatformInstance":   {ok: answer{status: http.StatusOK}},
	// devices (P2-T13, devicesapi — mounted; Headscale behind the real Locator is unreachable: see handlerSets)
	"listDevices":  {ok: answer{status: http.StatusOK}},
	"getDevice":    {ok: answer{status: http.StatusOK}},
	"renameDevice": {body: `{"given_name":"matrix-renamed"}`},
	"deleteDevice": {},
	"expireDevice": {idempotent: true},
	"syncDevices":  {idempotent: true, ok: answer{status: http.StatusAccepted}},
	// audit (P2-T08, auditapi — mounted)
	"listTenantAuditEvents":   {query: func(*call) string { return "limit=5" }, ok: answer{status: http.StatusOK}},
	"listPlatformAuditEvents": {query: func(*call) string { return "limit=5" }, ok: answer{status: http.StatusOK}},
	// jobs (P2-T12 backend, jobsapi — mounted at P2-T16)
	"listTenantJobs":   {query: func(*call) string { return "limit=5" }, ok: answer{status: http.StatusOK}},
	"getTenantJob":     {ok: answer{status: http.StatusOK}},
	"listPlatformJobs": {query: func(*call) string { return "limit=5" }, ok: answer{status: http.StatusOK}},
	"getPlatformJob":   {ok: answer{status: http.StatusOK}},
	// monitoring (P2-T13a, monitoringapi — mounted; reads only the database)
	"getTenantDashboard": {ok: answer{status: http.StatusOK}},
	"getPlatformHealth":  {ok: answer{status: http.StatusOK}},
	// notifications (P3-T05b, notificationsapi — mounted; own-only for every role, the list is the caller's own rows)
	"listNotifications": {query: func(*call) string { return "limit=5" }, ok: answer{status: http.StatusOK}},
	// dual control (P3-T04a, approvalsapi — mounted with the matrix's actions, world_test.go): granted deciders race
	// on the same request (one executes, the others get 409) — any answer that is not a refusal
	"listPlatformApprovals":   {query: func(*call) string { return "limit=5" }, ok: answer{status: http.StatusOK}},
	"getPlatformApproval":     {ok: answer{status: http.StatusOK}},
	"approvePlatformApproval": {body: `{"payload_sha256":"` + matrixPlatformHash + `"}`},
	"rejectPlatformApproval":  {},
	"listTenantApprovals":     {query: func(*call) string { return "limit=5" }, ok: answer{status: http.StatusOK}},
	"getTenantApproval":       {ok: answer{status: http.StatusOK}},
	"approveTenantApproval":   {body: `{"payload_sha256":"` + matrixTenantHash + `"}`},
	"rejectTenantApproval":    {},
	// invitations (P3-T05a, invitationsapi — mounted): the same address from every granted caller (201, then 409)
	"listTenantInvitations":  {query: func(*call) string { return "limit=5" }, ok: answer{status: http.StatusOK}},
	"createTenantInvitation": {idempotent: true, body: `{"email":"matrix-invitee@example.test","role":"tenant_viewer"}`},
	"revokeTenantInvitation": {},
	"resendTenantInvitation": {},
	// platform hosts (P3-T04, hostsapi — mounted): a granted create answers 201 the first time and 409 (name taken)
	// after; a granted PATCH without If-Match reaches the service and answers 428 on the existing host
	"listPlatformHosts": {query: func(*call) string { return "limit=5" }, ok: answer{status: http.StatusOK}},
	"getPlatformHost":   {ok: answer{status: http.StatusOK}},
	"createPlatformHost": {idempotent: true, body: `{"name":"matrix-created","region":"matrix",` +
		`"run_uid_range":{"first":50000,"last":50099},"tenant_net_pool":"10.251.0.0/24"}`},
	"updatePlatformHost": {body: `{"status":"active"}`,
		ok: answer{http.StatusPreconditionRequired, gen.ProblemCodePreconditionRequired}},
	// Keycloak console session (P3-T15, idpconsoleapi — mounted with the console action, world_test.go): the request is
	// always 2P (Super Admin only); granted callers race on one open request per person (202, then 409)
	"listIdpConsoleSessions":   {query: func(*call) string { return "limit=5" }, ok: answer{status: http.StatusOK}},
	"requestIdpConsoleSession": {idempotent: true, body: `{"reason":"matrix","duration_minutes":10,"source_cidr":"192.0.2.0/24"}`},
}

// objectKind is what a path parameter (other than the {tenantId} context of a tenant route) designates.
type objectKind string

const (
	objDevice     objectKind = "device"
	objMembership objectKind = "membership"
	objJob        objectKind = "job"
	objInstance   objectKind = "instance"
	objTenant     objectKind = "tenant" // /platform/tenants/{tenantId}: a resource, not a context
	objSession    objectKind = "session"
	objIdP        objectKind = "idp"
	objApproval   objectKind = "approval"
	objInvitation objectKind = "invitation"
	objHost       objectKind = "host" // /platform/hosts/{hostId} (P3-T04)
)

// paramObjects maps path parameters to object kinds; a new parameter must be added (TestEveryOperationHasAnExpectation).
var paramObjects = map[string]objectKind{
	"deviceId": objDevice, "membershipId": objMembership, "jobId": objJob, "instanceId": objInstance,
	"tenantId": objTenant, "sessionId": objSession, "idpId": objIdP, "approvalId": objApproval, "invitationId": objInvitation,
	"hostId": objHost,
}
