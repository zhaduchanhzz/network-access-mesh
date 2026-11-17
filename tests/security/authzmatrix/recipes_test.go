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
	// refusal (401/403/404), not 500/501 (handlers mounted later — P2-T11, P2-T13 — answer without a Headscale here).
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
	"authLogout":        {endsSession: true, ok: answer{status: http.StatusNoContent}},
	"getAuthSession":    {ok: answer{status: http.StatusOK}},
	"listAuthSessions":  {ok: answer{status: http.StatusOK}},
	"revokeAuthSession": {ok: answer{status: http.StatusNoContent}},
	// tenants / platform registry (P2-T11 — not mounted yet)
	"listMyTenants":         {},
	"getTenant":             {},
	"listTenantUsers":       {},
	"getTenantUser":         {},
	"listPlatformTenants":   {},
	"getPlatformTenant":     {},
	"listPlatformInstances": {},
	"getPlatformInstance":   {},
	// devices (P2-T13 — not mounted yet)
	"listDevices":  {},
	"getDevice":    {},
	"renameDevice": {body: `{"given_name":"matrix-renamed"}`},
	"deleteDevice": {},
	"expireDevice": {idempotent: true},
	"syncDevices":  {idempotent: true},
	// audit (P2-T08, auditapi — mounted)
	"listTenantAuditEvents":   {query: func(*call) string { return "limit=5" }, ok: answer{status: http.StatusOK}},
	"listPlatformAuditEvents": {query: func(*call) string { return "limit=5" }, ok: answer{status: http.StatusOK}},
	// jobs (P2-T12 — no HTTP handler set yet)
	"listTenantJobs":   {},
	"getTenantJob":     {},
	"listPlatformJobs": {},
	"getPlatformJob":   {},
	// monitoring (P2-T13a — not mounted yet)
	"getTenantDashboard": {},
	"getPlatformHealth":  {},
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
)

// paramObjects maps path parameters to object kinds; a new parameter must be added (TestEveryOperationHasAnExpectation).
var paramObjects = map[string]objectKind{
	"deviceId": objDevice, "membershipId": objMembership, "jobId": objJob, "instanceId": objInstance,
	"tenantId": objTenant, "sessionId": objSession, "idpId": objIdP,
}
