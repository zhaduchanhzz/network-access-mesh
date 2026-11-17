package authz

import (
	"strings"
)

// Operation is the authorization contract of one operation of api/openapi.yaml (§13.1), generated into
// operations_gen.go by tools/openapi_lint.py --write; CI fails when the committed table differs from the spec.
type Operation struct {
	ID          string     // operationId (lowerCamelCase)
	Method      string     // HTTP method, upper case
	Path        string     // path template below /api/v1
	Permission  Permission // x-permission: a matrix key or a special value
	AuditAction string     // x-audit-action: audit_events.action of its denials and of its write events (P2-T08)
	Secondary   Permission // x-permission-secondary (§8.4 invariant 4): checked by the service when it applies
	OwnResource bool       // x-own-resource: a grant of scope own may call it, on the caller's own resources
	DualControl bool       // x-dual-control: every caller needs a second approver (2P)
	// Conditions (x-conditions) are the conditions of conditional grants (§8.5/§8.6 cells such as "chỉ cho restore")
	// the operation enforces itself; Authorizer refuses a grant whose condition is not listed.
	Conditions []string
}

// TenantScoped reports whether the operation runs in the tenant of its path /tenants/{tenantId}/… (§13.1 "Tenant
// context"). Platform routes such as /platform/tenants/{tenantId} carry a tenant ID as a resource, not as context.
func (o Operation) TenantScoped() bool {
	return o.Path == "/tenants/{tenantId}" || strings.HasPrefix(o.Path, "/tenants/{tenantId}/")
}

// Requirement is what the operation demands from Authorizer.Require. Only GET and HEAD are read-only: everything
// else counts as a write, which a suspended tenant refuses (§8.4 invariant 5).
func (o Operation) Requirement() Requirement {
	return Requirement{
		Permission:  o.Permission,
		ReadOnly:    o.Method == "GET" || o.Method == "HEAD",
		OwnResource: o.OwnResource,
		DualControl: o.DualControl,
		Conditions:  o.Conditions,
	}
}

var (
	operationsByID     = map[string]Operation{}
	operationsByGoName = map[string]Operation{}
)

func init() {
	for _, o := range specOperations {
		operationsByID[o.ID] = o
		operationsByGoName[goName(o.ID)] = o
	}
}

// goName is the name oapi-codegen gives an operation (and passes to strict middlewares): the operationId with its
// first letter upper-cased ("listDevices" → "ListDevices"); operationIds are lowerCamelCase ASCII (spec-lint).
func goName(id string) string {
	if id == "" {
		return ""
	}
	return strings.ToUpper(id[:1]) + id[1:]
}

// OperationByID returns the operation with this operationId ("listDevices") or Go name ("ListDevices").
func OperationByID(id string) (Operation, bool) {
	if o, ok := operationsByID[id]; ok {
		return o, true
	}
	o, ok := operationsByGoName[id]
	return o, ok
}

// Operations returns every operation of the spec, sorted by operationId.
func Operations() []Operation {
	return append([]Operation(nil), specOperations...)
}
