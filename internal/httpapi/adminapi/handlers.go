// Package adminapi serves the administration operations of api/openapi.yaml built by P4-T03a (httpapi.AdminHandlers):
//
//   - platform (internal/platform): platform users (listPlatformUsers, getPlatformUser, createPlatformUser,
//     updatePlatformUser, deletePlatformUser, setPlatformUserSuperAdminRole — always a 2P request), system settings
//     (listPlatformSettings, getPlatformSetting, putPlatformSetting), identity providers
//     (listPlatformIdentityProviders, getPlatformIdentityProvider, updatePlatformIdentityProvider — a tenant row becomes
//     a 2P request), plans (listPlatformPlans, getPlatformPlan, createPlatformPlan, updatePlatformPlan) and
//     updatePlatformTenant;
//   - tenant (internal/tenants): getTenantSettings, updateTenantSettings, putTenantSecuritySettings (lifting a
//     second-person control becomes a tenant approval request), getTenantIdentityProvider,
//     updateTenantIdentityProvider, requestTenantDeletion.
//
// It only translates between the generated types and the services, which take every decision. Layer 1 (authzhook)
// decided the route; the decision's condition (excludes_super_admin, tenant_idp_dual_control) is handed to the service,
// which enforces it. The 2P operations make their request through internal/authz/approvals (202 + Location of
// /platform/approvals/{id} or /tenants/{tenantId}/approvals/{id}); the actions that execute them are registered in
// apps/internal/runner.
//
// Wiring (apps/internal/runner — api process):
//
//	httpapi.Handlers{…, Admin: adminapi.New(platform.New(store), tenantsService, approvalsService)}
package adminapi

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/authz"
	"github.com/zhaduchanhzz/network-access-mesh/internal/authz/approvals"
	"github.com/zhaduchanhzz/network-access-mesh/internal/config"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/authzhook"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/gen"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/problem"
	"github.com/zhaduchanhzz/network-access-mesh/internal/identity"
	"github.com/zhaduchanhzz/network-access-mesh/internal/platform"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
)

// Platform is the part of *platform.Service the handlers use.
type Platform interface {
	ListUsers(ctx context.Context, f platform.UserFilter) (platform.UserPage, error)
	GetUser(ctx context.Context, id uuid.UUID) (platform.PlatformUser, error)
	CreateUser(ctx context.Context, a platform.Actor, in platform.UserCreate, idem *platform.Idempotency) (platform.PlatformUser, error)
	UpdateUser(ctx context.Context, a platform.Actor, id uuid.UUID, p platform.UserPatch, ifMatch string) (platform.PlatformUser, error)
	DisableUser(ctx context.Context, a platform.Actor, id uuid.UUID, ifMatch string) (platform.PlatformUser, error)
	SuperAdminRequest(ctx context.Context, id uuid.UUID, grant bool, roleAfter string) (platform.SuperAdminPayload, error)
	ListSettings(ctx context.Context) ([]platform.Setting, error)
	GetSetting(ctx context.Context, key string) (platform.Setting, error)
	PutSetting(ctx context.Context, a platform.Actor, key string, value []byte, ifMatch string) (platform.Setting, error)
	ListIdPs(ctx context.Context, f platform.IdPFilter) (platform.IdPPage, error)
	GetIdP(ctx context.Context, id uuid.UUID) (tenants.IdPConfig, error)
	UpdateIdP(ctx context.Context, a platform.Actor, id uuid.UUID, c tenants.IdPChange, ifMatch string) (platform.IdPUpdateResult, error)
	ListPlans(ctx context.Context) ([]platform.Plan, error)
	GetPlan(ctx context.Context, id uuid.UUID) (platform.Plan, error)
	CreatePlan(ctx context.Context, a platform.Actor, in platform.PlanCreate, idem *platform.Idempotency) (platform.Plan, error)
	UpdatePlan(ctx context.Context, id uuid.UUID, p platform.PlanPatch, ifMatch string) (platform.Plan, error)
	UpdateTenant(ctx context.Context, id uuid.UUID, p platform.TenantPatch, ifMatch string) error
	// Labels names the tenants of a page (G4b-E12: slug and name instead of a UUID in the Platform Console).
	Labels(ctx context.Context, tenantIDs, hostIDs []uuid.UUID) (platform.Labels, error)
}

// Tenants is the part of *tenants.Service the handlers use.
type Tenants interface {
	GetRegistry(ctx context.Context, tenantID uuid.UUID) (tenants.Tenant, error)
	GetSettings(ctx context.Context, tenantID uuid.UUID) (tenants.SettingsView, error)
	PatchSettings(ctx context.Context, tenantID uuid.UUID, p config.SettingsPatch, ifMatch string) (tenants.SettingsView, error)
	PutSecuritySettings(ctx context.Context, a tenants.Actor, tenantID uuid.UUID, want config.SecuritySettings, ifMatch string) (tenants.SecurityResult, error)
	GetActiveIdP(ctx context.Context, tenantID uuid.UUID) (tenants.IdPConfig, error)
	UpdateIdP(ctx context.Context, a tenants.Actor, tenantID uuid.UUID, c tenants.IdPChange, secret []byte, ifMatch string) (tenants.IdPConfig, error)
	RecordPlatformIdPChangeRequested(ctx context.Context, p tenants.PlatformIdPChange, approvalID, requestedBy uuid.UUID, requester string, expiresAt time.Time) error
	RequestDeletion(ctx context.Context, a tenants.Actor, tenantID uuid.UUID, confirmSlug, reason string) (tenants.DeletionRequest, error)
}

// Approvals is the part of *approvals.Service the 2P operations use.
type Approvals interface {
	Request(ctx context.Context, actor approvals.Actor, in approvals.NewRequest) (approvals.Request, error)
}

var (
	_ Platform  = (*platform.Service)(nil)
	_ Tenants   = (*tenants.Service)(nil)
	_ Approvals = (*approvals.Service)(nil)
)

// Handlers implements httpapi.AdminHandlers.
type Handlers struct {
	platform Platform
	tenants  Tenants
	appr     Approvals
}

var _ httpapi.AdminHandlers = (*Handlers)(nil)

// New returns the handler set of P4-T03a.
func New(p Platform, t Tenants, appr Approvals) *Handlers {
	return &Handlers{platform: p, tenants: t, appr: appr}
}

var errNoDecision = errors.New("adminapi: no session or decision in the request context (hooks missing)")

// session is the caller's session and the layer-1 decision of the request (fail closed without them).
func session(ctx context.Context) (*identity.Session, authz.Decision, error) {
	s, ok := identity.SessionFromContext(ctx)
	d, okd := authzhook.DecisionFrom(ctx)
	if !ok || !okd || s == nil || s.IdentityID == uuid.Nil || d.Principal.IdentityID != s.IdentityID {
		return nil, authz.Decision{}, problem.Internal(errNoDecision)
	}
	return s, d, nil
}

func displayOf(s *identity.Session) string {
	if s.DisplayName != "" {
		return s.DisplayName
	}
	return s.Email
}

// platformActor is the caller of a platform operation.
func platformActor(ctx context.Context) (platform.Actor, *identity.Session, error) {
	s, d, err := session(ctx)
	if err != nil {
		return platform.Actor{}, s, err
	}
	if d.TenantID != uuid.Nil {
		return platform.Actor{}, s, problem.Internal(errors.New("adminapi: a platform operation decided with a tenant"))
	}
	return platform.Actor{IdentityID: s.IdentityID, AuthTime: s.AuthTime, Condition: d.Condition}, s, nil
}

// tenantActor is the caller of a tenant operation: its membership in the tenant of the path.
func tenantActor(ctx context.Context, tenantID uuid.UUID) (tenants.Actor, *identity.Session, error) {
	s, d, err := session(ctx)
	if err != nil {
		return tenants.Actor{}, s, err
	}
	if d.MembershipID == uuid.Nil || d.TenantID != tenantID {
		return tenants.Actor{}, s, problem.Internal(errNoDecision)
	}
	return tenants.Actor{IdentityID: s.IdentityID, MembershipID: d.MembershipID, AuthTime: s.AuthTime,
		Display: displayOf(s)}, s, nil
}

func ifMatchOf(p *gen.IfMatch) string {
	if p == nil {
		return ""
	}
	return *p
}

// details are the client texts of the refusals (by reason) — never a submitted value.
var details = map[string]string{ //nolint:gosec // G101: problem texts keyed by refusal reasons, no credential
	platform.ReasonSuperAdminTarget:  "A Super Admin is changed only through the dual-control super-admin-role operation.",
	platform.ReasonSelf:              "You cannot change your own platform user.",
	platform.ReasonAlreadyMember:     "This identity already is a platform user.",
	platform.ReasonNoPlatformIdP:     "There is not exactly one active platform identity provider.",
	platform.ReasonIdentityDisabled:  "The identity is disabled.",
	platform.ReasonState:             "The platform user already is in the requested state.",
	platform.ReasonLastSuperAdmin:    "The change would leave no active Super Admin.",
	platform.ReasonKeyTaken:          "A plan with this key already exists.",
	platform.ReasonNoSubscription:    "The tenant has no live subscription.",
	platform.ReasonTenantClosed:      "The tenant is being deprovisioned.",
	platform.ReasonConditionMismatch: "Your role cannot perform this operation.",
	"identity_mode_immutable":        "identity_mode cannot change once the tenant has its first Headscale user or device (ID-08).",
	"secret_store_unavailable":       "The client secret cannot be stored by this process.",
}

// failure maps an error of the services to its problem; the reason travels as the cause (an authz.Denial — the audit
// middleware records it, the client never sees it).
func failure(err error) error {
	var (
		pe *platform.AdminError
		te *tenants.AdminError
		d  *authz.Denial
	)
	kind, reason, field := err, "", ""
	switch {
	case errors.As(err, &d):
		return authzhook.Problem(err)
	case errors.As(err, &pe):
		kind, reason, field = pe.Kind, pe.Reason, pe.Field
	case errors.As(err, &te):
		kind, reason, field = te.Kind, te.Reason, te.Field
	}
	cause := &authz.Denial{Kind: err, Reason: reason}
	p := func(code gen.ProblemCode, def string) error {
		detail, ok := details[reason]
		if !ok {
			detail = def
		}
		e := &problem.Error{Code: code, Detail: detail, Cause: cause}
		if pe != nil && pe.RetryAfter > 0 {
			e.RetryAfter = pe.RetryAfter
		}
		return e
	}
	switch {
	case errors.Is(kind, platform.ErrNotFound), errors.Is(kind, tenants.ErrNotFound):
		return p(gen.ProblemCodeNotFound, "The resource does not exist.")
	case errors.Is(kind, platform.ErrInvalid), errors.Is(kind, tenants.ErrInvalid):
		if field == "" {
			field = "body"
		}
		if reason == "" {
			reason = "invalid"
		}
		v := problem.Validation("The request is invalid.", problem.Field(field, reason, "has an invalid value"))
		v.Cause = cause
		return v
	case errors.Is(kind, platform.ErrForbidden):
		return p(gen.ProblemCodeForbidden, "The request is not allowed.")
	case errors.Is(kind, platform.ErrReauthRequired), errors.Is(kind, tenants.ErrReauthRequired):
		return p(gen.ProblemCodeReauthRequired, "This operation needs a recent sign-in: sign in again.")
	case errors.Is(kind, platform.ErrPreconditionRequired), errors.Is(kind, tenants.ErrPreconditionRequired):
		return p(gen.ProblemCodePreconditionRequired, "If-Match with the current ETag of the resource is required.")
	case errors.Is(kind, platform.ErrPreconditionFailed), errors.Is(kind, tenants.ErrPreconditionFailed):
		return p(gen.ProblemCodePreconditionFailed, "The resource changed since it was read; read it again.")
	case errors.Is(kind, platform.ErrIdempotencyKeyReuse):
		return p(gen.ProblemCodeIdempotencyKeyReuse, "The Idempotency-Key was used for another request.")
	case errors.Is(kind, platform.ErrIdempotencyInProgress):
		return p(gen.ProblemCodeConflict, "A request with this Idempotency-Key is still in progress.")
	case errors.Is(kind, platform.ErrConflict), errors.Is(kind, tenants.ErrConflict), errors.Is(kind, tenants.ErrUnavailable),
		errors.Is(kind, tenants.ErrStale):
		return p(gen.ProblemCodeConflict, "The request conflicts with the current state.")
	}
	return problem.Internal(err)
}

// rawOrEmpty is a JSON value for the API ("{}" when empty).
func rawOrEmpty(b []byte) json.RawMessage {
	if len(b) == 0 {
		return json.RawMessage(`{}`)
	}
	return json.RawMessage(b)
}

func ptr[T any](v T) *T { return &v }
