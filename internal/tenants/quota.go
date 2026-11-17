package tenants

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
)

// Quota resources checked by a QuotaChecker (P3-T06a — the minimal checker: the platform tenant cap and the device
// allowance of a tenant's plan; the other PlanLimits keys of §13.3 join with their features).
const (
	QuotaTenants = "tenants" // system_settings quota.max_tenants: tenants not deleted, platform-wide
	QuotaDevices = "devices" // PlanLimits.max_devices of the tenant's live subscription (plan ⊕ override)
)

// ErrQuotaExceeded matches every quota refusal (errors.Is); the HTTP layer answers 403 quota_exceeded (§13.1).
var ErrQuotaExceeded = errors.New("quota exceeded")

// QuotaStatus is the outcome of one quota check: the effective limit, what is in use and what the operation adds.
// Numbers only — the platform cap or the caller's own plan, never another tenant's data.
type QuotaStatus struct {
	Resource  string // QuotaTenants, QuotaDevices
	Plan      string // subscription_plans.key of a plan quota; "" for the platform cap, and for a tenant without a live subscription
	Limit     int64  // effective limit (0 when the tenant has no live subscription)
	Used      int64  // in use now
	Requested int64  // what the operation adds (≥ 0)
}

// Allowed reports whether Used + Requested stays within Limit.
func (s QuotaStatus) Allowed() bool { return s.Requested >= 0 && s.Used <= s.Limit-s.Requested }

// QuotaExceededError is the typed refusal of a quota check: errors.Is(err, ErrQuotaExceeded) holds and errors.As gives
// the status (the HTTP layer reads Resource/Limit through QuotaResource/QuotaLimit — internal/httpapi/problem.FromQuota).
type QuotaExceededError struct{ Status QuotaStatus }

func (e *QuotaExceededError) Error() string {
	s := e.Status
	if s.Resource == QuotaDevices && s.Plan == "" {
		return fmt.Sprintf("quota exceeded: %s — the tenant has no live subscription", s.Resource)
	}
	return fmt.Sprintf("quota exceeded: %s %d in use + %d requested > limit %d", s.Resource, s.Used, s.Requested, s.Limit)
}

// Is makes errors.Is(err, ErrQuotaExceeded) true.
func (e *QuotaExceededError) Is(target error) bool { return target == ErrQuotaExceeded }

// QuotaResource names the quota (problem detail of 403 quota_exceeded).
func (e *QuotaExceededError) QuotaResource() string { return e.Status.Resource }

// QuotaLimit is the effective limit (problem detail of 403 quota_exceeded).
func (e *QuotaExceededError) QuotaLimit() int64 { return e.Status.Limit }

// Exceeded returns the refusal of a status that is not Allowed, nil otherwise — what a QuotaChecker returns as error.
func (s QuotaStatus) Exceeded() error {
	if s.Allowed() {
		return nil
	}
	return &QuotaExceededError{Status: s}
}

// QuotaChecker gates the creation of tenants and devices on the platform cap and the tenant's plan. It is declared here
// because tenants may not import usage (§13.6): internal/usage implements it (usage.Checker) and apps/* wire it.
//
// Every method returns the status it measured and, when the operation would exceed the quota, a *QuotaExceededError
// (errors.Is(err, ErrQuotaExceeded) ⇒ 403 quota_exceeded); any other error is an infrastructure failure (500).
//
//   - CheckTenantCreation is the plan/quota part of step 1 `validate` of tenant.provision (§11.3, P3-T05): may one more
//     tenant be created? It is a pure check (no lock); step 2 `registry.create` repeats it inside its own transaction
//     under a row lock (usage.TenantCreationTx) so two concurrent creations cannot both pass the cap.
//   - CheckDevices answers whether `adding` more devices may join the tenant; the enrollment request of §7.4 step 3
//     (P4-T06) runs the locked variant usage.DevicesTx inside the transaction that creates the request.
type QuotaChecker interface {
	CheckTenantCreation(ctx context.Context) (QuotaStatus, error)
	CheckDevices(ctx context.Context, tenantID uuid.UUID, adding int64) (QuotaStatus, error)
}
