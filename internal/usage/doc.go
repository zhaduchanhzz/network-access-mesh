// Package usage is the billing module of the Management Plane (§4.2: plan, quota, usage — `UsageService`,
// `QuotaChecker`). P3-T06a builds the minimal QuotaChecker: the platform-wide tenant cap (system_settings
// quota.max_tenants, 0012) used at step 1 `validate` / step 2 `registry.create` of tenant.provision (§11.3), and the
// device allowance of the tenant's plan (PlanLimits.max_devices of the live subscription ⊕ its override, §13.3) used by
// enrollment (§7.4 step 3 — EnrollmentTx, P4-T06: devices of the inventory plus unfinished enrollment requests within
// max_devices, live enrollment credentials within max_live_enrollment_credentials). Usage records and GET …/usage|billing
// arrive with P6-T11.
//
// tenants declares the QuotaChecker interface and the typed result (tenants.QuotaStatus, tenants.QuotaExceededError —
// errors.Is(err, tenants.ErrQuotaExceeded) ⇒ 403 quota_exceeded, §13.1); this package implements it (§13.6: usage may
// import tenants, never the other way round). Scopes (§6.1, §8.8):
//   - the tenant cap reads system_settings (a platform-only table) and counts every tenant: platform pool
//     (store.WithPlatformTx), or the caller's platform transaction (TenantCreationTx);
//   - the device quota reads the tenant's own subscription and device inventory: tenant pool (store.WithTenantTx of
//     that tenant — RLS shows nothing of another tenant), or the caller's tenant transaction (DevicesTx).
//
// The locked variants (TenantCreationTx, DevicesTx) take `SELECT … FOR UPDATE` on the row the limit comes from (the
// quota.max_tenants setting, the tenant's subscription) before counting, inside the caller's transaction that creates
// the tenant or the enrollment request — two concurrent creations serialise there and cannot both pass the limit.
// A limit that cannot be read (setting missing or malformed, plan limits malformed) is ErrQuotaUnavailable — an
// internal error, never "unlimited" (fail closed).
package usage
