package usage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
)

var (
	// ErrQuotaUnavailable: the limit could not be read (quota.max_tenants missing or not an integer, plan limits
	// malformed) — an internal error (500); a quota that cannot be read is never treated as unlimited.
	ErrQuotaUnavailable = errors.New("usage: quota limit unavailable")
	// ErrInvalid: a negative amount or a nil tenant.
	ErrInvalid = errors.New("usage: invalid argument")
)

// TenantCapKey is the system_settings key of the platform-wide tenant cap (0012; §13.3).
const TenantCapKey = "quota.max_tenants"

// Checker is the QuotaChecker of P3-T06a on the two pools of a process (api: validate, registry.create; api/worker:
// enrollment).
type Checker struct{ st *store.Store }

var _ tenants.QuotaChecker = (*Checker)(nil)

// NewChecker returns the checker on st.
func NewChecker(st *store.Store) *Checker { return &Checker{st: st} }

// CheckTenantCreation implements tenants.QuotaChecker: may one more tenant be created (tenants not deleted <
// quota.max_tenants)? Platform pool, no lock — step 1 `validate` (§11.3) is a pure check; registry.create repeats it
// with TenantCreationTx.
func (c *Checker) CheckTenantCreation(ctx context.Context) (tenants.QuotaStatus, error) {
	var st tenants.QuotaStatus
	err := c.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		var err error
		st, err = tenantCreation(ctx, q, false)
		return err
	})
	if err != nil {
		return st, err
	}
	return st, st.Exceeded()
}

// CheckDevices implements tenants.QuotaChecker: may `adding` more devices join the tenant? Tenant pool of that tenant,
// under the lock of its subscription row for the length of this read-only transaction. Enrollment uses DevicesTx in
// the transaction that creates the request instead.
func (c *Checker) CheckDevices(ctx context.Context, tenantID uuid.UUID, adding int64) (tenants.QuotaStatus, error) {
	if tenantID == uuid.Nil || adding < 0 {
		return tenants.QuotaStatus{}, ErrInvalid
	}
	var st tenants.QuotaStatus
	err := c.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		var err error
		st, err = devices(ctx, q, tenantID, adding, false)
		return err
	})
	if err != nil {
		return st, err
	}
	return st, st.Exceeded()
}

// TenantCreationTx is the tenant cap inside the caller's PLATFORM transaction (store.WithPlatformTx) that creates the
// tenant — step 2 `registry.create` (§11.3): it locks the quota.max_tenants row (`SELECT … FOR UPDATE`) before
// counting, so concurrent creations serialise on that row until the caller commits. A *tenants.QuotaExceededError
// means: roll back.
func TenantCreationTx(ctx context.Context, q *sqlcdb.Queries) (tenants.QuotaStatus, error) {
	st, err := tenantCreation(ctx, q, true)
	if err != nil {
		return st, err
	}
	return st, st.Exceeded()
}

// DevicesTx is the device quota inside the caller's TENANT transaction (store.WithTenantTx of tenantID) — the
// enrollment request of §7.4 step 3 (P4-T06): it locks the tenant's subscription row (`SELECT … FOR UPDATE`) before
// counting, so two concurrent requests cannot both pass the limit. adding = what the operation would add on top of the
// devices in the inventory (the new device plus the enrollment credentials still live — P4-T06 counts them in the same
// transaction once enrollment_requests exists).
func DevicesTx(ctx context.Context, q *sqlcdb.Queries, tenantID uuid.UUID, adding int64) (tenants.QuotaStatus, error) {
	if tenantID == uuid.Nil || adding < 0 {
		return tenants.QuotaStatus{}, ErrInvalid
	}
	st, err := devices(ctx, q, tenantID, adding, true)
	if err != nil {
		return st, err
	}
	return st, st.Exceeded()
}

// EnrollmentTx is the quota of an enrollment request (§7.4 step 3 — P4-T06) inside the caller's TENANT transaction
// (store.WithTenantTx of tenantID): it locks the tenant's subscription row (`SELECT … FOR UPDATE`) and only then
// counts, so two concurrent requests serialise there and cannot both pass a limit.
//   - devices: the devices of the inventory PLUS the enrollment requests that can still bring one (not finished) must stay
//     within PlanLimits.max_devices; newRequest adds the request being created (false: the request already counts —
//     /start of an approved request);
//   - credentials (issuing = true): the live enrollment credentials (codes and keys issued and not yet used or expired,
//     reusable keys still valid) plus the one being issued must stay within PlanLimits.max_live_enrollment_credentials.
//
// The first limit exceeded is returned as a *tenants.QuotaExceededError (Resource QuotaDevices or
// QuotaEnrollmentCredentials).
func EnrollmentTx(ctx context.Context, q *sqlcdb.Queries, tenantID uuid.UUID, newRequest, issuing bool) (tenants.QuotaStatus, error) {
	if tenantID == uuid.Nil {
		return tenants.QuotaStatus{}, ErrInvalid
	}
	r, err := q.LockTenantSubscriptionLimits(ctx, tenantID)
	live := err == nil
	if err != nil && !errors.Is(err, store.ErrNoRows) {
		return tenants.QuotaStatus{}, err
	}
	open, err := q.CountOpenEnrollmentRequests(ctx, tenantID)
	if err != nil {
		return tenants.QuotaStatus{}, err
	}
	dev := tenants.QuotaStatus{Resource: tenants.QuotaDevices, Requested: 1}
	if !newRequest {
		dev.Requested = 0
	}
	if live {
		dev.Plan = r.PlanKey
		if dev.Limit, err = effectiveLimit(r.Limits, r.Overrides, "max_devices"); err != nil {
			return dev, fmt.Errorf("%w: plan %s: %s", ErrQuotaUnavailable, r.PlanKey, err.Error())
		}
	}
	devices, err := q.CountTenantDevices(ctx, tenantID)
	if err != nil {
		return dev, err
	}
	dev.Used = devices + open
	if err := dev.Exceeded(); err != nil || !issuing {
		return dev, err
	}
	cred := tenants.QuotaStatus{Resource: tenants.QuotaEnrollmentCredentials, Requested: 1, Plan: dev.Plan}
	if live {
		if cred.Limit, err = effectiveLimit(r.Limits, r.Overrides, "max_live_enrollment_credentials"); err != nil {
			return cred, fmt.Errorf("%w: plan %s: %s", ErrQuotaUnavailable, r.PlanKey, err.Error())
		}
	}
	if cred.Used, err = q.CountLiveEnrollmentCredentials(ctx, tenantID); err != nil {
		return cred, err
	}
	return cred, cred.Exceeded()
}

func tenantCreation(ctx context.Context, q *sqlcdb.Queries, lock bool) (tenants.QuotaStatus, error) {
	st := tenants.QuotaStatus{Resource: tenants.QuotaTenants, Requested: 1}
	read := q.GetTenantCap
	if lock {
		read = q.LockTenantCap
	}
	raw, err := read(ctx)
	if errors.Is(err, store.ErrNoRows) {
		return st, fmt.Errorf("%w: system setting %s is missing", ErrQuotaUnavailable, TenantCapKey)
	}
	if err != nil {
		return st, err
	}
	if st.Limit, err = limitValue(raw); err != nil {
		return st, fmt.Errorf("%w: system setting %s: %s", ErrQuotaUnavailable, TenantCapKey, err.Error())
	}
	if st.Used, err = q.CountLiveTenants(ctx); err != nil {
		return st, err
	}
	return st, nil
}

func devices(ctx context.Context, q *sqlcdb.Queries, tenantID uuid.UUID, adding int64, lock bool) (tenants.QuotaStatus, error) {
	st := tenants.QuotaStatus{Resource: tenants.QuotaDevices, Requested: adding}
	var (
		planKey           string
		limits, overrides []byte
		err               error
	)
	if lock {
		var r sqlcdb.LockTenantSubscriptionLimitsRow
		r, err = q.LockTenantSubscriptionLimits(ctx, tenantID)
		planKey, limits, overrides = r.PlanKey, r.Limits, r.Overrides
	} else {
		var r sqlcdb.GetTenantSubscriptionLimitsRow
		r, err = q.GetTenantSubscriptionLimits(ctx, tenantID)
		planKey, limits, overrides = r.PlanKey, r.Limits, r.Overrides
	}
	switch {
	case errors.Is(err, store.ErrNoRows):
		// no live subscription: no device allowance (Limit 0, Plan "") — refused unless nothing is added
	case err != nil:
		return st, err
	default:
		st.Plan = planKey
		if st.Limit, err = effectiveLimit(limits, overrides, "max_devices"); err != nil {
			return st, fmt.Errorf("%w: plan %s: %s", ErrQuotaUnavailable, planKey, err.Error())
		}
	}
	if st.Used, err = q.CountTenantDevices(ctx, tenantID); err != nil {
		return st, err
	}
	return st, nil
}

// effectiveLimit is PlanLimits[key] of the subscription: the override when it holds the key, else the plan's (§13.3:
// an override replaces one key). The plan must hold the key (0012 requires the four quota keys).
func effectiveLimit(limits, overrides []byte, key string) (int64, error) {
	var plan, over map[string]json.RawMessage
	if err := json.Unmarshal(limits, &plan); err != nil || plan == nil {
		return 0, errors.New("limits is not an object")
	}
	if len(overrides) > 0 {
		if err := json.Unmarshal(overrides, &over); err != nil {
			return 0, errors.New("overrides is not an object")
		}
	}
	if v, ok := over[key]; ok {
		n, err := limitValue(v)
		if err != nil {
			return 0, fmt.Errorf("override %s: %w", key, err)
		}
		return n, nil
	}
	v, ok := plan[key]
	if !ok {
		return 0, fmt.Errorf("plan has no %s", key)
	}
	n, err := limitValue(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	return n, nil
}

// limitValue reads a JSON number that is an integer 0…2147483647 (the range of mg_plan_limits_valid, 0012 — which
// also accepts an integral value written with a fraction, e.g. 10.0).
func limitValue(raw []byte) (int64, error) {
	bad := errors.New("not an integer within 0…2147483647")
	if t := bytes.TrimSpace(raw); len(t) == 0 || t[0] < '0' || t[0] > '9' { // a JSON string would decode as a Number too
		return 0, bad
	}
	var num json.Number
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err := d.Decode(&num); err != nil || d.More() {
		return 0, bad
	}
	if n, err := strconv.ParseInt(num.String(), 10, 64); err == nil {
		if n < 0 || n > math.MaxInt32 {
			return 0, bad
		}
		return n, nil
	}
	f, err := strconv.ParseFloat(num.String(), 64)
	if err != nil || f != math.Trunc(f) || f < 0 || f > math.MaxInt32 {
		return 0, bad
	}
	return int64(f), nil
}
