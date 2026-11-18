package platform

// PATCH /platform/tenants/{id} (P4-T03a; §8.5 platform.tenant:update — "tên, plan, quota"): the registry name, the
// plan of the live subscription and its overrides (subscriptions.overrides — partial PlanLimits). One platform
// transaction locks the tenant row and the live subscription, writes, and records platform.tenant.update with the
// values before and after; every change bumps the tenant's version (the ETag of GET /platform/tenants/{id}).

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
)

// ActionTenantUpdate is the audit action of PATCH /platform/tenants/{id}.
const ActionTenantUpdate = "platform.tenant.update"

// TenantPatch is PATCH /platform/tenants/{id}; nil = unchanged. LimitsOverride replaces the overrides ({} removes
// them all).
type TenantPatch struct {
	Name           *string
	PlanKey        *string
	LimitsOverride []byte
}

// UpdateTenant applies a TenantPatch (If-Match = the tenant's version ETag). A deleted tenant is 404; a tenant being
// deprovisioned 409; a plan that does not exist or is closed 422; a plan or override change without a live
// subscription 409. Lowering a quota below the current use removes nothing — the next addition is refused.
func (s *Service) UpdateTenant(ctx context.Context, id uuid.UUID, p TenantPatch, ifMatch string) error {
	if p.Name == nil && p.PlanKey == nil && p.LimitsOverride == nil {
		return invalid("body", ReasonEmpty)
	}
	if p.Name != nil {
		n := strings.TrimSpace(*p.Name)
		if n == "" || utf8.RuneCountInString(n) > 128 || !utf8.ValidString(n) {
			return invalid("name", "invalid_name")
		}
		p.Name = &n
	}
	if p.PlanKey != nil && !planKeyRE.MatchString(*p.PlanKey) {
		return invalid("plan_key", "invalid_plan")
	}
	if p.LimitsOverride != nil {
		if f := CheckPlanLimits(p.LimitsOverride, true); f != "" {
			return invalid(strings.Replace(f, "limits", "limits_override", 1), "invalid_limits")
		}
	}
	return s.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		t, err := q.LockTenantRow(ctx, id)
		if errors.Is(err, store.ErrNoRows) || (err == nil && t.Status == tenants.StatusDeleted) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if err := ifMatchVersion(ifMatch, t.Version); err != nil {
			return err
		}
		if t.Status == tenants.StatusDeprovisioning {
			return refuse(ErrConflict, ReasonTenantClosed)
		}
		now := time.Now().UTC()
		d := audit.Details{}
		var changed []string
		name := t.Name
		if p.Name != nil && *p.Name != t.Name {
			name = *p.Name
			changed = append(changed, "name")
			d["before_name"], d["after_name"] = t.Name, name
		}
		if p.PlanKey != nil || p.LimitsOverride != nil {
			sub, err := q.LockLiveSubscription(ctx, id)
			if errors.Is(err, store.ErrNoRows) {
				return refuse(ErrConflict, ReasonNoSubscription)
			}
			if err != nil {
				return err
			}
			planID, planKey, overrides := sub.PlanID, sub.PlanKey, sub.Overrides
			if p.PlanKey != nil && *p.PlanKey != sub.PlanKey {
				plan, err := q.GetActivePlanByKey(ctx, *p.PlanKey)
				if errors.Is(err, store.ErrNoRows) {
					return invalid("plan_key", ReasonPlanUnavailable)
				}
				if err != nil {
					return err
				}
				planID, planKey = plan.ID, plan.Key
				changed = append(changed, "plan_key")
				d["before_plan"], d["after_plan"] = sub.PlanKey, planKey
			}
			if p.LimitsOverride != nil && !bytes.Equal(bytes.TrimSpace(p.LimitsOverride), bytes.TrimSpace(sub.Overrides)) {
				overrides = p.LimitsOverride
				changed = append(changed, "limits_override")
				d["before_limits_override"], d["after_limits_override"] = string(sub.Overrides), string(overrides)
			}
			if planID != sub.PlanID || !bytes.Equal(overrides, sub.Overrides) {
				err := q.UpdateSubscriptionPlan(ctx, sqlcdb.UpdateSubscriptionPlanParams{PlanID: planID, Overrides: overrides,
					Now: now, ID: sub.ID, TenantID: id})
				if store.SQLState(err) == "23514" {
					return invalid("limits_override", "invalid_limits")
				}
				if err != nil {
					return err
				}
			}
		}
		if len(changed) > 0 {
			if _, err := q.UpdateTenantName(ctx, sqlcdb.UpdateTenantNameParams{Name: name, Now: now, ID: id}); err != nil {
				return err
			}
		} else {
			changed = []string{}
		}
		d["changed"] = changed
		return audit.Record(ctx, q, audit.Event{Action: ActionTenantUpdate, ResourceType: "tenant", ResourceID: id.String(),
			Details: d})
	})
}
