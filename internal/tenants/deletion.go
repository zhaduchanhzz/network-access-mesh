package tenants

// POST /tenants/{t}/request-deletion (P4-T03a; §8.4 "Tenant Owner … yêu cầu xóa tenant", §8.6
// tenant.lifecycle:request_delete): the Owner asks; nothing is deleted or suspended — the deletion is DELETE
// /platform/tenants/{id}, always 2P (§11.4, P3-T09). The request is recorded twice: a platform event + notification of
// the Super Admins and Platform Operators (platform transaction — the reason is in the platform audit), then the
// tenant's audit event + the notification of the tenant's Owners (tenant transaction). The platform is notified at most
// once per tenant and UTC day (notification ref); a repeated request the same day is audited only.

import (
	"context"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/notifications"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// Audit actions of the deletion request.
const (
	ActionDeletionRequest         = "tenant.deletion.request"
	ActionPlatformDeletionRequest = "platform.tenant.deletion_requested"
)

// DeletionRequest is schema TenantDeletionRequest.
type DeletionRequest struct {
	TenantID         uuid.UUID
	RequestedAt      time.Time
	RequestedBy      uuid.UUID
	RequestedByName  string
	PlatformNotified bool
}

// RequestDeletion is POST /tenants/{t}/request-deletion: confirmSlug must be the tenant's slug (422), reason 1–1000
// characters, step-up.
func (s *Service) RequestDeletion(ctx context.Context, a Actor, tenantID uuid.UUID, confirmSlug, reason string) (DeletionRequest, error) {
	reason = strings.TrimSpace(reason)
	if reason == "" || utf8.RuneCountInString(reason) > 1000 || !utf8.ValidString(reason) {
		return DeletionRequest{}, adminInvalid("reason", "invalid_reason")
	}
	var slug, name string
	err := s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		r, err := q.GetTenantSettingsRow(ctx, tenantID)
		if errors.Is(err, store.ErrNoRows) || (err == nil && r.ID != tenantID) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		slug = r.Slug
		if m, err := q.GetTenantMember(ctx, sqlcdb.GetTenantMemberParams{TenantID: tenantID, ID: a.MembershipID}); err == nil {
			name = member(m).DisplayName
		}
		return nil
	})
	if err != nil {
		return DeletionRequest{}, err
	}
	if strings.TrimSpace(confirmSlug) != slug {
		return DeletionRequest{}, adminInvalid("confirm_slug", "slug_mismatch")
	}
	if err := s.stepUp(a); err != nil {
		return DeletionRequest{}, err
	}
	now := s.now().UTC()
	out := DeletionRequest{TenantID: tenantID, RequestedAt: now, RequestedBy: a.IdentityID, RequestedByName: name}
	pctx := audit.WithoutTenant(ctx) // the platform event must not inherit the tenant of the path
	err = s.st.WithPlatformJobTx(pctx, func(tx *store.Tx) error {
		res, err := notifications.Enqueue(pctx, tx, notifications.PlatformTenantDeletionRequested(tenantID, slug, name, now))
		if err != nil {
			return err
		}
		out.PlatformNotified = !res.Duplicate
		return audit.Record(pctx, tx.Q, audit.Event{Action: ActionPlatformDeletionRequest, TenantID: nil,
			ResourceType: "tenant", ResourceID: tenantID.String(), Details: audit.Details{"tenant_id": tenantID,
				"tenant_slug": slug, "requested_by_identity_id": a.IdentityID, "reason": reason,
				"platform_notified": out.PlatformNotified}})
	})
	if err != nil {
		return DeletionRequest{}, err
	}
	err = s.st.WithTenantJobTx(ctx, tenantID, func(tx *store.Tx) error {
		if err := audit.Record(ctx, tx.Q, audit.Event{Action: ActionDeletionRequest, TenantID: &tenantID,
			ResourceType: "tenant", ResourceID: tenantID.String(), Details: audit.Details{"reason": reason,
				"platform_notified": out.PlatformNotified}}); err != nil {
			return err
		}
		_, err := notifications.Enqueue(ctx, tx, notifications.TenantDeletionRequested(tenantID, name, now))
		return err
	})
	if err != nil {
		return DeletionRequest{}, err
	}
	return out, nil
}
