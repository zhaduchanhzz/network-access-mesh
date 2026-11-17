package devices

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/notifications"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// notifyExpiring writes the device.expiring notifications of an instance (P3-T05b): every live device not being (or
// already) revoked whose node key expires within ExpiryNotice gets one — its owner, or the Tenant Owners and Admins
// for a device without an owner (tagged). The notifications module dedupes on (device, expiry), so a later sync of the
// same expiry writes nothing and a new expiry (re-authentication) is a new notice. One tenant transaction (outbox +
// notification.send jobs commit together); a device whose name the module refuses (not a plain single-line name) is
// skipped. Returns how many devices got a new notice.
func (s *Service) notifyExpiring(ctx context.Context, tenantID, instanceID uuid.UUID) (int, error) {
	if s.notice < 0 {
		return 0, nil
	}
	before := s.now().Add(s.notice)
	n := 0
	err := s.st.WithTenantJobTx(ctx, tenantID, func(tx *store.Tx) error {
		rows, err := tx.Q.ListExpiringDevices(ctx, sqlcdb.ListExpiringDevicesParams{TenantID: tenantID,
			InstanceID: instanceID, Before: before})
		if err != nil {
			return err
		}
		for _, r := range rows {
			if r.Expiry == nil {
				continue
			}
			res, err := s.notify.Enqueue(ctx, tx, notifications.DeviceExpiring(tenantID, r.ID, r.OwnerMembershipID,
				r.DisplayName, r.Expiry.UTC().Truncate(time.Second)))
			if errors.Is(err, notifications.ErrInvalidEvent) {
				s.log.WarnContext(ctx, "devices: expiry notice skipped", "device_id", r.ID, "error", err.Error())
				continue
			}
			if err != nil {
				return err
			}
			if !res.Duplicate && len(res.Notifications) > 0 {
				n++
			}
		}
		return nil
	})
	return n, err
}
