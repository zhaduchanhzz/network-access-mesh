package devices

import (
	"context"
	"net/netip"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// RouteRegister is the device register as the network module sees it (P4-T12 — routes and the DNS lint): network may
// not read device_inventory_cache itself (§13.6 — devices owns it), so it calls these methods inside its own tenant
// transaction q (network.DeviceRegister, wired in apps/).
type RouteRegister struct{}

// ListLive returns the tenant's live devices (not removed), by given name.
func (RouteRegister) ListLive(ctx context.Context, q *sqlcdb.Queries, tenantID uuid.UUID) ([]sqlcdb.DeviceInventoryCache, error) {
	return q.ListLiveDevicesForRoutes(ctx, tenantID)
}

// LockLive locks the live device FOR UPDATE until q's transaction ends (store.ErrNoRows when there is none — another
// tenant's device included, RLS).
func (RouteRegister) LockLive(ctx context.Context, q *sqlcdb.Queries, tenantID, deviceID uuid.UUID) (sqlcdb.DeviceInventoryCache, error) {
	return q.LockLiveDevice(ctx, sqlcdb.LockLiveDeviceParams{TenantID: tenantID, ID: deviceID})
}

// RecordRoutes stores the approved and advertised routes just read from Headscale on the locked device.
func (RouteRegister) RecordRoutes(ctx context.Context, q *sqlcdb.Queries, tenantID, deviceID uuid.UUID, approved, advertised []netip.Prefix) error {
	if approved == nil {
		approved = []netip.Prefix{}
	}
	if advertised == nil {
		advertised = []netip.Prefix{}
	}
	return q.SetDeviceRoutes(ctx, sqlcdb.SetDeviceRoutesParams{ApprovedRoutes: approved, AvailableRoutes: advertised,
		TenantID: tenantID, ID: deviceID})
}
