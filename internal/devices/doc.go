// Package devices is the device inventory of a tenant (§4.2 module `devices`, P2-T13 of the master plan): the
// platform's device register on top of the node cache of the tenant's Headscale (device_inventory_cache, §6.3), the
// job inventory.sync that keeps it in step, two-phase revocation (revocation_state + job device.revoke, T-17) and the
// operations behind the devices endpoints of §13.2. Headscale is reached only through headscale.Registry (§13.4); the
// HTTP adapter is internal/httpapi/devicesapi.
//
// Sync (Service.Sync — inventory.sync, POST …/devices/sync, GET …/devices?fresh=true):
//
//  1. a short transaction reads the database clock — the snapshot time T0 —, the live instance of the tenant, the
//     node_expiry limit (TenantSettings.node_expiry, else node.expiry of the instance's rendered config) and the map
//     mg-<membership_uuid> → membership;
//  2. ListNodes, outside any transaction. Every cache row is normalised from ListNodes only (V-28: GetNode reports
//     subnet_routes = [] and user = null for tagged nodes);
//  3. one transaction locks device_inventory_sync_state of the instance and skips the snapshot when a newer one was
//     applied (synced_at ≥ T0: a stale snapshot never overwrites a newer one); otherwise, with generation + 1: a node
//     whose (instance, node id) has a live row with the same machine key updates it; the same node id with another
//     machine key (id handed out again after a restore — §6.3) marks the old row removed and inserts a new one; a node
//     without a live row is inserted, unless the newest row of that exact node was removed at or after T0 (the
//     snapshot predates the removal); a live row whose node is absent is marked removed. The owner of a user-owned
//     node is the membership named by its Headscale user; the owner of a tagged node is platform data and kept;
//  4. the expiry clamp (§7.4, §13.4, V-21): a user-owned node whose expiry is empty or beyond registration +
//     node_expiry is expired at exactly that time (ExpireNode with an explicit time), with an audit pair
//     device.expiry_clamp.requested → .succeeded/.failed (actor system) and security_event kind expiry_overridden;
//  5. revocations still pending whose job ended without success are settled failed (safety net).
//
// Revocation (Service.Revoke — POST …/expire, DELETE …/devices/{id}): pending + device.<kind>.requested + job
// device.revoke in one transaction (202); the job re-checks the node identity (node id + machine key), expires the
// live pre-auth keys of the node's user (§7.4), calls ExpireNode(requested_at) or DeleteNode, reads back with GetNode
// and only then settles applied (+ .succeeded). Instance not answering ⇒ the state stays pending and the job retries
// with backoff; out of attempts ⇒ failed + alert; Headscale refuses ⇒ failed at once; read-back not matching ⇒
// pending + retry.
package devices
