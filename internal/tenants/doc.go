// Package tenants is the Tenant Registry of the Management Plane (§4.2, §5.4): tenants, the tenant → Headscale instance
// mapping (tenant_instances), the identity provider bound to a tenant (identity_providers) and the read side of
// memberships (§13.2 "users (đọc)"). Lifecycle writes (create, suspend, delete) arrive with P3; in Phase 2 the only
// writer is `meshguard admin adopt-instance` (P2-T11), which registers the two tenants built by hand in Phase 1.
//
// Every query runs through internal/store with the scope of its caller (§6.1, §8.8 layers 3–4):
//   - tenant-scope reads (GET /tenants, GET /tenants/{t}, GET /tenants/{t}/users[/{id}], LocateInstance) run in
//     store.WithTenantTx on the tenant pool: RLS shows only the tenant of the path (or of the caller's identity), and
//     each query also filters on tenant_id (layer 5);
//   - platform reads (GET /platform/tenants[/{t}]) run in store.WithPlatformTx and return registry metadata only —
//     tenant-internal tables (tenant_memberships…) have no platform branch, so staff never see them here (§8.4
//     invariant 2);
//   - registry writes run in store.WithPlatformTx (only the platform roles may write tenants, tenant_instances and
//     identity_providers — migrations 0001, 0002).
//
// LocateInstance is the registry half of headscale.Registry.ForTenant (§13.4): internal/headscale reads the instance
// of a tenant through it and resolves the API key with the SecretStore. Nothing in this package reads or writes a
// secret value: the instance and IdP rows hold mgsec:// references only (§6.1).
package tenants
