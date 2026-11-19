// Package network is the tenant's network module (P4-T12 — §4.2 `network`, §12.3 Routes / DNS / Resources, §13.2
// groups "routes", "dns", "resources", §8.6 tenant.route:*, tenant.dns:*, tenant.resource:*, threats T-08 and T-09):
//
//	routes     GET /routes — every live device of the register with its advertised and approved routes (the cache of
//	           inventory.sync, with synced_at), the exit node, the warnings of §12.3/T-08: a prefix that overlaps one
//	           of another device, a router that is not a tagged node. POST /routes/approve and /routes/revoke take
//	           {device_id, prefixes[]} and If-Match = the device's routes_etag (428 when missing): the device row is
//	           locked FOR UPDATE for the whole read–check–write, the approved set is read DIRECTLY from Headscale (never
//	           the cache) and must still hash to If-Match (412 otherwise), approve only takes prefixes the node
//	           advertises now (422), the exit node is 0.0.0.0/0 + ::/0 together and needs confirm_exit_node (422),
//	           SetApprovedRoutes replaces the whole set (PL-10) and its read-back must hold exactly the new set. Two
//	           concurrent approvals of one device never lose a prefix: the second waits for the row, then reads the new
//	           set from Headscale and gets 412. With TenantSettings.routes.four_eyes an approval changes nothing: the
//	           caller gets the payload of a tenant approval request (tenant.route.approve — the single mechanism of
//	           approval_requests / internal/authz/approvals), executed by ExecuteRouteApproval once a second person
//	           approved it, on the exact approved set and only while the device's routes still have the approved ETag.
//	           A revocation never needs a second person (it narrows access).
//	dns        GET /dns: MagicDNS (always on — the platform renders dns.base_domain), the nameservers of the
//	           configuration version in force and the unfinished reconfiguration, if any. PUT /dns/settings (If-Match
//	           = the view's etag) enqueues instance.reconfigure through the internal entry point of P3-T13
//	           (orchestrator.EnqueueReconfigure, wired in apps/ — network may not import provisioning, §13.6): a new
//	           configuration version applied with a controlled restart behind a health gate, rolled back when it does
//	           not come up (202 + the job). GET/POST /dns/records, DELETE /dns/records/{id}: dns_records (A ⇔ IPv4,
//	           AAAA ⇔ IPv6; T-09 lint: a value must be a tailnet address of one of the tenant's devices or inside a
//	           route the tenant approved; a name under the platform's domain only inside the tenant's own MagicDNS
//	           domain) and the level-triggered job dns.records_write: the worker reads the whole set when it runs and
//	           the Host Agent writes records/extra-records.json atomically (WriteDnsRecords — tmp + rename in the
//	           directory Headscale watches; [] when empty): no restart.
//	resources  the Network Resource Catalog (§6.3 network_resources — the `hosts` aliases of §7.2): CRUD with an
//	           Idempotency-Key on create and If-Match on PATCH/DELETE; tags only from the tenant's catalog (P4-T15 —
//	           policies.RequireTags in the same transaction, wired in apps/), the owner group of the tenant; every
//	           change enqueues policy.apply (trigger resource_change) in its transaction — the one handler of
//	           internal/policies.
//
// The register of devices belongs to internal/devices (§13.6: network and devices only meet through a service
// interface): DeviceRegister is implemented there and wired in apps/. Every write records its audit event in the
// transaction of the change (Headscale calls: a paired operation — requested before the call, succeeded/failed after).
package network
