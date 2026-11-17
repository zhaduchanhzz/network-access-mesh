// Package provisioning brings tenant instances under the platform's management (§11). The orchestrator (state
// machine, compensation, Agent client) arrives in Phase 3; Phase 2 has only the adoption of the two instances built by
// hand in Phase 1 (P2-T11) — the out-of-band equivalent of steps 2, 3, 13, 16 and 19 of §11.3 — and the registration of
// the identity providers of the realms created in P2-T05:
//
//   - Adopter.Adopt (`meshguard admin adopt-instance`): registers the tenant, its host, its instance (from
//     meta/instance.json) and its identity provider; checks a NEW Headscale API key (read from stdin by the command)
//     through the edge admin listener before anything is written; stores it in the SecretStore; verifies it again
//     through headscale.Registry.ForTenant — the production path; then expires every other API key of the instance
//     (Phase 1 keys included) and activates tenant and instance.
//   - RegisterPlatformIdP and SetClientSecret (`meshguard admin register-platform-idp`, `set-idp-client-secret`).
//   - Bootstrapper (P2-T11a): BootstrapSuperAdmin (`meshguard admin bootstrap-super-admin` — the first two Super
//     Admins by (platform IdP, sub), refused from SuperAdminThreshold active Super Admins on, under the Super Admin
//     assignment lock) and SeedMembership (`meshguard admin seed-membership` — Tenant Owner / Tenant Admin by (the
//     tenant's own IdP, sub), without tenant_invitations). Their audit events (actor_type system) are written with
//     internal/audit in the transaction of the change; the issuer binding is the database's (composite foreign keys).
//
// Nothing here prints, logs or returns a credential: keys travel as headscale.Secret, the SecretStore keeps them
// encrypted, the registry holds mgsec:// references and public key prefixes only. Audit events go through the Auditor
// interface (P2-T08 builds internal/audit in parallel; LogAuditor is the default until P2-T16 wires it).
package provisioning
