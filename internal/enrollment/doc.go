// Package enrollment is the module `enrollment` of §4.2/§13.6 (P4-T06): adding a device to a tenant's tailnet through
// the Portal (§7.4, ADR-14).
//
//	request    POST /enrollment/requests — the caller's own device. One tenant transaction locks the tenant's
//	           subscription row and checks the quota (devices of the inventory PLUS unfinished requests ≤ max_devices,
//	           for a key with tags tagged devices PLUS unfinished requests with tags ≤ max_tagged_devices, live
//	           credentials ≤ max_live_enrollment_credentials — usage.EnrollmentTx). When the tenant requires an
//	           approval (TenantSettings.enrollment.requires_approval) and the caller cannot approve, the request stops at
//	           pending_approval; otherwise it is issued at once: web_auth ⇒ a one-time enrollment code (hostname
//	           mg-<code>) bound to the caller's Portal session, valid 10 minutes; preauth_key ⇒ a single-use, non-
//	           ephemeral pre-auth key of the caller's own Headscale user mg-<membership>, ≤ 15 minutes, always with an
//	           explicit expiration (V-06).
//	approval   /approve, /reject (tenant.enrollment:approve — the decider is never the requester; the requester is
//	           notified — enrollment.approved / enrollment.rejected — in the decision's transaction), then /start by the
//	           requester in its own Portal session issues the code or the key (§7.4 "Phê duyệt enrollment").
//	keys       POST /enrollment/keys (tenant.enrollment:issue_privileged): tagged, reusable, ephemeral keys, keys for
//	           another member and tag-only keys; requested_tags only from the tenant's catalog (policies.RequireTags in
//	           the same transaction — wired in apps/, enrollment does not import policies).
//	claim      POST /enrollment/web-auth/claim: accepted ONLY when the caller has a web_auth request awaiting a device
//	           that was issued in the same Portal session and has not expired; then AuthRegister and the check of the
//	           node it returns (name = mg-<code>, the expected user, no tag, register method cli). A new node that fails
//	           is deleted at once (security_event); a node that existed before is never deleted — the member's own
//	           device is a re-authentication, anything else is expired (security_event). A verified node is renamed to
//	           the device label, written to the device inventory with its enrollment link, notified (device.new) and
//	           synced (inventory.sync clamps its expiry).
//	revoke     POST /…/revoke: an unfinished request ends revoked; an issued pre-auth key is expired at Headscale and
//	           read back first (audit pair enrollment.revoke.requested → .succeeded/.failed).
//	reconcile  job enrollment.reconcile (worker, per tenant, scheduled while the tenant has open requests, a live
//	           reusable key or an inventory row waiting for its enrollment link): requests waiting for a decision or for
//	           /start for 24 hours, codes and keys past their expiry ⇒ expired; used keys ⇒ consumed with the node that
//	           used them; claims or issuances that never finished ⇒ failed; inventory rows of consumed/verified requests
//	           get their enrollment link. The nodes a pre-auth key registered enter the inventory (or get their link
//	           when inventory.sync came first) and are notified once each (device.new) — at the consumed transition
//	           (so they count against max_devices at once), then for a reusable key while it is live; a reusable key
//	           Headscale ended early (a device revocation expires it) ⇒ revoked.
//
// Plaintext pre-auth keys, enrollment codes and Auth IDs are never stored nor logged (only SHA-256 hashes and the key's
// numeric id); a credential is shown once — the response of an Idempotency-Key replay gets it back from the SecretStore
// (a Vault wired in apps/) until the credential expires, then 410 secret_no_longer_available (§13.1).
//
// Dependencies (§13.6): headscale, tenants, audit, usage and the base modules — never policies (TagGate), authz (the
// caller's "may approve" comes from the HTTP layer) nor secrets (Vault).
package enrollment
