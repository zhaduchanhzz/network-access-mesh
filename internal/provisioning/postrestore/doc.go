// Package postrestore is the reconcile after PostgreSQL was restored to an OLDER point in time (P3-T17; master plan
// §17.2 "Đối soát sau khi restore PostgreSQL về thời điểm cũ hơn", §17.4, §6.4, §8.3, §8.7, §11.4, §18 T-15/T-16) — the
// work of the host command `meshguard admin post-restore-reconcile`, run in the worker container while api and worker
// are in maintenance mode (platform.MaintenanceGate). After such a restore the registry is OLDER than the real state of
// the instances: what was revoked in the lost window is alive again in the database, tenants created in it exist on the
// host only, keys rotated in it are unknown, policies applied in it are newer than the database's. Headscale stays
// authoritative for nodes, keys and the policy in force (§6.4); PostgreSQL for the registry.
//
// One run, every step idempotent, `cutoff` = the database clock when the run starts:
//
//  1. maintenance: the persisted flag (system_settings `maintenance`) is set ON in the restored database with the
//     post_restore record (status running) — dropping the startup switch MG_MAINTENANCE can no longer reopen the API
//     before the run finished and was reviewed; audited platform.restore.reconcile.requested;
//  2. revocations: every session created before cutoff revoked (sessions.revoked_at, migration 0018), the auth requests
//     of the dump deleted; every approval request still open (pending, approved not executed) and every executed
//     Keycloak console session still in its window expired; every pending invitation revoked; every approved support
//     access grant revoked and every pending one expired (migration 0023, P4-T05 — a dump of an older schema has none);
//  3. instances: the Host Agent's inventory (ListInstances) against the registry through the report-only inspector of
//     P3-T12 — an instance on the host with no registry row (a tenant created in the gap) is an ORPHAN: reported,
//     never deleted, never adopted (adopt-instance or a 2P deprovision decides); a registered instance with nothing on
//     the host (deprovisioned in the gap) is LOST: marked failed, never provisioned again;
//  4. API keys: for each running instance the rotation of P3-T10 under apikey.LockName with AllowBootstrap and
//     trigger post_restore — the stored key still works and is not due ⇒ nothing; it is refused (rotated in the gap)
//     or its secret is lost ⇒ re-issued by the agent's BootstrapApiKey, every other valid key expired;
//  5. policies: Headscale's GetPolicy against the current application (policies.Service.ReviewRunning) — different ⇒
//     never overwritten: recorded as current application (trigger restore), imported as a validated version made
//     desired, tenant flagged for review (security event policy.restore_review_required);
//  6. inventory.sync enqueued for every running instance (it runs once the worker leaves maintenance);
//  7. jobs still open in the dump listed for review (the worker resumes them when it leaves maintenance);
//  8. audit.gap — one platform event and one per tenant naming the lost window [restore point, cutoff] — then the
//     post_restore record says reconciled; maintenance stays ON until `meshguard admin maintenance off`.
//
// A dry run (Request.DryRun) reads and counts only: no write to the database, no call that changes an instance or the
// host. The report (Report) holds no secret: ids, slugs, counts, key prefixes, hashes.
package postrestore
