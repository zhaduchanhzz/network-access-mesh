// Package deprovision is the deletion of a tenant (§11.4 "Deprovision", P3-T09): the lifecycle job tenant.deprovision
// of §13.5 (one lifecycle job per tenant — lock tenant:<id>:lifecycle), its API side behind dual control
// (DELETE /platform/tenants/{tenantId}, platform.tenant:delete — always 2P, §8.5, §13.2) and the periodic job
// tenant.keys_destroy that destroys the keys of deleted tenants once their grace period has passed (crypto-shredding,
// §6.1).
//
// API (the api process): the handler checks the request (Requester.Check — the tenant exists and can be deprovisioned,
// the slug typed by the requester is the tenant's) and turns it into an approval request of action
// platform.tenant.delete (payload: tenant_id, slug, skip_final_backup). When a second Super Admin approves it, the
// action apps/internal/runner registers runs Requester.EnqueueApproved in the approval's transaction: the checks again,
// audit platform.tenant.delete.requested, the job and its step 1 `validate`.
//
// Worker (Handler), in the order of §11.4:
//
//	 1 validate              API, in the approval's transaction                       compensation (/rollback only)
//	 2 backup.final          the final backup (backup.Service.FinalBackup — the       — (the backup stays in the book)
//	                         §17.1 path of instance.backup, in-process: an
//	                         instance.backup job would wait for this job's lock),
//	                         kept ≥ the key grace period; it fails ⇒ the job stops
//	                         failed_resumable — never past it without the backup,
//	                         unless the approved payload skips it (audited override
//	                         + security event)
//	 3 policy.suspend        the suspension policy (deny-all) through the policy core the desired version applied again
//	                                                                                  (only when the tenant was active)
//	 4 registry.deprovision  active|suspended|failed → deprovisioning: writes of     back to the status recorded
//	                         the tenant's roles refused, no login, no target of
//	                         monitoring, probes, sync, backups, rotation any more
//	 5 nodes.expire          POINT OF NO RETURN — every node expired (devices must   none (/rollback refused)
//	                         authenticate again), every valid pre-auth key expired;
//	                         read back
//	 6 access.revoke         every Portal session of the tenant's identities, its
//	                         pending logins, pending invitations, open approvals
//	 7 targets.remove        the instance is in no schedule target list any more
//	                         (health.probe, relay.probe, inventory.sync,
//	                         instance.backup, apikey.rotate)
//	 8 edge.detach           RemoveEdgeAttachment (the edge_attach flag first, then
//	                         detach — the shared edge never breaks)
//	 9 instance.remove       RemoveInstance(KEEP): compose down, then the network
//	10 storage.remove        RemoveInstance(DELETE_ARCHIVED, final backup's
//	                         sequence): the data directory (the agent checks the
//	                         signed archive); no final backup ⇒ the directory stays
//	11 idp.disable           every issuer of the tenant disabled (keycloak realm
//	                         disabled; external: disabled), rows disabled
//	12 relay.remove          relay assignments and embedded regions deleted
//	13 registry.delete       instance → removed, tenant → deleted (row kept, slug
//	                         reserved), subscription cancelled, instance API key
//	                         versions destroyed
//	14 keys.schedule         tenants.keys_destroy_after = deleted_at + KeyGrace
//	15 notify                tenant.deleted to the Owners and Admins, audit
//	                         .succeeded
//
// Point of no return: step 5 records its created_resources just before it expires the first node; from then on
// /rollback is refused (jobs.Kind.PointOfNoReturn, StateError point_of_no_return) and the compensation refuses too.
// Before it, /rollback undoes steps 4 and 3: the tenant is back in its status behind its desired policy (a suspended
// tenant stays behind the suspension policy); the final backup stays. A permanent error never compensates by itself:
// the job stops failed_resumable (like tenant.suspend — undoing a deprovision is an operator's decision).
//
// After step 13 the tenant is `deleted`: authorization treats it as non-existent (404), its slug stays reserved while
// any object of it remains — the final backup (until purged), the DEK (until the grace period has passed and the keys
// are destroyed) — and it no longer counts against quota.max_tenants. tenant.keys_destroy (Shredder, periodic) purges
// the tenant's issuers (keycloak realm deleted) and destroys every DEK and secret version of tenants whose
// keys_destroy_after has passed: the SecretStore can no longer decrypt anything of the tenant and the online restore of
// the final backup (its data key is wrapped under the tenant's backup key) is gone; the offline recovery identity still
// opens the archive until the backup is purged (P6-T04).
//
// The Headscale registry of the handler must reach the instance of a tenant that is `deprovisioning`
// (ReachableStatuses): the registry of every other job refuses it.
package deprovision
