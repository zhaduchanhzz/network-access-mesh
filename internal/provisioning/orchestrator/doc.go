// Package orchestrator is the Tenant Orchestrator of §11 (P3-T05): the state machine of tenant.provision — the 19
// steps of §11.3, each idempotent and recorded in provisioning_job_steps, executed by the job framework
// (internal/jobs, River) — and the two API-side entry points:
//
//   - Creator — POST /platform/tenants: step 1 `validate` (slug, reserved names, duplicates, a deleted tenant's
//     leftovers, plan, quota) and step 2 `registry.create` (tenant `provisioning`, subscription, audit
//     platform.tenant.create.requested, the job and its first two step rows) in ONE platform transaction;
//   - Control — POST /platform/jobs/{id}/retry, /cancel, /rollback (§13.2, platform.job:control): the transitions of
//     jobs.Transitions, plus the kind-specific /retry of a rolled_back tenant.provision (a NEW job from step 3).
//
// Steps 3–19 run in the worker (Provisioner, jobs.Handler + jobs.Compensator):
//
//	 3 placement.allocate   platform.Placer (host, run_uid, /29, hostname); instance id chosen first, kept in
//	                        created_resources                                   ⟲ Release: instance → removed
//	 4 dns.ensure           DNSChecker (wildcard mode: resolution of <slug>.mesh.<domain> only)
//	 5 secrets.generate     SecretStore.EnsureDEK (tenant DEK)                  ⟲ none: the DEK stays for /retry (§11.4 shreds it)
//	 6 idp.ensure           IdP driver EnsureIssuer + EnsureClient; identity_providers row `pending`
//	                                                                            ⟲ RemoveIssuer(disable), row → disabled
//	 7 storage.create       Agent EnsureInstance(storage)                       ⟲ RemoveInstance(DELETE_IF_NEVER_ACTIVATED)
//	 8 config.render        Agent ValidateConfig, EnsureInstance(config); instance_config_versions
//	 9 network.ensure       Agent EnsureInstance(network)                       ⟲ RemoveInstance(KEEP)
//	10 instance.start       instance → starting; Agent EnsureInstance(container)
//	                                                                            ⟲ RemoveInstance(KEEP), instance → failed
//	11 instance.wait_healthy Agent GetInstanceStatus until healthy (90 s); noise_key_fingerprint
//	12 policy.bootstrap     Agent BootstrapPolicy (deny-all) — BEFORE the edge is attached (PL-02)
//	13 apikey.bootstrap     Agent BootstrapApiKey; the key goes straight into the SecretStore (never logged, never in a
//	                        step, detail or error)                              ⟲ secret versions destroyed, registry cleared
//	14 edge.attach          Agent EnsureEdgeAttachment                          ⟲ RemoveEdgeAttachment(COMPENSATION)
//	15 policy.verify        Headscale GetPolicy = baseline; policy_versions v1, desired, policy_applications(bootstrap)
//	16 tenant.configure     settings, IdP `active`, Owner invitation + its notification
//	                                                                            ⟲ invitation revoked
//	17 relay.assign         relay_regions(embedded) + relay_assignments; Prober.Relay
//	                                                                            ⟲ rows deleted
//	18 edge.verify          Prober.Edge (/key?v= = fingerprint, forbidden paths 404) + Headscale Health
//	19 activate             tenant → active, instance → running, audit .succeeded, notification tenant.activated
//
// Failure handling (§11.3): a transient error is retried in place 5 times with backoff 2 s → 60 s ± 20 %; spent ⇒
// jobs.Resumable ⇒ failed_resumable (no compensation, the lock kept; /retry resumes from the failed step). A permanent
// error ⇒ compensation in reverse order (jobs.Run.CompensateSteps) ⇒ rolled_back, tenant `failed`, audit .failed. The
// whole job has the 10-minute deadline of the lifecycle group. Steps 4, 17 and 18 are behind interfaces (DNSChecker,
// Prober) so CI runs without public DNS.
//
// Nothing here logs or returns a credential: the API key exists only between the agent's response and the SecretStore,
// IdP secrets only as mgsec:// references.
//
// instance.reconfigure (P3-T13, reconfigure.go): a new configuration version of a running instance — validated,
// recorded `pending`, written, restarted, behind the health gate and the post-start gate of §11.4 — rolled back to the
// previous version when it does not come up (InstanceReconfigurer, jobs.Handler + jobs.Compensator); its API side is
// ReconfigureService (POST /platform/instances/{instanceId}/reconfigure) and EnqueueReconfigure, the internal entry
// point of the Phase 4 operations that change a setting rendered into the instance's configuration.
package orchestrator
