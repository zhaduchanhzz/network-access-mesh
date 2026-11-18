// Package lifecycle is the suspension of a tenant and its reversal (§11.4 "Suspend", P3-T08): the lifecycle jobs
// tenant.suspend and tenant.resume of §13.5 — one lifecycle job per tenant at a time (dedupe and lock key
// tenant:<id>:lifecycle) — and their API side, POST /platform/tenants/{tenantId}/suspend and /resume (§13.2,
// platform.tenant:suspend).
//
// API (Requester, the api process, one platform transaction): the tenant must exist (404), must be `active` for a
// suspend (`suspended` ⇒ 409 already_suspended) or `suspended` for a resume (`active` ⇒ 409 not_suspended), and must
// have a desired policy version — the version resume restores (§11.4 "lưu version": the desired version is kept, the
// job input records it). An unfinished lifecycle job of the tenant of the same kind is returned as is (202, nothing
// written); one of another kind ⇒ 409 lifecycle_job_in_progress. Otherwise: audit platform.tenant.<suspend|resume>
// .requested, the job (its River job included) and its step 1 `validate`, with the Idempotency-Key of the request.
//
// Worker (Handler):
//
//	tenant.suspend                                                    compensation (only by /rollback, reverse order)
//	  1 validate            API, in the transaction of the request    —
//	  2 policy.suspend      suspension policy (deny-all) through the  the desired version applied again (trigger
//	                        policy core: version kind suspension,      resume)
//	                        trigger suspend; desired version kept
//	  3 registry.suspend    tenants.status active → suspended: from   suspended → active
//	                        here every write of a tenant role is
//	                        refused (§8.4 invariant 5 — authz), web-auth
//	                        claims and enrollment included (P4-T06)
//	  4 preauthkeys.expire  ExpirePreAuthKey on every valid pre-auth  — (an expired key stays expired)
//	                        key, then ListPreAuthKeys: none valid
//	  5 notify              tenant.suspended to the Owners and Admins, —
//	                        audit .succeeded
//
//	tenant.resume                                                     compensation (automatic on a permanent error,
//	                                                                  or /rollback — reverse order)
//	  1 validate            API                                       —
//	  2 policy.resume       the desired version applied again          the suspension policy applied again
//	                        (kind baseline, trigger resume)            (trigger suspend)
//	  3 registry.resume     suspended → active                        active → suspended
//	  4 notify              tenant.resumed, audit .succeeded           —
//
// Order of the suspension: the policy first (the traffic is cut as early as possible), then the status — which closes
// every write of the tenant, including the issuing of new pre-auth keys —, then the keys: once the status is
// `suspended` no key can be issued, so none issued during the job survives it (the order of §11.4 — keys before the
// status — would leave that window open). The instance keeps running: it distributes the deny-all policy to the
// clients (§11.4); nodes are not expired, so resume is immediate.
//
// Failure (§11.3): a transient error is retried in place (StepRetries, backoff RetryBase → RetryMax ± 20 %), then the
// job stops failed_resumable, keeping the lifecycle lock (/retry resumes from the failed step). A permanent error of
// tenant.suspend also stops failed_resumable — never an automatic compensation, which would return a tenant to
// `active` that an operator suspended (fail closed); /rollback undoes it on purpose. A permanent error of
// tenant.resume is compensated at once: the tenant stays suspended behind the suspension policy, the job ends
// rolled_back. Either compensation closes the audit pair with .failed.
//
// The Headscale registry of the handler must reach the instance of a suspended tenant (locator.Options
// TenantStatuses: active and suspended): the registry of the other jobs refuses it (G2 L1), and so does every API
// path of the tenant.
package lifecycle
