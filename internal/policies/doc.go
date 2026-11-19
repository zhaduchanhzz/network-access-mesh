// Package policies is the policy module of the Management Plane (§4.2 module `policies`, §7.2, §7.3):
//
//   - the core (P3-T08a, below): applies a policy given as HuJSON — the deny-all baseline, the suspension policy, a
//     test fixture — to a tenant's Headscale and records it;
//   - the tag catalog (P4-T15 — tags.go, tagref.go);
//   - the typed model and its deterministic render (P4-T10 — model.go, render.go: principals by id, groups, hosts and
//     tagOwners rendered from the tables), the lint L3–L13 on the model and on the output (lintmodel.go — the output
//     rules run on every path of the core, before any Headscale call);
//   - the lifecycle of a version on the api's store (versions.go — draft → validated → pending_approval → approved,
//     4-eyes, If-Match, stale base, apply/rollback through the job, diff);
//   - ONE policy.apply handler (job.go, pipeline.go: the desired version rendered with the tables of now, the
//     suspension policy of a tenant being suspended, convergence rounds) and policy.drift_check with its schedule
//     (drift.go).
//
// # Flow (Service.Apply)
//
//	Lint            L2 (empty), syntax (HuJSON via github.com/tailscale/hujson — the parser Headscale itself uses),
//	                L1 ("grants" missing, null or not an array ⇒ allow-all), decoder guard (headscale.
//	                ValidatePolicyDocument). A refused policy is audited (policy.lint_rejected) and nothing else happens.
//	lock            store.WithTenantLock(tenant, "policy"): an advisory lock per tenant held across the Headscale calls
//	                (§7.2 — SetPolicy is last-write-wins); a second application of the same tenant waits.
//	record          policy_versions (source_hujson = the text as given, content_sha256 = its sha256; reused when it is
//	                already the desired version), policy_applications pending (applied_hujson = the exact bytes to
//	                send), policy.apply.requested — committed before the first call.
//	Headscale       CheckPolicy → SetPolicy → GetPolicy through headscale.Registry.ForTenant (§13.4).
//	read-back       sha256(GetPolicy().Data) == applied_sha256. No normalisation of the read-back: the REST API returns
//	                the stored string byte for byte (pinned by the contract tests — `headscale policy get` on the CLI
//	                appends one newline, RT-15, which is why the Phase 1 script dropped it). The normalisation happens
//	                BEFORE sending: Document.Applied is the HuJSON standardized (comments, trailing commas removed) and
//	                re-indented by encoding/json — what is sent, stored and compared is that one canonical string.
//	outcome         applied (supersede the current row, desired version for a baseline, policy.apply.succeeded, the
//	                policy.applied notification) or failed with an error_code; an unknown outcome re-asserts the
//	                previously applied policy first (§7.3, V-26) — no partial application is ever recorded applied.
//
// The internal command `meshguard-worker admin policy-apply` (apps/worker) applies a fixture read from stdin; it
// replaces infrastructure/host/tenant-policy.sh once the instance is reachable through the edge admin listener.
package policies
