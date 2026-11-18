// Package quarantine is the quarantine of a Headscale instance suspected of compromise and its release (§11.4
// "Quarantine", P3-T18): the jobs instance.quarantine and instance.release of §13.5, their API side —
// POST /platform/instances/{instanceId}/quarantine (platform.instance:quarantine, no 2P: the isolation must be
// immediate) and /release (platform.instance:release, always 2P) — and the step gate that makes every other multi-step
// job of a quarantined instance stop at its next step.
//
// Quarantine (API, one platform transaction — Requester.Quarantine):
//
//	1 validate             the instance exists and is not removed; an unfinished quarantine of it ⇒ that job (202)
//	2 registry.quarantine  tenant_instances.status → quarantined AT ONCE (any status but removed; the previous one in
//	                       created_resources), security event instance.quarantined (critical), audit
//	                       platform.instance.quarantine.requested — from this commit on: the step gate stops every
//	                       other job of the instance at its next step, the Headscale locator refuses the instance (no
//	                       API call of any job or request reaches it), reconcile/apikey/backup schedules skip it
//
// Worker (Handler, queue urgent — never waits for the tenant's lifecycle lock nor for a slot behind other jobs):
//
//	3 instance.isolate     the registry status re-asserted (a release that ended meanwhile is overridden), then Agent
//	                       QuarantineInstance: meta/quarantined FIRST, edge_attach flag cleared, container stopped,
//	                       edge detached (the tenant's hostname answers the uniform 404 of §14.6); data/ kept
//	4 instance.verify      Agent GetInstanceStatus: marked, no flag, edge not attached, container not running
//	5 notify               notification instance.quarantined (Super Admins, Platform Operators), audit .succeeded
//
// A failure of steps 3–4 (retries spent, the agent missing, an instance the agent does not manage) never lifts the
// quarantine: the registry stays quarantined, security event instance.quarantine_incomplete (critical), notification
// "incomplete", audit .failed — the operator isolates by hand (RUNBOOK) and may request the quarantine again.
//
// Release (2P): the API turns the request into an approval request (approvals, action platform.instance.release,
// payload {instance_id, tenant_id}); once a second person approved it, ExecuteRelease (in the approval's transaction)
// checks the instance is still quarantined with no quarantine in progress and enqueues instance.release:
//
//	1 validate             API (approval execution)
//	2 release.prepare      instance quarantined, tenant active or suspended, the applied policy's sha256 recorded
//	3 instance.release     Agent ReleaseInstance: start through the start guard, healthy, serves that policy, then
//	                       meta/quarantined removed (any failure: stopped again, still marked)
//	4 registry.starting    quarantined → starting (the Headscale locator reaches starting/running instances only)
//	5 edge.attach          Agent EnsureEdgeAttachment (policy present, start guard, alias unique, two members)
//	6 poststart.gate       §11.4 post-start gate through the API: Health (the platform's API key accepted) and
//	                       GetPolicy = the applied sha256
//	7 registry.release     starting → running (a quarantine requested meanwhile makes it fail)
//	8 notify               security event instance.released (high), notification instance.released, audit .succeeded
//
// Any failure of steps 2–7 ⇒ the instance is isolated again (QuarantineInstance) and the registry moved back to
// quarantined; security event instance.release_failed, notification "refused", audit .failed; the job ends failed
// (never retried by the queue — a new release needs a new approval).
package quarantine
