// Package reconcile is the REPORT-ONLY reconcile of the Tenant Orchestrator (P3-T12; master plan §11.4 "Reconcile",
// §13.5 instance.reconcile / host.reconcile, §16.3, §18 T-05, T-12, T-13, T-14): it compares the desired state of the
// registry (PostgreSQL) with the actual state reported by the Host Agent and by the tenant's Headscale, and reports the
// drift — it never adopts, modifies or deletes anything.
//
// Two scheduled jobs, both level-triggered (they carry ids only and read the desired state when they run):
//
//   - instance.reconcile (one per instance — starting, running, stopped; quarantined and removed instances are never
//     reconciled, and an instance whose tenant has a lifecycle job running is skipped: its drift is transient):
//     GetInstanceStatus of the agent — container state and health, image digest = tenant_instances.image_digest,
//     config_sha256 = the config version in force, network mg-t-<slug> (exists, net_cidr, internal, exactly the
//     instance's container and the edge), owner/mode of every agent-managed path (§14.2), Noise key fingerprint once
//     the agent reports it — and ListAPIKeys of the instance: only the current key (api_key_prefix) and, during a
//     rotation (RotationGrace after the current key was created), the key created just before it may be valid;
//   - host.reconcile (one per host): ListInstances of the agent — every instance directory, container and network
//     labelled meshguard.instance_id that has no registry row (or belongs to a removed instance, or disagrees with its
//     row), every registered instance with nothing on the host — and the hs-<slug> names on the edge's networks: each
//     must exist once, on the tenant's own network.
//
// Report-only is structural: the package holds the agent behind Agent (GetInstanceStatus and ListInstances only) and
// calls nothing on a Headscale instance but ListAPIKeys (checked by a test over the package's own source); the unit
// tests run it against fakes that record every call.
//
// Output: the report is the output of the job (provisioning_jobs.output — what monitoring reads: LatestReports,
// LatestHostReport), the gauge meshguard_reconcile_drift{kind} and the counter meshguard_reconcile_runs_total
// {scope,result}; security-relevant drift (a foreign API key, an extra network member, an alias collision, an image
// digest or Noise key mismatch, a network that is not internal, an object the agent's guard refuses, an unknown
// MeshGuard object or hs-* name on the host) is also a platform security_events row, deduplicated per subject for
// EventWindow. A report holds no secret: API keys appear by their public prefix only, and an instance report — the
// output of a job of the tenant — names nothing of another tenant (counts only).
//
// Without an agent (dev: MG_AGENT_SOCKET unset) the agent checks report agent_unavailable and the job still succeeds.
package reconcile
