package reconcile

import (
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
)

// Job kinds (§13.5).
const (
	KindInstance = "instance.reconcile"
	KindHost     = "host.reconcile"
)

// ReportSchema is the version of the report document (the output of a reconcile job).
const ReportSchema = 1

// Scopes of a report.
const (
	ScopeInstance = "instance"
	ScopeHost     = "host"
)

// Report statuses.
const (
	StatusClean      = "clean"      // every check ran, no drift
	StatusDrift      = "drift"      // at least one finding
	StatusIncomplete = "incomplete" // no finding, but a check could not run (agent or Headscale unavailable)
)

// Outcomes of one check.
const (
	OutcomeOK            = "ok"
	OutcomeDrift         = "drift"
	OutcomeUnavailable   = "unavailable"    // the source could not be read: the check says nothing
	OutcomeNotApplicable = "not_applicable" // nothing to compare (not recorded, not reported, not expected)
)

// Names of the checks.
const (
	CheckAgent     = "agent"     // GetInstanceStatus / ListInstances answered
	CheckContainer = "container" // state and health
	CheckImage     = "image"     // digest
	CheckConfig    = "config"    // config_sha256
	CheckNetwork   = "network"   // exists, subnet, internal, members, edge
	CheckPaths     = "paths"     // owner/mode (§14.2)
	CheckNoiseKey  = "noise_key" // fingerprint (§11.4 start guard)
	CheckAPIKeys   = "api_keys"  // ListAPIKeys of the instance
	CheckInventory = "inventory" // host: ListInstances against the registry
	CheckAliases   = "aliases"   // host: hs-<slug> on the edge's networks
)

// Drift kinds: the stable codes of a finding and the label of meshguard_reconcile_drift.
const (
	// instance.reconcile
	DriftInstanceMissing     = "instance_missing"             // the agent has no directory for a registered instance
	DriftGuardRefused        = "guard_refused"                // the agent's guard refuses: an object with a derived name is not this instance's
	DriftContainerAbsent     = "container_absent"             // no container mg-hs-<slug>
	DriftContainerNotRunning = "container_not_running"        // running/starting instance whose container does not run
	DriftContainerUnhealthy  = "container_unhealthy"          // its healthcheck fails
	DriftContainerRunning    = "container_running_unexpected" // stopped instance whose container runs
	DriftImageDigest         = "image_digest_mismatch"        // the container does not run tenant_instances.image_digest
	DriftConfigHash          = "config_hash_mismatch"         // config.yaml is not the config version in force
	DriftConfigMissing       = "config_missing"               // no config.yaml
	DriftNetworkAbsent       = "network_absent"               // no network mg-t-<slug>
	DriftNetworkSubnet       = "network_subnet_mismatch"      // its subnet is not net_cidr
	DriftNetworkNotInternal  = "network_not_internal"         // the tenant network has a way out (§14.3)
	DriftNetworkExtraMember  = "network_extra_member"         // a member other than the instance and the edge
	DriftContainerDetached   = "container_not_on_network"     // the running container is not on its network
	DriftEdgeDetached        = "edge_not_attached"            // running instance the edge cannot reach (edge supervisor)
	DriftPathPermissions     = "path_permissions"             // owner/mode of an agent-managed path (§14.2)
	DriftNoiseKey            = "noise_key_mismatch"           // the Noise key is not the recorded one (RT-06)
	DriftAPIKeyForeign       = "api_key_foreign"              // a valid API key other than the current one (and the previous one while rotating)
	DriftAPIKeyCurrent       = "api_key_current_missing"      // the recorded current key is not a valid key of the instance
	// host.reconcile
	DriftUnknownInstance   = "unknown_instance"            // a directory, container or network of an instance id the registry does not know
	DriftIdentityMismatch  = "inventory_identity_mismatch" // the host's tenant/slug of an instance is not the registry's
	DriftRemovedLeftover   = "removed_instance_leftover"   // resources of an instance the registry marks removed
	DriftRegisteredMissing = "registered_instance_missing" // a registered instance with nothing on the host
	DriftAliasCollision    = "alias_collision"             // hs-<slug> on another network or container of the edge
	DriftUnknownAlias      = "unknown_alias"               // hs-* name of no live instance on the edge's networks
)

// DriftKinds lists every kind (the gauge starts at 0 for each).
var DriftKinds = []string{
	DriftInstanceMissing, DriftGuardRefused, DriftContainerAbsent, DriftContainerNotRunning, DriftContainerUnhealthy,
	DriftContainerRunning, DriftImageDigest, DriftConfigHash, DriftConfigMissing, DriftNetworkAbsent, DriftNetworkSubnet,
	DriftNetworkNotInternal, DriftNetworkExtraMember, DriftContainerDetached, DriftEdgeDetached, DriftPathPermissions,
	DriftNoiseKey, DriftAPIKeyForeign, DriftAPIKeyCurrent,
	DriftUnknownInstance, DriftIdentityMismatch, DriftRemovedLeftover, DriftRegisteredMissing, DriftAliasCollision,
	DriftUnknownAlias,
}

// severities of the drift kinds (the scale of security_events, §16.3).
var severities = map[string]string{
	DriftInstanceMissing: audit.SeverityCritical, DriftGuardRefused: audit.SeverityHigh,
	DriftContainerAbsent: audit.SeverityHigh, DriftContainerNotRunning: audit.SeverityHigh,
	DriftContainerUnhealthy: audit.SeverityMedium, DriftContainerRunning: audit.SeverityMedium,
	DriftImageDigest: audit.SeverityHigh, DriftConfigHash: audit.SeverityHigh, DriftConfigMissing: audit.SeverityHigh,
	DriftNetworkAbsent: audit.SeverityHigh, DriftNetworkSubnet: audit.SeverityHigh, DriftNetworkNotInternal: audit.SeverityHigh,
	DriftNetworkExtraMember: audit.SeverityHigh, DriftContainerDetached: audit.SeverityHigh,
	DriftEdgeDetached: audit.SeverityMedium, DriftPathPermissions: audit.SeverityHigh, DriftNoiseKey: audit.SeverityCritical,
	DriftAPIKeyForeign: audit.SeverityHigh, DriftAPIKeyCurrent: audit.SeverityHigh,
	DriftUnknownInstance: audit.SeverityMedium, DriftIdentityMismatch: audit.SeverityHigh,
	DriftRemovedLeftover: audit.SeverityLow, DriftRegisteredMissing: audit.SeverityHigh,
	DriftAliasCollision: audit.SeverityHigh, DriftUnknownAlias: audit.SeverityMedium,
}

// securityKinds are the drift kinds that are also a security event (kind reconcile.<drift kind>): what points at
// tampering or at a broken isolation boundary rather than at an operational fault.
var securityKinds = map[string]bool{
	DriftGuardRefused: true, DriftImageDigest: true, DriftNetworkNotInternal: true, DriftNetworkExtraMember: true,
	DriftNoiseKey: true, DriftAPIKeyForeign: true, DriftUnknownInstance: true, DriftIdentityMismatch: true,
	DriftAliasCollision: true, DriftUnknownAlias: true,
}

// SecuritySource is the source of the security events of this package.
const SecuritySource = "reconcile"

// Report is the result of one reconcile run — the output of the job. It holds no secret; an instance report names
// nothing of another tenant.
type Report struct {
	Schema     int        `json:"schema"`
	Scope      string     `json:"scope"`
	Status     string     `json:"status"`
	TenantID   *uuid.UUID `json:"tenant_id,omitempty"`
	InstanceID *uuid.UUID `json:"instance_id,omitempty"`
	CheckedAt  time.Time  `json:"checked_at"`
	Checks     []Check    `json:"checks"`
	Findings   []Finding  `json:"findings"`
	DurationMS int64      `json:"duration_ms"`
}

// Check is the outcome of one check.
type Check struct {
	Name    string `json:"name"`
	Outcome string `json:"outcome"`
	Reason  string `json:"reason,omitempty"` // stable code when unavailable / not applicable
	Note    string `json:"note,omitempty"`   // a figure (counts, a public prefix)
}

// Finding is one drift.
type Finding struct {
	Kind     string `json:"kind"`
	Severity string `json:"severity"`
	// Subject names the object when a kind can occur several times in a report: an API key prefix, an instance id
	// (host), an alias (host).
	Subject  string   `json:"subject,omitempty"`
	Expected string   `json:"expected,omitempty"`
	Actual   string   `json:"actual,omitempty"`
	Items    []string `json:"items,omitempty"`
	Count    int      `json:"count,omitempty"`
}

// Skipped is the output of a job that did not reconcile.
type Skipped struct {
	Skipped string `json:"skipped"`
}

// Reasons a reconcile is skipped.
const (
	SkipInstanceNotFound = "instance_not_found"    // no instance with this id for this tenant
	SkipNotReconciled    = "instance_not_targeted" // allocated, failed, removed or quarantined (§11.4)
	SkipLifecycleBusy    = "lifecycle_job_active"  // a lifecycle job of the tenant is running: drift is transient
)

func (r *Report) add(f Finding) {
	f.Severity = severities[f.Kind]
	r.Findings = append(r.Findings, f)
}

func (r *Report) check(name, outcome, reason, note string) {
	r.Checks = append(r.Checks, Check{Name: name, Outcome: outcome, Reason: reason, Note: note})
}

// finish sets the status from the findings and checks.
func (r *Report) finish() {
	switch {
	case len(r.Findings) > 0:
		r.Status = StatusDrift
	default:
		r.Status = StatusClean
		for _, c := range r.Checks {
			if c.Outcome == OutcomeUnavailable {
				r.Status = StatusIncomplete
			}
		}
	}
	if r.Findings == nil {
		r.Findings = []Finding{}
	}
}

// Kinds counts the findings per kind.
func (r Report) Kinds() map[string]int {
	out := map[string]int{}
	for _, f := range r.Findings {
		out[f.Kind]++
	}
	return out
}
