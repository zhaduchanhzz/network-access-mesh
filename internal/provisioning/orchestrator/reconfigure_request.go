package orchestrator

// The API side of instance.reconfigure (P3-T13): POST /platform/instances/{instanceId}/reconfigure
// (platform.instance:operate — §8.5) through ReconfigureService, and the internal entry point EnqueueReconfigure for
// the Phase 4 operations that change a tenant setting rendered into the instance's configuration (DNS settings, OIDC,
// node expiry — §13.2): they enqueue the same job in the transaction of their own change.

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
)

// ConfigChange is a requested change of the platform-controlled parameters of an instance (schema
// InstanceReconfigure): an absent field keeps the value of the version in force. The empty change renders the version
// in force again with the registry's current values (the host's public entry — §17.4).
type ConfigChange struct {
	LogLevel       string   `json:"log_level,omitempty"`        // info | warn | error
	NodeExpiryDays *uint32  `json:"node_expiry_days,omitempty"` // 1..3650
	Nameservers    []string `json:"nameservers,omitempty"`      // 1..8 usable unicast addresses, no duplicates
	DERPRegionID   *uint32  `json:"derp_region_id,omitempty"`   // 900..999
}

// Bounds of a change — the agent's typed validation (agentspec) stays the authority (and also refuses a nameserver
// inside the host's tenant network pool).
const (
	maxNodeExpiryDays = 3650
	maxNameservers    = 8
	minDERPRegionID   = 900
	maxDERPRegionID   = 999
)

// Normalize checks the change and puts it in canonical form (addresses as netip prints them). A refusal is a
// *CreateError of kind ErrInvalid naming the field.
func (c *ConfigChange) Normalize() error {
	if c.LogLevel != "" {
		if _, ok := logLevels[c.LogLevel]; !ok {
			return invalid("log_level", "invalid_log_level")
		}
	}
	if c.NodeExpiryDays != nil && (*c.NodeExpiryDays < 1 || *c.NodeExpiryDays > maxNodeExpiryDays) {
		return invalid("node_expiry_days", "out_of_range")
	}
	if c.DERPRegionID != nil && (*c.DERPRegionID < minDERPRegionID || *c.DERPRegionID > maxDERPRegionID) {
		return invalid("derp_region_id", "out_of_range")
	}
	if c.Nameservers != nil {
		if len(c.Nameservers) < 1 || len(c.Nameservers) > maxNameservers {
			return invalid("nameservers", "invalid_count")
		}
		out := make([]string, 0, len(c.Nameservers))
		for _, s := range c.Nameservers {
			a, err := netip.ParseAddr(s)
			if err != nil || a.Zone() != "" || a.Is4In6() || a.IsUnspecified() || a.IsLoopback() || a.IsMulticast() ||
				a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() || a.IsInterfaceLocalMulticast() {
				return invalid("nameservers", "invalid_address")
			}
			if slices.Contains(out, a.String()) {
				return invalid("nameservers", "duplicate_address")
			}
			out = append(out, a.String())
		}
		c.Nameservers = out
	}
	return nil
}

// Equal reports whether two normalized changes ask for the same thing.
func (c ConfigChange) Equal(o ConfigChange) bool {
	eq := func(a, b *uint32) bool { return (a == nil) == (b == nil) && (a == nil || *a == *b) }
	return c.LogLevel == o.LogLevel && eq(c.NodeExpiryDays, o.NodeExpiryDays) && eq(c.DERPRegionID, o.DERPRegionID) &&
		slices.Equal(c.Nameservers, o.Nameservers)
}

// summary is the change as audit details (public values only).
func (c ConfigChange) summary() audit.Details {
	d := audit.Details{}
	if c.LogLevel != "" {
		d["log_level"] = c.LogLevel
	}
	if c.NodeExpiryDays != nil {
		d["node_expiry_days"] = *c.NodeExpiryDays
	}
	if c.Nameservers != nil {
		d["nameservers"] = c.Nameservers
	}
	if c.DERPRegionID != nil {
		d["derp_region_id"] = *c.DERPRegionID
	}
	return d
}

// ReconfigureRequest is one reconfiguration to enqueue (EnqueueReconfigure).
type ReconfigureRequest struct {
	TenantID, InstanceID uuid.UUID
	Change               ConfigChange
	RequestedBy          *uuid.UUID // the identity that asked (nil = system)
	RequestKey           string     // the Idempotency-Key of the API request ("" = none)
	Source               string     // SourcePlatform, or the Phase 4 operation that changed a tenant setting
	// Action is the base audit action of the operation the job closes (default platform.instance.reconfigure; a
	// tenant-scope caller passes its own x-audit-action and runs this in its tenant transaction).
	Action string
}

// EnqueueReconfigure is the internal entry point of instance.reconfigure: in the caller's transaction (platform or the
// tenant's — RLS), it checks the instance — running (quarantined ⇒ conflict), with a configuration version recorded by
// the orchestrator, tenant active or suspended —, returns the unfinished reconfiguration of the instance when it asks
// for the same change (created = false; another change ⇒ conflict reconfigure_in_progress — §13.5 (b): one unfinished
// job per instance:<id>:instance.reconfigure), otherwise opens the audit operation and enqueues the job (lifecycle
// group: it runs under the tenant's lifecycle lock — §13.5 (d)).
func EnqueueReconfigure(ctx context.Context, tx *store.Tx, req ReconfigureRequest) (jobs.Job, bool, error) {
	if err := req.Change.Normalize(); err != nil {
		return jobs.Job{}, false, err
	}
	inst, err := tx.Q.GetTenantInstance(ctx, req.InstanceID)
	if errors.Is(err, store.ErrNoRows) || (err == nil && req.TenantID != uuid.Nil && inst.TenantID != req.TenantID) {
		return jobs.Job{}, false, ErrNotFound
	}
	if err != nil {
		return jobs.Job{}, false, err
	}
	switch {
	case inst.Status == tenants.InstanceQuarantined:
		return jobs.Job{}, false, conflict("instance_quarantined")
	case inst.Status != tenants.InstanceRunning:
		return jobs.Job{}, false, conflict("instance_not_running")
	case inst.ConfigVersionID == nil:
		return jobs.Job{}, false, conflict("no_config_version")
	}
	t, err := tx.Q.GetTenant(ctx, inst.TenantID)
	if err != nil {
		return jobs.Job{}, false, notFound(err)
	}
	if t.Status != tenants.StatusActive && t.Status != tenants.StatusSuspended {
		return jobs.Job{}, false, conflict("tenant_not_active")
	}
	spec := jobs.Spec{Kind: ReconfigureKind, TenantID: &inst.TenantID, InstanceID: &inst.ID, RequestKey: req.RequestKey,
		RequestedBy: req.RequestedBy, Resource: &jobs.Resource{Type: "instance", ID: inst.ID.String()}}
	dedupe, err := jobs.DedupeKey(spec)
	if err != nil {
		return jobs.Job{}, false, err
	}
	active, err := tx.Q.GetActiveJobByDedupeKey(ctx, dedupe)
	switch {
	case err == nil:
		var prev ReconfigureInput
		if active.Kind == ReconfigureKind && json.Unmarshal(active.Input, &prev) == nil && prev.Change.Equal(req.Change) {
			j, err := jobs.ProjectTx(ctx, tx.Q, active.ID)
			return j, false, err
		}
		return jobs.Job{}, false, conflict("reconfigure_in_progress")
	case !errors.Is(err, store.ErrNoRows):
		return jobs.Job{}, false, err
	}
	action := req.Action
	if action == "" {
		action = ActionInstanceReconfigure
	}
	source := req.Source
	if source == "" {
		source = SourcePlatform
	}
	details := req.Change.summary()
	details["tenant_id"], details["instance_id"], details["source"] = inst.TenantID, inst.ID, source
	ev := audit.Event{Action: action, ResourceType: "instance", ResourceID: inst.ID.String(), Details: details}
	if req.TenantID != uuid.Nil {
		// a tenant-scope caller (PUT /tenants/{t}/dns/settings — P4-T12): the operation belongs to the tenant's audit
		// whatever the request scope says; the job closes it in a transaction of the tenant (DBStore.closeOperation)
		t := inst.TenantID
		ev.TenantID = &t
	}
	op, err := audit.Requested(ctx, tx.Q, ev)
	if err != nil {
		return jobs.Job{}, false, err
	}
	spec.Input = ReconfigureInput{TenantID: inst.TenantID, InstanceID: inst.ID, Change: req.Change, Source: source,
		RequestedBy: req.RequestedBy, Operation: op}
	enq, err := jobs.Enqueue(ctx, tx, spec)
	if err != nil {
		if errors.Is(err, jobs.ErrRequestKeyReuse) {
			return jobs.Job{}, false, &CreateError{Kind: ErrIdempotencyKeyReuse, Reason: "idempotency_key_reuse"}
		}
		return jobs.Job{}, false, err
	}
	if !enq.Created {
		// Another request enqueued the same kind between the check above and the insert: this transaction (and its
		// audit event) rolls back.
		return jobs.Job{}, false, conflict("reconfigure_in_progress")
	}
	audit.HandOff(ctx, op)
	j, err := jobs.ProjectTx(ctx, tx.Q, enq.Job.ID)
	return j, true, err
}

// ReconfigureOperation is the operationId of POST /platform/instances/{instanceId}/reconfigure (Idempotency-Key scope).
const ReconfigureOperation = "reconfigurePlatformInstance"

// ReconfigureService serves POST /platform/instances/{instanceId}/reconfigure in the api process.
type ReconfigureService struct {
	st *store.Store
}

// NewReconfigureService returns the API side of instance.reconfigure on the api's store.
func NewReconfigureService(st *store.Store) *ReconfigureService { return &ReconfigureService{st: st} }

// Reconfigured is the outcome of a request.
type Reconfigured struct {
	Job      jobs.Job
	Created  bool // a new job; false: the unfinished job asking for the same change (or a replay)
	Replayed bool // the stored answer of an earlier request with the same Idempotency-Key
}

// Request enqueues the reconfiguration of an instance (EnqueueReconfigure in one platform transaction) under the
// request's Idempotency-Key (§13.1): a replay returns the stored answer.
func (s *ReconfigureService) Request(ctx context.Context, actor, instanceID uuid.UUID, change ConfigChange,
	idem *Idempotency) (Reconfigured, error) {
	if actor == uuid.Nil {
		return Reconfigured{}, errors.New("orchestrator: reconfigure: no actor")
	}
	if err := change.Normalize(); err != nil {
		return Reconfigured{}, err
	}
	var key *jobs.IdempotencyKey
	if idem != nil {
		key = &jobs.IdempotencyKey{IdentityID: actor, OperationID: ReconfigureOperation, Key: idem.Key}
		replay, err := beginIdempotent(ctx, s.st, *key, idem.Hash)
		if err != nil {
			return Reconfigured{}, err
		}
		if replay != nil {
			return Reconfigured{Job: *replay, Replayed: true}, nil
		}
	}
	var out Reconfigured
	err := s.st.WithPlatformJobTx(ctx, func(tx *store.Tx) error {
		req := ReconfigureRequest{InstanceID: instanceID, Change: change, RequestedBy: &actor, Source: SourcePlatform}
		if idem != nil {
			req.RequestKey = idem.Key
		}
		j, created, err := EnqueueReconfigure(ctx, tx, req)
		if err != nil {
			return err
		}
		out = Reconfigured{Job: j, Created: created}
		if key == nil {
			return nil
		}
		body, err := json.Marshal(j)
		if err != nil {
			return err
		}
		return jobs.CompleteIdempotent(ctx, tx.Q, *key, idem.Hash, jobs.StoredResponse{Status: 202, Body: body,
			Resource: &jobs.Resource{Type: "job", ID: j.ID.String()}})
	})
	if err != nil && key != nil {
		_ = s.st.WithPlatformTx(context.WithoutCancel(ctx), func(q *sqlcdb.Queries) error {
			return jobs.FailIdempotent(ctx, q, *key, idem.Hash)
		})
	}
	if err != nil {
		return Reconfigured{}, err
	}
	return out, nil
}

// failCancelledReconfigure closes the audit operation of a reconfiguration cancelled before it ran (Control.Cancel).
func failCancelledReconfigure(ctx context.Context, tx *store.Tx, rec sqlcdb.ProvisioningJob) error {
	var in ReconfigureInput
	if err := json.Unmarshal(rec.Input, &in); err != nil || in.Operation.ID == uuid.Nil {
		return nil //nolint:nilerr // an unreadable input has no operation to close
	}
	if in.Operation.TenantID != nil {
		// an operation of a tenant-scope caller (PUT /dns/settings — P4-T12): this platform transaction cannot write the
		// tenant's event (RLS) — it stays open for reconcile (Logger.OpenOperations), the job itself is cancelled
		return nil
	}
	done, err := operationFinished(ctx, tx.Q, in.Operation)
	if err != nil || done {
		return err
	}
	return in.Operation.Failed(ctx, tx.Q, jobs.CodeCancelled, audit.Details{"job_id": rec.ID, "cancelled": true,
		"instance_id": in.InstanceID, "tenant_id": in.TenantID})
}
