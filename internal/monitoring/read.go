package monitoring

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// InstanceHealth is the health of an instance as the API shows it (schema InstanceHealth).
type InstanceHealth struct {
	Status    string     // healthy, unhealthy, unknown
	Reason    string     // "" when healthy; a stable code otherwise
	CheckedAt *time.Time // start of the last recorded probe (nil: never probed)
	Version   string     // version the instance reported at that probe ("" unknown)
}

// HealthOf is the health shown for an instance from its row (status, last_health, last_health_at) at the database time
// now: the verdict of the last recorded probe while it is younger than staleAfter; otherwise unknown with the reason —
// instance not running (only running instances are probed), never probed, record not understood, or stale. It is
// pure, so every view of an instance (dashboard, platform health, the instances of GET /platform/instances) applies
// the same rule.
func HealthOf(instanceStatus string, lastHealth []byte, lastHealthAt *time.Time, now time.Time, staleAfter time.Duration) InstanceHealth {
	h := InstanceHealth{Status: StatusUnknown, CheckedAt: lastHealthAt}
	var rec record
	valid := len(lastHealth) > 0 && json.Unmarshal(lastHealth, &rec) == nil && rec.valid()
	if valid {
		h.Version = rec.Version
	}
	switch {
	case lastHealthAt == nil || len(lastHealth) == 0:
		h.CheckedAt, h.Version = nil, ""
		h.Reason = ReasonNeverChecked
		if instanceStatus != "running" {
			h.Reason = ReasonInstanceNotRunning
		}
	case instanceStatus != "running":
		h.Reason = ReasonInstanceNotRunning
	case !valid:
		h.Reason = ReasonInvalidRecord
	case now.Sub(*lastHealthAt) > staleAfter:
		h.Reason = ReasonStale
	default:
		h.Status, h.Reason = rec.Status, rec.Reason
	}
	return h
}

// Dashboard sections and the reasons a section has no figure (§12.3 "không có số giả", §16.4).
const (
	SectionDevices        = "devices"
	SectionPolicies       = "policies"
	SectionRoutes         = "routes"
	SectionRelay          = "relay"
	SectionSecurityEvents = "security_events"

	// ReasonNeverSynced: the register of the tenant's instance was never synced — its counts are not figures.
	ReasonNeverSynced = "never_synced"
	// ReasonNoSource: the platform has no source for this section yet.
	ReasonNoSource = "no_source"
	// ReasonNotServed: the source exists but the dashboard does not serve the figure yet.
	ReasonNotServed = "not_served"
)

// Unavailable is a dashboard section without a real figure, with the reason.
type Unavailable struct {
	Section string
	Reason  string
	Detail  string // short English sentence for people; the reason is the stable part
}

// notYet are the sections of §16.4 without a figure in this release. Each one becomes a figure — and leaves this list —
// in the task that builds its source: policies (P3-T08a, P4-T10), relay (P3-T03a prober, P3-T05c), routes (P4-T12),
// security events (P6-T02a).
var notYet = []Unavailable{
	{SectionPolicies, ReasonNoSource, "Policy versions and their applications are not managed by the platform yet."},
	{SectionRoutes, ReasonNotServed, "Route status is not served by the dashboard yet."},
	{SectionRelay, ReasonNoSource, "Relay probes are not deployed yet."},
	{SectionSecurityEvents, ReasonNotServed, "Security events are not served by the dashboard yet."},
}

// TenantDashboard is the overview of one tenant (GET /tenants/{t}/dashboard): figures of the tenant only, each with
// the time it was observed.
type TenantDashboard struct {
	Devices     DeviceCounts
	Instance    InstanceHealth
	Unavailable []Unavailable
}

// TenantDashboard builds the dashboard of the tenant of the path: the health of its instance read on the tenant pool
// (RLS: no other tenant's row is visible) and its device figures from the devices module.
func (s *Service) TenantDashboard(ctx context.Context, tenantID uuid.UUID) (TenantDashboard, error) {
	if tenantID == uuid.Nil {
		return TenantDashboard{}, errors.New("monitoring: dashboard: a tenant is required")
	}
	var d TenantDashboard
	err := s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		r, err := q.GetTenantInstanceHealth(ctx, tenantID)
		if errors.Is(err, store.ErrNoRows) {
			d.Instance = InstanceHealth{Status: StatusUnknown, Reason: ReasonNoInstance}
			return nil
		}
		if err != nil {
			return err
		}
		d.Instance = HealthOf(r.Status, r.LastHealth, r.LastHealthAt, r.Now, s.staleAfter)
		return nil
	})
	if err != nil {
		return TenantDashboard{}, fmt.Errorf("monitoring: dashboard: instance health: %w", err)
	}
	if d.Devices, err = s.devices.DeviceCounts(ctx, tenantID); err != nil {
		return TenantDashboard{}, fmt.Errorf("monitoring: dashboard: devices: %w", err)
	}
	d.Unavailable = make([]Unavailable, 0, len(notYet)+1)
	if d.Devices.SyncedAt == nil {
		d.Unavailable = append(d.Unavailable, Unavailable{SectionDevices, ReasonNeverSynced,
			"The device register of the tenant's control plane has never been synced."})
	}
	d.Unavailable = append(d.Unavailable, notYet...)
	return d, nil
}

// Platform components of the health page (§16.2) and the reasons of their status.
const (
	ComponentPostgres = "postgres"
	ComponentWorker   = "worker"
	ComponentEdge     = "edge"
	ComponentAgent    = "agent"
	ComponentIdP      = "idp"

	ReasonNoHeartbeat     = "no_heartbeat"     // job.reaper never finished: no worker has run
	ReasonHeartbeatStale  = "heartbeat_stale"  // job.reaper last finished longer ago than HeartbeatMaxAge
	ReasonHeartbeatFailed = "heartbeat_failed" // the last run of job.reaper failed
	ReasonNotDeployed     = "not_deployed"     // the component does not exist in this release (agent: Phase 3)
	ReasonNoProbe         = "no_probe"         // no probe of the component is deployed yet (prober: P3-T03a, P3-T16)
)

// heartbeatKind is the periodic platform job whose runs prove a worker is alive (every minute — §13.5, §16.2).
const heartbeatKind = "job.reaper"

// Component is the health of one platform component.
type Component struct {
	Name      string
	Status    string
	Reason    string
	CheckedAt *time.Time
}

// TenantCounts are the tenants by status (every status of the enum, zeros included).
type TenantCounts struct {
	Total    int
	ByStatus map[string]int
}

// InstanceCounts are the instances that are not removed: by status, by health (HealthOf) and by the version reported
// at their last probe; Unhealthy repeats ByHealth["unhealthy"].
type InstanceCounts struct {
	Total     int
	ByStatus  map[string]int
	ByHealth  map[string]int
	ByVersion map[string]int
	Unhealthy int
}

// JobQueue is the platform's job queue: unfinished jobs by status and jobs that ended failed or rolled back in the last
// 24 hours.
type JobQueue struct {
	CheckedAt     time.Time
	Unfinished    map[string]int
	FailedLast24h int
}

// PlatformHealth is GET /platform/health.
type PlatformHealth struct {
	CheckedAt  time.Time
	Components []Component
	Tenants    TenantCounts
	Instances  InstanceCounts
	Jobs       JobQueue
}

// tenantStatuses, instanceStatuses and unfinishedStatuses are the enums of §6.3 shown with their zeros.
var (
	tenantStatuses     = []string{"pending", "provisioning", "active", "suspended", "deprovisioning", "deleted", "failed"}
	instanceStatuses   = []string{"allocated", "starting", "running", "stopped", "failed", "quarantined"}
	unfinishedStatuses = []string{"queued", "running", "compensating", "failed_resumable"}
)

func zeros(keys []string) map[string]int {
	m := make(map[string]int, len(keys))
	for _, k := range keys {
		m[k] = 0
	}
	return m
}

// PlatformHealth aggregates the platform's health in one platform transaction (one snapshot, one database time):
// tenants by status, instances by status / health / version, the job queue, and the components — postgres (this
// transaction), the worker (heartbeat: the last run of job.reaper), and those without a probe yet, reported unknown
// with the reason. It reads no tenant-internal table.
func (s *Service) PlatformHealth(ctx context.Context) (PlatformHealth, error) {
	out := PlatformHealth{
		Tenants:   TenantCounts{ByStatus: zeros(tenantStatuses)},
		Instances: InstanceCounts{ByStatus: zeros(instanceStatuses), ByHealth: zeros([]string{StatusHealthy, StatusUnhealthy, StatusUnknown}), ByVersion: map[string]int{}},
		Jobs:      JobQueue{Unfinished: zeros(unfinishedStatuses)},
	}
	worker := Component{Name: ComponentWorker, Status: StatusUnknown, Reason: ReasonNoHeartbeat}
	err := s.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		now, err := q.MonitoringNow(ctx)
		if err != nil {
			return err
		}
		out.CheckedAt, out.Jobs.CheckedAt = now.UTC(), now.UTC()
		tenants, err := q.CountTenantsByStatus(ctx)
		if err != nil {
			return err
		}
		for _, t := range tenants {
			out.Tenants.ByStatus[t.Status] += int(t.Tenants)
			out.Tenants.Total += int(t.Tenants)
		}
		instances, err := q.ListInstancesHealth(ctx)
		if err != nil {
			return err
		}
		for _, in := range instances {
			h := HealthOf(in.Status, in.LastHealth, in.LastHealthAt, now, s.staleAfter)
			out.Instances.Total++
			out.Instances.ByStatus[in.Status]++
			out.Instances.ByHealth[h.Status]++
			if h.Version != "" {
				out.Instances.ByVersion[h.Version]++
			}
		}
		out.Instances.Unhealthy = out.Instances.ByHealth[StatusUnhealthy]
		unfinished, err := q.CountJobsByStatus(ctx)
		if err != nil {
			return err
		}
		for _, j := range unfinished {
			out.Jobs.Unfinished[j.Status] += int(j.Jobs)
		}
		failed, err := q.CountJobsFailedSince(ctx, now.Add(-24*time.Hour))
		if err != nil {
			return err
		}
		out.Jobs.FailedLast24h = int(failed)
		hb, err := q.LatestFinishedPlatformJob(ctx, heartbeatKind)
		switch {
		case errors.Is(err, store.ErrNoRows):
		case err != nil:
			return err
		case hb.FinishedAt == nil:
		case hb.Status != "succeeded":
			worker = Component{Name: ComponentWorker, Status: StatusUnhealthy, Reason: ReasonHeartbeatFailed, CheckedAt: utc(hb.FinishedAt)}
		case now.Sub(*hb.FinishedAt) > s.heartbeat:
			worker = Component{Name: ComponentWorker, Status: StatusUnhealthy, Reason: ReasonHeartbeatStale, CheckedAt: utc(hb.FinishedAt)}
		default:
			worker = Component{Name: ComponentWorker, Status: StatusHealthy, CheckedAt: utc(hb.FinishedAt)}
		}
		return nil
	})
	if err != nil {
		return PlatformHealth{}, fmt.Errorf("monitoring: platform health: %w", err)
	}
	checked := out.CheckedAt
	out.Components = []Component{
		{Name: ComponentPostgres, Status: StatusHealthy, CheckedAt: &checked}, // this aggregation ran on it
		worker,
		{Name: ComponentEdge, Status: StatusUnknown, Reason: ReasonNoProbe},
		{Name: ComponentIdP, Status: StatusUnknown, Reason: ReasonNoProbe},
		{Name: ComponentAgent, Status: StatusUnknown, Reason: ReasonNotDeployed},
	}
	return out, nil
}

func utc(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	u := t.UTC()
	return &u
}
