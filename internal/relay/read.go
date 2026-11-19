package relay

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// CheckView is one check of the last recorded probe as the API shows it (schema RelayCheck).
type CheckView struct {
	OK         bool   `json:"ok"`
	Status     int    `json:"status,omitempty"` // HTTP status (derp); 0 = none received
	Code       string `json:"code,omitempty"`   // the prober's error code when the check failed
	DurationMS int64  `json:"duration_ms"`      // duration of the check, measured by the prober inside the platform
}

func viewOf(c checkRecord) CheckView {
	return CheckView(c)
}

// Health is the health of a relay region as the API shows it (schema RelayHealth).
type Health struct {
	Status    string     // healthy, unhealthy, unknown
	Reason    string     // "" when healthy; a stable code otherwise
	CheckedAt *time.Time // start of the last recorded probe (nil: never probed)
	// DERP and STUN are the checks of the last recorded probe (nil when there is none or it is not understood). They
	// belong to CheckedAt — a stale or no-longer-relevant probe keeps its checks, the verdict is what Status says.
	DERP, STUN *CheckView
}

// HealthInput is what HealthOf decides from: a region's row and the database time of the read.
type HealthInput struct {
	Kind string
	// Active: the region — and, in a tenant's view, its assignment — is administratively active.
	Active bool
	// Serving: a running instance serves the region (embedded: the DERP lives in the instance).
	Serving     bool
	LastProbe   []byte
	LastProbeAt *time.Time
	Now         time.Time
	StaleAfter  time.Duration
}

// HealthOf is the health shown for a region: the verdict of the last recorded probe while it is younger than
// StaleAfter; otherwise unknown with the reason — a kind not probed in this release, never probed, not active, not
// served by a running instance, record not understood, or stale. It is pure, so both read models apply the same rule.
func HealthOf(in HealthInput) Health {
	h := Health{Status: StatusUnknown}
	if in.Kind != KindEmbedded {
		h.Reason = ReasonNoProbe
		return h
	}
	var rec record
	valid := len(in.LastProbe) > 0 && json.Unmarshal(in.LastProbe, &rec) == nil && rec.valid()
	if in.LastProbeAt == nil || len(in.LastProbe) == 0 {
		switch {
		case !in.Active:
			h.Reason = ReasonNotActive
		case !in.Serving:
			h.Reason = ReasonInstanceNotRunning
		default:
			h.Reason = ReasonNeverChecked
		}
		return h
	}
	at := in.LastProbeAt.UTC()
	h.CheckedAt = &at
	if valid {
		derp, stun := viewOf(rec.DERP), viewOf(rec.STUN)
		h.DERP, h.STUN = &derp, &stun
	}
	switch {
	case !in.Active:
		h.Reason = ReasonNotActive
	case !in.Serving:
		h.Reason = ReasonInstanceNotRunning
	case !valid:
		h.Reason = ReasonInvalidRecord
	case in.Now.Sub(at) > in.StaleAfter:
		h.Reason = ReasonStale
	default:
		h.Status, h.Reason = rec.Status, rec.Reason
	}
	return h
}

// Region is a relay region (relay_regions, §6.3) as both read models show it — public relay parameters only (the
// same a client of the tenant finds in its DERP map), no secret.
type Region struct {
	ID           uuid.UUID
	Code         string // region_code (mg-<slug>)
	Name         string
	Kind         string // embedded | standalone | shared
	DERPRegionID int32  // 900–999
	Hostname     string
	IPv4, IPv6   netip.Addr // advertised addresses; zero = none
	STUNPort     int32      // 0 = none
	DERPPort     int32
	VerifyMode   string // in_process | verify_url
	Status       string // pending | active | disabled (administrative)
}

// Assignment is one relay of a tenant: an assignment of its instance to a region, with the region's health.
type Assignment struct {
	ID       uuid.UUID
	Priority int
	Status   string // pending | active | disabled (administrative)
	Region   Region
	Health   Health
}

// TenantRelay is GET /tenants/{t}/relay: the relays of the tenant's live instance and the figures the platform does
// not measure.
type TenantRelay struct {
	Assignments []Assignment
	Unavailable []Unavailable
}

func addr(a *netip.Addr) netip.Addr {
	if a == nil {
		return netip.Addr{}
	}
	return *a
}

func port(p *int32) int32 {
	if p == nil {
		return 0
	}
	return *p
}

// TenantRelay reads the relays of the tenant of the path on the tenant pool (RLS: no other tenant's row is visible):
// the assignments of its instances that are not removed, each with its region and the region's health.
func (s *Service) TenantRelay(ctx context.Context, tenantID uuid.UUID) (TenantRelay, error) {
	if tenantID == uuid.Nil {
		return TenantRelay{}, errors.New("relay: a tenant is required")
	}
	out := TenantRelay{Assignments: []Assignment{}, Unavailable: Unmeasured()}
	err := s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		rows, err := q.ListTenantRelay(ctx, tenantID)
		if err != nil {
			return err
		}
		for _, r := range rows {
			out.Assignments = append(out.Assignments, Assignment{ID: r.ID, Priority: int(r.Priority), Status: r.Status,
				Region: Region{ID: r.RegionID, Code: r.Code, Name: r.Name, Kind: r.Kind, DERPRegionID: r.DerpRegionID,
					Hostname: r.Hostname, IPv4: addr(r.Ipv4), IPv6: addr(r.Ipv6), STUNPort: port(r.StunPort), DERPPort: r.DerpPort,
					VerifyMode: r.VerifyMode, Status: r.RegionStatus},
				Health: HealthOf(HealthInput{Kind: r.Kind, Active: r.Status == AdminActive && r.RegionStatus == AdminActive,
					Serving: r.InstanceStatus == "running", LastProbe: r.LastProbe, LastProbeAt: r.LastProbeAt, Now: r.Now,
					StaleAfter: s.staleAfter})})
		}
		return nil
	})
	if err != nil {
		return TenantRelay{}, fmt.Errorf("relay: tenant relay: %w", err)
	}
	return out, nil
}

// Page sizes of §13.1.
const (
	DefaultLimit = 50
	MaxLimit     = 200
)

// ErrInvalid: a limit or cursor out of range (422 validation_failed).
var ErrInvalid = errors.New("relay: invalid argument")

// ErrNotFound: the tenant of GET /platform/tenants/{tenantId}/relay-regions does not exist (404 not_found).
var ErrNotFound = errors.New("relay: not found")

// PlatformAssignment is an assignment of a region as platform staff see it (registry metadata).
type PlatformAssignment struct {
	ID             uuid.UUID
	TenantID       uuid.UUID
	InstanceID     uuid.UUID
	Priority       int
	Status         string
	InstanceStatus string
}

// PlatformRegion is a region of GET /platform/relay-regions.
type PlatformRegion struct {
	Region
	HostID      *uuid.UUID
	TenantID    *uuid.UUID // nil: a shared region (Phase 7)
	Assignments []PlatformAssignment
	Health      Health
	CreatedAt   time.Time
	UpdatedAt   time.Time
	Version     int64
}

// RegionFilter holds the query parameters of GET /platform/relay-regions (and of
// GET /platform/tenants/{tenantId}/relay-regions — P4-T02).
type RegionFilter struct {
	Limit  int
	Cursor string
	// TenantID keeps only the regions of that tenant (uuid.Nil = every region); the tenant must exist (ErrNotFound).
	TenantID uuid.UUID
}

// RegionPage is one page of regions and the figures the platform does not measure.
type RegionPage struct {
	Items       []PlatformRegion
	NextCursor  string
	Unavailable []Unavailable
}

// PlatformRegions is GET /platform/relay-regions: one page of every region on the platform pool, ordered by
// (created_at, id), each with its assignments and its health.
func (s *Service) PlatformRegions(ctx context.Context, f RegionFilter) (RegionPage, error) {
	limit := f.Limit
	if limit == 0 {
		limit = DefaultLimit
	}
	if limit < 1 || limit > MaxLimit {
		return RegionPage{}, fmt.Errorf("%w: limit must be 1–%d", ErrInvalid, MaxLimit)
	}
	p := sqlcdb.ListRelayRegionsPageParams{RowLimit: int32(limit + 1)} //nolint:gosec // ≤ MaxLimit+1
	if f.Cursor != "" {
		t, id, err := decodeCursor(f.Cursor)
		if err != nil {
			return RegionPage{}, err
		}
		p.AfterCreatedAt, p.AfterID = &t, &id
	}
	if f.TenantID != uuid.Nil {
		t := f.TenantID
		p.TenantID = &t
	}
	out := RegionPage{Items: []PlatformRegion{}, Unavailable: Unmeasured()}
	err := s.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		if p.TenantID != nil {
			if _, err := q.GetTenantView(ctx, *p.TenantID); errors.Is(err, store.ErrNoRows) {
				return ErrNotFound
			} else if err != nil {
				return err
			}
		}
		rows, err := q.ListRelayRegionsPage(ctx, p)
		if err != nil {
			return err
		}
		now, err := q.MonitoringNow(ctx) // the database clock of this read (statement_timestamp)
		if err != nil {
			return err
		}
		if len(rows) > limit {
			rows = rows[:limit]
			last := rows[limit-1]
			out.NextCursor = encodeCursor(last.CreatedAt, last.ID)
		}
		ids := make([]uuid.UUID, 0, len(rows))
		for _, r := range rows {
			ids = append(ids, r.ID)
		}
		assigned := map[uuid.UUID][]PlatformAssignment{}
		if len(ids) > 0 {
			as, err := q.ListRelayAssignmentsOfRegions(ctx, ids)
			if err != nil {
				return err
			}
			for _, a := range as {
				assigned[a.RelayRegionID] = append(assigned[a.RelayRegionID], PlatformAssignment{ID: a.ID, TenantID: a.TenantID,
					InstanceID: a.InstanceID, Priority: int(a.Priority), Status: a.Status, InstanceStatus: a.InstanceStatus})
			}
		}
		for _, r := range rows {
			as := assigned[r.ID]
			if as == nil {
				as = []PlatformAssignment{}
			}
			active, serving := false, false
			for _, a := range as {
				if a.Status == AdminActive {
					active = true
					serving = serving || a.InstanceStatus == "running"
				}
			}
			out.Items = append(out.Items, PlatformRegion{
				Region: Region{ID: r.ID, Code: r.Code, Name: r.Name, Kind: r.Kind, DERPRegionID: r.DerpRegionID, Hostname: r.Hostname,
					IPv4: addr(r.Ipv4), IPv6: addr(r.Ipv6), STUNPort: port(r.StunPort), DERPPort: r.DerpPort, VerifyMode: r.VerifyMode,
					Status: r.Status},
				HostID: r.HostID, TenantID: r.TenantID, Assignments: as,
				Health: HealthOf(HealthInput{Kind: r.Kind, Active: r.Status == AdminActive && active, Serving: serving,
					LastProbe: r.LastProbe, LastProbeAt: r.LastProbeAt, Now: now, StaleAfter: s.staleAfter}),
				CreatedAt: r.CreatedAt.UTC(), UpdatedAt: r.UpdatedAt.UTC(), Version: r.Version})
		}
		return nil
	})
	if err != nil {
		return RegionPage{}, fmt.Errorf("relay: platform regions: %w", err)
	}
	return out, nil
}

// The cursor is opaque to clients: base64url of "<created_at RFC 3339>|<id>" of the last item of the page.
func encodeCursor(t time.Time, id uuid.UUID) string {
	return base64.RawURLEncoding.EncodeToString([]byte(t.UTC().Format(time.RFC3339Nano) + "|" + id.String()))
}

func decodeCursor(s string) (time.Time, uuid.UUID, error) {
	bad := fmt.Errorf("%w: invalid cursor", ErrInvalid)
	if len(s) > 512 {
		return time.Time{}, uuid.Nil, bad
	}
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return time.Time{}, uuid.Nil, bad
	}
	ts, idStr, ok := strings.Cut(string(raw), "|")
	if !ok {
		return time.Time{}, uuid.Nil, bad
	}
	t, err := time.Parse(time.RFC3339Nano, ts)
	if err != nil {
		return time.Time{}, uuid.Nil, bad
	}
	id, err := uuid.Parse(idStr)
	if err != nil {
		return time.Time{}, uuid.Nil, bad
	}
	return t, id, nil
}
