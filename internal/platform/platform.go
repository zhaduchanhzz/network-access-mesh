// Package platform holds the platform-side registry of the Management Plane (§4.2): hosts and the instances of every
// tenant as platform staff see them (GET /platform/instances[/{id}], P2-T11), the management of hosts (GET/POST/PATCH
// /platform/hosts and `meshguard admin host-set` — P3-T04, hosts.go) and the placement of new instances on hosts (Placer
// — step 3 of §11.3, P3-T04, placement.go). Relay regions and system settings join in Phase 3. Every
// query runs in store.WithPlatformTx on the platform pool (hosts is a platform-only table; the
// platform branch of tenant_instances' RLS shows every tenant's row) and returns registry metadata only — never the
// API key reference of an instance (§8.4 invariant 2: staff see no tenant-internal data here).
package platform

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
)

// Page sizes of §13.1.
const (
	DefaultLimit = 50
	MaxLimit     = 200
)

var (
	// ErrNotFound: no such instance or host (404 not_found).
	ErrNotFound = errors.New("platform: not found")
	// ErrInvalid: a filter, limit or cursor out of range (422 validation_failed), or an invalid host specification.
	ErrInvalid = errors.New("platform: invalid argument")
	// ErrConflict: a host specification that contradicts the registered host.
	ErrConflict = errors.New("platform: conflict with the registry")
)

// Instance is a tenant's Headscale instance as platform staff see it (schema Instance) — no secret, no reference.
type Instance struct {
	ID                  uuid.UUID
	TenantID            uuid.UUID
	HostID              uuid.UUID
	Status              string
	HeadscaleVersion    string
	ImageDigest         string
	ControlHostname     string
	ServerURL           string
	DerpRegionID        *int32
	RunUID              int32
	NetCIDR             netip.Prefix
	APIKeyExpiresAt     *time.Time
	NoiseKeyFingerprint *string
	// LastHealth and HealthCheckedAt are tenant_instances.last_health / last_health_at as health.probe recorded them
	// (P2-T13a — a record of stable codes, no secret); ReadAt is the database clock of the read. The health shown is
	// derived from them by monitoring.HealthOf in the HTTP adapter (tenantsapi) — the same rule as the dashboards
	// (stale, instance not running, never probed); platform may not import monitoring (§13.6).
	LastHealth      []byte
	HealthCheckedAt *time.Time
	ReadAt          time.Time
	Version         int64
	CreatedAt       time.Time
}

// InstancePage is one page of instances.
type InstancePage struct {
	Items      []Instance
	NextCursor string
}

// InstanceFilter holds the query parameters of GET /platform/instances.
type InstanceFilter struct {
	Limit  int
	Cursor string
	Status string    // one of tenants.InstanceStatuses
	HostID uuid.UUID // uuid.Nil = every host
}

// Host is a registered host (hosts, §6.3; shapes of status, capacity and public_entry fixed by 0014 — P3-T04).
type Host struct {
	ID            uuid.UUID
	Name          string
	Region        string
	Status        string // HostActive, HostDraining, HostDisabled
	RunUIDFirst   int32  // run_uid_range, inclusive bounds
	RunUIDLast    int32
	TenantNetPool netip.Prefix
	MaxInstances  int32      // capacity.max_instances: live (not removed) instances the host may hold
	PublicEntry   netip.Addr // public_entry.ipv4 (derp.server.ipv4 of its instances); zero = not declared yet
	EntryMode     string     // public_entry.mode: direct | vps_gateway | ""
	STUNPortFirst int32      // stun_port_range, inclusive bounds; 0 = none (shared STUN — MVP)
	STUNPortLast  int32
}

// HostSpec describes a host for EnsureHost.
type HostSpec struct {
	Name          string
	Region        string
	RunUIDFirst   int32
	RunUIDLast    int32
	TenantNetPool netip.Prefix
}

// Service reads the platform registry.
type Service struct {
	st *store.Store
}

// New returns the platform registry service on st.
func New(st *store.Store) *Service { return &Service{st: st} }

// ListInstances is GET /platform/instances.
func (s *Service) ListInstances(ctx context.Context, f InstanceFilter) (InstancePage, error) {
	limit := f.Limit
	if limit == 0 {
		limit = DefaultLimit
	}
	if limit < 1 || limit > MaxLimit {
		return InstancePage{}, fmt.Errorf("%w: limit must be 1–%d", ErrInvalid, MaxLimit)
	}
	p := sqlcdb.ListInstancesPageParams{RowLimit: int32(limit + 1)} //nolint:gosec // ≤ MaxLimit+1
	if f.Status != "" {
		if !slices.Contains(tenants.InstanceStatuses, f.Status) {
			return InstancePage{}, fmt.Errorf("%w: unknown instance status", ErrInvalid)
		}
		p.Status = &f.Status
	}
	if f.HostID != uuid.Nil {
		h := f.HostID
		p.HostID = &h
	}
	if f.Cursor != "" {
		t, id, err := decodeCursor(f.Cursor)
		if err != nil {
			return InstancePage{}, err
		}
		p.AfterCreatedAt, p.AfterID = &t, &id
	}
	var out InstancePage
	err := s.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		rows, err := q.ListInstancesPage(ctx, p)
		if err != nil {
			return err
		}
		now, err := q.MonitoringNow(ctx) // the database clock of this read (statement_timestamp)
		if err != nil {
			return err
		}
		out = InstancePage{Items: make([]Instance, 0, min(len(rows), limit))}
		for i, r := range rows {
			if i == limit {
				last := out.Items[limit-1]
				out.NextCursor = encodeCursor(last.CreatedAt, last.ID)
				break
			}
			out.Items = append(out.Items, instance(r, now))
		}
		return nil
	})
	return out, err
}

// GetInstance is GET /platform/instances/{instanceId}.
func (s *Service) GetInstance(ctx context.Context, id uuid.UUID) (Instance, error) {
	if id == uuid.Nil {
		return Instance{}, ErrNotFound
	}
	var out Instance
	err := s.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		r, err := q.GetTenantInstance(ctx, id)
		if errors.Is(err, store.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		now, err := q.MonitoringNow(ctx) // the database clock of this read (statement_timestamp)
		if err != nil {
			return err
		}
		out = instance(r, now)
		return nil
	})
	return out, err
}

var hostNameRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

func (h HostSpec) validate() error {
	switch {
	case !hostNameRE.MatchString(h.Name):
		return fmt.Errorf("%w: host name must be a DNS label", ErrInvalid)
	case h.Region == "" || len(h.Region) > 64 || strings.ContainsAny(h.Region, " \t\r\n"):
		return fmt.Errorf("%w: host region must be 1–64 characters without spaces", ErrInvalid)
	case h.RunUIDFirst < 1000 || h.RunUIDLast < h.RunUIDFirst || h.RunUIDLast > 1<<31-2:
		return fmt.Errorf("%w: run_uid range must lie within 1000–2147483646", ErrInvalid)
	case !h.TenantNetPool.IsValid() || h.TenantNetPool != h.TenantNetPool.Masked() || !h.TenantNetPool.Addr().Is4() ||
		h.TenantNetPool.Bits() < 8 || h.TenantNetPool.Bits() > 29 || h.TenantNetPool.Overlaps(tailnetRange):
		return fmt.Errorf("%w: tenant network pool must be an IPv4 network between /8 and /29 outside 100.64.0.0/10",
			ErrInvalid)
	}
	for _, id := range ReservedIDs {
		if id >= h.RunUIDFirst && id <= h.RunUIDLast {
			return fmt.Errorf("%w: run_uid range contains the platform UID/GID %d (versions.lock [ids])", ErrInvalid, id)
		}
	}
	return nil
}

// tailnetRange holds the addresses Headscale gives to nodes (§6.3: a tenant pool must not overlap it).
var tailnetRange = netip.MustParsePrefix("100.64.0.0/10")

// Contains reports whether the host can run an instance with this UID and network: the UID inside run_uid_range and
// the /29 inside tenant_net_pool (§6.3).
func (h Host) Contains(runUID int32, net netip.Prefix) bool {
	return runUID >= h.RunUIDFirst && runUID <= h.RunUIDLast && net.Bits() >= h.TenantNetPool.Bits() &&
		h.TenantNetPool.Contains(net.Addr())
}

// FindHost reads a host by name; ErrNotFound when it is not registered.
func (s *Service) FindHost(ctx context.Context, name string) (Host, error) {
	var out Host
	err := s.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		r, err := q.GetHostByName(ctx, name)
		if errors.Is(err, store.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		out, err = host(r)
		return err
	})
	return out, err
}

// CheckHost compares a specification with the registered host of that name: it returns the host when it exists
// and matches (exists = true), nothing when it does not exist yet (exists = false), ErrConflict when it differs.
func (s *Service) CheckHost(ctx context.Context, spec HostSpec) (Host, bool, error) {
	if err := spec.validate(); err != nil {
		return Host{}, false, err
	}
	h, err := s.FindHost(ctx, spec.Name)
	if errors.Is(err, ErrNotFound) {
		return Host{}, false, nil
	}
	if err != nil {
		return Host{}, false, err
	}
	if diff := hostDiff(h, spec); len(diff) > 0 {
		return h, true, fmt.Errorf("%w: host %s is registered with other values for: %s", ErrConflict, h.Name,
			strings.Join(diff, ", "))
	}
	return h, true, nil
}

// EnsureHost registers a host idempotently (Phase 2: `meshguard admin adopt-instance`; the API of hosts is CreateHost /
// UpdateHost — hosts.go): an existing host must match the specification, a missing one is inserted.
func (s *Service) EnsureHost(ctx context.Context, spec HostSpec) (Host, bool, error) {
	h, exists, err := s.CheckHost(ctx, spec)
	if err != nil || exists {
		return h, exists, err
	}
	err = s.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		r, err := q.CreateHost(ctx, sqlcdb.CreateHostParams{ // capacity, public_entry: table defaults (0014)
			Name: spec.Name, Region: spec.Region, TenantNetPool: spec.TenantNetPool,
			RunUidRange: pgtype.Range[pgtype.Int4]{
				Lower: pgtype.Int4{Int32: spec.RunUIDFirst, Valid: true}, LowerType: pgtype.Inclusive,
				Upper: pgtype.Int4{Int32: spec.RunUIDLast, Valid: true}, UpperType: pgtype.Inclusive, Valid: true,
			},
		})
		if err != nil {
			return err
		}
		h, err = host(r)
		return err
	})
	if store.SQLState(err) == "23505" { // registered concurrently: compare with the winner
		return s.CheckHost(ctx, spec)
	}
	return h, false, err
}

func hostDiff(h Host, s HostSpec) []string {
	var d []string
	if h.Region != s.Region {
		d = append(d, "region")
	}
	if h.RunUIDFirst != s.RunUIDFirst || h.RunUIDLast != s.RunUIDLast {
		d = append(d, "run_uid_range")
	}
	if h.TenantNetPool != s.TenantNetPool {
		d = append(d, "tenant_net_pool")
	}
	return d
}

// host maps a row; PostgreSQL returns int4range in canonical form [first, last+1).
func host(r sqlcdb.Host) (Host, error) {
	first, last, ok := bounds(r.RunUidRange)
	if !ok {
		return Host{}, fmt.Errorf("platform: host %s has an unbounded run_uid_range", r.Name)
	}
	h := Host{ID: r.ID, Name: r.Name, Region: r.Region, Status: r.Status, RunUIDFirst: first, RunUIDLast: last,
		TenantNetPool: r.TenantNetPool}
	if r.StunPortRange.Valid {
		if h.STUNPortFirst, h.STUNPortLast, ok = bounds(r.StunPortRange); !ok {
			return Host{}, fmt.Errorf("platform: host %s has an unbounded stun_port_range", r.Name)
		}
	}
	var err error
	if h.MaxInstances, h.PublicEntry, h.EntryMode, err = parseHostSettings(r.Capacity, r.PublicEntry); err != nil {
		return Host{}, fmt.Errorf("platform: host %s: %w", r.Name, err)
	}
	return h, nil
}

// bounds returns the inclusive bounds of a non-empty finite int4range.
func bounds(rg pgtype.Range[pgtype.Int4]) (int32, int32, bool) {
	if !rg.Valid || !rg.Lower.Valid || !rg.Upper.Valid || rg.LowerType == pgtype.Unbounded ||
		rg.UpperType == pgtype.Unbounded || rg.LowerType == pgtype.Empty {
		return 0, 0, false
	}
	first, last := rg.Lower.Int32, rg.Upper.Int32
	if rg.LowerType == pgtype.Exclusive {
		first++
	}
	if rg.UpperType == pgtype.Exclusive {
		last--
	}
	return first, last, first <= last
}

func instance(r sqlcdb.TenantInstance, now time.Time) Instance {
	out := Instance{ID: r.ID, TenantID: r.TenantID, HostID: r.HostID, Status: r.Status,
		HeadscaleVersion: r.HeadscaleVersion, ImageDigest: r.ImageDigest, ControlHostname: r.ControlHostname,
		ServerURL: r.ServerUrl, DerpRegionID: r.DerpRegionID, RunUID: r.RunUid, NetCIDR: r.NetCidr,
		APIKeyExpiresAt: r.ApiKeyExpiresAt, NoiseKeyFingerprint: r.NoiseKeyFingerprint, LastHealth: r.LastHealth,
		ReadAt: now.UTC(), Version: r.Version, CreatedAt: r.CreatedAt.UTC()}
	if r.LastHealthAt != nil {
		t := r.LastHealthAt.UTC()
		out.HealthCheckedAt = &t
	}
	return out
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
