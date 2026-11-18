package platform

// Placement — step 3 `placement.allocate` of tenant.provision (§11.3, P3-T04): choose a host by capacity and region,
// allocate the instance's run_uid, net_cidr and (fallback design only) STUN port, derive its control hostname, and
// register it in tenant_instances with status `allocated` — all in ONE platform transaction of the worker.
//
// Concurrency. Every allocation first locks the rows of its candidate hosts (`SELECT … FOR UPDATE`, ordered by id, so
// two allocations never wait on each other in opposite orders) and only then reads the allocation state of those hosts:
// allocations on one host are serialised, and under READ COMMITTED each statement after the lock sees every allocation
// committed before the lock was released. The constraints of tenant_instances stay the last word (UNIQUE(host_id,
// run_uid); partial UNIQUE of control_hostname, of (host_id, net_cidr) and of the tenant's live instance; net_cidr is a
// /29 — 0014): an insert that still collides with a writer that does not take the lock (adopt-instance) is retried.
//
// Allocation rules:
//   - run_uid: the smallest UID of hosts.run_uid_range that NO instance row of the host has ever held — removed rows
//     included, and the application roles cannot delete rows of tenant_instances, so a UID is never reused (the data
//     directory and the backups of a removed instance are still owned by it) — skipping the UIDs/GIDs of the core
//     services (ReservedIDs, versions.lock [ids]);
//   - net_cidr: the lowest /29 of hosts.tenant_net_pool that overlaps no instance of the host that is not removed. A
//     subnet is reusable once its instance is `removed`: it is not an identity (nothing persistent is owned by it or keyed
//     on it — the Docker network is deleted before an instance becomes removed, §11.4, and the agent refuses a subnet
//     that overlaps a network still present, so a premature reuse fails closed at step 9), while a /16 pool holds only
//     8 192 of them;
//   - stun_port (only with PlacerOptions.PerTenantSTUN — the fallback design of §10.1; off by default, MVP = shared
//     STUN): the lowest port of hosts.stun_port_range that no live instance of the host uses, skipping the platform's
//     own ports; reusable once the instance is removed;
//   - control_hostname <slug>.mesh.<domain>, server_url, MagicDNS base domain <slug>.tail.<domain>, internal address
//     hs-<slug>:8080 and data path are derived from the slug the registry holds — never taken from the caller.
//
// Host choice: hosts with status `active` in the tenant's deployment_region (any region when the tenant has none); a
// host takes the instance when it declares a public entry (hosts.public_entry.ipv4 — derp.server.ipv4 of the instance),
// has fewer live instances than capacity.max_instances and still has a free UID, /29 (and STUN port); among those, the
// least used (live / max_instances), then the name. No such host ⇒ *NoCapacityError (errors.Is ErrNoCapacity) naming
// why each candidate was refused.
//
// Idempotency: the job chooses the instance ID before the step runs (it is recorded in created_resources); calling
// Allocate again with the same ID returns the registered allocation (Existing) and writes nothing. Compensation of the
// step is Release: the row becomes `removed` — never deleted — so its UID stays consumed, while the hostname, the subnet
// and the tenant's single live slot are freed for a replacement instance.

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"path"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
)

// DefaultTenantsDir is the directory of the instance directories on a host (§14.2).
const DefaultTenantsDir = "/opt/meshguard/tenants"

// Host statuses (hosts.status, 0014).
const (
	HostActive   = "active"   // takes new instances
	HostDraining = "draining" // keeps its instances, takes no new one
	HostDisabled = "disabled" // out of service
)

// Reasons a candidate host could not take an instance (HostRejection.Reason).
const (
	RejectNoPublicEntry    = "public_entry_missing"    // hosts.public_entry has no ipv4
	RejectFull             = "capacity_full"           // live instances ≥ capacity.max_instances
	RejectRunUIDExhausted  = "run_uid_exhausted"       // every UID of run_uid_range has been used
	RejectNetPoolExhausted = "net_pool_exhausted"      // no free /29 left in tenant_net_pool
	RejectSTUNRangeMissing = "stun_port_range_missing" // per-tenant STUN enabled, host has no stun_port_range
	RejectSTUNExhausted    = "stun_port_exhausted"     // every port of stun_port_range is in use
)

var (
	// ErrNoCapacity: no candidate host can take the instance (the error is a *NoCapacityError).
	ErrNoCapacity = errors.New("platform: no host can take the instance")
	// ErrTenantNotPlaceable: the tenant is not in status provisioning.
	ErrTenantNotPlaceable = fmt.Errorf("%w: the tenant is not being provisioned", ErrConflict)
	// ErrTenantHasInstance: the tenant already has another instance that is not removed (MVP: one per tenant, §6.3).
	ErrTenantHasInstance = fmt.Errorf("%w: the tenant already has a live instance", ErrConflict)
	// ErrHostnameInUse: an instance that is not removed holds the control hostname (a deleted tenant's instance that is
	// not purged yet — §11.4: the slug is not reusable while objects of the old instance remain).
	ErrHostnameInUse = fmt.Errorf("%w: the control hostname is held by a live instance", ErrConflict)
	// ErrInstanceRemoved: the instance ID belongs to a removed instance — a new allocation needs a new ID.
	ErrInstanceRemoved = fmt.Errorf("%w: the instance was removed", ErrConflict)
)

// ReservedIDs are the UIDs/GIDs of the platform's own services (versions.lock [ids] and the Keycloak image): a tenant
// container runs as run_uid:run_uid, so none of them may be allocated (a tenant process with GID 20003 could read the
// worker's secrets — §14.2). Same list as the agent's (agentspec.reservedIDs); TestReservedIDsCoverVersionsLock keeps it
// in step with versions.lock.
var ReservedIDs = []int32{0, 999, 1000, 10001, 10007, 20001, 20002, 20003, 20004, 20005, 20006, 20007, 20008, 20009, 65532, 65534}

// ReservedPorts are the ports the platform itself listens on at a host or its public entry (edge 80/443, tunnel
// listeners 8080/8443, shared STUN 3478): never a per-tenant STUN port (agentspec.reservedPorts).
var ReservedPorts = []int32{80, 443, 3478, 8080, 8443}

// HostRejection says why one candidate host could not take the instance.
type HostRejection struct {
	HostID uuid.UUID
	Host   string
	Reason string // one of the Reject* constants
}

// NoCapacityError is the typed "no host" outcome of Allocate: errors.Is(err, ErrNoCapacity).
type NoCapacityError struct {
	Region   string          // the tenant's deployment_region ("" = any)
	Rejected []HostRejection // empty: no active host in the region
}

func (e *NoCapacityError) Error() string {
	where := "any region"
	if e.Region != "" {
		where = "region " + e.Region
	}
	if len(e.Rejected) == 0 {
		return "platform: no active host in " + where
	}
	parts := make([]string, len(e.Rejected))
	for i, r := range e.Rejected {
		parts[i] = r.Host + ": " + r.Reason
	}
	return "platform: no host in " + where + " can take the instance (" + strings.Join(parts, ", ") + ")"
}

// Is makes errors.Is(err, ErrNoCapacity) true.
func (e *NoCapacityError) Is(target error) bool { return target == ErrNoCapacity }

// PlacerOptions configures a Placer.
type PlacerOptions struct {
	// BaseDomain (MG_BASE_DOMAIN): control hostname <slug>.mesh.<BaseDomain>, MagicDNS <slug>.tail.<BaseDomain>.
	BaseDomain string
	// TenantsDir is the directory of instance directories on the hosts ("" = DefaultTenantsDir).
	TenantsDir string
	// PerTenantSTUN enables the fallback design of §10.1 (a STUN port per instance from hosts.stun_port_range). Off by
	// default: the MVP uses the shared STUN responder of the public entry.
	PerTenantSTUN bool
}

// Placer allocates instances. It needs the worker's platform pool (mg_worker_platform): hosts is a platform table.
type Placer struct {
	st            *store.Store
	base          string
	dir           string
	perTenantSTUN bool
}

var domainRE = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)

// NewPlacer returns a Placer on st.
func NewPlacer(st *store.Store, o PlacerOptions) (*Placer, error) {
	base := strings.ToLower(strings.TrimSpace(o.BaseDomain))
	if !domainRE.MatchString(base) {
		return nil, fmt.Errorf("%w: base domain must be a lower-case domain name", ErrInvalid)
	}
	dir := o.TenantsDir
	if dir == "" {
		dir = DefaultTenantsDir
	}
	if !path.IsAbs(dir) || path.Clean(dir) != dir || dir == "/" {
		return nil, fmt.Errorf("%w: tenants directory must be a clean absolute path", ErrInvalid)
	}
	return &Placer{st: st, base: base, dir: dir, perTenantSTUN: o.PerTenantSTUN}, nil
}

// AllocationRequest asks for the placement of one instance of a tenant.
type AllocationRequest struct {
	TenantID   uuid.UUID
	InstanceID uuid.UUID // chosen by the job beforehand — the idempotency key of the step
	// HeadscaleVersion and ImageDigest are the runtime the instance will run (tenant_instances keeps them from step 3).
	HeadscaleVersion string
	ImageDigest      string
}

// Allocation is the placement of an instance: everything step 7–10 needs to build the agent's InstanceSpec.
type Allocation struct {
	InstanceID       uuid.UUID
	TenantID         uuid.UUID
	Slug             string
	HostID           uuid.UUID
	HostName         string
	Region           string
	RunUID           int32
	NetCIDR          netip.Prefix
	STUNPort         int32      // 0 = shared STUN (MVP)
	PublicEntryIPv4  netip.Addr // derp.server.ipv4 (hosts.public_entry.ipv4)
	ControlHostname  string     // <slug>.mesh.<domain>
	ServerURL        string     // https://<control hostname>
	BaseDomain       string     // MagicDNS <slug>.tail.<domain>
	InternalAddress  string     // hs-<slug>:8080
	DataPath         string     // <tenants dir>/<instance_id>/data
	HeadscaleVersion string
	ImageDigest      string
	Status           string // tenant_instances.status
	Existing         bool   // true: the instance was already allocated (a repeated step) — nothing was written
}

var (
	digestRE  = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	versionRE = regexp.MustCompile(`^v?[0-9]+\.[0-9]+\.[0-9]+([.+-][0-9A-Za-z.+-]{1,32})?$`)
	slugRE    = regexp.MustCompile(`^[a-z][a-z0-9-]{1,30}[a-z0-9]$`) // §11.3 step 1
)

func (r AllocationRequest) validate() error {
	switch {
	case r.TenantID == uuid.Nil || r.InstanceID == uuid.Nil:
		return fmt.Errorf("%w: tenant and instance ids are required", ErrInvalid)
	case !digestRE.MatchString(r.ImageDigest):
		return fmt.Errorf("%w: image digest must be sha256:<64 hex>", ErrInvalid)
	case !versionRE.MatchString(r.HeadscaleVersion):
		return fmt.Errorf("%w: headscale version", ErrInvalid)
	}
	return nil
}

// allocationAttempts bounds the retries of an insert that collided with a writer outside the host lock.
const allocationAttempts = 3

// Allocate places the instance (see the file comment). Errors: ErrInvalid; ErrNotFound (no such tenant);
// ErrTenantNotPlaceable, ErrTenantHasInstance, ErrHostnameInUse, ErrInstanceRemoved (all ErrConflict); *NoCapacityError
// (ErrNoCapacity).
func (p *Placer) Allocate(ctx context.Context, req AllocationRequest) (Allocation, error) {
	if err := req.validate(); err != nil {
		return Allocation{}, err
	}
	var (
		out Allocation
		err error
	)
	for attempt := 1; attempt <= allocationAttempts; attempt++ {
		err = p.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
			var err error
			out, err = p.allocate(ctx, q, req)
			return err
		})
		if !retryable(err) {
			break
		}
	}
	return out, classify(err)
}

func (p *Placer) allocate(ctx context.Context, q *sqlcdb.Queries, req AllocationRequest) (Allocation, error) {
	// 1. a repeated step: the instance is already registered
	if a, found, err := p.existing(ctx, q, req); found || err != nil {
		return a, err
	}
	// 2. the tenant, as the registry holds it
	t, err := q.GetTenant(ctx, req.TenantID)
	if errors.Is(err, store.ErrNoRows) {
		return Allocation{}, ErrNotFound
	}
	if err != nil {
		return Allocation{}, err
	}
	if t.Status != tenants.StatusProvisioning {
		return Allocation{}, fmt.Errorf("%w (status %s)", ErrTenantNotPlaceable, t.Status)
	}
	if !slugRE.MatchString(t.Slug) || strings.Contains(t.Slug, "--") {
		return Allocation{}, fmt.Errorf("%w: tenant slug %q is not a valid instance name", ErrInvalid, t.Slug)
	}
	// 3. lock the candidate hosts, then read everything again under the lock
	hosts, err := q.LockPlacementHosts(ctx, t.DeploymentRegion)
	if err != nil {
		return Allocation{}, err
	}
	if a, found, err := p.existing(ctx, q, req); found || err != nil { // allocated while this transaction waited
		return a, err
	}
	switch live, err := q.GetLiveInstanceForTenant(ctx, t.ID); {
	case err == nil:
		return Allocation{}, fmt.Errorf("%w (instance %s, %s)", ErrTenantHasInstance, live.ID, live.Status)
	case !errors.Is(err, store.ErrNoRows):
		return Allocation{}, err
	}
	control := tenants.ControlHostname(t.Slug, p.base)
	switch holder, err := q.GetLiveInstanceByHostname(ctx, control); {
	case err == nil:
		return Allocation{}, fmt.Errorf("%w (%s: instance %s)", ErrHostnameInUse, control, holder.ID)
	case !errors.Is(err, store.ErrNoRows):
		return Allocation{}, err
	}
	// 4. choose the host and the resources
	region := ""
	if t.DeploymentRegion != nil {
		region = *t.DeploymentRegion
	}
	plan, err := p.choose(ctx, q, hosts, region)
	if err != nil {
		return Allocation{}, err
	}
	// 5. register the instance (status allocated)
	a := Allocation{InstanceID: req.InstanceID, TenantID: t.ID, Slug: t.Slug, HostID: plan.host.ID,
		HostName: plan.host.Name, Region: plan.host.Region, RunUID: plan.runUID, NetCIDR: plan.net, STUNPort: plan.stunPort,
		PublicEntryIPv4: plan.host.PublicEntry, ControlHostname: control, ServerURL: "https://" + control,
		BaseDomain: tenants.MagicDNSDomain(t.Slug, p.base), InternalAddress: "hs-" + t.Slug + ":8080",
		DataPath: path.Join(p.dir, req.InstanceID.String(), "data"), HeadscaleVersion: req.HeadscaleVersion,
		ImageDigest: req.ImageDigest, Status: tenants.InstanceAllocated}
	var stun *int32
	if a.STUNPort != 0 {
		stun = &a.STUNPort
	}
	if _, err := q.CreateTenantInstance(ctx, sqlcdb.CreateTenantInstanceParams{
		ID: a.InstanceID, TenantID: a.TenantID, HostID: a.HostID, Status: a.Status, HeadscaleVersion: a.HeadscaleVersion,
		ImageDigest: a.ImageDigest, ControlHostname: a.ControlHostname, ServerUrl: a.ServerURL, BaseDomain: a.BaseDomain,
		InternalAddress: a.InternalAddress, StunPort: stun, RunUid: a.RunUID, NetCidr: a.NetCIDR, DataPath: a.DataPath,
	}); err != nil {
		return Allocation{}, err
	}
	return a, nil
}

// existing returns the registered allocation of req.InstanceID (found = true), or found = false when there is none.
func (p *Placer) existing(ctx context.Context, q *sqlcdb.Queries, req AllocationRequest) (Allocation, bool, error) {
	r, err := q.GetTenantInstance(ctx, req.InstanceID)
	if errors.Is(err, store.ErrNoRows) {
		return Allocation{}, false, nil
	}
	if err != nil {
		return Allocation{}, false, err
	}
	switch {
	case r.TenantID != req.TenantID:
		return Allocation{}, true, fmt.Errorf("%w: instance %s belongs to another tenant", ErrConflict, r.ID)
	case r.Status == tenants.InstanceRemoved:
		return Allocation{}, true, fmt.Errorf("%w (instance %s)", ErrInstanceRemoved, r.ID)
	}
	t, err := q.GetTenant(ctx, r.TenantID)
	if err != nil {
		return Allocation{}, true, err
	}
	hr, err := q.GetHost(ctx, r.HostID)
	if err != nil {
		return Allocation{}, true, err
	}
	h, err := host(hr)
	if err != nil {
		return Allocation{}, true, err
	}
	a := Allocation{InstanceID: r.ID, TenantID: r.TenantID, Slug: t.Slug, HostID: h.ID, HostName: h.Name, Region: h.Region,
		RunUID: r.RunUid, NetCIDR: r.NetCidr, PublicEntryIPv4: h.PublicEntry, ControlHostname: r.ControlHostname,
		ServerURL: r.ServerUrl, BaseDomain: r.BaseDomain, InternalAddress: r.InternalAddress, DataPath: r.DataPath,
		HeadscaleVersion: r.HeadscaleVersion, ImageDigest: r.ImageDigest, Status: r.Status, Existing: true}
	if r.StunPort != nil {
		a.STUNPort = *r.StunPort
	}
	return a, true, nil
}

// hostPlan is what one candidate host would allocate.
type hostPlan struct {
	host     Host
	live     int64
	runUID   int32
	net      netip.Prefix
	stunPort int32
}

// allocRow is one instance row of a host as placement sees it.
type allocRow struct {
	removed  bool
	runUID   int32
	net      netip.Prefix
	stunPort *int32
}

// choose evaluates every locked host and returns the least used one that can take the instance.
func (p *Placer) choose(ctx context.Context, q *sqlcdb.Queries, rows []sqlcdb.Host, region string) (hostPlan, error) {
	noHost := &NoCapacityError{Region: region}
	if len(rows) == 0 {
		return hostPlan{}, noHost
	}
	ids := make([]uuid.UUID, len(rows))
	for i, r := range rows {
		ids[i] = r.ID
	}
	allocs, err := q.ListHostAllocations(ctx, ids)
	if err != nil {
		return hostPlan{}, err
	}
	byHost := map[uuid.UUID][]allocRow{}
	for _, a := range allocs {
		byHost[a.HostID] = append(byHost[a.HostID], allocRow{removed: a.Status == tenants.InstanceRemoved,
			runUID: a.RunUid, net: a.NetCidr, stunPort: a.StunPort})
	}
	var plans []hostPlan
	for _, r := range rows {
		h, err := host(r)
		if err != nil {
			return hostPlan{}, err
		}
		plan, reason := planHost(h, byHost[h.ID], p.perTenantSTUN)
		if reason != "" {
			noHost.Rejected = append(noHost.Rejected, HostRejection{HostID: h.ID, Host: h.Name, Reason: reason})
			continue
		}
		plans = append(plans, plan)
	}
	if len(plans) == 0 {
		return hostPlan{}, noHost
	}
	sort.SliceStable(plans, func(i, j int) bool { return lessUsed(plans[i], plans[j]) })
	return plans[0], nil
}

// lessUsed orders plans by utilisation live/max_instances (cross-multiplied, no float), then by name.
func lessUsed(a, b hostPlan) bool {
	ua, ub := a.live*int64(b.host.MaxInstances), b.live*int64(a.host.MaxInstances)
	if ua != ub {
		return ua < ub
	}
	return a.host.Name < b.host.Name
}

// planHost decides whether host h can take one more instance given its instance rows, and what it would allocate;
// reason is one of the Reject* constants when it cannot.
func planHost(h Host, rows []allocRow, perTenantSTUN bool) (hostPlan, string) {
	if !h.PublicEntry.IsValid() {
		return hostPlan{}, RejectNoPublicEntry
	}
	usedUIDs := make(map[int32]bool, len(rows))
	var liveNets []netip.Prefix
	usedPorts := map[int32]bool{}
	var live int64
	for _, r := range rows {
		usedUIDs[r.runUID] = true // removed rows too: a UID is never reused
		if r.removed {
			continue
		}
		live++
		liveNets = append(liveNets, r.net)
		if r.stunPort != nil {
			usedPorts[*r.stunPort] = true
		}
	}
	if live >= int64(h.MaxInstances) {
		return hostPlan{}, RejectFull
	}
	uid, ok := smallestFree(h.RunUIDFirst, h.RunUIDLast, func(u int32) bool {
		return usedUIDs[u] || slices.Contains(ReservedIDs, u)
	})
	if !ok {
		return hostPlan{}, RejectRunUIDExhausted
	}
	net, ok := smallestFreeNet(h.TenantNetPool, liveNets)
	if !ok {
		return hostPlan{}, RejectNetPoolExhausted
	}
	plan := hostPlan{host: h, live: live, runUID: uid, net: net}
	if perTenantSTUN {
		if h.STUNPortFirst == 0 {
			return hostPlan{}, RejectSTUNRangeMissing
		}
		port, ok := smallestFree(h.STUNPortFirst, h.STUNPortLast, func(p int32) bool {
			return usedPorts[p] || slices.Contains(ReservedPorts, p)
		})
		if !ok {
			return hostPlan{}, RejectSTUNExhausted
		}
		plan.stunPort = port
	}
	return plan, ""
}

// smallestFree returns the smallest v in [first, last] for which taken(v) is false.
func smallestFree(first, last int32, taken func(int32) bool) (int32, bool) {
	if first > last {
		return 0, false
	}
	for v := first; ; v++ {
		if !taken(v) {
			return v, true
		}
		if v == last {
			return 0, false
		}
	}
}

// smallestFreeNet returns the lowest /29 of pool (IPv4) that overlaps none of used.
func smallestFreeNet(pool netip.Prefix, used []netip.Prefix) (netip.Prefix, bool) {
	if !pool.IsValid() || !pool.Addr().Is4() || pool.Bits() > 29 {
		return netip.Prefix{}, false
	}
	type span struct{ lo, hi uint64 }
	start := uint64(v4(pool.Masked().Addr()))
	end := start + (uint64(1) << (32 - pool.Bits())) - 1
	spans := make([]span, 0, len(used))
	for _, u := range used {
		if !u.IsValid() || !u.Addr().Is4() {
			continue
		}
		lo := uint64(v4(u.Masked().Addr()))
		hi := lo + (uint64(1) << (32 - u.Bits())) - 1
		if hi >= start && lo <= end {
			spans = append(spans, span{lo, hi})
		}
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].lo < spans[j].lo })
	c := start // pool is aligned on 8 (≤ /29)
	for _, s := range spans {
		if s.hi < c {
			continue
		}
		if s.lo > c+7 {
			break
		}
		c = (s.hi + 8) &^ 7 // first /29 after the span
	}
	if c+7 > end {
		return netip.Prefix{}, false
	}
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], uint32(c)) //nolint:gosec // G115: c ≤ end ≤ 2^32-1
	return netip.PrefixFrom(netip.AddrFrom4(b), 29), true
}

func v4(a netip.Addr) uint32 {
	b := a.As4()
	return binary.BigEndian.Uint32(b[:])
}

// Release is the compensation of step 3 (§11.3): the instance becomes `removed` — the row is kept (the application
// roles cannot delete it), so its run_uid is never handed out again, while its hostname, subnet, STUN port and the
// tenant's live slot become free for a replacement. Only an instance that is `allocated` (never started — transition
// allocated → removed, §13.3) or `failed` (its later steps already compensated) is released; released = false when it
// was already removed. Another tenant's instance reads as ErrNotFound.
func (p *Placer) Release(ctx context.Context, tenantID, instanceID uuid.UUID) (bool, error) {
	if tenantID == uuid.Nil || instanceID == uuid.Nil {
		return false, ErrNotFound
	}
	var released bool
	err := p.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		r, err := q.GetTenantInstance(ctx, instanceID)
		if errors.Is(err, store.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		switch {
		case r.TenantID != tenantID:
			return ErrNotFound
		case r.Status == tenants.InstanceRemoved:
			return nil
		case r.Status != tenants.InstanceAllocated && r.Status != tenants.InstanceFailed:
			return fmt.Errorf("%w: instance %s is %s — only an allocated or failed instance is released", ErrConflict,
				instanceID, r.Status)
		}
		if _, err := q.TransitionTenantInstanceStatus(ctx, sqlcdb.TransitionTenantInstanceStatusParams{
			Status: tenants.InstanceRemoved, ID: instanceID, TenantID: tenantID, FromStatus: r.Status}); err != nil {
			return err
		}
		released = true
		return nil
	})
	return released, err
}

// retryable: a unique violation on an allocated resource (UID, subnet, STUN port) — another writer took it between the
// read and the insert; the next attempt reads the state again.
func retryable(err error) bool {
	if store.SQLState(err) != "23505" {
		return false
	}
	switch store.SQLConstraint(err) {
	case "tenant_instances_host_id_run_uid_key", "tenant_instances_net_live_key", "tenant_instances_stun_port_live_key":
		return true
	}
	return false
}

// classify turns the remaining constraint violations into the typed errors.
func classify(err error) error {
	if store.SQLState(err) != "23505" {
		return err
	}
	switch store.SQLConstraint(err) {
	case "tenant_instances_hostname_live_key":
		return fmt.Errorf("%w (refused by the database)", ErrHostnameInUse)
	case "tenant_instances_one_live_per_tenant":
		return fmt.Errorf("%w (refused by the database)", ErrTenantHasInstance)
	case "tenant_instances_pkey":
		return fmt.Errorf("%w: instance id already registered (refused by the database)", ErrConflict)
	}
	return fmt.Errorf("%w: refused by the database (constraint %s)", ErrConflict, store.SQLConstraint(err))
}

// maxInstancesRE is capacity.max_instances as 0014 accepts it: a JSON integer without fraction or exponent.
var maxInstancesRE = regexp.MustCompile(`^[0-9]{1,10}$`)

// parseHostSettings reads capacity and public_entry (the jsonb columns of hosts placement reads); a value outside the
// shapes of 0014 is an error (fail closed). An undeclared max_instances reads as 0 (the host takes nothing).
func parseHostSettings(capacity, publicEntry []byte) (maxInstances int32, entry netip.Addr, mode string, err error) {
	var c map[string]json.RawMessage
	if len(capacity) > 0 {
		if err := json.Unmarshal(capacity, &c); err != nil {
			return 0, netip.Addr{}, "", fmt.Errorf("capacity: %w", err)
		}
	}
	if raw, ok := c["max_instances"]; ok {
		n, err := strconv.ParseInt(string(raw), 10, 32)
		if !maxInstancesRE.Match(raw) || err != nil {
			return 0, netip.Addr{}, "", errors.New("capacity.max_instances is not an integer 0…2147483647")
		}
		maxInstances = int32(n) //nolint:gosec // G115: ParseInt with bitSize 32 bounds n
	}
	var pe struct {
		IPv4 string `json:"ipv4"`
		Mode string `json:"mode"`
	}
	if len(publicEntry) > 0 {
		if err := json.Unmarshal(publicEntry, &pe); err != nil {
			return 0, netip.Addr{}, "", fmt.Errorf("public_entry: %w", err)
		}
	}
	if pe.IPv4 != "" {
		a, err := netip.ParseAddr(pe.IPv4)
		if err != nil || !a.Is4() || a.String() != pe.IPv4 {
			return 0, netip.Addr{}, "", errors.New("public_entry.ipv4 is not a canonical IPv4 address")
		}
		entry = a
	}
	return maxInstances, entry, pe.Mode, nil
}
