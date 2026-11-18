// Package orphans is the orphan-resource detector of the provisioning tests (P3-T07): after a provisioning ran, failed,
// was compensated or retried, nothing may be left that the registry does not account for — no container, network,
// instance directory or SecretStore version, and, inside a live instance, no valid Headscale API key other than the one
// the SecretStore holds (§11.3 step 13, T-05).
//
// Two halves:
//
//   - Check compares an Inventory — what exists, with the registry's view of what should — and returns the findings.
//     It is pure (unit-tested on hand-built inventories, orphans_test.go).
//   - Collect builds the Inventory from the real sources of a test host: the Docker Engine (containers and networks with
//     a MeshGuard name or label, the edge's attachments), the agent's tenants directory, the Host Agent (inventory,
//     API keys of each live instance), PostgreSQL (tenants, instances, IdPs, secret versions), the SecretStore (the
//     stored key) and the Headscale adapter (the stored key must authenticate through the edge). The host part reuses the
//     "unknown resources" logic of reconcile (P3-T12, reconcile.Inspector.Host) over the agent's inventory, restricted to
//     the run's scope, on top of its own raw scan (which also sees what the agent's inventory does not: helper
//     containers, hidden directories of an interrupted create/remove, unlabelled objects with a derived name).
//
// The detector only reads. A host shared by other runs is handled by Scope: only tenants whose slug starts with the
// run's prefix, and the run's own tenants directory, are judged.
package orphans

import (
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Instance statuses of tenant_instances (internal/tenants).
const (
	StatusAllocated   = "allocated"
	StatusStarting    = "starting"
	StatusRunning     = "running"
	StatusStopped     = "stopped"
	StatusFailed      = "failed"
	StatusRemoved     = "removed"
	StatusQuarantined = "quarantined"
)

// APIKeySecretName is the SecretStore name of an instance API key (provisioning.APIKeySecretName).
const APIKeySecretName = "headscale-api-key" //nolint:gosec // G101: the name of a secret, not a credential

// Scope selects the run being checked on a host other runs may share.
type Scope struct {
	SlugPrefix string // tenants whose slug starts with it ("" = every tenant)
	TenantsDir string // the agent's tenants directory (MG_AGENT_TENANTS_DIR) — owned by the run: every entry is judged
	Edge       string // container name of the edge (its tenant-network attachments are judged)
	// EdgeNetwork is the edge's platform network (MG_AGENT_EDGE_NETWORK) — never a tenant network.
	EdgeNetwork string
	// AllowSecrets are secret names a tenant may hold besides the instance API key and its IdP client secret.
	AllowSecrets []string
	// Settled: no job of the run is in flight, so allocated/failed instances (states inside a provisioning or a
	// compensation) are findings themselves.
	Settled bool
}

func (s Scope) inScope(slug string) bool { return strings.HasPrefix(slug, s.SlugPrefix) }

// Tenant is a tenants row, with what a deprovision must have closed (P3-T09).
type Tenant struct {
	ID     uuid.UUID
	Slug   string
	Status string
	// KeysDestroyAfter is tenants.keys_destroy_after (a deleted tenant's crypto-shredding schedule; nil = none).
	KeysDestroyAfter *time.Time
	LiveDEKs         int // DEK versions of the tenant still holding key material
	LiveSessions     int // Portal sessions of the tenant's identities not revoked
}

// Instance is a tenant_instances row (with its tenant's slug).
type Instance struct {
	ID, TenantID uuid.UUID
	Slug         string
	Status       string
	APIKeyRef    string // mgsec://<tenant>/headscale-api-key#n ("" = none)
	APIKeyPrefix string
}

// IdP is an identity_providers row.
type IdP struct {
	ID, TenantID    uuid.UUID
	Status          string
	ClientSecretRef string
}

// Secret is one version of a secret (tenant scope; platform secrets have TenantID uuid.Nil).
type Secret struct {
	TenantID  uuid.UUID
	Name      string
	Version   int32
	Destroyed bool
}

// Ref is the mgsec:// reference of the version.
func (s Secret) Ref() string {
	owner := s.TenantID.String()
	if s.TenantID == uuid.Nil {
		owner = "platform"
	}
	return fmt.Sprintf("mgsec://%s/%s#%d", owner, s.Name, s.Version)
}

// Invitation is a tenant_invitations row.
type Invitation struct {
	ID, TenantID uuid.UUID
	Status       string
}

// Relay is an embedded relay region or assignment of a tenant (relay_regions, relay_assignments).
type Relay struct {
	TenantID uuid.UUID
	Kind     string // region or assignment
	Name     string // code of the region, id of the assignment
}

// Registry is what PostgreSQL says should exist.
type Registry struct {
	Tenants     []Tenant
	Instances   []Instance
	IdPs        []IdP
	Secrets     []Secret
	Invitations []Invitation
	Relays      []Relay
}

// Container is a Docker container with a MeshGuard name or label.
type Container struct {
	ID, Name, State string
	Labels          map[string]string
}

// Network is a Docker network with a MeshGuard name or label.
type Network struct {
	ID, Name string
	Labels   map[string]string
}

// Host is what exists on the Docker host and in the tenants directory.
type Host struct {
	Containers   []Container
	Networks     []Network
	EdgeNetworks []string // networks the edge container is attached to
	Dirs         []string // entries of Scope.TenantsDir (hidden ones included)
}

// APIKey is one key a Headscale instance reports (public part only).
type APIKey struct {
	Prefix     string
	Expiration time.Time // zero: never expires
}

// Valid follows Headscale: no expiration or an expiration in the future.
func (k APIKey) Valid(now time.Time) bool { return k.Expiration.IsZero() || k.Expiration.After(now) }

// Keys is the API key state of one live instance.
type Keys struct {
	InstanceID   uuid.UUID
	Listed       []APIKey // the keys Headscale reports (through the agent)
	ListErr      string   // the keys could not be listed
	StoredPrefix string   // prefix of the key the SecretStore holds under the registry's reference
	StoredErr    string   // the stored key could not be read
	APIOK        bool     // the stored key authenticated a call to the instance's REST API through the edge
	APIErr       string
}

// HostFinding is a finding of reconcile's host check (reconcile.Inspector.Host) over the scoped agent inventory.
type HostFinding struct{ Kind, Subject string }

// Inventory is one observation of a run.
type Inventory struct {
	Scope    Scope
	Now      time.Time
	Registry Registry
	Host     Host
	Keys     []Keys
	// Reconcile are the findings of reconcile's host check; nil when it did not run.
	Reconcile []HostFinding
}

// Finding is one thing left behind (or missing).
type Finding struct {
	Kind    string `json:"kind"`
	Subject string `json:"subject"`
	Detail  string `json:"detail,omitempty"`
}

func (f Finding) String() string {
	if f.Detail == "" {
		return f.Kind + " " + f.Subject
	}
	return f.Kind + " " + f.Subject + " (" + f.Detail + ")"
}

// Kinds of findings.
const (
	ContainerHelper      = "helper_container_left"      // a one-shot helper outlived its RPC
	ContainerUnknown     = "container_unknown_instance" // labelled with an instance the registry does not have
	ContainerOfRemoved   = "container_of_removed_instance"
	ContainerUnlabelled  = "container_unlabelled"     // derived name without the instance label
	ContainerMisnamed    = "container_misnamed"       // labelled with an instance, but not mg-hs-<its slug>
	ContainerMissing     = "container_missing"        // a starting/running/stopped instance has no container
	ContainerNotRunning  = "container_not_running"    // a starting/running instance's container is not running
	ContainerUnexpected  = "container_unexpected"     // an allocated instance (before step 10) has a container
	NetworkUnknown       = "network_unknown_instance" // labelled with an instance the registry does not have
	NetworkOfRemoved     = "network_of_removed_instance"
	NetworkUnlabelled    = "network_unlabelled"
	NetworkMisnamed      = "network_misnamed"
	NetworkMissing       = "network_missing"
	EdgeAttachedOrphan   = "edge_attached_orphan" // the edge is on a tenant network that is not a live instance's
	EdgeNotAttached      = "edge_not_attached"    // a running instance's network lacks the edge
	DirHidden            = "directory_hidden_leftover"
	DirUnknown           = "directory_unknown_instance"
	DirOfRemoved         = "directory_of_removed_instance"
	DirForeign           = "directory_foreign" // not an instance id at all
	DirMissing           = "directory_missing"
	InstanceUnsettled    = "instance_unsettled" // allocated/failed while nothing is in flight
	SecretOrphan         = "secret_orphan"      // a live version no registry row references
	SecretUnexpected     = "secret_unexpected"  // a live secret of a name the tenant should not hold
	SecretMissing        = "secret_missing"     // the registry references a version that is not live
	PendingSecretLeft    = "pending_secret_left"
	APIKeyUnlisted       = "apikey_unlisted"
	APIKeyUnchecked      = "apikey_unchecked"
	APIKeyUnregistered   = "apikey_valid_unregistered" //nolint:gosec // G101: a finding kind — a valid key while the registry has none
	APIKeyExtraValid     = "apikey_extra_valid"        //nolint:gosec // G101: a finding kind — a valid key other than the registry's
	APIKeyRegisteredGone = "apikey_registered_invalid" // the registry's key is not (or no longer) valid
	APIKeySecretUnread   = "apikey_secret_unreadable"
	APIKeySecretMismatch = "apikey_secret_mismatch" // the SecretStore holds another key than the registry's prefix
	APIKeyRejected       = "apikey_rejected"        // the stored key did not authenticate through the edge
	ReconcilePrefix      = "reconcile."             // + a reconcile drift kind (unknown_instance, removed_instance_leftover…)
	// Registry rows a rolled-back provisioning must have undone (tenant `failed`, §11.3 compensations 6, 16, 17).
	InvitationLeft = "invitation_pending_on_failed_tenant"
	RelayLeft      = "relay_of_failed_tenant"
	IdPNotDisabled = "idp_not_disabled_on_failed_tenant"
	// What a deprovision must have closed (tenant `deleted`, §11.4 — P3-T09): no live instance, invitation, relay row,
	// enabled IdP or Portal session; the destruction of its keys scheduled, and done once the grace period has passed.
	InstanceOfDeleted     = "instance_live_on_deleted_tenant"
	InvitationLeftDeleted = "invitation_pending_on_deleted_tenant"
	RelayLeftDeleted      = "relay_of_deleted_tenant"
	IdPNotDisabledDeleted = "idp_not_disabled_on_deleted_tenant"
	SessionLeft           = "session_live_on_deleted_tenant"
	KeysUnscheduled       = "keys_destruction_unscheduled"
	KeysLeft              = "keys_live_after_grace"
	labelInstance         = "meshguard.instance_id"
	labelHelperInstance   = "meshguard.helper_instance_id"
	labelTenant           = "meshguard.tenant_id"
	labelRole             = "meshguard.role"
	roleHelper            = "agent-helper"
	containerPrefix       = "mg-hs-"
	helperPrefix          = "mg-helper-"
	networkPrefix         = "mg-t-"
	creatingSuffix        = ".creating"
	removingSuffix        = ".removing"
	pendingIdPSecretStart = "idp-pending."
)

// live: the instance holds (or may hold) host resources.
func live(status string) bool { return status != StatusRemoved }

// serving: the instance must have its directory, network and container.
func serving(status string) bool {
	return status == StatusStarting || status == StatusRunning || status == StatusStopped
}

type checker struct {
	inv       Inventory
	out       []Finding
	instances map[uuid.UUID]Instance
	bySlug    map[string][]Instance
	tenants   map[uuid.UUID]Tenant
}

func (c *checker) add(kind, subject, detail string) {
	c.out = append(c.out, Finding{Kind: kind, Subject: subject, Detail: detail})
}

// Check returns every finding of the inventory, sorted.
func Check(inv Inventory) []Finding {
	c := &checker{inv: inv, instances: map[uuid.UUID]Instance{}, bySlug: map[string][]Instance{}, tenants: map[uuid.UUID]Tenant{}}
	for _, t := range inv.Registry.Tenants {
		if inv.Scope.inScope(t.Slug) {
			c.tenants[t.ID] = t
		}
	}
	for _, i := range inv.Registry.Instances {
		if _, ok := c.tenants[i.TenantID]; ok {
			c.instances[i.ID] = i
			c.bySlug[i.Slug] = append(c.bySlug[i.Slug], i)
		}
	}
	c.settled()
	c.containers()
	c.networks()
	c.edge()
	c.dirs()
	c.secrets()
	c.keys()
	c.closedTenants()
	for _, f := range inv.Reconcile {
		c.add(ReconcilePrefix+f.Kind, f.Subject, "")
	}
	sort.Slice(c.out, func(i, j int) bool {
		if c.out[i].Kind != c.out[j].Kind {
			return c.out[i].Kind < c.out[j].Kind
		}
		return c.out[i].Subject < c.out[j].Subject
	})
	return c.out
}

func (c *checker) settled() {
	if !c.inv.Scope.Settled {
		return
	}
	for _, i := range c.instances {
		if i.Status == StatusAllocated || i.Status == StatusFailed {
			c.add(InstanceUnsettled, i.ID.String(), i.Slug+" "+i.Status)
		}
	}
}

// liveBySlug is the live instance of a slug (a tenant has at most one — tenant_instances_one_live_per_tenant).
func (c *checker) liveBySlug(slug string) (Instance, bool) {
	for _, i := range c.bySlug[slug] {
		if live(i.Status) {
			return i, true
		}
	}
	return Instance{}, false
}

// slugOf returns the slug in a derived name (mg-hs-<slug>, mg-t-<slug>, mg-helper-<slug>-<op>-<hex>) when it is in scope.
func (c *checker) nameInScope(name, prefix string) bool {
	rest, ok := strings.CutPrefix(name, prefix)
	return ok && c.inv.Scope.inScope(rest)
}

// object classifies one labelled or derived-name object of the scope against the registry.
func (c *checker) object(kind, name string, labels map[string]string, wantName func(Instance) string,
	unknown, removed, unlabelled, misnamed string,
) (Instance, bool) {
	id, err := uuid.Parse(labels[labelInstance])
	if err != nil {
		c.add(unlabelled, name, "no "+labelInstance+" label")
		return Instance{}, false
	}
	inst, ok := c.instances[id]
	switch {
	case !ok:
		c.add(unknown, name, kind+" of instance "+id.String())
		return Instance{}, false
	case !live(inst.Status):
		c.add(removed, name, "instance "+id.String()+" is "+inst.Status)
		return Instance{}, false
	case name != wantName(inst):
		c.add(misnamed, name, "instance "+id.String()+" is "+inst.Slug)
		return Instance{}, false
	}
	return inst, true
}

func (c *checker) labelledInScope(labels map[string]string) bool {
	for _, k := range []string{labelInstance, labelHelperInstance} {
		if id, err := uuid.Parse(labels[k]); err == nil {
			if _, ok := c.instances[id]; ok {
				return true
			}
		}
	}
	if id, err := uuid.Parse(labels[labelTenant]); err == nil {
		if _, ok := c.tenants[id]; ok {
			return true
		}
	}
	return false
}

func (c *checker) containers() {
	seen := map[uuid.UUID]Container{}
	for _, ct := range c.inv.Host.Containers {
		helper := ct.Labels[labelRole] == roleHelper || strings.HasPrefix(ct.Name, helperPrefix)
		inScope := c.labelledInScope(ct.Labels) || c.nameInScope(ct.Name, containerPrefix) || c.nameInScope(ct.Name, helperPrefix)
		if !inScope {
			continue
		}
		if helper {
			c.add(ContainerHelper, ct.Name, "state "+ct.State)
			continue
		}
		inst, ok := c.object("container", ct.Name, ct.Labels, func(i Instance) string { return containerPrefix + i.Slug },
			ContainerUnknown, ContainerOfRemoved, ContainerUnlabelled, ContainerMisnamed)
		if ok {
			seen[inst.ID] = ct
		}
	}
	for _, i := range c.instances {
		ct, has := seen[i.ID]
		switch {
		case serving(i.Status) && !has:
			c.add(ContainerMissing, i.ID.String(), i.Slug+" "+i.Status)
		case (i.Status == StatusStarting || i.Status == StatusRunning) && has && ct.State != "running":
			c.add(ContainerNotRunning, ct.Name, "state "+ct.State)
		case i.Status == StatusAllocated && has:
			c.add(ContainerUnexpected, ct.Name, "instance allocated (step 10 not reached)")
		}
	}
}

func (c *checker) networks() {
	seen := map[uuid.UUID]bool{}
	for _, n := range c.inv.Host.Networks {
		if n.Name == c.inv.Scope.EdgeNetwork {
			continue
		}
		if !c.labelledInScope(n.Labels) && !c.nameInScope(n.Name, networkPrefix) {
			continue
		}
		inst, ok := c.object("network", n.Name, n.Labels, func(i Instance) string { return networkPrefix + i.Slug },
			NetworkUnknown, NetworkOfRemoved, NetworkUnlabelled, NetworkMisnamed)
		if ok {
			seen[inst.ID] = true
		}
	}
	for _, i := range c.instances {
		if serving(i.Status) && !seen[i.ID] {
			c.add(NetworkMissing, i.ID.String(), i.Slug+" "+i.Status)
		}
	}
}

func (c *checker) edge() {
	if c.inv.Scope.Edge == "" {
		return
	}
	attached := map[string]bool{}
	for _, n := range c.inv.Host.EdgeNetworks {
		if n == c.inv.Scope.EdgeNetwork || !c.nameInScope(n, networkPrefix) {
			continue
		}
		attached[n] = true
		inst, ok := c.liveBySlug(strings.TrimPrefix(n, networkPrefix))
		if !ok || (inst.Status != StatusStarting && inst.Status != StatusRunning) {
			c.add(EdgeAttachedOrphan, n, "no starting/running instance of this slug")
		}
	}
	for _, i := range c.instances {
		if i.Status == StatusRunning && !attached[networkPrefix+i.Slug] {
			c.add(EdgeNotAttached, networkPrefix+i.Slug, "instance "+i.ID.String()+" is running")
		}
	}
}

func (c *checker) dirs() {
	if c.inv.Scope.TenantsDir == "" {
		return
	}
	seen := map[uuid.UUID]bool{}
	for _, d := range c.inv.Host.Dirs {
		if strings.HasPrefix(d, ".") {
			// .<id>.creating (interrupted create) or .<id>.removing (interrupted remove — §14.2)
			c.add(DirHidden, d, "")
			continue
		}
		id, err := uuid.Parse(d)
		if err != nil || id.String() != d {
			c.add(DirForeign, d, "")
			continue
		}
		var inst Instance
		var known bool
		for _, i := range c.inv.Registry.Instances { // the directory is the run's: judge it against every instance
			if i.ID == id {
				inst, known = i, true
			}
		}
		switch {
		case !known:
			c.add(DirUnknown, d, "")
		case !live(inst.Status):
			c.add(DirOfRemoved, d, inst.Slug)
		default:
			seen[id] = true
		}
	}
	for _, i := range c.instances {
		if serving(i.Status) && !seen[i.ID] {
			c.add(DirMissing, i.ID.String(), i.Slug+" "+i.Status)
		}
	}
}

func (c *checker) secrets() {
	referenced := map[string]bool{}
	for _, i := range c.instances {
		if live(i.Status) && i.APIKeyRef != "" {
			referenced[i.APIKeyRef] = true
		}
	}
	idps := map[uuid.UUID]bool{}
	for _, p := range c.inv.Registry.IdPs {
		if _, ok := c.tenants[p.TenantID]; !ok {
			continue
		}
		idps[p.ID] = true
		if p.ClientSecretRef != "" {
			referenced[p.ClientSecretRef] = true
		}
	}
	liveRefs := map[string]bool{}
	for _, s := range c.inv.Registry.Secrets {
		if s.Destroyed {
			continue
		}
		liveRefs[s.Ref()] = true
		if s.TenantID == uuid.Nil {
			// pending client secret of an external IdP (idp-pending.<idp_id>.client): step 6 moves it under the tenant and
			// destroys it.
			rest, ok := strings.CutPrefix(s.Name, pendingIdPSecretStart)
			if id, err := uuid.Parse(strings.TrimSuffix(rest, ".client")); ok && err == nil && idps[id] {
				c.add(PendingSecretLeft, s.Ref(), "")
			}
			continue
		}
		if _, ok := c.tenants[s.TenantID]; !ok {
			continue
		}
		switch {
		case referenced[s.Ref()]:
		case s.Name == APIKeySecretName || strings.HasPrefix(s.Name, "idp."):
			c.add(SecretOrphan, s.Ref(), "no registry row references this live version")
		case slices.Contains(c.inv.Scope.AllowSecrets, s.Name):
		default:
			c.add(SecretUnexpected, s.Ref(), "")
		}
	}
	for ref := range referenced {
		if !liveRefs[ref] && strings.Contains(ref, "/"+APIKeySecretName+"#") {
			c.add(SecretMissing, ref, "referenced by a live instance")
		}
	}
}

func (c *checker) keys() {
	byID := map[uuid.UUID]Keys{}
	for _, k := range c.inv.Keys {
		byID[k.InstanceID] = k
	}
	for _, i := range c.instances {
		if i.Status != StatusStarting && i.Status != StatusRunning {
			continue
		}
		k, ok := byID[i.ID]
		if !ok {
			c.add(APIKeyUnchecked, i.ID.String(), i.Slug)
			continue
		}
		if k.ListErr != "" {
			c.add(APIKeyUnlisted, i.ID.String(), k.ListErr)
			continue
		}
		registeredValid := false
		for _, key := range k.Listed {
			if !key.Valid(c.inv.Now) {
				continue
			}
			switch {
			case i.APIKeyPrefix == "":
				c.add(APIKeyUnregistered, i.ID.String(), "prefix "+key.Prefix)
			case key.Prefix != i.APIKeyPrefix:
				c.add(APIKeyExtraValid, i.ID.String(), "prefix "+key.Prefix+" besides "+i.APIKeyPrefix)
			default:
				registeredValid = true
			}
		}
		if i.APIKeyPrefix == "" {
			continue
		}
		if !registeredValid {
			c.add(APIKeyRegisteredGone, i.ID.String(), "prefix "+i.APIKeyPrefix)
		}
		switch {
		case k.StoredErr != "":
			c.add(APIKeySecretUnread, i.ID.String(), k.StoredErr)
		case k.StoredPrefix != i.APIKeyPrefix:
			c.add(APIKeySecretMismatch, i.ID.String(), "stored "+k.StoredPrefix+", registry "+i.APIKeyPrefix)
		}
		if !k.APIOK {
			c.add(APIKeyRejected, i.ID.String(), k.APIErr)
		}
	}
}

// closedTenants: a tenant that ended `failed` (rolled back, or cancelled before it ran) or `deleted` (deprovisioned —
// P3-T09) keeps its rows for audit, but nothing of it may stay usable — no pending invitation, no relay region or
// assignment, no IdP that is not disabled; a deleted tenant also has no live instance and no live Portal session, its
// key destruction is scheduled, and once that time has passed no DEK or secret version of it holds key material.
func (c *checker) closedTenants() {
	state := func(id uuid.UUID) string {
		if t, ok := c.tenants[id]; ok && (t.Status == "failed" || t.Status == "deleted") {
			return t.Status
		}
		return ""
	}
	pick := func(st, failed, deleted string) string {
		if st == "deleted" {
			return deleted
		}
		return failed
	}
	for _, inv := range c.inv.Registry.Invitations {
		if st := state(inv.TenantID); st != "" && inv.Status == "pending" {
			c.add(pick(st, InvitationLeft, InvitationLeftDeleted), inv.ID.String(), "tenant "+c.tenants[inv.TenantID].Slug)
		}
	}
	for _, r := range c.inv.Registry.Relays {
		if st := state(r.TenantID); st != "" {
			c.add(pick(st, RelayLeft, RelayLeftDeleted), r.Kind+" "+r.Name, "tenant "+c.tenants[r.TenantID].Slug)
		}
	}
	for _, p := range c.inv.Registry.IdPs {
		if st := state(p.TenantID); st != "" && p.Status != "disabled" {
			c.add(pick(st, IdPNotDisabled, IdPNotDisabledDeleted), p.ID.String(), p.Status)
		}
	}
	for _, i := range c.instances {
		if state(i.TenantID) == "deleted" && live(i.Status) {
			c.add(InstanceOfDeleted, i.ID.String(), i.Slug+" "+i.Status)
		}
	}
	liveSecrets := map[uuid.UUID]int{}
	for _, s := range c.inv.Registry.Secrets {
		if !s.Destroyed {
			liveSecrets[s.TenantID]++
		}
	}
	for _, t := range c.tenants {
		if t.Status != "deleted" {
			continue
		}
		if t.LiveSessions > 0 {
			c.add(SessionLeft, t.Slug, fmt.Sprintf("%d session(s)", t.LiveSessions))
		}
		switch {
		case t.KeysDestroyAfter == nil:
			c.add(KeysUnscheduled, t.Slug, "")
		case !c.inv.Now.Before(*t.KeysDestroyAfter) && (t.LiveDEKs > 0 || liveSecrets[t.ID] > 0):
			c.add(KeysLeft, t.Slug, fmt.Sprintf("%d DEK(s), %d secret version(s)", t.LiveDEKs, liveSecrets[t.ID]))
		}
	}
}

// Summary counts what an inventory covered (for test logs).
func (inv Inventory) Summary() string {
	live, removed := 0, 0
	for _, i := range inv.Registry.Instances {
		if !inv.Scope.inScope(i.Slug) {
			continue
		}
		if i.Status == StatusRemoved {
			removed++
		} else {
			live++
		}
	}
	secrets, destroyed := 0, 0
	for _, s := range inv.Registry.Secrets {
		if s.Destroyed {
			destroyed++
		} else {
			secrets++
		}
	}
	valid := 0
	for _, k := range inv.Keys {
		for _, key := range k.Listed {
			if key.Valid(inv.Now) {
				valid++
			}
		}
	}
	return fmt.Sprintf("instances live=%d removed=%d; host: containers=%d networks=%d edge_networks=%d dirs=%d; "+
		"secret versions live=%d destroyed=%d; keys checked=%d valid=%d; reconcile findings=%d", live, removed,
		len(inv.Host.Containers), len(inv.Host.Networks), len(inv.Host.EdgeNetworks), len(inv.Host.Dirs), secrets, destroyed,
		len(inv.Keys), valid, len(inv.Reconcile))
}
