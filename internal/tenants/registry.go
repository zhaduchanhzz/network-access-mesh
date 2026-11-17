package tenants

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// InstanceRecord is what the registry knows of the live instance of a tenant: the input of headscale's Locator
// (§13.4 rule 2: ForTenant loads tenant_instances + the secret). It holds the reference of the API key, never the key.
type InstanceRecord struct {
	TenantID        uuid.UUID
	TenantSlug      string // X-MG-Instance of the edge admin listener (§14.6)
	TenantStatus    string
	InstanceID      uuid.UUID
	Status          string
	APIKeyRef       string // mgsec://<tenant_id>/<name>#<version>; "" when no key is registered yet
	APIKeyPrefix    string // public prefix of that key
	APIKeyExpiresAt *time.Time
}

// LocateInstance reads the live (not removed) instance of a tenant in the TENANT scope of that tenant (tenant pool):
// RLS makes another tenant's row unreachable whatever the arguments, and the query filters on tenant_id as well
// (§8.8 layers 3–5). ErrNotFound when the tenant does not exist or has no live instance.
func (s *Service) LocateInstance(ctx context.Context, tenantID uuid.UUID) (InstanceRecord, error) {
	if tenantID == uuid.Nil {
		return InstanceRecord{}, ErrNotFound
	}
	var out InstanceRecord
	err := s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		t, err := q.GetTenant(ctx, tenantID)
		if errors.Is(err, store.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		i, err := q.GetLiveInstanceForTenant(ctx, tenantID)
		if errors.Is(err, store.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if t.ID != tenantID || i.TenantID != tenantID {
			return fmt.Errorf("tenants: registry returned a row of another tenant for %s", tenantID)
		}
		out = InstanceRecord{TenantID: t.ID, TenantSlug: t.Slug, TenantStatus: t.Status, InstanceID: i.ID,
			Status: i.Status, APIKeyExpiresAt: i.ApiKeyExpiresAt}
		if i.ApiKeySecretRef != nil {
			out.APIKeyRef = *i.ApiKeySecretRef
		}
		if i.ApiKeyPrefix != nil {
			out.APIKeyPrefix = *i.ApiKeyPrefix
		}
		return nil
	})
	return out, err
}

// Identity-provider scopes and drivers (identity_providers, §6.3, §8.2).
const (
	IdPScopePlatform  = "platform"
	IdPScopeTenant    = "tenant"
	IdPDriverKeycloak = "keycloak"
	IdPDriverExternal = "external"
	IdPStatusActive   = "active"
)

// IdPSpec is the registration of an identity provider (§8.2: the triple issuer, client, organisation constraint —
// here a realm-per-tenant issuer, so no required claims). The ID is allocated beforehand (MG_IDP_ID_* — P2-T05: the
// redirect URI registered in the realm carries it).
type IdPSpec struct {
	ID        uuid.UUID
	Scope     string     // IdPScopePlatform or IdPScopeTenant
	TenantID  *uuid.UUID // set ⇔ scope tenant
	Issuer    string
	ClientID  string
	Driver    string // IdPDriverKeycloak or IdPDriverExternal
	DriverRef string // e.g. the Keycloak realm; "" = none
}

// IdP is a registered identity provider (no secret: ClientSecretRef is a reference).
type IdP struct {
	ID              uuid.UUID
	Scope           string
	TenantID        *uuid.UUID
	Issuer          string
	ClientID        string
	Driver          string
	DriverRef       string
	Status          string
	ClientSecretRef string // "" when none
}

// InstanceSpec is the registration of a tenant's Headscale instance (tenant_instances, §6.3).
type InstanceSpec struct {
	ID               uuid.UUID
	HostID           uuid.UUID
	HeadscaleVersion string // as reported by GET /version (v0.29.7)
	ImageDigest      string // sha256:<64 hex>
	ControlHostname  string // <slug>.mesh.<base domain>
	ServerURL        string // https://<control hostname>
	BaseDomain       string // MagicDNS base domain of the tailnet
	InternalAddress  string // hs-<slug>:8080 — what the edge proxies to
	DerpRegionID     *int32
	RunUID           int32
	NetCIDR          netip.Prefix
	DataPath         string
}

// Adoption registers one tenant built by hand in Phase 1 (`meshguard admin adopt-instance`, P2-T11).
type Adoption struct {
	TenantID uuid.UUID
	Slug     string
	Name     string // display name of a new tenant
	Region   string // deployment_region of a new tenant (the host's region)
	Instance InstanceSpec
	IdP      IdPSpec
}

// AdoptionState reports what the registry held before (CheckAdoption) or after (Register) an adoption.
type AdoptionState struct {
	TenantExists   bool // false: Register created it (status provisioning)
	InstanceExists bool // false: Register created it (status starting)
	IdPExists      bool // false: Register created it (status active)
	TenantStatus   string
	InstanceStatus string
	APIKeyRef      string // current reference of the instance API key ("" = none)
	RuntimeUpdated bool   // Register updated headscale_version / image_digest of an existing instance
}

var (
	slugRE   = regexp.MustCompile(`^[a-z][a-z0-9-]{1,30}[a-z0-9]$`) // §11.3 step 1 / §14.5
	digestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// adoptableTenant and adoptableInstance: an adoption (and a key rotation through it) only touches a tenant that is
// being brought up or is serving, and an instance that is starting or running — never a suspended, deleted, removed or
// quarantined one (those need their own lifecycle flow, P3).
var (
	adoptableTenant   = []string{StatusProvisioning, StatusActive}
	adoptableInstance = []string{InstanceStarting, InstanceRunning}
)

// validate checks an adoption; write = false (CheckAdoption) accepts a host that is not registered yet (HostID nil).
func (a Adoption) validate(write bool) error {
	var errs []string
	if a.TenantID == uuid.Nil {
		errs = append(errs, "tenant id")
	}
	if !slugRE.MatchString(a.Slug) || strings.Contains(a.Slug, "--") {
		errs = append(errs, "slug")
	}
	if n := len([]rune(a.Name)); n < 1 || n > 200 {
		errs = append(errs, "name")
	}
	i := a.Instance
	if i.ID == uuid.Nil || (write && i.HostID == uuid.Nil) {
		errs = append(errs, "instance or host id")
	}
	if i.HeadscaleVersion == "" || !digestRE.MatchString(i.ImageDigest) {
		errs = append(errs, "headscale version or image digest")
	}
	if i.ControlHostname == "" || i.ServerURL != "https://"+i.ControlHostname || i.BaseDomain == "" ||
		i.InternalAddress == "" || i.DataPath == "" {
		errs = append(errs, "instance addresses")
	}
	if i.RunUID <= 0 || !i.NetCIDR.IsValid() || i.NetCIDR != i.NetCIDR.Masked() {
		errs = append(errs, "run_uid or net_cidr")
	}
	if err := a.IdP.validate(); err != nil {
		errs = append(errs, "identity provider ("+err.Error()+")")
	} else if a.IdP.Scope != IdPScopeTenant || a.IdP.TenantID == nil || *a.IdP.TenantID != a.TenantID {
		errs = append(errs, "identity provider must be of scope tenant and bound to the tenant")
	}
	if len(errs) > 0 {
		return fmt.Errorf("%w: invalid adoption: %s", ErrInvalid, strings.Join(errs, ", "))
	}
	return nil
}

func (p IdPSpec) validate() error {
	switch {
	case p.ID == uuid.Nil:
		return errors.New("id")
	case p.Scope != IdPScopePlatform && p.Scope != IdPScopeTenant:
		return errors.New("scope")
	case (p.Scope == IdPScopePlatform) != (p.TenantID == nil):
		return errors.New("tenant id ⇔ scope tenant")
	case !strings.HasPrefix(p.Issuer, "https://") || len(p.Issuer) > 512:
		return errors.New("issuer must be an https URL")
	case p.ClientID == "" || len(p.ClientID) > 255:
		return errors.New("client id")
	case p.Driver != IdPDriverKeycloak && p.Driver != IdPDriverExternal:
		return errors.New("driver")
	}
	return nil
}

// CheckAdoption reads the registry and reports what an adoption would find, refusing every contradiction with
// ErrConflict — nothing is written. The admin command runs it before it calls Headscale.
func (s *Service) CheckAdoption(ctx context.Context, a Adoption) (AdoptionState, error) {
	if err := a.validate(false); err != nil {
		return AdoptionState{}, err
	}
	var st AdoptionState
	err := s.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		var err error
		st, err = adopt(ctx, q, a, false)
		return err
	})
	return st, err
}

// Register applies an adoption in ONE platform transaction (all or nothing): a missing tenant is created with status
// provisioning, a missing instance with status starting (Activate moves them to active/running once the API key is
// verified), a missing IdP row with status active; existing rows must match (ErrConflict otherwise) — so running it
// again is a no-op. The version and image of an existing instance are updated when they changed (an observation, not
// an identity field).
func (s *Service) Register(ctx context.Context, a Adoption) (AdoptionState, error) {
	if err := a.validate(true); err != nil {
		return AdoptionState{}, err
	}
	var st AdoptionState
	err := s.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		var err error
		st, err = adopt(ctx, q, a, true)
		return err
	})
	return st, conflictFromDB(err)
}

func adopt(ctx context.Context, q *sqlcdb.Queries, a Adoption, write bool) (AdoptionState, error) {
	var st AdoptionState
	// 1. the tenant
	t, err := q.GetTenant(ctx, a.TenantID)
	switch {
	case errors.Is(err, store.ErrNoRows):
		owner, err := q.GetLiveTenantBySlug(ctx, a.Slug)
		if err == nil {
			return st, fmt.Errorf("%w: slug %s already belongs to tenant %s", ErrConflict, a.Slug, owner.ID)
		}
		if !errors.Is(err, store.ErrNoRows) {
			return st, err
		}
		st.TenantStatus = StatusProvisioning
		if write {
			region := a.Region
			if _, err := q.InsertAdoptedTenant(ctx, sqlcdb.InsertAdoptedTenantParams{ID: a.TenantID, Slug: a.Slug,
				Name: a.Name, Status: StatusProvisioning, DeploymentRegion: optional(region)}); err != nil {
				return st, err
			}
		}
	case err != nil:
		return st, err
	default:
		st.TenantExists, st.TenantStatus = true, t.Status
		if t.Slug != a.Slug {
			return st, fmt.Errorf("%w: tenant %s is registered with slug %s, not %s", ErrConflict, t.ID, t.Slug, a.Slug)
		}
		if !slices.Contains(adoptableTenant, t.Status) {
			return st, fmt.Errorf("%w: tenant %s is %s", ErrConflict, t.ID, t.Status)
		}
	}

	// 2. the instance: one live instance per tenant (§6.3, MVP) — a second instance is never adopted
	if st.TenantExists {
		live, err := q.GetLiveInstanceForTenant(ctx, a.TenantID)
		if err == nil && live.ID != a.Instance.ID {
			return st, fmt.Errorf("%w: tenant %s already has instance %s (%s); a second instance cannot be adopted",
				ErrConflict, a.TenantID, live.ID, live.Status)
		}
		if err != nil && !errors.Is(err, store.ErrNoRows) {
			return st, err
		}
	}
	inst, err := q.GetTenantInstance(ctx, a.Instance.ID)
	switch {
	case errors.Is(err, store.ErrNoRows):
		st.InstanceStatus = InstanceStarting
		if write {
			i := a.Instance
			if _, err := q.CreateTenantInstance(ctx, sqlcdb.CreateTenantInstanceParams{
				ID: i.ID, TenantID: a.TenantID, HostID: i.HostID, Status: InstanceStarting,
				HeadscaleVersion: i.HeadscaleVersion, ImageDigest: i.ImageDigest, ControlHostname: i.ControlHostname,
				ServerUrl: i.ServerURL, BaseDomain: i.BaseDomain, InternalAddress: i.InternalAddress,
				DerpRegionID: i.DerpRegionID, RunUid: i.RunUID, NetCidr: i.NetCIDR, DataPath: i.DataPath,
			}); err != nil {
				return st, err
			}
		}
	case err != nil:
		return st, err
	default:
		st.InstanceExists, st.InstanceStatus = true, inst.Status
		if inst.ApiKeySecretRef != nil {
			st.APIKeyRef = *inst.ApiKeySecretRef
		}
		if inst.TenantID != a.TenantID {
			return st, fmt.Errorf("%w: instance %s belongs to tenant %s", ErrConflict, inst.ID, inst.TenantID)
		}
		if !slices.Contains(adoptableInstance, inst.Status) {
			return st, fmt.Errorf("%w: instance %s is %s", ErrConflict, inst.ID, inst.Status)
		}
		if diff := instanceDiff(inst, a.Instance); len(diff) > 0 {
			return st, fmt.Errorf("%w: instance %s is registered with other values for: %s", ErrConflict, inst.ID,
				strings.Join(diff, ", "))
		}
		if write && (inst.HeadscaleVersion != a.Instance.HeadscaleVersion || inst.ImageDigest != a.Instance.ImageDigest) {
			if _, err := q.SetTenantInstanceRuntime(ctx, sqlcdb.SetTenantInstanceRuntimeParams{
				HeadscaleVersion: a.Instance.HeadscaleVersion, ImageDigest: a.Instance.ImageDigest, ID: inst.ID,
				TenantID: a.TenantID}); err != nil {
				return st, err
			}
			st.RuntimeUpdated = true
		}
	}

	// 3. the identity provider of the tenant
	exists, err := ensureIdP(ctx, q, a.IdP, write)
	st.IdPExists = exists
	return st, err
}

// instanceDiff names the identity fields of a registered instance that differ from the specification.
func instanceDiff(r sqlcdb.TenantInstance, s InstanceSpec) []string {
	var d []string
	check := func(name string, same bool) {
		if !same {
			d = append(d, name)
		}
	}
	check("host_id", r.HostID == s.HostID)
	check("control_hostname", r.ControlHostname == s.ControlHostname)
	check("server_url", r.ServerUrl == s.ServerURL)
	check("base_domain", r.BaseDomain == s.BaseDomain)
	check("internal_address", r.InternalAddress == s.InternalAddress)
	check("run_uid", r.RunUid == s.RunUID)
	check("net_cidr", r.NetCidr == s.NetCIDR)
	check("data_path", r.DataPath == s.DataPath)
	check("derp_region_id", (r.DerpRegionID == nil && s.DerpRegionID == nil) ||
		(r.DerpRegionID != nil && s.DerpRegionID != nil && *r.DerpRegionID == *s.DerpRegionID))
	return d
}

// ensureIdP checks an IdP registration against the registry and, when write is set, inserts it if missing (status
// active). The issuer, client, scope and tenant of a row are immutable (§6.3): a row with the same id and other
// values is a conflict, never an update.
func ensureIdP(ctx context.Context, q *sqlcdb.Queries, p IdPSpec, write bool) (bool, error) {
	row, err := q.GetIdentityProvider(ctx, p.ID)
	switch {
	case err == nil:
		if diff := idpDiff(row, p); len(diff) > 0 {
			return true, fmt.Errorf("%w: identity provider %s is registered with other values for: %s", ErrConflict,
				p.ID, strings.Join(diff, ", "))
		}
		if row.Status != IdPStatusActive {
			return true, fmt.Errorf("%w: identity provider %s is %s", ErrConflict, p.ID, row.Status)
		}
		return true, nil
	case !errors.Is(err, store.ErrNoRows):
		return false, err
	}
	if p.Scope == IdPScopeTenant {
		other, err := q.GetActiveTenantIdentityProvider(ctx, p.TenantID)
		if err == nil {
			return false, fmt.Errorf("%w: tenant %s already has the active identity provider %s", ErrConflict,
				*p.TenantID, other.ID)
		}
		if !errors.Is(err, store.ErrNoRows) {
			return false, err
		}
	} else {
		others, err := q.ListActivePlatformIdPs(ctx)
		if err != nil {
			return false, err
		}
		if len(others) > 0 {
			return false, fmt.Errorf("%w: the platform already has the active identity provider %s", ErrConflict,
				others[0].ID)
		}
	}
	if !write {
		return false, nil
	}
	_, err = q.InsertIdentityProviderWithID(ctx, sqlcdb.InsertIdentityProviderWithIDParams{
		ID: p.ID, Scope: p.Scope, TenantID: p.TenantID, Issuer: p.Issuer, ClientID: p.ClientID, Driver: p.Driver,
		DriverRef: optional(p.DriverRef), Status: IdPStatusActive,
	})
	return false, err
}

func idpDiff(r sqlcdb.IdentityProvider, p IdPSpec) []string {
	var d []string
	if r.Scope != p.Scope {
		d = append(d, "scope")
	}
	if (r.TenantID == nil) != (p.TenantID == nil) || (r.TenantID != nil && *r.TenantID != *p.TenantID) {
		d = append(d, "tenant_id")
	}
	if r.Issuer != p.Issuer {
		d = append(d, "issuer")
	}
	if r.ClientID != p.ClientID {
		d = append(d, "client_id")
	}
	if r.Driver != p.Driver {
		d = append(d, "driver")
	}
	return d
}

// RegisterIdP registers an identity provider on its own (the platform IdP — `meshguard admin register-platform-idp`):
// idempotent, immutable fields checked as in Register. It returns the row and whether it existed before.
func (s *Service) RegisterIdP(ctx context.Context, p IdPSpec) (IdP, bool, error) {
	if err := p.validate(); err != nil {
		return IdP{}, false, fmt.Errorf("%w: invalid identity provider: %s", ErrInvalid, err.Error())
	}
	var (
		out    IdP
		exists bool
	)
	err := s.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		var err error
		if exists, err = ensureIdP(ctx, q, p, true); err != nil {
			return err
		}
		row, err := q.GetIdentityProvider(ctx, p.ID)
		out = idp(row)
		return err
	})
	return out, exists, conflictFromDB(err)
}

// GetIdP reads an identity provider (platform pool).
func (s *Service) GetIdP(ctx context.Context, id uuid.UUID) (IdP, error) {
	var out IdP
	err := s.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		row, err := q.GetIdentityProvider(ctx, id)
		if errors.Is(err, store.ErrNoRows) {
			return ErrNotFound
		}
		out = idp(row)
		return err
	})
	return out, err
}

// SetIdPClientSecretRef records the reference of an IdP's client secret (the value lives in the SecretStore) and
// returns the previous reference ("" = none).
func (s *Service) SetIdPClientSecretRef(ctx context.Context, id uuid.UUID, ref string) (string, error) {
	var prev string
	err := s.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		row, err := q.GetIdentityProvider(ctx, id)
		if errors.Is(err, store.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if row.ClientSecretRef != nil {
			prev = *row.ClientSecretRef
		}
		_, err = q.SetIdentityProviderClientSecretRef(ctx, sqlcdb.SetIdentityProviderClientSecretRefParams{
			ClientSecretRef: &ref, ID: id})
		return err
	})
	return prev, err
}

func idp(r sqlcdb.IdentityProvider) IdP {
	out := IdP{ID: r.ID, Scope: r.Scope, TenantID: r.TenantID, Issuer: r.Issuer, ClientID: r.ClientID,
		Driver: r.Driver, Status: r.Status}
	if r.DriverRef != nil {
		out.DriverRef = *r.DriverRef
	}
	if r.ClientSecretRef != nil {
		out.ClientSecretRef = *r.ClientSecretRef
	}
	return out
}

// APIKey is the reference, public prefix and expiry of an instance API key (tenant_instances.api_key_*).
type APIKey struct {
	Ref       string // mgsec://… — "" clears it
	Prefix    string
	ExpiresAt *time.Time
}

// SetInstanceAPIKey records the API key reference of an instance (platform pool — only the platform roles may update
// tenant_instances) and returns the previous one.
func (s *Service) SetInstanceAPIKey(ctx context.Context, tenantID, instanceID uuid.UUID, k APIKey) (APIKey, error) {
	var prev APIKey
	err := s.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		cur, err := q.GetTenantInstance(ctx, instanceID)
		if errors.Is(err, store.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if cur.TenantID != tenantID {
			return ErrNotFound
		}
		prev = APIKey{Ref: deref(cur.ApiKeySecretRef), Prefix: deref(cur.ApiKeyPrefix), ExpiresAt: cur.ApiKeyExpiresAt}
		_, err = q.SetTenantInstanceAPIKey(ctx, sqlcdb.SetTenantInstanceAPIKeyParams{
			ApiKeySecretRef: optional(k.Ref), ApiKeyPrefix: optional(k.Prefix), ApiKeyExpiresAt: k.ExpiresAt,
			ID: instanceID, TenantID: tenantID})
		return err
	})
	return prev, err
}

// Activation reports the transitions Activate made ("" = already in the target status).
type Activation struct {
	TenantFrom   string
	InstanceFrom string
}

// Activate ends an adoption like step 19 of §11.3: instance starting → running, tenant provisioning → active, in one
// platform transaction. Statuses already at the target are left alone; any other status is ErrConflict.
func (s *Service) Activate(ctx context.Context, tenantID, instanceID uuid.UUID) (Activation, error) {
	var act Activation
	err := s.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		inst, err := q.GetTenantInstance(ctx, instanceID)
		if errors.Is(err, store.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		switch {
		case inst.TenantID != tenantID:
			return ErrNotFound
		case inst.Status == InstanceStarting:
			if _, err := q.TransitionTenantInstanceStatus(ctx, sqlcdb.TransitionTenantInstanceStatusParams{
				Status: InstanceRunning, ID: instanceID, TenantID: tenantID, FromStatus: InstanceStarting}); err != nil {
				return err
			}
			act.InstanceFrom = InstanceStarting
		case inst.Status != InstanceRunning:
			return fmt.Errorf("%w: instance %s is %s", ErrConflict, instanceID, inst.Status)
		}
		t, err := q.GetTenant(ctx, tenantID)
		if err != nil {
			return err
		}
		switch t.Status {
		case StatusProvisioning:
			if _, err := q.TransitionTenantStatus(ctx, sqlcdb.TransitionTenantStatusParams{
				Status: StatusActive, ID: tenantID, FromStatus: StatusProvisioning}); err != nil {
				return err
			}
			act.TenantFrom = StatusProvisioning
		case StatusActive:
		default:
			return fmt.Errorf("%w: tenant %s is %s", ErrConflict, tenantID, t.Status)
		}
		return nil
	})
	return act, err
}

// conflictFromDB turns a unique or foreign-key violation raised by a registration into ErrConflict naming the
// constraint (another tenant already holds that host name, UID, network or issuer/client pair).
func conflictFromDB(err error) error {
	if err == nil || errors.Is(err, ErrConflict) || errors.Is(err, ErrInvalid) {
		return err
	}
	switch store.SQLState(err) {
	case "23505", "23503", "23514":
		return fmt.Errorf("%w: refused by the database (constraint %s)", ErrConflict, store.SQLConstraint(err))
	}
	return err
}

func optional(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}
