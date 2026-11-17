package idp

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/secrets"
)

// Driver names: the values of identity_providers.driver (CHECK of migration 0002).
const (
	DriverKeycloak = "keycloak"
	DriverExternal = "external"
)

// Scope is identity_providers.scope.
type Scope string

// Scopes of an IdP registration.
const (
	ScopePlatform Scope = "platform"
	ScopeTenant   Scope = "tenant"
)

// Registration is the part of an identity_providers row a driver works on (§6.3). An IdP registration is the
// triple (issuer, client_id, organisation constraint); issuer, scope and tenant are immutable (§8.2).
type Registration struct {
	IdPID    uuid.UUID // identity_providers.id: part of the redirect URI /api/v1/auth/callback/<IdPID> (§8.3)
	Scope    Scope
	TenantID uuid.UUID // uuid.Nil for the platform scope
	Driver   string
	Issuer   string
	ClientID string
	// ClientSecretRef is identity_providers.client_secret_ref (mgsec://…); "" for a public client.
	ClientSecretRef string
	// DriverRef is identity_providers.driver_ref: the driver's own handle (keycloak: realm and the reference of the
	// per-realm service-account secret). Opaque to callers.
	DriverRef string
}

// Validate checks the scope/tenant pairing (CHECK (scope='platform') = (tenant_id IS NULL)) and the IdP id.
func (r Registration) Validate(op string) error {
	switch {
	case r.IdPID == uuid.Nil:
		return NewError(CodeInvalidArgument, op, "idp_id_missing", nil)
	case r.Scope == ScopePlatform && r.TenantID != uuid.Nil, r.Scope == ScopeTenant && r.TenantID == uuid.Nil:
		return NewError(CodeInvalidArgument, op, "scope_tenant_mismatch", nil)
	case r.Scope != ScopePlatform && r.Scope != ScopeTenant:
		return NewError(CodeInvalidArgument, op, "scope_invalid", nil)
	}
	return nil
}

// ClientSecretOwner returns the SecretStore reference of version v of the client secret of r: a tenant secret for a
// tenant IdP, a platform secret (DEK platform — the api reads it for the token request) for the platform IdP.
func (r Registration) ClientSecretOwner(v int32) secrets.Ref {
	name := "idp." + r.IdPID.String() + ".client"
	if r.Scope == ScopePlatform {
		return secrets.PlatformRef(name, v)
	}
	return secrets.TenantRef(r.TenantID, name, v)
}

// IssuerSpec asks a driver to make the issuer of a registration exist in the desired state.
type IssuerSpec struct {
	Registration
	// Realm is the Keycloak realm to create or reconcile (keycloak only; ignored when DriverRef names one).
	Realm string
	// DisplayName is shown on the login pages (keycloak only); "" uses the realm name ("Platform" for the platform).
	DisplayName string
}

// IssuerResult is the outcome of EnsureIssuer.
type IssuerResult struct {
	Issuer    string   // identity_providers.issuer (immutable once stored)
	DriverRef string   // identity_providers.driver_ref
	Created   bool     // the issuer did not exist and was created
	Changes   []string // settings the driver corrected (drift repaired), in a stable order
	Unmanaged []string // objects found at the IdP that the driver does not manage (reported, not touched)
}

// ClientSpec asks a driver to make the OIDC client of a registration exist in the desired state.
type ClientSpec struct {
	Registration
	// ClientSecret is the secret supplied by the tenant (external only); nil for a public client or for keycloak (the
	// driver generates the secret). Never logged.
	ClientSecret secrets.Plaintext
}

// ClientResult is the outcome of EnsureClient.
type ClientResult struct {
	ClientID        string
	ClientSecretRef string   // "" for a public client
	Created         bool     // the client did not exist and was created
	SecretRotated   bool     // a new secret version was written (the row must take ClientSecretRef)
	Changes         []string // settings the driver corrected
}

// Invite describes a user to create at a platform-hosted IdP (§8.2 Khởi tạo ban đầu, tenant_invitations).
type Invite struct {
	Email     string
	FirstName string
	LastName  string
	// Actions are the required actions of the new user; nil = VERIFY_EMAIL, UPDATE_PASSWORD, CONFIGURE_TOTP.
	Actions []string
	// SendEmail asks the IdP to e-mail the required-actions link (needs SMTP at the IdP).
	SendEmail bool
	// LinkLifespan is the validity of the e-mailed link; 0 uses the realm default.
	LinkLifespan time.Duration
}

// InviteResult is the outcome of InviteUser.
type InviteResult struct {
	Subject   string // the user's id at the IdP = the sub claim of its tokens
	Created   bool
	EmailSent bool
}

// DisableResult is the outcome of DisableUser.
type DisableResult struct {
	Subject         string
	Found           bool // false: no such user at the IdP (nothing to disable — idempotent success)
	AlreadyDisabled bool
	SessionsRevoked bool
}

// RemoveMode selects what RemoveIssuer does.
type RemoveMode string

// Remove modes: Disable keeps the issuer (and its users) but refuses every login and token — the state of a suspended
// or deprovisioning tenant; Purge deletes it for good (tenant deletion after the grace period, §11.4).
const (
	RemoveDisable RemoveMode = "disable"
	RemovePurge   RemoveMode = "purge"
)

// RemoveResult is the outcome of RemoveIssuer.
type RemoveResult struct {
	Mode          RemoveMode
	AlreadyAbsent bool // the issuer no longer existed (purge) or does not exist (disable)
	Changed       bool // the call changed the IdP
}

// Discovery is the checked discovery document of an issuer (OpenID Connect Discovery 1.0).
type Discovery struct {
	Issuer                string
	AuthorizationEndpoint string
	TokenEndpoint         string
	JWKSURI               string
	UserinfoEndpoint      string
	EndSessionEndpoint    string
	CodeChallengeMethods  []string
	IssParameterSupported bool // authorization_response_iss_parameter_supported (RFC 9207)
	SigningKeys           int  // usable signature keys in the JWKS
}

// IdPDriver is the IdP driver of §8.2 (step idp.ensure of the orchestrator, member invitation and offboarding). No
// business code depends on Keycloak: callers hold an IdPDriver chosen by identity_providers.driver. Every method is
// idempotent: calling it again with the same input converges to the same state without duplicates.
type IdPDriver interface {
	// Name is the identity_providers.driver value of the driver.
	Name() string
	// EnsureIssuer makes the issuer exist and conform (keycloak: realm from the template, drift repaired; external:
	// the tenant-supplied issuer is checked through the hardened client).
	EnsureIssuer(ctx context.Context, spec IssuerSpec) (IssuerResult, error)
	// EnsureClient makes the Portal client exist and conform and its secret be in the SecretStore.
	EnsureClient(ctx context.Context, spec ClientSpec) (ClientResult, error)
	// InviteUser creates (or finds) a user at the IdP and optionally e-mails its required actions.
	InviteUser(ctx context.Context, reg Registration, inv Invite) (InviteResult, error)
	// DisableUser disables a user at the IdP and revokes its IdP sessions (offboarding, §8.2 Vòng đời danh tính).
	DisableUser(ctx context.Context, reg Registration, subject string) (DisableResult, error)
	// RemoveIssuer disables or purges the issuer (and destroys the secrets the driver owns on purge).
	RemoveIssuer(ctx context.Context, reg Registration, mode RemoveMode) (RemoveResult, error)
	// CheckDiscovery fetches and checks the discovery document and the JWKS of the stored issuer: the issuer of the
	// document must equal the stored issuer and every endpoint must pass the driver's URL rules.
	CheckDiscovery(ctx context.Context, reg Registration) (Discovery, error)
}

// Registry selects a driver by identity_providers.driver.
type Registry struct {
	drivers map[string]IdPDriver
}

// NewRegistry returns a registry of the given drivers. Names must be distinct and one of the values the database
// accepts (keycloak, external).
func NewRegistry(drivers ...IdPDriver) (*Registry, error) {
	r := &Registry{drivers: map[string]IdPDriver{}}
	for _, d := range drivers {
		if d == nil {
			return nil, fmt.Errorf("idp: nil driver")
		}
		n := d.Name()
		if n != DriverKeycloak && n != DriverExternal {
			return nil, fmt.Errorf("idp: unknown driver name %q (identity_providers.driver accepts keycloak, external)", n)
		}
		if _, dup := r.drivers[n]; dup {
			return nil, fmt.Errorf("idp: driver %q registered twice", n)
		}
		r.drivers[n] = d
	}
	return r, nil
}

// Driver returns the driver registered under name.
func (r *Registry) Driver(name string) (IdPDriver, error) {
	if d, ok := r.drivers[name]; ok {
		return d, nil
	}
	return nil, NewError(CodeUnknownDriver, "registry", "", nil)
}

// For returns the driver of a registration (reg.Driver).
func (r *Registry) For(reg Registration) (IdPDriver, error) { return r.Driver(reg.Driver) }

// Names lists the registered drivers, sorted.
func (r *Registry) Names() []string {
	out := make([]string, 0, len(r.drivers))
	for n := range r.drivers {
		out = append(out, n)
	}
	slices.Sort(out)
	return out
}
