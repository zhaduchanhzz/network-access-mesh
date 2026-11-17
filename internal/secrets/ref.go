package secrets

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

// Scope is the DEK series a secret is encrypted under (tenant_keys.scope, §6.3).
type Scope string

const (
	// ScopeTenant: one versioned DEK per tenant, wrapped by kek-app.
	ScopeTenant Scope = "tenant"
	// ScopePlatform: platform secrets the api needs while serving requests (e.g. the client secret of the platform
	// IdP); wrapped by kek-app.
	ScopePlatform Scope = "platform"
	// ScopePlatformOps: platform secrets only the worker uses (IdP admin credentials, SMTP password); wrapped by
	// kek-ops, which is mounted into the worker only, and hidden from the mg_api_* roles by RLS (§6.1, §7.6).
	ScopePlatformOps Scope = "platform_ops"
)

// Owner names one DEK series: a tenant, the platform, or platform_ops.
type Owner struct {
	Scope  Scope
	Tenant uuid.UUID // set only for ScopeTenant
}

// TenantOwner is the DEK series of tenant id.
func TenantOwner(id uuid.UUID) Owner { return Owner{Scope: ScopeTenant, Tenant: id} }

var (
	// PlatformOwner is the DEK series of scope platform.
	PlatformOwner = Owner{Scope: ScopePlatform}
	// PlatformOpsOwner is the DEK series of scope platform_ops (worker only).
	PlatformOpsOwner = Owner{Scope: ScopePlatformOps}
)

func (o Owner) validate() error {
	switch o.Scope {
	case ScopeTenant:
		if o.Tenant == uuid.Nil {
			return fmt.Errorf("%w: a tenant owner needs a tenant ID", ErrInvalid)
		}
	case ScopePlatform, ScopePlatformOps:
		if o.Tenant != uuid.Nil {
			return fmt.Errorf("%w: a platform owner has no tenant ID", ErrInvalid)
		}
	default:
		return fmt.Errorf("%w: unknown scope", ErrInvalid)
	}
	return nil
}

// String is "tenant/<uuid>", "platform" or "platform_ops" (for logs and errors).
func (o Owner) String() string {
	if o.Scope == ScopeTenant {
		return "tenant/" + o.Tenant.String()
	}
	return string(o.Scope)
}

// tenantPtr is the tenant_id column of the owner's rows (NULL for the platform scopes).
func (o Owner) tenantPtr() *uuid.UUID {
	if o.Scope != ScopeTenant {
		return nil
	}
	id := o.Tenant
	return &id
}

// RefPrefix starts every secret reference.
const RefPrefix = "mgsec://"

const platformSegment = "platform"

// nameRE is the CHECK of secrets.name (0003).
var nameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,127}$`)

// Ref is a secret reference mgsec://<tenant_id|platform>/<name>#<version> (§6.1): the only form in which business
// tables hold a secret. Tenant is uuid.Nil for platform secrets (scope platform or platform_ops — the reference does
// not say which; the stored row does). A reference is not secret and may be logged.
type Ref struct {
	Tenant  uuid.UUID
	Name    string
	Version int32
}

// TenantRef returns the reference of version v of tenant's secret name.
func TenantRef(tenant uuid.UUID, name string, v int32) Ref {
	return Ref{Tenant: tenant, Name: name, Version: v}
}

// PlatformRef returns the reference of version v of the platform secret name.
func PlatformRef(name string, v int32) Ref { return Ref{Name: name, Version: v} }

// IsPlatform reports whether r names a platform secret.
func (r Ref) IsPlatform() bool { return r.Tenant == uuid.Nil }

func (r Ref) ownerSegment() string {
	if r.IsPlatform() {
		return platformSegment
	}
	return r.Tenant.String()
}

// String returns the canonical form mgsec://<tenant_id|platform>/<name>#<version>.
func (r Ref) String() string {
	return RefPrefix + r.ownerSegment() + "/" + r.Name + "#" + strconv.FormatInt(int64(r.Version), 10)
}

// Validate checks the name against the column CHECK of 0003 and that the version is positive. Its errors never
// repeat the reference, in case a caller passed a secret value by mistake.
func (r Ref) Validate() error {
	if !nameRE.MatchString(r.Name) {
		return fmt.Errorf("%w: secret name must match %s", ErrInvalid, nameRE)
	}
	if r.Version < 1 {
		return fmt.Errorf("%w: secret version must be ≥ 1", ErrInvalid)
	}
	return nil
}

// ParseRef parses the canonical form only: a lower-case hyphenated tenant UUID (never the nil UUID) or "platform",
// a name matching the column CHECK, and a decimal version without sign or leading zero. Errors never repeat the input.
func ParseRef(s string) (Ref, error) {
	bad := func(why string) (Ref, error) {
		return Ref{}, fmt.Errorf("%w: secret reference: %s", ErrInvalid, why)
	}
	rest, ok := strings.CutPrefix(s, RefPrefix)
	if !ok {
		return bad("must start with " + RefPrefix)
	}
	owner, rest, ok := strings.Cut(rest, "/")
	if !ok {
		return bad("missing /<name>")
	}
	name, ver, ok := strings.Cut(rest, "#")
	if !ok {
		return bad("missing #<version>")
	}
	var r Ref
	if owner != platformSegment {
		id, err := uuid.Parse(owner)
		if err != nil || id == uuid.Nil || id.String() != owner {
			return bad(`owner must be "platform" or a canonical tenant UUID`)
		}
		r.Tenant = id
	}
	v, ok := parseVersion(ver)
	if !ok {
		return bad("version must be a decimal integer in 1…2147483647 without leading zeros")
	}
	r.Name, r.Version = name, v
	if err := r.Validate(); err != nil {
		return Ref{}, err
	}
	return r, nil
}

func parseVersion(s string) (int32, bool) {
	if s == "" || len(s) > 10 || s[0] == '0' {
		return 0, false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
	}
	v, err := strconv.ParseInt(s, 10, 32) // bitSize 32: v fits in an int32
	if err != nil || v < 1 {
		return 0, false
	}
	return int32(v), true
}
