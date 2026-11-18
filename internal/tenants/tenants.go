package tenants

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// Tenant statuses (tenants.status, §6.3).
const (
	StatusPending        = "pending"
	StatusProvisioning   = "provisioning"
	StatusActive         = "active"
	StatusSuspended      = "suspended"
	StatusDeprovisioning = "deprovisioning"
	StatusDeleted        = "deleted"
	StatusFailed         = "failed"
)

// TenantStatuses is the set of tenants.status (enum TenantStatus of api/openapi.yaml).
var TenantStatuses = []string{StatusPending, StatusProvisioning, StatusActive, StatusSuspended, StatusDeprovisioning,
	StatusDeleted, StatusFailed}

// Instance statuses (TenantInstanceStatus, §13.3).
const (
	InstanceAllocated   = "allocated"
	InstanceStarting    = "starting"
	InstanceRunning     = "running"
	InstanceStopped     = "stopped"
	InstanceFailed      = "failed"
	InstanceRemoved     = "removed"
	InstanceQuarantined = "quarantined"
)

// InstanceStatuses is the set of tenant_instances.status (enum InstanceStatus of api/openapi.yaml).
var InstanceStatuses = []string{InstanceAllocated, InstanceStarting, InstanceRunning, InstanceStopped, InstanceFailed,
	InstanceRemoved, InstanceQuarantined}

// Page sizes of §13.1 (?limit=50&cursor=…, at most 200).
const (
	DefaultLimit = 50
	MaxLimit     = 200
)

var (
	// ErrNotFound: no such tenant, member or instance in the caller's scope — also another tenant's object
	// (404 not_found, §8.4 invariant 6).
	ErrNotFound = errors.New("tenants: not found")
	// ErrInvalid: a filter, limit or cursor out of range (422 validation_failed), or an invalid registration.
	ErrInvalid = errors.New("tenants: invalid argument")
	// ErrConflict: a registration that contradicts the registry (adopt-instance refuses it, nothing is written).
	ErrConflict = errors.New("tenants: conflict with the registry")
)

// Tenant is the registry view of a tenant (schema Tenant, §13.3) — metadata only, no tenant-internal data.
type Tenant struct {
	ID               uuid.UUID
	Slug             string
	Name             string
	Status           string
	DeploymentRegion string // "" when not set
	ControlURL       string // server_url of the live instance, else https://<slug>.mesh.<base domain>, else ""
	CreatedAt        time.Time
	UpdatedAt        time.Time
	Version          int64 // optimistic-lock counter, source of the ETag
}

// TenantPage is one page of tenants.
type TenantPage struct {
	Items      []Tenant
	NextCursor string // "" on the last page
}

// Member is a membership of a tenant with its identity (schema Membership).
type Member struct {
	ID                uuid.UUID
	TenantID          uuid.UUID
	IdentityID        uuid.UUID
	DisplayName       string // display name, else e-mail, else the IdP subject
	Email             string // "" when unknown
	Role              string // roles.key
	Status            string
	HeadscaleUsername string // mg-<membership_uuid>
	Version           int64
	CreatedAt         time.Time
	// Offboarding is the two-phase state of the offboarding (P4-T09, T-17): the latest member.offboard job of the
	// membership; nil when it was never offboarded.
	Offboarding *Offboarding
}

// Membership statuses (CHECK of 0024 — P4-T09).
const (
	MemberActive     = "active"
	MemberLocked     = "locked"
	MemberOffboarded = "offboarded"
)

// MemberStatuses is the set of tenant_memberships.status (enum MembershipStatus of api/openapi.yaml).
var MemberStatuses = []string{MemberActive, MemberLocked, MemberOffboarded}

// Offboarding states (schema MembershipOffboarding): pending until the member.offboard job verified the nodes, the
// pre-auth keys and the IdP account; applied when it did; failed when the job ended without doing so (DELETE again
// retries it).
const (
	OffboardPending = "pending"
	OffboardApplied = "applied"
	OffboardFailed  = "failed"
)

// Offboarding is the state of the offboarding of a membership and its job.
type Offboarding struct {
	State string
	JobID uuid.UUID
}

// OffboardState maps the status of a member.offboard job to the offboarding state.
func OffboardState(jobStatus string) string {
	switch jobStatus {
	case "succeeded":
		return OffboardApplied
	case "failed", "cancelled", "rolled_back":
		return OffboardFailed
	}
	return OffboardPending
}

// MemberPage is one page of members.
type MemberPage struct {
	Items      []Member
	NextCursor string
}

// Page selects one page of a list.
type Page struct {
	Limit  int    // 0 ⇒ DefaultLimit; 1…MaxLimit
	Cursor string // next_cursor of the previous page
}

// MemberFilter holds the query parameters of GET /tenants/{t}/users.
type MemberFilter struct {
	Page
	Role   string // roles.key
	Status string // tenant_memberships.status
	Query  string // part of the display name or e-mail
}

// RegistryFilter holds the query parameters of GET /platform/tenants.
type RegistryFilter struct {
	Page
	Status string // one of TenantStatuses
	Query  string // part of the slug or name
}

// Options configures a Service.
type Options struct {
	// BaseDomain (MG_BASE_DOMAIN) gives the control URL https://<slug>.mesh.<BaseDomain> of a tenant that has no live
	// instance yet; a tenant with an instance reports the instance's registered server_url.
	BaseDomain string
	// Notifier delivers invitations (P3-T05b); nil ⇒ OutboxNotifier (notification_outbox kind tenant.invitation).
	Notifier InvitationNotifier
	// Now is the clock of the invitations; nil ⇒ time.Now.
	Now func() time.Time
}

// Service reads (and, for the admin commands, writes) the Tenant Registry, and manages invitations (P3-T05a).
type Service struct {
	st       *store.Store
	base     string
	notifier InvitationNotifier
	now      func() time.Time
}

// New returns the registry service on st (the process's two pools).
func New(st *store.Store, o Options) *Service {
	s := &Service{st: st, base: strings.ToLower(strings.TrimSpace(o.BaseDomain)), notifier: o.Notifier, now: o.Now}
	if s.notifier == nil {
		s.notifier = OutboxNotifier{}
	}
	if s.now == nil {
		s.now = time.Now
	}
	return s
}

var (
	roleKeyRE = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	statusRE  = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
)

const maxQuery = 64

// GetTenant is GET /tenants/{tenantId}: the tenant of the path, read in its own scope (tenant pool, RLS) — a tenant
// that does not exist reads the same as another tenant's (ErrNotFound).
func (s *Service) GetTenant(ctx context.Context, tenantID uuid.UUID) (Tenant, error) {
	var out Tenant
	err := s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		var err error
		out, err = s.getView(ctx, q, tenantID)
		return err
	})
	return out, err
}

// GetRegistry is GET /platform/tenants/{tenantId}: registry metadata of any tenant (platform pool).
func (s *Service) GetRegistry(ctx context.Context, tenantID uuid.UUID) (Tenant, error) {
	var out Tenant
	err := s.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		var err error
		out, err = s.getView(ctx, q, tenantID)
		return err
	})
	return out, err
}

func (s *Service) getView(ctx context.Context, q *sqlcdb.Queries, tenantID uuid.UUID) (Tenant, error) {
	if tenantID == uuid.Nil {
		return Tenant{}, ErrNotFound
	}
	row, err := q.GetTenantView(ctx, tenantID)
	if errors.Is(err, store.ErrNoRows) {
		return Tenant{}, ErrNotFound
	}
	if err != nil {
		return Tenant{}, err
	}
	if row.Tenant.ID != tenantID { // layer 2 of §8.8: the object must be the tenant of the path
		return Tenant{}, ErrNotFound
	}
	return s.tenant(row.Tenant, row.ControlUrl), nil
}

// ListMemberTenants is GET /tenants: the tenants where the identity holds an active membership. An identity of scope
// tenant belongs to exactly one tenant (its IdP's — §8.2), so the query runs in that tenant's scope; identities of
// scope platform are members of no tenant (staff reach tenants through Support Access Grants — P4-T13) and get an
// empty list from the caller without a query.
func (s *Service) ListMemberTenants(ctx context.Context, identityID, identityTenant uuid.UUID, p Page) (TenantPage, error) {
	limit, after, afterID, err := p.params()
	if err != nil {
		return TenantPage{}, err
	}
	if identityID == uuid.Nil || identityTenant == uuid.Nil {
		return TenantPage{Items: []Tenant{}}, nil
	}
	var out TenantPage
	err = s.st.WithTenantTx(ctx, identityTenant, func(q *sqlcdb.Queries) error {
		rows, err := q.ListMemberTenantsPage(ctx, sqlcdb.ListMemberTenantsPageParams{
			IdentityID: identityID, AfterCreatedAt: after, AfterID: afterID, RowLimit: int32(limit + 1), //nolint:gosec // ≤ MaxLimit+1
		})
		if err != nil {
			return err
		}
		out = TenantPage{Items: make([]Tenant, 0, min(len(rows), limit))}
		for i, r := range rows {
			if i == limit {
				last := out.Items[limit-1]
				out.NextCursor = encodeCursor(last.CreatedAt, last.ID)
				break
			}
			if r.Tenant.ID != identityTenant { // issuer binding (§8.4 invariant 1): only the identity's own tenant
				return fmt.Errorf("tenants: membership of identity %s in tenant %s outside its IdP's tenant", identityID,
					r.Tenant.ID)
			}
			out.Items = append(out.Items, s.tenant(r.Tenant, r.ControlUrl))
		}
		return nil
	})
	return out, err
}

// ListRegistry is GET /platform/tenants: registry metadata of every tenant (platform pool), ordered by creation.
func (s *Service) ListRegistry(ctx context.Context, f RegistryFilter) (TenantPage, error) {
	limit, after, afterID, err := f.params()
	if err != nil {
		return TenantPage{}, err
	}
	p := sqlcdb.ListRegistryTenantsPageParams{AfterCreatedAt: after, AfterID: afterID, RowLimit: int32(limit + 1)} //nolint:gosec // ≤ MaxLimit+1
	if f.Status != "" {
		if !slices.Contains(TenantStatuses, f.Status) {
			return TenantPage{}, fmt.Errorf("%w: unknown tenant status", ErrInvalid)
		}
		p.Status = &f.Status
	}
	if f.Query != "" {
		pat, err := likePattern(f.Query)
		if err != nil {
			return TenantPage{}, err
		}
		p.Pattern = &pat
	}
	var out TenantPage
	err = s.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		rows, err := q.ListRegistryTenantsPage(ctx, p)
		if err != nil {
			return err
		}
		out = TenantPage{Items: make([]Tenant, 0, min(len(rows), limit))}
		for i, r := range rows {
			if i == limit {
				last := out.Items[limit-1]
				out.NextCursor = encodeCursor(last.CreatedAt, last.ID)
				break
			}
			out.Items = append(out.Items, s.tenant(r.Tenant, r.ControlUrl))
		}
		return nil
	})
	return out, err
}

// ListMembers is GET /tenants/{tenantId}/users: memberships of the tenant of the path (tenant pool, RLS + filter).
func (s *Service) ListMembers(ctx context.Context, tenantID uuid.UUID, f MemberFilter) (MemberPage, error) {
	limit, after, afterID, err := f.params()
	if err != nil {
		return MemberPage{}, err
	}
	p := sqlcdb.ListTenantMembersPageParams{TenantID: tenantID, AfterCreatedAt: after, AfterID: afterID,
		RowLimit: int32(limit + 1)} //nolint:gosec // ≤ MaxLimit+1
	if f.Role != "" {
		if !roleKeyRE.MatchString(f.Role) {
			return MemberPage{}, fmt.Errorf("%w: invalid role key", ErrInvalid)
		}
		p.RoleKey = &f.Role
	}
	if f.Status != "" {
		if !statusRE.MatchString(f.Status) {
			return MemberPage{}, fmt.Errorf("%w: invalid membership status", ErrInvalid)
		}
		p.Status = &f.Status
	}
	if f.Query != "" {
		pat, err := likePattern(f.Query)
		if err != nil {
			return MemberPage{}, err
		}
		p.Pattern = &pat
	}
	if tenantID == uuid.Nil {
		return MemberPage{}, ErrNotFound
	}
	var out MemberPage
	err = s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		rows, err := q.ListTenantMembersPage(ctx, p)
		if err != nil {
			return err
		}
		out = MemberPage{Items: make([]Member, 0, min(len(rows), limit))}
		for i, r := range rows {
			if i == limit {
				last := out.Items[limit-1]
				out.NextCursor = encodeCursor(last.CreatedAt, last.ID)
				break
			}
			if r.TenantID != tenantID { // defence in depth: RLS and the WHERE clause already exclude it
				return fmt.Errorf("tenants: membership %s of another tenant in the page of %s", r.ID, tenantID)
			}
			out.Items = append(out.Items, member(sqlcdb.GetTenantMemberRow(r)))
		}
		return nil
	})
	return out, err
}

// GetMember is GET /tenants/{tenantId}/users/{membershipId}: a membership of another tenant is ErrNotFound.
func (s *Service) GetMember(ctx context.Context, tenantID, membershipID uuid.UUID) (Member, error) {
	if tenantID == uuid.Nil || membershipID == uuid.Nil {
		return Member{}, ErrNotFound
	}
	var out Member
	err := s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		r, err := q.GetTenantMember(ctx, sqlcdb.GetTenantMemberParams{TenantID: tenantID, ID: membershipID})
		if errors.Is(err, store.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if r.TenantID != tenantID || r.ID != membershipID {
			return ErrNotFound
		}
		out = member(r)
		return nil
	})
	return out, err
}

// tenant maps a row to the registry view.
func (s *Service) tenant(t sqlcdb.Tenant, serverURL *string) Tenant {
	out := Tenant{ID: t.ID, Slug: t.Slug, Name: t.Name, Status: t.Status, CreatedAt: t.CreatedAt.UTC(),
		UpdatedAt: t.UpdatedAt.UTC(), Version: t.Version}
	if t.DeploymentRegion != nil {
		out.DeploymentRegion = *t.DeploymentRegion
	}
	switch {
	case serverURL != nil && *serverURL != "":
		out.ControlURL = *serverURL
	case s.base != "":
		out.ControlURL = ControlURL(t.Slug, s.base)
	}
	return out
}

// ControlURL is the login server of a tenant's tailnet: https://<slug>.mesh.<base domain> (§15.4, render_instance.py).
func ControlURL(slug, baseDomain string) string {
	return "https://" + ControlHostname(slug, baseDomain)
}

// ControlHostname is <slug>.mesh.<base domain>: the public control-plane host name of the tenant (§15.4).
func ControlHostname(slug, baseDomain string) string { return slug + ".mesh." + baseDomain }

// MagicDNSDomain is <slug>.tail.<base domain>: the MagicDNS base domain of the tenant's tailnet (config.yaml
// dns.base_domain rendered by tools/render_instance.py).
func MagicDNSDomain(slug, baseDomain string) string { return slug + ".tail." + baseDomain }

func member(r sqlcdb.GetTenantMemberRow) Member {
	m := Member{ID: r.ID, TenantID: r.TenantID, IdentityID: r.IdentityID, Role: r.RoleKey, Status: r.Status,
		HeadscaleUsername: r.HeadscaleUsername, Version: r.Version, CreatedAt: r.CreatedAt.UTC()}
	if id, err := uuid.Parse(r.OffboardJobID); err == nil {
		m.Offboarding = &Offboarding{State: OffboardState(r.OffboardJobStatus), JobID: id}
	}
	if r.Email != nil {
		m.Email = *r.Email
	}
	switch {
	case r.DisplayName != nil && strings.TrimSpace(*r.DisplayName) != "":
		m.DisplayName = *r.DisplayName
	case m.Email != "":
		m.DisplayName = m.Email
	default:
		m.DisplayName = r.Subject
	}
	return m
}

// params validates the page and returns the limit and the decoded cursor.
func (p Page) params() (int, *time.Time, *uuid.UUID, error) {
	limit := p.Limit
	if limit == 0 {
		limit = DefaultLimit
	}
	if limit < 1 || limit > MaxLimit {
		return 0, nil, nil, fmt.Errorf("%w: limit must be 1–%d", ErrInvalid, MaxLimit)
	}
	if p.Cursor == "" {
		return limit, nil, nil, nil
	}
	t, id, err := decodeCursor(p.Cursor)
	if err != nil {
		return 0, nil, nil, err
	}
	return limit, &t, &id, nil
}

// likePattern turns a search term into an ILIKE pattern matching it anywhere, with LIKE's metacharacters escaped
// (the default escape character of LIKE is the backslash).
func likePattern(q string) (string, error) {
	if q == "" || len([]rune(q)) > maxQuery {
		return "", fmt.Errorf("%w: q must hold 1–%d characters", ErrInvalid, maxQuery)
	}
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return "%" + r.Replace(q) + "%", nil
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
