// Package store is the only path from the Management Plane to PostgreSQL (§6.1, §8.8 layer 3–4).
//
// A process holds two pools that log in as different roles — the tenant pool as a member of mg_app_tenant
// (mg_api_tenant / mg_worker_tenant) and the platform pool as a member of mg_app_platform (mg_api_platform /
// mg_worker_platform) — so a tenant-pool connection never matches the platform branch of any RLS policy, whatever
// it sets in app.scope. Every query runs inside WithTenantTx (app.scope='tenant' + app.tenant_id, tenant pool) or
// WithPlatformTx (app.scope='platform', app.tenant_id cleared, platform pool); the GUCs are set with
// set_config(…, true) so they end with the transaction. Business modules only ever see *sqlcdb.Queries bound to
// such a transaction: the pools are unexported and internal/archtest forbids database drivers outside this package.
package store

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"

	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// Group roles that carry the RLS policies (§6.1). Every application login role is a member of exactly one.
const (
	GroupTenant   = "mg_app_tenant"
	GroupPlatform = "mg_app_platform"
)

var (
	// ErrNoTenant is returned by WithTenantTx when the tenant ID is the zero UUID.
	ErrNoTenant = errors.New("store: tenant ID is required")
	// ErrNoRows is returned by single-row queries that match nothing (re-exported so modules need no driver import).
	ErrNoRows = pgx.ErrNoRows
)

// Credentials name a login role and the file secret that holds its password (§7.6, §14.2). The password itself
// never appears in configuration, the environment or the URL.
type Credentials struct {
	User         string
	PasswordFile string
}

// Config describes the two pools of one process (api or worker).
type Config struct {
	// URL is a postgres:// URL without user and password, e.g. postgres://postgres:5432/meshguard?sslmode=disable.
	URL      string
	Tenant   Credentials  // a member of mg_app_tenant
	Platform Credentials  // a member of mg_app_platform
	MaxConns int32        // per pool; 0 keeps the pgxpool default
	Logger   *slog.Logger // River's logger (queue.go); nil discards
}

// Store owns the tenant and the platform pool, and the insert-only queue client used by WithTenantJobTx and
// WithPlatformJobTx.
type Store struct {
	tenant   *pgxpool.Pool
	platform *pgxpool.Pool
	cfg      Config
	inserter *river.Client[pgx.Tx]
}

// Open creates both pools and verifies that each logs in as a role of the right group (and neither is a superuser
// nor BYPASSRLS), so swapped or wrong credentials fail at start-up instead of widening a scope at run time.
func Open(ctx context.Context, cfg Config) (*Store, error) {
	tenant, err := newPool(ctx, cfg.URL, cfg.Tenant, cfg.MaxConns)
	if err != nil {
		return nil, fmt.Errorf("store: tenant pool: %w", err)
	}
	platform, err := newPool(ctx, cfg.URL, cfg.Platform, cfg.MaxConns)
	if err != nil {
		tenant.Close()
		return nil, fmt.Errorf("store: platform pool: %w", err)
	}
	s := &Store{tenant: tenant, platform: platform, cfg: cfg}
	if err := checkPoolRole(ctx, tenant, GroupTenant); err != nil {
		s.Close()
		return nil, fmt.Errorf("store: tenant pool: %w", err)
	}
	if err := checkPoolRole(ctx, platform, GroupPlatform); err != nil {
		s.Close()
		return nil, fmt.Errorf("store: platform pool: %w", err)
	}
	if s.inserter, err = newInserter(cfg.Logger); err != nil {
		s.Close()
		return nil, fmt.Errorf("store: queue inserter: %w", err)
	}
	return s, nil
}

// Close closes both pools.
func (s *Store) Close() {
	s.tenant.Close()
	s.platform.Close()
}

// Ping checks both pools; it is the PostgreSQL readiness probe of api and worker.
func (s *Store) Ping(ctx context.Context) error {
	return errors.Join(s.tenant.Ping(ctx), s.platform.Ping(ctx))
}

// WithTenantTx runs fn in a transaction on the tenant pool with app.scope='tenant' and app.tenant_id=tenantID.
// RLS then exposes only that tenant's rows; tables of scope P are not even granted to the tenant roles. The
// transaction commits when fn returns nil and rolls back otherwise. Do not nest calls (each one holds a connection).
func (s *Store) WithTenantTx(ctx context.Context, tenantID uuid.UUID, fn func(q *sqlcdb.Queries) error) error {
	return s.tenantTx(ctx, tenantID, func(tx pgx.Tx) error { return fn(sqlcdb.New(tx)) })
}

// WithPlatformTx runs fn in a transaction on the platform pool with app.scope='platform' and app.tenant_id cleared.
// Tenant-internal tables (scope T) stay invisible: platform staff reach them only through a support grant and
// WithTenantTx (§6.1, §8.7).
func (s *Store) WithPlatformTx(ctx context.Context, fn func(q *sqlcdb.Queries) error) error {
	return s.platformTx(ctx, func(tx pgx.Tx) error { return fn(sqlcdb.New(tx)) })
}

const (
	setTenantScope   = `SELECT set_config('app.scope', 'tenant', true), set_config('app.tenant_id', $1, true)`
	setPlatformScope = `SELECT set_config('app.scope', 'platform', true), set_config('app.tenant_id', '', true)`
)

func (s *Store) tenantTx(ctx context.Context, tenantID uuid.UUID, fn func(pgx.Tx) error) error {
	if tenantID == uuid.Nil {
		return ErrNoTenant
	}
	support, isSupport := SupportActorFrom(ctx)
	return pgx.BeginTxFunc(ctx, s.tenant, pgx.TxOptions{}, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, setTenantScope, tenantID.String()); err != nil {
			return fmt.Errorf("store: set tenant scope: %w", err)
		}
		if isSupport {
			if err := checkSupportGrant(ctx, tx, tenantID, support); err != nil {
				return err
			}
		}
		return fn(tx)
	})
}

// SupportActor is platform staff acting inside a tenant through a Support Access Grant (§8.7, P4-T13): the grant and
// its grantee. The authorization layer puts it in the request context when it grants a request through a grant;
// every WithTenantTx / WithTenantJobTx of that context then re-checks the grant inside the transaction (§6.1 row
// "Platform scope": right tenant, right grantee, approved, within its window — not revoked or expired since layer 1
// decided), before any other statement, and refuses with ErrSupportGrantNotLive (fail closed — IT-17 support case).
type SupportActor struct {
	GrantID        uuid.UUID
	PlatformUserID uuid.UUID
}

type supportKey struct{}

// ErrSupportGrantNotLive: a support actor's transaction whose grant is no longer live (or never was, for this tenant
// and this person) — nothing ran.
var ErrSupportGrantNotLive = errors.New("store: the support access grant of the actor is not live")

// WithSupportActor returns ctx carrying a support actor (a zero grant or person is refused at the first transaction).
func WithSupportActor(ctx context.Context, a SupportActor) context.Context {
	return context.WithValue(ctx, supportKey{}, a)
}

// WithoutSupportActor returns ctx without the support actor: the audit trail's own writes (the record of what the
// actor did, including a refusal after the grant ended) must not depend on the grant.
func WithoutSupportActor(ctx context.Context) context.Context {
	if _, ok := SupportActorFrom(ctx); !ok {
		return ctx
	}
	return context.WithValue(ctx, supportKey{}, nil)
}

// SupportActorFrom returns the support actor of ctx, if any.
func SupportActorFrom(ctx context.Context) (SupportActor, bool) {
	a, ok := ctx.Value(supportKey{}).(SupportActor)
	return a, ok
}

const supportGrantLive = `SELECT EXISTS (SELECT 1 FROM support_access_grants
 WHERE tenant_id = $1 AND id = $2 AND grantee_platform_user_id = $3
   AND status = 'approved' AND starts_at <= now() AND expires_at > now())`

func checkSupportGrant(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID, a SupportActor) error {
	if a.GrantID == uuid.Nil || a.PlatformUserID == uuid.Nil {
		return ErrSupportGrantNotLive
	}
	var live bool
	if err := tx.QueryRow(ctx, supportGrantLive, tenantID, a.GrantID, a.PlatformUserID).Scan(&live); err != nil {
		return fmt.Errorf("store: check support grant: %w", err)
	}
	if !live {
		return ErrSupportGrantNotLive
	}
	return nil
}

func (s *Store) platformTx(ctx context.Context, fn func(pgx.Tx) error) error {
	return pgx.BeginTxFunc(ctx, s.platform, pgx.TxOptions{}, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, setPlatformScope); err != nil {
			return fmt.Errorf("store: set platform scope: %w", err)
		}
		return fn(tx)
	})
}

// SQLState returns the PostgreSQL error code carried by err ("" if none), e.g. 23503 for a foreign-key violation
// (a cross-tenant reference) or 42501 for a missing privilege.
func SQLState(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code
	}
	return ""
}

// SQLConstraint returns the constraint or index named by a PostgreSQL error ("" if none) — for example the partial
// unique index provisioning_jobs_lock_key when a second lifecycle job of a tenant tries to start (§13.5 (d)).
func SQLConstraint(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.ConstraintName
	}
	return ""
}

// newPool builds a pool for one login role. The password is read from the file on every new connection, so a
// rotated secret is picked up without a restart.
func newPool(ctx context.Context, rawURL string, cred Credentials, maxConns int32) (*pgxpool.Pool, error) {
	cfg, err := poolConfig(rawURL, cred)
	if err != nil {
		return nil, err
	}
	if maxConns > 0 {
		cfg.MaxConns = maxConns
	}
	return pgxpool.NewWithConfig(ctx, cfg)
}

func poolConfig(rawURL string, cred Credentials) (*pgxpool.Config, error) {
	if err := checkURL(rawURL); err != nil {
		return nil, err
	}
	if cred.User == "" || cred.PasswordFile == "" {
		return nil, errors.New("a login role and its password file are required")
	}
	cfg, err := pgxpool.ParseConfig(rawURL)
	if err != nil {
		return nil, errors.New("invalid database URL") // pgx errors may echo the URL; keep logs clean
	}
	cfg.ConnConfig.User = cred.User
	cfg.ConnConfig.Password = ""
	cfg.ConnConfig.RuntimeParams["application_name"] = "meshguard/" + cred.User
	file := cred.PasswordFile
	cfg.BeforeConnect = func(_ context.Context, cc *pgx.ConnConfig) error {
		pw, err := ReadPasswordFile(file)
		if err != nil {
			return err
		}
		cc.Password = pw
		return nil
	}
	return cfg, nil
}

// checkURL accepts only postgres:// URLs that carry neither user nor password: credentials come from Credentials.
func checkURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") {
		return errors.New("the database URL must be a postgres:// URL")
	}
	if u.User != nil {
		return errors.New("the database URL must not contain a user or password (use Credentials)")
	}
	q := u.Query()
	for k := range q {
		if k := strings.ToLower(k); k == "user" || k == "password" || k == "passfile" {
			return fmt.Errorf("the database URL must not set %q", k)
		}
	}
	return nil
}

// USAGE = the group's privileges, and so its RLS policies, apply to the role; MEMBER = any membership at all
// (including one that only allows SET ROLE).
const roleQuery = `SELECT current_user::text,
       pg_has_role(current_user, 'mg_app_tenant', 'USAGE'), pg_has_role(current_user, 'mg_app_tenant', 'MEMBER'),
       pg_has_role(current_user, 'mg_app_platform', 'USAGE'), pg_has_role(current_user, 'mg_app_platform', 'MEMBER'),
       r.rolsuper, r.rolbypassrls
FROM pg_roles r WHERE r.rolname = current_user`

// checkPoolRole verifies that the pool's login role inherits group and has no membership of the other application
// group, and that it neither is a superuser nor bypasses RLS.
func checkPoolRole(ctx context.Context, pool *pgxpool.Pool, group string) error {
	var (
		user                        string
		tenantUse, tenantMember     bool
		platformUse, platformMember bool
		superuser, bypassesRLS      bool
	)
	if err := pool.QueryRow(ctx, roleQuery).Scan(&user, &tenantUse, &tenantMember, &platformUse, &platformMember,
		&superuser, &bypassesRLS); err != nil {
		return fmt.Errorf("check login role: %w", err)
	}
	switch {
	case superuser || bypassesRLS:
		return fmt.Errorf("login role %s must be neither superuser nor BYPASSRLS", user)
	case group == GroupTenant && (!tenantUse || platformMember),
		group == GroupPlatform && (!platformUse || tenantMember):
		return fmt.Errorf("login role %s must belong to %s and only to it", user, group)
	}
	return nil
}
