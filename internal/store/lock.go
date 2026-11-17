package store

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// lockNameRE bounds the names of tenant locks (they become part of the advisory-lock key).
var lockNameRE = regexp.MustCompile(`^[a-z][a-z0-9_.]{0,31}$`)

// TenantLockKey is the text hashed into the advisory-lock key of WithTenantLock (exported for tests and diagnostics).
func TenantLockKey(tenantID uuid.UUID, name string) string {
	return "meshguard:tenant:" + tenantID.String() + ":" + name
}

// WithTenantLock serialises fn with every other holder of the same (tenant, name) lock, in every process connected to
// the database — the per-tenant advisory lock of §7.2 ("ghi policy được tuần tự hóa theo tenant"): SetPolicy is
// last-write-wins on Headscale, so two applications of one tenant must never interleave.
//
// It opens a DEDICATED connection with the tenant pool's login role (not a pool connection: holders waiting for the
// lock must never exhaust the pool that fn needs for its own transactions), begins a transaction with scope tenant,
// takes pg_advisory_xact_lock(hashtextextended(TenantLockKey(tenantID, name), 0)) — waiting at most wait (lock_timeout
// of the lock transaction; 0 = until ctx ends) —, runs fn, then rolls the lock transaction back and closes the
// connection, which releases the lock. The lock transaction does nothing else: it holds no row lock and writes nothing,
// so it blocks only other holders of the same key; fn opens its own transactions (WithTenantTx, WithTenantJobTx). A
// crash, a cancelled ctx or a dropped connection ends the transaction and releases the lock with it. fn may call Agent
// or Headscale while the lock is held: that is the purpose of the lock (policy application), unlike the lifecycle lock
// of §13.5 (d), which never holds a transaction across such calls.
//
// Two different keys may hash to the same lock: they are then serialised with each other, which is safe.
func (s *Store) WithTenantLock(ctx context.Context, tenantID uuid.UUID, name string, wait time.Duration,
	fn func(ctx context.Context) error,
) error {
	if tenantID == uuid.Nil {
		return ErrNoTenant
	}
	if !lockNameRE.MatchString(name) {
		return fmt.Errorf("store: invalid tenant lock name %q", name)
	}
	if fn == nil {
		return errors.New("store: WithTenantLock: no function")
	}
	pc := s.tenant.Config()
	cc := pc.ConnConfig.Copy()
	if pc.BeforeConnect != nil {
		if err := pc.BeforeConnect(ctx, cc); err != nil { // reads the password file, like the pool
			return fmt.Errorf("store: tenant lock: %w", err)
		}
	}
	conn, err := pgx.ConnectConfig(ctx, cc)
	if err != nil {
		return fmt.Errorf("store: tenant lock: connect: %w", err)
	}
	defer func() { _ = conn.Close(context.WithoutCancel(ctx)) }() // also releases the lock
	tx, err := conn.Begin(ctx)
	if err != nil {
		return fmt.Errorf("store: tenant lock: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }() // nothing to commit
	if _, err := tx.Exec(ctx, setTenantScope, tenantID.String()); err != nil {
		return fmt.Errorf("store: tenant lock: set tenant scope: %w", err)
	}
	ms := int64(0)
	if wait > 0 {
		ms = max(wait.Milliseconds(), 1)
	}
	if _, err := tx.Exec(ctx, "SELECT set_config('lock_timeout', $1, true)", fmt.Sprintf("%dms", ms)); err != nil {
		return fmt.Errorf("store: tenant lock: lock_timeout: %w", err)
	}
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", TenantLockKey(tenantID, name)); err != nil {
		if SQLState(err) == lockNotAvailable {
			return fmt.Errorf("%w: %s of tenant %s", ErrLockTimeout, name, tenantID)
		}
		return fmt.Errorf("store: tenant lock %s: %w", name, err)
	}
	return fn(ctx)
}

// lockNotAvailable is the SQLSTATE of a lock wait cut by lock_timeout (55P03).
const lockNotAvailable = "55P03"

// ErrLockTimeout: WithTenantLock waited longer than its bound for another holder of the same lock.
var ErrLockTimeout = errors.New("store: tenant lock not acquired in time")
