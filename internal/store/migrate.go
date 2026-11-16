package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/lock"

	"github.com/zhaduchanhzz/network-access-mesh/database"
)

// Bootstrap runs database/bootstrap/superuser.sql (idempotent) on a superuser connection to the target database:
// it creates mg_migrator and mg_backup — the two roles that need superuser to create — and hands the database to
// mg_migrator. Everything else is created by the migrations themselves.
func Bootstrap(ctx context.Context, superuser Execer) error {
	q, err := database.Bootstrap.ReadFile("bootstrap/superuser.sql")
	if err != nil {
		return err
	}
	if _, err := superuser.Exec(ctx, string(q)); err != nil { // no arguments ⇒ simple protocol, several statements
		return fmt.Errorf("store: bootstrap: %w", err)
	}
	return nil
}

// OpenMigrator opens a database/sql handle logged in as the migration role (mg_migrator) for Migrate.
func OpenMigrator(rawURL string, cred Credentials) (*sql.DB, error) {
	pc, err := poolConfig(rawURL, cred)
	if err != nil {
		return nil, fmt.Errorf("store: migrator: %w", err)
	}
	cc := pc.ConnConfig.Copy()
	pw, err := ReadPasswordFile(cred.PasswordFile)
	if err != nil {
		return nil, fmt.Errorf("store: migrator: %w", err)
	}
	cc.Password = pw
	return stdlib.OpenDB(*cc), nil
}

// Migrate applies every pending forward-only migration (goose, embedded SQL — §4.3, §6.1) under a session lock
// that keeps two migrate jobs from running at once.
func Migrate(ctx context.Context, db *sql.DB) error {
	p, err := newProvider(db)
	if err != nil {
		return err
	}
	if _, err := p.Up(ctx); err != nil {
		return fmt.Errorf("store: migrate: %w", err)
	}
	return nil
}

// MigrateTo applies pending migrations up to and including version.
func MigrateTo(ctx context.Context, db *sql.DB, version int64) error {
	p, err := newProvider(db)
	if err != nil {
		return err
	}
	if _, err := p.UpTo(ctx, version); err != nil {
		return fmt.Errorf("store: migrate to %d: %w", version, err)
	}
	return nil
}

// SchemaVersion returns the version of the last applied migration (0 on an empty database).
func SchemaVersion(ctx context.Context, db *sql.DB) (int64, error) {
	p, err := newProvider(db)
	if err != nil {
		return 0, err
	}
	v, err := p.GetDBVersion(ctx)
	if err != nil {
		return 0, fmt.Errorf("store: schema version: %w", err)
	}
	return v, nil
}

func newProvider(db *sql.DB) (*goose.Provider, error) {
	fsys, err := fs.Sub(database.Migrations, "migrations")
	if err != nil {
		return nil, err
	}
	locker, err := lock.NewPostgresSessionLocker()
	if err != nil {
		return nil, err
	}
	p, err := goose.NewProvider(goose.DialectPostgres, db, fsys, goose.WithSessionLocker(locker))
	if err != nil {
		return nil, fmt.Errorf("store: migrations: %w", err)
	}
	return p, nil
}

// PartitionGrantViolations runs database/checks/partition_grants.sql and returns one line per violation: a
// partition with a privilege granted to any role other than its owner, a partition without RLS, or a default
// privilege (§6.1 — RLS of the parent does not apply when a partition is queried directly). CI requires none.
func PartitionGrantViolations(ctx context.Context, db interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
},
) ([]string, error) {
	q, err := database.Checks.ReadFile("checks/partition_grants.sql")
	if err != nil {
		return nil, err
	}
	rows, err := db.Query(ctx, string(q))
	if err != nil {
		return nil, fmt.Errorf("store: partition grant check: %w", err)
	}
	out, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (string, error) {
		var check, object, detail string
		err := r.Scan(&check, &object, &detail)
		return check + ": " + object + " — " + detail, err
	})
	if err != nil {
		return nil, errors.Join(errors.New("store: partition grant check"), err)
	}
	return out, nil
}
