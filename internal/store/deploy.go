package store

// Deployment steps of database/README.md ("Triển khai"), wrapped for the `migrate` job of P2-T16
// (`meshguard-api migrate bootstrap|up|status`, compose project mg-app): the one-time superuser bootstrap, the
// forward-only migration with the passwords of the application login roles, and the checks a deployment must pass.
// Every password comes from a file secret and reaches the server only as a SCRAM verifier computed here
// (SetRolePassword); nothing secret is returned, logged or put in an error.

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/zhaduchanhzz/network-access-mesh/database"
)

// Bootstrap roles (database/bootstrap/superuser.sql) and the application login roles whose passwords the migrate job
// sets as mg_migrator (§6.1). mg_readonly stays without password (no consumer yet — it cannot log in).
const (
	MigratorRole = "mg_migrator"
	BackupRole   = "mg_backup"
)

// LoginRoles are the application login roles of a deployment (api, worker, detached audit, partition maintenance).
var LoginRoles = []string{"mg_api_tenant", "mg_api_platform", "mg_worker_tenant", "mg_worker_platform", AuditWriterRole,
	"mg_partition_maint"}

// connect opens one connection as cred (password read from its file).
func connect(ctx context.Context, rawURL string, cred Credentials) (*pgx.Conn, error) {
	pc, err := poolConfig(rawURL, cred)
	if err != nil {
		return nil, err
	}
	cc := pc.ConnConfig.Copy()
	if cc.Password, err = ReadPasswordFile(cred.PasswordFile); err != nil {
		return nil, err
	}
	c, err := pgx.ConnectConfig(ctx, cc)
	if err != nil {
		return nil, fmt.Errorf("connect as %s: %w", cred.User, err)
	}
	return c, nil
}

// BootstrapDatabase is the one-time superuser step: database/bootstrap/superuser.sql (Bootstrap — creates mg_migrator
// and mg_backup, hands the database to mg_migrator; idempotent) and the passwords of those two roles from their files.
// Run again, it only re-applies the same state (and the passwords, for a rotation).
func BootstrapDatabase(ctx context.Context, rawURL string, superuser Credentials, migratorPasswordFile,
	backupPasswordFile string,
) error {
	c, err := connect(ctx, rawURL, superuser)
	if err != nil {
		return fmt.Errorf("store: bootstrap: %w", err)
	}
	defer func() { _ = c.Close(context.WithoutCancel(ctx)) }()
	if err := Bootstrap(ctx, c); err != nil {
		return err
	}
	for role, file := range map[string]string{MigratorRole: migratorPasswordFile, BackupRole: backupPasswordFile} {
		pw, err := ReadPasswordFile(file)
		if err != nil {
			return fmt.Errorf("store: bootstrap: %w", err)
		}
		if err := SetRolePassword(ctx, c, role, pw); err != nil {
			return fmt.Errorf("store: bootstrap: %w", err)
		}
	}
	return nil
}

// SetLoginPasswords sets, as mg_migrator (ADMIN on the roles it created in the migrations), the password of every
// application login role from files[role]; a missing entry is an error (a deployment sets all of them).
func SetLoginPasswords(ctx context.Context, rawURL string, migrator Credentials, files map[string]string) ([]string, error) {
	var missing []string
	for _, r := range LoginRoles {
		if files[r] == "" {
			missing = append(missing, r)
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("store: no password file for %s", strings.Join(missing, ", "))
	}
	c, err := connect(ctx, rawURL, migrator)
	if err != nil {
		return nil, fmt.Errorf("store: login passwords: %w", err)
	}
	defer func() { _ = c.Close(context.WithoutCancel(ctx)) }()
	var done []string
	for _, r := range LoginRoles {
		pw, err := ReadPasswordFile(files[r])
		if err != nil {
			return done, fmt.Errorf("store: login passwords: %w", err)
		}
		if err := SetRolePassword(ctx, c, r, pw); err != nil {
			return done, fmt.Errorf("store: login passwords: %w", err)
		}
		done = append(done, r)
	}
	return done, nil
}

// DeployState is what the checks of a deployment read back as mg_migrator.
type DeployState struct {
	SchemaVersion   int64    `json:"schema_version"`
	LatestMigration int64    `json:"latest_migration"`
	RiverMigrations int      `json:"river_migrations"`
	SystemRoles     int      `json:"system_roles"`
	PartitionIssues []string `json:"partition_grant_violations"`
}

// Current reports whether the schema is at the latest embedded migration, River is migrated, the RBAC seed is in and
// no partition carries a privilege.
func (s DeployState) Current() bool {
	return s.SchemaVersion > 0 && s.SchemaVersion == s.LatestMigration && s.RiverMigrations > 0 && s.SystemRoles > 0 &&
		len(s.PartitionIssues) == 0
}

// ReadDeployState reads the schema version, River's migrations, the seeded system roles and the partition check
// (database/checks) as mg_migrator. Read-only.
func ReadDeployState(ctx context.Context, rawURL string, migrator Credentials) (DeployState, error) {
	var st DeployState
	var err error
	if st.LatestMigration, err = LatestMigration(); err != nil {
		return st, err
	}
	db, err := OpenMigrator(rawURL, migrator)
	if err != nil {
		return st, err
	}
	defer func() { _ = db.Close() }()
	if st.SchemaVersion, err = SchemaVersion(ctx, db); err != nil {
		return st, err
	}
	c, err := connect(ctx, rawURL, migrator)
	if err != nil {
		return st, fmt.Errorf("store: deploy state: %w", err)
	}
	defer func() { _ = c.Close(context.WithoutCancel(ctx)) }()
	if st.SchemaVersion == 0 {
		return st, nil // nothing migrated yet: no table to read
	}
	err = c.QueryRow(ctx, "SELECT count(*) FROM pg_tables WHERE schemaname = $1 AND tablename = 'river_migration'",
		QueueSchema).Scan(&st.RiverMigrations)
	if err == nil && st.RiverMigrations > 0 {
		err = c.QueryRow(ctx, "SELECT count(*) FROM "+QueueSchema+".river_migration").Scan(&st.RiverMigrations)
	}
	if err != nil {
		return st, fmt.Errorf("store: river migrations: %w", err)
	}
	if err := c.QueryRow(ctx, "SELECT count(*) FROM roles WHERE is_system").Scan(&st.SystemRoles); err != nil {
		return st, fmt.Errorf("store: seeded roles: %w", err)
	}
	if st.PartitionIssues, err = PartitionGrantViolations(ctx, c); err != nil {
		return st, err
	}
	if st.PartitionIssues == nil {
		st.PartitionIssues = []string{}
	}
	return st, nil
}

// LatestMigration is the highest version among the embedded goose migrations (NNNN_name.sql).
func LatestMigration() (int64, error) {
	names, err := fs.Glob(database.Migrations, "migrations/*.sql")
	if err != nil {
		return 0, fmt.Errorf("store: embedded migrations: %w", err)
	}
	if len(names) == 0 {
		return 0, errors.New("store: no embedded migration")
	}
	sort.Strings(names)
	base := path.Base(names[len(names)-1])
	v, err := strconv.ParseInt(strings.SplitN(base, "_", 2)[0], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("store: migration %s: %w", base, err)
	}
	return v, nil
}
