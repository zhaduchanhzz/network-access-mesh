// Command mg-e2e-dbinit prepares the platform PostgreSQL of the dev/CI stack (P2-T01a, compose.yaml at the repository
// root) along the deployment path of database/README.md ("Triển khai"), with the repository's own code:
//
//  1. store.Bootstrap as the cluster superuser (database/bootstrap/superuser.sql);
//  2. the passwords of mg_migrator and mg_backup (store.SetRolePassword — SCRAM verifier computed here);
//  3. store.MigrateAll as mg_migrator (goose migrations + seeds, then River's schema and its privileges);
//  4. the passwords of the application login roles, set by mg_migrator;
//  5. checks: schema at the latest embedded migration, River migrated, seeded system roles, no privilege on a
//     partition (database/checks), and store.Open accepts the api and the worker role pairs (role groups checked).
//
// Every password is read from a file in -secrets (pg_superuser_password, role_<role>); nothing secret is printed. The
// result is one JSON line on stdout. Test tooling only: never built into the api/worker images.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/zhaduchanhzz/network-access-mesh/database"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
)

// loginRoles are the application login roles whose passwords mg_migrator sets after the migration (§6.1; the same
// list as internal/store/storetest).
var loginRoles = []string{
	"mg_api_tenant", "mg_worker_tenant", "mg_api_platform", "mg_worker_platform", "mg_readonly", "mg_audit_writer",
	"mg_partition_maint",
}

// result is the JSON line printed on success.
type result struct {
	SchemaVersion   int64    `json:"schema_version"`
	LatestMigration int64    `json:"latest_migration"`
	RiverMigrations int      `json:"river_migrations"`
	SystemRoles     int      `json:"system_roles"`
	PartitionIssues []string `json:"partition_grant_violations"`
	Pools           []string `json:"pools"`
	RolesWithPasswd []string `json:"roles_with_password"`
}

func main() {
	url := flag.String("url", "postgres://postgres:5432/meshguard?sslmode=disable", "database URL without credentials")
	dir := flag.String("secrets", "/run/secrets", "directory of the password files")
	timeout := flag.Duration("timeout", 3*time.Minute, "overall timeout")
	flag.Parse()
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	res, err := run(ctx, *url, *dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mg-e2e-dbinit: %v\n", err)
		os.Exit(1)
	}
	out, _ := json.Marshal(res)
	fmt.Println(string(out))
}

func roleFile(dir, role string) string { return filepath.Join(dir, "role_"+role) }

// connect opens a pgx connection to url as user, with the password read from file.
func connect(ctx context.Context, url, user, file string) (*pgx.Conn, error) {
	cfg, err := pgx.ParseConfig(url)
	if err != nil {
		return nil, fmt.Errorf("parse URL: %w", err)
	}
	cfg.User = user
	// the superuser password follows the same file-secret rules as the role passwords (printable ASCII, ≥ 16)
	if cfg.Password, err = store.ReadPasswordFile(file); err != nil {
		return nil, err
	}
	c, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("connect as %s: %w", user, err)
	}
	return c, nil
}

func run(ctx context.Context, url, dir string) (*result, error) {
	su, err := connect(ctx, url, "postgres", filepath.Join(dir, "pg_superuser_password"))
	if err != nil {
		return nil, err
	}
	defer func() { _ = su.Close(context.Background()) }()
	if err := store.Bootstrap(ctx, su); err != nil {
		return nil, err
	}
	for _, r := range []string{"mg_migrator", "mg_backup"} {
		pw, err := store.ReadPasswordFile(roleFile(dir, r))
		if err != nil {
			return nil, err
		}
		if err := store.SetRolePassword(ctx, su, r, pw); err != nil {
			return nil, err
		}
	}
	migrator := store.Credentials{User: "mg_migrator", PasswordFile: roleFile(dir, "mg_migrator")}
	if err := store.MigrateAll(ctx, url, migrator); err != nil {
		return nil, err
	}

	mig, err := connect(ctx, url, "mg_migrator", migrator.PasswordFile)
	if err != nil {
		return nil, err
	}
	defer func() { _ = mig.Close(context.Background()) }()
	res := &result{RolesWithPasswd: []string{"mg_migrator", "mg_backup"}}
	for _, r := range loginRoles {
		pw, err := store.ReadPasswordFile(roleFile(dir, r))
		if err != nil {
			return nil, err
		}
		if err := store.SetRolePassword(ctx, mig, r, pw); err != nil {
			return nil, err
		}
		res.RolesWithPasswd = append(res.RolesWithPasswd, r)
	}

	if res.LatestMigration, err = latestMigration(); err != nil {
		return nil, err
	}
	db, err := store.OpenMigrator(url, migrator)
	if err != nil {
		return nil, err
	}
	defer func() { _ = db.Close() }()
	if res.SchemaVersion, err = store.SchemaVersion(ctx, db); err != nil {
		return nil, err
	}
	if err := mig.QueryRow(ctx, "SELECT count(*) FROM "+store.QueueSchema+".river_migration").Scan(&res.RiverMigrations); err != nil {
		return nil, fmt.Errorf("river migrations: %w", err)
	}
	if err := mig.QueryRow(ctx, "SELECT count(*) FROM roles WHERE is_system").Scan(&res.SystemRoles); err != nil {
		return nil, fmt.Errorf("seeded roles: %w", err)
	}
	if res.PartitionIssues, err = store.PartitionGrantViolations(ctx, mig); err != nil {
		return nil, err
	}

	for _, pair := range [][3]string{{"api", "mg_api_tenant", "mg_api_platform"}, {"worker", "mg_worker_tenant", "mg_worker_platform"}} {
		s, err := store.Open(ctx, store.Config{
			URL:      url,
			Tenant:   store.Credentials{User: pair[1], PasswordFile: roleFile(dir, pair[1])},
			Platform: store.Credentials{User: pair[2], PasswordFile: roleFile(dir, pair[2])},
			MaxConns: 2,
		})
		if err != nil {
			return nil, fmt.Errorf("%s pools: %w", pair[0], err)
		}
		err = s.Ping(ctx)
		s.Close()
		if err != nil {
			return nil, fmt.Errorf("%s pools: ping: %w", pair[0], err)
		}
		res.Pools = append(res.Pools, pair[0])
	}
	if res.SchemaVersion != res.LatestMigration {
		return res, fmt.Errorf("schema version %d, latest embedded migration %d", res.SchemaVersion, res.LatestMigration)
	}
	if len(res.PartitionIssues) > 0 {
		return res, errors.New("privilege on a partition: " + strings.Join(res.PartitionIssues, "; "))
	}
	return res, nil
}

// latestMigration is the highest version among the embedded goose migrations (NNNN_name.sql).
func latestMigration() (int64, error) {
	names, err := fs.Glob(database.Migrations, "migrations/*.sql")
	if err != nil {
		return 0, fmt.Errorf("embedded migrations: %w", err)
	}
	if len(names) == 0 {
		return 0, errors.New("no embedded migration")
	}
	sort.Strings(names)
	base := path.Base(names[len(names)-1])
	v, err := strconv.ParseInt(strings.SplitN(base, "_", 2)[0], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("migration %s: %w", base, err)
	}
	return v, nil
}
