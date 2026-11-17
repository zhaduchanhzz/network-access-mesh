package main

// `meshguard-api migrate <bootstrap|up|status>` — the one-shot database jobs of the compose project mg-app (P2-T16;
// database/README.md "Triển khai", §6.1):
//
//	bootstrap  ONCE, as the cluster superuser (service db-bootstrap, profile bootstrap): database/bootstrap/
//	           superuser.sql — mg_migrator and mg_backup, the database handed to mg_migrator — and the passwords of
//	           those two roles from their files. Idempotent (run again for a password rotation).
//	up         as mg_migrator (service migrate, profile migrate): every pending goose migration, the seeds, River's
//	           schema and its privileges (store.MigrateAll), then the passwords of the application login roles from the
//	           migrate job's own copies, then the checks (schema at the latest embedded migration, River migrated, RBAC
//	           seeded, no privilege on a partition). The host script infrastructure/host/migrate.sh first runs the
//	           pre-migration backup of mg-backup and stops when it fails (P2-T03a).
//	status     as mg_migrator, read-only: the same checks.
//
// Output: one JSON line of the state (versions, counts, role names — never a password). Exit status: 0 done / current,
// 1 failed / not current, 2 usage or configuration error.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"time"

	"github.com/zhaduchanhzz/network-access-mesh/internal/config"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/logx"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
)

const (
	migrateUsage = "usage: meshguard-api migrate bootstrap|up|status   (one-shot services of mg-app — " +
		"infrastructure/host/RUNBOOK.md)\n"
	// superuserRole is the superuser of the official postgres image (POSTGRES_USER unset).
	superuserRole  = "postgres"
	migrateTimeout = 15 * time.Minute
)

// migrateResult is the JSON line printed by every mode.
type migrateResult struct {
	Mode         string             `json:"mode"`
	Before       *store.DeployState `json:"before,omitempty"`
	State        *store.DeployState `json:"state,omitempty"`
	PasswordsSet []string           `json:"passwords_set,omitempty"`
	Current      bool               `json:"current"`
}

func migrate(ctx context.Context, args []string, getenv func(string) string, environ []string, stdout, stderr io.Writer) int {
	if len(args) != 1 || !config.MigrateModes[args[0]] {
		_, _ = io.WriteString(stderr, "meshguard-api migrate: one mode expected\n"+migrateUsage)
		return 2
	}
	mode := args[0]
	cfg, err := config.LoadMigrate(mode, getenv, environ)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "meshguard-api migrate %s: invalid configuration:\n%v\n", mode, err)
		return 2
	}
	ctx, cancel := context.WithTimeout(ctx, migrateTimeout)
	defer cancel()
	fail := func(err error) int {
		_, _ = fmt.Fprintf(stderr, "meshguard-api migrate %s: FAILED: %s\n", mode, logx.RedactString(err.Error()))
		return 1
	}
	migrator := store.Credentials{User: store.MigratorRole, PasswordFile: cfg.MigratorPasswordFile}
	res := migrateResult{Mode: mode}
	switch mode {
	case "bootstrap":
		if err := store.BootstrapDatabase(ctx, cfg.URL, store.Credentials{User: superuserRole,
			PasswordFile: cfg.SuperuserPasswordFile}, cfg.MigratorPasswordFile, cfg.BackupPasswordFile); err != nil {
			return fail(err)
		}
		res.PasswordsSet = []string{store.MigratorRole, store.BackupRole}
		st, err := store.ReadDeployState(ctx, cfg.URL, migrator) // proves mg_migrator logs in with its new password
		if err != nil {
			return fail(err)
		}
		res.State, res.Current = &st, st.Current()
	case "up":
		before, err := store.ReadDeployState(ctx, cfg.URL, migrator)
		if err != nil {
			return fail(err)
		}
		res.Before = &before
		if err := store.MigrateAll(ctx, cfg.URL, migrator); err != nil {
			return fail(err)
		}
		files := make(map[string]string, len(store.LoginRoles))
		for _, r := range store.LoginRoles {
			files[r] = filepath.Join(cfg.RolePasswordDir, r)
		}
		if res.PasswordsSet, err = store.SetLoginPasswords(ctx, cfg.URL, migrator, files); err != nil {
			return fail(err)
		}
		st, err := store.ReadDeployState(ctx, cfg.URL, migrator)
		if err != nil {
			return fail(err)
		}
		res.State, res.Current = &st, st.Current()
	case "status":
		st, err := store.ReadDeployState(ctx, cfg.URL, migrator)
		if err != nil {
			return fail(err)
		}
		res.State, res.Current = &st, st.Current()
	}
	b, _ := json.Marshal(res)
	_, _ = fmt.Fprintln(stdout, string(b))
	if mode != "bootstrap" && !res.Current {
		_, _ = fmt.Fprintf(stderr, "meshguard-api migrate %s: the database is NOT at the state of this release\n", mode)
		return 1
	}
	return 0
}
