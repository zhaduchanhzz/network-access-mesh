package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"path/filepath"
	"strings"
)

// Migrate is the configuration of `meshguard-api migrate <bootstrap|up|status>` — the one-shot services db-bootstrap
// and migrate of the compose project mg-app (P2-T16, §6.1, database/README.md "Triển khai"). Secret values never come
// from the environment: only absolute paths of file secrets (mounted from /opt/meshguard/secrets on the host).
type Migrate struct {
	Env      string     // MG_ENV
	LogLevel slog.Level // MG_LOG_LEVEL
	URL      string     // MG_DB_URL, without user or password
	// SuperuserPasswordFile (MG_DB_SUPERUSER_PASSWORD_FILE, bootstrap only): the cluster superuser `postgres`.
	SuperuserPasswordFile string
	// MigratorPasswordFile (MG_DB_MIGRATOR_PASSWORD_FILE): mg_migrator — the role that migrates (mg-sec-migrate).
	MigratorPasswordFile string
	// BackupPasswordFile (MG_DB_BACKUP_PASSWORD_FILE, bootstrap only): mg_backup, the role of pg-backup (P2-T03a).
	BackupPasswordFile string
	// RolePasswordDir (MG_DB_ROLE_PASSWORD_DIR, up only): one file <role> per application login role (the migrate
	// job's own copies — §14.2 "mỗi consumer một bản, xoay cùng lúc"); mg_migrator sets them after migrating.
	RolePasswordDir string
}

// MigrateModes are the subcommands of `meshguard-api migrate`.
var MigrateModes = map[string]bool{"bootstrap": true, "up": true, "status": true}

// LoadMigrate reads the configuration of one migrate mode.
func LoadMigrate(mode string, getenv func(string) string, environ []string) (Migrate, error) {
	var errs []error
	if !MigrateModes[mode] {
		errs = append(errs, errors.New("migrate: unknown mode (bootstrap, up, status)"))
	}
	for _, kv := range environ { // same rule as Load: a secret is a file, never a value in the environment
		name, _, _ := strings.Cut(kv, "=")
		if strings.HasPrefix(name, "MG_") && secretName.MatchString(name) &&
			!strings.HasSuffix(name, "_FILE") && !strings.HasSuffix(name, "_DIR") {
			errs = append(errs, fmt.Errorf("%s: secret values must be passed as a file (%s_FILE) or a directory of files (%s_DIR), not in the environment", name, name, name))
		}
	}
	m := Migrate{
		Env:                   withDefault(getenv("MG_ENV"), "dev"),
		URL:                   strings.TrimSpace(getenv("MG_DB_URL")),
		SuperuserPasswordFile: strings.TrimSpace(getenv("MG_DB_SUPERUSER_PASSWORD_FILE")),
		MigratorPasswordFile:  strings.TrimSpace(getenv("MG_DB_MIGRATOR_PASSWORD_FILE")),
		BackupPasswordFile:    strings.TrimSpace(getenv("MG_DB_BACKUP_PASSWORD_FILE")),
		RolePasswordDir:       strings.TrimSpace(getenv("MG_DB_ROLE_PASSWORD_DIR")),
	}
	if !envs[m.Env] {
		errs = append(errs, fmt.Errorf("MG_ENV must be dev, ci, staging or production, got %q", m.Env))
	}
	if err := m.LogLevel.UnmarshalText([]byte(withDefault(getenv("MG_LOG_LEVEL"), "info"))); err != nil {
		errs = append(errs, fmt.Errorf("MG_LOG_LEVEL: %w", err))
	}
	if u, err := url.Parse(m.URL); err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") || u.Host == "" {
		errs = append(errs, errors.New("MG_DB_URL must be a postgres:// URL"))
	} else if u.User != nil || u.Query().Has("password") || u.Query().Has("user") {
		errs = append(errs, errors.New("MG_DB_URL must not carry a user or password"))
	}
	need := map[string]string{"MG_DB_MIGRATOR_PASSWORD_FILE": m.MigratorPasswordFile}
	switch mode {
	case "bootstrap":
		need["MG_DB_SUPERUSER_PASSWORD_FILE"] = m.SuperuserPasswordFile
		need["MG_DB_BACKUP_PASSWORD_FILE"] = m.BackupPasswordFile
	case "up":
		need["MG_DB_ROLE_PASSWORD_DIR"] = m.RolePasswordDir
	}
	for name, v := range need {
		if !filepath.IsAbs(v) {
			errs = append(errs, fmt.Errorf("%s must be an absolute path (migrate %s)", name, mode))
		}
	}
	if mode != "bootstrap" && m.SuperuserPasswordFile != "" {
		// the superuser password is mounted into the one-time bootstrap service only (db-bootstrap)
		errs = append(errs, errors.New("MG_DB_SUPERUSER_PASSWORD_FILE: only `migrate bootstrap` uses the superuser"))
	}
	return m, errors.Join(errs...)
}
