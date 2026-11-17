package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
)

// Database is the connection configuration of the two pools of a process (§6.1, store.Config): a postgres:// URL
// without credentials and, per pool, a login role and the file secret holding its password (§14.2).
type Database struct {
	URL                  string // MG_DB_URL, e.g. postgres://postgres:5432/meshguard?sslmode=disable
	TenantUser           string // MG_DB_TENANT_USER (api: mg_api_tenant, worker: mg_worker_tenant)
	TenantPasswordFile   string // MG_DB_TENANT_PASSWORD_FILE
	PlatformUser         string // MG_DB_PLATFORM_USER (api: mg_api_platform, worker: mg_worker_platform)
	PlatformPasswordFile string // MG_DB_PLATFORM_PASSWORD_FILE
}

// EdgeAdmin locates the edge admin listener through which every Headscale call goes (§14.6): its base URL and the
// file secret of its token (on the host /opt/meshguard/secrets/app/edge_admin_token, root:mg-sec-app 0440).
type EdgeAdmin struct {
	URL       string // MG_EDGE_ADMIN_URL, http(s)://host:port of the listener on mg-admin
	TokenFile string // MG_EDGE_ADMIN_TOKEN_FILE
}

// Admin is the configuration of `meshguard admin <command>` (host-only commands of the api binary — P2-T11, P2-T11a):
// the same variables as the api service it runs beside (`docker compose run api admin …` inherits them), validated
// for what the admin commands need. Secret values never come from the environment: only *_FILE / *_DIR paths.
type Admin struct {
	Env        string     // MG_ENV
	LogLevel   slog.Level // MG_LOG_LEVEL
	BaseDomain string     // MG_BASE_DOMAIN (required)
	KEKAppDir  string     // MG_KEK_APP_DIR (required: the SecretStore of the api — kek-app)
	DB         Database
	Edge       EdgeAdmin // required when LoadAdmin is asked for it
}

var loginRoleRE = regexp.MustCompile(`^mg_[a-z][a-z_]{0,39}$`)

// LoadDatabase reads MG_DB_URL, MG_DB_{TENANT,PLATFORM}_USER and MG_DB_{TENANT,PLATFORM}_PASSWORD_FILE.
func LoadDatabase(getenv func(string) string) (Database, []error) {
	d := Database{
		URL:                  strings.TrimSpace(getenv("MG_DB_URL")),
		TenantUser:           strings.TrimSpace(getenv("MG_DB_TENANT_USER")),
		TenantPasswordFile:   strings.TrimSpace(getenv("MG_DB_TENANT_PASSWORD_FILE")),
		PlatformUser:         strings.TrimSpace(getenv("MG_DB_PLATFORM_USER")),
		PlatformPasswordFile: strings.TrimSpace(getenv("MG_DB_PLATFORM_PASSWORD_FILE")),
	}
	var errs []error
	if u, err := url.Parse(d.URL); err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") || u.Host == "" {
		errs = append(errs, errors.New("MG_DB_URL must be a postgres:// URL"))
	} else if u.User != nil || u.Query().Has("password") || u.Query().Has("user") {
		errs = append(errs, errors.New("MG_DB_URL must not carry a user or password (use MG_DB_*_USER and MG_DB_*_PASSWORD_FILE)"))
	}
	for name, v := range map[string]string{"MG_DB_TENANT_USER": d.TenantUser, "MG_DB_PLATFORM_USER": d.PlatformUser} {
		if !loginRoleRE.MatchString(v) {
			errs = append(errs, fmt.Errorf("%s must name an mg_* login role", name))
		}
	}
	if d.TenantUser != "" && d.TenantUser == d.PlatformUser {
		errs = append(errs, errors.New("MG_DB_TENANT_USER and MG_DB_PLATFORM_USER must be two roles (§6.1)"))
	}
	for name, v := range map[string]string{"MG_DB_TENANT_PASSWORD_FILE": d.TenantPasswordFile,
		"MG_DB_PLATFORM_PASSWORD_FILE": d.PlatformPasswordFile} {
		if !filepath.IsAbs(v) {
			errs = append(errs, fmt.Errorf("%s must be an absolute path", name))
		}
	}
	return d, errs
}

// LoadEdgeAdmin reads MG_EDGE_ADMIN_URL and MG_EDGE_ADMIN_TOKEN_FILE.
func LoadEdgeAdmin(getenv func(string) string) (EdgeAdmin, []error) {
	e := EdgeAdmin{URL: strings.TrimSpace(getenv("MG_EDGE_ADMIN_URL")),
		TokenFile: strings.TrimSpace(getenv("MG_EDGE_ADMIN_TOKEN_FILE"))}
	var errs []error
	u, err := url.Parse(e.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" ||
		u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		errs = append(errs, errors.New("MG_EDGE_ADMIN_URL must be http(s)://host:port without path, query or user info"))
	}
	if !filepath.IsAbs(e.TokenFile) {
		errs = append(errs, errors.New("MG_EDGE_ADMIN_TOKEN_FILE must be an absolute path"))
	}
	return e, errs
}

// LoadAdmin reads the configuration of the admin commands. needEdge: the command calls Headscale (adopt-instance).
func LoadAdmin(getenv func(string) string, environ []string, needEdge bool) (Admin, error) {
	var errs []error
	for _, kv := range environ { // same rule as Load: a secret is a file, never a value in the environment
		name, _, _ := strings.Cut(kv, "=")
		if strings.HasPrefix(name, "MG_") && secretName.MatchString(name) &&
			!strings.HasSuffix(name, "_FILE") && !strings.HasSuffix(name, "_DIR") {
			errs = append(errs, fmt.Errorf("%s: secret values must be passed as a file (%s_FILE) or a directory of files (%s_DIR), not in the environment", name, name, name))
		}
	}
	a := Admin{
		Env:        withDefault(getenv("MG_ENV"), "dev"),
		BaseDomain: strings.ToLower(strings.TrimSpace(getenv("MG_BASE_DOMAIN"))),
		KEKAppDir:  strings.TrimSpace(getenv("MG_KEK_APP_DIR")),
	}
	if !envs[a.Env] {
		errs = append(errs, fmt.Errorf("MG_ENV must be dev, staging or production, got %q", a.Env))
	}
	if err := a.LogLevel.UnmarshalText([]byte(withDefault(getenv("MG_LOG_LEVEL"), "info"))); err != nil {
		errs = append(errs, fmt.Errorf("MG_LOG_LEVEL: %w", err))
	}
	if !domainRE.MatchString(a.BaseDomain) {
		errs = append(errs, errors.New("MG_BASE_DOMAIN must be set to a valid domain"))
	}
	if !filepath.IsAbs(a.KEKAppDir) {
		errs = append(errs, errors.New("MG_KEK_APP_DIR must be the absolute path of the kek-app keyring"))
	}
	if getenv("MG_KEK_OPS_DIR") != "" {
		errs = append(errs, errors.New("MG_KEK_OPS_DIR: the admin commands run with the api's keyring only (§7.6)"))
	}
	var e []error
	a.DB, e = LoadDatabase(getenv)
	errs = append(errs, e...)
	if needEdge {
		a.Edge, e = LoadEdgeAdmin(getenv)
		errs = append(errs, e...)
	}
	return a, errors.Join(errs...)
}
