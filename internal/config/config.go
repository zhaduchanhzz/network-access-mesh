// Package config loads process configuration from environment variables.
//
// Secret VALUES never come from the environment (§7.6, §25.1 rule 9): a variable whose name looks like a secret
// (PASSWORD, TOKEN, SECRET, KEY, KEK, CREDENTIAL) is only accepted as *_FILE pointing at a file secret, or *_DIR
// pointing at a directory of file secrets (a KEK keyring). Load refuses to start otherwise, so a misconfigured
// deployment fails loudly instead of leaking a secret through `docker inspect`.
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/mail"
	"net/netip"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// Config is the configuration shared by the api and worker processes.
type Config struct {
	Service      string     // "api" or "worker"
	Env          string     // "dev", "staging" or "production"
	HTTPAddr     string     // public API listener (api only); behind the edge
	InternalAddr string     // /healthz, /readyz, /metrics — never routed by the edge
	LogLevel     slog.Level // MG_LOG_LEVEL
	BaseDomain   string     // MG_BASE_DOMAIN (D-1); hostnames are derived from it
	// TrustedProxies (MG_TRUSTED_PROXIES, comma-separated IPs or CIDRs): peers whose X-Forwarded-For the api believes —
	// the edge's static address on mg-edge (§14.3). Required for api outside dev: behind the edge every request comes
	// from the edge, so without it the per-IP rate limit (§13.1) would be one bucket shared by all clients.
	TrustedProxies []netip.Prefix
	// KEK keyrings of the SecretStore (§7.6, secrets.LoadKeyring): directories of file secrets, one file per KEK
	// version plus ACTIVE. kek-app is mounted into api and worker, kek-ops into the worker only.
	KEKAppDir string // MG_KEK_APP_DIR
	KEKOpsDir string // MG_KEK_OPS_DIR (worker only)
	// EgressDeny (MG_EGRESS_DENY_CIDRS, comma-separated CIDRs or IPs): destinations the SSRF-hardened IdP client
	// (internal/idp, §8.2, T-21) refuses on top of its built-in special-purpose ranges — every Docker address pool of
	// the platform (daemon.json default-address-pools, the platform networks of infrastructure/host/networks.sh, the
	// tenant pool), the LAN, the tunnel and the public entry of the environment. Values come from the deployment
	// (rendered from the environment file), never from code.
	EgressDeny []netip.Prefix
	// IdPPlatformAddr (MG_IDP_PLATFORM_ADDR, host:port, optional): the address the platform route of internal/idp
	// dials for the platform-hosted IdP auth.<MG_BASE_DOMAIN> — e.g. the edge's static address on mg-edge. Empty: the
	// host name itself through the container's resolver (the edge alias auth.<domain> on mg-edge, §14.3).
	IdPPlatformAddr string

	// Wired: the process runs with its dependencies — PostgreSQL, SecretStore, edge admin listener, audit — and every
	// variable below is required (P2-T16). Always outside dev; in dev only when MG_DB_URL is set: without it a dev
	// process serves the internal endpoints and a public API that answers 501 (smoke test of the `images` workflow).
	Wired bool
	// DB: the two pools of the process (MG_DB_URL, MG_DB_{TENANT,PLATFORM}_USER, MG_DB_*_PASSWORD_FILE): the roles of
	// the service itself — mg_api_* for api, mg_worker_* for worker (§6.1).
	DB Database
	// AuditWriterPasswordFile (MG_DB_AUDIT_WRITER_PASSWORD_FILE, api): the password of mg_audit_writer, the detached
	// audit path (P2-T08; root:mg-sec-app 0440 on the host — §14.2).
	AuditWriterPasswordFile string
	// PartitionPasswordFile (MG_DB_PARTITION_PASSWORD_FILE, worker): the password of mg_partition_maint for the daily
	// partition.maintain job (§6.1; root:mg-sec-worker 0440).
	PartitionPasswordFile string
	// Edge: the edge admin listener through which every Headscale call goes (MG_EDGE_ADMIN_URL,
	// MG_EDGE_ADMIN_TOKEN_FILE — §14.6).
	Edge EdgeAdmin
	// IdPProvisionerClientID (MG_IDP_PROVISIONER_CLIENT_ID, worker, optional): the master-realm client of the keycloak
	// driver's provisioning identity; empty = the driver's default (mg-provisioner). Its secret is found in the
	// SecretStore (platform_ops), never configured.
	IdPProvisionerClientID string
	// Agent (MG_AGENT_SOCKET, MG_AGENT_TOKEN_FILE, worker, optional): the Host Agent — LoadAgentClient.
	Agent AgentClient
	// SMTP is the relay of notification e-mails (worker only — P3-T05b, §21.3 external dependency). Addr empty = no relay:
	// e-mail notifications are cancelled and only the Portal records are delivered — refused in production.
	SMTP SMTP
}

// SMTP is the notification relay of the worker (MG_SMTP_*). The password is a file secret (MG_SMTP_PASSWORD_FILE), never
// a value in the environment.
type SMTP struct {
	Addr         string // MG_SMTP_ADDR host:port
	TLS          string // MG_SMTP_TLS: starttls (default), implicit (port 465), none (dev/ci test sink only)
	ServerName   string // MG_SMTP_SERVER_NAME: TLS server name; default the host of Addr
	Username     string // MG_SMTP_USERNAME: "" = no authentication
	PasswordFile string // MG_SMTP_PASSWORD_FILE: absolute path of the file secret; required with a username
	From         string // MG_SMTP_FROM: RFC 5322 sender, e.g. "MeshGuard <no-reply@example.com>"
	CAFile       string // MG_SMTP_CA_FILE: PEM bundle trusted in addition to the system roots (private relay)
}

// AppHost is the Tenant Portal origin app.<MG_BASE_DOMAIN> (§8.3, §15.4); "" without a domain.
func (c Config) AppHost() string { return prefixed("app.", c.BaseDomain) }

// AdminHost is the Platform Console origin admin.<MG_BASE_DOMAIN>; "" without a domain.
func (c Config) AdminHost() string { return prefixed("admin.", c.BaseDomain) }

func prefixed(p, domain string) string {
	if domain == "" {
		return ""
	}
	return p + domain
}

// IdPPlatformHost is the host name of the platform-hosted IdP (§15.4): auth.<MG_BASE_DOMAIN>; "" without a domain.
func (c Config) IdPPlatformHost() string {
	if c.BaseDomain == "" {
		return ""
	}
	return "auth." + c.BaseDomain
}

var (
	secretName = regexp.MustCompile(`(?i)(PASSWORD|PASSWD|TOKEN|SECRET|_KEY$|_KEY_|APIKEY|CREDENTIAL|KEK)`)
	domainRE   = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)
	// ci: the dev/CI stack (compose.yaml, tests/e2e) — strict like staging: it runs the deployment configuration.
	envs       = map[string]bool{"dev": true, "ci": true, "staging": true, "production": true}
	clientIDRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)
	services   = map[string]bool{"api": true, "worker": true}
)

// Load reads the configuration. getenv looks up one variable; environ lists all variables as KEY=VALUE.
func Load(service string, getenv func(string) string, environ []string) (Config, error) {
	var errs []error
	if !services[service] {
		errs = append(errs, fmt.Errorf("unknown service %q", service))
	}
	for _, kv := range environ {
		name, _, _ := strings.Cut(kv, "=")
		if strings.HasPrefix(name, "MG_") && secretName.MatchString(name) &&
			!strings.HasSuffix(name, "_FILE") && !strings.HasSuffix(name, "_DIR") {
			errs = append(errs, fmt.Errorf("%s: secret values must be passed as a file (%s_FILE) or a directory of files (%s_DIR), not in the environment", name, name, name))
		}
	}
	cfg := Config{
		Service:      service,
		Env:          withDefault(getenv("MG_ENV"), "dev"),
		HTTPAddr:     withDefault(getenv("MG_HTTP_ADDR"), ":8080"),
		InternalAddr: withDefault(getenv("MG_INTERNAL_ADDR"), ":9090"),
		BaseDomain:   strings.ToLower(strings.TrimSpace(getenv("MG_BASE_DOMAIN"))),
		KEKAppDir:    strings.TrimSpace(getenv("MG_KEK_APP_DIR")),
		KEKOpsDir:    strings.TrimSpace(getenv("MG_KEK_OPS_DIR")),
	}
	for name, dir := range map[string]string{"MG_KEK_APP_DIR": cfg.KEKAppDir, "MG_KEK_OPS_DIR": cfg.KEKOpsDir} {
		if dir != "" && !filepath.IsAbs(dir) {
			errs = append(errs, fmt.Errorf("%s must be an absolute path", name))
		}
	}
	if cfg.KEKOpsDir != "" && service != "worker" {
		errs = append(errs, errors.New("MG_KEK_OPS_DIR: the kek-ops keyring is mounted into the worker only (§7.6)"))
	}
	if !envs[cfg.Env] {
		errs = append(errs, fmt.Errorf("MG_ENV must be dev, ci, staging or production, got %q", cfg.Env))
	}
	for name, addr := range map[string]string{"MG_HTTP_ADDR": cfg.HTTPAddr, "MG_INTERNAL_ADDR": cfg.InternalAddr} {
		if err := checkAddr(addr); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
		}
	}
	if cfg.HTTPAddr == cfg.InternalAddr {
		errs = append(errs, errors.New("MG_HTTP_ADDR and MG_INTERNAL_ADDR must differ"))
	}
	if cfg.BaseDomain == "" && cfg.Env != "dev" {
		errs = append(errs, errors.New("MG_BASE_DOMAIN is required outside dev"))
	}
	if cfg.BaseDomain != "" && !domainRE.MatchString(cfg.BaseDomain) {
		errs = append(errs, fmt.Errorf("MG_BASE_DOMAIN %q is not a valid domain", cfg.BaseDomain))
	}
	lvl := withDefault(getenv("MG_LOG_LEVEL"), "info")
	if err := cfg.LogLevel.UnmarshalText([]byte(lvl)); err != nil {
		errs = append(errs, fmt.Errorf("MG_LOG_LEVEL: %w", err))
	}
	proxies, err := parsePrefixes(getenv("MG_TRUSTED_PROXIES"))
	if err != nil {
		errs = append(errs, fmt.Errorf("MG_TRUSTED_PROXIES: %w", err))
	}
	cfg.TrustedProxies = proxies
	if service == "api" && len(proxies) == 0 && err == nil && cfg.Env != "dev" {
		errs = append(errs, errors.New("MG_TRUSTED_PROXIES is required for api outside dev (the edge's address on mg-edge)"))
	}
	for _, p := range proxies {
		// G2 wiring review: the edge's own address, never a range — with mg-edge's /24, idp and every other member
		// of the network could forge X-Forwarded-For (and, with the edge-only listener, reach the api directly).
		if cfg.Env != "dev" && p.Bits() != p.Addr().BitLen() {
			errs = append(errs, fmt.Errorf("MG_TRUSTED_PROXIES must list single addresses outside dev (the edge's), not %s", p))
		}
	}
	deny, err := parsePrefixes(getenv("MG_EGRESS_DENY_CIDRS"))
	if err != nil {
		errs = append(errs, fmt.Errorf("MG_EGRESS_DENY_CIDRS: %w", err))
	}
	cfg.EgressDeny = deny
	cfg.IdPPlatformAddr = strings.TrimSpace(getenv("MG_IDP_PLATFORM_ADDR"))
	if cfg.IdPPlatformAddr != "" {
		if err := checkAddr(cfg.IdPPlatformAddr); err != nil {
			errs = append(errs, fmt.Errorf("MG_IDP_PLATFORM_ADDR: %w", err))
		} else if h, _, _ := net.SplitHostPort(cfg.IdPPlatformAddr); h == "" {
			errs = append(errs, errors.New("MG_IDP_PLATFORM_ADDR: a host is required"))
		}
	}
	if cfg.Env != "dev" && len(deny) == 0 && err == nil {
		errs = append(errs, errors.New("MG_EGRESS_DENY_CIDRS is required outside dev (platform address pools, LAN, "+
			"tunnel, public entry — T-21)"))
	}
	cfg.IdPProvisionerClientID = strings.TrimSpace(getenv("MG_IDP_PROVISIONER_CLIENT_ID"))
	if cfg.IdPProvisionerClientID != "" && (service != "worker" || !clientIDRE.MatchString(cfg.IdPProvisionerClientID)) {
		errs = append(errs, errors.New("MG_IDP_PROVISIONER_CLIENT_ID: a client id ([a-z0-9-], at most 64) of the worker's IdP driver"))
	}
	cfg.SMTP, err = loadSMTP(service, cfg.Env, getenv)
	if err != nil {
		errs = append(errs, err)
	}
	var agentErrs []error
	cfg.Agent, agentErrs = LoadAgentClient(service, getenv)
	errs = append(errs, agentErrs...)
	cfg.Wired = cfg.Env != "dev" || strings.TrimSpace(getenv("MG_DB_URL")) != ""
	if cfg.Wired && services[service] {
		errs = append(errs, cfg.loadDependencies(getenv)...)
	}
	return cfg, errors.Join(errs...)
}

// loadDependencies reads and checks what a wired process needs (Config.Wired): the database roles of the service, the
// keyrings, the edge admin listener, the domain and the per-service secret files. Errors name variables, never values.
func (c *Config) loadDependencies(getenv func(string) string) []error {
	var errs, e []error
	c.DB, e = LoadDatabase(getenv)
	errs = append(errs, e...)
	if want := "mg_" + c.Service + "_tenant"; c.DB.TenantUser != "" && c.DB.TenantUser != want {
		errs = append(errs, fmt.Errorf("MG_DB_TENANT_USER must be %s for the %s process (§6.1)", want, c.Service))
	}
	if want := "mg_" + c.Service + "_platform"; c.DB.PlatformUser != "" && c.DB.PlatformUser != want {
		errs = append(errs, fmt.Errorf("MG_DB_PLATFORM_USER must be %s for the %s process (§6.1)", want, c.Service))
	}
	c.Edge, e = LoadEdgeAdmin(getenv)
	errs = append(errs, e...)
	if c.BaseDomain == "" {
		errs = append(errs, errors.New("MG_BASE_DOMAIN is required (app., admin. and auth. host names)"))
	}
	if c.KEKAppDir == "" {
		errs = append(errs, errors.New("MG_KEK_APP_DIR is required (keyring kek-app — §7.6)"))
	}
	c.AuditWriterPasswordFile = strings.TrimSpace(getenv("MG_DB_AUDIT_WRITER_PASSWORD_FILE"))
	c.PartitionPasswordFile = strings.TrimSpace(getenv("MG_DB_PARTITION_PASSWORD_FILE"))
	switch c.Service {
	case "api":
		if !filepath.IsAbs(c.AuditWriterPasswordFile) {
			errs = append(errs, errors.New("MG_DB_AUDIT_WRITER_PASSWORD_FILE must be the absolute path of the "+
				"mg_audit_writer password (api — P2-T08)"))
		}
		if c.PartitionPasswordFile != "" {
			errs = append(errs, errors.New("MG_DB_PARTITION_PASSWORD_FILE: partition.maintain runs in the worker only"))
		}
	case "worker":
		if c.KEKOpsDir == "" {
			errs = append(errs, errors.New("MG_KEK_OPS_DIR is required for the worker (keyring kek-ops — §7.6)"))
		}
		if !filepath.IsAbs(c.PartitionPasswordFile) {
			errs = append(errs, errors.New("MG_DB_PARTITION_PASSWORD_FILE must be the absolute path of the "+
				"mg_partition_maint password (worker — §6.1)"))
		}
		if c.AuditWriterPasswordFile != "" {
			errs = append(errs, errors.New("MG_DB_AUDIT_WRITER_PASSWORD_FILE: the worker has no detached audit path "+
				"yet — a service declares only the secrets it uses (§14.2)"))
		}
	}
	return errs
}

// smtpTLS are the accepted MG_SMTP_TLS values.
var smtpTLS = map[string]bool{"starttls": true, "implicit": true, "none": true}

// loadSMTP reads MG_SMTP_* (worker only). Errors name variables, never values.
func loadSMTP(service, env string, getenv func(string) string) (SMTP, error) {
	c := SMTP{
		Addr:         strings.TrimSpace(getenv("MG_SMTP_ADDR")),
		TLS:          strings.ToLower(withDefault(getenv("MG_SMTP_TLS"), "starttls")),
		ServerName:   strings.TrimSpace(getenv("MG_SMTP_SERVER_NAME")),
		Username:     strings.TrimSpace(getenv("MG_SMTP_USERNAME")),
		PasswordFile: strings.TrimSpace(getenv("MG_SMTP_PASSWORD_FILE")),
		From:         strings.TrimSpace(getenv("MG_SMTP_FROM")),
		CAFile:       strings.TrimSpace(getenv("MG_SMTP_CA_FILE")),
	}
	set := c.Addr != "" || c.ServerName != "" || c.Username != "" || c.PasswordFile != "" || c.From != "" || c.CAFile != "" ||
		strings.TrimSpace(getenv("MG_SMTP_TLS")) != ""
	if service != "worker" {
		if set {
			return SMTP{}, errors.New("MG_SMTP_*: the notification relay is configured on the worker only (notification.send)")
		}
		return SMTP{}, nil
	}
	if c.Addr == "" {
		switch {
		case env == "production":
			return SMTP{}, errors.New("MG_SMTP_ADDR is required in production (notification e-mails — §21.3)")
		case set:
			return SMTP{}, errors.New("MG_SMTP_*: MG_SMTP_ADDR is required when another MG_SMTP_ variable is set")
		}
		return SMTP{}, nil
	}
	var errs []error
	if err := checkAddr(c.Addr); err != nil {
		errs = append(errs, fmt.Errorf("MG_SMTP_ADDR: %w", err))
	} else if h, _, _ := net.SplitHostPort(c.Addr); h == "" {
		errs = append(errs, errors.New("MG_SMTP_ADDR: a host is required"))
	}
	if !smtpTLS[c.TLS] {
		errs = append(errs, errors.New("MG_SMTP_TLS must be starttls, implicit or none"))
	}
	if c.TLS == "none" && env != "dev" && env != "ci" {
		errs = append(errs, errors.New("MG_SMTP_TLS=none is allowed only in dev and ci (the test mail sink)"))
	}
	if a, err := mail.ParseAddress(c.From); err != nil || a.Address == "" {
		errs = append(errs, errors.New("MG_SMTP_FROM must be an RFC 5322 address (\"Name <addr@domain>\")"))
	}
	switch {
	case c.Username != "" && !filepath.IsAbs(c.PasswordFile):
		errs = append(errs, errors.New("MG_SMTP_PASSWORD_FILE must be the absolute path of the relay password (file secret)"))
	case c.Username == "" && c.PasswordFile != "":
		errs = append(errs, errors.New("MG_SMTP_PASSWORD_FILE is set without MG_SMTP_USERNAME"))
	case c.Username != "" && c.TLS == "none":
		errs = append(errs, errors.New("MG_SMTP_USERNAME: authentication requires TLS (MG_SMTP_TLS starttls or implicit)"))
	}
	if c.CAFile != "" && !filepath.IsAbs(c.CAFile) {
		errs = append(errs, errors.New("MG_SMTP_CA_FILE must be an absolute path"))
	}
	return c, errors.Join(errs...)
}

// parsePrefixes reads a comma-separated list of IP addresses (taken as single-address prefixes) and CIDRs.
func parsePrefixes(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, item := range strings.Split(s, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if strings.Contains(item, "/") {
			p, err := netip.ParsePrefix(item)
			if err != nil {
				return nil, fmt.Errorf("%q is not a CIDR", item)
			}
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(item)
		if err != nil {
			return nil, fmt.Errorf("%q is not an IP address", item)
		}
		a = a.Unmap().WithZone("")
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out, nil
}

func withDefault(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return strings.TrimSpace(v)
}

func checkAddr(addr string) error {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return fmt.Errorf("invalid port %q", port)
	}
	return nil
}
