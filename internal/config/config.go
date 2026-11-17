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
	envs       = map[string]bool{"dev": true, "staging": true, "production": true}
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
		errs = append(errs, fmt.Errorf("MG_ENV must be dev, staging or production, got %q", cfg.Env))
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
	return cfg, errors.Join(errs...)
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
