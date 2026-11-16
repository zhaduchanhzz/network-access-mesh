// Package config loads process configuration from environment variables.
//
// Secret VALUES never come from the environment (§7.6, §25.1 rule 9): a variable whose name looks like a secret
// (PASSWORD, TOKEN, SECRET, KEY, CREDENTIAL) is only accepted as *_FILE pointing at a file secret. Load refuses to
// start otherwise, so a misconfigured deployment fails loudly instead of leaking a secret through `docker inspect`.
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
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
}

var (
	secretName = regexp.MustCompile(`(?i)(PASSWORD|PASSWD|TOKEN|SECRET|_KEY$|_KEY_|APIKEY|CREDENTIAL)`)
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
		if strings.HasPrefix(name, "MG_") && secretName.MatchString(name) && !strings.HasSuffix(name, "_FILE") {
			errs = append(errs, fmt.Errorf("%s: secret values must be passed as a file (%s_FILE), not in the environment", name, name))
		}
	}
	cfg := Config{
		Service:      service,
		Env:          withDefault(getenv("MG_ENV"), "dev"),
		HTTPAddr:     withDefault(getenv("MG_HTTP_ADDR"), ":8080"),
		InternalAddr: withDefault(getenv("MG_INTERNAL_ADDR"), ":9090"),
		BaseDomain:   strings.ToLower(strings.TrimSpace(getenv("MG_BASE_DOMAIN"))),
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
