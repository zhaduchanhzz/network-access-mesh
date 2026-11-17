package config

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
)

// Provisioning configures the Tenant Orchestrator of the worker (P3-T05, §11.3) — the instance parameters it sends
// the Host Agent and the checks of steps 4, 17 and 18. Rendered by tools/render_app.py (staging/production) from
// versions.lock and the environment file; none of it is a secret.
type Provisioning struct {
	// HeadscaleDigest (MG_PROVISION_HEADSCALE_DIGEST, sha256:<64 hex>): the image of new instances — [images.mg-headscale]
	// of versions.lock; the agent's allowlist must hold it. Empty = the worker does not run tenant.provision.
	HeadscaleDigest string
	// HeadscaleVersion (MG_PROVISION_HEADSCALE_VERSION, e.g. v0.29.7): recorded at step 3, verified at step 15.
	HeadscaleVersion string
	// Nameservers (MG_PROVISION_NAMESERVERS, comma-separated IPs): dns.nameservers.global of every instance (RT-07).
	Nameservers []netip.Addr
	// EdgeAddr (MG_PROVISION_EDGE_ADDR, ip:port): the edge's public listener as the prober reaches it (steps 17, 18).
	EdgeAddr string
	// ProberURL (MG_PROBER_URL, http://host:port): the prober RPC (apps/probe, P3-T03a). Empty: steps 17/18 stop the
	// job in failed_resumable (prober_not_configured) — the edge is never declared verified without it.
	ProberURL string
	// DNSCheck (MG_PROVISION_DNS_CHECK): "resolve" (default — step 4 resolves <slug>.mesh.<domain>) or "skip" (dev/ci
	// stacks without public DNS only).
	DNSCheck string
	// DNSServer (MG_PROVISION_DNS_SERVER, ip:port, optional): the resolver of step 4; empty = the container's.
	DNSServer string
}

// Enabled reports whether the worker runs tenant.provision.
func (p Provisioning) Enabled() bool { return p.HeadscaleDigest != "" }

var (
	digestRE  = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	versionRE = regexp.MustCompile(`^v?[0-9]+\.[0-9]+\.[0-9]+([.+-][0-9A-Za-z.+-]{1,32})?$`)
)

// LoadProvisioning reads MG_PROVISION_* and MG_PROBER_URL (worker only). Errors name variables, never values.
func LoadProvisioning(service, env string, getenv func(string) string) (Provisioning, []error) {
	p := Provisioning{
		HeadscaleDigest:  strings.TrimSpace(getenv("MG_PROVISION_HEADSCALE_DIGEST")),
		HeadscaleVersion: strings.TrimSpace(getenv("MG_PROVISION_HEADSCALE_VERSION")),
		EdgeAddr:         strings.TrimSpace(getenv("MG_PROVISION_EDGE_ADDR")),
		ProberURL:        strings.TrimSpace(getenv("MG_PROBER_URL")),
		DNSCheck:         withDefault(strings.TrimSpace(getenv("MG_PROVISION_DNS_CHECK")), "resolve"),
		DNSServer:        strings.TrimSpace(getenv("MG_PROVISION_DNS_SERVER")),
	}
	ns := strings.TrimSpace(getenv("MG_PROVISION_NAMESERVERS"))
	set := p.HeadscaleDigest != "" || p.HeadscaleVersion != "" || ns != "" || p.EdgeAddr != "" || p.ProberURL != "" ||
		p.DNSServer != "" || strings.TrimSpace(getenv("MG_PROVISION_DNS_CHECK")) != ""
	if !set {
		return p, nil
	}
	var errs []error
	if service != "worker" {
		return p, []error{errors.New("MG_PROVISION_*, MG_PROBER_URL: the Tenant Orchestrator runs in the worker only")}
	}
	if !digestRE.MatchString(p.HeadscaleDigest) || !versionRE.MatchString(p.HeadscaleVersion) {
		errs = append(errs, errors.New("MG_PROVISION_HEADSCALE_DIGEST (sha256:<64 hex>) and MG_PROVISION_HEADSCALE_VERSION "+
			"(vX.Y.Z) are required together"))
	}
	for _, s := range strings.Split(ns, ",") {
		a, err := netip.ParseAddr(strings.TrimSpace(s))
		if err != nil || !a.IsGlobalUnicast() {
			errs = append(errs, errors.New("MG_PROVISION_NAMESERVERS must list 1–8 unicast IP addresses"))
			break
		}
		p.Nameservers = append(p.Nameservers, a)
	}
	if len(p.Nameservers) > 8 {
		errs = append(errs, errors.New("MG_PROVISION_NAMESERVERS must list 1–8 unicast IP addresses"))
	}
	if _, err := netip.ParseAddrPort(p.EdgeAddr); err != nil {
		errs = append(errs, errors.New("MG_PROVISION_EDGE_ADDR must be ip:port (the edge's public listener)"))
	}
	if p.ProberURL != "" {
		u, err := url.Parse(p.ProberURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil ||
			(u.Path != "" && u.Path != "/") || u.RawQuery != "" {
			errs = append(errs, errors.New("MG_PROBER_URL must be http(s)://host:port"))
		}
	}
	switch p.DNSCheck {
	case "resolve":
	case "skip":
		if env != "dev" && env != "ci" {
			errs = append(errs, errors.New("MG_PROVISION_DNS_CHECK=skip is for the dev/ci stacks only"))
		}
	default:
		errs = append(errs, fmt.Errorf("MG_PROVISION_DNS_CHECK must be resolve or skip"))
	}
	if p.DNSServer != "" {
		if h, _, err := net.SplitHostPort(p.DNSServer); err != nil || net.ParseIP(h) == nil {
			errs = append(errs, errors.New("MG_PROVISION_DNS_SERVER must be ip:port"))
		}
	}
	return p, errs
}
