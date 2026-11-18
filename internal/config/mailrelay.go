package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/mail"
	"net/netip"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// MailRelay is the configuration of `meshguard-worker mailrelay` (P3-T05b-mail): the SMTP bridge between the internal
// `mail` network (worker notifications, Keycloak, Alertmanager) and the Cloudflare Worker that sends through Cloudflare
// Email Service. It is its own process (own container from the worker image), so it does not go through Load.
type MailRelay struct {
	Env          string     // MG_ENV: dev, ci, staging, production
	LogLevel     slog.Level // MG_LOG_LEVEL
	InternalAddr string     // MG_INTERNAL_ADDR: /healthz, /readyz, /metrics (default :9090)
	// SMTPAddr (MG_MAILRELAY_SMTP_ADDR, default ":587") is the SMTP listener; with SMTPNetwork set, its host part is
	// replaced by the container's own address inside that network (the `mail` network — the listener is reachable
	// there only, not on mg-egress or mg-obs). Required outside dev/ci.
	SMTPAddr    string
	SMTPNetwork netip.Prefix // MG_MAILRELAY_SMTP_CIDR
	Hostname    string       // MG_MAILRELAY_HOSTNAME: greeting/EHLO name and TLS name of the relay (default mailrelay)
	// TLSCertFile, TLSKeyFile (MG_MAILRELAY_TLS_CERT_FILE, MG_MAILRELAY_TLS_KEY_FILE): STARTTLS certificate of the
	// internal CA (infrastructure/host/mail-secrets.sh). Set ⇒ STARTTLS offered AND required before MAIL. Unset ⇒ plain
	// text, allowed only in dev and ci.
	TLSCertFile string
	TLSKeyFile  string
	// URL (MG_MAILRELAY_URL) of the Worker endpoint, https://…/v1/send (http only in dev/ci — the fake Worker of the
	// stack). Not secret: the HMAC key is.
	URL string
	// HMACKeyFile (MG_MAILRELAY_HMAC_KEY_FILE): the shared key of the Worker (RELAY_HMAC_KEY), a file secret read at every
	// message (rotation without restart).
	HMACKeyFile string
	CAFile      string        // MG_MAILRELAY_CA_FILE: PEM roots trusted for the Worker URL in addition to the system roots
	AllowedFrom []string      // MG_MAILRELAY_ALLOWED_FROM: sender addresses accepted in MAIL FROM and the From header
	Rate        int           // MG_MAILRELAY_RATE_PER_MINUTE: messages per minute (0 = no limit; default 60)
	Timeout     time.Duration // MG_MAILRELAY_TIMEOUT: forwarding budget of one message, all attempts (default 8 s)
}

// PlainTextAllowed reports whether the environment may run the relay without TLS (the dev/CI test stack only).
func (m MailRelay) PlainTextAllowed() bool { return m.Env == "dev" || m.Env == "ci" }

var hostnameRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)

// MailRelaySendPath is the only path the Worker answers (infrastructure/mail/cf-worker).
const MailRelaySendPath = "/v1/send"

// LoadMailRelay reads the configuration of the relay. Errors name variables, never values.
func LoadMailRelay(getenv func(string) string, environ []string) (MailRelay, error) {
	errs := secretEnvErrors(environ)
	c := MailRelay{
		Env:          withDefault(getenv("MG_ENV"), "dev"),
		InternalAddr: withDefault(getenv("MG_INTERNAL_ADDR"), ":9090"),
		SMTPAddr:     withDefault(getenv("MG_MAILRELAY_SMTP_ADDR"), ":587"),
		Hostname:     strings.ToLower(withDefault(getenv("MG_MAILRELAY_HOSTNAME"), "mailrelay")),
		TLSCertFile:  strings.TrimSpace(getenv("MG_MAILRELAY_TLS_CERT_FILE")),
		TLSKeyFile:   strings.TrimSpace(getenv("MG_MAILRELAY_TLS_KEY_FILE")),
		URL:          strings.TrimSpace(getenv("MG_MAILRELAY_URL")),
		HMACKeyFile:  strings.TrimSpace(getenv("MG_MAILRELAY_HMAC_KEY_FILE")),
		CAFile:       strings.TrimSpace(getenv("MG_MAILRELAY_CA_FILE")),
	}
	if !envs[c.Env] {
		errs = append(errs, fmt.Errorf("MG_ENV must be dev, ci, staging or production, got %q", c.Env))
	}
	if err := c.LogLevel.UnmarshalText([]byte(withDefault(getenv("MG_LOG_LEVEL"), "info"))); err != nil {
		errs = append(errs, fmt.Errorf("MG_LOG_LEVEL: %w", err))
	}
	for name, addr := range map[string]string{"MG_INTERNAL_ADDR": c.InternalAddr, "MG_MAILRELAY_SMTP_ADDR": c.SMTPAddr} {
		if err := checkAddr(addr); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
		}
	}
	if c.InternalAddr == c.SMTPAddr {
		errs = append(errs, errors.New("MG_INTERNAL_ADDR and MG_MAILRELAY_SMTP_ADDR must differ"))
	}
	if v := strings.TrimSpace(getenv("MG_MAILRELAY_SMTP_CIDR")); v != "" {
		p, err := netip.ParsePrefix(v)
		if err != nil || !p.Addr().Is4() {
			errs = append(errs, errors.New("MG_MAILRELAY_SMTP_CIDR must be an IPv4 CIDR (the subnet of the `mail` network)"))
		} else {
			c.SMTPNetwork = p.Masked()
		}
	} else if !c.PlainTextAllowed() {
		errs = append(errs, errors.New("MG_MAILRELAY_SMTP_CIDR is required outside dev/ci: the SMTP listener binds to the "+
			"relay's address on the `mail` network only"))
	}
	if !hostnameRE.MatchString(c.Hostname) || len(c.Hostname) > 253 {
		errs = append(errs, errors.New("MG_MAILRELAY_HOSTNAME must be a host name"))
	}
	switch {
	case (c.TLSCertFile == "") != (c.TLSKeyFile == ""):
		errs = append(errs, errors.New("MG_MAILRELAY_TLS_CERT_FILE and MG_MAILRELAY_TLS_KEY_FILE go together"))
	case c.TLSCertFile == "" && !c.PlainTextAllowed():
		errs = append(errs, errors.New("MG_MAILRELAY_TLS_CERT_FILE and MG_MAILRELAY_TLS_KEY_FILE are required outside "+
			"dev/ci (STARTTLS with the internal CA — plain text is for the test stack only)"))
	}
	for name, p := range map[string]string{"MG_MAILRELAY_TLS_CERT_FILE": c.TLSCertFile, "MG_MAILRELAY_TLS_KEY_FILE": c.TLSKeyFile,
		"MG_MAILRELAY_CA_FILE": c.CAFile} {
		if p != "" && !filepath.IsAbs(p) {
			errs = append(errs, fmt.Errorf("%s must be an absolute path", name))
		}
	}
	if !filepath.IsAbs(c.HMACKeyFile) {
		errs = append(errs, errors.New("MG_MAILRELAY_HMAC_KEY_FILE must be the absolute path of the Worker's HMAC key (file secret)"))
	}
	if err := checkRelayURL(c.URL, c.PlainTextAllowed()); err != nil {
		errs = append(errs, err)
	}
	for _, a := range strings.Split(getenv("MG_MAILRELAY_ALLOWED_FROM"), ",") {
		if a = strings.TrimSpace(a); a == "" {
			continue
		}
		p, err := mail.ParseAddress(a)
		if err != nil || p.Name != "" || p.Address != a || strings.ContainsAny(a, "<> \t\"") {
			errs = append(errs, errors.New("MG_MAILRELAY_ALLOWED_FROM: bare sender addresses (local@domain), comma-separated"))
			break
		}
		c.AllowedFrom = append(c.AllowedFrom, strings.ToLower(a))
	}
	if len(c.AllowedFrom) == 0 {
		errs = append(errs, errors.New("MG_MAILRELAY_ALLOWED_FROM is required (the sender addresses of the Worker's binding)"))
	}
	rate, err := strconv.Atoi(withDefault(getenv("MG_MAILRELAY_RATE_PER_MINUTE"), "60"))
	if err != nil || rate < 0 || rate > 10000 {
		errs = append(errs, errors.New("MG_MAILRELAY_RATE_PER_MINUTE: an integer in [0, 10000] (0 = no limit)"))
	}
	c.Rate = rate
	if c.Timeout, err = time.ParseDuration(withDefault(getenv("MG_MAILRELAY_TIMEOUT"), "8s")); err != nil ||
		c.Timeout < 2*time.Second || c.Timeout > time.Minute {
		errs = append(errs, errors.New("MG_MAILRELAY_TIMEOUT: a duration in [2s, 1m] (below the SMTP clients' own timeouts)"))
	}
	return c, errors.Join(errs...)
}

// checkRelayURL accepts https://host[:port]/v1/send (http only on the test stack), no credentials, query or fragment.
func checkRelayURL(raw string, plainAllowed bool) error {
	u, err := url.Parse(raw)
	switch {
	case raw == "":
		return errors.New("MG_MAILRELAY_URL is required (the Worker endpoint https://…/v1/send)")
	case err != nil || u.Host == "" || u.Opaque != "":
		return errors.New("MG_MAILRELAY_URL must be an absolute URL")
	case u.Scheme != "https" && (u.Scheme != "http" || !plainAllowed):
		return errors.New("MG_MAILRELAY_URL must use https (http only in dev/ci)")
	case u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery:
		return errors.New("MG_MAILRELAY_URL must not carry credentials, a query or a fragment")
	case u.Path != MailRelaySendPath:
		return fmt.Errorf("MG_MAILRELAY_URL must end with the Worker's path %s", MailRelaySendPath)
	}
	if h := u.Hostname(); h == "" || net.ParseIP(h) == nil && !hostnameRE.MatchString(strings.ToLower(h)) {
		return errors.New("MG_MAILRELAY_URL: invalid host")
	}
	return nil
}
