package config

import (
	"strings"
	"testing"
	"time"
)

func relayEnv() map[string]string {
	return map[string]string{
		"MG_ENV":                     "staging",
		"MG_MAILRELAY_SMTP_CIDR":     "10.249.8.0/24",
		"MG_MAILRELAY_TLS_CERT_FILE": "/run/secrets/mail_tls_cert",
		"MG_MAILRELAY_TLS_KEY_FILE":  "/run/secrets/mail_tls_key",
		"MG_MAILRELAY_URL":           "https://meshguard-mailrelay.example.workers.dev/v1/send",
		"MG_MAILRELAY_HMAC_KEY_FILE": "/run/secrets/mail_relay_hmac_key",
		"MG_MAILRELAY_ALLOWED_FROM":  "No-Reply@example.com",
	}
}

func TestMailRelayConfig(t *testing.T) {
	get, list := env(relayEnv())
	c, err := LoadMailRelay(get, list)
	if err != nil {
		t.Fatalf("LoadMailRelay: %v", err)
	}
	if c.SMTPAddr != ":587" || c.InternalAddr != ":9090" || c.Hostname != "mailrelay" || c.Rate != 60 ||
		c.Timeout != 8*time.Second || c.SMTPNetwork.String() != "10.249.8.0/24" || c.PlainTextAllowed() ||
		len(c.AllowedFrom) != 1 || c.AllowedFrom[0] != "no-reply@example.com" {
		t.Fatalf("unexpected configuration: %+v", c)
	}

	bad := []struct {
		name, key, value, want string
	}{
		{"http outside dev/ci", "MG_MAILRELAY_URL", "http://relay.example.com/v1/send", "https"},
		{"credentials in the URL", "MG_MAILRELAY_URL", "https://u:p@relay.example.com/v1/send", "credentials"},
		{"query in the URL", "MG_MAILRELAY_URL", "https://relay.example.com/v1/send?k=1", "query"},
		{"wrong path", "MG_MAILRELAY_URL", "https://relay.example.com/send", "/v1/send"},
		{"no URL", "MG_MAILRELAY_URL", "", "MG_MAILRELAY_URL is required"},
		{"relative key file", "MG_MAILRELAY_HMAC_KEY_FILE", "key", "MG_MAILRELAY_HMAC_KEY_FILE"},
		{"no TLS outside dev/ci", "MG_MAILRELAY_TLS_CERT_FILE", "", "go together"},
		{"no listen network outside dev/ci", "MG_MAILRELAY_SMTP_CIDR", "", "MG_MAILRELAY_SMTP_CIDR is required"},
		{"IPv6 listen network", "MG_MAILRELAY_SMTP_CIDR", "fd00::/64", "IPv4 CIDR"},
		{"display name in the sender list", "MG_MAILRELAY_ALLOWED_FROM", "MeshGuard <no-reply@example.com>", "bare sender"},
		{"no sender", "MG_MAILRELAY_ALLOWED_FROM", " , ", "MG_MAILRELAY_ALLOWED_FROM is required"},
		{"rate", "MG_MAILRELAY_RATE_PER_MINUTE", "-1", "MG_MAILRELAY_RATE_PER_MINUTE"},
		{"timeout too long", "MG_MAILRELAY_TIMEOUT", "5m", "MG_MAILRELAY_TIMEOUT"},
		{"same listeners", "MG_INTERNAL_ADDR", ":587", "must differ"},
		{"bad hostname", "MG_MAILRELAY_HOSTNAME", "mail_relay", "MG_MAILRELAY_HOSTNAME"},
		{"secret value in the environment", "MG_MAILRELAY_HMAC_KEY", "x", "must be passed as a file"},
		{"unknown environment", "MG_ENV", "test", "MG_ENV"},
	}
	for _, tc := range bad {
		m := relayEnv()
		m[tc.key] = tc.value
		get, list := env(m)
		if _, err := LoadMailRelay(get, list); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want %q", tc.name, err, tc.want)
		} else if strings.Contains(err.Error(), "u:p@") || strings.Contains(err.Error(), "example.workers.dev") {
			t.Errorf("%s: the error repeats a value: %v", tc.name, err)
		}
	}

	// the dev/CI stack: plain text and an http fake Worker are allowed there, and only there
	m := relayEnv()
	m["MG_ENV"] = "ci"
	m["MG_MAILRELAY_URL"] = "http://fakeworker:8787/v1/send"
	delete(m, "MG_MAILRELAY_TLS_CERT_FILE")
	delete(m, "MG_MAILRELAY_TLS_KEY_FILE")
	delete(m, "MG_MAILRELAY_SMTP_CIDR")
	get, list = env(m)
	c, err = LoadMailRelay(get, list)
	if err != nil || !c.PlainTextAllowed() || c.TLSCertFile != "" || c.SMTPNetwork.IsValid() {
		t.Fatalf("ci without TLS: %+v, %v", c, err)
	}
	m["MG_ENV"] = "production"
	get, list = env(m)
	if _, err := LoadMailRelay(get, list); err == nil || !strings.Contains(err.Error(), "https") ||
		!strings.Contains(err.Error(), "required outside dev/ci") {
		t.Fatalf("production without TLS and with http: %v", err)
	}
}
