package config

import (
	"log/slog"
	"strings"
	"testing"
)

func env(m map[string]string) (func(string) string, []string) {
	var list []string
	for k, v := range m {
		list = append(list, k+"="+v)
	}
	return func(k string) string { return m[k] }, list
}

func TestDefaultsInDev(t *testing.T) {
	get, list := env(map[string]string{})
	cfg, err := Load("api", get, list)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Env != "dev" || cfg.HTTPAddr != ":8080" || cfg.InternalAddr != ":9090" || cfg.LogLevel != slog.LevelInfo {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
}

func TestStagingRequiresDomain(t *testing.T) {
	get, list := env(map[string]string{"MG_ENV": "staging"})
	if _, err := Load("worker", get, list); err == nil || !strings.Contains(err.Error(), "MG_BASE_DOMAIN") {
		t.Fatalf("expected MG_BASE_DOMAIN error, got %v", err)
	}
	m := wiredEnv("worker")
	m["MG_BASE_DOMAIN"] = "Example.COM"
	get, list = env(m)
	cfg, err := Load("worker", get, list)
	if err != nil || cfg.BaseDomain != "example.com" {
		t.Fatalf("Load = %+v, %v", cfg, err)
	}
}

func TestSecretValuesInEnvironmentRejected(t *testing.T) {
	for _, name := range []string{"MG_DB_PASSWORD", "MG_EDGE_ADMIN_TOKEN", "MG_OIDC_CLIENT_SECRET", "MG_KEK_KEY", "MG_SMTP_CREDENTIAL"} {
		get, list := env(map[string]string{name: "value"})
		_, err := Load("api", get, list)
		if err == nil || !strings.Contains(err.Error(), name+"_FILE") {
			t.Errorf("%s: expected rejection, got %v", name, err)
		}
	}
	get, list := env(map[string]string{"MG_DB_PASSWORD_FILE": "/run/secrets/db"})
	if _, err := Load("api", get, list); err != nil {
		t.Errorf("*_FILE must be accepted: %v", err)
	}
}

func TestTrustedProxies(t *testing.T) {
	get, list := env(map[string]string{"MG_TRUSTED_PROXIES": " 10.249.0.2, 10.249.2.0/24 ,::ffff:10.0.0.9,fd00::/8"})
	cfg, err := Load("api", get, list)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := []string{"10.249.0.2/32", "10.249.2.0/24", "10.0.0.9/32", "fd00::/8"}
	if len(cfg.TrustedProxies) != len(want) {
		t.Fatalf("TrustedProxies = %v, want %v", cfg.TrustedProxies, want)
	}
	for i, p := range cfg.TrustedProxies {
		if p.String() != want[i] {
			t.Errorf("TrustedProxies[%d] = %s, want %s", i, p, want[i])
		}
	}
	for _, bad := range []string{"edge", "10.249.0.0/33", "10.249.0.300"} {
		get, list := env(map[string]string{"MG_TRUSTED_PROXIES": bad})
		if _, err := Load("api", get, list); err == nil || !strings.Contains(err.Error(), "MG_TRUSTED_PROXIES") {
			t.Errorf("%q: expected an error, got %v", bad, err)
		}
	}
	// Required for api outside dev; the worker has no public listener.
	m := wiredEnv("api")
	delete(m, "MG_TRUSTED_PROXIES")
	get, list = env(m)
	if _, err := Load("api", get, list); err == nil || !strings.Contains(err.Error(), "MG_TRUSTED_PROXIES is required") {
		t.Errorf("api in staging without MG_TRUSTED_PROXIES: got %v", err)
	}
	get, list = env(wiredEnv("worker"))
	if _, err := Load("worker", get, list); err != nil {
		t.Errorf("worker in staging: %v", err)
	}
}

// TestKEKKeyrings: keyrings come as directory paths only (§7.6); a KEK value in the environment is refused, and the
// kek-ops keyring is accepted for the worker only.
func TestKEKKeyrings(t *testing.T) {
	get, list := env(map[string]string{"MG_KEK_APP_DIR": "/run/secrets/kek-app", "MG_KEK_OPS_DIR": "/run/secrets/kek-ops"})
	cfg, err := Load("worker", get, list)
	if err != nil || cfg.KEKAppDir != "/run/secrets/kek-app" || cfg.KEKOpsDir != "/run/secrets/kek-ops" {
		t.Fatalf("worker: %+v, %v", cfg, err)
	}
	if _, err := Load("api", get, list); err == nil || !strings.Contains(err.Error(), "MG_KEK_OPS_DIR") {
		t.Errorf("api with kek-ops: err = %v, want a refusal", err)
	}
	get, list = env(map[string]string{"MG_KEK_APP_DIR": "/run/secrets/kek-app"})
	if cfg, err := Load("api", get, list); err != nil || cfg.KEKAppDir != "/run/secrets/kek-app" || cfg.KEKOpsDir != "" {
		t.Errorf("api: %+v, %v", cfg, err)
	}
	get, list = env(map[string]string{"MG_KEK_APP_DIR": "run/secrets/kek-app"})
	if _, err := Load("api", get, list); err == nil {
		t.Error("relative keyring path accepted")
	}
	value := strings.Repeat("c4", 32) // shaped like a KEK file (64 hex characters)
	for _, name := range []string{"MG_KEK_APP", "MG_KEK", "MG_KEK_OPS_HEX"} {
		get, list := env(map[string]string{name: value})
		_, err := Load("worker", get, list)
		if err == nil || !strings.Contains(err.Error(), name+"_FILE") {
			t.Errorf("%s: expected rejection, got %v", name, err)
		} else if strings.Contains(err.Error(), value) {
			t.Errorf("%s: the error repeats the value: %v", name, err)
		}
	}
}

func TestInvalidValues(t *testing.T) {
	cases := map[string]map[string]string{
		"bad env":        {"MG_ENV": "prod"},
		"bad addr":       {"MG_HTTP_ADDR": "8080"},
		"bad port":       {"MG_INTERNAL_ADDR": ":70000"},
		"same addr":      {"MG_HTTP_ADDR": ":9000", "MG_INTERNAL_ADDR": ":9000"},
		"bad level":      {"MG_LOG_LEVEL": "loud"},
		"bad domain":     {"MG_BASE_DOMAIN": "not a domain"},
		"unknown option": {},
	}
	for name, m := range cases {
		get, list := env(m)
		service := "api"
		if name == "unknown option" {
			service = "agent"
		}
		if _, err := Load(service, get, list); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

// TestIdPEgress: the deny list of the hardened IdP client and the dial address of the platform IdP come from the
// environment of the deployment (P2-T05a, T-21); the platform IdP host is derived from MG_BASE_DOMAIN.
func TestIdPEgress(t *testing.T) {
	get, list := env(map[string]string{
		"MG_EGRESS_DENY_CIDRS": " 10.249.0.0/16,10.250.0.0/16 , 172.24.0.0/13,192.0.2.8,::ffff:198.51.100.7",
		"MG_IDP_PLATFORM_ADDR": "10.249.0.2:443", "MG_BASE_DOMAIN": "example.com",
	})
	cfg, err := Load("worker", get, list)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := []string{"10.249.0.0/16", "10.250.0.0/16", "172.24.0.0/13", "192.0.2.8/32", "198.51.100.7/32"}
	if len(cfg.EgressDeny) != len(want) {
		t.Fatalf("EgressDeny = %v, want %v", cfg.EgressDeny, want)
	}
	for i, p := range cfg.EgressDeny {
		if p.String() != want[i] {
			t.Errorf("EgressDeny[%d] = %s, want %s", i, p, want[i])
		}
	}
	if cfg.IdPPlatformAddr != "10.249.0.2:443" || cfg.IdPPlatformHost() != "auth.example.com" {
		t.Errorf("platform IdP: addr %q host %q", cfg.IdPPlatformAddr, cfg.IdPPlatformHost())
	}
	// both optional: empty deny list (the built-in ranges still apply), dial the host name itself
	get, list = env(map[string]string{})
	if cfg, err := Load("api", get, list); err != nil || len(cfg.EgressDeny) != 0 || cfg.IdPPlatformAddr != "" ||
		cfg.IdPPlatformHost() != "" {
		t.Errorf("defaults: %+v, %v", cfg, err)
	}
	for name, m := range map[string]map[string]string{
		"deny not a CIDR":   {"MG_EGRESS_DENY_CIDRS": "docker-pool"},
		"deny bad prefix":   {"MG_EGRESS_DENY_CIDRS": "10.0.0.0/33"},
		"addr without port": {"MG_IDP_PLATFORM_ADDR": "10.249.0.2"},
		"addr without host": {"MG_IDP_PLATFORM_ADDR": ":443"},
		"addr bad port":     {"MG_IDP_PLATFORM_ADDR": "edge:0"},
	} {
		get, list := env(m)
		if _, err := Load("worker", get, list); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

// wiredEnv is a complete staging configuration of api or worker as the compose project mg-app renders it (P2-T16).
func wiredEnv(service string) map[string]string {
	m := map[string]string{
		"MG_ENV": "staging", "MG_BASE_DOMAIN": "example.com", "MG_KEK_APP_DIR": "/run/secrets/kek-app",
		"MG_DB_URL":         "postgres://postgres:5432/meshguard?sslmode=disable",
		"MG_DB_TENANT_USER": "mg_" + service + "_tenant", "MG_DB_TENANT_PASSWORD_FILE": "/run/secrets/db_tenant_password",
		"MG_DB_PLATFORM_USER": "mg_" + service + "_platform", "MG_DB_PLATFORM_PASSWORD_FILE": "/run/secrets/db_platform_password",
		"MG_EDGE_ADMIN_URL": "http://10.249.2.2:8081", "MG_EDGE_ADMIN_TOKEN_FILE": "/run/secrets/edge_admin_token",
		"MG_EGRESS_DENY_CIDRS": "10.249.0.0/16,10.250.0.0/16,172.24.0.0/13,192.0.2.0/24,198.51.100.7",
		"MG_IDP_PLATFORM_ADDR": "10.249.0.2:443",
	}
	if service == "api" {
		m["MG_TRUSTED_PROXIES"] = "10.249.0.2"
		m["MG_DB_AUDIT_WRITER_PASSWORD_FILE"] = "/run/secrets/db_audit_writer_password"
	} else {
		m["MG_KEK_OPS_DIR"] = "/run/secrets/kek-ops"
		m["MG_DB_PARTITION_PASSWORD_FILE"] = "/run/secrets/db_partition_password"
	}
	return m
}

// TestWiredDependencies: outside dev (and in dev once MG_DB_URL is set) a process is wired and every dependency is
// required — the roles of its own service, both keyrings for the worker, the edge admin listener, the per-service
// secret files, the egress deny list; a dev process without MG_DB_URL stays bare (P2-T16).
func TestWiredDependencies(t *testing.T) {
	for _, service := range []string{"api", "worker"} {
		for _, e := range []string{"staging", "ci", "production"} {
			m := wiredEnv(service)
			m["MG_ENV"] = e
			if service == "worker" && e == "production" { // the notification relay is required in production (P3-T05b)
				m["MG_SMTP_ADDR"], m["MG_SMTP_FROM"] = "smtp.example.com:587", "MeshGuard <no-reply@example.com>"
			}
			get, list := env(m)
			cfg, err := Load(service, get, list)
			if err != nil || !cfg.Wired || cfg.DB.TenantUser != "mg_"+service+"_tenant" || cfg.Edge.URL == "" {
				t.Fatalf("%s/%s: %+v, %v", service, e, cfg, err)
			}
			if cfg.AppHost() != "app.example.com" || cfg.AdminHost() != "admin.example.com" ||
				cfg.IdPPlatformHost() != "auth.example.com" {
				t.Errorf("%s: hosts %q %q %q", service, cfg.AppHost(), cfg.AdminHost(), cfg.IdPPlatformHost())
			}
		}
		for _, name := range []string{"MG_DB_URL", "MG_DB_TENANT_USER", "MG_DB_TENANT_PASSWORD_FILE", "MG_DB_PLATFORM_USER",
			"MG_DB_PLATFORM_PASSWORD_FILE", "MG_EDGE_ADMIN_URL", "MG_EDGE_ADMIN_TOKEN_FILE", "MG_KEK_APP_DIR",
			"MG_BASE_DOMAIN", "MG_EGRESS_DENY_CIDRS"} {
			m := wiredEnv(service)
			delete(m, name)
			get, list := env(m)
			if _, err := Load(service, get, list); err == nil || !strings.Contains(err.Error(), name) {
				t.Errorf("%s without %s: %v", service, name, err)
			}
		}
	}
	for service, name := range map[string]string{"api": "MG_DB_AUDIT_WRITER_PASSWORD_FILE", "worker": "MG_DB_PARTITION_PASSWORD_FILE"} {
		m := wiredEnv(service)
		delete(m, name)
		get, list := env(m)
		if _, err := Load(service, get, list); err == nil || !strings.Contains(err.Error(), name) {
			t.Errorf("%s without %s: %v", service, name, err)
		}
	}
	m := wiredEnv("worker")
	delete(m, "MG_KEK_OPS_DIR")
	get, list := env(m)
	if _, err := Load("worker", get, list); err == nil || !strings.Contains(err.Error(), "MG_KEK_OPS_DIR is required") {
		t.Errorf("worker without kek-ops: %v", err)
	}
	for name, c := range map[string]struct {
		service string
		set     map[string]string
		want    string
	}{
		"api with worker roles":      {"api", map[string]string{"MG_DB_TENANT_USER": "mg_worker_tenant"}, "MG_DB_TENANT_USER must be mg_api_tenant"},
		"worker with api roles":      {"worker", map[string]string{"MG_DB_PLATFORM_USER": "mg_api_platform"}, "MG_DB_PLATFORM_USER must be mg_worker_platform"},
		"api with partition role":    {"api", map[string]string{"MG_DB_PARTITION_PASSWORD_FILE": "/run/secrets/p"}, "worker only"},
		"worker with audit writer":   {"worker", map[string]string{"MG_DB_AUDIT_WRITER_PASSWORD_FILE": "/run/secrets/a"}, "only the secrets it uses"},
		"relative audit writer":      {"api", map[string]string{"MG_DB_AUDIT_WRITER_PASSWORD_FILE": "a"}, "MG_DB_AUDIT_WRITER_PASSWORD_FILE"},
		"api with kek-ops":           {"api", map[string]string{"MG_KEK_OPS_DIR": "/run/secrets/kek-ops"}, "MG_KEK_OPS_DIR"},
		"provisioner client for api": {"api", map[string]string{"MG_IDP_PROVISIONER_CLIENT_ID": "mg-provisioner"}, "MG_IDP_PROVISIONER_CLIENT_ID"},
		"bad provisioner client":     {"worker", map[string]string{"MG_IDP_PROVISIONER_CLIENT_ID": "Bad Client"}, "MG_IDP_PROVISIONER_CLIENT_ID"},
		"credentials in the DB URL":  {"api", map[string]string{"MG_DB_URL": "postgres://u:hunter2CANARY@db:5432/x"}, "MG_DB_URL"},
		"trusted proxy range":        {"api", map[string]string{"MG_TRUSTED_PROXIES": "10.249.0.0/24"}, "single addresses"},
		"edge plus a range":          {"api", map[string]string{"MG_TRUSTED_PROXIES": "10.249.0.2,10.249.0.0/24"}, "single addresses"},
	} {
		m := wiredEnv(c.service)
		for k, v := range c.set {
			m[k] = v
		}
		get, list := env(m)
		_, err := Load(c.service, get, list)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v (want %q)", name, err, c.want)
		} else if strings.Contains(err.Error(), "hunter2CANARY") {
			t.Errorf("%s: the error repeats the value: %v", name, err)
		}
	}
	m = wiredEnv("worker")
	m["MG_IDP_PROVISIONER_CLIENT_ID"] = "mg-provisioner-2"
	get, list = env(m)
	if cfg, err := Load("worker", get, list); err != nil || cfg.IdPProvisionerClientID != "mg-provisioner-2" {
		t.Errorf("provisioner client id: %+v, %v", cfg, err)
	}
	// dev: bare without MG_DB_URL, wired (everything required) with it
	get, list = env(map[string]string{})
	if cfg, err := Load("worker", get, list); err != nil || cfg.Wired {
		t.Errorf("dev without MG_DB_URL: wired %v, %v", cfg.Wired, err)
	}
	get, list = env(map[string]string{"MG_DB_URL": "postgres://postgres:5432/meshguard"})
	if _, err := Load("api", get, list); err == nil || !strings.Contains(err.Error(), "MG_KEK_APP_DIR is required") {
		t.Errorf("dev with MG_DB_URL only: %v", err)
	}
	m = wiredEnv("api")
	m["MG_ENV"] = "dev"
	delete(m, "MG_EGRESS_DENY_CIDRS")
	get, list = env(m)
	if cfg, err := Load("api", get, list); err != nil || !cfg.Wired {
		t.Errorf("dev wired without deny list: wired %v, %v", cfg.Wired, err)
	}
}

// TestSMTPRelay (P3-T05b): MG_SMTP_* is a worker setting; no relay is allowed outside production (e-mails cancelled),
// required in production; TLS none only in dev/ci; authentication needs a password FILE and TLS; From is an address.
func TestSMTPRelay(t *testing.T) {
	load := func(service string, extra map[string]string) (Config, error) {
		m := wiredEnv(service)
		for k, v := range extra {
			m[k] = v
		}
		get, list := env(m)
		return Load(service, get, list)
	}
	cfg, err := load("worker", nil)
	if err != nil || cfg.SMTP.Addr != "" {
		t.Fatalf("no relay in staging: %+v %v", cfg.SMTP, err)
	}
	ok := map[string]string{"MG_SMTP_ADDR": "smtp.example.com:587", "MG_SMTP_FROM": "MeshGuard <no-reply@example.com>",
		"MG_SMTP_USERNAME": "mailer", "MG_SMTP_PASSWORD_FILE": "/run/secrets/smtp_password"}
	cfg, err = load("worker", ok)
	if err != nil || cfg.SMTP.TLS != "starttls" || cfg.SMTP.Username != "mailer" {
		t.Fatalf("valid relay: %+v %v", cfg.SMTP, err)
	}
	if _, err := load("worker", map[string]string{"MG_ENV": "production"}); err == nil || !strings.Contains(err.Error(), "MG_SMTP_ADDR is required") {
		t.Fatalf("production without relay: %v", err)
	}
	bad := []map[string]string{
		{"MG_SMTP_ADDR": "smtp.example.com:587"}, // no From
		{"MG_SMTP_ADDR": "smtp.example.com", "MG_SMTP_FROM": "a@example.com"},
		{"MG_SMTP_ADDR": "smtp.example.com:25", "MG_SMTP_FROM": "a@example.com", "MG_SMTP_TLS": "none"}, // staging
		{"MG_SMTP_ADDR": "smtp.example.com:25", "MG_SMTP_FROM": "a@example.com", "MG_SMTP_TLS": "ssl"},
		{"MG_SMTP_ADDR": "smtp.example.com:25", "MG_SMTP_FROM": "a@example.com", "MG_SMTP_USERNAME": "u"},
		{"MG_SMTP_ADDR": "smtp.example.com:25", "MG_SMTP_FROM": "a@example.com", "MG_SMTP_PASSWORD_FILE": "/x"},
		{"MG_SMTP_ADDR": "smtp.example.com:25", "MG_SMTP_FROM": "a@example.com", "MG_SMTP_CA_FILE": "ca.pem"},
		{"MG_SMTP_FROM": "a@example.com"}, // address missing
	}
	for _, b := range bad {
		if _, err := load("worker", b); err == nil {
			t.Errorf("accepted %v", b)
		}
	}
	if _, err := load("api", map[string]string{"MG_SMTP_ADDR": "smtp.example.com:587", "MG_SMTP_FROM": "a@example.com"}); err == nil {
		t.Error("api accepted MG_SMTP_*")
	}
	if cfg, err := load("worker", map[string]string{"MG_ENV": "ci", "MG_SMTP_ADDR": "mailpit:1025", "MG_SMTP_TLS": "none",
		"MG_SMTP_FROM": "MeshGuard <no-reply@mesh.test>"}); err != nil || cfg.SMTP.TLS != "none" {
		t.Fatalf("ci test sink: %+v %v", cfg.SMTP, err)
	}
}
