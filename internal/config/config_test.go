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
	get, list = env(map[string]string{"MG_ENV": "staging", "MG_BASE_DOMAIN": "Example.COM"})
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
	get, list = env(map[string]string{"MG_ENV": "staging", "MG_BASE_DOMAIN": "example.com"})
	if _, err := Load("api", get, list); err == nil || !strings.Contains(err.Error(), "MG_TRUSTED_PROXIES is required") {
		t.Errorf("api in staging without MG_TRUSTED_PROXIES: got %v", err)
	}
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
