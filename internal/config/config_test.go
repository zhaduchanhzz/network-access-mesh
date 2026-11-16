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
