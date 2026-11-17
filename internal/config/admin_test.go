package config

import (
	"strings"
	"testing"
)

func adminEnv() map[string]string {
	return map[string]string{
		"MG_ENV": "staging", "MG_BASE_DOMAIN": "Example.TEST", "MG_KEK_APP_DIR": "/run/secrets/kek-app",
		"MG_DB_URL": "postgres://postgres:5432/meshguard?sslmode=disable", "MG_DB_TENANT_USER": "mg_api_tenant",
		"MG_DB_TENANT_PASSWORD_FILE": "/run/secrets/db_tenant", "MG_DB_PLATFORM_USER": "mg_api_platform",
		"MG_DB_PLATFORM_PASSWORD_FILE": "/run/secrets/db_platform", "MG_EDGE_ADMIN_URL": "http://10.0.0.2:8081",
		"MG_EDGE_ADMIN_TOKEN_FILE": "/run/secrets/edge_admin_token",
	}
}

func loadAdmin(env map[string]string, needEdge bool) (Admin, error) {
	var environ []string
	for k, v := range env {
		environ = append(environ, k+"="+v)
	}
	return LoadAdmin(func(k string) string { return env[k] }, environ, needEdge)
}

func TestLoadAdmin(t *testing.T) {
	a, err := loadAdmin(adminEnv(), true)
	if err != nil {
		t.Fatal(err)
	}
	if a.BaseDomain != "example.test" || a.DB.TenantUser != "mg_api_tenant" || a.Edge.URL != "http://10.0.0.2:8081" ||
		a.Edge.TokenFile != "/run/secrets/edge_admin_token" || a.Env != "staging" {
		t.Fatalf("LoadAdmin = %+v", a)
	}
	// without the edge (register-platform-idp, set-idp-client-secret)
	env := adminEnv()
	delete(env, "MG_EDGE_ADMIN_URL")
	delete(env, "MG_EDGE_ADMIN_TOKEN_FILE")
	if _, err := loadAdmin(env, false); err != nil {
		t.Fatalf("without edge: %v", err)
	}
	if _, err := loadAdmin(env, true); err == nil {
		t.Fatal("adopt without the edge configuration accepted")
	}

	canary := "hunter2-CANARY-value"
	for name, mod := range map[string]func(map[string]string){
		"secret value in env":   func(e map[string]string) { e["MG_DB_PASSWORD"] = canary },
		"token value in env":    func(e map[string]string) { e["MG_EDGE_ADMIN_TOKEN"] = canary },
		"credentials in URL":    func(e map[string]string) { e["MG_DB_URL"] = "postgres://u:" + canary + "@db:5432/x" },
		"password query in URL": func(e map[string]string) { e["MG_DB_URL"] = "postgres://db:5432/x?password=" + canary },
		"same role twice":       func(e map[string]string) { e["MG_DB_PLATFORM_USER"] = "mg_api_tenant" },
		"not an mg role":        func(e map[string]string) { e["MG_DB_TENANT_USER"] = "postgres" },
		"relative password":     func(e map[string]string) { e["MG_DB_TENANT_PASSWORD_FILE"] = "db_tenant" },
		"no base domain":        func(e map[string]string) { delete(e, "MG_BASE_DOMAIN") },
		"no keyring":            func(e map[string]string) { delete(e, "MG_KEK_APP_DIR") },
		"kek-ops":               func(e map[string]string) { e["MG_KEK_OPS_DIR"] = "/run/secrets/kek-ops" },
		"edge URL with path":    func(e map[string]string) { e["MG_EDGE_ADMIN_URL"] = "http://10.0.0.2:8081/api" },
		"edge URL with user":    func(e map[string]string) { e["MG_EDGE_ADMIN_URL"] = "http://u:p@10.0.0.2:8081" },
		"relative token file":   func(e map[string]string) { e["MG_EDGE_ADMIN_TOKEN_FILE"] = "token" },
		"bad env":               func(e map[string]string) { e["MG_ENV"] = "prod" },
	} {
		env := adminEnv()
		mod(env)
		_, err := loadAdmin(env, true)
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if strings.Contains(err.Error(), canary) {
			t.Errorf("%s: the error repeats the value: %v", name, err)
		}
	}
}
