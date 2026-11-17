//go:build linux

package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadConfigRefusals(t *testing.T) {
	dir := testDir(t)
	if _, err := LoadConfig(getenv(testEnv(dir)), environ(testEnv(dir))); err != nil {
		t.Fatalf("good configuration: %v", err)
	}
	cases := map[string]func(env map[string]string){
		"secret value in the environment":    func(env map[string]string) { env["MG_AGENT_TOKEN"] = token },
		"TCP listener":                       func(env map[string]string) { env["MG_AGENT_SOCKET"] = "tcp://0.0.0.0:7443" },
		"host:port listener":                 func(env map[string]string) { env["MG_AGENT_SOCKET"] = "0.0.0.0:7443" },
		"relative socket":                    func(env map[string]string) { env["MG_AGENT_SOCKET"] = "run/agent.sock" },
		"unclean socket path":                func(env map[string]string) { env["MG_AGENT_SOCKET"] = "/run/meshguard/../agent.sock" },
		"socket path longer than sun_path":   func(env map[string]string) { env["MG_AGENT_SOCKET"] = "/" + strings.Repeat("a", 110) },
		"no socket group outside dev":        func(env map[string]string) { delete(env, "MG_AGENT_SOCKET_GID") },
		"socket group not numeric":           func(env map[string]string) { env["MG_AGENT_SOCKET_GID"] = "mg-sec-worker" },
		"no peer UID":                        func(env map[string]string) { delete(env, "MG_AGENT_PEER_UIDS") },
		"root as peer UID":                   func(env map[string]string) { env["MG_AGENT_PEER_UIDS"] = "65532,0" },
		"peer UID is a tenant UID":           func(env map[string]string) { env["MG_AGENT_PEER_UIDS"] = "30005" },
		"peer UID not numeric":               func(env map[string]string) { env["MG_AGENT_PEER_UIDS"] = "worker" },
		"relative token file":                func(env map[string]string) { env["MG_AGENT_TOKEN_FILE"] = "token" },
		"no allowlist":                       func(env map[string]string) { delete(env, "MG_AGENT_IMAGE_ALLOWLIST_FILE") },
		"no run_uid range":                   func(env map[string]string) { delete(env, "MG_AGENT_RUN_UID_RANGE") },
		"run_uid range not min-max":          func(env map[string]string) { env["MG_AGENT_RUN_UID_RANGE"] = "30000" },
		"no tenant pool":                     func(env map[string]string) { delete(env, "MG_AGENT_TENANT_NET_POOL") },
		"no public entry":                    func(env map[string]string) { delete(env, "MG_AGENT_PUBLIC_ENTRY_IPV4") },
		"lock wait too long":                 func(env map[string]string) { env["MG_AGENT_LOCK_WAIT"] = "1h" },
		"edge container name with a slash":   func(env map[string]string) { env["MG_AGENT_EDGE_CONTAINER"] = "../mg-edge" },
		"unknown environment":                func(env map[string]string) { env["MG_ENV"] = "prod" },
		"STUN port range not min-max":        func(env map[string]string) { env["MG_AGENT_STUN_PORT_RANGE"] = "3478" },
		"log level":                          func(env map[string]string) { env["MG_LOG_LEVEL"] = "trace" },
		"secret value under another MG name": func(env map[string]string) { env["MG_AGENT_PASSWORD"] = "x" },
		"unknown driver":                     func(env map[string]string) { env["MG_AGENT_DRIVER"] = "kubernetes" },
		"Docker over TCP":                    func(env map[string]string) { env["DOCKER_HOST"] = "tcp://10.0.0.1:2375" },
		"Docker over SSH":                    func(env map[string]string) { env["DOCKER_HOST"] = "ssh://root@host" },
		"relative Docker socket":             func(env map[string]string) { env["DOCKER_HOST"] = "unix://docker.sock" },
		"relative compose binary":            func(env map[string]string) { env["MG_AGENT_COMPOSE_BIN"] = "docker-compose" },
		"unclean DOCKER_CONFIG":              func(env map[string]string) { env["DOCKER_CONFIG"] = "/tmp/../root/.docker" },
		// P3-T03: the helper image is the agent's own, pinned; the supervisor's network and period are bounded
		"no helper image with compose":   func(env map[string]string) { delete(env, "MG_AGENT_HELPER_IMAGE") },
		"helper image by tag":            func(env map[string]string) { env["MG_AGENT_HELPER_IMAGE"] = "ghcr.io/x/agent:latest" },
		"helper image digest upper case": func(env map[string]string) { env["MG_AGENT_HELPER_IMAGE"] = "sha256:" + strings.Repeat("A", 64) },
		"helper image with options": func(env map[string]string) {
			env["MG_AGENT_HELPER_IMAGE"] = "--privileged sha256:" + strings.Repeat("a", 64)
		},
		"edge network with a slash":          func(env map[string]string) { env["MG_AGENT_EDGE_NETWORK"] = "../mg-edge" },
		"supervisor interval too short":      func(env map[string]string) { env["MG_AGENT_EDGE_SUPERVISOR_INTERVAL"] = "100ms" },
		"supervisor interval too long":       func(env map[string]string) { env["MG_AGENT_EDGE_SUPERVISOR_INTERVAL"] = "1h" },
		"supervisor interval not a duration": func(env map[string]string) { env["MG_AGENT_EDGE_SUPERVISOR_INTERVAL"] = "30" },
	}
	for name, mut := range cases {
		env := testEnv(dir)
		mut(env)
		_, err := LoadConfig(getenv(env), environ(env))
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if strings.Contains(err.Error(), token) {
			t.Errorf("%s: the error leaks a value", name)
		}
	}
	t.Logf("%d refused configurations", len(cases))
}

// TestBuildDriver: none needs no Docker at all; compose needs an executable compose binary nobody else can replace,
// and starts (logging a warning) even when the engine is unreachable.
func TestBuildDriver(t *testing.T) {
	dir := testDir(t)
	env := testEnv(dir)
	env["MG_AGENT_DRIVER"] = "none"
	cfg, err := LoadConfig(getenv(env), environ(env))
	if err != nil {
		t.Fatal(err)
	}
	logs := &syncBuffer{}
	log := (&harness{logs: logs}).logger()
	if d, inv, err := buildDriver(context.Background(), cfg, log); err != nil || d.Name() != "none" || inv != nil {
		t.Fatalf("none: %v %v %v", d, inv, err)
	}
	cfg.Driver = "compose"
	cfg.DockerHost = "unix://" + filepath.Join(dir, "no-docker.sock")
	for name, mode := range map[string]os.FileMode{"missing": 0, "not executable": 0o644, "writable by group": 0o775} {
		bin := filepath.Join(dir, "compose-"+strings.ReplaceAll(name, " ", "-"))
		if mode != 0 {
			write(t, bin, "#!/bin/sh\n", mode)
		}
		cfg.ComposeBin = bin
		if _, _, err := buildDriver(context.Background(), cfg, log); err == nil {
			t.Errorf("compose binary %s: accepted", name)
		}
	}
	cfg.ComposeBin = filepath.Join(dir, "compose")
	write(t, cfg.ComposeBin, "#!/bin/sh\n", 0o755)
	d, inv, err := buildDriver(context.Background(), cfg, log)
	if err != nil || d.Name() != "compose" || inv == nil {
		t.Fatalf("compose: %v %v %v", d, inv, err)
	}
	if len(logs.lines(t, "agent_docker_unreachable")) != 1 {
		t.Fatal("an unreachable engine at start is not logged")
	}
}

func TestPrepareRefusals(t *testing.T) {
	cases := map[string]func(t *testing.T, dir string, env map[string]string){
		"token readable by others": func(t *testing.T, dir string, _ map[string]string) { chmod(t, filepath.Join(dir, "token"), 0o444) },
		"token writable by group":  func(t *testing.T, dir string, _ map[string]string) { chmod(t, filepath.Join(dir, "token"), 0o460) },
		"token too short": func(t *testing.T, dir string, _ map[string]string) {
			write(t, filepath.Join(dir, "token"), "short", 0o400)
		},
		"token is a symlink": func(t *testing.T, dir string, _ map[string]string) {
			_ = os.Remove(filepath.Join(dir, "token"))
			write(t, filepath.Join(dir, "real-token"), token, 0o400)
			if err := os.Symlink(filepath.Join(dir, "real-token"), filepath.Join(dir, "token")); err != nil {
				t.Fatal(err)
			}
		},
		"allowlist writable by group": func(t *testing.T, dir string, _ map[string]string) { chmod(t, filepath.Join(dir, "allowlist"), 0o664) },
		"allowlist with a tag": func(t *testing.T, dir string, _ map[string]string) {
			write(t, filepath.Join(dir, "allowlist"), repo+":v0.29.7\n", 0o644)
		},
		"empty allowlist": func(t *testing.T, dir string, _ map[string]string) {
			write(t, filepath.Join(dir, "allowlist"), "# nothing\n", 0o644)
		},
		"no tenants directory": func(t *testing.T, dir string, _ map[string]string) { _ = os.RemoveAll(filepath.Join(dir, "tenants")) },
		"tenants directory writable by others": func(t *testing.T, dir string, _ map[string]string) {
			chmod(t, filepath.Join(dir, "tenants"), 0o777)
		},
		"run_uid range with the worker's group": func(_ *testing.T, _ string, env map[string]string) {
			env["MG_AGENT_RUN_UID_RANGE"] = "20000-29999"
		},
		"public entry inside the tenant pool": func(_ *testing.T, _ string, env map[string]string) {
			env["MG_AGENT_PUBLIC_ENTRY_IPV4"] = "10.250.9.9"
		},
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			dir := testDir(t)
			env := testEnv(dir)
			mut(t, dir, env)
			cfg, err := LoadConfig(getenv(env), environ(env))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := cfg.Prepare(); err == nil {
				t.Fatal("accepted")
			} else if strings.Contains(err.Error(), token) {
				t.Fatal("the error leaks the token")
			}
		})
	}
}

func chmod(t *testing.T, p string, mode os.FileMode) {
	t.Helper()
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
}

func write(t *testing.T, p, content string, mode os.FileMode) {
	t.Helper()
	_ = os.Chmod(p, 0o600)
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	chmod(t, p, mode)
}
