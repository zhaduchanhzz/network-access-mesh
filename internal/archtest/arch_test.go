// Package archtest enforces the module dependency rules of §13.6 on every package under internal/:
// a module may import only the modules it is allowed to (plus the base modules, for business modules), never a
// module it is explicitly forbidden to use, and every module must be declared in the table below first.
// It also enforces §6.1 "lint cấm dùng pool trực tiếp": only internal/store may import a database driver, so every
// query goes through store.WithTenantTx / store.WithPlatformTx (P2-T03).
// A violation fails `go test ./...` and therefore CI (P2-T01).
package archtest

import (
	"fmt"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

const modulePath = "github.com/zhaduchanhzz/network-access-mesh"

// base modules may be used by every business module (§13.6, last paragraph); `kit` holds technical utilities
// (logging, HTTP plumbing, build info) and imports no module.
var base = []string{"store", "config", "audit", "jobs", "notifications", "kit"}

// allowed lists, per module, the modules it may import (§13.6 column "Phụ thuộc vào"). "*" = any non-forbidden module.
var allowed = map[string][]string{
	// base and foundation modules: only what is listed (kit is always allowed)
	"store":         {},
	"config":        {"store"},
	"audit":         {"store"},
	"jobs":          {"store"},
	"notifications": {"audit", "store", "jobs"}, // jobs: notification.send enqueued in the event's transaction (P3-T05b)
	"secrets":       {"store"},
	"authz":         {"store"},
	"kit":           {},
	// business modules: what is listed + base modules
	"identity":     {"audit", "config", "idp"},
	"idp":          {"secrets"},
	"tenants":      {"identity", "audit", "jobs"},
	"members":      {"tenants", "identity", "headscale", "idp", "audit", "notifications"},
	"headscale":    {"tenants", "secrets"},
	"devices":      {"headscale", "tenants", "audit", "usage"},
	"policies":     {"headscale", "tenants", "audit", "usage"},
	"network":      {"headscale", "tenants", "audit", "usage"},
	"enrollment":   {"headscale", "tenants", "audit", "usage"},
	"provisioning": {"tenants", "headscale", "secrets", "relay", "idp", "platform", "policies", "agentclient"},
	"agentclient":  {},
	"relay":        {"tenants"},
	"monitoring":   {"tenants"},
	"usage":        {"tenants"},
	"platform":     {"tenants", "relay"},
	"httpapi":      {"*"},
	"archtest":     {},
}

// forbidden edges are rejected even when another rule would allow them (§13.6 column "Không được phụ thuộc").
var forbidden = map[string][]string{
	"identity":      {"headscale", "provisioning"},
	"tenants":       {"usage", "provisioning", "headscale", "members"},
	"members":       {"policies", "devices", "provisioning"},
	"httpapi":       {"headscale", "store"},
	"authz":         {"headscale", "provisioning"},
	"platform":      {"headscale"},
	"relay":         {"policies", "devices"},
	"monitoring":    {"policies", "devices"},
	"usage":         {"policies", "devices"},
	"jobs":          {"*business*"},
	"notifications": {"*business*"},
	"secrets":       {"*business*"},
	"idp":           {"*business*"},
	"store":         {"*"},
	"config":        {"*except-store*"},
}

var baseOrFoundation = map[string]bool{"store": true, "config": true, "audit": true, "jobs": true, "notifications": true, "secrets": true, "authz": true, "kit": true, "archtest": true}

// imports returns module → set of internal modules it imports (non-test files only).
func imports(root string) (map[string]map[string]bool, error) {
	out := map[string]map[string]bool{}
	internalDir := filepath.Join(root, "internal")
	err := filepath.WalkDir(internalDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == "testdata" || strings.HasPrefix(d.Name(), ".")) {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, _ := filepath.Rel(internalDir, path)
		mod := strings.Split(filepath.ToSlash(rel), "/")[0]
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		if out[mod] == nil {
			out[mod] = map[string]bool{}
		}
		for _, imp := range f.Imports {
			p, _ := strconv.Unquote(imp.Path.Value)
			if dep, ok := strings.CutPrefix(p, modulePath+"/internal/"); ok {
				if d := strings.Split(dep, "/")[0]; d != mod {
					out[mod][d] = true
				}
			}
		}
		return nil
	})
	return out, err
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// violations checks the import graph of the repository rooted at root.
func violations(root string) ([]string, error) {
	graph, err := imports(root)
	if err != nil {
		return nil, err
	}
	var out []string
	for mod, deps := range graph {
		if _, known := allowed[mod]; !known {
			out = append(out, fmt.Sprintf("internal/%s: module not declared in the §13.6 table (add it to archtest first)", mod))
			continue
		}
		for dep := range deps {
			if _, known := allowed[dep]; !known {
				out = append(out, fmt.Sprintf("internal/%s → %s: imported module not declared in §13.6", mod, dep))
				continue
			}
			f := forbidden[mod]
			switch {
			case contains(f, dep), contains(f, "*"),
				contains(f, "*business*") && !baseOrFoundation[dep],
				contains(f, "*except-store*") && dep != "store" && dep != "kit":
				out = append(out, fmt.Sprintf("internal/%s → %s: forbidden by §13.6", mod, dep))
			case dep == "kit", contains(allowed[mod], dep), contains(allowed[mod], "*"):
			case !baseOrFoundation[mod] && contains(base, dep):
			default:
				out = append(out, fmt.Sprintf("internal/%s → %s: not an allowed dependency (§13.6)", mod, dep))
			}
		}
	}
	sort.Strings(out)
	return out, nil
}

func TestModuleDependencies(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	v, err := violations(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, msg := range v {
		t.Error(msg)
	}
}

// TestCheckerCatchesViolations proves the checker fails on a known-bad tree (testdata/bad).
func TestCheckerCatchesViolations(t *testing.T) {
	v, err := violations(filepath.Join("testdata", "bad"))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"internal/authz → headscale: forbidden by §13.6",
		"internal/devices → policies: not an allowed dependency (§13.6)",
		"internal/mystery: module not declared in the §13.6 table (add it to archtest first)",
	}
	if strings.Join(v, "\n") != strings.Join(want, "\n") {
		t.Fatalf("violations =\n%s\nwant\n%s", strings.Join(v, "\n"), strings.Join(want, "\n"))
	}
}

// drivers are the packages that can open or drive a database connection. Only internal/store (and its
// sub-packages) may import them (§6.1, §8.8 layer 3); pgx/v5/pgtype (value types in generated models) is allowed.
// River's drivers and migrator count too (P2-T12): internal/jobs uses River's types, internal/store its connections.
var drivers = []string{"database/sql", "github.com/jackc/pgx", "github.com/pressly/goose", "github.com/lib/pq",
	"github.com/riverqueue/river/riverdriver", "github.com/riverqueue/river/rivermigrate"}

func isDriver(path string) bool {
	if strings.HasPrefix(path, "github.com/jackc/pgx/v5/pgtype") {
		return false
	}
	for _, d := range drivers {
		if path == d || strings.HasPrefix(path, d+"/") {
			return true
		}
	}
	return false
}

// driverViolations lists imports of database drivers outside internal/store (non-test files).
func driverViolations(root string) ([]string, error) {
	var out []string
	internalDir := filepath.Join(root, "internal")
	err := filepath.WalkDir(internalDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == "testdata" || strings.HasPrefix(d.Name(), ".")) {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, _ := filepath.Rel(internalDir, path)
		mod := strings.Split(filepath.ToSlash(rel), "/")[0]
		if mod == "store" {
			return nil
		}
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, imp := range f.Imports {
			if p, _ := strconv.Unquote(imp.Path.Value); isDriver(p) {
				out = append(out, fmt.Sprintf("internal/%s → %s: database driver outside internal/store (§6.1)", mod, p))
			}
		}
		return nil
	})
	sort.Strings(out)
	return out, err
}

func TestOnlyStoreImportsDatabaseDrivers(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	v, err := driverViolations(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, msg := range v {
		t.Error(msg)
	}
}

// TestDriverCheckCatchesViolations proves the driver rule fails on the bad fixture and lets store and pgtype pass.
func TestDriverCheckCatchesViolations(t *testing.T) {
	v, err := driverViolations(filepath.Join("testdata", "bad"))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"internal/policies → database/sql: database driver outside internal/store (§6.1)",
		"internal/tenants → github.com/jackc/pgx/v5/pgxpool: database driver outside internal/store (§6.1)",
	}
	if strings.Join(v, "\n") != strings.Join(want, "\n") {
		t.Fatalf("driver violations =\n%s\nwant\n%s", strings.Join(v, "\n"), strings.Join(want, "\n"))
	}
}

func TestFixtureIsNotCompiled(t *testing.T) {
	// testdata is ignored by the go tool, so the bad fixture never breaks the real build.
	if _, err := os.Stat(filepath.Join("testdata", "bad", "internal", "authz", "authz.go")); err != nil {
		t.Fatal(err)
	}
}
