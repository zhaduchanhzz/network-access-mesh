package archtest

import (
	"fmt"
	"go/ast"
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

// ADR-05 (P3-T01): the Host Agent is the ONLY component with the Docker socket. In code: only apps/agent — and the
// compose driver it runs (internal/provisioning/driver/compose, P3-T02), which only apps/agent may import — may
// import a Docker client library or name the Docker socket. api and worker therefore never link a Docker client;
// a violation fails `go test ./...` and CI.

// dockerClients are the import path prefixes of libraries that drive the Docker Engine API.
var dockerClients = []string{
	"github.com/docker/docker", "github.com/moby/moby", "github.com/docker/cli", "github.com/docker/compose",
	"github.com/fsouza/go-dockerclient", "github.com/testcontainers/testcontainers-go", "github.com/containerd/containerd",
}

// dockerAllowed are the only trees (slash paths from the repository root) that may use them.
var dockerAllowed = []string{"apps/agent/", "internal/provisioning/driver/compose/"}

const composeDriver = modulePath + "/internal/provisioning/driver/compose"

func hasPrefixAny(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if s == p || strings.HasPrefix(s, p) || strings.HasPrefix(s, p+"/") {
			return true
		}
	}
	return false
}

// dockerViolations scans the non-test Go files of apps/ and internal/ (nested modules and testdata excluded).
func dockerViolations(root string) ([]string, error) {
	var out []string
	for _, top := range []string{"apps", "internal"} {
		base := filepath.Join(root, top)
		if _, err := os.Stat(base); err != nil {
			continue
		}
		err := filepath.WalkDir(base, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if d.Name() == "testdata" || d.Name() == "node_modules" || strings.HasPrefix(d.Name(), ".") {
					return filepath.SkipDir
				}
				if _, err := os.Stat(filepath.Join(path, "go.mod")); err == nil && path != root {
					return filepath.SkipDir // another module
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			rel, _ := filepath.Rel(root, path)
			rel = filepath.ToSlash(rel)
			allowed := hasPrefixAny(rel, dockerAllowed)
			f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
			if err != nil {
				return err
			}
			for _, imp := range f.Imports {
				p, _ := strconv.Unquote(imp.Path.Value)
				switch {
				case hasPrefixAny(p, dockerClients) && !allowed:
					out = append(out, fmt.Sprintf("%s → %s: Docker client outside apps/agent (ADR-05)", rel, p))
				case (p == composeDriver || strings.HasPrefix(p, composeDriver+"/")) && !allowed:
					out = append(out, fmt.Sprintf("%s → %s: only apps/agent may import the compose driver (ADR-05)", rel, p))
				}
			}
			if !allowed {
				ast.Inspect(f, func(n ast.Node) bool {
					if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING && strings.Contains(lit.Value, "docker.sock") {
						out = append(out, fmt.Sprintf("%s: names the Docker socket outside apps/agent (ADR-05)", rel))
					}
					return true
				})
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	sort.Strings(out)
	return out, nil
}

func TestOnlyTheAgentDrivesDocker(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	v, err := dockerViolations(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, msg := range v {
		t.Error(msg)
	}
}

// TestDockerCheckCatchesViolations proves the rule on a known tree (testdata/docker): the agent and the compose
// driver may, everyone else may not — import a client, import the compose driver, or name docker.sock.
func TestDockerCheckCatchesViolations(t *testing.T) {
	v, err := dockerViolations(filepath.Join("testdata", "docker"))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"apps/worker/worker.go → github.com/docker/docker/client: Docker client outside apps/agent (ADR-05)",
		"apps/worker/worker.go → github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/driver/compose: only apps/agent may import the compose driver (ADR-05)",
		"internal/headscale/headscale.go: names the Docker socket outside apps/agent (ADR-05)",
		"internal/provisioning/runner.go → github.com/moby/moby/client: Docker client outside apps/agent (ADR-05)",
	}
	if strings.Join(v, "\n") != strings.Join(want, "\n") {
		t.Fatalf("violations =\n%s\nwant\n%s", strings.Join(v, "\n"), strings.Join(want, "\n"))
	}
}
