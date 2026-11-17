package archtest

import (
	"bufio"
	"bytes"
	"fmt"
	"go/build/constraint"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// The test-session fixture of P2-T15a (tests/security/sessionfixture) mints Portal sessions without any IdP. §20 asks
// for it to build "only with a test tag": every file of it — and of every package importing it — requires the build
// tag below, and no production binary may contain it nor any other test-only package.
const (
	fixtureTag = "mgtestfixture"
	fixtureDir = "tests/security/sessionfixture"
	fixturePkg = modulePath + "/" + fixtureDir
)

// testOnly are the packages a production binary must never contain: the fixture and the harnesses that only test
// code imports (PostgreSQL harness and cluster rules, fake OpenID Provider).
var testOnly = []string{
	fixturePkg,
	modulePath + "/internal/store/storetest",
	modulePath + "/internal/store/storetest/pgcluster",
	modulePath + "/internal/identity/identitytest",
}

// goFile is one Go file of the repository with its build constraint (nil when none) and imports.
type goFile struct {
	rel     string // slash-separated path from the repository root
	expr    constraint.Expr
	imports []string
}

// goFiles lists the Go files of the module (nested modules, testdata, node_modules and dot directories excluded).
func goFiles(root string) ([]goFile, error) {
	var out []goFile
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path == root {
				return nil
			}
			if n := d.Name(); n == "testdata" || n == "node_modules" || strings.HasPrefix(n, ".") {
				return filepath.SkipDir
			}
			if _, err := os.Stat(filepath.Join(path, "go.mod")); err == nil {
				return filepath.SkipDir // another module (tests/isolation/derpprobe)
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		src, err := os.ReadFile(path) //nolint:gosec // a file of this repository, found by walking it
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		f := goFile{rel: filepath.ToSlash(rel)}
		if f.expr, err = buildConstraint(src); err != nil {
			return fmt.Errorf("%s: %w", f.rel, err)
		}
		ast, err := parser.ParseFile(token.NewFileSet(), path, src, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, imp := range ast.Imports {
			p, _ := strconv.Unquote(imp.Path.Value)
			f.imports = append(f.imports, p)
		}
		out = append(out, f)
		return nil
	})
	return out, err
}

// buildConstraint returns the //go:build expression of a Go file (the comment lines before the package clause).
func buildConstraint(src []byte) (constraint.Expr, error) {
	sc := bufio.NewScanner(bytes.NewReader(src))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case constraint.IsGoBuild(line):
			return constraint.Parse(line)
		case line == "", strings.HasPrefix(line, "//"):
			continue
		}
		break // first non-comment line: the header is over
	}
	return nil, nil
}

// mentions reports whether expr uses tag.
func mentions(expr constraint.Expr, tag string) bool {
	found := false
	if expr != nil {
		expr.Eval(func(t string) bool {
			found = found || t == tag
			return true
		})
	}
	return found
}

// requires reports whether expr is false whenever tag is unset, whatever the other tags (all assignments tried).
func requires(expr constraint.Expr, tag string) bool {
	if expr == nil {
		return false
	}
	var others []string
	expr.Eval(func(t string) bool {
		if t != tag {
			others = append(others, t)
		}
		return true
	})
	if len(others) > 12 {
		return false // not a constraint this repository writes
	}
	for set := 0; set < 1<<len(others); set++ {
		on := map[string]bool{}
		for i, t := range others {
			on[t] = set&(1<<i) != 0
		}
		if expr.Eval(func(t string) bool { return t != tag && on[t] }) {
			return false
		}
	}
	return true
}

// fixtureViolations checks the build tag of the fixture: every file of the fixture package and every file importing
// it requires the tag, and the tag is only used under tests/ (CI runs `go test -tags mgtestfixture ./tests/...`).
func fixtureViolations(files []goFile) []string {
	var out []string
	inFixture := 0
	for _, f := range files {
		imports := false
		for _, p := range f.imports {
			imports = imports || p == fixturePkg
		}
		switch {
		case strings.HasPrefix(f.rel, fixtureDir+"/") && !strings.Contains(strings.TrimPrefix(f.rel, fixtureDir+"/"), "/"):
			inFixture++
			if !requires(f.expr, fixtureTag) {
				out = append(out, f.rel+": file of the session fixture without //go:build "+fixtureTag)
			}
		case imports && !requires(f.expr, fixtureTag):
			out = append(out, f.rel+": imports the session fixture without //go:build "+fixtureTag)
		}
		if mentions(f.expr, fixtureTag) && !strings.HasPrefix(f.rel, "tests/") {
			out = append(out, f.rel+": build tag "+fixtureTag+" outside tests/ (CI runs the tagged tests of ./tests/... only)")
		}
	}
	if inFixture == 0 {
		out = append(out, fixtureDir+": no Go file found (moved? update internal/archtest)")
	}
	sort.Strings(out)
	return out
}

// TestSessionFixtureNeedsItsTag — the files of the fixture and of its consumers carry //go:build mgtestfixture, so a
// build without the tag cannot even see the package.
func TestSessionFixtureNeedsItsTag(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	files, err := goFiles(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, msg := range fixtureViolations(files) {
		t.Error(msg)
	}
}

// TestFixtureCheckCatchesViolations proves the tag rules on hand-made files: untagged fixture file, `tag || x`,
// untagged importer, tag used outside tests/ — and accepts `tag`, `tag && linux`, `!windows && tag`.
func TestFixtureCheckCatchesViolations(t *testing.T) {
	parse := func(s string) constraint.Expr {
		if s == "" {
			return nil
		}
		e, err := constraint.Parse("//go:build " + s)
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	files := []goFile{
		{rel: fixtureDir + "/ok.go", expr: parse(fixtureTag)},
		{rel: fixtureDir + "/and.go", expr: parse(fixtureTag + " && linux")},
		{rel: fixtureDir + "/not.go", expr: parse("!windows && " + fixtureTag)},
		{rel: fixtureDir + "/untagged.go", expr: nil},
		{rel: fixtureDir + "/or.go", expr: parse(fixtureTag + " || linux")},
		{rel: fixtureDir + "/negated.go", expr: parse("!" + fixtureTag)},
		{rel: "tests/security/matrix/m_test.go", expr: parse(fixtureTag), imports: []string{fixturePkg}},
		{rel: "tests/security/leak/l_test.go", expr: parse("linux"), imports: []string{fixturePkg}},
		{rel: "internal/identity/x.go", expr: parse(fixtureTag)},
	}
	want := []string{
		"internal/identity/x.go: build tag " + fixtureTag + " outside tests/ (CI runs the tagged tests of ./tests/... only)",
		"tests/security/leak/l_test.go: imports the session fixture without //go:build " + fixtureTag,
		fixtureDir + "/negated.go: file of the session fixture without //go:build " + fixtureTag,
		fixtureDir + "/or.go: file of the session fixture without //go:build " + fixtureTag,
		fixtureDir + "/untagged.go: file of the session fixture without //go:build " + fixtureTag,
	}
	sort.Strings(want)
	if got := fixtureViolations(files); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("violations =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if v := fixtureViolations(nil); len(v) != 1 || !strings.Contains(v[0], "no Go file found") {
		t.Fatalf("an empty tree must fail: %v", v)
	}
}

// goList runs the go command of this toolchain (go test puts its GOROOT/bin first in PATH) in the repository root.
func goList(t *testing.T, root string, args ...string) string {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), "go", append([]string{"list"}, args...)...) //nolint:gosec // fixed arguments
	cmd.Dir = root
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list %s: %v\n%s", strings.Join(args, " "), err, stderr.String())
	}
	return string(out)
}

// TestProductionBinariesExcludeTestFixtures — `go list -deps` of apps/api and apps/worker, without the tag (the
// production build, infrastructure/docker/app/Dockerfile) and even with it, contains neither the session fixture nor
// another test-only package; and without the tag the fixture has no Go file, so no untagged build can import it.
func TestProductionBinariesExcludeTestFixtures(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	for _, tags := range [][]string{nil, {"-tags", fixtureTag}} {
		args := append(append([]string{"-deps", "-f", "{{.ImportPath}}"}, tags...), "./apps/api", "./apps/worker")
		deps := strings.Fields(goList(t, root, args...))
		has := map[string]bool{}
		for _, p := range deps {
			has[p] = true
			if strings.HasPrefix(p, modulePath+"/tests/") {
				t.Errorf("go list %v: production binaries depend on %s", tags, p)
			}
		}
		for _, p := range testOnly {
			if has[p] {
				t.Errorf("go list %v: production binaries depend on the test-only package %s", tags, p)
			}
		}
		if !has[modulePath+"/apps/internal/runner"] || !has[modulePath+"/internal/httpapi"] || len(deps) < 50 {
			t.Fatalf("go list %v returned an implausible dependency list (%d packages)", tags, len(deps))
		}
	}
	untagged := goList(t, root, "-e", "-f", "{{if .Error}}{{.Error}}{{end}}", "./"+fixtureDir)
	if !strings.Contains(untagged, "build constraints exclude all Go files") {
		t.Errorf("without -tags %s the fixture still has Go files: %q", fixtureTag, untagged)
	}
	tagged := goList(t, root, "-e", "-tags", fixtureTag, "-f", "{{.Name}}{{if .Error}} {{.Error}}{{end}}", "./"+fixtureDir)
	if strings.TrimSpace(tagged) != "sessionfixture" {
		t.Errorf("with -tags %s: %q, want the package sessionfixture", fixtureTag, tagged)
	}
}
