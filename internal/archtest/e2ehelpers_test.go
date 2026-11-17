package archtest

import (
	"path/filepath"
	"strings"
	"testing"
)

// The enrollment test helper of P3-T14a (tests/e2e/helpers) issues real pre-auth keys through the Headscale adapter;
// §20 asks for it to build "only with a test tag" — the same tag as the session fixture (the rules of fixture_test.go
// apply to it: the tag only under tests/, production binaries depend on no tests/ package).
const e2eHelpersDir = "tests/e2e/helpers"

// TestE2EHelpersNeedTheTag — every Go file of tests/e2e/helpers requires //go:build mgtestfixture, so without the tag
// the package has no Go file at all (go list), and with it the package builds.
func TestE2EHelpersNeedTheTag(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	files, err := goFiles(root)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, f := range files {
		if rest, ok := strings.CutPrefix(f.rel, e2eHelpersDir+"/"); ok && !strings.Contains(rest, "/") {
			n++
			if !requires(f.expr, fixtureTag) {
				t.Errorf("%s: file of the enrollment test helper without //go:build %s", f.rel, fixtureTag)
			}
		}
	}
	if n == 0 {
		t.Fatalf("%s: no Go file found (moved? update internal/archtest)", e2eHelpersDir)
	}
	untagged := goList(t, root, "-e", "-f", "{{if .Error}}{{.Error}}{{end}}", "./"+e2eHelpersDir)
	if !strings.Contains(untagged, "build constraints exclude all Go files") {
		t.Errorf("without -tags %s the helper still has Go files: %q", fixtureTag, untagged)
	}
	tagged := goList(t, root, "-e", "-tags", fixtureTag, "-f", "{{.Name}}{{if .Error}} {{.Error}}{{end}}", "./"+e2eHelpersDir)
	if strings.TrimSpace(tagged) != "helpers" {
		t.Errorf("with -tags %s: %q, want the package helpers", fixtureTag, tagged)
	}
}
