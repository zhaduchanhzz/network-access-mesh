package pgcluster

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestRolePassword pins the derivation documented in database/README.md: every harness must compute the same value.
func TestRolePassword(t *testing.T) {
	got := RolePassword("pw", "mg_api_tenant")
	sum := sha256.Sum256([]byte("meshguard-test|pw|mg_api_tenant"))
	if got != hex.EncodeToString(sum[:]) {
		t.Fatalf("RolePassword = %s, want the documented derivation", got)
	}
	if got == RolePassword("pw", "mg_api_platform") || got == RolePassword("other", "mg_api_tenant") {
		t.Fatal("the password must depend on the role and on the superuser password")
	}
}

// TestHarnessesShareTheClusterRules: a test harness that takes its own advisory lock or derives role passwords its
// own way races the other test packages again (P2 integration: three branches had brought three different keys).
func TestHarnessesShareTheClusterRules(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	self, err := filepath.Abs("pgcluster.go")
	if err != nil {
		t.Fatal(err)
	}
	var offenders []string
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "testdata", "docs":
				return filepath.SkipDir
			}
			return nil
		}
		harness := strings.HasSuffix(path, "_test.go") ||
			strings.Contains(filepath.ToSlash(path), "/internal/store/storetest/")
		if !strings.HasSuffix(path, ".go") || !harness || filepath.Dir(path) == filepath.Dir(self) {
			return nil
		}
		b, err := os.ReadFile(path) //nolint:gosec // a file of this repository, found by walking it
		if err != nil {
			return err
		}
		src := string(b)
		if strings.Contains(src, "pg_advisory_lock(") || strings.Contains(src, `"meshguard-test|"`) ||
			strings.Contains(src, `"DROP DATABASE`) {
			rel, _ := filepath.Rel(root, path)
			offenders = append(offenders, filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range offenders {
		t.Errorf("%s takes an advisory lock, derives role passwords or drops databases itself — use pgcluster.Lock, "+
			"pgcluster.RolePassword and pgcluster.DropDatabases", f)
	}
}

// TestLockSerialises: a second Lock waits until the first is released (real PostgreSQL, like every harness).
func TestLockSerialises(t *testing.T) {
	raw := os.Getenv("MG_TEST_PG_ADMIN_URL")
	if raw == "" {
		if os.Getenv("MG_TEST_PG_REQUIRED") == "1" {
			t.Fatal("MG_TEST_PG_ADMIN_URL is not set but MG_TEST_PG_REQUIRED=1")
		}
		t.Skip("MG_TEST_PG_ADMIN_URL not set — PostgreSQL integration tests skipped")
	}
	ctx := t.Context()
	release, err := Lock(ctx, raw)
	if err != nil {
		t.Fatal(err)
	}
	acquired := make(chan func())
	failed := make(chan error, 1)
	go func() {
		r, err := Lock(ctx, raw)
		if err != nil {
			failed <- err
			return
		}
		acquired <- r
	}()
	select {
	case r := <-acquired:
		r()
		release()
		t.Fatal("a second Lock got the cluster lock while the first held it")
	case err := <-failed:
		release()
		t.Fatal(err)
	case <-time.After(500 * time.Millisecond):
	}
	release()
	select {
	case r := <-acquired:
		r()
	case err := <-failed:
		t.Fatal(err)
	case <-time.After(30 * time.Second):
		t.Fatal("the second Lock never got the cluster lock after the first was released")
	}
}

// TestLockHidesTheURL: an unparsable admin URL is reported without echoing it (it carries the superuser password).
func TestLockHidesTheURL(t *testing.T) {
	_, err := Lock(t.Context(), "postgres://postgres:canary-pw@%zz/postgres")
	if err == nil || strings.Contains(err.Error(), "canary-pw") {
		t.Fatalf("err = %v", err)
	}
}
