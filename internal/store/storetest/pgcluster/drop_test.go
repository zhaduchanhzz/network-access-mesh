package pgcluster

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"net/url"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func adminURLOrSkip(t *testing.T) string {
	t.Helper()
	raw := os.Getenv("MG_TEST_PG_ADMIN_URL")
	if raw == "" {
		if os.Getenv("MG_TEST_PG_REQUIRED") == "1" {
			t.Fatal("MG_TEST_PG_ADMIN_URL is not set but MG_TEST_PG_REQUIRED=1")
		}
		t.Skip("MG_TEST_PG_ADMIN_URL not set — PostgreSQL integration tests skipped")
	}
	return raw
}

// captureReport sends the stderr line of DropDatabases to a buffer for the test.
func captureReport(t *testing.T) *bytes.Buffer {
	t.Helper()
	var b bytes.Buffer
	prev := dropOut
	dropOut = &b
	t.Cleanup(func() { dropOut = prev })
	return &b
}

func connectPostgres(t *testing.T, raw string) *pgx.Conn {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal("the admin URL does not parse")
	}
	u.Path = "/postgres"
	c, err := pgx.Connect(t.Context(), u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close(context.Background()) })
	return c
}

func createDatabases(t *testing.T, c *pgx.Conn, n int) []string {
	t.Helper()
	var names []string
	for range n {
		b := make([]byte, 6)
		_, _ = rand.Read(b)
		name := "mgdrop_" + hex.EncodeToString(b)
		if _, err := c.Exec(t.Context(), "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
			t.Fatal(err)
		}
		names = append(names, name)
	}
	return names
}

func existing(t *testing.T, c *pgx.Conn, names []string) []string {
	t.Helper()
	rows, err := c.Query(t.Context(), "SELECT datname FROM pg_database WHERE datname = ANY($1) ORDER BY 1", names)
	if err != nil {
		t.Fatal(err)
	}
	out, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestDropDatabases: every database is dropped, also one a session is still connected to (WITH (FORCE)), and the
// report counts them; nothing is left.
func TestDropDatabases(t *testing.T) {
	raw := adminURLOrSkip(t)
	out := captureReport(t)
	c := connectPostgres(t, raw)
	names := createDatabases(t, c, 2*DropParallel+1)
	u, _ := url.Parse(raw)
	u.Path = "/" + names[0]
	busy, err := pgx.Connect(t.Context(), u.String()) // a leaked session of a test: terminated by FORCE
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = busy.Close(context.Background()) }()
	if left := DropDatabases("test", raw, names); len(left) != 0 {
		t.Fatalf("left %v; report: %s", left, out)
	}
	if got := existing(t, c, names); len(got) != 0 {
		t.Fatalf("still on the cluster: %v", got)
	}
	if want := "pgcluster: test: dropped 9/9 test databases"; !strings.Contains(out.String(), want) ||
		strings.Contains(out.String(), "LEFT") {
		t.Errorf("report %q, want %q", out, want)
	}
}

// TestDropDatabasesBounded: a DROP that cannot finish (another session holds a lock on the database object) never
// holds the caller past the budget; the database is reported as left, the others are dropped; the report never holds
// the admin URL (its password).
func TestDropDatabasesBounded(t *testing.T) {
	raw := adminURLOrSkip(t)
	out := captureReport(t)
	c := connectPostgres(t, raw)
	names := createDatabases(t, c, 3)
	stuck := names[1]
	holder := connectPostgres(t, raw)
	tx, err := holder.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	// COMMENT ON DATABASE takes a lock on the database object until the transaction ends: DROP DATABASE waits for it
	if _, err := tx.Exec(t.Context(), "COMMENT ON DATABASE "+pgx.Identifier{stuck}.Sanitize()+" IS 'held'"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MG_TEST_PG_CLEANUP_TIMEOUT", "3s")
	start := time.Now()
	left := DropDatabases("test", raw, names)
	took := time.Since(start)
	_ = tx.Rollback(context.Background())
	// The stuck database is always left. Under a loaded cluster (go test ./... runs every package's harness at once)
	// a DROP of the free ones can wait on a checkpoint past the 3s budget too: they may be left as well — the bound
	// is what this test asserts, not the cluster's speed — but the report must say exactly what was left.
	if !slices.Contains(left, stuck) {
		t.Errorf("left %v, want it to hold the stuck %s; report: %s", left, stuck, out)
	}
	if len(left) > 1 {
		t.Logf("loaded cluster: %d free database(s) also left within the 3s budget: %v", len(left)-1, left)
	}
	if took > 20*time.Second {
		t.Errorf("DropDatabases took %s with a 3s budget", took)
	}
	if got := existing(t, c, names); !slices.Equal(got, slices.Sorted(slices.Values(left))) {
		t.Errorf("on the cluster: %v, want exactly the reported left %v", got, left)
	}
	if want := fmt.Sprintf("dropped %d/3", 3-len(left)); !strings.Contains(out.String(), want) ||
		!strings.Contains(out.String(), fmt.Sprintf("%d LEFT", len(left))) || !strings.Contains(out.String(), stuck) {
		t.Errorf("report %q, want %q, %d LEFT and %s", out, want, len(left), stuck)
	}
	if pw, _ := url.Parse(raw); pw != nil {
		if p, ok := pw.User.Password(); ok && p != "" && strings.Contains(out.String(), p) {
			t.Error("the report holds the superuser password")
		}
	}
	if left := DropDatabases("test", raw, left); len(left) != 0 { // once released, they go
		t.Errorf("second drop left %v", left)
	}
}

// TestDropBudget: the budget is DropBudget, MG_TEST_PG_CLEANUP_TIMEOUT overrides it, and it never reaches past
// -test.timeout minus the margin (0 when the binary is already there: nothing is attempted).
func TestDropBudget(t *testing.T) {
	_ = captureReport(t)
	prev := processStart
	t.Cleanup(func() { processStart = prev })
	timeout := time.Duration(0)
	if f := flag.Lookup("test.timeout"); f != nil {
		timeout, _ = time.ParseDuration(f.Value.String())
	}
	if timeout <= 0 {
		t.Skip("run without -test.timeout")
	}
	processStart = time.Now() // plenty of time left
	if b := dropBudget(); timeout > DropBudget+dropMargin+time.Minute && b != DropBudget {
		t.Errorf("budget %s, want %s", b, DropBudget)
	}
	t.Setenv("MG_TEST_PG_CLEANUP_TIMEOUT", "40s")
	if b := dropBudget(); timeout > time.Minute+dropMargin && b != 40*time.Second {
		t.Errorf("budget %s with MG_TEST_PG_CLEANUP_TIMEOUT=40s", b)
	}
	t.Setenv("MG_TEST_PG_CLEANUP_TIMEOUT", "not-a-duration")
	processStart = time.Now().Add(-timeout + dropMargin + 10*time.Second) // 10 s left before the margin
	if b := dropBudget(); b > 10*time.Second || b < 8*time.Second {
		t.Errorf("budget %s with 10 s left before the margin", b)
	}
	processStart = time.Now().Add(-timeout) // at the timeout
	if b := dropBudget(); b != 0 {
		t.Errorf("budget %s at the timeout, want 0", b)
	}
	if left := DropDatabases("test", "postgres://postgres@127.0.0.1:1/postgres", []string{"a", "b"}); len(left) != 2 {
		t.Errorf("left %v with no budget", left)
	}
}
