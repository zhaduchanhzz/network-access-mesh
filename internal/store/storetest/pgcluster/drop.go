package pgcluster

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
)

// The bounds of DropDatabases.
const (
	// DropBudget is the longest a harness spends dropping its databases at the end of a test binary
	// (MG_TEST_PG_CLEANUP_TIMEOUT, a Go duration, overrides it).
	DropBudget = 2 * time.Minute
	// DropParallel is how many DROP DATABASE statements run at a time, each on its own session.
	DropParallel = 4
	// dropMargin is kept free before the -test.timeout of the binary: what remains of it is the budget when it is
	// shorter than DropBudget.
	dropMargin = 15 * time.Second
	// maxListed bounds the database names printed on stderr.
	maxListed = 10
)

// processStart is when the test binary started (package initialisation runs before testing.M starts the -test.timeout
// alarm, so the budget derived from it is on the safe side).
var processStart = time.Now()

// dropOut is where DropDatabases reports (a test replaces it).
var dropOut io.Writer = os.Stderr

// DropDatabases drops the named databases of the cluster adminURL (the superuser URL of MG_TEST_PG_ADMIN_URL, any
// database) points at — DROP DATABASE IF EXISTS … WITH (FORCE) from database postgres —, DropParallel at a time, all
// within one budget: DropBudget (or MG_TEST_PG_CLEANUP_TIMEOUT), never more than what is left of the binary's
// -test.timeout minus a margin. It writes one line on stderr — label, how many were dropped, how long it took, how many
// are left and the first names — and returns the names it did not drop. It never fails: the cluster is throwaway, and
// a database left on it costs nothing, whereas a cleanup still running at -test.timeout turns a package whose tests all
// passed into a FAIL (panic: test timed out).
//
// Why a DROP can be slow: every DROP DATABASE waits for an immediate checkpoint (dropdb requests CHECKPOINT_IMMEDIATE |
// CHECKPOINT_FORCE | CHECKPOINT_WAIT, then waits for every backend of the cluster to absorb a ProcSignalBarrier), so a
// harness that drops tens of databases one by one while the other test packages of `go test ./...` write to the same
// cluster pays tens of checkpoints of their dirty buffers. Concurrent DROPs share a checkpoint.
func DropDatabases(label, adminURL string, names []string) []string {
	if len(names) == 0 {
		return nil
	}
	start := time.Now()
	budget := dropBudget()
	u, err := url.Parse(adminURL)
	if err != nil {
		report(label, len(names), names, time.Since(start), budget, errors.New("the admin URL does not parse"))
		return slices.Clone(names)
	}
	u.Path = "/postgres"
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()

	work := make(chan string)
	var (
		mu      sync.Mutex
		left    []string
		lastErr error
		wg      sync.WaitGroup
	)
	for range min(DropParallel, len(names)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var c *pgx.Conn
			defer func() {
				if c != nil {
					cctx, ccancel := context.WithTimeout(context.Background(), 5*time.Second)
					_ = c.Close(cctx)
					ccancel()
				}
			}()
			for n := range work { // every name is taken: the sender never blocks once the budget is spent
				err := ctx.Err()
				if err == nil && (c == nil || c.IsClosed()) {
					if c, err = pgx.Connect(ctx, u.String()); err != nil {
						c, err = nil, errors.New("cannot connect to database postgres") // never echo the URL
					}
				}
				if err == nil {
					_, err = c.Exec(ctx, "DROP DATABASE IF EXISTS "+pgx.Identifier{n}.Sanitize()+" WITH (FORCE)")
				}
				if err != nil {
					mu.Lock()
					left, lastErr = append(left, n), err
					mu.Unlock()
				}
			}
		}()
	}
	for _, n := range names {
		work <- n
	}
	close(work)
	wg.Wait()
	slices.Sort(left)
	report(label, len(names), left, time.Since(start), budget, lastErr)
	return left
}

// dropBudget is DropBudget (or MG_TEST_PG_CLEANUP_TIMEOUT), cut to what is left of -test.timeout minus dropMargin.
func dropBudget() time.Duration {
	b := DropBudget
	if v := strings.TrimSpace(os.Getenv("MG_TEST_PG_CLEANUP_TIMEOUT")); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			b = d
		}
	}
	if f := flag.Lookup("test.timeout"); f != nil {
		if d, err := time.ParseDuration(f.Value.String()); err == nil && d > 0 {
			b = min(b, max(time.Until(processStart.Add(d))-dropMargin, 0))
		}
	}
	return b
}

func report(label string, total int, left []string, took, budget time.Duration, err error) {
	line := fmt.Sprintf("pgcluster: %s: dropped %d/%d test databases in %s (budget %s)", label, total-len(left), total,
		took.Round(time.Millisecond), budget.Round(time.Second))
	if len(left) > 0 {
		shown := left[:min(len(left), maxListed)]
		line += fmt.Sprintf("; %d LEFT on the throwaway cluster: %s", len(left), strings.Join(shown, ", "))
		if len(left) > len(shown) {
			line += ", …"
		}
		if err != nil {
			line += " — last error: " + err.Error()
		}
	}
	_, _ = fmt.Fprintln(dropOut, line)
}
