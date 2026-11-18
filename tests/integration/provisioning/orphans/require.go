package orphans

import (
	"context"
	"strings"
	"testing"
)

// Require is the test helper: it collects the inventory of the run, logs what was covered and fails the test with
// every finding (nothing may be left behind that the registry does not account for). It returns the inventory for
// further assertions.
func Require(tb testing.TB, ctx context.Context, src Sources, scope Scope) Inventory { //nolint:revive // testing.TB first, like t.Helper users
	tb.Helper()
	inv, err := Collect(ctx, src, scope)
	if err != nil {
		tb.Fatalf("orphan detector: %v", err)
	}
	fs := Check(inv)
	tb.Logf("orphan detector: %d finding(s) — %s", len(fs), inv.Summary())
	if len(fs) > 0 {
		lines := make([]string, 0, len(fs))
		for _, f := range fs {
			lines = append(lines, "  "+f.String())
		}
		tb.Fatalf("orphan detector: resources left behind or missing:\n%s", strings.Join(lines, "\n"))
	}
	return inv
}
