// Command healthprobe is the HEALTHCHECK helper of the edge image (P1-T06, §14.4).
//
// The edge runtime is distroless (no shell, no curl), so Docker needs a tiny static binary to probe Caddy.
// It sends one GET to the given URL (no redirects followed) and exits 0 only if the status matches.
//
//	healthprobe <url> [expected_status]   # expected_status defaults to 204
//
// Exit codes: 0 = healthy, 1 = probe failed or unexpected status, 2 = usage error.
package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) < 1 || len(args) > 2 {
		fmt.Fprintln(os.Stderr, "usage: healthprobe <url> [expected_status]")
		return 2
	}
	want := http.StatusNoContent
	if len(args) == 2 {
		n, err := strconv.Atoi(args[1])
		if err != nil || n < 100 || n > 599 {
			fmt.Fprintln(os.Stderr, "expected_status must be an HTTP status code")
			return 2
		}
		want = n
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	// The URL comes from the container's HEALTHCHECK definition (compose), never from request input.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, args[0], nil) //nolint:gosec // fixed by HEALTHCHECK
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req) //nolint:gosec // fixed by HEALTHCHECK, see above
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	_ = resp.Body.Close()
	if resp.StatusCode != want {
		fmt.Fprintf(os.Stderr, "status %d, want %d\n", resp.StatusCode, want)
		return 1
	}
	return 0
}
