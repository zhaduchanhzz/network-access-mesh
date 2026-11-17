package runner

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// Healthcheck is the container healthcheck of api and worker (`meshguard healthcheck`, compose `healthcheck:` — the
// distroless image has no shell or curl): GET /readyz on the process's own internal listener (MG_INTERNAL_ADDR, via
// loopback). Exit status 0 when every readiness probe passes, 1 otherwise; it prints only the status line.
func Healthcheck(getenv func(string) string, stdout io.Writer) int {
	addr := strings.TrimSpace(getenv("MG_INTERNAL_ADDR"))
	if addr == "" {
		addr = ":9090"
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		_, _ = fmt.Fprintln(stdout, "healthcheck: MG_INTERNAL_ADDR is not host:port")
		return 1
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+net.JoinHostPort(host, port)+"/readyz", nil)
	if err != nil {
		return 1
	}
	client := &http.Client{Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}}
	resp, err := client.Do(req)
	if err != nil {
		_, _ = fmt.Fprintln(stdout, "healthcheck: internal listener unreachable")
		return 1
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	_ = resp.Body.Close()
	_, _ = fmt.Fprintf(stdout, "healthcheck: HTTP %d %s\n", resp.StatusCode, strings.TrimSpace(string(body)))
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}
