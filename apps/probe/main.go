// Command meshguard-probe is the Prober of the platform (P3-T03a; §14.4, §16.1, §11.3 steps 17–18 of the master
// plan): STUN binding to the shared STUN responder of the public entry, HTTPS GET to an IP with an explicit SNI and
// Host, and the edge (step 18) and relay (step 17) checks built on them — see apps/probe/prober. It holds no secret.
//
//	meshguard-probe [serve]           the service: RPC API for the worker on MG_PROBE_LISTEN (default :8080) +
//	                                  internal listener MG_INTERNAL_ADDR (default :9090: /healthz, /readyz, /metrics,
//	                                  and /probe — one probe per scrape for Prometheus, P3-T16)
//	meshguard-probe run <kind>        one probe in this process; the request (JSON) on stdin, the result on stdout
//	meshguard-probe call <kind>       the same through the RPC API of a running service (--url, default
//	                                  MG_PROBER_URL) — what the worker does
//	meshguard-probe selftest          stub STUN responder + stub edge on loopback, every probe kind through the RPC API
//	meshguard-probe healthcheck       container healthcheck: /readyz of the internal listener
//	meshguard-probe alertsink         the internal alert channel of staging (P3-T16): receiver of Alertmanager's
//	                                  webhook on MG_ALERTSINK_LISTEN (default :8080) + the internal listener — see
//	                                  apps/probe/alertsink (MG_ALERTSINK_ALLOW_CALLERS required)
//	meshguard-probe version
//
// <kind> is stun, https, edge or relay. Exit status: 0 = the probe passed (selftest: every case), 1 = the probe ran
// and failed (the result is printed), 2 = usage or configuration error, 3 = the probe could not run (invalid request,
// target or caller not allowed, RPC failure — {"error": …} is printed).
//
// Configuration (environment; no secret): MG_PROBE_ALLOW_CALLERS and MG_PROBE_ALLOW_TARGETS (required by serve:
// comma-separated IPs/CIDRs — RPC clients, probe targets), MG_PROBE_ALLOW_SCRAPERS (callers of /probe — Prometheus;
// unset: every scrape is refused), MG_PROBE_CAPVER (capability version of the key module, default 113),
// MG_PROBE_CA_FILE (PEM roots that REPLACE the system roots — the dev/CI CA; unset in production, where the edge has a
// public ACME certificate), MG_PROBE_MAX_INFLIGHT (default 8), MG_LOG_LEVEL (default info). `run` allows exactly the
// targets named in its request.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/buildinfo"
)

const usage = `usage: meshguard-probe [serve]
       meshguard-probe run <stun|https|edge|relay>                 (request JSON on stdin)
       meshguard-probe call [--url http://prober:8080] <stun|https|edge|relay>   (request JSON on stdin)
       meshguard-probe selftest
       meshguard-probe healthcheck
       meshguard-probe alertsink
       meshguard-probe version
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	code := dispatch(ctx, os.Args[1:], os.Getenv, os.Stdin, os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

// dispatch runs one subcommand and returns the exit status. Arguments are never echoed back.
func dispatch(ctx context.Context, args []string, getenv func(string) string, stdin io.Reader, stdout, stderr io.Writer) int {
	cmd := "serve"
	if len(args) > 0 {
		cmd, args = args[0], args[1:]
	}
	switch cmd {
	case "version":
		if len(args) == 0 {
			_, _ = fmt.Fprintf(stdout, "meshguard-probe %s (%s)\n", buildinfo.Version, buildinfo.Commit)
			return 0
		}
	case "serve":
		if len(args) == 0 {
			return serveCmd(ctx, getenv, stdout, stderr)
		}
	case "healthcheck":
		if len(args) == 0 {
			return healthcheck(getenv, stdout)
		}
	case "selftest":
		if len(args) == 0 {
			return selftest(ctx, stdout)
		}
	case "alertsink":
		if len(args) == 0 {
			return alertsinkCmd(ctx, getenv, stdout, stderr)
		}
	case "run":
		if len(args) == 1 && validKind(args[0]) {
			return runCmd(ctx, args[0], getenv, stdin, stdout, stderr)
		}
	case "call":
		fs := flag.NewFlagSet("call", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		url := fs.String("url", getenv("MG_PROBER_URL"), "")
		if err := fs.Parse(args); err == nil && fs.NArg() == 1 && validKind(fs.Arg(0)) {
			return callCmd(ctx, *url, fs.Arg(0), stdin, stdout, stderr)
		}
	}
	_, _ = fmt.Fprint(stderr, "meshguard-probe: unknown subcommand or invalid arguments\n"+usage)
	return 2
}

func validKind(k string) bool { return k == "stun" || k == "https" || k == "edge" || k == "relay" }
