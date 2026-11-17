// Command meshguard-api serves the SaaS REST API (/api/v1) and the internal endpoints (§4.2, §13).
//
// Without arguments it runs the api. `meshguard admin <command>` runs ONE host-only administration command and exits
// (§4.4: adopt-instance, register-platform-idp, set-idp-client-secret — P2-T11; bootstrap-super-admin,
// seed-membership — P2-T11a); it starts no listener and is never reachable through the API. `migrate
// bootstrap|up|status` is the one-shot database job of the compose project mg-app and `healthcheck` the container
// healthcheck (P2-T16).
package main

import (
	"context"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/zhaduchanhzz/network-access-mesh/apps/internal/runner"
)

func main() {
	os.Exit(dispatch(os.Args[1:], os.Stdin, os.Stdout, os.Stderr, func() int { return runner.Main("api") }))
}

// dispatch picks the run mode from the command-line arguments: none ⇒ run (the api process, unchanged); "admin" ⇒
// one administration command; anything else is a usage error (exit status 2). Errors never repeat an argument, in
// case a value that must stay secret was passed by mistake.
func dispatch(args []string, stdin stdinFile, stdout, stderr io.Writer, run func() int) int {
	if len(args) == 0 {
		return run()
	}
	switch args[0] {
	case "admin":
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()
		return admin(ctx, args[1:], adminIO{stdin: stdin, stdout: stdout, stderr: stderr, getenv: os.Getenv,
			environ: os.Environ()})
	case "migrate":
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()
		return migrate(ctx, args[1:], os.Getenv, os.Environ(), stdout, stderr)
	case "healthcheck":
		if len(args) == 1 {
			return runner.Healthcheck(os.Getenv, stdout)
		}
	}
	_, _ = io.WriteString(stderr, "meshguard-api: unknown subcommand\n"+
		"usage: meshguard-api                       (run the api)\n"+
		"       meshguard-api admin <command> ...   (host-only administration — `meshguard-api admin` lists them)\n"+
		"       meshguard-api migrate bootstrap|up|status   (one-shot database job of mg-app)\n"+
		"       meshguard-api healthcheck           (container healthcheck: /readyz of this process)\n")
	return 2
}
