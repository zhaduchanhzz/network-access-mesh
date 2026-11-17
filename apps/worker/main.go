// Command meshguard-worker runs background jobs: orchestrator, inventory sync, key rotation, backups (§4.2, §13.5).
//
// Without arguments it runs the worker. Subcommands run once and exit, and start no listener: kek-drill, the key
// ceremony drill (P2-T04a); admin idp-bootstrap, the bootstrap of the keycloak IdP driver (P2-T05a/P2-T16 — admin.go);
// admin policy-apply, the internal command of the policy core (P3-T08a — policyapply.go); admin idp-audit-sync, one pass
// of idp.audit_sync (P3-T15 — auditsync.go); admin apikey-rotate, the rotation of a tenant's instance API key now
// (P3-T10 — apikeyrotate.go); healthcheck, the container healthcheck.
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/zhaduchanhzz/network-access-mesh/apps/internal/runner"
)

func main() {
	os.Exit(dispatch(os.Args[1:], os.Stdout, os.Stderr, func() int { return runner.Main("worker") }))
}

// dispatch picks the run mode from the command-line arguments: none ⇒ run (the worker process, unchanged);
// "kek-drill" ⇒ the key ceremony drill; anything else is a usage error (exit status 2). The error does not repeat
// the argument, in case a value that must stay secret was passed by mistake.
func dispatch(args []string, stdout, stderr io.Writer, run func() int) int {
	if len(args) == 0 {
		return run()
	}
	switch args[0] {
	case "kek-drill":
		return kekDrill(args[1:], stdout, stderr)
	case "admin":
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()
		return admin(ctx, args[1:], os.Stdin, stdout, stderr, os.Getenv, os.Environ())
	case "healthcheck":
		if len(args) == 1 {
			return runner.Healthcheck(os.Getenv, stdout)
		}
	}
	_, _ = fmt.Fprint(stderr, "meshguard-worker: unknown subcommand\nusage: meshguard-worker            (run the worker)\n"+
		"       meshguard-worker kek-drill --live <dir> --recovered <dir> [--keyring kek-app,kek-ops]\n"+
		"       meshguard-worker admin idp-bootstrap --admin-username <name> [--adopt-realm <realm>]...\n"+
		"       meshguard-worker admin policy-apply --tenant <uuid|slug> [--kind baseline|suspension] --file - < policy.hujson\n"+
		"       meshguard-worker admin idp-audit-sync   (one pass of idp.audit_sync now — P3-T15)\n"+
		"       meshguard-worker admin apikey-rotate --tenant <uuid|slug> [--force] [--allow-bootstrap]\n"+
		"       meshguard-worker healthcheck   (container healthcheck: /readyz of this process)\n")
	return 2
}
