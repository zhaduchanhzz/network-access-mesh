// Command meshguard-worker runs background jobs: orchestrator, inventory sync, key rotation, backups (§4.2, §13.5).
//
// Without arguments it runs the worker. Subcommands run once and exit, and start no listener: kek-drill, the key
// ceremony drill (P2-T04a); admin idp-bootstrap, the bootstrap of the keycloak IdP driver (P2-T05a/P2-T16 — admin.go);
// admin policy-apply, the internal command of the policy core (P3-T08a — policyapply.go); admin idp-audit-sync, one pass
// of idp.audit_sync (P3-T15 — auditsync.go); admin apikey-rotate, the rotation of a tenant's instance API key now
// (P3-T10 — apikeyrotate.go); admin relay-probe, the relay probe of a tenant's regions now (P3-T05c — relayprobe.go);
// admin post-restore-reconcile, the reconcile after PostgreSQL was restored to an older point (P3-T17 —
// postrestore.go); healthcheck, the container healthcheck. mailrelay is the one long-running subcommand:
// the SMTP bridge of the outbound e-mail relay, run as its own container from this image (P3-T05b-mail —
// mailrelay.go).
package main

import (
	"context"
	"fmt"
	"io"
	"net"
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
	case "mailrelay":
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()
		return mailRelay(ctx, args[1:], stdout, stderr, os.Getenv, os.Environ(), net.InterfaceAddrs)
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
		"       meshguard-worker admin relay-probe --tenant <uuid|slug>   (the tenant's relay regions now — P3-T05c)\n"+
		"       meshguard-worker admin post-restore-reconcile --restore-point <RFC 3339> [--dry-run]\n"+
		"       meshguard-worker admin mail-test --to <address>   (one test e-mail through MG_SMTP_* — P3-T05b-mail)\n"+
		"       meshguard-worker mailrelay     (SMTP bridge to the Cloudflare Worker — P3-T05b-mail, MG_MAILRELAY_*)\n"+
		"       meshguard-worker healthcheck   (container healthcheck: /readyz of this process)\n")
	return 2
}
