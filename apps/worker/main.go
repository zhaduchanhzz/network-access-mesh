// Command meshguard-worker runs background jobs: orchestrator, inventory sync, key rotation, backups (§4.2, §13.5).
//
// Without arguments it runs the worker. The only subcommand is kek-drill, the key ceremony drill (P2-T04a): it runs
// once and exits, and starts no listener.
package main

import (
	"fmt"
	"io"
	"os"

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
	if args[0] == "kek-drill" {
		return kekDrill(args[1:], stdout, stderr)
	}
	_, _ = fmt.Fprint(stderr, "meshguard-worker: unknown subcommand\nusage: meshguard-worker            (run the worker)\n"+
		"       meshguard-worker kek-drill --live <dir> --recovered <dir> [--keyring kek-app,kek-ops]\n")
	return 2
}
