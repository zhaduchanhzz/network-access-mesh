package main

// `meshguard admin maintenance on|off|status` (P3-T17, §17.2): the persisted maintenance flag (system_settings
// `maintenance` — internal/platform/maintenance.go), polled by every api and worker process: ON ⇒ the api answers 503
// maintenance except the platform sign-in on admin.<domain>, the worker runs no job and no schedule. The startup switch
// MG_MAINTENANCE of the processes is independent (the restore runbook starts api and worker with it, because the
// restored database does not hold this flag). Changes are audited platform.maintenance.enable / .disable (actor_type
// system, request id admin-<uuid>). `off` is refused while the post-restore reconcile recorded in the flag is running
// or failed — `--force` overrides it (the event says so). Output: one JSON object (the flag after the command — no
// secret). Exit status: 0 done (also when nothing changed), 1 refused or failed, 2 usage.
//
// Runs beside the api like the other admin commands — `docker compose -p mg-app run --rm --no-deps -T api admin
// maintenance …` (also while api and worker are stopped: only the database is needed) or `exec` in the running api.

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/platform"
)

// maintenanceOutput is the JSON result of the command.
type maintenanceOutput struct {
	Enabled     bool                  `json:"enabled"`
	Changed     bool                  `json:"changed"`
	Reason      string                `json:"reason,omitempty"`
	Since       *time.Time            `json:"since,omitempty"`
	By          string                `json:"by,omitempty"`
	PostRestore *platform.PostRestore `json:"post_restore,omitempty"`
	Note        string                `json:"note,omitempty"`
}

func runMaintenance(ctx context.Context, args []string, aio adminIO) int {
	const cmd = "maintenance"
	if len(args) == 0 {
		return usageError(aio, cmd, "on, off or status expected")
	}
	verb := args[0]
	fset := flag.NewFlagSet(cmd, flag.ContinueOnError)
	reason := fset.String("reason", "", "why (a short code, [a-z0-9_.-])")
	force := fset.Bool("force", false, "turn it off although the post-restore reconcile is running or failed")
	if err := parseFlags(fset, args[1:]); err != nil || fset.NArg() != 0 {
		return usageError(aio, cmd, "invalid flags")
	}
	switch {
	case verb != "on" && verb != "off" && verb != "status":
		return usageError(aio, cmd, "on, off or status expected")
	case *reason != "" && verb != "on":
		return usageError(aio, cmd, "--reason goes with on")
	case *force && verb != "off":
		return usageError(aio, cmd, "--force goes with off")
	}
	d, err := openDeps(ctx, aio, false)
	if err != nil {
		return fail(aio, cmd, err)
	}
	defer d.close()
	svc := platform.New(d.st)
	out := maintenanceOutput{}
	var m platform.Maintenance
	if verb == "status" {
		if m, err = svc.Maintenance(ctx); err != nil {
			return fail(aio, cmd, err)
		}
	} else {
		res, err := svc.SetMaintenance(ctx, platform.MaintenanceChange{Enable: verb == "on", Reason: *reason, Force: *force,
			Actor: platform.SystemActor{Command: "meshguard admin maintenance " + verb,
				RequestID: "admin-" + uuid.Must(uuid.NewV7()).String()}})
		if err != nil {
			if errors.Is(err, platform.ErrPostRestorePending) {
				_, _ = fmt.Fprintf(aio.stderr, "meshguard admin %s: the post-restore reconcile has not completed: run "+
					"`meshguard admin post-restore-reconcile` (worker) again and review its report — nothing was changed\n", cmd)
			}
			return fail(aio, cmd, err)
		}
		m, out.Changed = res.After, res.Changed
	}
	out.Enabled, out.Reason, out.Since, out.By, out.PostRestore = m.Enabled, m.Reason, m.Since, m.By, m.PostRestore
	if !m.Enabled {
		out.Note = "processes started with MG_MAINTENANCE=1 stay in maintenance until restarted without it"
	}
	if m.PostRestore != nil && m.PostRestore.Status == platform.PostRestoreReconciled && len(m.PostRestore.Incomplete) > 0 {
		out.Note = fmt.Sprintf("the last post-restore reconcile was incomplete (%d item(s)) — see its report", len(m.PostRestore.Incomplete))
	}
	b, _ := json.Marshal(out)
	_, _ = fmt.Fprintf(aio.stdout, "%s\n", b)
	return 0
}
