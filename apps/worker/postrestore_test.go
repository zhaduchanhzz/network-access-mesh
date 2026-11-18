package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/zhaduchanhzz/network-access-mesh/internal/config"
	"github.com/zhaduchanhzz/network-access-mesh/internal/devices"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/postrestore"
)

type fakeReconciler struct {
	reqs []postrestore.Request
	rep  postrestore.Report
	err  error
}

func (f *fakeReconciler) Run(_ context.Context, req postrestore.Request) (postrestore.Report, error) {
	f.reqs = append(f.reqs, req)
	return f.rep, f.err
}

// TestPostRestoreCommand: flags (an RFC 3339 restore point is required), exit codes (0 completed, 3 incomplete, 1
// failed, 2 usage, configuration or refused request) and the report as the JSON document on stdout.
func TestPostRestoreCommand(t *testing.T) {
	rec := &fakeReconciler{}
	vars := wiredWorkerEnv(t)
	env := postRestoreEnv{getenv: func(k string) string { return vars[k] },
		open: func(context.Context, config.Config, io.Writer) (reconciler, func(), error) {
			return rec, func() {}, nil
		}}
	for k, v := range vars {
		env.environ = append(env.environ, k+"="+v)
	}
	run := func(args ...string) (int, string, string) {
		var out, errb bytes.Buffer
		code := postRestore(context.Background(), args, &out, &errb, env)
		return code, out.String(), errb.String()
	}
	for _, args := range [][]string{{}, {"--restore-point", "yesterday"}, {"--restore-point", "2026-11-18"},
		{"--restore-point", "2026-11-18T02:30:00Z", "extra"}, {"--dry"}} {
		if code, _, _ := run(args...); code != 2 {
			t.Errorf("%v: exit %d, want 2", args, code)
		}
	}
	if len(rec.reqs) != 0 {
		t.Fatalf("usage errors reached the reconcile: %+v", rec.reqs)
	}
	rec.rep = postrestore.Report{Schema: postrestore.ReportSchema, Status: postrestore.StatusCompleted, DryRun: true}
	code, out, _ := run("--restore-point", "2026-11-18T02:30:00Z", "--dry-run")
	var rep postrestore.Report
	if err := json.Unmarshal([]byte(out), &rep); err != nil || code != 0 || rep.Status != postrestore.StatusCompleted {
		t.Fatalf("completed: %d %q %v", code, out, err)
	}
	if want := time.Date(2026, 11, 18, 2, 30, 0, 0, time.UTC); !rec.reqs[0].RestorePoint.Equal(want) || !rec.reqs[0].DryRun {
		t.Fatalf("request %+v", rec.reqs[0])
	}
	rec.rep = postrestore.Report{Status: postrestore.StatusIncomplete, Incomplete: []string{"instances:host:agent_not_configured"}}
	if code, _, stderr := run("--restore-point", "2026-11-18T09:30:00+07:00"); code != 3 || !strings.Contains(stderr, "INCOMPLETE") ||
		rec.reqs[1].DryRun {
		t.Fatalf("incomplete: %d %s", code, stderr)
	}
	rec.rep, rec.err = postrestore.Report{Status: postrestore.StatusFailed}, errors.New("database gone")
	if code, out, _ := run("--restore-point", "2026-11-18T02:30:00Z"); code != 1 || !strings.Contains(out, `"status": "failed"`) {
		t.Fatalf("failed: %d %s", code, out)
	}
	rec.err = postrestore.ErrInvalidRequest
	if code, _, _ := run("--restore-point", "2026-11-18T02:30:00Z"); code != 2 {
		t.Fatalf("refused request: %d", code)
	}
	env.getenv = func(string) string { return "" }
	env.environ = nil
	if code, _, stderr := run("--restore-point", "2026-11-18T02:30:00Z"); code != 2 || !strings.Contains(stderr, "not configured") {
		t.Fatalf("not wired: %d %s", code, stderr)
	}
}

// TestInventorySyncKind: the kind the reconcile enqueues is the devices module's (provisioning may not import devices
// — §13.6 — so the two constants are tied here).
func TestInventorySyncKind(t *testing.T) {
	if postrestore.InventorySyncKind != devices.KindSync {
		t.Fatalf("postrestore.InventorySyncKind %q ≠ devices.KindSync %q", postrestore.InventorySyncKind, devices.KindSync)
	}
}
