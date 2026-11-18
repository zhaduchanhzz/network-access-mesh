package runner

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"maps"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/zhaduchanhzz/network-access-mesh/internal/relay"
)

// TestWorkerSchedules (P3-T17): workerSchedules holds every periodic schedule of the worker process — the four of
// Phase 2/3, relay.probe (P3-T05c) and, with a Host Agent and a manifest key, instance.backup (P3-T11). A schedule
// added to the worker without being listed here fails this test (or TestSchedulesOnlyInWorkControl).
func TestWorkerSchedules(t *testing.T) {
	base := []string{"apikey.rotate", "health.probe", "inventory.sync", "reconcile", "relay.probe"}
	for _, tc := range []struct {
		name string
		s    schedulers
		want []string
	}{
		{"backups off, no prober", schedulers{}, base},
		{"backups on, prober", schedulers{relays: &relay.Service{}, backupsOn: true}, append(slices.Clone(base), "instance.backup")},
	} {
		got := workerSchedules(tc.s)
		names := slices.Sorted(maps.Keys(got))
		slices.Sort(tc.want)
		if !slices.Equal(names, tc.want) {
			t.Errorf("%s: schedules %v, want %v", tc.name, names, tc.want)
		}
		for n, run := range got {
			if run == nil {
				t.Errorf("%s: schedule %s has no function", tc.name, n)
			}
		}
	}
}

// TestSchedulesOnlyInWorkControl (P3-T17): maintenance mode stops the worker's schedules only because workControl
// runs them — so no schedule may be built or started anywhere else. Over the source of the processes (apps/, tests
// excluded): every NewScheduler call is in workerSchedules (or relaySchedule, which workerSchedules calls), the map
// of workerSchedules goes only to workControl.schedules in buildWorker, and the goroutines of this package are only
// those of startBackground and workControl.startWork. The periodic jobs of jobs.Worker (RegisterPeriodic) run inside
// the job worker, which workControl stops too.
func TestSchedulesOnlyInWorkControl(t *testing.T) {
	type site struct{ file, fn string }
	var builds, relayCalls, listCalls, goStmts []site
	var wired int
	apps := filepath.Join("..", "..")
	err := filepath.WalkDir(apps, func(file string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == "node_modules" || d.Name() == "web" || d.Name() == "testdata") {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(file, ".go") || strings.HasSuffix(file, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(token.NewFileSet(), file, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(apps, file)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		inRunner := path.Dir(rel) == "internal/runner"
		for _, decl := range f.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			at := site{rel, fd.Name.Name}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.CallExpr:
					switch fun := x.Fun.(type) {
					case *ast.SelectorExpr:
						if fun.Sel.Name == "NewScheduler" {
							builds = append(builds, at)
						}
					case *ast.Ident:
						switch fun.Name {
						case "relaySchedule":
							relayCalls = append(relayCalls, at)
						case "workerSchedules":
							listCalls = append(listCalls, at)
						}
					}
				case *ast.GoStmt:
					if inRunner {
						goStmts = append(goStmts, at)
					}
				case *ast.CompositeLit:
					if id, ok := x.Type.(*ast.Ident); ok && id.Name == "workControl" {
						for _, e := range x.Elts {
							kv, ok := e.(*ast.KeyValueExpr)
							if k, isID := kv.Key.(*ast.Ident); ok && isID && k.Name == "schedules" {
								if c, ok := kv.Value.(*ast.CallExpr); ok {
									if fn, ok := c.Fun.(*ast.Ident); ok && fn.Name == "workerSchedules" && at.fn == "buildWorker" {
										wired++
									}
								}
							}
						}
					}
				}
				return true
			})
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	only := func(what string, sites []site, allowed ...string) {
		t.Helper()
		if len(sites) == 0 {
			t.Errorf("%s: none found — the test no longer sees the source", what)
		}
		for _, s := range sites {
			if path.Dir(s.file) != "internal/runner" || !slices.Contains(allowed, s.fn) {
				t.Errorf("%s in %s (%s): only %v of apps/internal/runner may — a schedule outside workControl keeps "+
					"enqueueing jobs in maintenance mode (P3-T17)", what, s.fn, s.file, allowed)
			}
		}
	}
	only("NewScheduler call", builds, "workerSchedules", "relaySchedule")
	only("relaySchedule call", relayCalls, "workerSchedules")
	only("workerSchedules call", listCalls, "buildWorker")
	only("goroutine", goStmts, "startBackground", "startWork")
	if wired != 1 {
		t.Errorf("buildWorker sets workControl{schedules: workerSchedules(…)} %d times, want 1", wired)
	}
}
