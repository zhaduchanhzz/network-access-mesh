package main

// `meshguard-worker admin upgrade-wave` — upgrade the Headscale instances to one image in waves (P3-T13a, §11.4 Upgrade:
// "canary trước, rồi từng nhóm, tự dừng ở health gate lỗi đầu tiên"): the canary alone, then the other instances with at
// most --max-parallel unfinished upgrades; the first upgrade that does not succeed (or cannot be enqueued) stops the
// wave — no further instance is enqueued, the ones in flight are awaited. Each upgrade is an ordinary instance.upgrade
// job (preflight, cold backup, configtest of the target binary on a copy, switch, gates, rollback by restore) run by the
// workers of the platform; this command only enqueues them (audit actor system "upgrade-wave", source admin_wave) and
// follows their status. An instance already on the image is skipped; running the command again resumes a stopped wave.
//
//	docker compose -p mg-app exec -T worker /usr/local/bin/meshguard admin upgrade-wave --image sha256:<64 hex> \
//	    (--canary <instance uuid>) (--instances <uuid>,<uuid>… | --all) [--max-parallel N] [--job-timeout 20m] [--dry-run]
//
// Output: one JSON object per event (planned, skipped, enqueued, succeeded, failed, refused) then the report. Exit
// status: 0 the wave completed; 1 it stopped at a failure (or could not run); 2 usage or configuration error.

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/config"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/logx"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/orchestrator"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
)

const upgradeWaveUsage = `usage: meshguard-worker admin upgrade-wave --image sha256:<64 hex> (--canary <instance uuid>)
    (--instances <uuid>,<uuid>… | --all) [--max-parallel N] [--job-timeout 20m] [--dry-run]
  runs inside the worker container: docker compose -p mg-app exec -T worker /usr/local/bin/meshguard admin upgrade-wave …
  the canary first, alone; then at most N unfinished upgrades (1..20, default 1); the first failure stops the wave
`

var digestFlagRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// upgradeWaveEnv is what the command needs from the process: the configuration and an opener of the store (tests).
type upgradeWaveEnv struct {
	getenv  func(string) string
	environ []string
	open    func(ctx context.Context, cfg config.Config) (*store.Store, func(), error)
	run     func(ctx context.Context, cfg orchestrator.WaveConfig) (orchestrator.WaveReport, error)
}

func upgradeWave(ctx context.Context, args []string, stdout, stderr io.Writer, env upgradeWaveEnv) int {
	fset := flag.NewFlagSet("upgrade-wave", flag.ContinueOnError)
	fset.SetOutput(io.Discard) // flag errors may quote a value
	image := fset.String("image", "", "")
	canary := fset.String("canary", "", "")
	list := fset.String("instances", "", "")
	all := fset.Bool("all", false, "")
	parallel := fset.Int("max-parallel", 1, "")
	timeout := fset.Duration("job-timeout", 20*time.Minute, "")
	dry := fset.Bool("dry-run", false, "")
	usage := func(msg string) int {
		_, _ = io.WriteString(stderr, "meshguard-worker admin upgrade-wave: "+msg+"\n"+upgradeWaveUsage)
		return 2
	}
	if err := fset.Parse(args); err != nil || fset.NArg() != 0 {
		return usage("invalid flags")
	}
	if !digestFlagRE.MatchString(*image) {
		return usage("--image takes a digest sha256:<64 hex> (never a tag)")
	}
	wc := orchestrator.WaveConfig{ImageDigest: *image, All: *all, MaxParallel: *parallel, JobTimeout: *timeout, DryRun: *dry}
	if *canary != "" {
		id, err := uuid.Parse(*canary)
		if err != nil {
			return usage("--canary takes an instance UUID")
		}
		wc.Canary = id
	}
	if *list != "" {
		for _, s := range strings.Split(*list, ",") {
			id, err := uuid.Parse(strings.TrimSpace(s))
			if err != nil {
				return usage("--instances takes instance UUIDs separated by commas")
			}
			wc.Instances = append(wc.Instances, id)
		}
	}
	switch {
	case *all && len(wc.Instances) > 0:
		return usage("--instances and --all are exclusive")
	case !*all && len(wc.Instances) == 0 && wc.Canary == uuid.Nil:
		return usage("name the instances: --canary, --instances or --all")
	case *parallel < 1 || *parallel > 20:
		return usage("--max-parallel lies within 1..20")
	case *timeout < time.Minute || *timeout > 2*time.Hour:
		return usage("--job-timeout lies within 1m..2h")
	}
	cfg, err := config.Load("worker", env.getenv, env.environ)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "meshguard-worker admin upgrade-wave: invalid configuration:\n%v\n", err)
		return 2
	}
	if !cfg.Wired {
		_, _ = io.WriteString(stderr, "meshguard-worker admin upgrade-wave: the worker is not configured (MG_DB_URL)\n")
		return 2
	}
	st, closeSt, err := env.open(ctx, cfg)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "meshguard-worker admin upgrade-wave: FAILED: %s\n", logx.RedactString(err.Error()))
		return 1
	}
	defer closeSt()
	enc := json.NewEncoder(stdout)
	wc.Store = st
	wc.Progress = func(e orchestrator.WaveEvent) { _ = enc.Encode(e) }
	run := env.run
	if run == nil {
		run = orchestrator.RunUpgradeWave
	}
	rep, err := run(ctx, wc)
	_ = enc.Encode(map[string]any{"report": rep})
	switch {
	case errors.Is(err, orchestrator.ErrWaveStopped):
		_, _ = fmt.Fprintf(stderr, "meshguard-worker admin upgrade-wave: STOPPED at the first failure (%d failed, %d succeeded, %d skipped)\n",
			len(rep.Failed), rep.Succeeded, rep.Skipped)
		return 1
	case err != nil:
		_, _ = fmt.Fprintf(stderr, "meshguard-worker admin upgrade-wave: FAILED: %s\n", logx.RedactString(err.Error()))
		return 1
	}
	return 0
}

// openWaveStore opens the worker's two pools (the wave enqueues in platform transactions and reads job rows).
func openWaveStore(ctx context.Context, cfg config.Config) (*store.Store, func(), error) {
	st, err := store.Open(ctx, store.Config{URL: cfg.DB.URL,
		Tenant:   store.Credentials{User: cfg.DB.TenantUser, PasswordFile: cfg.DB.TenantPasswordFile},
		Platform: store.Credentials{User: cfg.DB.PlatformUser, PasswordFile: cfg.DB.PlatformPasswordFile}, MaxConns: 4})
	if err != nil {
		return nil, nil, err
	}
	return st, st.Close, nil
}
