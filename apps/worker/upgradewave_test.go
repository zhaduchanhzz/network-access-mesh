package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/config"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/orchestrator"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
)

// TestUpgradeWaveCommand: flags (a digest, never a tag; the instances named; --instances xor --all; bounds), the
// configuration (exit 2 before anything is opened), the wave run with the parsed settings, the JSON lines and the exit
// codes (0 completed, 1 stopped at a failure).
func TestUpgradeWaveCommand(t *testing.T) {
	vars := wiredWorkerEnv(t)
	var got orchestrator.WaveConfig
	result := struct {
		rep orchestrator.WaveReport
		err error
	}{}
	opened := 0
	env := upgradeWaveEnv{getenv: func(k string) string { return vars[k] },
		open: func(context.Context, config.Config) (*store.Store, func(), error) {
			opened++
			return nil, func() {}, nil
		},
		run: func(_ context.Context, c orchestrator.WaveConfig) (orchestrator.WaveReport, error) {
			got = c
			c.Progress(orchestrator.WaveEvent{Instance: c.Canary, Phase: "canary", Event: "succeeded"})
			return result.rep, result.err
		}}
	for k, v := range vars {
		env.environ = append(env.environ, k+"="+v)
	}
	digest := "sha256:" + strings.Repeat("e", 64)
	canary, other := uuid.New(), uuid.New()
	run := func(args ...string) (int, string, string) {
		var out, errw bytes.Buffer
		code := upgradeWave(context.Background(), args, &out, &errw, env)
		return code, out.String(), errw.String()
	}
	for _, args := range [][]string{
		{"--image", "headscale:latest", "--all"},
		{"--image", digest},
		{"--image", digest, "--all", "--instances", other.String()},
		{"--image", digest, "--canary", "x"},
		{"--image", digest, "--instances", "a,b"},
		{"--image", digest, "--all", "--max-parallel", "21"},
		{"--image", digest, "--all", "--job-timeout", "5s"},
		{"--image", digest, "--all", "extra"},
	} {
		if code, _, _ := run(args...); code != 2 {
			t.Errorf("%v: exit %d, want 2", args, code)
		}
	}
	if opened != 0 {
		t.Fatal("the store was opened for a usage error")
	}
	code, out, _ := run("--image", digest, "--canary", canary.String(), "--instances", other.String(), "--max-parallel", "3",
		"--job-timeout", "30m")
	if code != 0 || got.ImageDigest != digest || got.Canary != canary || len(got.Instances) != 1 || got.Instances[0] != other ||
		got.MaxParallel != 3 || got.JobTimeout != 30*time.Minute || got.All || got.DryRun {
		t.Fatalf("exit %d, wave %+v", code, got)
	}
	if !strings.Contains(out, `"event":"succeeded"`) || !strings.Contains(out, `"report"`) {
		t.Fatalf("output %s", out)
	}
	result.err = orchestrator.ErrWaveStopped
	result.rep = orchestrator.WaveReport{Failed: []orchestrator.WaveEvent{{Instance: other, Event: "failed", Code: "preflight_failed"}}}
	if code, _, errw := run("--image", digest, "--all", "--dry-run"); code != 1 || !strings.Contains(errw, "STOPPED") || !got.All || !got.DryRun {
		t.Fatalf("stopped wave: exit %d %s", code, errw)
	}
}
