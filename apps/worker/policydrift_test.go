package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/config"
)

// fakeDrift stands for the store: the job it "enqueues" finishes with the given status, output and error.
type fakeDrift struct {
	tenant          uuid.UUID
	status          string
	output, errJSON string
	enqueueErr      error
	enqueued        int
}

func (f *fakeDrift) ResolveTenant(_ context.Context, ref string) (uuid.UUID, error) {
	if ref == "tenant-a" {
		return f.tenant, nil
	}
	return uuid.Nil, errors.New("no tenant with this slug")
}

func (f *fakeDrift) Enqueue(context.Context, uuid.UUID) (uuid.UUID, error) {
	f.enqueued++
	return uuid.New(), f.enqueueErr
}

func (f *fakeDrift) Job(context.Context, uuid.UUID, uuid.UUID) (string, []byte, []byte, error) {
	return f.status, []byte(f.output), []byte(f.errJSON), nil
}

// TestPolicyDriftCheckCommand — flags, configuration, the exit status of each outcome of the job, one JSON line.
func TestPolicyDriftCheckCommand(t *testing.T) {
	vars := wiredWorkerEnv(t)
	env := func(f *fakeDrift) policyDriftEnv {
		return policyDriftEnv{getenv: func(k string) string { return vars[k] },
			open: func(context.Context, config.Config) (driftChecker, func(), error) { return f, func() {}, nil }}
	}
	for name, tc := range map[string]struct {
		args []string
		f    *fakeDrift
		code int
	}{
		"no tenant flag": {nil, &fakeDrift{}, 2},
		"bad tenant":     {[]string{"--tenant", "Bad Slug!"}, &fakeDrift{}, 2},
		"unknown tenant": {[]string{"--tenant", "tenant-z"}, &fakeDrift{}, 2},
		"in sync":        {[]string{"--tenant", "tenant-a"}, &fakeDrift{status: "succeeded", output: `{"state":"in_sync"}`}, 0},
		"drift":          {[]string{"--tenant", "tenant-a"}, &fakeDrift{status: "succeeded", output: `{"state":"drift"}`}, 3},
		"no policy": {[]string{"--tenant", "tenant-a"}, &fakeDrift{status: "failed", output: `{"state":"no_policy"}`,
			errJSON: `{"code":"no_policy"}`}, 3},
		"store":   {[]string{"--tenant", "tenant-a"}, &fakeDrift{status: "failed", errJSON: `{"code":"store"}`}, 1},
		"enqueue": {[]string{"--tenant", "tenant-a"}, &fakeDrift{enqueueErr: errors.New("db down")}, 1},
	} {
		tc.f.tenant = uuid.New()
		var out, errb bytes.Buffer
		code := policyDriftCheck(context.Background(), tc.args, &out, &errb, env(tc.f))
		if code != tc.code {
			t.Errorf("%s: exit %d, want %d (%s)", name, code, tc.code, errb.String())
			continue
		}
		if code == 2 {
			continue
		}
		var o policyDriftOutput
		if err := json.Unmarshal(out.Bytes(), &o); err != nil || o.Tenant != tc.f.tenant.String() {
			t.Errorf("%s: output %q %v", name, out.String(), err)
		}
	}
}
