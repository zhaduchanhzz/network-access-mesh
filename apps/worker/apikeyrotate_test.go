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

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/config"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/apikey"
)

// fakeRotator stands for the registry and the rotation.
type fakeRotator struct {
	tenant, instance uuid.UUID
	reqs             []apikey.Request
	res              apikey.Result
	err              error
}

func (f *fakeRotator) ResolveInstance(_ context.Context, ref string) (uuid.UUID, uuid.UUID, error) {
	if ref == "tenant-a" || ref == f.tenant.String() {
		return f.tenant, f.instance, nil
	}
	return uuid.Nil, uuid.Nil, errors.New("no tenant with this slug")
}

func (f *fakeRotator) Rotate(_ context.Context, req apikey.Request) (apikey.Result, error) {
	f.reqs = append(f.reqs, req)
	return f.res, f.err
}

// TestAPIKeyRotateCommand: flags, exit codes (0 rotated or not due, 1 failed, 2 usage, 3 skipped otherwise), the JSON
// output — prefix and expiry only: never a key, never the SecretStore reference.
func TestAPIKeyRotateCommand(t *testing.T) {
	rot := &fakeRotator{tenant: uuid.New(), instance: uuid.New()}
	vars := wiredWorkerEnv(t)
	env := apikeyRotateEnv{getenv: func(k string) string { return vars[k] },
		open: func(context.Context, config.Config, io.Writer) (keyRotator, func(), error) {
			return rot, func() {}, nil
		}}
	for k, v := range vars {
		env.environ = append(env.environ, k+"="+v)
	}
	run := func(args ...string) (int, apikeyRotateOutput, string, string) {
		var out, errb bytes.Buffer
		code := apikeyRotate(context.Background(), args, &out, &errb, env)
		var o apikeyRotateOutput
		if out.Len() > 0 {
			if err := json.Unmarshal(out.Bytes(), &o); err != nil {
				t.Fatalf("output %q: %v", out.String(), err)
			}
		}
		return code, o, out.String(), errb.String()
	}
	exp := time.Date(2027, 2, 16, 8, 0, 0, 0, time.UTC)
	rot.res = apikey.Result{Outcome: apikey.OutcomeRotated, KeyPrefix: "abcdefghijkl", ExpiresAt: &exp, RefVersion: 3,
		PreviousPrefix: "zyxwvutsrqpo"}
	code, o, out, _ := run("--tenant", "tenant-a", "--force")
	if code != 0 || o.Outcome != apikey.OutcomeRotated || o.KeyPrefix != "abcdefghijkl" || o.ExpiresAt != "2027-02-16T08:00:00Z" ||
		o.Tenant != rot.tenant.String() || o.Instance != rot.instance.String() {
		t.Fatalf("rotated: exit %d %+v", code, o)
	}
	if strings.Contains(out, "mgsec://") || strings.Contains(out, "hskey-") || strings.Contains(out, "ref_") || strings.Contains(out, "previous") {
		t.Fatalf("output names a reference or a key: %s", out)
	}
	req := rot.reqs[0]
	if !req.Force || req.AllowBootstrap || req.Trigger != apikey.TriggerAdmin || req.TenantID != rot.tenant ||
		req.InstanceID != rot.instance || !strings.Contains(req.Actor, "apikey-rotate") {
		t.Fatalf("request %+v", req)
	}
	if code, _, _, _ = run("--tenant", rot.tenant.String(), "--allow-bootstrap"); code != 0 || !rot.reqs[1].AllowBootstrap ||
		rot.reqs[1].Force {
		t.Fatalf("allow-bootstrap: exit %d %+v", code, rot.reqs[1])
	}
	rot.res = apikey.Result{Outcome: apikey.OutcomeSkipped, SkipReason: apikey.SkipNotDue, KeyPrefix: "abcdefghijkl", ExpiresAt: &exp}
	if code, o, _, _ = run("--tenant", "tenant-a"); code != 0 || o.SkipReason != apikey.SkipNotDue {
		t.Fatalf("not due: exit %d %+v", code, o)
	}
	rot.res = apikey.Result{Outcome: apikey.OutcomeSkipped, SkipReason: apikey.SkipQuarantined}
	if code, o, _, _ = run("--tenant", "tenant-a"); code != 3 || o.SkipReason != apikey.SkipQuarantined {
		t.Fatalf("quarantined: exit %d %+v", code, o)
	}
	rot.res = apikey.Result{Outcome: "", KeyPrefix: "abcdefghijkl"}
	rot.err = jobs.Permanent(apikey.CodeKeyRejected, errors.New("refused hskey-api-abcdefghijkl-"+strings.Repeat("s", 64)))
	code, o, out, stderr := run("--tenant", "tenant-a")
	if code != 1 || o.Outcome != "failed" || o.ErrorCode != apikey.CodeKeyRejected || !strings.Contains(stderr, "FAILED") ||
		strings.Contains(stderr+out, strings.Repeat("s", 64)) {
		t.Fatalf("failed: exit %d %+v %q", code, o, stderr)
	}
	rot.err = nil
	for _, args := range [][]string{
		{},                                    // no tenant
		{"--tenant", "Bad Slug!"},             // tenant format
		{"--tenant", "tenant-a", "extra"},     // stray argument
		{"--tenant", "tenant-a", "--ttl=1h"},  // unknown flag
		{"--tenant", "unknown-tenant"},        // resolve fails
		{"--tenant", "tenant-a", "--force=x"}, // bad bool
	} {
		if code, _, _, _ := run(args...); code != 2 {
			t.Errorf("%q: exit %d, want 2", args, code)
		}
	}
	// the dispatch of `admin`
	var errb bytes.Buffer
	if code := admin(context.Background(), []string{"apikey-rotate", "--tenant", "Bad Slug!"}, nil, io.Discard, &errb,
		func(string) string { return "" }, nil); code != 2 || !strings.Contains(errb.String(), "apikey-rotate") {
		t.Fatalf("admin dispatch: %d %q", code, errb.String())
	}
}
