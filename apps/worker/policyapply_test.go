package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/config"
	"github.com/zhaduchanhzz/network-access-mesh/internal/policies"
)

// fakeCore stands for the policy core: it runs the real lint, so a refused policy never reaches "Apply".
type fakeCore struct {
	tenant  uuid.UUID
	applied []policies.ApplyRequest
	fail    error
}

func (f *fakeCore) ResolveTenant(_ context.Context, ref string) (uuid.UUID, error) {
	if ref == "tenant-a" || ref == f.tenant.String() {
		return f.tenant, nil
	}
	return uuid.Nil, errors.New("no tenant with this slug")
}

func (f *fakeCore) Apply(_ context.Context, req policies.ApplyRequest) (policies.Result, error) {
	doc, err := policies.Lint(req.HuJSON)
	if err != nil {
		return policies.Result{TenantID: req.TenantID}, err
	}
	f.applied = append(f.applied, req)
	res := policies.Result{TenantID: req.TenantID, InstanceID: uuid.New(), VersionID: uuid.New(), Version: 1,
		VersionCreated: true, ApplicationID: uuid.New(), State: policies.StateApplied, ContentSHA256: doc.ContentSHA256,
		AppliedSHA256: doc.AppliedSHA256, ReadbackSHA256: doc.AppliedSHA256}
	if f.fail != nil {
		res.State, res.ErrorCode, res.ReadbackSHA256 = policies.StateFailed, policies.CodePolicyRejected, ""
		return res, &policies.ApplyError{Code: policies.CodePolicyRejected, Result: res, Err: f.fail}
	}
	return res, nil
}

// pipeWith returns the read end of a pipe holding text.
func pipeWith(t *testing.T, text string) *os.File {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	go func() { _, _ = io.WriteString(w, text); _ = w.Close() }()
	t.Cleanup(func() { _ = r.Close() })
	return r
}

type ttyStdin struct{ io.Reader }

func (ttyStdin) Stat() (fs.FileInfo, error) { return ttyInfo{}, nil }

type ttyInfo struct{}

func (ttyInfo) Name() string       { return "tty" }
func (ttyInfo) Size() int64        { return 0 }
func (ttyInfo) Mode() fs.FileMode  { return fs.ModeCharDevice | fs.ModeDevice }
func (ttyInfo) ModTime() time.Time { return time.Time{} }
func (ttyInfo) IsDir() bool        { return false }
func (ttyInfo) Sys() any           { return nil }

// TestPolicyApplyCommand: flags, stdin only, exit codes (0 applied, 1 failed, 2 usage, 3 lint), JSON output.
func TestPolicyApplyCommand(t *testing.T) {
	core := &fakeCore{tenant: uuid.New()}
	env := policyApplyEnv{environ: nil, open: func(context.Context, config.Config) (policyCore, func(), error) {
		return core, func() {}, nil
	}}
	vars := wiredWorkerEnv(t)
	env.getenv = func(k string) string { return vars[k] }
	for k, v := range vars {
		env.environ = append(env.environ, k+"="+v)
	}
	allow, err := os.ReadFile("../../infrastructure/headscale/templates/test-allow-intra.hujson")
	if err != nil {
		t.Fatal(err)
	}
	run := func(args []string, in stdinFile) (int, string, string) {
		var out, errb bytes.Buffer
		code := policyApply(context.Background(), args, in, &out, &errb, env)
		return code, out.String(), errb.String()
	}

	code, out, stderr := run([]string{"--tenant", "tenant-a", "--file", "-"}, pipeWith(t, string(allow)))
	var res policyApplyOutput
	if code != 0 || json.Unmarshal([]byte(out), &res) != nil || res.State != "applied" || res.ReadbackSHA256 != res.AppliedSHA256 {
		t.Fatalf("apply: exit %d out %q err %q", code, out, stderr)
	}
	if len(core.applied) != 1 || core.applied[0].Kind != policies.KindBaseline || core.applied[0].Trigger != policies.TriggerManual ||
		core.applied[0].HuJSON != string(allow) || core.applied[0].TenantID != core.tenant {
		t.Fatalf("request %+v", core.applied)
	}

	for name, doc := range map[string]string{"empty": "", "no grants": `{"ssh": []}`} {
		code, out, stderr = run([]string{"--tenant", core.tenant.String(), "--file", "-"}, pipeWith(t, doc))
		if code != 3 || !strings.Contains(stderr, "BLOCKED by lint") || !strings.Contains(out, `"state":"rejected"`) {
			t.Errorf("%s: exit %d out %q err %q", name, code, out, stderr)
		}
	}
	if len(core.applied) != 1 {
		t.Fatal("a refused policy was applied")
	}

	core.fail = errors.New("refused")
	if code, out, _ = run([]string{"--tenant", "tenant-a", "--kind", "suspension", "--trigger", "suspend", "--file", "-"},
		pipeWith(t, string(allow))); code != 1 || !strings.Contains(out, `"error_code":"policy_rejected"`) {
		t.Fatalf("failed apply: exit %d %q", code, out)
	}

	for _, args := range [][]string{
		{"--tenant", "tenant-a"},                                  // no --file -
		{"--tenant", "tenant-a", "--file", "/etc/passwd"},          // only stdin
		{"--tenant", "Bad Slug!", "--file", "-"},                   // tenant format
		{"--tenant", "tenant-a", "--kind", "user", "--file", "-"},  // kind
		{"--tenant", "tenant-a", "--file", "-", "extra"},           // stray argument
		{"--tenant", "unknown-tenant", "--file", "-"},              // resolve fails
	} {
		if code, _, _ := run(args, pipeWith(t, string(allow))); code != 2 {
			t.Errorf("%q: exit %d, want 2", args, code)
		}
	}
	if code, _, stderr := run([]string{"--tenant", "tenant-a", "--file", "-"}, ttyStdin{strings.NewReader("{}")}); code != 2 ||
		!strings.Contains(stderr, "terminal") {
		t.Errorf("terminal stdin: exit %d %q", code, stderr)
	}
}

// wiredWorkerEnv is a complete worker configuration (as rendered for mg-app), enough for config.Load.
func wiredWorkerEnv(t *testing.T) map[string]string {
	t.Helper()
	dir := t.TempDir()
	return map[string]string{
		"MG_ENV": "staging", "MG_BASE_DOMAIN": "example.com", "MG_DB_URL": "postgres://postgres:5432/meshguard?sslmode=disable",
		"MG_DB_TENANT_USER": "mg_worker_tenant", "MG_DB_TENANT_PASSWORD_FILE": dir + "/t",
		"MG_DB_PLATFORM_USER": "mg_worker_platform", "MG_DB_PLATFORM_PASSWORD_FILE": dir + "/p",
		"MG_EDGE_ADMIN_URL": "http://10.249.0.2:8081", "MG_EDGE_ADMIN_TOKEN_FILE": dir + "/e",
		"MG_KEK_APP_DIR": dir + "/kek-app", "MG_KEK_OPS_DIR": dir + "/kek-ops",
		"MG_DB_PARTITION_PASSWORD_FILE": dir + "/pm", "MG_EGRESS_DENY_CIDRS": "10.0.0.0/8",
	}
}
