package compose

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strconv"
	"strings"

	agentv1 "github.com/zhaduchanhzz/network-access-mesh/api/agent/v1"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/logx"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/agentspec"
)

// maxDetail bounds ValidateConfigResponse.detail (agent.proto).
const maxDetail = 4 << 10

// ValidateConfig — the syntax gate of §11.3 step 8 / §11.5: the configuration of s is rendered (and checked against
// the isolation invariants) into the scratch directory <instance>/config.next/, then `headscale configtest` runs in a
// throw-away container — the pinned image of s, no network, read-only rootfs, cap_drop ALL, the tenant's run_uid,
// config.next/ and records/ mounted read-only, and a SCRATCH data directory on tmpfs (configtest creates keys and
// opens/migrates a database — RT-05): the instance's data/ is never mounted. config.next/ and the container are
// removed whatever happens; config/ is not touched (EnsureInstance with TARGET_PHASE_CONFIG writes it — the same bytes,
// the same config_sha256). Valid = exit code 0 and no warning or error logged by configtest (with log.format json
// Headscale logs to stdout; "failed to parse node.expiry" is only a warning and exit code 0 — §11.3 step 11).
func (d *Driver) ValidateConfig(ctx context.Context, s agentspec.InstanceSpec) (*agentv1.ValidateConfigResponse, error) {
	r, err := Render(d.cfg.Host, s)
	if err != nil {
		return nil, err
	}
	n, l := d.cfg.Host.Names(s.Ref), newLayout(s.Ref.InstanceID.String())
	t, err := d.open()
	if err != nil {
		return nil, err
	}
	defer func() { _ = t.Close() }()
	for _, rel := range []string{l.dir, l.records} {
		fi, err := t.lstat(rel)
		if err != nil {
			return nil, err
		}
		if fi == nil || !fi.IsDir() {
			return nil, state("spec.instance", "%s does not exist (EnsureInstance with TARGET_PHASE_STORAGE first)", filepath.Base(rel))
		}
	}
	next := filepath.Join(l.dir, "config.next")
	if err := t.removeAll(next); err != nil { // a leftover of an interrupted run
		return nil, err
	}
	defer func() {
		if err := t.removeAll(next); err != nil {
			d.cfg.Log.Error("configtest_cleanup_failed", "instance_id", l.id, "error", err)
		}
	}()
	o := t.owners(int(s.RunUID))
	if _, err := t.ensureDir(next, o["config"], true); err != nil {
		return nil, err
	}
	for name, content := range map[string][]byte{"config.yaml": r.Config, "bootstrap-policy.hujson": r.Policy} {
		if _, err := t.writeFile(filepath.Join(next, name), content, o["tenant"]); err != nil {
			return nil, err
		}
	}
	name, err := helperName(s.Ref.Slug, helperConfigtest)
	if err != nil {
		return nil, err
	}
	uid := strconv.FormatUint(uint64(s.RunUID), 10)
	tmpfs := "uid=" + uid + ",gid=" + uid + ",mode=0700"
	spec := OneShot{
		Name: name, Image: r.Image, Cmd: []string{"configtest"}, User: uid + ":" + uid, Labels: helperLabels(s.Ref, helperConfigtest),
		Binds: []Bind{{Source: n.ConfigNextDir, Target: "/etc/headscale", ReadOnly: true}, {Source: n.RecordsDir, Target: "/etc/headscale-records", ReadOnly: true}},
		Tmpfs: map[string]string{"/var/lib/headscale": tmpfs + ",size=64m", "/var/run/headscale": tmpfs + ",size=1m"},
		// the instance's own limits (at most 16 GiB / 16 CPUs / 4096 PIDs — agentspec)
		MemoryBytes: int64(s.Limits.MemoryMiB) << 20, NanoCPUs: int64(s.Limits.CPUMillis) * 1_000_000, PIDs: int64(s.Limits.PIDs),
		Timeout: configtestTimeout, MaxOutput: helperMaxOutput,
	}
	if err := d.cfg.Engine.EnsureImage(ctx, r.Image); err != nil {
		return nil, err
	}
	res, err := d.cfg.Engine.RunOnce(ctx, spec)
	if err != nil {
		return nil, err
	}
	findings := configFindings(res.Stdout)
	valid := res.ExitCode == 0 && len(findings) == 0 && !res.Truncated
	out := &agentv1.ValidateConfigResponse{Valid: valid, ConfigSha256: r.ConfigSHA256, ExitCode: int32(res.ExitCode)} //nolint:gosec // G115: an exit code
	if !valid {
		out.Detail = detail(res.Stderr, findings, res.Truncated)
	}
	d.cfg.Log.Info("config_validated", "instance_id", l.id, "valid", valid, "exit_code", res.ExitCode, "config_sha256", r.ConfigSHA256,
		"image", r.Image)
	return out, nil
}

// configFindings returns the log lines of configtest at level warn or above (JSON lines on stdout).
func configFindings(stdout []byte) []string {
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(stdout))
	sc.Buffer(make([]byte, 0, 64<<10), helperMaxOutput)
	for sc.Scan() {
		var line struct {
			Level string `json:"level"`
		}
		if json.Unmarshal(sc.Bytes(), &line) != nil {
			continue
		}
		switch strings.ToLower(line.Level) {
		case "warn", "warning", "error", "fatal", "panic":
			out = append(out, sc.Text())
		}
	}
	return out
}

// detail is ValidateConfigResponse.detail: stderr then the warnings, redacted, valid UTF-8, at most 4 KiB.
func detail(stderr []byte, findings []string, truncated bool) string {
	var b strings.Builder
	b.WriteString(strings.TrimSpace(string(stderr)))
	for _, f := range findings {
		if b.Len() > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(f)
	}
	if truncated {
		b.WriteString("\n(output truncated)")
	}
	s := logx.RedactString(strings.ToValidUTF8(b.String(), "?"))
	if len(s) > maxDetail {
		s = strings.ToValidUTF8(s[:maxDetail-3], "") + "…"
	}
	return s
}
