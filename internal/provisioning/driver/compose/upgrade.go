package compose

// The agent side of instance.upgrade (P3-T13a, §11.4 Upgrade, §17.6):
//
//   - InspectImage — the Headscale version of an allowlisted image, from its binary (`headscale version -o json` in a
//     one-shot container: no network, no mount, no capability, read-only rootfs); the official image carries no version
//     label, the MeshGuard build does (P2-T10a) — the binary is asked for both. The daemon pulls a missing image here,
//     before the instance is stopped.
//   - PreflightUpgrade — `headscale configtest` of the TARGET binary on a COPY of the data: the cold backup of the upgrade
//     is verified (signed manifest, identity, Noise key — §17.2 step 2) and decrypted into the instance's staging
//     directory by the restore helper, the configuration of the target is rendered into config.next/, and configtest —
//     which opens and migrates the database and loads the stored policy (policy.mode database: NewState →
//     NewPolicyManager — read in the source at v0.29.7, RT-05) — runs on that copy. data/ is never mounted; the copy and
//     config.next/ are removed whatever happens.
//   - UpgradeInstance — the switch: compare-and-swap of meta/instance.json "image", compose.yaml rendered again with the
//     target image (the configuration in force otherwise: same config_sha256), the container created again without
//     being started. The instance must be stopped; StartInstance starts it after the start guard.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	agentv1 "github.com/zhaduchanhzz/network-access-mesh/api/agent/v1"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/agentspec"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/backupfmt"
)

const (
	helperVersion      = "version"
	helperPreflight    = "preflight"
	helperPreflightRun = "pfconfigtest"
	versionTimeout     = 60 * time.Second
	// preflightTimeout bounds configtest on the copy: it migrates the database, which may take longer than the syntax
	// gate on scratch data (configtestTimeout).
	preflightTimeout = 5 * time.Minute
	// nobody runs `headscale version` (no file is read or written).
	nobody = "65534:65534"
)

var (
	hsVersionRE = regexp.MustCompile(`^v?\d{1,4}\.\d{1,4}\.\d{1,4}$`)
	commitRE    = regexp.MustCompile(`^[0-9a-f]{7,64}$`)
)

// imageVersion is what an image's binary reports.
type imageVersion struct{ Version, Commit string }

// versionCache maps an image digest to its version (a digest names immutable content: asked once per agent process).
type versionCache struct {
	mu sync.Mutex
	m  map[string]imageVersion
}

func (c *versionCache) get(digest string) (imageVersion, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.m[digest]
	return v, ok
}

func (c *versionCache) put(digest string, v imageVersion) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = map[string]imageVersion{}
	}
	c.m[digest] = v
}

// imageVersion runs `headscale version -o json` of an allowlisted image in a one-shot container (cached per digest).
// An image that cannot be pulled or run is UNAVAILABLE (the worker retries); one that answers no release version is an
// error.
func (d *Driver) imageVersion(ctx context.Context, ref agentspec.Ref, img agentspec.AllowedImage) (imageVersion, error) {
	if v, ok := d.versions.get(img.Digest); ok {
		return v, nil
	}
	name, err := helperName(ref.Slug, helperVersion)
	if err != nil {
		return imageVersion{}, err
	}
	spec := OneShot{Name: name, Image: img.Reference(), Cmd: []string{"version", "-o", "json"}, User: nobody,
		Labels: helperLabels(ref, helperVersion), MemoryBytes: 64 << 20, NanoCPUs: 250_000_000, PIDs: 16,
		Timeout: versionTimeout, MaxOutput: 4 << 10}
	if err := d.cfg.Engine.EnsureImage(ctx, spec.Image); err != nil {
		return imageVersion{}, status.Errorf(codes.Unavailable, "image %s is not available: %v", img.Digest, err)
	}
	res, err := d.cfg.Engine.RunOnce(ctx, spec)
	if err != nil {
		return imageVersion{}, status.Errorf(codes.Unavailable, "headscale version did not run: %v", err)
	}
	var out struct {
		Version string `json:"version"`
		Commit  string `json:"commit"`
	}
	if res.ExitCode != 0 || res.Truncated || json.Unmarshal(bytes.TrimSpace(res.Stdout), &out) != nil ||
		!hsVersionRE.MatchString(out.Version) || (out.Commit != "" && !commitRE.MatchString(out.Commit)) {
		return imageVersion{}, fmt.Errorf("headscale version of %s: exit code %d, no release version in %d bytes", img.Digest,
			res.ExitCode, len(res.Stdout))
	}
	v := imageVersion{Version: out.Version, Commit: out.Commit}
	d.versions.put(img.Digest, v)
	d.cfg.Log.Info("image_version", "image", img.Reference(), "headscale_version", v.Version, "commit", v.Commit)
	return v, nil
}

// InspectImage — the version of an allowlisted image (P3-T13a).
func (d *Driver) InspectImage(ctx context.Context, i agentspec.Inspect) (*agentv1.InspectImageResponse, error) {
	v, err := d.imageVersion(ctx, i.Ref, i.Image)
	if err != nil {
		return nil, err
	}
	return &agentv1.InspectImageResponse{Repository: i.Image.Repository, ImageDigest: i.Image.Digest, HeadscaleVersion: v.Version,
		Commit: v.Commit}, nil
}

// stoppedContainer: the container of the instance, which must not be running (§11.4 Upgrade: everything between the
// cold backup and the start happens on a stopped instance). nil when it does not exist.
func (d *Driver) stoppedContainer(ctx context.Context, n agentspec.Names, ref agentspec.Ref) (*Container, error) {
	c, err := d.cfg.Engine.Container(ctx, n.Container)
	if err != nil || c == nil {
		return nil, err
	}
	if err := ownContainer(c, n, ref); err != nil {
		return nil, err
	}
	switch c.State {
	case "running", "restarting", "paused":
		return nil, state("instance", "the instance must be stopped first (§11.4 Upgrade: cold backup) — container %s is %s", n.Container, c.State)
	}
	return c, nil
}

// upgradeState reads the instance for an upgrade operation: activated with a recorded Noise key fingerprint, the
// rendering of spec equal to the configuration in force (an upgrade changes the image only).
func (d *Driver) upgradeState(t *tree, l layout, spec agentspec.InstanceSpec) (instanceState, *Rendered, string, error) {
	r, err := Render(d.cfg.Host, spec)
	if err != nil {
		return instanceState{}, nil, "", err
	}
	st, err := d.readState(t, l, spec.Ref.InstanceID)
	if err != nil {
		return instanceState{}, nil, "", err
	}
	recorded, _ := st.meta[metaFingerprint].(string)
	if !st.activated || !fingerprintRE.MatchString(recorded) {
		return instanceState{}, nil, "", state("instance", "only an activated instance with a recorded Noise key fingerprint is upgraded")
	}
	if cs, _ := st.meta["config_sha256"].(string); cs != r.ConfigSHA256 {
		return instanceState{}, nil, "", &agentspec.Refusal{Reason: agentv1.RefusalReason_REFUSAL_REASON_CONFLICT, Field: "spec",
			Msg: "the configuration of spec is not the one in force — an upgrade changes the image only (reconfigure first)"}
	}
	return st, r, recorded, nil
}

// PreflightUpgrade — configtest of the target binary on a decrypted copy of the cold backup (§11.4 Upgrade).
func (d *Driver) PreflightUpgrade(ctx context.Context, p agentspec.Preflight) (*agentv1.PreflightUpgradeResponse, error) {
	cfg, err := d.backupCfg()
	if err != nil {
		return nil, err
	}
	ref := p.Ref
	n, l := d.cfg.Host.Names(ref), newLayout(ref.InstanceID.String())
	t, err := d.open()
	if err != nil {
		return nil, err
	}
	defer func() { _ = t.Close() }()
	st, r, recorded, err := d.upgradeState(t, l, p.Spec)
	if err != nil {
		return nil, err
	}
	if image, _ := st.meta["image"].(string); image != p.From.Reference() {
		return nil, &agentspec.Refusal{Reason: agentv1.RefusalReason_REFUSAL_REASON_CONFLICT, Field: "from_image_digest",
			Msg: "the instance does not run this image"}
	}
	if _, err := d.stoppedContainer(ctx, n, ref); err != nil {
		return nil, err
	}
	bt, err := d.openBackups()
	if err != nil {
		return nil, err
	}
	defer func() { _ = bt.Close() }()
	// ---- everything below until the restore helper runs: no byte of the archive is decrypted
	m, err := d.checkArtifact(bt, l.id, ref, p.Sequence, p.ManifestSHA256, p.ArchiveSHA256, cfg, recorded)
	if err != nil {
		d.cfg.Log.Error("security_event", "kind", "preflight.refused", "severity", "high", "instance_id", l.id,
			"tenant_id", ref.TenantID.String(), "sequence", p.Sequence, "error", err)
		return nil, err
	}
	if m.Image != p.From.Reference() {
		return nil, integrity("artifact", "the backup was not taken with the instance's current image")
	}
	target, err := d.imageVersion(ctx, ref, p.Spec.Image)
	if err != nil {
		return nil, err
	}
	if _, err := backupfmt.UpgradePath(m.HeadscaleVersion, target.Version); err != nil {
		return nil, &agentspec.Refusal{Reason: agentv1.RefusalReason_REFUSAL_REASON_STATE, Field: "spec.image_digest", Msg: err.Error()}
	}
	staging, err := d.newStaging(t, l, int(st.runUID), helperPreflight)
	if err != nil {
		return nil, err
	}
	defer d.dropStaging(t, l)
	identity, err := backupfmt.AgeIdentity(p.DataKey)
	if err != nil {
		return nil, &agentspec.Refusal{Reason: agentv1.RefusalReason_REFUSAL_REASON_MALFORMED, Field: "data_key", Msg: "not a data key"}
	}
	req, err := json.Marshal(RestoreHelperRequest{Identity: identity, Files: m.Files, MaxDBBytes: cfg.MaxDBBytes})
	if err != nil {
		return nil, err
	}
	defer clear(req)
	stagingAbs := filepath.Join(d.cfg.Host.TenantsDir, staging)
	unpack, err := d.helperSpec(ref, st.runUID, helperPreflight, RestoreUnpackCommand, []Bind{
		{Source: filepath.Join(n.BackupDir, backupfmt.ArchiveName(p.Sequence)), Target: helperArchiveIn, ReadOnly: true},
		{Source: stagingAbs, Target: helperStagingDir},
	}, req, cfg.Timeout)
	if err != nil {
		return nil, err
	}
	res, err := d.runHelper(ctx, unpack, ref, helperPreflight)
	if err != nil {
		return nil, err
	}
	if res.NoiseFingerprint != recorded {
		return nil, integrity("artifact", "the decrypted Noise key is not the instance's (start guard, §11.4)")
	}
	stagedData := filepath.Join(staging, stagingData)
	if err := d.checkStagedData(t, stagedData, int(st.runUID)); err != nil {
		return nil, err
	}
	// the configuration of the target, rendered into config.next/ (as ValidateConfig — the same bytes as config/)
	next := filepath.Join(l.dir, "config.next")
	if err := t.removeAll(next); err != nil {
		return nil, err
	}
	defer func() {
		if err := t.removeAll(next); err != nil {
			d.cfg.Log.Error("configtest_cleanup_failed", "instance_id", l.id, "error", err)
		}
	}()
	o := t.owners(int(st.runUID))
	if _, err := t.ensureDir(next, o["config"], true); err != nil {
		return nil, err
	}
	for name, content := range map[string][]byte{"config.yaml": r.Config, "bootstrap-policy.hujson": r.Policy} {
		if _, err := t.writeFile(filepath.Join(next, name), content, o["tenant"]); err != nil {
			return nil, err
		}
	}
	name, err := helperName(ref.Slug, helperPreflightRun)
	if err != nil {
		return nil, err
	}
	uid := strconv.FormatUint(uint64(st.runUID), 10)
	s := p.Spec
	run := OneShot{
		Name: name, Image: r.Image, Cmd: []string{"configtest"}, User: uid + ":" + uid, Labels: helperLabels(ref, helperPreflightRun),
		Binds: []Bind{{Source: n.ConfigNextDir, Target: "/etc/headscale", ReadOnly: true},
			{Source: n.RecordsDir, Target: "/etc/headscale-records", ReadOnly: true},
			{Source: filepath.Join(stagingAbs, stagingData), Target: "/var/lib/headscale"}},
		Tmpfs:       map[string]string{"/var/run/headscale": "uid=" + uid + ",gid=" + uid + ",mode=0700,size=1m"},
		MemoryBytes: int64(s.Limits.MemoryMiB) << 20, NanoCPUs: int64(s.Limits.CPUMillis) * 1_000_000, PIDs: int64(s.Limits.PIDs),
		Timeout: preflightTimeout, MaxOutput: helperMaxOutput,
	}
	if err := d.cfg.Engine.EnsureImage(ctx, r.Image); err != nil {
		return nil, status.Errorf(codes.Unavailable, "image %s is not available: %v", p.Spec.Image.Digest, err)
	}
	ct, err := d.cfg.Engine.RunOnce(ctx, run)
	if err != nil {
		return nil, err
	}
	// warnings about stored data are reported, not fatal (the configuration itself passed the strict syntax gate —
	// ValidateConfig — with the target image); an error, a fatal line or a non-zero exit code fails the preflight
	findings := configFindings(ct.Stdout)
	fatal := false
	for _, f := range findings {
		var line struct {
			Level string `json:"level"`
		}
		if json.Unmarshal([]byte(f), &line) == nil && !strings.EqualFold(line.Level, "warn") && !strings.EqualFold(line.Level, "warning") {
			fatal = true
		}
	}
	valid := ct.ExitCode == 0 && !fatal && !ct.Truncated
	out := &agentv1.PreflightUpgradeResponse{Valid: valid, ExitCode: int32(ct.ExitCode), ConfigSha256: r.ConfigSHA256, //nolint:gosec // G115: an exit code
		BackupHeadscaleVersion: m.HeadscaleVersion, TargetHeadscaleVersion: target.Version}
	if !valid || len(findings) > 0 {
		out.Detail = detail(ct.Stderr, findings, ct.Truncated)
	}
	d.cfg.Log.Info("upgrade_preflight", "instance_id", l.id, "valid", valid, "exit_code", ct.ExitCode, "image", r.Image,
		"backup_headscale_version", m.HeadscaleVersion, "target_headscale_version", target.Version, "sequence", p.Sequence)
	return out, nil
}

// UpgradeInstance — the switch of §11.4 Upgrade: compose.yaml rendered with the target image and meta/instance.json
// "image" swapped (compare-and-swap on From), then the container created again — not started. Already on To (a retried
// call): the files and the container are brought to it, nothing else changes.
func (d *Driver) UpgradeInstance(ctx context.Context, u agentspec.Upgrade) (*agentv1.InstanceStatus, error) {
	ref := u.Ref
	n, l := d.cfg.Host.Names(ref), newLayout(ref.InstanceID.String())
	t, err := d.open()
	if err != nil {
		return nil, err
	}
	defer func() { _ = t.Close() }()
	st, r, _, err := d.upgradeState(t, l, u.Spec)
	if err != nil {
		return nil, err
	}
	image, _ := st.meta["image"].(string)
	if image != u.From.Reference() && image != u.To.Reference() {
		return nil, &agentspec.Refusal{Reason: agentv1.RefusalReason_REFUSAL_REASON_CONFLICT, Field: "from_image_digest",
			Msg: "the instance runs neither from_image_digest nor to_image_digest (compare-and-swap)"}
	}
	if _, err := d.stoppedContainer(ctx, n, ref); err != nil {
		return nil, err
	}
	o := t.owners(int(st.runUID))
	// compose.yaml first, meta last: a crash in between leaves meta on the previous image — the next call completes it
	if _, err := t.writeFile(l.composeFile, r.Compose, o["compose"]); err != nil {
		return nil, err
	}
	configMeta(st.meta, r)
	if err := writeMetaMap(t, l, st.meta); err != nil {
		return nil, err
	}
	uctx, cancel := context.WithTimeout(ctx, upTimeout)
	defer cancel()
	if err := d.cfg.Compose.Compose(uctx, project(n), "up", "--no-start", "--no-build", "--pull", "missing", "--quiet-pull"); err != nil {
		return nil, err
	}
	c, err := d.cfg.Engine.Container(ctx, n.Container)
	if err != nil {
		return nil, err
	}
	if c == nil {
		return nil, fmt.Errorf("container %s does not exist after compose up --no-start", n.Container)
	}
	if err := ownContainer(c, n, ref); err != nil {
		return nil, err
	}
	if c.Image != r.Image {
		return nil, fmt.Errorf("container %s was not created from the target image", n.Container)
	}
	d.cfg.Log.Info("instance_image_switched", "instance_id", l.id, "from", image, "to", r.Image, "container_state", c.State,
		"config_sha256", r.ConfigSHA256)
	return d.status(ctx, t, l, n, ref)
}
