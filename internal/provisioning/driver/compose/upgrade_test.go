//go:build linux

package compose

// The agent side of instance.upgrade (P3-T13a) on the fake engine — the real Docker path is agent-it
// (TestUpgradeEndToEnd): InspectImage asks the binary once per digest; PreflightUpgrade decrypts the cold backup into
// staging and runs configtest of the TARGET image on that copy (never data/), removes the copy and config.next/, and
// refuses — before decrypting anything — a running instance, another current image, another configuration, a backup
// of another image, a tampered manifest and a version path §11.4 does not allow; UpgradeInstance swaps the image of a
// stopped instance (compose.yaml + meta, container created again, not started), is idempotent and refuses a running
// instance, a third image and a configuration change.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"

	agentv1 "github.com/zhaduchanhzz/network-access-mesh/api/agent/v1"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/agentspec"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/backupfmt"
)

// upgradeRig: the rig's instance live (activated, edge attached), backups on, and two allowed images — the rig's own
// (patched, "a…") and the official one ("b…"), each with the version its binary reports.
func upgradeRig(t *testing.T) (*rig, agentspec.AllowedImage, agentspec.AllowedImage) {
	t.Helper()
	rg := newRig(t)
	from := rg.s.Image
	to := agentspec.AllowedImage{Repository: OfficialRepository, Digest: "sha256:" + strings.Repeat("b", 64)}
	allow, err := agentspec.ParseAllowlist(strings.NewReader(from.Reference() + "\n" + to.Reference() + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	rg.h.Images = allow
	rg.live(t)
	rg.withBackups(t)
	rg.e.binaryVersion = map[string]string{from.Reference(): "v0.29.7", to.Reference(): "v0.29.7"}
	return rg, from, to
}

func (rg *rig) target(img agentspec.AllowedImage) agentspec.InstanceSpec {
	s := rg.s
	s.Image = img
	return s
}

func (rg *rig) stop(t *testing.T) {
	t.Helper()
	if _, err := rg.d.StopInstance(context.Background(), rg.call()); err != nil {
		t.Fatal(err)
	}
}

// dataSums is sha256 of every file of data/ (the test reads them; the agent never does).
func (rg *rig) dataSums(t *testing.T) map[string]string {
	t.Helper()
	ents, err := os.ReadDir(filepath.Join(rg.idir, "data"))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, e := range ents {
		b, err := os.ReadFile(filepath.Join(rg.idir, "data", e.Name())) //nolint:gosec // a temporary directory of the test
		if err != nil {
			t.Fatal(err)
		}
		s := sha256.Sum256(b)
		out[e.Name()] = hex.EncodeToString(s[:])
	}
	return out
}

func preflightReq(rg *rig, to, from agentspec.AllowedImage, a *agentv1.BackupArtifact, dk []byte) agentspec.Preflight {
	return agentspec.Preflight{Call: rg.call(), Spec: rg.target(to), From: from, Sequence: a.GetSequence(),
		ArchiveSHA256: a.GetArchiveSha256(), ManifestSHA256: a.GetManifestSha256(), DataKey: dk}
}

func TestInspectImage(t *testing.T) {
	rg, _, to := upgradeRig(t)
	ctx := context.Background()
	for range 2 {
		r, err := rg.d.InspectImage(ctx, agentspec.Inspect{Call: rg.call(), Image: to})
		if err != nil || r.GetHeadscaleVersion() != "v0.29.7" || r.GetRepository() != OfficialRepository || r.GetImageDigest() != to.Digest ||
			r.GetCommit() == "" {
			t.Fatalf("InspectImage = %v, %v", r, err)
		}
	}
	if n := rg.e.helperRuns("version"); n != 1 {
		t.Fatalf("version helper ran %d times, want 1 (cached per digest)", n)
	}
	for _, run := range rg.e.runs {
		if run.Cmd[0] == "version" && (run.User != nobody || len(run.Binds) != 0 || run.Image != to.Reference()) {
			t.Fatalf("version helper %+v: no mount, nobody, the inspected image", run)
		}
	}
	// a binary that answers no version (exit 1): an error, nothing cached
	other := agentspec.AllowedImage{Repository: OfficialRepository, Digest: "sha256:" + strings.Repeat("c", 64)}
	if _, err := rg.d.imageVersion(ctx, rg.s.Ref, other); err == nil {
		t.Fatal("an image without a version was accepted")
	}
}

func TestPreflightUpgrade(t *testing.T) {
	rg, from, to := upgradeRig(t)
	ctx := context.Background()
	// running ⇒ refused (the preflight runs on a stopped instance, after the cold backup)
	rg.stop(t)
	dk, a := rg.backup(t, 2000, uuid.New())
	if a.GetMethod() != agentv1.BackupMethod_BACKUP_METHOD_COLD_COPY {
		t.Fatalf("backup of a stopped instance: %s", a.GetMethod())
	}
	before := rg.dataSums(t)
	snap := rg.paths(t)
	var seen []OneShot
	rg.e.configtest = func(cfg []byte) OneShotResult {
		return OneShotResult{Stdout: []byte(`{"level":"info","message":"Opening database"}` + "\n" +
			`{"level":"warn","message":"discarding stored Hostinfo until the node reports again"}` + "\n")}
	}
	r, err := rg.d.PreflightUpgrade(ctx, preflightReq(rg, to, from, a, dk))
	if err != nil || !r.GetValid() || r.GetTargetHeadscaleVersion() != "v0.29.7" || r.GetBackupHeadscaleVersion() != "0.29.7" ||
		!strings.Contains(r.GetDetail(), "discarding stored Hostinfo") {
		t.Fatalf("preflight = %v, %v", r, err)
	}
	for _, run := range rg.e.runs {
		if len(run.Cmd) == 1 && run.Cmd[0] == "configtest" {
			seen = append(seen, run)
		}
	}
	if len(seen) != 1 {
		t.Fatalf("%d configtest runs", len(seen))
	}
	ct := seen[0]
	if ct.Image != to.Reference() || ct.Labels[LabelHelper] != helperPreflightRun {
		t.Fatalf("configtest ran %s (%v), want the target image", ct.Image, ct.Labels)
	}
	var dataBind *Bind
	for i, b := range ct.Binds {
		if b.Target == "/var/lib/headscale" {
			dataBind = &ct.Binds[i]
		}
		if b.Source == filepath.Join(rg.idir, "data") {
			t.Fatal("configtest of the target mounted the live data/")
		}
	}
	if dataBind == nil || dataBind.ReadOnly || !strings.Contains(dataBind.Source, filepath.Join(rg.idir, stagingParent)) {
		t.Fatalf("data of configtest: %+v — want the decrypted copy in staging, writable (migration)", dataBind)
	}
	if got := rg.dataSums(t); !equalMaps(got, before) {
		t.Fatalf("data/ changed: %v → %v", before, got)
	}
	if after := rg.paths(t); after != snap {
		t.Fatalf("host changed by the preflight (staging or config.next left):\n%s\n---\n%s", snap, after)
	}

	// configtest of the target refuses the copy (a stored policy or a migration it cannot handle)
	rg.e.configtest = func([]byte) OneShotResult {
		return OneShotResult{ExitCode: 1, Stdout: []byte(`{"level":"fatal","message":"initializing policy manager: parsing policy"}` + "\n")}
	}
	if r, err := rg.d.PreflightUpgrade(ctx, preflightReq(rg, to, from, a, dk)); err != nil || r.GetValid() || r.GetExitCode() != 1 ||
		!strings.Contains(r.GetDetail(), "policy manager") {
		t.Fatalf("failing configtest = %v, %v", r, err)
	}
	if got := rg.dataSums(t); !equalMaps(got, before) {
		t.Fatal("data/ changed by a failed preflight")
	}
	rg.e.configtest = nil

	// refusals — none of them decrypts anything
	unpacks := rg.e.helperRuns(RestoreUnpackCommand)
	bdir := filepath.Join(rg.h.BackupsDir, rg.s.Ref.InstanceID.String())
	other := rg.target(to)
	other.Headscale.NodeExpiryDays = 30
	cases := []struct {
		name  string
		setup func() func()
		req   agentspec.Preflight
		want  agentv1.RefusalReason
	}{
		{"current image is not from", nil, preflightReq(rg, from, to, a, dk), agentv1.RefusalReason_REFUSAL_REASON_CONFLICT},
		{"another configuration", nil, func() agentspec.Preflight {
			p := preflightReq(rg, to, from, a, dk)
			p.Spec = other
			return p
		}(), agentv1.RefusalReason_REFUSAL_REASON_CONFLICT},
		{"manifest tampered", func() func() {
			p := filepath.Join(bdir, backupfmt.ManifestName(2000))
			orig, _ := os.ReadFile(p)                                                                          //nolint:gosec // test dir
			_ = os.WriteFile(p, bytes.Replace(orig, []byte(`"cold_copy"`), []byte(`"vacuum_into"`), 1), 0o400) //nolint:gosec // test dir
			return func() { _ = os.WriteFile(p, orig, 0o400) }                                                 //nolint:gosec // G703: test dir
		}, preflightReq(rg, to, from, a, dk), agentv1.RefusalReason_REFUSAL_REASON_INTEGRITY},
		{"target skips a minor", func() func() {
			rg.e.binaryVersion[to.Reference()] = "v0.31.0"
			rg.d.versions = versionCache{}
			return func() { rg.e.binaryVersion[to.Reference()] = "v0.29.7"; rg.d.versions = versionCache{} }
		}, preflightReq(rg, to, from, a, dk), agentv1.RefusalReason_REFUSAL_REASON_STATE},
		{"target is a downgrade", func() func() {
			rg.e.binaryVersion[to.Reference()] = "v0.29.6"
			rg.d.versions = versionCache{}
			return func() { rg.e.binaryVersion[to.Reference()] = "v0.29.7"; rg.d.versions = versionCache{} }
		}, preflightReq(rg, to, from, a, dk), agentv1.RefusalReason_REFUSAL_REASON_STATE},
		{"instance running", func() func() {
			if _, err := rg.d.StartInstance(ctx, rg.call()); err != nil {
				t.Fatal(err)
			}
			return func() { rg.stop(t) }
		}, preflightReq(rg, to, from, a, dk), agentv1.RefusalReason_REFUSAL_REASON_STATE},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			undo := func() {}
			if c.setup != nil {
				undo = c.setup()
			}
			defer undo()
			_, err := rg.d.PreflightUpgrade(ctx, c.req)
			if reason(err) != c.want {
				t.Fatalf("got %v, want %s", err, c.want)
			}
		})
	}
	if n := rg.e.helperRuns(RestoreUnpackCommand); n != unpacks {
		t.Fatalf("a refused preflight decrypted the archive (%d unpack runs, want %d)", n, unpacks)
	}
}

func TestUpgradeInstance(t *testing.T) {
	rg, from, to := upgradeRig(t)
	ctx := context.Background()
	up := func(f, t2 agentspec.AllowedImage) (*agentv1.InstanceStatus, error) {
		return rg.d.UpgradeInstance(ctx, agentspec.Upgrade{Call: rg.call(), From: f, To: t2, Spec: rg.target(t2)})
	}
	if _, err := up(from, to); reason(err) != agentv1.RefusalReason_REFUSAL_REASON_STATE {
		t.Fatalf("switch of a running instance: %v", err)
	}
	rg.stop(t)
	data := rg.dataSums(t)
	cfgBefore, _ := os.ReadFile(filepath.Join(rg.idir, "config", "config.yaml")) //nolint:gosec // test dir
	st, err := up(from, to)
	if err != nil {
		t.Fatal(err)
	}
	if st.GetContainerState() != agentv1.ContainerState_CONTAINER_STATE_CREATED || st.GetImageDigest() != to.Digest {
		t.Fatalf("after the switch: %s %s (want a created container of the target, not started)", st.GetContainerState(), st.GetImageDigest())
	}
	m := rg.meta(t)
	cmp, _ := os.ReadFile(filepath.Join(rg.idir, "compose.yaml"))               //nolint:gosec // test dir
	cfgAfter, _ := os.ReadFile(filepath.Join(rg.idir, "config", "config.yaml")) //nolint:gosec // test dir
	if m["image"] != to.Reference() || !bytes.Contains(cmp, []byte("image: "+to.Reference())) || bytes.Contains(cmp, []byte(from.Digest)) ||
		!bytes.Equal(cfgBefore, cfgAfter) || m[metaFingerprint] == nil || m[metaEdgeAttach] != true {
		t.Fatalf("meta %v, compose has target: %v, config unchanged: %v", m, bytes.Contains(cmp, []byte(to.Digest)), bytes.Equal(cfgBefore, cfgAfter))
	}
	if got := rg.dataSums(t); !equalMaps(got, data) {
		t.Fatal("the switch touched data/")
	}
	// a retried call: nothing changes
	c1, _ := rg.e.Container(ctx, "mg-hs-acme")
	if _, err := up(from, to); err != nil {
		t.Fatalf("retried switch: %v", err)
	}
	c2, _ := rg.e.Container(ctx, "mg-hs-acme")
	if c1.ID != c2.ID {
		t.Fatal("a retried switch created the container again")
	}
	// start (start guard) — the target image runs
	if st, err := rg.d.StartInstance(ctx, rg.call()); err != nil || st.GetContainerState() != agentv1.ContainerState_CONTAINER_STATE_RUNNING ||
		st.GetImageDigest() != to.Digest {
		t.Fatalf("start after the switch: %v, %v", st, err)
	}
	// a third image (compare-and-swap), a configuration change ⇒ refused; switching back needs a stopped instance
	third := agentspec.AllowedImage{Repository: OfficialRepository, Digest: "sha256:" + strings.Repeat("c", 64)}
	allow, _ := agentspec.ParseAllowlist(strings.NewReader(from.Reference() + "\n" + to.Reference() + "\n" + third.Reference() + "\n"))
	rg.h.Images = allow
	rg.stop(t)
	if _, err := up(third, from); reason(err) != agentv1.RefusalReason_REFUSAL_REASON_CONFLICT {
		t.Fatalf("switch from an image the instance does not run: %v", err)
	}
	spec := rg.target(from)
	spec.Headscale.LogLevel = "warn"
	if _, err := rg.d.UpgradeInstance(ctx, agentspec.Upgrade{Call: rg.call(), From: to, To: from, Spec: spec}); reason(err) != agentv1.RefusalReason_REFUSAL_REASON_CONFLICT {
		t.Fatalf("switch that changes the configuration: %v", err)
	}
	// the switch back (the rollback of an upgrade)
	if st, err := up(to, from); err != nil || st.GetImageDigest() != from.Digest {
		t.Fatalf("switch back: %v, %v", st, err)
	}
	if rg.meta(t)["image"] != from.Reference() {
		t.Fatal("meta not back on the previous image")
	}
}

// paths lists every path under the instance directory with its type and owner (not the times: a directory's mtime
// changes when the agent creates and removes its staging directory and config.next/ inside it).
func (rg *rig) paths(t *testing.T) string {
	t.Helper()
	var lines []string
	err := filepath.WalkDir(rg.idir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		uid, gid, mode := ownerMode(t, p)
		rel, _ := filepath.Rel(rg.idir, p)
		lines = append(lines, fmt.Sprintf("%s %v %d:%d", rel, mode, uid, gid))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return strings.Join(lines, "\n")
}

func equalMaps(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}
