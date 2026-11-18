//go:build linux

package compose

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/google/uuid"

	agentv1 "github.com/zhaduchanhzz/network-access-mesh/api/agent/v1"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/agentspec"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/backupfmt"
)

// withBackups enables backups on the rig: a manifest key, a recovery recipient, the backups directory.
func (rg *rig) withBackups(t *testing.T) *BackupConfig {
	t.Helper()
	if err := os.MkdirAll(rg.h.BackupsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	_, k, _ := ed25519.GenerateKey(rand.Reader)
	rk, _ := backupfmt.NewDataKey()
	rp, _ := backupfmt.DataRecipient(rk)
	rec, _ := backupfmt.RecipientString(rp)
	cfg := &BackupConfig{Signer: k, Verify: []ed25519.PublicKey{k.Public().(ed25519.PublicKey)}, Recovery: rec,
		MaxDBBytes: 64 << 20, Timeout: time.Minute, KeepPrevious: time.Hour}
	rg.d.cfg.Backup = cfg
	rg.e.imageVersion = "v0.29.7+mg.1"
	return cfg
}

// live provisions the rig's instance and activates it through the edge attachment (meta/activated, fingerprint).
func (rg *rig) live(t *testing.T) {
	t.Helper()
	rg.withEdge()
	rg.provision(t, rg.s)
	if _, err := rg.attachRef(rg.s.Ref, uuid.New()); err != nil {
		t.Fatal(err)
	}
}

func (rg *rig) backup(t *testing.T, seq uint64, job uuid.UUID) ([]byte, *agentv1.BackupArtifact) {
	t.Helper()
	dk, _ := backupfmt.NewDataKey()
	pub, _ := backupfmt.DataRecipient(dk)
	a, err := rg.d.Backup(context.Background(), agentspec.Backup{Call: agentspec.Call{Ref: rg.s.Ref, JobID: job}, Sequence: seq, DataRecipient: pub})
	if err != nil {
		t.Fatalf("backup %d: %v", seq, err)
	}
	return dk, a
}

func restoreReq(ref agentspec.Ref, a *agentv1.BackupArtifact, dk, policy []byte) agentspec.Restore {
	return agentspec.Restore{Call: agentspec.Call{Ref: ref, JobID: uuid.New()}, Sequence: a.GetSequence(), ArchiveSHA256: a.GetArchiveSha256(),
		ManifestSHA256: a.GetManifestSha256(), DataKey: dk, Policy: policy}
}

// TestBackupRestore — §17.1–§17.2 on the fake engine (the real sqlite3/age path runs in agent-it): the backup is
// complete and signed; a retried call of the same job returns it; every refusal of T-15 happens before the restore
// helper runs (nothing decrypted); the restore sets the applied policy offline, detaches the edge, swaps data/
// (the previous one kept), starts the instance and serves the applied policy.
func TestBackupRestore(t *testing.T) {
	rg := newRig(t)
	rg.live(t)
	cfg := rg.withBackups(t)
	ctx := context.Background()
	job := uuid.New()
	dk, a := rg.backup(t, 1000, job)
	if a.GetMethod() != agentv1.BackupMethod_BACKUP_METHOD_VACUUM_INTO || a.GetHeadscaleVersion() != "0.29.7" || a.GetNoiseKeyFingerprint() != rg.fingerprintOnDisk(t) {
		t.Fatalf("artifact %+v", a)
	}
	m, err := backupfmt.Parse(a.GetManifest(), a.GetManifestSignature(), cfg.Verify)
	if err != nil {
		t.Fatalf("the returned manifest does not verify: %v", err)
	}
	if err := m.Check(backupfmt.Identity{TenantID: rg.s.Ref.TenantID, InstanceID: rg.s.Ref.InstanceID, Slug: "acme", Sequence: 1000}); err != nil {
		t.Fatal(err)
	}
	bdir := filepath.Join(rg.h.BackupsDir, rg.s.Ref.InstanceID.String())
	for name, mode := range map[string]os.FileMode{backupfmt.ArchiveName(1000): 0o440, backupfmt.ManifestName(1000): 0o400, backupfmt.SignatureName(1000): 0o400} {
		if _, _, md := ownerMode(t, filepath.Join(bdir, name)); md.Perm() != mode {
			t.Errorf("%s mode %v", name, md)
		}
	}
	if fi, err := os.Lstat(filepath.Join(rg.idir, stagingParent)); err == nil {
		t.Fatalf("staging left behind: %v", fi.Mode())
	}
	// a retried call of the same job: the same backup; another job with the same sequence: conflict
	if _, again := rg.backup(t, 1000, job); again.GetArchiveSha256() != a.GetArchiveSha256() {
		t.Fatal("a retried backup changed the archive")
	}
	pub, _ := backupfmt.DataRecipient(dk)
	if _, err := rg.d.Backup(ctx, agentspec.Backup{Call: rg.call(), Sequence: 1000, DataRecipient: pub}); reason(err) != agentv1.RefusalReason_REFUSAL_REASON_CONFLICT {
		t.Fatalf("same sequence, other job: %v", err)
	}
	// the data changes after the backup (a new database page)
	db := filepath.Join(rg.idir, "data", "db.sqlite")
	before, _ := os.ReadFile(db) //nolint:gosec // a temporary directory of the test
	after := bytes.Clone(before)
	after[200] = 0x42
	if err := os.WriteFile(db, after, 0o600); err != nil { //nolint:gosec // G703: a temporary directory of the test
		t.Fatal(err)
	}
	policy := []byte(`{"grants":[]}`)
	runsBefore := rg.e.helperRuns(RestoreUnpackCommand)

	// ---- refusals before anything is decrypted (T-15)
	other, _ := backupfmt.NewDataKey()
	tamper := func(file string, fn func([]byte) []byte) func() {
		p := filepath.Join(bdir, file)
		orig, _ := os.ReadFile(p)                          //nolint:gosec // a temporary directory of the test
		_ = os.WriteFile(p, fn(bytes.Clone(orig)), 0o400)  //nolint:gosec // a temporary directory of the test
		return func() { _ = os.WriteFile(p, orig, 0o400) } //nolint:gosec // G703: a temporary directory of the test
	}
	refusals := []struct {
		name  string
		setup func() func()
		req   agentspec.Restore
		want  agentv1.RefusalReason
	}{
		{"manifest changed (tenant_id)", func() func() {
			return tamper(backupfmt.ManifestName(1000), func(b []byte) []byte {
				return bytes.Replace(b, []byte(rg.s.Ref.TenantID.String()), []byte(uuid.NewString()), 1)
			})
		}, restoreReq(rg.s.Ref, a, dk, policy), agentv1.RefusalReason_REFUSAL_REASON_INTEGRITY},
		{"manifest re-signed with another key", func() func() {
			_, k2, _ := ed25519.GenerateKey(rand.Reader)
			p := filepath.Join(bdir, backupfmt.SignatureName(1000))
			orig, _ := os.ReadFile(p)                                                //nolint:gosec // a temporary directory of the test
			raw, _ := os.ReadFile(filepath.Join(bdir, backupfmt.ManifestName(1000))) //nolint:gosec // a temporary directory of the test
			_ = os.WriteFile(p, backupfmt.Sign(k2, raw), 0o400)                      //nolint:gosec // a temporary directory of the test
			return func() { _ = os.WriteFile(p, orig, 0o400) }                       //nolint:gosec // a temporary directory of the test
		}, restoreReq(rg.s.Ref, a, dk, policy), agentv1.RefusalReason_REFUSAL_REASON_INTEGRITY},
		{"archive changed", func() func() {
			return tamper(backupfmt.ArchiveName(1000), func(b []byte) []byte { b[len(b)-1] ^= 1; return b })
		}, restoreReq(rg.s.Ref, a, dk, policy), agentv1.RefusalReason_REFUSAL_REASON_INTEGRITY},
		{"manifest digest not the recorded one", func() func() { return func() {} }, func() agentspec.Restore {
			r := restoreReq(rg.s.Ref, a, dk, policy)
			r.ManifestSHA256 = strings.Repeat("0", 64)
			return r
		}(), agentv1.RefusalReason_REFUSAL_REASON_INTEGRITY},
		{"no backup with that sequence", func() func() { return func() {} }, func() agentspec.Restore {
			r := restoreReq(rg.s.Ref, a, dk, policy)
			r.Sequence = 999
			return r
		}(), agentv1.RefusalReason_REFUSAL_REASON_NOT_FOUND},
	}
	for _, c := range refusals {
		undo := c.setup()
		_, err := rg.d.Restore(ctx, c.req)
		undo()
		if reason(err) != c.want {
			t.Errorf("%s: want %v, got %v", c.name, c.want, err)
		}
	}
	if n := rg.e.helperRuns(RestoreUnpackCommand); n != runsBefore {
		t.Fatalf("a refused restore ran the decrypting helper (%d runs)", n-runsBefore)
	}
	// wrong data key: the helper cannot decrypt — nothing swapped
	if _, err := rg.d.Restore(ctx, restoreReq(rg.s.Ref, a, other, policy)); reason(err) != agentv1.RefusalReason_REFUSAL_REASON_INTEGRITY {
		t.Fatalf("wrong data key: %v", err)
	}
	if cur, _ := os.ReadFile(db); !bytes.Equal(cur, after) { //nolint:gosec // a temporary directory of the test
		t.Fatal("a refused restore changed data/")
	}
	if !rg.edgeOn(rg.h.Names(rg.s.Ref).Network) {
		t.Fatal("a refused restore detached the edge")
	}

	// ---- the restore
	req := restoreReq(rg.s.Ref, a, dk, policy)
	resp, err := rg.d.Restore(ctx, req)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if cur, _ := os.ReadFile(db); !bytes.Equal(cur, before) { //nolint:gosec // a temporary directory of the test
		t.Fatal("data/db.sqlite is not the backed-up one")
	}
	if !strings.HasPrefix(resp.GetPreviousDataKeptAs(), prevDataPrefix) || resp.GetPolicySha256() != sha256Hex(policy) || resp.GetAlreadyRestored() {
		t.Fatalf("response %+v", resp)
	}
	if kept, _ := os.ReadFile(filepath.Join(rg.idir, resp.GetPreviousDataKeptAs(), "db.sqlite")); !bytes.Equal(kept, after) { //nolint:gosec // a temporary directory of the test
		t.Fatal("the previous data/ was not kept")
	}
	if len(rg.e.offline) != 1 || !bytes.Equal(rg.e.offline[0], policy) {
		t.Fatalf("offline policy set %q", rg.e.offline)
	}
	m2 := rg.meta(t)
	if m2[metaEdgeAttach] == true || rg.edgeOn(rg.h.Names(rg.s.Ref).Network) {
		t.Fatal("the restored instance is still attached to the edge (§17.2: only after PostRestoreReconcile)")
	}
	if c, _ := rg.e.Container(ctx, rg.h.Names(rg.s.Ref).Container); c == nil || c.State != "running" {
		t.Fatal("the restored instance does not run")
	}
	if hs := rg.e.hs[rg.h.Names(rg.s.Ref).Container]; !bytes.Equal(hs.policy, policy) {
		t.Fatalf("served policy %q", hs.policy)
	}
	if _, err := os.Lstat(filepath.Join(rg.idir, "config", restorePolicyFile)); err == nil {
		t.Fatal("config/restore-policy.hujson left behind")
	}
	uid, _, mode := ownerMode(t, filepath.Join(rg.idir, "data"))
	if uid != int(rg.s.RunUID) || mode.Perm() != 0o700 {
		t.Fatalf("data/ %d %v", uid, mode)
	}
	// a retried call of the same job: not decrypted or swapped again
	runs := rg.e.helperRuns(RestoreUnpackCommand)
	req.DataKey = dk
	again, err := rg.d.Restore(ctx, req)
	if err != nil || !again.GetAlreadyRestored() || rg.e.helperRuns(RestoreUnpackCommand) != runs {
		t.Fatalf("retried restore: %v %+v", err, again)
	}
	// keep the backup's policy (PostgreSQL older than the backup): served policy returned for import
	keep := restoreReq(rg.s.Ref, a, dk, nil)
	keep.KeepBackupPolicy, keep.Policy = true, nil
	kr, err := rg.d.Restore(ctx, keep)
	if err != nil || !bytes.Equal(kr.GetBackupPolicyHujson(), policy) {
		t.Fatalf("keep backup policy: %v %+v", err, kr)
	}
}

// TestRestoreRefusesAnotherInstancesArchive (AC-19, T-15): the archive of A copied into B's backup directory is refused
// by its signed identity before anything is decrypted; B's data is untouched.
func TestRestoreRefusesAnotherInstancesArchive(t *testing.T) {
	rg := newRig(t)
	rg.live(t)
	rg.withBackups(t)
	ctx := context.Background()
	b := rg.second("beta")
	rg.provision(t, b)
	if _, err := rg.attachRef(b.Ref, uuid.New()); err != nil {
		t.Fatal(err)
	}
	dk, a := rg.backup(t, 77, uuid.New())
	src := filepath.Join(rg.h.BackupsDir, rg.s.Ref.InstanceID.String())
	dst := filepath.Join(rg.h.BackupsDir, b.Ref.InstanceID.String())
	if err := os.MkdirAll(dst, 0o750); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{backupfmt.ArchiveName(77), backupfmt.ManifestName(77), backupfmt.SignatureName(77)} {
		raw, _ := os.ReadFile(filepath.Join(src, n))                            //nolint:gosec // a temporary directory of the test
		if err := os.WriteFile(filepath.Join(dst, n), raw, 0o400); err != nil { //nolint:gosec // a temporary directory of the test
			t.Fatal(err)
		}
	}
	bdata := filepath.Join(rg.dir, b.Ref.InstanceID.String(), "data", "db.sqlite")
	before, _ := os.ReadFile(bdata) //nolint:gosec // a temporary directory of the test
	runs := rg.e.helperRuns(RestoreUnpackCommand)
	_, err := rg.d.Restore(ctx, restoreReq(b.Ref, a, dk, []byte(`{"grants":[]}`)))
	if reason(err) != agentv1.RefusalReason_REFUSAL_REASON_IDENTITY_MISMATCH {
		t.Fatalf("A's archive into B: %v", err)
	}
	if rg.e.helperRuns(RestoreUnpackCommand) != runs {
		t.Fatal("A's archive was decrypted for B")
	}
	if after, _ := os.ReadFile(bdata); !bytes.Equal(before, after) || !rg.edgeOn(rg.h.Names(b.Ref).Network) { //nolint:gosec // a temporary directory of the test
		t.Fatal("B changed")
	}
	if !strings.Contains(rg.logs.String(), `"kind":"restore.refused"`) {
		t.Fatal("no security event for the refused restore")
	}
}

// TestBackupRefusesHostileDataDir (IT-15, unit level): a symlink to another instance's file, a FIFO, a huge sparse
// file, an unexpected name or a corrupt database in data/ ⇒ the backup fails closed (UNSAFE_PATH / INTEGRITY) with a
// security event, no archive is written, and the next backup of a clean data/ succeeds.
func TestBackupRefusesHostileDataDir(t *testing.T) {
	rg := newRig(t)
	rg.live(t)
	rg.withBackups(t)
	b := rg.second("beta")
	rg.provision(t, b)
	victim := filepath.Join(rg.dir, b.Ref.InstanceID.String(), "data", "noise_private.key")
	data := filepath.Join(rg.idir, "data")
	cases := []struct {
		name   string
		plant  func() func()
		reason agentv1.RefusalReason
	}{
		{"symlink to B's key", func() func() {
			p := filepath.Join(data, "db.sqlite-wal")
			_ = os.Symlink(victim, p)
			return func() { _ = os.Remove(p) }
		}, agentv1.RefusalReason_REFUSAL_REASON_UNSAFE_PATH},
		{"fifo", func() func() {
			p := filepath.Join(data, "db.sqlite-shm")
			_ = syscall.Mkfifo(p, 0o600)
			return func() { _ = os.Remove(p) }
		}, agentv1.RefusalReason_REFUSAL_REASON_UNSAFE_PATH},
		{"huge sparse file", func() func() {
			p := filepath.Join(data, "db.sqlite-wal")
			f, _ := os.Create(p) //nolint:gosec // a temporary directory of the test
			_ = f.Truncate(1 << 40)
			_ = f.Close()
			return func() { _ = os.Remove(p) }
		}, agentv1.RefusalReason_REFUSAL_REASON_UNSAFE_PATH},
		{"unexpected name", func() func() {
			p := filepath.Join(data, "loot")
			_ = os.WriteFile(p, []byte("x"), 0o600) //nolint:gosec // a temporary directory of the test
			return func() { _ = os.Remove(p) }
		}, agentv1.RefusalReason_REFUSAL_REASON_UNSAFE_PATH},
		{"corrupt database", func() func() {
			p := filepath.Join(data, "db.sqlite")
			orig, _ := os.ReadFile(p)                                    //nolint:gosec // a temporary directory of the test
			_ = os.WriteFile(p, bytes.Repeat([]byte{0xff}, 4096), 0o600) //nolint:gosec // a temporary directory of the test
			return func() { _ = os.WriteFile(p, orig, 0o600) }           //nolint:gosec // a temporary directory of the test
		}, agentv1.RefusalReason_REFUSAL_REASON_INTEGRITY},
	}
	bdir := filepath.Join(rg.h.BackupsDir, rg.s.Ref.InstanceID.String())
	for i, c := range cases {
		undo := c.plant()
		dk, _ := backupfmt.NewDataKey()
		pub, _ := backupfmt.DataRecipient(dk)
		seq := uint64(10 + i)
		_, err := rg.d.Backup(context.Background(), agentspec.Backup{Call: rg.call(), Sequence: seq, DataRecipient: pub})
		undo()
		if reason(err) != c.reason {
			t.Errorf("%s: want %v, got %v", c.name, c.reason, err)
		}
		if _, err := os.Lstat(filepath.Join(bdir, backupfmt.ArchiveName(seq))); err == nil {
			t.Errorf("%s: an archive was written", c.name)
		}
	}
	if n := strings.Count(rg.logs.String(), `"msg":"security_event"`); n != len(cases) {
		t.Fatalf("%d security events for %d hostile data directories", n, len(cases))
	}
	rg.backup(t, 100, uuid.New()) // clean again: the backup works
}

// TestStartGuardRefusesCorruptOrOversizedDatabase (IT-15): a start is refused and contained when db.sqlite is no
// SQLite database or larger than its bound (a huge sparse file).
func TestStartGuardRefusesCorruptOrOversizedDatabase(t *testing.T) {
	for name, plant := range map[string]func(p string){
		"corrupt header": func(p string) { _ = os.WriteFile(p, bytes.Repeat([]byte{0}, 4096), 0o600) }, //nolint:gosec // a temporary directory of the test
		"huge sparse": func(p string) {
			f, _ := os.OpenFile(p, os.O_WRONLY, 0) //nolint:gosec // a temporary directory of the test
			_ = f.Truncate(DefaultMaxDBBytes + 4096)
			_ = f.Close()
		},
	} {
		t.Run(name, func(t *testing.T) {
			rg := newRig(t)
			rg.live(t)
			n := rg.h.Names(rg.s.Ref)
			if _, err := rg.d.StopInstance(context.Background(), rg.call()); err != nil {
				t.Fatal(err)
			}
			plant(filepath.Join(rg.idir, "data", "db.sqlite"))
			_, err := rg.d.StartInstance(context.Background(), rg.call())
			if reason(err) != agentv1.RefusalReason_REFUSAL_REASON_STATE {
				t.Fatalf("start: %v", err)
			}
			if rg.edgeOn(n.Network) || rg.meta(t)[metaEdgeAttach] == true {
				t.Fatal("not contained")
			}
			if !strings.Contains(rg.logs.String(), `"msg":"start_guard_failed"`) {
				t.Fatal("no Critical event")
			}
		})
	}
}

// TestRemoveArchived: DELETE_ARCHIVED removes an activated instance's directory only with a valid final backup of it.
func TestRemoveArchived(t *testing.T) {
	rg := newRig(t)
	rg.live(t)
	rg.withBackups(t)
	ctx := context.Background()
	if _, err := rg.d.RemoveEdgeAttachment(ctx, agentspec.EdgeDetach{Call: rg.call(), Reason: agentv1.EdgeDetachReason_EDGE_DETACH_REASON_DEPROVISION}); err != nil {
		t.Fatal(err)
	}
	rm := func(seq uint64) error {
		_, err := rg.d.RemoveInstance(ctx, agentspec.Remove{Call: rg.call(), Data: agentv1.DataDisposition_DATA_DISPOSITION_DELETE_ARCHIVED, ArchiveSequence: seq})
		return err
	}
	if err := rm(5); reason(err) != agentv1.RefusalReason_REFUSAL_REASON_STATE {
		t.Fatalf("no final backup: %v", err)
	}
	if _, err := os.Stat(rg.idir); err != nil {
		t.Fatal("removed without a final backup")
	}
	rg.backup(t, 5, uuid.New())
	if err := rm(5); err != nil {
		t.Fatalf("with the final backup: %v", err)
	}
	if _, err := os.Stat(rg.idir); !os.IsNotExist(err) {
		t.Fatal("directory still there")
	}
}
