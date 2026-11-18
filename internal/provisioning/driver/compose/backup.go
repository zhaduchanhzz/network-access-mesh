package compose

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "github.com/zhaduchanhzz/network-access-mesh/api/agent/v1"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/agentspec"
	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/backupfmt"
)

// Backup/restore v1 (P3-T11; §17.1–§17.2). Layout of backups/tenants/<instance_id>/ (an os.Root at the backups
// directory — symlinks never followed): the three files of each backup (backupfmt.ArchiveName…), root-owned; the
// archive 0440 root:run_gid so that the restore helper (run_uid) can read it through a read-only bind mount, the
// manifest and its signature 0400. The staging directory of a job is <instance>/.staging/<op>-<random>/ (run_uid, 0700
// — under .staging/, root:run_gid 0750), created and removed by the agent around each helper run.

// BackupConfig enables Backup and Restore. Nil in Config: both are refused (STATE) — the key ceremony (P2-T04a) was
// not done on this host.
type BackupConfig struct {
	// Signer is the manifest signing key (secrets/agent/manifest_signing_key — held by the agent only, §7.6).
	Signer ed25519.PrivateKey
	// Verify are the trusted manifest keys: the signer's public key and older keys still listed in
	// MG_BACKUP_MANIFEST_PUBKEY (archives signed before a rotation).
	Verify []ed25519.PublicKey
	// Recovery is the platform recovery recipient (age X25519 — the DR path, private key offline).
	Recovery string
	// MaxDBBytes bounds db.sqlite and its -wal (§17.1).
	MaxDBBytes int64
	// Timeout bounds one helper run (backup-snapshot, restore-unpack, the offline policy set).
	Timeout time.Duration
	// KeepPrevious is how long the data/ replaced by a restore is kept (data.prev-<time>).
	KeepPrevious time.Duration
}

const (
	modeBackupDir     = 0o750 // root:run_gid
	modeArchive       = 0o440 // root:run_gid — read by the restore helper through a bind mount
	modeManifest      = 0o400 // root:root
	modeStagingParent = 0o750 // root:run_gid
	modeStagingJob    = 0o700 // run_uid:run_gid
	stagingParent     = ".staging"
	prevDataPrefix    = "data.prev-"
	prevDataLayout    = "20060102T150405.000000000Z"
	// restorePolicyFile is the policy a restore sets, in config/ (the container sees it at /etc/headscale/…).
	restorePolicyFile        = "restore-policy.hujson"
	restorePolicyInContainer = "/etc/headscale/" + restorePolicyFile
	maxArchiveBytes          = 64 << 30
	metaRestore              = "restore"
	healthWait               = 90 * time.Second
	helperMemory             = 512 << 20
)

func (d *Driver) backupCfg() (*BackupConfig, error) {
	if d.cfg.Backup == nil {
		return nil, state("instance", "backups are not configured on this agent (MG_AGENT_MANIFEST_SIGNING_KEY_FILE, MG_AGENT_BACKUP_RECOVERY_RECIPIENT — key ceremony P2-T04a)")
	}
	if d.cfg.HelperImage == "" {
		return nil, state("instance", "no helper image configured (MG_AGENT_HELPER_IMAGE)")
	}
	return d.cfg.Backup, nil
}

func integrity(field, format string, args ...any) error {
	return &agentspec.Refusal{Reason: agentv1.RefusalReason_REFUSAL_REASON_INTEGRITY, Field: field, Msg: fmt.Sprintf(format, args...)}
}

func (d *Driver) openBackups() (*tree, error) {
	if d.cfg.Host.BackupsDir == "" {
		return nil, errors.New("no backups directory configured")
	}
	return openTree(d.cfg.Host.BackupsDir, d.cfg.Host.OwnerUID, d.cfg.AgentGID)
}

// newStaging creates a fresh staging directory of the instance for one helper run (leftovers of interrupted runs of
// this instance are removed first: the caller holds the instance's lock).
func (d *Driver) newStaging(t *tree, l layout, runUID int, op string) (string, error) {
	parent := filepath.Join(l.dir, stagingParent)
	if err := t.removeAll(parent); err != nil {
		return "", err
	}
	if _, err := t.ensureDir(parent, owner{t.agentUID, runUID, modeStagingParent}, true); err != nil {
		return "", err
	}
	var rnd [4]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return "", err
	}
	rel := filepath.Join(parent, op+"-"+hex.EncodeToString(rnd[:]))
	if _, err := t.ensureDir(rel, owner{runUID, runUID, modeStagingJob}, true); err != nil {
		return "", err
	}
	return rel, nil
}

func (d *Driver) dropStaging(t *tree, l layout) {
	if err := t.removeAll(filepath.Join(l.dir, stagingParent)); err != nil {
		d.cfg.Log.Error("staging_cleanup_failed", "instance_id", l.id, "error", err)
	}
}

// helperSpec is a one-shot container of the agent image running a backup helper as the instance's run_uid.
func (d *Driver) helperSpec(ref agentspec.Ref, runUID uint32, op, cmd string, binds []Bind, stdin []byte, timeout time.Duration) (OneShot, error) {
	name, err := helperName(ref.Slug, op)
	if err != nil {
		return OneShot{}, err
	}
	uid := strconv.FormatUint(uint64(runUID), 10)
	return OneShot{
		Name: name, Image: d.cfg.HelperImage, Entrypoint: []string{HelperBinary}, Cmd: []string{cmd},
		User: uid + ":" + uid, Labels: helperLabels(ref, op), Binds: binds,
		Tmpfs:       map[string]string{"/tmp": "uid=" + uid + ",gid=" + uid + ",mode=0700,size=16m"},
		MemoryBytes: helperMemory, NanoCPUs: 1_000_000_000, PIDs: 64, Timeout: timeout, MaxOutput: 64 << 10, Stdin: stdin,
	}, nil
}

// runHelper runs a helper and decodes its result. A helper that could not run, timed out or answered nonsense is an
// error (fail closed); a definitive "unsafe" or "integrity" outcome is a typed refusal plus the security log line.
func (d *Driver) runHelper(ctx context.Context, spec OneShot, ref agentspec.Ref, op string) (*HelperResult, error) {
	if err := d.cfg.Engine.EnsureImage(ctx, spec.Image); err != nil {
		return nil, err
	}
	res, err := d.cfg.Engine.RunOnce(ctx, spec)
	if err != nil {
		d.cfg.Log.Error("backup_helper_failed", "severity", "high", "instance_id", ref.InstanceID.String(), "op", op, "error", err)
		return nil, fmt.Errorf("%s helper: %w", op, err)
	}
	var out HelperResult
	if json.Unmarshal(bytes.TrimSpace(res.Stdout), &out) != nil || res.Truncated {
		return nil, fmt.Errorf("%s helper: exit code %d, unreadable result", op, res.ExitCode)
	}
	switch {
	case res.ExitCode == 0 && out.OK:
		return &out, nil
	case res.ExitCode == HelperExitUnsafe:
		// the security event of IT-15 (§17.1): a hostile data directory or archive — nothing was read past it
		d.cfg.Log.Error("security_event", "kind", "backup.unsafe_data", "severity", "high", "alert", "MeshGuardBackupUnsafeData",
			"instance_id", ref.InstanceID.String(), "tenant_id", ref.TenantID.String(), "op", op, "reason", out.Reason, "path", out.Path)
		return nil, &agentspec.Refusal{Reason: agentv1.RefusalReason_REFUSAL_REASON_UNSAFE_PATH, Field: "instance",
			Msg: fmt.Sprintf("%s refused (fail closed): %s %s", op, out.Reason, out.Path)}
	case res.ExitCode == HelperExitIntegrity:
		d.cfg.Log.Error("security_event", "kind", "backup.integrity", "severity", "high", "alert", "MeshGuardBackupIntegrity",
			"instance_id", ref.InstanceID.String(), "tenant_id", ref.TenantID.String(), "op", op, "reason", out.Reason, "path", out.Path)
		return nil, integrity("instance", "%s refused (fail closed): %s %s", op, out.Reason, out.Path)
	default:
		return nil, fmt.Errorf("%s helper: exit code %d: %s", op, res.ExitCode, out.Reason)
	}
}

// ---------------------------------------------------------------------------------------------------- Backup

// Backup — §17.1. Under the instance lock (the server takes it): VACUUM INTO when the container runs, a cold copy when
// it is stopped; the helper writes the age-encrypted tar into the job's staging directory; the agent copies the
// ciphertext into backups/tenants/<instance_id>/ hashing it, then writes and signs the manifest. A complete backup of
// the same sequence and job is returned as is (a retried call); one of another job is a conflict.
func (d *Driver) Backup(ctx context.Context, b agentspec.Backup) (*agentv1.BackupArtifact, error) {
	cfg, err := d.backupCfg()
	if err != nil {
		return nil, err
	}
	n, l := d.cfg.Host.Names(b.Ref), newLayout(b.Ref.InstanceID.String())
	t, err := d.open()
	if err != nil {
		return nil, err
	}
	defer func() { _ = t.Close() }()
	st, err := d.readState(t, l, b.Ref.InstanceID)
	if err != nil {
		return nil, err
	}
	bt, err := d.openBackups()
	if err != nil {
		return nil, err
	}
	defer func() { _ = bt.Close() }()
	dir := l.id
	if _, err := bt.ensureDir(dir, owner{bt.agentUID, int(st.runUID), modeBackupDir}, true); err != nil {
		return nil, err
	}
	if a, err := d.existingBackup(bt, dir, b, cfg); a != nil || err != nil {
		return a, err
	}
	image, _ := st.meta["image"].(string)
	if image == "" {
		return nil, state("instance", "the instance has no rendered configuration yet (meta/instance.json image)")
	}
	version := d.headscaleVersion(ctx, b.Ref, image)
	method := backupfmt.MethodColdCopy
	pmethod := agentv1.BackupMethod_BACKUP_METHOD_COLD_COPY
	if c, err := d.cfg.Engine.Container(ctx, n.Container); err != nil {
		return nil, err
	} else if c != nil {
		if err := ownContainer(c, n, b.Ref); err != nil {
			return nil, err
		}
		if c.State == "running" || c.State == "restarting" || c.State == "paused" {
			method, pmethod = backupfmt.MethodVacuumInto, agentv1.BackupMethod_BACKUP_METHOD_VACUUM_INTO
		}
	}
	dataRecipient, err := backupfmt.RecipientString(b.DataRecipient)
	if err != nil {
		return nil, &agentspec.Refusal{Reason: agentv1.RefusalReason_REFUSAL_REASON_MALFORMED, Field: "data_recipient", Msg: "not an X25519 public key"}
	}
	staging, err := d.newStaging(t, l, int(st.runUID), "backup")
	if err != nil {
		return nil, err
	}
	defer d.dropStaging(t, l)
	req, err := json.Marshal(BackupHelperRequest{Method: method, Recipients: []string{dataRecipient, cfg.Recovery}, MaxDBBytes: cfg.MaxDBBytes})
	if err != nil {
		return nil, err
	}
	spec, err := d.helperSpec(b.Ref, st.runUID, "backup", BackupSnapshotCommand, []Bind{
		{Source: n.DataDir, Target: helperDataDir, ReadOnly: true},
		{Source: n.ConfigDir, Target: filepath.Dir(helperConfigFile), ReadOnly: true},
		{Source: n.RecordsDir, Target: filepath.Dir(helperRecordsFile), ReadOnly: true},
		{Source: filepath.Join(d.cfg.Host.TenantsDir, staging), Target: helperStagingDir},
	}, req, cfg.Timeout)
	if err != nil {
		return nil, err
	}
	created := time.Now().UTC()
	res, err := d.runHelper(ctx, spec, b.Ref, "backup")
	if err != nil {
		return nil, err
	}
	if res.NoiseFingerprint != "" {
		if rec, _ := st.meta[metaFingerprint].(string); rec != "" && rec != res.NoiseFingerprint {
			return nil, integrity("instance", "the Noise key in data/ is not the one recorded at activation (start guard, §11.4) — not backed up")
		}
	}
	sum, size, err := copyArchive(t, filepath.Join(staging, stagingArchive), int(st.runUID), bt, filepath.Join(dir, backupfmt.ArchiveName(b.Sequence)),
		owner{bt.agentUID, int(st.runUID), modeArchive})
	if err != nil {
		return nil, err
	}
	if res.ArchiveSize != 0 && res.ArchiveSize != size {
		return nil, integrity("instance", "the archive changed between the helper and the copy")
	}
	tv, _ := st.meta["template_version"].(string)
	cs, _ := st.meta["config_sha256"].(string)
	m := &backupfmt.Manifest{
		Format: backupfmt.Format, TenantID: b.Ref.TenantID.String(), InstanceID: b.Ref.InstanceID.String(), Slug: b.Ref.Slug,
		Sequence: b.Sequence, JobID: b.JobID.String(), CreatedAt: created.Format(time.RFC3339Nano), Method: method,
		Image: image, HeadscaleVersion: version, TemplateVersion: tv, ConfigSHA256: cs, NoiseFingerprint: res.NoiseFingerprint,
		SQLiteVersion: res.SQLiteVersion, Files: res.Files,
		Archive: backupfmt.Archive{SHA256: sum, Size: size, Encryption: backupfmt.EncryptionAgeV1,
			Recipients: []string{"data-key:" + dataRecipient, "recovery:" + cfg.Recovery}},
		SigningKey: backupfmt.KeyID(cfg.Signer.Public().(ed25519.PublicKey)),
	}
	raw, err := m.Encode()
	if err != nil {
		return nil, err
	}
	sig := backupfmt.Sign(cfg.Signer, raw)
	// the manifest is written last: its presence means the backup is complete
	if _, err := bt.writeFile(filepath.Join(dir, backupfmt.SignatureName(b.Sequence)), sig, owner{bt.agentUID, bt.agentGID, modeManifest}); err != nil {
		return nil, err
	}
	if _, err := bt.writeFile(filepath.Join(dir, backupfmt.ManifestName(b.Sequence)), raw, owner{bt.agentUID, bt.agentGID, modeManifest}); err != nil {
		return nil, err
	}
	removed := d.pruneArchives(bt, dir, b.RetainFrom, b.Sequence)
	d.cfg.Log.Info("backup_created", "instance_id", l.id, "sequence", b.Sequence, "method", method, "archive_sha256", sum,
		"size_bytes", size, "headscale_version", version, "removed_archives", removed)
	return artifact(m, raw, sig, pmethod, removed), nil
}

func artifact(m *backupfmt.Manifest, raw, sig []byte, method agentv1.BackupMethod, removed uint32) *agentv1.BackupArtifact {
	ms := sha256.Sum256(raw)
	return &agentv1.BackupArtifact{Sequence: m.Sequence, ArchiveSha256: m.Archive.SHA256, ManifestSha256: hex.EncodeToString(ms[:]),
		SizeBytes: uint64(m.Archive.Size), Method: method, CreatedAt: timestamppb.New(m.Time()), //nolint:gosec // G115: a size ≥ 0
		HeadscaleVersion: m.HeadscaleVersion, Manifest: raw, ManifestSignature: sig, NoiseKeyFingerprint: m.NoiseFingerprint,
		RemovedArchives: removed}
}

// existingBackup handles a sequence that already has files: a complete, valid backup of the same job is returned (a
// retried call); a complete one of another job is a conflict; partial files (an interrupted run) are removed.
func (d *Driver) existingBackup(bt *tree, dir string, b agentspec.Backup, cfg *BackupConfig) (*agentv1.BackupArtifact, error) {
	raw, err := bt.readFile(filepath.Join(dir, backupfmt.ManifestName(b.Sequence)), backupfmt.MaxManifestBytes)
	if err != nil {
		return nil, err
	}
	if raw == nil {
		for _, name := range []string{backupfmt.ArchiveName(b.Sequence), backupfmt.SignatureName(b.Sequence)} {
			if err := bt.removeFile(filepath.Join(dir, name)); err != nil {
				return nil, err
			}
		}
		return nil, nil
	}
	m, sig, err := d.verifiedManifest(bt, dir, b.Sequence, raw, cfg)
	if err != nil {
		return nil, err
	}
	if m.JobID != b.JobID.String() || m.TenantID != b.Ref.TenantID.String() || m.InstanceID != b.Ref.InstanceID.String() {
		return nil, &agentspec.Refusal{Reason: agentv1.RefusalReason_REFUSAL_REASON_CONFLICT, Field: "sequence",
			Msg: "a backup with this sequence already exists (another job)"}
	}
	method := agentv1.BackupMethod_BACKUP_METHOD_VACUUM_INTO
	if m.Method == backupfmt.MethodColdCopy {
		method = agentv1.BackupMethod_BACKUP_METHOD_COLD_COPY
	}
	return artifact(m, raw, sig, method, d.pruneArchives(bt, dir, b.RetainFrom, b.Sequence)), nil
}

// verifiedManifest reads the signature of a manifest already read, verifies it and the archive's digest.
func (d *Driver) verifiedManifest(bt *tree, dir string, seq uint64, raw []byte, cfg *BackupConfig) (*backupfmt.Manifest, []byte, error) {
	sig, err := bt.readFile(filepath.Join(dir, backupfmt.SignatureName(seq)), backupfmt.MaxSignatureBytes)
	if err != nil {
		return nil, nil, err
	}
	m, err := backupfmt.Parse(raw, sig, cfg.Verify)
	if err != nil {
		return nil, nil, integrity("artifact", "%v", err)
	}
	sum, size, err := hashFile(bt, filepath.Join(dir, backupfmt.ArchiveName(seq)))
	if err != nil {
		return nil, nil, err
	}
	if sum != m.Archive.SHA256 || size != m.Archive.Size {
		return nil, nil, integrity("artifact", "the archive's digest or size differs from its signed manifest")
	}
	return m, sig, nil
}

// pruneArchives removes the complete and partial backups of the directory with a sequence below from (never the
// current one); it returns how many backups were removed.
func (d *Driver) pruneArchives(bt *tree, dir string, from, current uint64) uint32 {
	if from == 0 {
		return 0
	}
	ents, err := fs.ReadDir(bt.root.FS(), dir)
	if err != nil {
		d.cfg.Log.Error("backup_prune_failed", "instance_id", dir, "error", err)
		return 0
	}
	seqs := map[uint64]bool{}
	for _, e := range ents {
		seq, ok := backupfmt.ParseName(e.Name())
		if !ok || seq >= from || seq == current {
			continue
		}
		if err := bt.removeFile(filepath.Join(dir, e.Name())); err != nil {
			d.cfg.Log.Error("backup_prune_failed", "instance_id", dir, "error", err)
			continue
		}
		seqs[seq] = true
	}
	return uint32(len(seqs)) //nolint:gosec // G115: a directory listing
}

// copyArchive copies the ciphertext the helper wrote (a regular file of run_uid in the staging directory, opened
// without following anything) into the backups tree under a temporary name, hashing it, then renames it into place.
func copyArchive(t *tree, src string, runUID int, bt *tree, dst string, o owner) (string, int64, error) {
	fi, err := t.lstat(src)
	if err != nil {
		return "", 0, err
	}
	if fi == nil {
		return "", 0, errors.New("the helper wrote no archive")
	}
	if uid, _, ok := fileOwner(fi); !fi.Mode().IsRegular() || (ok && uid != runUID) || fi.Size() <= 0 || fi.Size() > maxArchiveBytes {
		return "", 0, unsafePath(src, "the archive is not a regular file of the instance within its bound")
	}
	in, err := t.root.Open(src)
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = in.Close() }()
	if st, err := in.Stat(); err != nil || !os.SameFile(st, fi) {
		return "", 0, unsafePath(src, "replaced while being read")
	}
	tmp := dst + ".partial"
	_ = bt.root.Remove(tmp)
	out, err := bt.root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", 0, err
	}
	ok := false
	defer func() {
		if !ok {
			_ = out.Close()
			_ = bt.root.Remove(tmp)
		}
	}()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(out, h), io.LimitReader(in, maxArchiveBytes+1))
	if err != nil {
		return "", 0, err
	}
	if n != fi.Size() {
		return "", 0, unsafePath(src, "changed while being copied")
	}
	if err := out.Chown(o.uid, o.gid); err != nil {
		return "", 0, err
	}
	if err := out.Chmod(o.mode); err != nil {
		return "", 0, err
	}
	if err := out.Sync(); err != nil {
		return "", 0, err
	}
	if err := out.Close(); err != nil {
		return "", 0, err
	}
	ok = true
	if err := bt.root.Rename(tmp, dst); err != nil {
		_ = bt.root.Remove(tmp)
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, bt.syncDir(filepath.Dir(dst))
}

// hashFile hashes a regular file of the backups tree.
func hashFile(bt *tree, rel string) (string, int64, error) {
	fi, err := bt.lstat(rel)
	if err != nil {
		return "", 0, err
	}
	if fi == nil {
		return "", 0, integrity("artifact", "the archive does not exist")
	}
	if !fi.Mode().IsRegular() {
		return "", 0, unsafePath(rel, "not a regular file")
	}
	f, err := bt.root.Open(rel)
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = f.Close() }()
	if st, err := f.Stat(); err != nil || !os.SameFile(st, fi) {
		return "", 0, unsafePath(rel, "replaced while being read")
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, maxArchiveBytes+1))
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// checkFinalBackup is the condition of RemoveInstance(DELETE_ARCHIVED) (§11.4 Deprovision: backup cuối): the backup
// ArchiveSequence of this instance exists, its manifest is signed by a trusted key, describes this tenant, instance
// and slug, and the archive matches it.
func (d *Driver) checkFinalBackup(r agentspec.Remove) error {
	cfg, err := d.backupCfg()
	if err != nil {
		return err
	}
	bt, err := d.openBackups()
	if err != nil {
		return err
	}
	defer func() { _ = bt.Close() }()
	dir := r.Ref.InstanceID.String()
	raw, err := bt.readFile(filepath.Join(dir, backupfmt.ManifestName(r.ArchiveSequence)), backupfmt.MaxManifestBytes)
	if err != nil {
		return err
	}
	if raw == nil {
		return state("archived_backup_sequence", "no final backup with this sequence — the directory of an activated instance is never deleted without one")
	}
	m, _, err := d.verifiedManifest(bt, dir, r.ArchiveSequence, raw, cfg)
	if err != nil {
		return err
	}
	if err := m.Check(backupfmt.Identity{TenantID: r.Ref.TenantID, InstanceID: r.Ref.InstanceID, Slug: r.Ref.Slug, Sequence: r.ArchiveSequence}); err != nil {
		return &agentspec.Refusal{Reason: agentv1.RefusalReason_REFUSAL_REASON_IDENTITY_MISMATCH, Field: "archived_backup_sequence", Msg: err.Error()}
	}
	return nil
}

// headscaleVersion is the Headscale version of an image: the label org.opencontainers.image.version (the MeshGuard
// build carries it — P2-T10a), else what the binary reports (`headscale version -o json` in a one-shot container — the
// official image has no such label; P3-T13a), "unknown" when neither answers.
func (d *Driver) headscaleVersion(ctx context.Context, ref agentspec.Ref, image string) string {
	v, err := d.cfg.Engine.ImageVersion(ctx, image)
	if err != nil {
		d.cfg.Log.Warn("image_version_unavailable", "image", image, "error", err)
	}
	if pv, ok := backupfmt.ParseVersion(v); ok {
		return pv.String()
	}
	if _, digest, ok := strings.Cut(image, "@"); ok {
		if img, allowed := d.cfg.Host.Images.Lookup(digest); allowed && img.Reference() == image {
			iv, err := d.imageVersion(ctx, ref, img)
			if err == nil {
				if pv, ok := backupfmt.ParseVersion(iv.Version); ok {
					return pv.String()
				}
			}
			d.cfg.Log.Warn("image_version_unavailable", "image", image, "error", err)
		}
	}
	return "unknown"
}

// ---------------------------------------------------------------------------------------------------- Restore

// Restore — §17.2 steps 2–4 (step 5 is PostRestoreReconcile, step 6 the worker): the manifest's signature, hashes,
// identity (tenant, instance, slug, sequence), Noise key and version are checked BEFORE anything is decrypted; the
// restore helper decrypts and unpacks into the staging directory (regular entries of the manifest only, digests
// checked, integrity_check); the policy is set offline on the restored database (Headscale one-shot, no network) —
// the restored database never serves its old policy; the edge_attach flag is cleared, the edge detached, the instance
// stopped; data/ is renamed to data.prev-<time> and the staging data/ renamed into place; the instance starts — still
// without the edge — passing the start guard; the policy is set again over the CLI (exact bytes) and read back.
//
// Every refusal before the first change — the edge_attach flag cleared, the edge detached, the instance stopped
// (detachForRestore), or the restore of the same job found already swapped in — is marked unchanged
// (Refusal.unchanged): the worker then ends the job without keeping the tenant's lifecycle lock. Until then only the
// scratch files of a restore are written (the staging directory, removed on return, and config/restore-policy.hujson,
// which the running instance never reads and the next restore rewrites).
func (d *Driver) Restore(ctx context.Context, r agentspec.Restore) (*agentv1.RestoreResponse, error) {
	changed := false
	resp, err := d.restore(ctx, r, &changed)
	if err != nil && !changed {
		return nil, agentspec.Unchanged(err)
	}
	return resp, err
}

// restore is Restore; *changed is set just before the first change of the instance.
func (d *Driver) restore(ctx context.Context, r agentspec.Restore, changed *bool) (*agentv1.RestoreResponse, error) {
	cfg, err := d.backupCfg()
	if err != nil {
		return nil, err
	}
	n, l := d.cfg.Host.Names(r.Ref), newLayout(r.Ref.InstanceID.String())
	t, err := d.open()
	if err != nil {
		return nil, err
	}
	defer func() { _ = t.Close() }()
	st, err := d.readState(t, l, r.Ref.InstanceID)
	if err != nil {
		return nil, err
	}
	recorded, _ := st.meta[metaFingerprint].(string)
	if !st.activated || !fingerprintRE.MatchString(recorded) {
		return nil, state("instance", "only an activated instance with a recorded Noise key fingerprint is restored (v1)")
	}
	bt, err := d.openBackups()
	if err != nil {
		return nil, err
	}
	defer func() { _ = bt.Close() }()
	// ---- everything below until the helper runs: no byte of the archive is decrypted
	m, err := d.checkArchive(ctx, bt, l.id, r, cfg, st, recorded)
	if err != nil {
		d.cfg.Log.Error("security_event", "kind", "restore.refused", "severity", "high", "instance_id", l.id,
			"tenant_id", r.Ref.TenantID.String(), "sequence", r.Sequence, "error", err)
		return nil, err
	}
	filesSum := backupfmt.FilesSHA256(m.Files, "data/")
	if !r.KeepBackupPolicy {
		// the policy the restore sets, offline and again over the CLI: config/restore-policy.hujson (root:run_gid 0440)
		if _, err := t.writeFile(filepath.Join(l.config, restorePolicyFile), r.Policy, t.owners(int(st.runUID))["tenant"]); err != nil {
			return nil, err
		}
	}
	if prev, ok := st.meta[metaRestore].(map[string]any); ok && prev["job_id"] == r.JobID.String() && prev["sequence"] == strconv.FormatUint(r.Sequence, 10) {
		kept, _ := prev["kept_as"].(string)
		*changed = true // swapped in by an earlier call of this job
		return d.finishRestore(ctx, t, l, n, r, filesSum, kept, true)
	}
	staging, err := d.newStaging(t, l, int(st.runUID), "restore")
	if err != nil {
		return nil, err
	}
	defer d.dropStaging(t, l)
	identity, err := backupfmt.AgeIdentity(r.DataKey)
	if err != nil {
		return nil, &agentspec.Refusal{Reason: agentv1.RefusalReason_REFUSAL_REASON_MALFORMED, Field: "data_key", Msg: "not a data key"}
	}
	req, err := json.Marshal(RestoreHelperRequest{Identity: identity, Files: m.Files, MaxDBBytes: cfg.MaxDBBytes})
	if err != nil {
		return nil, err
	}
	defer clear(req)
	stagingAbs := filepath.Join(d.cfg.Host.TenantsDir, staging)
	spec, err := d.helperSpec(r.Ref, st.runUID, "restore", RestoreUnpackCommand, []Bind{
		{Source: filepath.Join(n.BackupDir, backupfmt.ArchiveName(r.Sequence)), Target: helperArchiveIn, ReadOnly: true},
		{Source: stagingAbs, Target: helperStagingDir},
	}, req, cfg.Timeout)
	if err != nil {
		return nil, err
	}
	res, err := d.runHelper(ctx, spec, r.Ref, "restore")
	if err != nil {
		return nil, err
	}
	if res.NoiseFingerprint != recorded {
		return nil, integrity("artifact", "the restored Noise key is not the instance's (start guard, §11.4)")
	}
	stagedData := filepath.Join(staging, stagingData)
	if err := d.checkStagedData(t, stagedData, int(st.runUID)); err != nil {
		return nil, err
	}
	// §17.2 step 4: the policy is set on the restored database before it ever serves (offline, no network)
	if !r.KeepBackupPolicy {
		if err := d.setPolicyOffline(ctx, n, r.Ref, st.runUID, filepath.Join(stagingAbs, stagingData), cfg); err != nil {
			return nil, err
		}
	}
	// §17.2 step 3: no edge, stopped, swap — from here on a failure is not "unchanged"
	*changed = true
	if err := d.detachForRestore(ctx, t, l, n, r.Ref, st.meta); err != nil {
		return nil, err
	}
	kept := prevDataPrefix + time.Now().UTC().Format(prevDataLayout)
	keptRel := filepath.Join(l.dir, kept)
	if fi, err := t.lstat(keptRel); err != nil {
		return nil, err
	} else if fi != nil {
		return nil, state("instance", "%s exists already — retry in a second", kept)
	}
	if err := t.root.Rename(l.data, keptRel); err != nil {
		return nil, fmt.Errorf("keep the previous data/: %w", err)
	}
	if err := t.root.Rename(stagedData, l.data); err != nil {
		// put the previous data/ back: the instance stays as it was (stopped, no edge)
		if rerr := t.root.Rename(keptRel, l.data); rerr != nil {
			d.cfg.Log.Error("restore_swap_failed", "severity", "critical", "instance_id", l.id, "error", rerr)
		}
		return nil, fmt.Errorf("swap the restored data/ in: %w", err)
	}
	if err := t.syncDir(l.dir); err != nil {
		return nil, err
	}
	if _, err := t.fix(l.data, mustLstat(t, l.data), t.owners(int(st.runUID))["data"]); err != nil {
		return nil, err
	}
	d.fps.forget(r.Ref.InstanceID)
	st.meta[metaRestore] = map[string]any{"job_id": r.JobID.String(), "sequence": strconv.FormatUint(r.Sequence, 10),
		"kept_as": kept, "at": time.Now().UTC().Format(time.RFC3339), "files_sha256": filesSum}
	if err := writeMetaMap(t, l, st.meta); err != nil {
		return nil, err
	}
	d.cfg.Log.Info("restore_swapped", "instance_id", l.id, "sequence", r.Sequence, "kept_as", kept, "files_sha256", filesSum,
		"manifest_created_at", m.CreatedAt, "headscale_version", m.HeadscaleVersion)
	d.prunePrevious(t, l, cfg.KeepPrevious)
	return d.finishRestore(ctx, t, l, n, r, filesSum, kept, false)
}

func mustLstat(t *tree, rel string) fs.FileInfo {
	fi, _ := t.lstat(rel)
	return fi
}

// checkArchive is every check of §17.2 step 2 that precedes decryption (T-15): the manifest file's digest is the one
// the worker recorded; its signature verifies with a trusted key; it describes exactly this tenant, instance, slug and
// sequence; the archive's digest and size are the signed ones (and the ones the worker recorded); its Noise key is the
// instance's; its Headscale version is restorable on the running image.
func (d *Driver) checkArchive(ctx context.Context, bt *tree, dir string, r agentspec.Restore, cfg *BackupConfig, st instanceState, recorded string) (*backupfmt.Manifest, error) {
	m, err := d.checkArtifact(bt, dir, r.Ref, r.Sequence, r.ManifestSHA256, r.ArchiveSHA256, cfg, recorded)
	if err != nil {
		return nil, err
	}
	image, _ := st.meta["image"].(string)
	if err := backupfmt.Restorable(m.HeadscaleVersion, m.Image, d.headscaleVersion(ctx, r.Ref, image), image); err != nil {
		return nil, &agentspec.Refusal{Reason: agentv1.RefusalReason_REFUSAL_REASON_STATE, Field: "artifact", Msg: err.Error()}
	}
	return m, nil
}

// checkArtifact is the part of §17.2 step 2 shared by Restore and PreflightUpgrade (P3-T13a), before anything is
// decrypted: the manifest file's digest is the one the worker recorded; its signature verifies with a trusted key; it
// describes exactly this tenant, instance, slug and sequence; the archive's digest and size are the signed ones (and
// the ones the worker recorded); its Noise key is the instance's.
func (d *Driver) checkArtifact(bt *tree, dir string, ref agentspec.Ref, seq uint64, manifestSHA, archiveSHA string, cfg *BackupConfig,
	recorded string) (*backupfmt.Manifest, error) {
	raw, err := bt.readFile(filepath.Join(dir, backupfmt.ManifestName(seq)), backupfmt.MaxManifestBytes)
	if err != nil {
		return nil, err
	}
	if raw == nil {
		return nil, &agentspec.Refusal{Reason: agentv1.RefusalReason_REFUSAL_REASON_NOT_FOUND, Field: "artifact.sequence",
			Msg: "no backup with this sequence for this instance"}
	}
	if s := sha256.Sum256(raw); hex.EncodeToString(s[:]) != manifestSHA {
		return nil, integrity("artifact.manifest_sha256", "the manifest is not the one recorded for this backup")
	}
	m, _, err := d.verifiedManifest(bt, dir, seq, raw, cfg)
	if err != nil {
		return nil, err
	}
	if err := m.Check(backupfmt.Identity{TenantID: ref.TenantID, InstanceID: ref.InstanceID, Slug: ref.Slug, Sequence: seq}); err != nil {
		return nil, &agentspec.Refusal{Reason: agentv1.RefusalReason_REFUSAL_REASON_IDENTITY_MISMATCH, Field: "artifact", Msg: err.Error()}
	}
	if m.Archive.SHA256 != archiveSHA {
		return nil, integrity("artifact.archive_sha256", "the archive is not the one recorded for this backup")
	}
	if m.NoiseFingerprint != recorded {
		return nil, integrity("artifact", "the archive holds another Noise key than the instance's (start guard, §11.4)")
	}
	return m, nil
}

// checkStagedData: the restored data/ holds exactly the three files, regular, of run_uid (the helper wrote them).
func (d *Driver) checkStagedData(t *tree, rel string, runUID int) error {
	fi, err := t.lstat(rel)
	if err != nil {
		return err
	}
	if fi == nil || !fi.IsDir() {
		return integrity("artifact", "the helper produced no data directory")
	}
	ents, err := fs.ReadDir(t.root.FS(), rel)
	if err != nil {
		return err
	}
	names := make([]string, 0, len(ents))
	for _, e := range ents {
		fi, err := t.lstat(filepath.Join(rel, e.Name()))
		if err != nil {
			return err
		}
		if uid, _, ok := fileOwner(fi); !fi.Mode().IsRegular() || (ok && uid != runUID) {
			return unsafePath(filepath.Join(rel, e.Name()), "not a regular file of the instance")
		}
		names = append(names, e.Name())
	}
	slices.Sort(names)
	if !slices.Equal(names, []string{"db.sqlite", "derp_server_private.key", "noise_private.key"}) {
		return integrity("artifact", "the restored data directory does not hold exactly the three files of the archive")
	}
	return nil
}

// setPolicyOffline — §17.2 step 4: `headscale policy set --bypass-grpc-and-access-database-directly --force` (RT-15:
// --force, or the CLI asks interactively) in a one-shot container of the instance's image — run_uid, no network,
// read-only rootfs — on the restored data directory, with config/ (and the policy file the agent wrote there) read-only.
func (d *Driver) setPolicyOffline(ctx context.Context, n agentspec.Names, ref agentspec.Ref, runUID uint32, data string, cfg *BackupConfig) error {
	t, err := d.open()
	if err != nil {
		return err
	}
	defer func() { _ = t.Close() }()
	m, err := readMetaMap(t, newLayout(ref.InstanceID.String()))
	if err != nil {
		return err
	}
	image, _ := m["image"].(string)
	if image == "" {
		return state("instance", "no image recorded in meta/instance.json")
	}
	name, err := helperName(ref.Slug, "policyset")
	if err != nil {
		return err
	}
	uid := strconv.FormatUint(uint64(runUID), 10)
	spec := OneShot{
		Name: name, Image: image, User: uid + ":" + uid, Labels: helperLabels(ref, "policyset"),
		Cmd: []string{"policy", "set", "--bypass-grpc-and-access-database-directly", "--force", "--file", restorePolicyInContainer},
		Binds: []Bind{{Source: n.ConfigDir, Target: "/etc/headscale", ReadOnly: true}, {Source: n.RecordsDir, Target: "/etc/headscale-records", ReadOnly: true},
			{Source: data, Target: "/var/lib/headscale"}},
		Tmpfs:       map[string]string{"/var/run/headscale": "uid=" + uid + ",gid=" + uid + ",mode=0700,size=1m"},
		Env:         []string{"HEADSCALE_LOG_LEVEL=error"},
		MemoryBytes: helperMemory, NanoCPUs: 1_000_000_000, PIDs: 64, Timeout: min(cfg.Timeout, 2*time.Minute), MaxOutput: 16 << 10,
	}
	if err := d.cfg.Engine.EnsureImage(ctx, image); err != nil {
		return err
	}
	res, err := d.cfg.Engine.RunOnce(ctx, spec)
	if err != nil {
		return fmt.Errorf("offline policy set: %w", err)
	}
	if res.ExitCode != 0 {
		return state("applied_policy_hujson", "the policy cannot be set on the restored database (exit code %d): %s", res.ExitCode,
			strings.TrimSpace(detail(res.Stderr, configFindings(res.Stdout), res.Truncated)))
	}
	return nil
}

// detachForRestore clears the edge_attach flag, detaches the edge and stops the container (§17.2 step 3).
func (d *Driver) detachForRestore(ctx context.Context, t *tree, l layout, n agentspec.Names, ref agentspec.Ref, meta map[string]any) error {
	if flag, _ := meta[metaEdgeAttach].(bool); flag {
		delete(meta, metaEdgeAttach)
		if err := writeMetaMap(t, l, meta); err != nil {
			return err
		}
	}
	if attached, err := d.edgeAttached(ctx, n); err != nil {
		return err
	} else if attached {
		if err := d.cfg.Engine.DisconnectNetwork(ctx, n.Network, d.cfg.Edge); err != nil {
			return err
		}
	}
	c, err := d.cfg.Engine.Container(ctx, n.Container)
	if err != nil {
		return err
	}
	if c == nil {
		return state("instance", "container %s does not exist (EnsureInstance with TARGET_PHASE_CONTAINER)", n.Container)
	}
	if err := ownContainer(c, n, ref); err != nil {
		return err
	}
	sctx, cancel := context.WithTimeout(ctx, stopTimeout)
	defer cancel()
	if err := d.cfg.Compose.Compose(sctx, project(n), "stop"); err != nil {
		return err
	}
	d.cfg.Log.Info("restore_instance_stopped", "instance_id", l.id, "edge_detached", true)
	return nil
}

// finishRestore starts the restored instance (start guard first — still without the edge), waits for it to be healthy,
// sets the applied policy over the CLI (exact bytes) or reads the archive's policy, and removes the policy file.
func (d *Driver) finishRestore(ctx context.Context, t *tree, l layout, n agentspec.Names, r agentspec.Restore, filesSum, kept string, again bool) (*agentv1.RestoreResponse, error) {
	if _, err := d.lifecycle(ctx, r.Call, stopTimeout, "start"); err != nil {
		return nil, err
	}
	if err := d.waitHealthy(ctx, n, r.Ref); err != nil {
		return nil, err
	}
	out := &agentv1.RestoreResponse{RestoredDataSha256: filesSum, PreviousDataKeptAs: kept, AlreadyRestored: again}
	get := func() ([]byte, error) {
		res, err := d.cfg.Engine.Exec(ctx, n.Container, []string{headscaleBin, "policy", "get", "-o", "json"}, execTimeout)
		if err != nil {
			return nil, err
		}
		if res.ExitCode != 0 {
			return nil, cliError("policy get", res)
		}
		return readBack(res.Stdout), nil
	}
	if r.KeepBackupPolicy {
		pol, err := get()
		if err != nil {
			return nil, err
		}
		if len(pol) == 0 || len(pol) > agentspec.MaxPolicyBytes {
			return nil, state("instance", "the restored instance serves no policy, or one larger than %d bytes", agentspec.MaxPolicyBytes)
		}
		out.BackupPolicyHujson, out.PolicySha256 = pol, sha256Hex(pol)
		return out, nil
	}
	want := sha256Hex(r.Policy)
	if pol, err := get(); err != nil {
		return nil, err
	} else if sha256Hex(pol) != want {
		res, err := d.cfg.Engine.Exec(ctx, n.Container, []string{headscaleBin, "policy", "set", "--file", restorePolicyInContainer}, execTimeout)
		if err != nil {
			return nil, err
		}
		if res.ExitCode != 0 {
			return nil, cliError("policy set", res)
		}
		if pol, err = get(); err != nil {
			return nil, err
		} else if got := sha256Hex(pol); got != want {
			return nil, state("instance", "the policy read back (sha256 %s) is not the applied policy (sha256 %s)", got, want)
		}
	}
	if err := t.removeFile(filepath.Join(l.config, restorePolicyFile)); err != nil {
		return nil, err
	}
	out.PolicySha256 = want
	d.cfg.Log.Info("restore_started", "instance_id", l.id, "sequence", r.Sequence, "policy_sha256", want, "already_restored", again)
	return out, nil
}

// waitHealthy waits for the container to run and be healthy (§11.3 step 11 — 90 s).
func (d *Driver) waitHealthy(ctx context.Context, n agentspec.Names, ref agentspec.Ref) error {
	deadline := time.Now().Add(healthWait)
	for {
		c, err := d.cfg.Engine.Container(ctx, n.Container)
		if err != nil {
			return err
		}
		if c != nil {
			if err := ownContainer(c, n, ref); err != nil {
				return err
			}
			if c.State == "running" && (c.Health == "healthy" || c.Health == "") {
				return nil
			}
		}
		if time.Now().After(deadline) {
			return state("instance", "the restored instance is not healthy within %s", healthWait)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

// prunePrevious removes the data.prev-* directories older than keep (the one of this restore is recent).
func (d *Driver) prunePrevious(t *tree, l layout, keep time.Duration) {
	if keep <= 0 {
		return
	}
	ents, err := fs.ReadDir(t.root.FS(), l.dir)
	if err != nil {
		return
	}
	for _, e := range ents {
		stamp, ok := strings.CutPrefix(e.Name(), prevDataPrefix)
		if !ok {
			continue
		}
		at, err := time.Parse(prevDataLayout, stamp)
		if err != nil || time.Since(at) < keep {
			continue
		}
		if err := t.removeAll(filepath.Join(l.dir, e.Name())); err != nil {
			d.cfg.Log.Error("restore_prune_failed", "instance_id", l.id, "error", err)
			continue
		}
		d.cfg.Log.Info("restore_previous_data_removed", "instance_id", l.id, "kept_as", e.Name())
	}
}
