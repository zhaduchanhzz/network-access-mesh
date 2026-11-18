//go:build linux

package compose

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/backupfmt"
)

// helperEnv holds the paths a helper works with: fixed in the container (defaultHelperEnv), temporary directories in
// unit tests.
type helperEnv struct {
	dataDir, configFile, recordsFile, staging, archiveIn string
	sqliteBin, ageBin                                    string
	now                                                  func() time.Time
}

func defaultHelperEnv() helperEnv {
	return helperEnv{dataDir: helperDataDir, configFile: helperConfigFile, recordsFile: helperRecordsFile,
		staging: helperStagingDir, archiveIn: helperArchiveIn, sqliteBin: SQLiteBinary, ageBin: AgeBinary, now: time.Now}
}

// ---------------------------------------------------------------------------------------------------- inventory

// fileKind names what a non-regular entry is (never followed, never opened for reading).
func fileKind(m fs.FileMode) string {
	switch {
	case m&fs.ModeSymlink != 0:
		return "symlink"
	case m&fs.ModeNamedPipe != 0:
		return "fifo"
	case m&fs.ModeDevice != 0, m&fs.ModeCharDevice != 0:
		return "device"
	case m&fs.ModeSocket != 0:
		return "socket"
	case m.IsDir():
		return "directory"
	case !m.IsRegular():
		return "special file"
	}
	return ""
}

func nlinkOf(fi fs.FileInfo) uint64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Nlink)
	}
	return 0
}

// inventory checks every entry of data/ BEFORE anything is read (§17.1, IT-15): only the names of dataEntries, only
// regular files with one link, each within its bound and all within the total. A symlink (to a file of another
// instance or anywhere), a FIFO, a device, a socket, a directory, a hard link, an oversized (sparse) file or an
// unexpected name fails the backup closed.
func (e helperEnv) inventory(maxDB int64) (map[string]fs.FileInfo, *helperOutcome) {
	ents, err := os.ReadDir(e.dataDir)
	if err != nil {
		o := errorOutcome("cannot list data/")
		return nil, &o
	}
	out := map[string]fs.FileInfo{}
	var total int64
	for _, ent := range ents {
		name := ent.Name()
		limit, known := dataEntries[name]
		if !known {
			o := unsafeOutcome("unexpected entry in data/", reportedName(name))
			return nil, &o
		}
		if limit == 0 {
			limit = maxDB
		}
		fi, err := os.Lstat(filepath.Join(e.dataDir, name))
		if err != nil {
			o := errorOutcome("cannot stat an entry of data/")
			return nil, &o
		}
		if k := fileKind(fi.Mode()); k != "" {
			o := unsafeOutcome(k+" in data/ (never followed or read)", name)
			return nil, &o
		}
		if nlinkOf(fi) != 1 {
			o := unsafeOutcome("hard link in data/", name)
			return nil, &o
		}
		if fi.Size() > limit {
			o := unsafeOutcome(fmt.Sprintf("file larger than its bound (%d bytes)", limit), name)
			return nil, &o
		}
		total += fi.Size()
		out[name] = fi
	}
	if total > 2*maxDB+maxShmBytes+2*maxKeyFileBytes {
		o := unsafeOutcome("data/ larger than its bound", "")
		return nil, &o
	}
	for _, need := range []string{"db.sqlite", "noise_private.key", "derp_server_private.key"} {
		if out[need] == nil {
			o := integrityOutcome("required file missing from data/", need)
			return nil, &o
		}
	}
	return out, nil
}

// readRegular reads a regular file with O_NOFOLLOW and O_NONBLOCK (a symlink or a FIFO swapped in after the inventory
// is refused, never followed or waited on), checking type, links and bound on the open descriptor.
func readRegular(path string, limit int64) ([]byte, *helperOutcome) {
	f, err := openRegular(path, limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	b, rerr := io.ReadAll(io.LimitReader(f, limit+1))
	if rerr != nil || int64(len(b)) > limit {
		o := unsafeOutcome("file changed while being read", filepath.Base(path))
		return nil, &o
	}
	return b, nil
}

func openRegular(path string, limit int64) (*os.File, *helperOutcome) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0) //nolint:gosec // G304: fixed paths inside the helper container
	if errors.Is(err, syscall.ELOOP) {
		o := unsafeOutcome("symlink (never followed)", filepath.Base(path))
		return nil, &o
	}
	if err != nil {
		o := errorOutcome("cannot open " + filepath.Base(path))
		return nil, &o
	}
	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		o := errorOutcome("cannot stat " + filepath.Base(path))
		return nil, &o
	}
	if k := fileKind(fi.Mode()); k != "" {
		_ = f.Close()
		o := unsafeOutcome(k+" (never read)", filepath.Base(path))
		return nil, &o
	}
	if nlinkOf(fi) > 1 {
		_ = f.Close()
		o := unsafeOutcome("hard link", filepath.Base(path))
		return nil, &o
	}
	if fi.Size() > limit {
		_ = f.Close()
		o := unsafeOutcome("file larger than its bound", filepath.Base(path))
		return nil, &o
	}
	// back to blocking reads for a regular file
	if err := syscall.SetNonblock(int(f.Fd()), false); err != nil { //nolint:gosec // G115: a descriptor
		_ = f.Close()
		o := errorOutcome("cannot read " + filepath.Base(path))
		return nil, &o
	}
	return f, nil
}

// copyRegular copies a regular file (readRegular rules) to dst (O_EXCL, 0600) and syncs it.
func copyRegular(src, dst string, limit int64) *helperOutcome {
	f, o := openRegular(src, limit)
	if o != nil {
		return o
	}
	defer func() { _ = f.Close() }()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600) //nolint:gosec // G304: staging paths
	if err != nil {
		e := errorOutcome("cannot create a staging file")
		return &e
	}
	n, err := io.Copy(out, io.LimitReader(f, limit+1))
	if err == nil && n > limit {
		err = errors.New("grew")
	}
	if err == nil {
		err = out.Sync()
	}
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		e := unsafeOutcome("file changed while being copied", filepath.Base(src))
		return &e
	}
	return nil
}

func syncPath(p string) error {
	f, err := os.Open(p) //nolint:gosec // G304: staging paths
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	return f.Sync()
}

// ---------------------------------------------------------------------------------------------------- sqlite3

// sqlite runs the sqlite3 shell (static, ≥ 3.51.3 — §17.1) on db with the defensive settings of §17.1 (trusted_schema
// off, cell_size_check on, no mmap, a 10 s busy timeout) and returns the output lines tagged by the queries.
func (e helperEnv) sqlite(db string, readonly bool, sql ...string) ([]string, error) {
	args := []string{"-batch", "-bail", "-init", "/dev/null", "-noheader", "-list"}
	if readonly {
		args = append(args, "-readonly")
	}
	args = append(args, db, ".timeout 10000", "PRAGMA trusted_schema=OFF;", "PRAGMA cell_size_check=ON;", "PRAGMA mmap_size=0;")
	args = append(args, sql...)
	cmd := exec.CommandContext(context.Background(), e.sqliteBin, args...) //nolint:gosec // G204: fixed binary, fixed SQL, fixed paths
	cmd.Env = []string{"HOME=/nonexistent"}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(errb.String())
		if len(msg) > 256 {
			msg = msg[:256]
		}
		return nil, fmt.Errorf("sqlite3: %w: %s", err, msg)
	}
	return strings.Split(strings.TrimSpace(out.String()), "\n"), nil
}

// tagged returns the values of the lines starting with tag.
func tagged(lines []string, tag string) []string {
	var out []string
	for _, l := range lines {
		if v, ok := strings.CutPrefix(l, tag); ok {
			out = append(out, v)
		}
	}
	return out
}

const (
	sqlQuickCheck     = "SELECT 'qc:' || quick_check FROM pragma_quick_check;"
	sqlIntegrityCheck = "SELECT 'ic:' || integrity_check FROM pragma_integrity_check;"
	sqlForeignKeys    = `SELECT 'fk:' || "table" FROM pragma_foreign_key_check;`
)

// checkDatabase runs integrity_check and foreign_key_check on a copy (§17.1: after the fsync, before encryption).
func (e helperEnv) checkDatabase(db string) *helperOutcome {
	lines, err := e.sqlite(db, false, sqlIntegrityCheck, sqlForeignKeys)
	if err != nil {
		o := integrityOutcome("the database copy cannot be checked", backupfmt.PathDB)
		return &o
	}
	if ic := tagged(lines, "ic:"); len(ic) != 1 || ic[0] != "ok" {
		o := integrityOutcome("integrity_check failed on the database copy", backupfmt.PathDB)
		return &o
	}
	if fk := tagged(lines, "fk:"); len(fk) != 0 {
		o := integrityOutcome("foreign_key_check failed on the database copy", backupfmt.PathDB)
		return &o
	}
	return nil
}

func (e helperEnv) sqliteVersion() string {
	out, err := exec.CommandContext(context.Background(), e.sqliteBin, "-version").Output() //nolint:gosec // G204: fixed binary
	if err != nil {
		return ""
	}
	f := strings.Fields(string(out))
	if len(f) == 0 {
		return ""
	}
	return f[0]
}

// ---------------------------------------------------------------------------------------------------- backup-snapshot

// backupSnapshot — §17.1: inventory of data/; the database by VACUUM INTO from a read-only connection (instance
// running — never a copy of a file being written) or by a cold copy (instance stopped, under the agent's instance
// lock), quick_check before, integrity_check + foreign_key_check after; the keys and the configuration read with
// O_NOFOLLOW; a tar of the five files streamed straight into age (two X25519 recipients) — no plaintext archive is ever
// written; the database copy is removed.
func (e helperEnv) backupSnapshot(req BackupHelperRequest) (out helperOutcome) {
	if req.MaxDBBytes <= 0 || req.MaxDBBytes > 64<<30 || len(req.Recipients) != 2 ||
		(req.Method != backupfmt.MethodVacuumInto && req.Method != backupfmt.MethodColdCopy) {
		return errorOutcome("invalid request")
	}
	for _, r := range req.Recipients {
		if _, err := backupfmt.ParseRecipient(r); err != nil {
			return errorOutcome("invalid recipient")
		}
	}
	inv, o := e.inventory(req.MaxDBBytes)
	if o != nil {
		return *o
	}
	plain := filepath.Join(e.staging, "plain")
	cold := filepath.Join(e.staging, "cold")
	defer func() { _ = os.RemoveAll(plain); _ = os.RemoveAll(cold) }()
	if err := os.Mkdir(plain, 0o700); err != nil {
		return errorOutcome("cannot create the staging directory")
	}
	dbCopy := filepath.Join(plain, "db.sqlite")
	src := filepath.Join(e.dataDir, "db.sqlite")
	switch req.Method {
	case backupfmt.MethodVacuumInto:
		// a read-only connection on the read-only mount (the instance runs: -wal and -shm exist — V-12); nofollow=1
		// refuses a symlink swapped in after the inventory
		uri := "file:" + src + "?mode=ro&nofollow=1"
		lines, err := e.sqlite(uri, true, sqlQuickCheck)
		if err != nil {
			return integrityOutcome("the live database cannot be read (VACUUM INTO refused — fail closed, never a copy of a file being written)", backupfmt.PathDB)
		}
		if qc := tagged(lines, "qc:"); len(qc) != 1 || qc[0] != "ok" {
			return integrityOutcome("quick_check failed on the live database", backupfmt.PathDB)
		}
		if _, err := e.sqlite(uri, true, "VACUUM INTO '"+dbCopy+"';"); err != nil {
			return integrityOutcome("VACUUM INTO failed", backupfmt.PathDB)
		}
	case backupfmt.MethodColdCopy:
		// the instance is stopped: copy the database with its WAL (the -shm index is rebuilt), then compact the copy
		if err := os.Mkdir(cold, 0o700); err != nil {
			return errorOutcome("cannot create the staging directory")
		}
		for _, name := range []string{"db.sqlite", "db.sqlite-wal"} {
			if inv[name] == nil {
				continue
			}
			if o := copyRegular(filepath.Join(e.dataDir, name), filepath.Join(cold, name), req.MaxDBBytes); o != nil {
				return *o
			}
		}
		lines, err := e.sqlite(filepath.Join(cold, "db.sqlite"), false, sqlQuickCheck)
		if err != nil {
			return integrityOutcome("the database cannot be read", backupfmt.PathDB)
		}
		if qc := tagged(lines, "qc:"); len(qc) != 1 || qc[0] != "ok" {
			return integrityOutcome("quick_check failed on the database", backupfmt.PathDB)
		}
		if _, err := e.sqlite(filepath.Join(cold, "db.sqlite"), false, "VACUUM INTO '"+dbCopy+"';"); err != nil {
			return integrityOutcome("VACUUM INTO failed", backupfmt.PathDB)
		}
	}
	if err := syncPath(dbCopy); err != nil {
		return errorOutcome("cannot sync the database copy")
	}
	if err := syncPath(plain); err != nil {
		return errorOutcome("cannot sync the staging directory")
	}
	if fi, err := os.Lstat(dbCopy); err != nil || !fi.Mode().IsRegular() || fi.Size() > req.MaxDBBytes {
		return integrityOutcome("the database copy is not a regular file within its bound", backupfmt.PathDB)
	}
	if o := e.checkDatabase(dbCopy); o != nil {
		return *o
	}
	noise, o := readRegular(filepath.Join(e.dataDir, "noise_private.key"), noiseKeyMaxBytes)
	if o != nil {
		return *o
	}
	defer clear(noise)
	fp, err := NoiseFingerprint(noise)
	if err != nil {
		return integrityOutcome("noise_private.key does not hold a Noise private key", backupfmt.PathNoiseKey)
	}
	derp, o := readRegular(filepath.Join(e.dataDir, "derp_server_private.key"), maxKeyFileBytes)
	if o != nil {
		return *o
	}
	defer clear(derp)
	cfg, o := readRegular(e.configFile, maxConfigBytes)
	if o != nil {
		return *o
	}
	recs, o := readRegular(e.recordsFile, maxConfigBytes)
	if o != nil {
		return *o
	}
	db, o := openRegular(dbCopy, req.MaxDBBytes)
	if o != nil {
		return *o
	}
	defer func() { _ = db.Close() }()
	dbInfo, err := db.Stat()
	if err != nil {
		return errorOutcome("cannot stat the database copy")
	}
	files, o := e.encrypt(req.Recipients, []tarSource{
		{backupfmt.PathDB, db, dbInfo.Size()},
		{backupfmt.PathNoiseKey, bytes.NewReader(noise), int64(len(noise))},
		{backupfmt.PathDERPKey, bytes.NewReader(derp), int64(len(derp))},
		{backupfmt.PathConfig, bytes.NewReader(cfg), int64(len(cfg))},
		{backupfmt.PathRecords, bytes.NewReader(recs), int64(len(recs))},
	})
	if o != nil {
		return *o
	}
	arch, err := os.Lstat(filepath.Join(e.staging, stagingArchive))
	if err != nil || !arch.Mode().IsRegular() {
		return errorOutcome("the archive was not written")
	}
	return helperOutcome{res: HelperResult{Files: files, NoiseFingerprint: fp, SQLiteVersion: e.sqliteVersion(), ArchiveSize: arch.Size()}}
}

type tarSource struct {
	path string
	r    io.Reader
	size int64
}

// encrypt streams a tar of srcs into `age -e -r <data key> -r <recovery> -o /staging/archive.tar.age`.
func (e helperEnv) encrypt(recipients []string, srcs []tarSource) ([]backupfmt.File, *helperOutcome) {
	out := filepath.Join(e.staging, stagingArchive)
	cmd := exec.CommandContext(context.Background(), e.ageBin, "-e", "-r", recipients[0], "-r", recipients[1], "-o", out) //nolint:gosec // G204: fixed binary, validated recipients
	cmd.Env = []string{}
	var errb bytes.Buffer
	cmd.Stderr = &errb
	stdin, err := cmd.StdinPipe()
	if err != nil {
		o := errorOutcome("age: " + err.Error())
		return nil, &o
	}
	if err := cmd.Start(); err != nil {
		o := errorOutcome("age cannot start")
		return nil, &o
	}
	files, werr := writeTar(stdin, srcs, e.now().UTC())
	cerr := stdin.Close()
	if err := cmd.Wait(); err != nil || werr != nil || cerr != nil {
		_ = os.Remove(out)
		o := errorOutcome("encryption failed")
		return nil, &o
	}
	return files, nil
}

func writeTar(w io.Writer, srcs []tarSource, mtime time.Time) ([]backupfmt.File, error) {
	tw := tar.NewWriter(w)
	files := make([]backupfmt.File, 0, len(srcs))
	for _, s := range srcs {
		hdr := &tar.Header{Typeflag: tar.TypeReg, Name: s.path, Mode: 0o600, Size: s.size, ModTime: mtime.Truncate(time.Second), Format: tar.FormatPAX}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, err
		}
		h := sha256.New()
		n, err := io.Copy(tw, io.TeeReader(io.LimitReader(s.r, s.size), h))
		if err != nil {
			return nil, err
		}
		if n != s.size {
			return nil, fmt.Errorf("%s: %d of %d bytes", s.path, n, s.size)
		}
		files = append(files, backupfmt.File{Path: s.path, Size: s.size, SHA256: hex.EncodeToString(h.Sum(nil))})
	}
	return files, tw.Close()
}

// ---------------------------------------------------------------------------------------------------- restore-unpack

// restoreUnpack — §17.2 step 2: decrypt (the identity reaches age through a pipe, never a file) and unpack into
// /staging/data/, accepting only regular entries named in the (already verified) manifest, of exactly the manifest's
// size and sha256 — age authenticates the ciphertext as it streams and must end with success; then integrity_check +
// foreign_key_check on the restored database and the fingerprint of the restored Noise key.
func (e helperEnv) restoreUnpack(req RestoreHelperRequest) helperOutcome {
	if !strings.HasPrefix(req.Identity, "AGE-SECRET-KEY-1") || req.MaxDBBytes <= 0 || len(req.Files) != len(backupfmt.ArchivePaths) {
		return errorOutcome("invalid request")
	}
	want := map[string]backupfmt.File{}
	for i, f := range req.Files {
		if f.Path != backupfmt.ArchivePaths[i] {
			return errorOutcome("invalid request")
		}
		want[f.Path] = f
	}
	dst := filepath.Join(e.staging, stagingData)
	if err := os.Mkdir(dst, 0o700); err != nil {
		return errorOutcome("cannot create the staging data directory")
	}
	ok := false
	defer func() {
		if !ok {
			_ = os.RemoveAll(dst)
		}
	}()
	idR, idW, err := os.Pipe()
	if err != nil {
		return errorOutcome("pipe")
	}
	cmd := exec.CommandContext(context.Background(), e.ageBin, "-d", "-i", "/dev/fd/3", e.archiveIn) //nolint:gosec // G204: fixed binary and paths
	cmd.Env = []string{}
	cmd.ExtraFiles = []*os.File{idR}
	var errb bytes.Buffer
	cmd.Stderr = &errb
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = idR.Close()
		_ = idW.Close()
		return errorOutcome("pipe")
	}
	if err := cmd.Start(); err != nil {
		_ = idR.Close()
		_ = idW.Close()
		return errorOutcome("age cannot start")
	}
	_ = idR.Close()
	_, werr := io.WriteString(idW, req.Identity+"\n")
	_ = idW.Close()
	res, o := unpackTar(bufio.NewReader(stdout), want, dst, req.MaxDBBytes)
	_, _ = io.Copy(io.Discard, stdout)
	waitErr := cmd.Wait()
	switch {
	case werr != nil:
		return errorOutcome("cannot hand the identity to age")
	case waitErr != nil:
		// wrong data key ("no identity matched any of the recipients"), truncated or tampered ciphertext
		return integrityOutcome("the archive does not decrypt with this data key, or its ciphertext is not authentic", "")
	case o != nil:
		return *o
	}
	for _, f := range res {
		if err := syncPath(filepath.Join(dst, strings.TrimPrefix(f.Path, "data/"))); err != nil {
			return errorOutcome("cannot sync a restored file")
		}
	}
	if err := syncPath(dst); err != nil {
		return errorOutcome("cannot sync the restored data directory")
	}
	if o := e.checkDatabase(filepath.Join(dst, "db.sqlite")); o != nil {
		return *o
	}
	// the checks of the copy may leave -wal/-shm behind: only the archive's files belong to the restored data/
	for _, name := range []string{"db.sqlite-wal", "db.sqlite-shm", "db.sqlite-journal"} {
		_ = os.Remove(filepath.Join(dst, name))
	}
	noise, o2 := readRegular(filepath.Join(dst, "noise_private.key"), noiseKeyMaxBytes)
	if o2 != nil {
		return *o2
	}
	defer clear(noise)
	fp, err := NoiseFingerprint(noise)
	if err != nil {
		return integrityOutcome("the restored noise_private.key does not hold a Noise private key", backupfmt.PathNoiseKey)
	}
	ok = true
	return helperOutcome{res: HelperResult{Files: res, NoiseFingerprint: fp, SQLiteVersion: e.sqliteVersion()}}
}

// unpackTar reads the decrypted tar: regular entries of want only, once each, of the expected size and digest; data/
// entries are written to dst (O_EXCL, O_NOFOLLOW, 0600), the others only checked. Every entry of want must appear.
func unpackTar(r io.Reader, want map[string]backupfmt.File, dst string, maxDB int64) ([]backupfmt.File, *helperOutcome) {
	tr := tar.NewReader(r)
	seen := map[string]bool{}
	var got []backupfmt.File
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			o := integrityOutcome("the archive is not a valid tar", "")
			return nil, &o
		}
		w, known := want[hdr.Name]
		switch {
		case hdr.Typeflag != tar.TypeReg:
			o := unsafeOutcome("archive entry that is not a regular file", reportedName(filepath.Base(hdr.Name)))
			return nil, &o
		case !known:
			o := unsafeOutcome("archive entry not in the manifest", reportedName(filepath.Base(hdr.Name)))
			return nil, &o
		case seen[hdr.Name]:
			o := unsafeOutcome("duplicate archive entry", hdr.Name)
			return nil, &o
		case hdr.Size != w.Size || hdr.Size < 0 || hdr.Size > maxDB:
			o := integrityOutcome("archive entry size differs from the manifest", hdr.Name)
			return nil, &o
		}
		seen[hdr.Name] = true
		h := sha256.New()
		var sink io.Writer = h
		var f *os.File
		if base, ok := strings.CutPrefix(hdr.Name, "data/"); ok {
			f, err = os.OpenFile(filepath.Join(dst, base), os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600) //nolint:gosec // G304: names of the fixed list
			if err != nil {
				o := errorOutcome("cannot create a restored file")
				return nil, &o
			}
			sink = io.MultiWriter(f, h)
		}
		n, err := io.Copy(sink, io.LimitReader(tr, hdr.Size))
		if f != nil {
			if cerr := f.Close(); err == nil {
				err = cerr
			}
		}
		if err != nil || n != hdr.Size {
			o := integrityOutcome("archive entry truncated", hdr.Name)
			return nil, &o
		}
		if hex.EncodeToString(h.Sum(nil)) != w.SHA256 {
			o := integrityOutcome("archive entry digest differs from the manifest", hdr.Name)
			return nil, &o
		}
		got = append(got, w)
	}
	for p := range want {
		if !seen[p] {
			o := integrityOutcome("archive entry missing", p)
			return nil, &o
		}
	}
	slices.SortFunc(got, func(a, b backupfmt.File) int {
		return slices.Index(backupfmt.ArchivePaths, a.Path) - slices.Index(backupfmt.ArchivePaths, b.Path)
	})
	var data []backupfmt.File
	for _, f := range got {
		if strings.HasPrefix(f.Path, "data/") {
			data = append(data, f)
		}
	}
	return data, nil
}

// ---------------------------------------------------------------------------------------------------- data-check

// sqliteMagic starts every SQLite database file.
var sqliteMagic = []byte("SQLite format 3\x00")

// dataCheck is the structural check the start guard adds before a start (IT-15): db.sqlite is a regular file with one
// link, within its bound, with a valid SQLite header and a size that is a whole number of pages. A garbage, truncated
// or oversized (sparse) database is refused before Headscale ever opens it.
func (e helperEnv) dataCheck(maxDB int64) helperOutcome {
	f, o := openRegular(filepath.Join(e.dataDir, "db.sqlite"), maxDB)
	if o != nil {
		return *o
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return errorOutcome("cannot stat db.sqlite")
	}
	hdr := make([]byte, 100)
	if _, err := io.ReadFull(f, hdr); err != nil || !bytes.Equal(hdr[:16], sqliteMagic) {
		return integrityOutcome("db.sqlite is not an SQLite database", "db.sqlite")
	}
	page := int64(binary.BigEndian.Uint16(hdr[16:18]))
	if page == 1 {
		page = 65536
	}
	if page < 512 || page > 65536 || page&(page-1) != 0 || fi.Size() < page || fi.Size()%page != 0 {
		return integrityOutcome("db.sqlite has an invalid page size or length", "db.sqlite")
	}
	return helperOutcome{}
}
