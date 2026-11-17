package main

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/logx"
)

// The tests replace age, pg_dump and pg_dumpall with small shell scripts (the real tools run in the restore drill,
// tests/backup/drill.sh). The fake age "encrypts" by base64 behind a header naming the recipient, so the tests can
// check both that the plaintext never appears in the destination and that it round-trips. The fake dump tools refuse
// to run unless their standard output is a pipe and the pgpass file is 0600: the plaintext is streamed, never staged.

const plaintextMarker = "PLAINTEXT-ROWS-7f3a"

const fakeAge = `#!/bin/sh
PATH=/usr/bin:/bin
d=$(dirname "$0")
case "$1" in
  --version) echo v1.3.2; exit 0 ;;
  --encrypt) ;;
  *) echo "fake age: unexpected arguments" >&2; exit 2 ;;
esac
[ "$2" = --recipient ] || { echo "fake age: no recipient" >&2; exit 2; }
case "$3" in age1*) ;; *) echo "fake age: malformed recipient" >&2; exit 1 ;; esac
if [ -e "$d/age.fail" ]; then cat >/dev/null; echo "fake age: failing on purpose" >&2; exit 1; fi
printf 'FAKE-AGE %s\n' "$3"
base64 -w0
`

const fakeDump = `#!/bin/sh
PATH=/usr/bin:/bin
d=$(dirname "$0")
me=$(basename "$0")
[ "$1" = --version ] && { echo "$me (PostgreSQL) 18.7"; exit 0; }
[ -p /proc/self/fd/1 ] || { echo "$me: stdout is not a pipe" >&2; exit 3; }
[ "$(stat -c %a "$PGPASSFILE")" = 600 ] || { echo "$me: pgpass is not 0600" >&2; exit 4; }
grep -q ":$PGUSER:" "$PGPASSFILE" || { echo "$me: no pgpass line" >&2; exit 5; }
echo "` + plaintextMarker + ` $me db=$PGDATABASE user=$PGUSER gss=$PGGSSENCMODE args=$*"
if [ -e "$d/$me.fail" ]; then echo "$me: error: connection to server failed" >&2; exit 1; fi
exit 0
`

const testPassword = `s3cr3t:pa\ss-9c1e`

type env struct {
	t                         *testing.T
	bin, dest, runtime, pwDir string
	logs                      *bytes.Buffer
	cfg                       *Config
}

func newEnv(t *testing.T, target string) *env {
	t.Helper()
	e := &env{t: t, bin: t.TempDir(), dest: t.TempDir(), runtime: t.TempDir(), pwDir: t.TempDir(), logs: &bytes.Buffer{}}
	for name, body := range map[string]string{"age": fakeAge, "pg_dump": fakeDump, "pg_dumpall": fakeDump} {
		if err := os.WriteFile(filepath.Join(e.bin, name), []byte(body), 0o700); err != nil { //nolint:gosec // test tool
			t.Fatal(err)
		}
	}
	pwFile := filepath.Join(e.pwDir, "pg_backup_password")
	if err := os.WriteFile(pwFile, []byte(testPassword+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	m := baseEnv(target)
	m["MG_BACKUP_DEST"], m["MG_BACKUP_AGE_BIN"], m["MG_BACKUP_PG_BIN_DIR"] = e.dest, filepath.Join(e.bin, "age"), e.bin
	m["MG_BACKUP_RUNTIME_DIR"], m["MG_BACKUP_PG_PASSWORD_FILE"] = e.runtime, pwFile
	if target == TargetEdge {
		m["MG_BACKUP_SOURCE"] = t.TempDir()
	}
	cfg, err := LoadConfig(getenvOf(m))
	if err != nil {
		t.Fatal(err)
	}
	e.cfg = cfg
	return e
}

func (e *env) backuper(now time.Time) *Backuper {
	tools, err := e.cfg.Preflight(e.t.Context())
	if err != nil {
		e.t.Fatalf("preflight: %v", err)
	}
	log := logx.New(e.logs, slog.LevelDebug, "backup")
	return &Backuper{Cfg: e.cfg, Log: log, Tools: tools, Now: func() time.Time { return now }}
}

func (e *env) fail(tool string) {
	if err := os.WriteFile(filepath.Join(e.bin, tool+".fail"), nil, 0o600); err != nil {
		e.t.Fatal(err)
	}
}

// listing returns the names in the destination (hidden files included).
func listing(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		out = append(out, e.Name())
	}
	sort.Strings(out)
	return out
}

// decrypt undoes the fake age.
func decrypt(t *testing.T, raw []byte) []byte {
	t.Helper()
	header, body, ok := bytes.Cut(raw, []byte("\n"))
	if !ok || !bytes.Equal(header, []byte("FAKE-AGE "+exampleRecipient)) {
		t.Fatalf("not encrypted to the configured recipient: header %q", header)
	}
	out, err := base64.StdEncoding.DecodeString(string(body))
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func noPlaintextIn(t *testing.T, dir string, needles ...string) {
	t.Helper()
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		raw, err := os.ReadFile(p) //nolint:gosec // test directory
		if err != nil {
			t.Fatal(err)
		}
		for _, n := range needles {
			if bytes.Contains(raw, []byte(n)) {
				t.Errorf("%s holds %q in clear", d.Name(), n)
			}
		}
		return nil
	})
}

var t0 = time.Date(2026, 11, 17, 2, 30, 0, 0, time.UTC)

func TestPostgresBackup(t *testing.T) {
	e := newEnv(t, TargetPostgres)
	m, err := e.backuper(t0).Run(t.Context(), LabelScheduled)
	if err != nil {
		t.Fatalf("Run: %v\n%s", err, e.logs)
	}
	id := "postgres-20261117T023000Z-scheduled"
	want := []string{".lock", id + ".globals.sql.age", id + ".manifest.json", id + ".pgdump.age", StatusFile, StatusProm}
	if got := listing(t, e.dest); strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("destination = %v, want %v", got, want)
	}
	if m.ID != id || len(m.Files) != 2 || m.Recipient != exampleRecipient || m.Tools["pg_dump"] != "pg_dump (PostgreSQL) 18.7" {
		t.Errorf("manifest = %+v", m)
	}
	for _, f := range m.Files {
		raw, err := os.ReadFile(filepath.Join(e.dest, f.Name)) //nolint:gosec // test
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(raw)
		if int64(len(raw)) != f.Size || hex.EncodeToString(sum[:]) != f.SHA256 {
			t.Errorf("%s: size/sha256 in the manifest do not match the file", f.Name)
		}
		plain := string(decrypt(t, raw))
		tool := map[bool]string{true: "pg_dumpall", false: "pg_dump"}[strings.HasSuffix(f.Name, PartGlobals)]
		if !strings.HasPrefix(plain, plaintextMarker+" "+tool+" db=meshguard user=mg_backup gss=disable") {
			t.Errorf("%s decrypts to %q", f.Name, plain)
		}
		if fi, _ := os.Stat(filepath.Join(e.dest, f.Name)); fi.Mode().Perm() != 0o640 {
			t.Errorf("%s mode %v, want 0640", f.Name, fi.Mode().Perm())
		}
	}
	noPlaintextIn(t, e.dest, plaintextMarker, "s3cr3t")
	if strings.Contains(e.logs.String(), "s3cr3t") || strings.Contains(e.logs.String(), plaintextMarker) {
		t.Error("the logs hold the password or plaintext")
	}
	if got := listing(t, e.runtime); len(got) != 0 {
		t.Errorf("runtime dir after the run = %v, want empty (pgpass removed)", got)
	}
	_, st, err := ReadStatus(e.dest)
	if err != nil {
		t.Fatal(err)
	}
	if st.LastSuccess == nil || st.LastSuccess.ID != id || !st.LastAttempt.OK || st.ConsecutiveFailures != 0 ||
		st.LastSuccess.TotalBytes != m.TotalBytes() || len(st.LastSuccess.Files) != 2 || st.MaxAgeSeconds != 26*3600 {
		t.Errorf("status = %+v", st)
	}
	prom, _ := os.ReadFile(filepath.Join(e.dest, StatusProm)) //nolint:gosec // test
	for _, line := range []string{`meshguard_backup_last_success_timestamp_seconds{target="postgres"} 1794882600`,
		`meshguard_backup_last_attempt_success{target="postgres"} 1`, `meshguard_backup_consecutive_failures{target="postgres"} 0`} {
		if !strings.Contains(string(prom), line+"\n") {
			t.Errorf("status.prom lacks %q:\n%s", line, prom)
		}
	}
	var onDisk Manifest
	raw, _ := os.ReadFile(filepath.Join(e.dest, id+".manifest.json")) //nolint:gosec // test
	if err := json.Unmarshal(raw, &onDisk); err != nil || onDisk.Format != ManifestFormat || len(onDisk.Files) != 2 {
		t.Errorf("manifest on disk: %v %+v", err, onDisk)
	}
}

// TestFailureKeepsNothing: a dump tool that fails after printing part of its output, or a failing age, leaves no
// artifact and no partial file; the status records the failure and keeps the last success.
func TestFailureKeepsNothing(t *testing.T) {
	for _, tool := range []string{"pg_dump", "pg_dumpall", "age"} {
		t.Run(tool, func(t *testing.T) {
			e := newEnv(t, TargetPostgres)
			b := e.backuper(t0)
			if _, err := b.Run(t.Context(), LabelScheduled); err != nil {
				t.Fatal(err)
			}
			before := listing(t, e.dest)
			e.fail(tool)
			b.Now = func() time.Time { return t0.Add(24 * time.Hour) }
			_, err := b.Run(t.Context(), LabelScheduled)
			if err == nil || errors.Is(err, ErrConfig) {
				t.Fatalf("Run with a failing %s = %v, want a run error", tool, err)
			}
			if after := listing(t, e.dest); strings.Join(after, " ") != strings.Join(before, " ") {
				t.Errorf("destination changed: %v → %v", before, after)
			}
			_, st, err := ReadStatus(e.dest)
			if err != nil {
				t.Fatal(err)
			}
			if st.LastAttempt.OK || st.ConsecutiveFailures != 1 || st.LastSuccess == nil ||
				st.LastSuccess.ID != "postgres-20261117T023000Z-scheduled" || st.LastAttempt.Error == "" {
				t.Errorf("status after failure = %+v", st)
			}
			if strings.Contains(st.LastAttempt.Error, "s3cr3t") {
				t.Error("the error in the status holds the password")
			}
		})
	}
}

// TestBadRecipientWritesNothing: an empty, invalid or mismatching recipient stops the run before the first write
// (not even the lock file or the status) — through Run and through the `once` subcommand.
func TestBadRecipientWritesNothing(t *testing.T) {
	e := newEnv(t, TargetPostgres)
	b := e.backuper(t0)
	for name, r := range map[string]string{"empty": "", "garbage": "age1notarecipient", "private key": "AGE-SECRET-KEY-1ABC"} {
		e.cfg.Recipient = r
		if _, err := b.Run(t.Context(), LabelScheduled); !errors.Is(err, ErrConfig) {
			t.Errorf("%s: Run = %v, want ErrConfig", name, err)
		}
	}
	e.cfg.Recipient = exampleRecipient
	other := filepath.Join(t.TempDir(), "recipient")
	if err := os.WriteFile(other, []byte("# ceremony\n"+encodeRecipient([32]byte{9})+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	e.cfg.RecipientFile = other
	if _, err := b.Run(t.Context(), LabelScheduled); !errors.Is(err, ErrConfig) {
		t.Errorf("recipient file mismatch: Run = %v, want ErrConfig", err)
	}
	if _, err := e.cfg.Preflight(t.Context()); !errors.Is(err, ErrConfig) {
		t.Errorf("recipient file mismatch: Preflight = %v, want ErrConfig", err)
	}
	if got := listing(t, e.dest); len(got) != 0 {
		t.Errorf("destination = %v, want empty", got)
	}

	for name, r := range map[string]string{"empty": "", "invalid": "age1qqqq"} {
		m := baseEnv(TargetPostgres)
		m["MG_BACKUP_RECIPIENT"], m["MG_BACKUP_DEST"] = r, e.dest
		var out, errb bytes.Buffer
		if code := dispatch(t.Context(), []string{"once", "--label", "pre-migration"}, getenvOf(m), &out, &errb); code != 2 {
			t.Errorf("once with an %s recipient: exit %d, want 2", name, code)
		}
		if !strings.Contains(errb.String(), "nothing written") {
			t.Errorf("once with an %s recipient: stderr %q", name, errb.String())
		}
	}
	if got := listing(t, e.dest); len(got) != 0 {
		t.Errorf("destination after once = %v, want empty", got)
	}
}

func TestDispatch(t *testing.T) {
	e := newEnv(t, TargetPostgres)
	m := map[string]string{"MG_BACKUP_TARGET": "postgres", "MG_BACKUP_RECIPIENT": exampleRecipient,
		"MG_BACKUP_DEST": e.dest, "MG_BACKUP_AGE_BIN": e.cfg.AgeBin, "MG_BACKUP_PG_BIN_DIR": e.bin,
		"MG_BACKUP_RUNTIME_DIR": e.runtime, "MG_BACKUP_PG_PASSWORD_FILE": e.cfg.PG.PasswordFile,
		"MG_BACKUP_PG_HOST": "postgres", "MG_BACKUP_PG_DATABASE": "meshguard", "MG_BACKUP_PG_USER": "mg_backup"}
	run := func(args ...string) (int, string) {
		var out, errb bytes.Buffer
		code := dispatch(t.Context(), args, getenvOf(m), &out, &errb)
		return code, out.String() + errb.String()
	}
	if code, out := run("check"); code != 0 || len(listing(t, e.dest)) != 0 {
		t.Errorf("check: exit %d (%s), destination %v", code, out, listing(t, e.dest))
	}
	if code, _ := run("status"); code != 1 {
		t.Errorf("status without a status file: exit %d, want 1", code)
	}
	if code, out := run("once", "--label", "pre-migration"); code != 0 {
		t.Fatalf("once: exit %d: %s", code, out)
	}
	if code, out := run("status"); code != 0 || !strings.Contains(out, `"label": "pre-migration"`) {
		t.Errorf("status after once: exit %d: %s", code, out)
	}
	if code, _ := run("status", "--max-age", "1ns"); code != 1 {
		t.Errorf("status --max-age 1ns: exit %d, want 1", code)
	}
	for _, args := range [][]string{{"bogus"}, {"once", "--label", "nightly"}, {"run", "--label", "manual"},
		{"check", "extra"}, {"once", "--max-age", "1h"}} {
		if code, _ := run(args...); code != 2 {
			t.Errorf("%v: exit %d, want 2", args, code)
		}
	}
	if code, out := run("version"); code != 0 || !strings.HasPrefix(out, "meshguard-backup ") {
		t.Errorf("version: %d %q", code, out)
	}
}

func TestEdgeBackup(t *testing.T) {
	e := newEnv(t, TargetEdge)
	src := e.cfg.Source
	mk := func(rel string, mode os.FileMode, content string) {
		p := filepath.Join(src, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
	}
	mk("caddy/acme/acme-v02/users/default/default.key", 0o600, "-----BEGIN EC "+plaintextMarker)
	mk("caddy/certificates/acme-v02/example/example.crt", 0o644, "CERT")
	mk("caddy/last_clean.json", 0o644, `{"tls":{}}`)
	mk("caddy/locks/empty", 0o600, "")
	if err := os.Chmod(filepath.Join(src, "caddy/acme"), 0o700); err != nil { //nolint:gosec // the edge's directory mode
		t.Fatal(err)
	}
	if err := os.Symlink("certificates/acme-v02/example/example.crt", filepath.Join(src, "caddy/current.crt")); err != nil {
		t.Fatal(err)
	}
	mtime := time.Date(2026, 1, 2, 3, 4, 5, 123456789, time.UTC)
	if err := os.Chtimes(filepath.Join(src, "caddy/last_clean.json"), mtime, mtime); err != nil {
		t.Fatal(err)
	}
	m, err := e.backuper(t0).Run(t.Context(), LabelManual)
	if err != nil {
		t.Fatalf("Run: %v\n%s", err, e.logs)
	}
	if len(m.Files) != 1 || m.Files[0].Name != "edge-20261117T023000Z-manual.tar.age" {
		t.Fatalf("manifest files = %+v", m.Files)
	}
	noPlaintextIn(t, e.dest, plaintextMarker)
	raw, _ := os.ReadFile(filepath.Join(e.dest, m.Files[0].Name)) //nolint:gosec // test
	tr := tar.NewReader(bytes.NewReader(decrypt(t, raw)))
	got := map[string]*tar.Header{}
	contents := map[string]string{}
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		got[h.Name] = h
		b, _ := io.ReadAll(tr)
		contents[h.Name] = string(b)
	}
	uid, gid := os.Getuid(), os.Getgid()
	for name, want := range map[string]struct {
		typ  byte
		mode int64
	}{
		"./":            {tar.TypeDir, -1},
		"./caddy/acme/": {tar.TypeDir, 0o700},
		"./caddy/acme/acme-v02/users/default/default.key":   {tar.TypeReg, 0o600},
		"./caddy/certificates/acme-v02/example/example.crt": {tar.TypeReg, 0o644},
		"./caddy/last_clean.json":                           {tar.TypeReg, 0o644},
		"./caddy/locks/empty":                               {tar.TypeReg, 0o600},
		"./caddy/current.crt":                               {tar.TypeSymlink, -1},
	} {
		h := got[name]
		if h == nil {
			t.Errorf("%s missing from the archive (have %d entries)", name, len(got))
			continue
		}
		if h.Typeflag != want.typ || (want.mode >= 0 && h.Mode != want.mode) || h.Uid != uid || h.Gid != gid {
			t.Errorf("%s: type %c mode %o uid %d gid %d", name, h.Typeflag, h.Mode, h.Uid, h.Gid)
		}
	}
	if contents["./caddy/acme/acme-v02/users/default/default.key"] != "-----BEGIN EC "+plaintextMarker {
		t.Error("key file content differs")
	}
	if h := got["./caddy/last_clean.json"]; h == nil || !h.ModTime.Equal(mtime) {
		t.Errorf("mtime not preserved: %+v", h)
	}
	if h := got["./caddy/current.crt"]; h == nil || h.Linkname != "certificates/acme-v02/example/example.crt" {
		t.Errorf("symlink target: %+v", h)
	}

	// a FIFO (or socket, device) in the volume fails the archive: nothing kept, failure recorded
	if err := syscall.Mkfifo(filepath.Join(src, "caddy/fifo"), 0o600); err != nil {
		t.Fatal(err)
	}
	before := listing(t, e.dest)
	b := e.backuper(t0.Add(time.Hour))
	if _, err := b.Run(t.Context(), LabelManual); err == nil || !strings.Contains(err.Error(), "unsupported file type") {
		t.Errorf("Run with a FIFO = %v, want unsupported file type", err)
	}
	after := listing(t, e.dest)
	if strings.Join(after, " ") != strings.Join(before, " ") {
		t.Errorf("destination changed: %v → %v", before, after)
	}
}

func TestRetention(t *testing.T) {
	e := newEnv(t, TargetPostgres)
	c := e.cfg
	c.KeepDays, c.KeepMin, c.KeepOnDemand = 14, 3, 2
	now := t0
	mkSet := func(label string, age time.Duration, complete bool) string {
		id := "postgres-" + now.Add(-age).Format("20060102T150405Z") + "-" + label
		parts := []string{PartGlobals, PartPGDump}
		if complete {
			parts = append(parts, PartManifest)
		}
		for _, p := range parts {
			if err := os.WriteFile(filepath.Join(c.Dest, id+"."+p), []byte("x"), 0o640); err != nil { //nolint:gosec // mode of real artifacts
				t.Fatal(err)
			}
		}
		return id
	}
	day := 24 * time.Hour
	var scheduled []string
	for i := 0; i < 20; i++ {
		scheduled = append(scheduled, mkSet(LabelScheduled, time.Duration(i)*day, true))
	}
	var pre []string
	for i := 0; i < 4; i++ {
		pre = append(pre, mkSet(LabelPreMigration, time.Duration(i)*40*day, true))
	}
	manual := mkSet(LabelManual, 100*day, true)
	other := filepath.Join(c.Dest, "edge-20200101T000000Z-scheduled.tar.age") // another target: never touched
	unrelated := filepath.Join(c.Dest, "notes.txt")
	for _, p := range []string{other, unrelated} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	removed := applyRetention(c, now)
	exists := func(id string) bool {
		_, err := os.Stat(filepath.Join(c.Dest, id+"."+PartManifest))
		return err == nil
	}
	for i, id := range scheduled {
		if want := i <= 14; exists(id) != want { // 14 days back inclusive (day 14 is exactly at the cutoff)
			t.Errorf("scheduled set %d days old kept=%v, want %v", i, !want, want)
		}
	}
	for i, id := range pre {
		if want := i < 2; exists(id) != want {
			t.Errorf("pre-migration set #%d kept=%v, want %v", i, !want, want)
		}
	}
	if !exists(manual) {
		t.Error("the only manual set was removed")
	}
	for _, p := range []string{other, unrelated} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("%s was removed", filepath.Base(p))
		}
	}
	if len(removed) != (5+2)*3 {
		t.Errorf("removed %d files, want 21: %v", len(removed), removed)
	}

	// KeepMin wins over the age limit: the 3 newest scheduled sets stay even when all are old
	c2 := newEnv(t, TargetPostgres).cfg
	c2.KeepDays, c2.KeepMin = 1, 3
	c.Dest = c2.Dest
	var old []string
	for i := 0; i < 5; i++ {
		old = append(old, mkSet(LabelScheduled, time.Duration(30+i)*day, true))
	}
	applyRetention(c2, now)
	for i, id := range old {
		_, err := os.Stat(filepath.Join(c2.Dest, id+"."+PartManifest))
		if (err == nil) != (i < 3) {
			t.Errorf("old scheduled set #%d: kept=%v", i, err == nil)
		}
	}

	// an interrupted run leaves partial files and a set without manifest: removed before the next run
	incomplete := mkSet(LabelScheduled, 0, false)
	partial := filepath.Join(c.Dest, "."+incomplete+".pgdump.age.partial")
	if err := os.WriteFile(partial, []byte("x"), 0o640); err != nil { //nolint:gosec // mode of real artifacts
		t.Fatal(err)
	}
	removeIncomplete(c.Dest, slog.New(slog.NewTextHandler(io.Discard, nil)))
	for _, p := range []string{partial, filepath.Join(c.Dest, incomplete+"."+PartGlobals)} {
		if _, err := os.Stat(p); err == nil {
			t.Errorf("%s survived", filepath.Base(p))
		}
	}
}

// TestLockSerialisesRuns: a run waits while another holds the destination's lock (a scheduled run and a
// pre-migration `once` in another container) and gives up when its context ends.
func TestLockSerialisesRuns(t *testing.T) {
	e := newEnv(t, TargetPostgres)
	unlock, err := lockDir(t.Context(), e.dest)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 1500*time.Millisecond)
	defer cancel()
	if _, err := e.backuper(t0).Run(ctx, LabelPreMigration); err == nil || !strings.Contains(err.Error(), "still running") {
		t.Errorf("Run while locked = %v, want a lock timeout", err)
	}
	unlock()
	if _, err := e.backuper(t0).Run(t.Context(), LabelPreMigration); err != nil {
		t.Errorf("Run after unlock: %v", err)
	}
}
