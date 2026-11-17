//go:build linux

package compose

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	agentv1 "github.com/zhaduchanhzz/network-access-mesh/api/agent/v1"
)

func newTree(t *testing.T) (*tree, string) {
	t.Helper()
	needRoot(t)
	dir := t.TempDir()
	tr, err := openTree(dir, os.Geteuid(), os.Getegid())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tr.Close() })
	return tr, dir
}

func inode(t *testing.T, p string) (uint64, time.Time) {
	t.Helper()
	fi, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Sys().(*syscall.Stat_t).Ino, fi.ModTime()
}

// TestWriteFileAtomic: tmp (O_EXCL) + fchown/fchmod + fsync + rename + fsync of the directory; nothing rewritten when
// the content is the same (owner and mode corrected in place); no temporary file left behind.
func TestWriteFileAtomic(t *testing.T) {
	tr, dir := newTree(t)
	o := owner{0, 30001, 0o440}
	changed, err := tr.writeFile("f", []byte("one\n"), o)
	if err != nil || !changed {
		t.Fatalf("first write: %v %v", changed, err)
	}
	p := filepath.Join(dir, "f")
	ino, mtime := inode(t, p)
	if uid, gid, mode := ownerMode(t, p); uid != 0 || gid != 30001 || mode != 0o440 {
		t.Fatalf("owner/mode %d:%d %v", uid, gid, mode)
	}
	time.Sleep(10 * time.Millisecond)
	if changed, err := tr.writeFile("f", []byte("one\n"), o); err != nil || changed {
		t.Fatalf("same content rewritten: %v %v", changed, err)
	}
	if i, m := inode(t, p); i != ino || !m.Equal(mtime) {
		t.Fatal("same content: file replaced")
	}
	// drifted mode/owner: corrected in place, not rewritten
	_ = os.Chmod(p, 0o644) //nolint:gosec // G302: the drift under test
	_ = os.Chown(p, 0, 0)
	if changed, err := tr.writeFile("f", []byte("one\n"), o); err != nil || !changed {
		t.Fatalf("drift not corrected: %v %v", changed, err)
	}
	if i, _ := inode(t, p); i != ino {
		t.Fatal("drift: file replaced instead of corrected")
	}
	if uid, gid, mode := ownerMode(t, p); uid != 0 || gid != 30001 || mode != 0o440 {
		t.Fatalf("after correction %d:%d %v", uid, gid, mode)
	}
	// new content: a new inode renamed over the old one (readers see the old or the new file, never a partial one)
	if changed, err := tr.writeFile("f", []byte("two\n"), o); err != nil || !changed {
		t.Fatalf("new content: %v %v", changed, err)
	}
	if i, _ := inode(t, p); i == ino {
		t.Fatal("new content written in place (not atomic)")
	}
	if b, _ := os.ReadFile(p); string(b) != "two\n" { //nolint:gosec // G304: test
		t.Fatalf("content %q", b)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("temporary files left: %v", entries)
	}
	// a directory where a file is expected is refused
	_ = os.Mkdir(filepath.Join(dir, "d"), 0o700)
	if _, err := tr.writeFile("d", []byte("x"), o); reason(err) != agentv1.RefusalReason_REFUSAL_REASON_UNSAFE_PATH {
		t.Fatalf("directory at a file path: %v", err)
	}
}

// TestSymlinksNeverFollowed: a symlink where the agent expects a file or a directory is refused — for reading,
// writing, changing owner or mode — and its target is never touched; ".." and absolute symlinks cannot leave the root.
func TestSymlinksNeverFollowed(t *testing.T) {
	tr, dir := newTree(t)
	outside := t.TempDir()
	victim := filepath.Join(outside, "victim")
	if err := os.WriteFile(victim, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{victim, "../../../../../../" + strings.TrimPrefix(victim, "/"), "inside"} {
		_ = os.Remove(filepath.Join(dir, "link"))
		_ = os.WriteFile(filepath.Join(dir, "inside"), []byte("in"), 0o600)
		if err := os.Symlink(target, filepath.Join(dir, "link")); err != nil {
			t.Fatal(err)
		}
		if _, err := tr.writeFile("link", []byte("pwned"), owner{0, 0, 0o644}); reason(err) != agentv1.RefusalReason_REFUSAL_REASON_UNSAFE_PATH {
			t.Errorf("write through symlink to %s: %v", target, err)
		}
		if _, err := tr.readFile("link", 1<<10); reason(err) != agentv1.RefusalReason_REFUSAL_REASON_UNSAFE_PATH {
			t.Errorf("read through symlink to %s: %v", target, err)
		}
		if err := tr.ensureFileOwner("link", owner{0, 0, 0o600}); reason(err) != agentv1.RefusalReason_REFUSAL_REASON_UNSAFE_PATH {
			t.Errorf("chown through symlink to %s: %v", target, err)
		}
		if _, err := tr.ensureDir("link", owner{0, 0, 0o700}, true); reason(err) != agentv1.RefusalReason_REFUSAL_REASON_UNSAFE_PATH {
			t.Errorf("directory through symlink to %s: %v", target, err)
		}
	}
	if b, _ := os.ReadFile(victim); string(b) != "keep" { //nolint:gosec // G304: test
		t.Fatal("victim modified")
	}
	if fi, _ := os.Stat(victim); fi.Mode().Perm() != 0o600 {
		t.Fatal("victim mode changed")
	}
	// a symlinked directory on the way: os.Root refuses to leave the root
	if err := os.Symlink(outside, filepath.Join(dir, "out")); err != nil {
		t.Fatal(err)
	}
	if _, err := tr.writeFile("out/new", []byte("x"), owner{0, 0, 0o600}); err == nil {
		t.Fatal("wrote through a symlinked directory leaving the root")
	}
	if _, err := os.Stat(filepath.Join(outside, "new")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("file created outside the root")
	}
	if _, err := tr.writeFile("../escape", []byte("x"), owner{0, 0, 0o600}); err == nil {
		t.Fatal("wrote outside the root with ..")
	}
}

// TestRemoveInstanceKeepsSymlinkTargets: data/ belongs to the tenant, which can plant symlinks there; removing the
// instance removes the links, never what they point to.
func TestRemoveInstanceKeepsSymlinkTargets(t *testing.T) {
	tr, dir := newTree(t)
	l := newLayout("22222222-2222-4222-8222-222222222222")
	if err := tr.createInstance(l, 30001, []byte("{}\n")); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	victim := filepath.Join(outside, "victim")
	_ = os.WriteFile(victim, []byte("keep"), 0o600)
	_ = os.Symlink(victim, filepath.Join(dir, l.data, "db.sqlite"))
	_ = os.Symlink(outside, filepath.Join(dir, l.data, "dir"))
	_ = os.WriteFile(filepath.Join(dir, l.data, "noise_private.key"), []byte("k"), 0o600)
	removed, err := tr.removeInstance(l)
	if err != nil || !removed {
		t.Fatalf("remove: %v %v", removed, err)
	}
	if b, _ := os.ReadFile(victim); string(b) != "keep" { //nolint:gosec // G304: test
		t.Fatal("symlink target removed or changed")
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("left: %v", entries)
	}
	if removed, err := tr.removeInstance(l); err != nil || removed {
		t.Fatalf("second removal: %v %v", removed, err)
	}
	// an interrupted removal left the hidden directory: removed by the next call
	_ = os.MkdirAll(filepath.Join(dir, l.removingDir, "data"), 0o700)
	if _, err := tr.removeInstance(l); err != nil {
		t.Fatal(err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("leftover removing directory kept: %v", entries)
	}
}

// TestCreateInstanceIsAtomic: the instance directory never exists without meta/instance.json — it is assembled under
// a hidden name and renamed; an existing instance directory is never overwritten.
func TestCreateInstanceIsAtomic(t *testing.T) {
	tr, dir := newTree(t)
	l := newLayout("22222222-2222-4222-8222-222222222222")
	if err := tr.createInstance(l, 30001, []byte("{\"a\": 1}\n")); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, l.metaFile)); string(b) != "{\"a\": 1}\n" { //nolint:gosec // G304: test
		t.Fatalf("meta %q", b)
	}
	if err := tr.createInstance(l, 30001, []byte("{}\n")); err == nil {
		t.Fatal("an existing instance directory was replaced")
	}
	if b, _ := os.ReadFile(filepath.Join(dir, l.metaFile)); string(b) != "{\"a\": 1}\n" { //nolint:gosec // G304: test
		t.Fatal("meta of the existing instance changed")
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Fatalf("the refused attempt left %d entries", len(entries))
	}
}
