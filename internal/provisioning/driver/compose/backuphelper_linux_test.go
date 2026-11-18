//go:build linux

package compose

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/backupfmt"
)

type entry struct {
	name    string
	typ     byte
	content []byte
	link    string
}

func tarOf(t *testing.T, es []entry) []byte {
	t.Helper()
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	for _, e := range es {
		h := &tar.Header{Name: e.name, Typeflag: e.typ, Mode: 0o600, Size: int64(len(e.content)), Linkname: e.link, ModTime: time.Unix(0, 0)}
		if e.typ != tar.TypeReg {
			h.Size = 0
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if e.typ == tar.TypeReg {
			_, _ = tw.Write(e.content)
		}
	}
	_ = tw.Close()
	return b.Bytes()
}

func fileOf(path string, content []byte) backupfmt.File {
	s := sha256.Sum256(content)
	return backupfmt.File{Path: path, Size: int64(len(content)), SHA256: hex.EncodeToString(s[:])}
}

// TestUnpackTarRefusesHostileArchives: only regular entries named in the manifest, each once, of the manifest's size
// and digest, are written — a symlink or hard-link entry, a path escaping the staging directory, an entry not in the
// manifest, a duplicate, a changed byte or a missing entry fails the restore before anything is swapped.
func TestUnpackTarRefusesHostileArchives(t *testing.T) {
	good := map[string][]byte{}
	var want []backupfmt.File
	for _, p := range backupfmt.ArchivePaths {
		good[p] = []byte("content of " + p)
		want = append(want, fileOf(p, good[p]))
	}
	wantMap := func() map[string]backupfmt.File {
		m := map[string]backupfmt.File{}
		for _, f := range want {
			m[f.Path] = f
		}
		return m
	}
	all := func() []entry {
		var es []entry
		for _, p := range backupfmt.ArchivePaths {
			es = append(es, entry{name: p, typ: tar.TypeReg, content: good[p]})
		}
		return es
	}
	dst := t.TempDir()
	files, o := unpackTar(bytes.NewReader(tarOf(t, all())), wantMap(), dst, 1<<20)
	if o != nil || len(files) != 3 {
		t.Fatalf("valid archive: %+v %d", o, len(files))
	}
	if b, _ := os.ReadFile(filepath.Join(dst, "db.sqlite")); !bytes.Equal(b, good[backupfmt.PathDB]) { //nolint:gosec // a temporary directory of the test
		t.Fatal("db.sqlite not unpacked")
	}
	cases := map[string]struct {
		es   []entry
		code int
	}{
		"symlink entry":    {append([]entry{{name: backupfmt.PathDB, typ: tar.TypeSymlink, link: "/opt/meshguard/tenants/other/data/db.sqlite"}}, all()[1:]...), HelperExitUnsafe},
		"hard link entry":  {append([]entry{{name: backupfmt.PathDB, typ: tar.TypeLink, link: "data/noise_private.key"}}, all()[1:]...), HelperExitUnsafe},
		"path traversal":   {append(all(), entry{name: "data/../../escape", typ: tar.TypeReg, content: []byte("x")}), HelperExitUnsafe},
		"not in manifest":  {append(all(), entry{name: "data/extra", typ: tar.TypeReg, content: []byte("x")}), HelperExitUnsafe},
		"duplicate":        {append(all(), all()[0]), HelperExitUnsafe},
		"changed byte":     {append([]entry{{name: backupfmt.PathDB, typ: tar.TypeReg, content: []byte("content of data/db.sqlitX")}}, all()[1:]...), HelperExitIntegrity},
		"missing entry":    {all()[:4], HelperExitIntegrity},
		"directory entry":  {append([]entry{{name: "data/", typ: tar.TypeDir}}, all()...), HelperExitUnsafe},
		"fifo entry":       {append([]entry{{name: backupfmt.PathDERPKey, typ: tar.TypeFifo}}, all()...), HelperExitUnsafe},
		"not a tar at all": {nil, HelperExitIntegrity},
	}
	for name, c := range cases {
		d := t.TempDir()
		raw := tarOf(t, c.es)
		if c.es == nil {
			raw = []byte("garbage that is no tar stream at all, long enough to fill a block? no.")
		}
		_, o := unpackTar(bytes.NewReader(raw), wantMap(), d, 1<<20)
		if o == nil || o.code != c.code {
			t.Errorf("%s: want exit %d, got %+v", name, c.code, o)
		}
		if _, err := os.Lstat(filepath.Join(filepath.Dir(d), "escape")); err == nil {
			t.Fatalf("%s: a file escaped the staging directory", name)
		}
	}
}

// TestDataCheck: the start guard's structural check of db.sqlite.
func TestDataCheck(t *testing.T) {
	for name, c := range map[string]struct {
		content []byte
		ok      bool
	}{
		"valid":          {validDB(), true},
		"garbage":        {bytes.Repeat([]byte{0xab}, 4096), false},
		"truncated":      {validDB()[:100], false},
		"not page-sized": {append(validDB(), 1), false},
		"bad page size":  {func() []byte { b := validDB(); b[16], b[17] = 0x03, 0x00; return b }(), false},
		"empty":          {nil, false},
	} {
		d := t.TempDir()
		_ = os.WriteFile(filepath.Join(d, "db.sqlite"), c.content, 0o600)
		o := helperEnv{dataDir: d}.dataCheck(DefaultMaxDBBytes)
		if (o.code == 0) != c.ok {
			t.Errorf("%s: exit %d (%s)", name, o.code, o.res.Reason)
		}
	}
	d := t.TempDir()
	_ = os.Symlink("/etc/passwd", filepath.Join(d, "db.sqlite"))
	if o := (helperEnv{dataDir: d}).dataCheck(DefaultMaxDBBytes); o.code != HelperExitUnsafe {
		t.Errorf("symlink: exit %d", o.code)
	}
}
