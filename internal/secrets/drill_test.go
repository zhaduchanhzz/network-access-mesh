package secrets

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestKCVTestVectors pins the key check value (KCVLabel): the ceremony scripts compute the same values with Python's
// hmac module (infrastructure/host/key-ceremony/test_ceremony.py checks the same vectors), and every KCV written on an
// offline copy depends on it.
func TestKCVTestVectors(t *testing.T) {
	seq := make([]byte, keySize) // 00 01 02 … 1f
	for i := range seq {
		seq[i] = byte(i)
	}
	ones := bytes.Repeat([]byte{0xff}, keySize)
	for _, c := range []struct {
		key  []byte
		want string
	}{{seq, "1dccd334"}, {ones, "185483a4"}} {
		if got := kcv(c.key); got != c.want {
			t.Errorf("kcv(%x…) = %s, want %s", c.key[:2], got, c.want)
		}
	}
	flipped := bytes.Clone(seq)
	flipped[31] ^= 0x01
	if kcv(flipped) == kcv(seq) {
		t.Error("a one-bit change of the key keeps the KCV")
	}
	// LoadKeyring exposes the same value per kek_id, and nothing for an unknown kek_id
	dir := t.TempDir()
	writeKeyFile(t, dir, "kek-1", seq)
	writeActive(t, dir, "kek-1")
	kr, err := LoadKeyring(KEKApp, dir)
	if err != nil {
		t.Fatal(err)
	}
	if kr.KCV("kek-1") != "1dccd334" || kr.KCV("kek-2") != "" {
		t.Errorf("Keyring.KCV = %q / %q", kr.KCV("kek-1"), kr.KCV("kek-2"))
	}
}

// setMode sets the mode of a test file (the host modes 0440 and the refused 0444/0441 are parameters, as in
// TestLoadKeyringRejects).
func setMode(t *testing.T, p string, m os.FileMode) {
	t.Helper()
	if err := os.Chmod(p, m); err != nil {
		t.Fatal(err)
	}
}

// copyKeyring copies a keyring directory (the recovered keyring of the drill), every file with the host mode 0440.
func copyKeyring(t *testing.T, src string) string {
	t.Helper()
	dst := filepath.Join(t.TempDir(), "recovered")
	if err := os.CopyFS(dst, os.DirFS(src)); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dst)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		setMode(t, filepath.Join(dst, e.Name()), 0o440)
	}
	return dst
}

// rewrite replaces one file of a copied keyring (the copy is 0440: make it writable first).
func rewrite(t *testing.T, dir, name, content string) {
	t.Helper()
	p := filepath.Join(dir, name)
	setMode(t, p, 0o600)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// assertNoKeyMaterial fails if the report (formatted every way a caller could print it) or an error contains any
// encoding of the keys.
func assertNoKeyMaterial(t *testing.T, tk *testKeyring, v ...any) {
	t.Helper()
	var out []string
	for _, x := range v {
		out = append(out, fmt.Sprintf("%v %+v %#v", x, x, x))
	}
	joined := strings.Join(out, "\n")
	for _, m := range tk.material() {
		if strings.Contains(joined, m) || strings.Contains(strings.ToLower(joined), strings.ToLower(m)) {
			t.Fatalf("key material in the drill output: %d bytes", len(m))
		}
	}
}

// TestDrillMatch: a faithful copy of a keyring with two KEK versions (rewrap window) passes, every kek_id both ways,
// for both keyrings, with the host modes.
func TestDrillMatch(t *testing.T) {
	for _, name := range []string{KEKApp, KEKOps} {
		tk := newTestKeyring(t, name, "staging-2026-11")
		tk.add(t, "staging-2027-11", randomKey(t), true)
		rec := copyKeyring(t, tk.dir)
		r, err := Drill(name, tk.dir, rec)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !r.OK() || r.Keyring != name || r.LiveActive != "staging-2027-11" || r.RecoveredActive != r.LiveActive ||
			len(r.KEKs) != 2 {
			t.Fatalf("%s: report %+v", name, r)
		}
		for _, k := range r.KEKs {
			if !k.LiveToRecovered || !k.RecoveredToLive || k.LiveKCV == "" || k.LiveKCV != k.RecoveredKCV ||
				k.LiveKCV != kcv(tk.keys[k.ID]) {
				t.Errorf("%s: %+v", name, k)
			}
		}
		assertNoKeyMaterial(t, tk, r, *r)
	}
}

// TestDrillDetectsDifferences: each way a recovered keyring can differ from the live one fails the drill, naming
// the kek_id and the KCVs only.
func TestDrillDetectsDifferences(t *testing.T) {
	tk := newTestKeyring(t, KEKApp, "kek-old")
	tk.add(t, "kek-new", randomKey(t), true)
	newHex := hex.EncodeToString(tk.keys["kek-new"])
	flip := func(h string, bit int) string { // flip one bit of the hex-encoded key
		b, _ := hex.DecodeString(h)
		b[bit/8] ^= 1 << (bit % 8)
		return hex.EncodeToString(b)
	}
	cases := map[string]struct {
		edit func(t *testing.T, dir string)
		want []string // substrings of the problems
	}{
		"one-bit difference (last bit)": {
			func(t *testing.T, dir string) { rewrite(t, dir, "kek-new", flip(newHex, 255)+"\n") },
			[]string{`kek_id "kek-new": KCV differs`, "does not unwrap with the recovered one", "does not unwrap with the live one"},
		},
		"one-bit difference (first bit)": {
			func(t *testing.T, dir string) { rewrite(t, dir, "kek-new", flip(newHex, 0)+"\n") },
			[]string{`kek_id "kek-new": KCV differs`},
		},
		"same key under another kek_id": {
			func(t *testing.T, dir string) {
				if err := os.Rename(filepath.Join(dir, "kek-new"), filepath.Join(dir, "kek-newer")); err != nil {
					t.Fatal(err)
				}
				rewrite(t, dir, ActiveFile, "kek-newer\n")
			},
			[]string{`ACTIVE differs: live "kek-new", recovered "kek-newer"`, `kek_id "kek-new" is missing`, `kek_id "kek-newer" is only in the recovered`},
		},
		"ACTIVE names the old KEK": {
			func(t *testing.T, dir string) { rewrite(t, dir, ActiveFile, "kek-old\n") },
			[]string{`ACTIVE differs: live "kek-new", recovered "kek-old"`},
		},
		"old KEK version missing": {
			func(t *testing.T, dir string) {
				if err := os.Remove(filepath.Join(dir, "kek-old")); err != nil {
					t.Fatal(err)
				}
			},
			[]string{`kek_id "kek-old" is missing from the recovered keyring`},
		},
		"keys of the two versions swapped": {
			func(t *testing.T, dir string) {
				rewrite(t, dir, "kek-new", hex.EncodeToString(tk.keys["kek-old"])+"\n")
				rewrite(t, dir, "kek-old", newHex+"\n")
			},
			[]string{`kek_id "kek-new": KCV differs`, `kek_id "kek-old": KCV differs`},
		},
	}
	for name, c := range cases {
		rec := copyKeyring(t, tk.dir)
		c.edit(t, rec)
		r, err := Drill(KEKApp, tk.dir, rec)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if r.OK() {
			t.Errorf("%s: drill passed", name)
			continue
		}
		all := strings.Join(r.Problems, "\n")
		for _, w := range c.want {
			if !strings.Contains(all, w) {
				t.Errorf("%s: problems lack %q:\n%s", name, w, all)
			}
		}
		assertNoKeyMaterial(t, tk, r, *r)
	}
	// a faithful copy still passes after all this (the cases worked on their own copies)
	if r, err := Drill(KEKApp, tk.dir, copyKeyring(t, tk.dir)); err != nil || !r.OK() {
		t.Fatalf("control: %+v %v", r, err)
	}
}

// TestDrillKeyringsOfDifferentScopes: the keyring name only selects the scope of the test DEK; a kek-ops copy that
// holds the kek-app key under the same kek_id (offline copies mixed up) fails on the KCV.
func TestDrillKeyringsOfDifferentScopes(t *testing.T) {
	app := newTestKeyring(t, KEKApp, "k1")
	ops := newTestKeyring(t, KEKOps, "k1") // same kek_id, other key
	r, err := Drill(KEKOps, ops.dir, app.dir)
	if err != nil {
		t.Fatal(err)
	}
	if r.OK() || !strings.Contains(strings.Join(r.Problems, "\n"), `kek_id "k1": KCV differs`) {
		t.Fatalf("kek-ops recovered from the kek-app key: %+v", r)
	}
}

// TestDrillRejectsWhatLoadKeyringRejects: the recovered keyring is held to the rules of a process start; the error
// names the side and the file, never the content.
func TestDrillRejectsWhatLoadKeyringRejects(t *testing.T) {
	tk := newTestKeyring(t, KEKApp, "kek-1")
	keyHex := hex.EncodeToString(tk.keys["kek-1"])
	cases := map[string]func(t *testing.T, dir string){
		"63 hex characters": func(t *testing.T, dir string) { rewrite(t, dir, "kek-1", keyHex[:63]+"\n") },
		"65 hex characters": func(t *testing.T, dir string) { rewrite(t, dir, "kek-1", keyHex+"0\n") },
		"groups with spaces": func(t *testing.T, dir string) {
			rewrite(t, dir, "kek-1", keyHex[:4]+" "+keyHex[4:]+"\n")
		},
		"non-hex letter": func(t *testing.T, dir string) { rewrite(t, dir, "kek-1", "g"+keyHex[1:]+"\n") },
		"no ACTIVE": func(t *testing.T, dir string) {
			if err := os.Remove(filepath.Join(dir, ActiveFile)); err != nil {
				t.Fatal(err)
			}
		},
		"world-readable key file":   func(t *testing.T, dir string) { setMode(t, filepath.Join(dir, "kek-1"), 0o444) },
		"other-executable key file": func(t *testing.T, dir string) { setMode(t, filepath.Join(dir, "kek-1"), 0o441) },
	}
	for name, edit := range cases {
		if strings.Contains(name, "able") && runtime.GOOS == "windows" {
			continue
		}
		rec := copyKeyring(t, tk.dir)
		edit(t, rec)
		r, err := Drill(KEKApp, tk.dir, rec)
		if err == nil {
			t.Errorf("%s: drill ran (%+v)", name, r)
			continue
		}
		if !strings.HasPrefix(err.Error(), "recovered keyring: ") {
			t.Errorf("%s: error does not name the side: %v", name, err)
		}
		assertNoKeyMaterial(t, tk, err)
		if strings.Contains(err.Error(), keyHex[:16]) {
			t.Errorf("%s: error quotes the key file: %v", name, err)
		}
	}
	// the live side is checked the same way, and a relative directory is refused
	if _, err := Drill(KEKApp, "relative/kek-app", tk.dir); err == nil || !strings.HasPrefix(err.Error(), "live keyring: ") {
		t.Errorf("relative live directory: %v", err)
	}
	if _, err := Drill("kek-other", tk.dir, tk.dir); err == nil {
		t.Error("unknown keyring name accepted")
	}
}
