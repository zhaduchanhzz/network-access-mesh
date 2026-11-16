package secrets

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// randomKey returns a fresh 32-byte key (test keys are generated per run, never committed).
func randomKey(t testing.TB) []byte {
	t.Helper()
	k, err := newDEK()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// writeKeyFile writes one KEK file the way P2-T04a does: 64 hex characters and a newline (mode 0600 here; on the
// host 0440 root:<service group> — accepted too, see TestLoadKeyringRejects).
func writeKeyFile(t testing.TB, dir, kekID string, key []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, kekID), []byte(hex.EncodeToString(key)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeActive(t testing.TB, dir, kekID string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, ActiveFile), []byte(kekID+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// testKeyring is a keyring directory created for one test, with the raw keys kept for leak checks.
type testKeyring struct {
	name string
	dir  string
	keys map[string][]byte
	kr   *Keyring
}

// newTestKeyring creates a keyring directory holding one fresh KEK (active) and loads it.
func newTestKeyring(t testing.TB, name, kekID string) *testKeyring {
	t.Helper()
	tk := &testKeyring{name: name, dir: t.TempDir(), keys: map[string][]byte{}}
	return tk.add(t, kekID, randomKey(t), true)
}

// add writes another KEK version (optionally making it ACTIVE) and reloads the keyring.
func (tk *testKeyring) add(t testing.TB, kekID string, key []byte, active bool) *testKeyring {
	t.Helper()
	tk.keys[kekID] = key
	writeKeyFile(t, tk.dir, kekID, key)
	if active {
		writeActive(t, tk.dir, kekID)
	}
	return tk.reload(t)
}

// remove deletes a KEK file (the old KEK after a completed rewrap) and reloads.
func (tk *testKeyring) remove(t testing.TB, kekID string) *testKeyring {
	t.Helper()
	if err := os.Remove(filepath.Join(tk.dir, kekID)); err != nil {
		t.Fatal(err)
	}
	delete(tk.keys, kekID)
	return tk.reload(t)
}

func (tk *testKeyring) reload(t testing.TB) *testKeyring {
	t.Helper()
	kr, err := LoadKeyring(tk.name, tk.dir)
	if err != nil {
		t.Fatalf("LoadKeyring(%s): %v", tk.name, err)
	}
	tk.kr = kr
	return tk
}

// material returns every encoding of every key under which it could leak into a log line or an error.
func (tk *testKeyring) material() []string {
	var out []string
	for _, k := range tk.keys {
		out = append(out, keyEncodings(k)...)
	}
	return out
}

func keyEncodings(k []byte) []string {
	h := hex.EncodeToString(k)
	return []string{h, strings.ToUpper(h), base64.StdEncoding.EncodeToString(k), base64.RawURLEncoding.EncodeToString(k),
		string(k)}
}

func TestLoadKeyring(t *testing.T) {
	tk := newTestKeyring(t, KEKApp, "app-2026-11")
	old := tk.kr
	tk.add(t, "app-2027-11", randomKey(t), true)
	if err := os.WriteFile(filepath.Join(tk.dir, ".editor-swap"), []byte("ignored"), 0o600); err != nil {
		t.Fatal(err)
	}
	tk.reload(t)
	kr := tk.kr
	if kr.Name() != KEKApp || kr.Active() != "app-2027-11" || strings.Join(kr.IDs(), ",") != "app-2026-11,app-2027-11" {
		t.Fatalf("keyring = %s active %s ids %v", kr.Name(), kr.Active(), kr.IDs())
	}
	aad := wrapAAD("tenant", ptr(uuid.New()), 1)
	dek := randomKey(t)
	id, nonce, wrapped, err := kr.wrap(dek, aad)
	if err != nil || id != "app-2027-11" {
		t.Fatalf("wrap: %s %v", id, err)
	}
	if got, err := kr.unwrap(id, nonce, wrapped, aad); err != nil || !bytes.Equal(got, dek) {
		t.Fatalf("unwrap: %v", err)
	}
	// a DEK wrapped under the old KEK still unwraps while both are in the keyring (rewrap window — §7.6)
	oid, onon, owr, err := old.wrap(dek, aad)
	if err != nil || oid != "app-2026-11" {
		t.Fatal(oid, err)
	}
	if got, err := kr.unwrap(oid, onon, owr, aad); err != nil || !bytes.Equal(got, dek) {
		t.Fatalf("unwrap under the old KEK: %v", err)
	}
}

func TestKeyringWrongKeyAndAAD(t *testing.T) {
	a := newTestKeyring(t, KEKApp, "kek-1").kr
	sameID := newTestKeyring(t, KEKApp, "kek-1").kr // same kek_id, other key bytes
	tenantA, tenantB := uuid.New(), uuid.New()
	aad := wrapAAD("tenant", &tenantA, 1)
	_, nonce, wrapped, err := a.wrap(randomKey(t), aad)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sameID.unwrap("kek-1", nonce, wrapped, aad); !errors.Is(err, ErrIntegrity) {
		t.Errorf("wrong KEK under the same kek_id: %v, want ErrIntegrity", err)
	}
	if _, err := a.unwrap("kek-2", nonce, wrapped, aad); !errors.Is(err, ErrUnknownKEK) {
		t.Errorf("unknown kek_id: %v, want ErrUnknownKEK", err)
	}
	for name, other := range map[string][]byte{
		"other tenant":   wrapAAD("tenant", &tenantB, 1),
		"other version":  wrapAAD("tenant", &tenantA, 2),
		"platform scope": wrapAAD("platform", nil, 1),
	} {
		if _, err := a.unwrap("kek-1", nonce, wrapped, other); !errors.Is(err, ErrIntegrity) {
			t.Errorf("%s: %v, want ErrIntegrity", name, err)
		}
	}
}

func TestLoadKeyringRejects(t *testing.T) {
	key := randomKey(t)
	keyHex := hex.EncodeToString(key)
	type setup func(t *testing.T, dir string)
	file := func(name, content string, mode os.FileMode) setup {
		return func(t *testing.T, dir string) {
			p := filepath.Join(dir, name)
			if err := os.WriteFile(p, []byte(content), mode); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(p, mode); err != nil {
				t.Fatal(err)
			}
		}
	}
	const hostMode = 0o440 // root:<service group> on the host (§14.2)
	good := file("kek-1", keyHex+"\n", hostMode)
	active := file(ActiveFile, "kek-1\n", hostMode)
	cases := map[string][]setup{
		"empty directory":    nil,
		"no ACTIVE":          {good},
		"ACTIVE unknown":     {good, file(ActiveFile, "kek-9\n", 0o640)},
		"ACTIVE two words":   {good, file(ActiveFile, "kek-1 kek-2\n", 0o640)},
		"ACTIVE empty":       {good, file(ActiveFile, "", 0o640)},
		"short key":          {file("kek-1", keyHex[:62]+"\n", 0o640), active},
		"long key":           {file("kek-1", keyHex+"ab\n", 0o640), active},
		"not hex":            {file("kek-1", "g"+keyHex[1:]+"\n", 0o640), active},
		"raw bytes":          {file("kek-1", string(key), 0o640), active},
		"two newlines":       {file("kek-1", keyHex+"\n\n", 0o640), active},
		"spaces":             {file("kek-1", " "+keyHex[1:]+"\n", 0o640), active},
		"bad entry name":     {good, active, file("kek 2", keyHex, 0o640)},
		"subdirectory":       {good, active, func(t *testing.T, dir string) { _ = os.Mkdir(filepath.Join(dir, "sub"), 0o750) }},
		"stray backup file":  {good, active, file("ACTIVE.bak", "kek-1\n", 0o640)},
		"world-readable key": {file("kek-1", keyHex+"\n", 0o644), active},
	}
	for name, steps := range cases {
		if name == "world-readable key" && runtime.GOOS == "windows" {
			continue
		}
		dir := t.TempDir()
		for _, s := range steps {
			s(t, dir)
		}
		kr, err := LoadKeyring(KEKApp, dir)
		if err == nil {
			t.Errorf("%s: loaded (active %s)", name, kr.Active())
			continue
		}
		if strings.Contains(strings.ToLower(err.Error()), keyHex[2:20]) {
			t.Errorf("%s: the error quotes the key file: %v", name, err)
		}
	}
	if _, err := LoadKeyring(KEKApp, "relative/kek-app"); err == nil {
		t.Error("relative directory accepted")
	}
	if _, err := LoadKeyring(KEKApp, filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("missing directory accepted")
	}
	dir := t.TempDir()
	good(t, dir)
	active(t, dir)
	if _, err := LoadKeyring("kek-other", dir); err == nil {
		t.Error("unknown keyring name accepted")
	}
	if kr, err := LoadKeyring(KEKOps, dir); err != nil || kr.Name() != KEKOps {
		t.Errorf("valid keyring as %s: %v", KEKOps, err)
	}
}

func ptr[T any](v T) *T { return &v }
