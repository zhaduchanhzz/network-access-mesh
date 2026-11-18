package backupfmt

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func hex64(c string) string { return strings.Repeat(c, 64) }

func sampleManifest(signer ed25519.PrivateKey) *Manifest {
	files := make([]File, 0, len(ArchivePaths))
	for _, p := range ArchivePaths {
		files = append(files, File{Path: p, Size: 10, SHA256: hex64("a")})
	}
	return &Manifest{
		Format: Format, TenantID: "11111111-1111-4111-8111-111111111111", InstanceID: "22222222-2222-4222-8222-222222222222",
		Slug: "acme", Sequence: 1700000000123, JobID: "33333333-3333-4333-8333-333333333333",
		CreatedAt: time.Date(2026, 11, 18, 1, 2, 3, 4, time.UTC).Format(time.RFC3339Nano), Method: MethodVacuumInto,
		Image: "ghcr.io/x/headscale@sha256:" + hex64("b"), HeadscaleVersion: "0.29.7", TemplateVersion: "1",
		ConfigSHA256: hex64("c"), NoiseFingerprint: hex64("d"), SQLiteVersion: "3.54.1", Files: files,
		Archive:    Archive{SHA256: hex64("e"), Size: 4096, Encryption: EncryptionAgeV1, Recipients: []string{"data-key:x", "recovery:y"}},
		SigningKey: KeyID(signer.Public().(ed25519.PublicKey)),
	}
}

func newKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func pub(k ed25519.PrivateKey) ed25519.PublicKey { return k.Public().(ed25519.PublicKey) }

// TestManifestSignature (T-15): a manifest verifies only with its own key, unchanged, in canonical form, and is
// refused when one byte — tenant, sequence, a digest — is changed or when another key signed it.
func TestManifestSignature(t *testing.T) {
	k, other := newKey(t), newKey(t)
	m := sampleManifest(k)
	raw, err := m.Encode()
	if err != nil {
		t.Fatal(err)
	}
	sig := Sign(k, raw)
	got, err := Parse(raw, sig, []ed25519.PublicKey{pub(other), pub(k)})
	if err != nil {
		t.Fatalf("valid manifest refused: %v", err)
	}
	if got.Sequence != m.Sequence || got.TenantID != m.TenantID {
		t.Fatalf("parsed %+v", got)
	}
	cases := map[string]func() ([]byte, []byte, []ed25519.PublicKey){
		"tenant_id changed": func() ([]byte, []byte, []ed25519.PublicKey) {
			return bytes.Replace(raw, []byte(m.TenantID), []byte("44444444-4444-4444-8444-444444444444"), 1), sig, []ed25519.PublicKey{pub(k)}
		},
		"sequence changed": func() ([]byte, []byte, []ed25519.PublicKey) {
			return bytes.Replace(raw, []byte("1700000000123"), []byte("1700000000124"), 1), sig, []ed25519.PublicKey{pub(k)}
		},
		"archive digest changed": func() ([]byte, []byte, []ed25519.PublicKey) {
			return bytes.Replace(raw, []byte(hex64("e")), []byte(hex64("f")), 1), sig, []ed25519.PublicKey{pub(k)}
		},
		"signed by another key": func() ([]byte, []byte, []ed25519.PublicKey) {
			m2 := sampleManifest(other)
			r2, _ := m2.Encode()
			return r2, Sign(other, r2), []ed25519.PublicKey{pub(k)}
		},
		"signature without context": func() ([]byte, []byte, []ed25519.PublicKey) {
			return raw, ed25519.Sign(k, raw), []ed25519.PublicKey{pub(k)}
		},
		"no signature":   func() ([]byte, []byte, []ed25519.PublicKey) { return raw, nil, []ed25519.PublicKey{pub(k)} },
		"no trusted key": func() ([]byte, []byte, []ed25519.PublicKey) { return raw, sig, nil },
		"not canonical (re-signed with whitespace)": func() ([]byte, []byte, []ed25519.PublicKey) {
			r2 := bytes.Replace(raw, []byte(`,"slug"`), []byte(`, "slug"`), 1)
			return r2, Sign(k, r2), []ed25519.PublicKey{pub(k)}
		},
		"unknown field (re-signed)": func() ([]byte, []byte, []ed25519.PublicKey) {
			r2 := bytes.Replace(raw, []byte(`{"format"`), []byte(`{"extra":1,"format"`), 1)
			return r2, Sign(k, r2), []ed25519.PublicKey{pub(k)}
		},
		"signing_key names another key (re-signed)": func() ([]byte, []byte, []ed25519.PublicKey) {
			m2 := sampleManifest(other)
			r2, _ := m2.Encode()
			return r2, Sign(k, r2), []ed25519.PublicKey{pub(k)}
		},
	}
	for name, c := range cases {
		r, s, keys := c()
		if _, err := Parse(r, s, keys); !errors.Is(err, ErrManifest) {
			t.Errorf("%s: want ErrManifest, got %v", name, err)
		}
	}
}

// TestManifestIdentity (AC-19, T-15): a manifest of A never matches B — tenant, instance, slug or sequence.
func TestManifestIdentity(t *testing.T) {
	m := sampleManifest(newKey(t))
	want := Identity{TenantID: uuid.MustParse(m.TenantID), InstanceID: uuid.MustParse(m.InstanceID), Slug: m.Slug, Sequence: m.Sequence}
	if err := m.Check(want); err != nil {
		t.Fatal(err)
	}
	for name, w := range map[string]Identity{
		"other tenant":   {TenantID: uuid.New(), InstanceID: want.InstanceID, Slug: want.Slug, Sequence: want.Sequence},
		"other instance": {TenantID: want.TenantID, InstanceID: uuid.New(), Slug: want.Slug, Sequence: want.Sequence},
		"other slug":     {TenantID: want.TenantID, InstanceID: want.InstanceID, Slug: "other", Sequence: want.Sequence},
		"other sequence": {TenantID: want.TenantID, InstanceID: want.InstanceID, Slug: want.Slug, Sequence: want.Sequence + 1},
	} {
		if err := m.Check(w); !errors.Is(err, ErrManifest) {
			t.Errorf("%s: want ErrManifest, got %v", name, err)
		}
	}
}

// TestDataKeyWrap (T-15): a data key wrapped with tenant A's backup key opens only with that key, for that tenant,
// instance and sequence; tenant B's backup key — or A's key for another instance/backup — opens nothing.
func TestDataKeyWrap(t *testing.T) {
	keyA, keyB := make([]byte, BackupKeyBytes), make([]byte, BackupKeyBytes)
	_, _ = rand.Read(keyA)
	_, _ = rand.Read(keyB)
	dk, err := NewDataKey()
	if err != nil {
		t.Fatal(err)
	}
	ta, ia := uuid.New(), uuid.New()
	w, err := WrapDataKey(keyA, dk, ta, ia, 5)
	if err != nil || len(w) != WrappedDataKeyBytes {
		t.Fatalf("wrap: %v (%d bytes)", err, len(w))
	}
	if bytes.Contains(w, dk) {
		t.Fatal("the wrapped key contains the data key")
	}
	got, err := UnwrapDataKey(keyA, w, ta, ia, 5)
	if err != nil || !bytes.Equal(got, dk) {
		t.Fatalf("unwrap: %v", err)
	}
	for name, try := range map[string]func() ([]byte, error){
		"tenant B's backup key": func() ([]byte, error) { return UnwrapDataKey(keyB, w, ta, ia, 5) },
		"another tenant":        func() ([]byte, error) { return UnwrapDataKey(keyA, w, uuid.New(), ia, 5) },
		"another instance":      func() ([]byte, error) { return UnwrapDataKey(keyA, w, ta, uuid.New(), 5) },
		"another sequence":      func() ([]byte, error) { return UnwrapDataKey(keyA, w, ta, ia, 6) },
		"one bit flipped": func() ([]byte, error) {
			x := bytes.Clone(w)
			x[20] ^= 1
			return UnwrapDataKey(keyA, x, ta, ia, 5)
		},
		"truncated": func() ([]byte, error) { return UnwrapDataKey(keyA, w[:40], ta, ia, 5) },
	} {
		if k, err := try(); !errors.Is(err, ErrUnwrap) || k != nil {
			t.Errorf("%s: want ErrUnwrap, got %v", name, err)
		}
	}
	// B's data key is another identity: its recipient is never A's (the age layer refuses — agent-it checks it for real)
	dkB, _ := NewDataKey()
	pa, _ := DataRecipient(dk)
	pb, _ := DataRecipient(dkB)
	if bytes.Equal(pa, pb) {
		t.Fatal("two data keys, one recipient")
	}
}

// TestAgeEncodings: the age identity and recipient strings of a data key round-trip and agree with each other; the
// recovery recipient parser refuses identities, private keys and corrupted strings.
func TestAgeEncodings(t *testing.T) {
	dk, _ := NewDataKey()
	id, err := AgeIdentity(dk)
	if err != nil || !strings.HasPrefix(id, "AGE-SECRET-KEY-1") || len(id) != 74 || strings.ToUpper(id) != id {
		t.Fatalf("identity %q… (%d chars): %v", id[:16], len(id), err)
	}
	back, err := ParseAgeIdentity(id)
	if err != nil || !bytes.Equal(back, dk) {
		t.Fatalf("identity round trip: %v", err)
	}
	p, _ := DataRecipient(dk)
	r, err := RecipientString(p)
	if err != nil || !strings.HasPrefix(r, "age1") || len(r) != 62 {
		t.Fatalf("recipient %q: %v", r, err)
	}
	if got, err := ParseRecipient(r); err != nil || !bytes.Equal(got, p) {
		t.Fatalf("recipient round trip: %v", err)
	}
	// the published recipient of the staging ceremony (P2-T04a evidence) parses
	if _, err := ParseRecipient("age19xj7cfa42y3mshtts25e4td278yhmjp5tkeeky2ryhvea4zpr4cqd9p2tx"); err != nil {
		t.Fatalf("staging recovery recipient: %v", err)
	}
	// the last character replaced by another one (a fixed "q" equals the original 1 time in 32 — the checksum is random)
	last := "q"
	if r[61:] == "q" {
		last = "p"
	}
	bad := []string{"", id, strings.ToUpper(r), r[:61] + last, "age1" + strings.Repeat("q", 58), "age1pq1abc", r + "q"}
	for _, s := range bad {
		if _, err := ParseRecipient(s); err == nil {
			t.Errorf("recipient %q accepted", s)
		}
	}
	// BIP 173 test vectors (valid / invalid checksum)
	if _, _, err := bech32Decode("A12UEL5L"); err != nil {
		t.Errorf("BIP173 valid vector: %v", err)
	}
	if _, _, err := bech32Decode("a12uel5m"); err == nil {
		t.Error("BIP173 invalid checksum accepted")
	}
}

func TestRestorableVersions(t *testing.T) {
	img, other := "r@sha256:"+hex64("1"), "r@sha256:"+hex64("2")
	ok := [][2]string{{"0.29.7", "v0.29.7+mg.1"}, {"0.29.1", "0.29.7"}, {"0.28.3", "0.29.7"}}
	for _, c := range ok {
		if err := Restorable(c[0], img, c[1], other); err != nil {
			t.Errorf("%s on %s: %v", c[0], c[1], err)
		}
	}
	bad := [][2]string{{"0.30.0", "0.29.7"}, {"0.27.0", "0.29.7"}, {"1.29.7", "0.29.7"}, {"unknown", "0.29.7"}}
	for _, c := range bad {
		if err := Restorable(c[0], img, c[1], other); err == nil {
			t.Errorf("%s on %s accepted", c[0], c[1])
		}
	}
	if err := Restorable("unknown", img, "unknown", img); err != nil {
		t.Errorf("same image, unknown version: %v", err)
	}
}

func TestUpgradePath(t *testing.T) {
	ok := []struct{ from, to, path string }{
		{"0.29.7", "v0.29.7", PathPatch}, {"v0.29.7+mg.1", "v0.29.7", PathPatch}, {"0.29.6", "0.29.7", PathPatch},
		{"0.29.7", "0.30.0", PathMinor}, {"0.29.7", "v0.30.2", PathMinor},
	}
	for _, c := range ok {
		if p, err := UpgradePath(c.from, c.to); err != nil || p != c.path {
			t.Errorf("%s → %s: %q, %v", c.from, c.to, p, err)
		}
	}
	bad := [][2]string{{"0.29.7", "0.29.6"}, {"0.30.0", "0.29.7"}, {"0.29.7", "0.31.0"}, {"0.29.7", "1.0.0"},
		{"unknown", "0.29.7"}, {"0.29.7", ""}}
	for _, c := range bad {
		if _, err := UpgradePath(c[0], c[1]); !errors.Is(err, ErrVersionPath) {
			t.Errorf("%s → %s accepted (%v)", c[0], c[1], err)
		}
	}
}

func TestNames(t *testing.T) {
	for _, n := range []string{ArchiveName(42), ManifestName(42), SignatureName(42), ArchiveName(42) + ".partial"} {
		if seq, ok := ParseName(n); !ok || seq != 42 {
			t.Errorf("%s: %d %v", n, seq, ok)
		}
	}
	for _, n := range []string{"42.tar.age", "../00000000000000000042.tar.age", "00000000000000000042.tar", "00000000000000000000.tar.age"} {
		if _, ok := ParseName(n); ok {
			t.Errorf("%s accepted", n)
		}
	}
}

func TestKeysParse(t *testing.T) {
	k := newKey(t)
	spki := PublicKeySPKI(pub(k))
	keys, err := ParsePublicKeys(" " + spki + " , " + PublicKeySPKI(pub(newKey(t))))
	if err != nil || len(keys) != 2 || !keys[0].Equal(pub(k)) {
		t.Fatalf("parse: %v", err)
	}
	// the published staging key of the ceremony parses
	if _, err := ParsePublicKeys("MCowBQYDK2VwAyEA7rQo5bebwY3AlnB9ahjZwGGUzVu39POjhZbZwbg7Wlc="); err != nil {
		t.Fatalf("staging manifest key: %v", err)
	}
	for _, s := range []string{"", "x", "MCowBQYDK2VwAyEA"} {
		if _, err := ParsePublicKeys(s); err == nil {
			t.Errorf("%q accepted", s)
		}
	}
	if _, err := ParseSigningKey([]byte("-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n")); err == nil {
		t.Error("a public key block accepted as signing key")
	}
}
