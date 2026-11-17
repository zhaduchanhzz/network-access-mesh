package secrets

import (
	"bytes"
	"crypto/cipher"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func testAEAD(t *testing.T) cipher.AEAD {
	t.Helper()
	key, err := newDEK()
	if err != nil {
		t.Fatal(err)
	}
	a, err := newAEAD(key)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// TestAADFormat pins the AAD bytes: changing them makes every stored secret and wrapped DEK unreadable.
func TestAADFormat(t *testing.T) {
	tenant := uuid.MustParse("0195f3a2-7c41-7b9e-8d2a-5f0e6c1b9a77")
	for _, c := range []struct{ got, want string }{
		{string(secretAAD(TenantRef(tenant, "headscale.apikey", 7))), "mgsec/v1|0195f3a2-7c41-7b9e-8d2a-5f0e6c1b9a77|headscale.apikey|7"},
		{string(secretAAD(PlatformRef("smtp.password", 1))), "mgsec/v1|platform|smtp.password|1"},
		{string(wrapAAD("tenant", &tenant, 2)), "mgdek/v1|tenant|0195f3a2-7c41-7b9e-8d2a-5f0e6c1b9a77|2"},
		{string(wrapAAD("platform", nil, 1)), "mgdek/v1|platform||1"},
		{string(wrapAAD("platform_ops", nil, 3)), "mgdek/v1|platform_ops||3"},
	} {
		if c.got != c.want {
			t.Errorf("AAD = %q, want %q", c.got, c.want)
		}
	}
}

// TestSecretAADBinding: a ciphertext opens only under the AAD of its own tenant, name and version (§7.6).
func TestSecretAADBinding(t *testing.T) {
	a, b := uuid.New(), uuid.New()
	aead := testAEAD(t)
	ref := TenantRef(a, "headscale.apikey", 2)
	value := []byte("an API key bound to its tenant, name and version")
	nonce, ct, err := seal(aead, value, secretAAD(ref))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ct, value) {
		t.Fatal("ciphertext contains the plaintext")
	}
	if pt, err := open(aead, nonce, ct, secretAAD(ref)); err != nil || !bytes.Equal(pt, value) {
		t.Fatalf("open with the right AAD: %q, %v", pt, err)
	}
	for name, other := range map[string]Ref{
		"other tenant":  TenantRef(b, ref.Name, ref.Version),
		"platform":      PlatformRef(ref.Name, ref.Version),
		"other name":    TenantRef(a, "headscale.apikey2", ref.Version),
		"older version": TenantRef(a, ref.Name, 1),
		"newer version": TenantRef(a, ref.Name, 3),
	} {
		if _, err := open(aead, nonce, ct, secretAAD(other)); !errors.Is(err, ErrIntegrity) {
			t.Errorf("%s: open succeeded or wrong error (%v), want ErrIntegrity", name, err)
		}
	}
}

// TestOpenRejectsWrongKeyAndTampering: wrong key, any modified byte of nonce/ciphertext/tag, truncation.
func TestOpenRejectsWrongKeyAndTampering(t *testing.T) {
	aead := testAEAD(t)
	aad := secretAAD(PlatformRef("x", 1))
	nonce, ct, err := seal(aead, []byte("value"), aad)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := open(testAEAD(t), nonce, ct, aad); !errors.Is(err, ErrIntegrity) {
		t.Errorf("wrong key: %v", err)
	}
	flip := func(b []byte, i int) []byte {
		c := bytes.Clone(b)
		c[i] ^= 0x01
		return c
	}
	cases := map[string][2][]byte{
		"nonce":        {flip(nonce, 0), ct},
		"ciphertext":   {nonce, flip(ct, 0)},
		"tag":          {nonce, flip(ct, len(ct)-1)},
		"truncated":    {nonce, ct[:len(ct)-1]},
		"short nonce":  {nonce[:8], ct},
		"empty":        {nonce, nil},
		"nonce reused": {nonce, mustSeal(t, aead, nonce, []byte("other"), aad)},
	}
	for name, c := range cases {
		pt, err := open(aead, c[0], c[1], aad)
		if name == "nonce reused" { // same nonce, other plaintext: a valid ciphertext, only to show nonces must be fresh
			if err != nil || string(pt) != "other" {
				t.Errorf("%s: %q, %v", name, pt, err)
			}
			continue
		}
		if !errors.Is(err, ErrIntegrity) {
			t.Errorf("%s: open succeeded or wrong error (%v)", name, err)
		}
	}
	// fresh random nonce every time
	n2, _, err := seal(aead, []byte("value"), aad)
	if err != nil || bytes.Equal(n2, nonce) || len(n2) != nonceSize {
		t.Errorf("nonces: %x then %x (%v)", nonce, n2, err)
	}
}

func mustSeal(t *testing.T, aead cipher.AEAD, nonce, pt, aad []byte) []byte {
	t.Helper()
	return aead.Seal(nil, nonce, pt, aad)
}

// TestPlaintextRedacted: a decrypted value printed or logged by mistake shows [REDACTED].
func TestPlaintextRedacted(t *testing.T) {
	const canary = "CANARY-plaintext-51d0"
	p := Plaintext(canary)
	var out []string
	for _, verb := range []string{"%s", "%v", "%+v", "%#v", "%q", "%x", "%X", "%d", "%T"} {
		out = append(out, fmt.Sprintf(verb, p))
	}
	out = append(out, fmt.Sprint(p), fmt.Sprintln(p), p.String(), p.GoString(), fmt.Sprintf("%v", []any{p}),
		fmt.Sprintf("%+v", struct{ V Plaintext }{p}))
	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("x", "value", p, "nested", slog.GroupValue(slog.Any("v", p)))
	slog.New(slog.NewTextHandler(&buf, nil)).Info("x", "value", p)
	out = append(out, buf.String())
	j, err := json.Marshal(map[string]any{"v": p})
	if err != nil {
		t.Fatal(err)
	}
	out = append(out, string(j))
	for _, s := range out {
		if strings.Contains(s, canary) || strings.Contains(s, fmt.Sprintf("%x", canary)) {
			t.Errorf("value leaked: %s", s)
		}
	}
	if string(p.Bytes()) != canary || string(p) != canary {
		t.Error("Bytes()/conversion must return the value")
	}
	p.Wipe()
	if !bytes.Equal(p, make([]byte, len(canary))) {
		t.Error("Wipe did not zero the value")
	}
}
