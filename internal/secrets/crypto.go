package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strconv"

	"github.com/google/uuid"
)

const (
	keySize   = 32 // AES-256 for KEKs and DEKs
	nonceSize = 12 // standard GCM nonce, random per encryption

	// MaxValueSize bounds one secret value (API keys, client secrets, passwords are far smaller).
	MaxValueSize = 64 << 10

	// AAD formats. The version prefix lets a later format coexist with rows written under this one.
	secretAADPrefix = "mgsec/v1"
	wrapAADPrefix   = "mgdek/v1"

	redacted = "[REDACTED]"
)

// errAuth is what every failed GCM open becomes: wrong key, wrong AAD, or modified nonce/ciphertext/tag. The cause
// is deliberately not distinguished (and the cipher's own error is not wrapped).
var errAuth = fmt.Errorf("%w: authentication failed", ErrIntegrity)

// secretAAD binds a ciphertext to its reference: "mgsec/v1|<tenant_id|platform>|<name>|<version>" — the
// tenant_id|name|version of §7.6. A ciphertext moved to another tenant, name or version (older value replayed into a
// newer version) no longer authenticates. The name cannot contain "|" (column CHECK), so the encoding is unambiguous.
func secretAAD(r Ref) []byte {
	return []byte(secretAADPrefix + "|" + r.ownerSegment() + "|" + r.Name + "|" + strconv.FormatInt(int64(r.Version), 10))
}

// wrapAAD binds a wrapped DEK to the identity of its row: "mgdek/v1|<scope>|<tenant_id or empty>|<version>" — the
// scope|tenant_id|version of §7.6 (also the UNIQUE NULLS NOT DISTINCT key of tenant_keys). A wrapped DEK copied or
// swapped into the row of another tenant, scope or version no longer unwraps.
func wrapAAD(scope string, tenant *uuid.UUID, version int32) []byte {
	t := ""
	if tenant != nil {
		t = tenant.String()
	}
	return []byte(wrapAADPrefix + "|" + scope + "|" + t + "|" + strconv.FormatInt(int64(version), 10))
}

// newAEAD returns AES-256-GCM for a 32-byte key. The caller clears key afterwards; the cipher keeps its own schedule.
func newAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != keySize {
		return nil, errors.New("key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// seal encrypts plaintext with a fresh random nonce.
func seal(aead cipher.AEAD, plaintext, aad []byte) (nonce, ciphertext []byte, err error) {
	nonce = make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	return nonce, aead.Seal(nil, nonce, plaintext, aad), nil
}

// open decrypts and authenticates; any failure is errAuth.
func open(aead cipher.AEAD, nonce, ciphertext, aad []byte) ([]byte, error) {
	if len(nonce) != aead.NonceSize() || len(ciphertext) < aead.Overhead() {
		return nil, errAuth
	}
	pt, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, errAuth
	}
	return pt, nil
}

// newDEK returns 32 random bytes.
func newDEK() ([]byte, error) {
	k := make([]byte, keySize)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	return k, nil
}

// Plaintext is a decrypted secret value. Printing or logging it — fmt verbs, slog, encoding/json — yields
// "[REDACTED]"; the value itself is read with Bytes or a conversion (string(p), []byte(p)). Wipe zeroes it once the
// caller is done (best effort: Go may have copied it).
type Plaintext []byte

// Bytes returns the value.
func (p Plaintext) Bytes() []byte { return p }

// Wipe overwrites the value with zeros.
func (p Plaintext) Wipe() { clear(p) }

// String implements fmt.Stringer without revealing the value.
func (Plaintext) String() string { return redacted }

// GoString implements fmt.GoStringer without revealing the value.
func (Plaintext) GoString() string { return redacted }

// Format implements fmt.Formatter: every verb (%s, %v, %x, %q, %d…) prints [REDACTED].
func (Plaintext) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, redacted) }

// LogValue implements slog.LogValuer.
func (Plaintext) LogValue() slog.Value { return slog.StringValue(redacted) }

// MarshalJSON keeps the value out of JSON (a response that must show a secret once converts it explicitly).
func (Plaintext) MarshalJSON() ([]byte, error) { return []byte(`"` + redacted + `"`), nil }
