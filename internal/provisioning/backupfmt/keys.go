package backupfmt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

// Key sizes.
const (
	DataKeyBytes   = 32 // a backup's data key: an X25519 private key
	BackupKeyBytes = 32 // a tenant's backup key (SecretStore): an AES-256 key
	// WrappedDataKeyBytes is nonce (12) + ciphertext (32) + tag (16).
	WrappedDataKeyBytes = 12 + DataKeyBytes + 16
	// BackupKeySecretName is the SecretStore name of a tenant's backup key (mgsec://<tenant>/backup-key#<v>).
	BackupKeySecretName = "backup-key"
)

// ErrKey is any malformed key or recipient (the message never contains key material).
var ErrKey = errors.New("backupfmt: invalid key")

// NewDataKey returns a fresh random data key.
func NewDataKey() ([]byte, error) {
	k := make([]byte, DataKeyBytes)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	return k, nil
}

// DataRecipient is the X25519 public key of a data key — what the agent encrypts a backup to (BackupRequest
// data_recipient): the data key itself never reaches the agent for a backup.
func DataRecipient(dataKey []byte) ([]byte, error) {
	if len(dataKey) != DataKeyBytes {
		return nil, ErrKey
	}
	k, err := ecdh.X25519().NewPrivateKey(dataKey)
	if err != nil {
		return nil, ErrKey
	}
	return k.PublicKey().Bytes(), nil
}

// RecipientString is the age encoding of an X25519 public key: age1… (bech32, lower case).
func RecipientString(pub []byte) (string, error) {
	if len(pub) != 32 {
		return "", ErrKey
	}
	return bech32Encode("age", pub)
}

// AgeIdentity is the age encoding of a data key: AGE-SECRET-KEY-1… (bech32, upper case). The result is a secret.
func AgeIdentity(dataKey []byte) (string, error) {
	if len(dataKey) != DataKeyBytes {
		return "", ErrKey
	}
	s, err := bech32Encode("age-secret-key-", dataKey)
	if err != nil {
		return "", ErrKey
	}
	return strings.ToUpper(s), nil
}

// ParseRecipient checks an age X25519 recipient (age1 + 58 bech32 characters, valid checksum) and returns its public
// key. Anything else — a post-quantum or plugin recipient, an identity, a private key — is refused.
func ParseRecipient(s string) ([]byte, error) {
	if len(s) != 62 || !strings.HasPrefix(s, "age1") {
		return nil, ErrKey
	}
	hrp, data, err := bech32Decode(s)
	if err != nil || hrp != "age" || len(data) != 32 || strings.ToLower(s) != s {
		return nil, ErrKey
	}
	return data, nil
}

// ---------------------------------------------------------------------------------------------------- data key wrap

func wrapAAD(tenant, instance uuid.UUID, seq uint64) []byte {
	return []byte("meshguard.instance-backup.data-key.v1|" + tenant.String() + "|" + instance.String() + "|" + strconv.FormatUint(seq, 10))
}

// WrapDataKey wraps a data key with a tenant's backup key (online path, §17.1): AES-256-GCM, random nonce, the
// additional data binds tenant, instance and sequence. The result (nonce||ciphertext||tag) is stored with the backup
// (backups.wrapped_data_key) and is not secret.
func WrapDataKey(backupKey, dataKey []byte, tenant, instance uuid.UUID, seq uint64) ([]byte, error) {
	if len(backupKey) != BackupKeyBytes || len(dataKey) != DataKeyBytes || seq == 0 {
		return nil, ErrKey
	}
	aead, err := gcm(backupKey)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize(), WrappedDataKeyBytes)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, dataKey, wrapAAD(tenant, instance, seq)), nil //nolint:gosec // G407: the nonce is read from crypto/rand just above
}

// ErrUnwrap is a wrapped data key that does not open with this backup key for this tenant, instance and sequence.
var ErrUnwrap = errors.New("backupfmt: the wrapped data key does not open with this backup key for this tenant, instance and sequence")

// UnwrapDataKey reverses WrapDataKey. The result is a secret: clear it after use.
func UnwrapDataKey(backupKey, wrapped []byte, tenant, instance uuid.UUID, seq uint64) ([]byte, error) {
	if len(backupKey) != BackupKeyBytes || len(wrapped) != WrappedDataKeyBytes {
		return nil, ErrUnwrap
	}
	aead, err := gcm(backupKey)
	if err != nil {
		return nil, err
	}
	n := aead.NonceSize()
	k, err := aead.Open(nil, wrapped[:n], wrapped[n:], wrapAAD(tenant, instance, seq))
	if err != nil {
		return nil, ErrUnwrap
	}
	return k, nil
}

func gcm(key []byte) (cipher.AEAD, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrKey
	}
	return cipher.NewGCM(b)
}

// ---------------------------------------------------------------------------------------------------- manifest keys

// ParseSigningKey reads the manifest signing key of the key ceremony: an Ed25519 private key, PKCS#8, PEM (openssl
// genpkey) or DER. The error never contains key material.
func ParseSigningKey(raw []byte) (ed25519.PrivateKey, error) {
	der := raw
	if b, _ := pem.Decode(raw); b != nil {
		if b.Type != "PRIVATE KEY" {
			return nil, fmt.Errorf("%w: want a PKCS#8 PRIVATE KEY block", ErrKey)
		}
		der = b.Bytes
	}
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("%w: not a PKCS#8 private key", ErrKey)
	}
	ek, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%w: not an Ed25519 key", ErrKey)
	}
	return ek, nil
}

// ParsePublicKeys reads MG_BACKUP_MANIFEST_PUBKEY: one or more (comma-separated — the previous key stays listed while
// a rotation is in progress) Ed25519 public keys, SubjectPublicKeyInfo DER in standard base64.
func ParsePublicKeys(s string) ([]ed25519.PublicKey, error) {
	var out []ed25519.PublicKey
	for _, f := range strings.Split(s, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		der, err := base64.StdEncoding.Strict().DecodeString(f)
		if err != nil {
			return nil, fmt.Errorf("%w: not base64", ErrKey)
		}
		k, err := x509.ParsePKIXPublicKey(der)
		if err != nil {
			return nil, fmt.Errorf("%w: not a SubjectPublicKeyInfo", ErrKey)
		}
		ek, ok := k.(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("%w: not an Ed25519 public key", ErrKey)
		}
		out = append(out, ek)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: no public key", ErrKey)
	}
	return out, nil
}

// PublicKeySPKI encodes a public key as MG_BACKUP_MANIFEST_PUBKEY does.
func PublicKeySPKI(k ed25519.PublicKey) string {
	der, err := x509.MarshalPKIXPublicKey(k)
	if err != nil {
		panic(err) // an ed25519.PublicKey always marshals
	}
	return base64.StdEncoding.EncodeToString(der)
}

// KeyID is the identifier of a manifest key recorded in the manifest: hex sha256 of its SubjectPublicKeyInfo.
func KeyID(k ed25519.PublicKey) string {
	der, err := x509.MarshalPKIXPublicKey(k)
	if err != nil {
		panic(err)
	}
	s := sha256.Sum256(der)
	return hex.EncodeToString(s[:])
}

// ParseAgeIdentity reverses AgeIdentity (an AGE-SECRET-KEY-1… X25519 identity). The result is a secret.
func ParseAgeIdentity(s string) ([]byte, error) {
	if !strings.HasPrefix(s, "AGE-SECRET-KEY-1") {
		return nil, ErrKey
	}
	hrp, data, err := bech32Decode(s)
	if err != nil || hrp != "age-secret-key-" || len(data) != DataKeyBytes {
		return nil, ErrKey
	}
	return data, nil
}
