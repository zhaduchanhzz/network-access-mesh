package idp

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"

	"github.com/zhaduchanhzz/network-access-mesh/internal/secrets"
)

// maxVersionProbe bounds the search for the latest version of a secret in StoreNewVersion.
const maxVersionProbe = 256

// NewSecretValue returns a fresh client secret: 32 random bytes, base64url without padding (43 characters).
func NewSecretValue() (secrets.Plaintext, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	out := make([]byte, base64.RawURLEncoding.EncodedLen(len(b)))
	base64.RawURLEncoding.Encode(out, b)
	clear(b)
	return secrets.Plaintext(out), nil
}

// StoreNewVersion writes value as the newest version of the secret named by base (base.Version is ignored): version 1
// when the secret does not exist yet, otherwise one more than the latest version. The SecretStore is written BEFORE
// the IdP, so a credential valid at the IdP is never missing from the store.
func StoreNewVersion(ctx context.Context, st secrets.SecretStore, base secrets.Ref, value []byte,
	opts ...secrets.Option,
) (secrets.Ref, error) {
	first := base
	first.Version = 1
	err := st.Put(ctx, first, value, opts...)
	if err == nil {
		return first, nil
	}
	if !errors.Is(err, secrets.ErrExists) {
		return secrets.Ref{}, err
	}
	for v := int32(1); v <= maxVersionProbe; v++ {
		r := base
		r.Version = v
		next, err := st.Rotate(ctx, r, value, opts...)
		switch {
		case err == nil:
			return next, nil
		case errors.Is(err, secrets.ErrConflict): // not the latest version: try the next one
		default:
			return secrets.Ref{}, err
		}
	}
	return secrets.Ref{}, errors.New("idp: no latest version found for the secret")
}

// DestroyOlder destroys every version of ref's secret before ref.Version (only the latest version is valid at the
// IdP). Missing versions are skipped; Destroy is idempotent.
func DestroyOlder(ctx context.Context, st secrets.SecretStore, ref secrets.Ref) error {
	for v := int32(1); v < ref.Version; v++ {
		r := ref
		r.Version = v
		if err := st.Destroy(ctx, r); err != nil && !errors.Is(err, secrets.ErrNotFound) {
			return err
		}
	}
	return nil
}

// ReadSecret reads one secret version for a driver; any failure is CodeCredentials (the cause names the reference,
// never the value).
func ReadSecret(ctx context.Context, st secrets.SecretStore, op string, ref secrets.Ref) (secrets.Plaintext, error) {
	if st == nil {
		return nil, NewError(CodeCredentials, op, "no_secret_store", nil)
	}
	p, err := st.Get(ctx, ref)
	if err != nil {
		return nil, NewError(CodeCredentials, op, "secret_unreadable", err)
	}
	return p, nil
}
