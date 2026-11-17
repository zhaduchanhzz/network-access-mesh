package identity

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
)

// secretLen is the size in bytes of every random secret of the module: session id, state, nonce, PKCE verifier and
// browser-binding cookie (256 bits, §8.3 step 4).
const secretLen = 32

// csrfMessage is the HMAC message of the CSRF token (§8.3 step 8).
const csrfMessage = "csrf-v1"

// pkceKeyInfo is the HKDF info string of the key that encrypts the PKCE verifier of an auth request.
const pkceKeyInfo = "meshguard identity auth_request pkce v1"

// hintKeyInfo is the HKDF info string of the key that encrypts the ID token kept as the logout id_token_hint of a
// session (sessions.id_token_hint_enc, migration 0008 — G2 round 2, A-1).
const hintKeyInfo = "meshguard identity session id_token_hint v1"

// maxHintToken bounds the ID token kept as a logout hint (the CHECK of 0008 allows 16 KiB plus nonce and tag); a larger
// token is not kept and the logout sends client_id only.
const maxHintToken = 16384

var b64 = base64.RawURLEncoding

// newSecret returns secretLen random bytes. crypto/rand.Read never fails (Go ≥ 1.24 aborts the process instead).
func newSecret() []byte {
	b := make([]byte, secretLen)
	_, _ = rand.Read(b)
	return b
}

// encodeSecret encodes a secret for a cookie, a URL parameter or a header: unpadded base64url, 43 characters.
func encodeSecret(b []byte) string { return b64.EncodeToString(b) }

// decodeSecret strictly decodes an encoded secret; anything that is not exactly secretLen bytes is rejected.
func decodeSecret(s string) ([]byte, bool) {
	if len(s) != b64.EncodedLen(secretLen) {
		return nil, false
	}
	b, err := b64.Strict().DecodeString(s)
	if err != nil || len(b) != secretLen {
		return nil, false
	}
	return b, true
}

// hashSecret is the lookup key stored in the database instead of a secret (sessions.id_hash, auth_requests.state_hash,
// auth_requests.browser_binding_hash).
func hashSecret(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}

// csrfToken derives the CSRF token of a session: HMAC-SHA256(key = raw session id, msg = "csrf-v1"), base64url.
func csrfToken(rawSessionID []byte) string {
	mac := hmac.New(sha256.New, rawSessionID)
	_, _ = mac.Write([]byte(csrfMessage)) // hash.Hash.Write never fails
	return b64.EncodeToString(mac.Sum(nil))
}

// validCSRF compares a presented X-CSRF-Token with the token of the session in constant time.
func validCSRF(rawSessionID []byte, presented string) bool {
	want := csrfToken(rawSessionID)
	return len(presented) == len(want) && subtle.ConstantTimeCompare([]byte(presented), []byte(want)) == 1
}

// equalHash compares two hashes in constant time.
func equalHash(a, b []byte) bool {
	return len(a) == len(b) && subtle.ConstantTimeCompare(a, b) == 1
}

// pkceKey derives the AES-256 key that protects the PKCE verifier of one auth request from the state and the
// browser-binding cookie. Neither is stored (the database keeps only their SHA-256), so a copy of auth_requests alone
// does not reveal the verifier, and the authorization response (code + state in a URL) is not enough either.
func pkceKey(state, binding []byte) ([]byte, error) {
	ikm := make([]byte, 0, len(state)+len(binding))
	ikm = append(ikm, state...)
	ikm = append(ikm, binding...)
	return hkdf.Key(sha256.New, ikm, nil, pkceKeyInfo, 32)
}

// sealVerifier encrypts the PKCE verifier with AES-256-GCM; aad binds the ciphertext to its auth request.
func sealVerifier(state, binding, aad []byte, verifier string) ([]byte, error) {
	gcm, err := pkceAEAD(state, binding)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	_, _ = rand.Read(nonce)
	return gcm.Seal(nonce, nonce, []byte(verifier), aad), nil
}

// openVerifier decrypts a sealed PKCE verifier.
func openVerifier(state, binding, aad, sealed []byte) (string, error) {
	gcm, err := pkceAEAD(state, binding)
	if err != nil {
		return "", err
	}
	if len(sealed) < gcm.NonceSize()+gcm.Overhead() {
		return "", errors.New("sealed verifier too short")
	}
	plain, err := gcm.Open(nil, sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():], aad)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

func pkceAEAD(state, binding []byte) (cipher.AEAD, error) {
	key, err := pkceKey(state, binding)
	if err != nil {
		return nil, err
	}
	return aesGCM(key)
}

func aesGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// hintAEAD is the AES-256-GCM of the logout hint of one session, keyed by HKDF-SHA256 of the raw session id. The raw id
// lives only in the browser's cookie — the database keeps its SHA-256 (sessions.id_hash) — so neither a copy of the
// sessions table nor a backup opens the hint: only a request carrying that session's cookie does, at logout.
func hintAEAD(rawSessionID []byte) (cipher.AEAD, error) {
	key, err := hkdf.Key(sha256.New, rawSessionID, nil, hintKeyInfo, 32)
	if err != nil {
		return nil, err
	}
	return aesGCM(key)
}

// hintAAD binds a sealed hint to its session row and IdP: a ciphertext moved to another row or IdP does not open.
func hintAAD(idHash []byte, idpID [16]byte) []byte {
	aad := make([]byte, 0, len(idHash)+len(idpID))
	aad = append(aad, idHash...)
	return append(aad, idpID[:]...)
}

// sealHint encrypts the raw ID token of a login for the logout of the session created with it.
func sealHint(rawSessionID, aad []byte, idToken string) ([]byte, error) {
	if idToken == "" || len(idToken) > maxHintToken {
		return nil, errors.New("id token empty or too large to keep as a logout hint")
	}
	gcm, err := hintAEAD(rawSessionID)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	_, _ = rand.Read(nonce)
	return gcm.Seal(nonce, nonce, []byte(idToken), aad), nil
}

// openHint decrypts a sealed logout hint; the error never carries any part of it.
func openHint(rawSessionID, aad, sealed []byte) (string, error) {
	gcm, err := hintAEAD(rawSessionID)
	if err != nil {
		return "", err
	}
	if len(sealed) < gcm.NonceSize()+gcm.Overhead()+1 {
		return "", errors.New("sealed hint too short")
	}
	plain, err := gcm.Open(nil, sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():], aad)
	if err != nil {
		return "", errors.New("sealed hint does not open with this session")
	}
	return string(plain), nil
}
