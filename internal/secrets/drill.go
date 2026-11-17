package secrets

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"

	"github.com/google/uuid"
)

// Key ceremony support (P2-T04a, docs/operations/key-ceremony.md): the key check value of a KEK and the drill that
// proves a keyring rebuilt from the offline copies is equivalent to the live one.

// KCVLabel is the message of the key check value (KCV) of a KEK. The KCV is a short, non-secret fingerprint written
// next to every offline copy of a KEK and recorded in the repository, so that a copy re-entered from paper (or a
// keyring rebuilt after losing the host) can be checked before it is used:
//
//	KCV = hex(HMAC-SHA256(key = the 32-byte KEK, message = "meshguard/kek-kcv/v1")[:4])   — 8 lowercase hex characters
//
// The ceremony scripts (infrastructure/host/key-ceremony) compute the same value. It is deliberately not the classic
// AES KCV (the first bytes of AES_K(0^128)): for AES-GCM that block is the GHASH key H, so publishing part of it
// would publish part of a subkey. 32 bits make an undetected typo a 1 in 4·10^9 event and reveal nothing usable
// about a 256-bit random key.
const KCVLabel = "meshguard/kek-kcv/v1"

const kcvBytes = 4

// kcv returns the key check value of a raw KEK.
func kcv(key []byte) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(KCVLabel))
	return hex.EncodeToString(m.Sum(nil)[:kcvBytes])
}

// DrillKEK is the drill result for one kek_id.
type DrillKEK struct {
	ID           string
	LiveKCV      string // "" when the live keyring has no KEK with this kek_id
	RecoveredKCV string // "" when the recovered keyring has no KEK with this kek_id
	// LiveToRecovered: a fresh DEK wrapped under the live KEK unwraps with the recovered KEK, and a test secret sealed
	// under that DEK decrypts with the unwrapped copy. RecoveredToLive: the same the other way round.
	LiveToRecovered bool
	RecoveredToLive bool
}

// DrillReport is the result of Drill for one keyring: kek_ids, key check values and verdicts — never key material.
type DrillReport struct {
	Keyring         string // KEKApp or KEKOps
	LiveActive      string
	RecoveredActive string
	KEKs            []DrillKEK // every kek_id of either keyring, sorted
	Problems        []string   // why the drill failed (kek_ids and KCVs only); empty = PASS
}

// OK reports whether the drill passed.
func (r *DrillReport) OK() bool { return len(r.Problems) == 0 }

// Drill is the key ceremony drill (P2-T04a): it proves that the keyring in recoveredDir — rebuilt from the offline
// copies — is equivalent to the live keyring in liveDir. Both are read with LoadKeyring, so the rules of a process
// start apply (absolute directory, file names, exactly 64 hexadecimal characters, no access for "other"); a keyring
// that cannot be loaded is an error that names files, never their content. The keyrings are equivalent when they
// hold the same kek_ids with the same key check values, ACTIVE names the same kek_id, and for every kek_id the real
// wrap/unwrap of the SecretStore works in both directions: a random DEK wrapped by one keyring under the AAD format
// of tenant_keys (mgdek/v1, owner of the keyring's scope) unwraps with the other, and a random test secret sealed under
// that DEK with the AAD format of secrets (mgsec/v1) decrypts with the unwrapped copy. Nothing touches a database or
// the disk; the DEKs and test secrets live only in memory and are cleared.
func Drill(name, liveDir, recoveredDir string) (*DrillReport, error) {
	live, err := LoadKeyring(name, liveDir)
	if err != nil {
		return nil, fmt.Errorf("live keyring: %w", err)
	}
	rec, err := LoadKeyring(name, recoveredDir)
	if err != nil {
		return nil, fmt.Errorf("recovered keyring: %w", err)
	}
	return drill(live, rec)
}

func drill(live, rec *Keyring) (*DrillReport, error) {
	owner, err := drillOwner(live.name)
	if err != nil {
		return nil, err
	}
	r := &DrillReport{Keyring: live.name, LiveActive: live.active, RecoveredActive: rec.active}
	problem := func(format string, a ...any) { r.Problems = append(r.Problems, fmt.Sprintf(format, a...)) }
	if live.active != rec.active {
		problem("ACTIVE differs: live %q, recovered %q", live.active, rec.active)
	}
	ids := append(live.IDs(), rec.IDs()...)
	slices.Sort(ids)
	for _, id := range slices.Compact(ids) {
		k := DrillKEK{ID: id, LiveKCV: live.KCV(id), RecoveredKCV: rec.KCV(id)}
		switch {
		case k.RecoveredKCV == "":
			problem("kek_id %q is missing from the recovered keyring", id)
		case k.LiveKCV == "":
			problem("kek_id %q is only in the recovered keyring", id)
		default:
			if k.LiveKCV != k.RecoveredKCV {
				problem("kek_id %q: KCV differs (live %s, recovered %s)", id, k.LiveKCV, k.RecoveredKCV)
			}
			if k.LiveToRecovered, err = roundTrip(live, rec, id, owner); err != nil {
				return nil, err
			}
			if k.RecoveredToLive, err = roundTrip(rec, live, id, owner); err != nil {
				return nil, err
			}
			if !k.LiveToRecovered {
				problem("kek_id %q: a DEK wrapped by the live keyring does not unwrap with the recovered one", id)
			}
			if !k.RecoveredToLive {
				problem("kek_id %q: a DEK wrapped by the recovered keyring does not unwrap with the live one", id)
			}
		}
		r.KEKs = append(r.KEKs, k)
	}
	return r, nil
}

// drillOwner is the DEK series the drill wraps its test DEKs for: a random tenant for kek-app (tenant DEKs are what
// kek-app mostly wraps), platform_ops for kek-ops.
func drillOwner(keyring string) (Owner, error) {
	if keyring == KEKOps {
		return PlatformOpsOwner, nil
	}
	t, err := uuid.NewRandom()
	if err != nil {
		return Owner{}, err
	}
	return TenantOwner(t), nil
}

// roundTrip wraps a fresh DEK with KEK id of from and unwraps it with to (AAD of tenant_keys), then seals a fresh test
// secret under the original DEK and opens it with the unwrapped copy (AAD of secrets). It reports whether both
// worked; an error means the system could not provide randomness.
func roundTrip(from, to *Keyring, id string, owner Owner) (bool, error) {
	dek, err := newDEK()
	if err != nil {
		return false, err
	}
	defer clear(dek)
	value, err := newDEK() // the test secret: 32 random bytes
	if err != nil {
		return false, err
	}
	defer clear(value)
	wrapAD := wrapAAD(string(owner.Scope), owner.tenantPtr(), 1)
	nonce, wrapped, err := from.wrapWith(id, dek, wrapAD)
	if err != nil {
		return false, err
	}
	got, err := to.unwrap(id, nonce, wrapped, wrapAD)
	if err != nil {
		return false, nil
	}
	defer clear(got)
	ref := PlatformRef("kek-drill", 1)
	if owner.Scope == ScopeTenant {
		ref = TenantRef(owner.Tenant, "kek-drill", 1)
	}
	sealer, err := newAEAD(dek)
	if err != nil {
		return false, err
	}
	opener, err := newAEAD(got)
	if err != nil {
		return false, nil
	}
	sn, ct, err := seal(sealer, value, secretAAD(ref))
	if err != nil {
		return false, err
	}
	pt, err := open(opener, sn, ct, secretAAD(ref))
	if err != nil {
		return false, nil
	}
	defer clear(pt)
	return hmac.Equal(pt, value), nil
}
