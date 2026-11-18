package config

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"strings"
	"time"
)

// Backup configures the per-tenant backups of the worker (P3-T11, §17.1): the manifest keys it verifies every archive
// with (MG_BACKUP_MANIFEST_PUBKEY — the public key of the key ceremony, P2-T04a; the previous key stays listed during
// a rotation), the schedule period of instance.backup (MG_BACKUP_INTERVAL, MVP 1 h — §17.3 RPO; 15 min when hardened)
// and how long a backup is kept (MG_BACKUP_RETENTION). No key ⇒ the worker neither schedules nor runs backups and
// refuses restores (a manifest it cannot verify is never trusted).
type Backup struct {
	ManifestKeys []ed25519.PublicKey
	Interval     time.Duration
	Retention    time.Duration
}

// Enabled reports whether the worker runs backups.
func (b Backup) Enabled() bool { return len(b.ManifestKeys) > 0 }

// LoadBackup reads MG_BACKUP_* (worker only; another service ignores them — the recovery recipient of the same
// environment file is the backup services', P2-T03a). Errors name variables, never values.
func LoadBackup(service string, getenv func(string) string) (Backup, []error) {
	var b Backup
	if service != "worker" {
		return b, nil
	}
	var errs []error
	for _, f := range strings.Split(strings.TrimSpace(getenv("MG_BACKUP_MANIFEST_PUBKEY")), ",") {
		if f = strings.TrimSpace(f); f == "" {
			continue
		}
		k, err := parseEd25519SPKI(f)
		if err != nil {
			errs = append(errs, errors.New("MG_BACKUP_MANIFEST_PUBKEY: Ed25519 public keys (SubjectPublicKeyInfo, base64), comma-separated"))
			break
		}
		b.ManifestKeys = append(b.ManifestKeys, k)
	}
	var err error
	if b.Interval, err = time.ParseDuration(withDefault(strings.TrimSpace(getenv("MG_BACKUP_INTERVAL")), "1h")); err != nil ||
		b.Interval < 15*time.Minute || b.Interval > 24*time.Hour {
		errs = append(errs, errors.New("MG_BACKUP_INTERVAL: a duration in [15m, 24h]"))
	}
	if b.Retention, err = time.ParseDuration(withDefault(strings.TrimSpace(getenv("MG_BACKUP_RETENTION")), "168h")); err != nil ||
		b.Retention < 24*time.Hour || b.Retention > 400*24*time.Hour {
		errs = append(errs, errors.New("MG_BACKUP_RETENTION: a duration in [24h, 9600h]"))
	}
	return b, errs
}

func parseEd25519SPKI(s string) (ed25519.PublicKey, error) {
	der, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil {
		return nil, err
	}
	k, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, err
	}
	ek, ok := k.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("not Ed25519")
	}
	return ek, nil
}
