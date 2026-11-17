package secrets

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// Key management. EnsureDEK may run in the api; RotateDEK, Rewrap and DestroyTenantKeys update tenant_keys, which only
// the worker roles may do (0003) — in the api they fail with SQLSTATE 42501.

// rewrapBatch is the number of DEKs rewrapped per transaction.
const rewrapBatch = 100

// activeDEK returns owner's active DEK, creating the next version when there is none — unless the latest DEK was
// destroyed: an owner whose keys were shredded stays shredded (ErrKeyDestroyed). Two transactions creating the first
// DEK of an owner at once: the loser's INSERT … ON CONFLICT DO NOTHING returns nothing and it reads the winner's row.
func (s *Store) activeDEK(ctx context.Context, q *sqlcdb.Queries, owner Owner) (k sqlcdb.TenantKey, created bool, err error) {
	scope, tenant := string(owner.Scope), owner.tenantPtr()
	k, err = q.GetActiveDEK(ctx, sqlcdb.GetActiveDEKParams{Scope: scope, TenantID: tenant})
	if !errors.Is(err, store.ErrNoRows) {
		return k, false, err
	}
	next := int32(1)
	latest, err := q.GetLatestDEK(ctx, sqlcdb.GetLatestDEKParams{Scope: scope, TenantID: tenant})
	switch {
	case err == nil && latest.State == stateDestroyed:
		return k, false, ErrKeyDestroyed
	case err == nil:
		next = latest.Version + 1
	case !errors.Is(err, store.ErrNoRows):
		return k, false, err
	}
	k, err = s.createDEK(ctx, q, owner, next)
	if errors.Is(err, store.ErrNoRows) {
		k, err = q.GetActiveDEK(ctx, sqlcdb.GetActiveDEKParams{Scope: scope, TenantID: tenant})
		return k, false, err
	}
	return k, err == nil, err
}

// createDEK generates a DEK, wraps it with the active KEK of the owner's keyring and inserts it as version v.
func (s *Store) createDEK(ctx context.Context, q *sqlcdb.Queries, owner Owner, v int32) (sqlcdb.TenantKey, error) {
	kr, err := s.keyring(owner.Scope)
	if err != nil {
		return sqlcdb.TenantKey{}, err
	}
	dek, err := newDEK()
	if err != nil {
		return sqlcdb.TenantKey{}, err
	}
	defer clear(dek)
	kekID, nonce, wrapped, err := kr.wrap(dek, wrapAAD(string(owner.Scope), owner.tenantPtr(), v))
	if err != nil {
		return sqlcdb.TenantKey{}, err
	}
	return q.InsertDEK(ctx, sqlcdb.InsertDEKParams{
		Scope: string(owner.Scope), TenantID: owner.tenantPtr(), Version: v, WrappedDek: wrapped, WrapNonce: nonce,
		KekID: kekID,
	})
}

// EnsureDEK makes sure owner has an active DEK that this process can unwrap and returns its version — step
// secrets.generate of tenant.provision (§11.3).
func (s *Store) EnsureDEK(ctx context.Context, owner Owner) (int32, error) {
	if err := owner.validate(); err != nil {
		return 0, fmt.Errorf("secrets: ensure DEK: %w", err)
	}
	var (
		k       sqlcdb.TenantKey
		created bool
	)
	err := s.tx(ctx, owner.Tenant, func(q *sqlcdb.Queries) error {
		var err error
		if k, created, err = s.activeDEK(ctx, q, owner); err != nil {
			return err
		}
		_, err = s.dekAEAD(k, owner)
		return err
	})
	if err != nil {
		return 0, fmt.Errorf("secrets: ensure DEK of %s: %w", owner, err)
	}
	if created {
		s.logCreated(&k)
	}
	return k.Version, nil
}

// RotateDEK retires owner's active DEK and makes version+1 active (worker). Secret versions written before stay under
// the retired DEK and remain readable; new versions use the new DEK. An owner without a DEK gets version 1.
func (s *Store) RotateDEK(ctx context.Context, owner Owner) (int32, error) {
	if err := owner.validate(); err != nil {
		return 0, fmt.Errorf("secrets: rotate DEK: %w", err)
	}
	var (
		k       sqlcdb.TenantKey
		created bool
	)
	err := s.tx(ctx, owner.Tenant, func(q *sqlcdb.Queries) error {
		scope, tenant := string(owner.Scope), owner.tenantPtr()
		cur, err := q.LockActiveDEK(ctx, sqlcdb.LockActiveDEKParams{Scope: scope, TenantID: tenant})
		if errors.Is(err, store.ErrNoRows) {
			k, created, err = s.activeDEK(ctx, q, owner)
			return err
		}
		if err != nil {
			return err
		}
		latest, err := q.GetLatestDEK(ctx, sqlcdb.GetLatestDEKParams{Scope: scope, TenantID: tenant})
		if err != nil {
			return err
		}
		if n, err := q.RetireDEK(ctx, cur.ID); err != nil || n != 1 {
			return errors.Join(errors.New("retire the active DEK"), err)
		}
		k, err = s.createDEK(ctx, q, owner, latest.Version+1)
		if errors.Is(err, store.ErrNoRows) {
			return ErrConflict
		}
		created = err == nil
		return err
	})
	if err != nil {
		return 0, fmt.Errorf("secrets: rotate DEK of %s: %w", owner, err)
	}
	if created {
		s.logCreated(&k)
	}
	s.log.Info("secrets: DEK rotated", "owner", owner.String(), "dek_version", k.Version)
	return k.Version, nil
}

// ShredReport counts what DestroyTenantKeys erased.
type ShredReport struct {
	DEKs    int64 // DEK versions whose key material was erased
	Secrets int64 // secret versions whose ciphertext was erased
}

// DestroyTenantKeys is the crypto-shredding step of tenant deletion (§6.1, §11.4 — worker, after the grace period):
// it erases the key material of every DEK of the tenant and the ciphertext of every secret version. Afterwards no
// secret of the tenant can be decrypted, and the tenant can get no new DEK. Limits (§6.1): wrapped DEKs and
// ciphertexts remain in PostgreSQL dumps/WAL until their retention ends; this erases the live copies only.
func (s *Store) DestroyTenantKeys(ctx context.Context, tenant uuid.UUID) (ShredReport, error) {
	if tenant == uuid.Nil {
		return ShredReport{}, fmt.Errorf("secrets: destroy tenant keys: %w: tenant ID required", ErrInvalid)
	}
	var r ShredReport
	err := s.db.WithTenantTx(ctx, tenant, func(q *sqlcdb.Queries) error {
		id := tenant
		var err error
		if r.DEKs, err = q.DestroyTenantDEKs(ctx, &id); err != nil {
			return err
		}
		r.Secrets, err = q.DestroyTenantSecrets(ctx, &id)
		return err
	})
	if err != nil {
		return ShredReport{}, fmt.Errorf("secrets: destroy keys of tenant %s: %w", tenant, err)
	}
	s.log.Warn("secrets: tenant keys destroyed (crypto-shredding)", "tenant_id", tenant.String(),
		"deks", r.DEKs, "secret_versions", r.Secrets)
	return r, nil
}

// RewrapReport is the outcome of Rewrap for one keyring.
type RewrapReport struct {
	Keyring   string
	ActiveKEK string
	Rewrapped int
}

// Rewrap completes a KEK rotation (§7.6; worker): every DEK — active or retired — of the keyring's scopes that is
// wrapped by another KEK is unwrapped and wrapped again by the active KEK. It covers kek-app (tenant and platform
// DEKs) and, when loaded, kek-ops (platform_ops). Idempotent. Procedure (runbook: P2-T04a/P6-T05): (1) add the new
// KEK file to the keyring and point ACTIVE at it, keeping the old file; (2) restart api and worker so every process
// wraps new DEKs with the new KEK (keyrings are read at start-up); (3) run Rewrap; (4) once KEKUsage no longer lists
// the old kek_id, remove its file (keep the offline copies per P2-T04a) and restart.
func (s *Store) Rewrap(ctx context.Context) ([]RewrapReport, error) {
	var out []RewrapReport
	for _, kr := range []*Keyring{s.app, s.ops} {
		if kr == nil {
			continue
		}
		r := RewrapReport{Keyring: kr.Name(), ActiveKEK: kr.Active()}
		for {
			n := 0
			err := s.db.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
				rows, err := q.ListDEKsToRewrap(ctx, sqlcdb.ListDEKsToRewrapParams{
					Scopes: scopesOf(kr), ActiveKekID: kr.Active(), RowLimit: rewrapBatch,
				})
				if err != nil {
					return err
				}
				for _, k := range rows {
					if err := s.rewrapOne(ctx, q, kr, k); err != nil {
						return err
					}
					n++
				}
				return nil
			})
			if err != nil {
				return out, fmt.Errorf("secrets: rewrap %s: %w", kr.Name(), err)
			}
			r.Rewrapped += n
			if n < rewrapBatch {
				break
			}
		}
		out = append(out, r)
		s.log.Info("secrets: DEKs rewrapped", "keyring", r.Keyring, "kek_id", r.ActiveKEK, "deks", r.Rewrapped)
	}
	return out, nil
}

func (s *Store) rewrapOne(ctx context.Context, q *sqlcdb.Queries, kr *Keyring, k sqlcdb.TenantKey) error {
	aad := wrapAAD(k.Scope, k.TenantID, k.Version)
	dek, err := kr.unwrap(k.KekID, k.WrapNonce, k.WrappedDek, aad)
	if err != nil {
		return fmt.Errorf("DEK %s (%s v%d, kek_id %s): %w", k.ID, k.Scope, k.Version, k.KekID, err)
	}
	defer clear(dek)
	kekID, nonce, wrapped, err := kr.wrap(dek, aad)
	if err != nil {
		return err
	}
	n, err := q.RewrapDEK(ctx, sqlcdb.RewrapDEKParams{
		WrappedDek: wrapped, WrapNonce: nonce, NewKekID: kekID, ID: k.ID, OldKekID: k.KekID,
	})
	if err == nil && n != 1 {
		err = fmt.Errorf("DEK %s changed during rewrap", k.ID)
	}
	return err
}

// scopesOf lists the DEK scopes a keyring wraps.
func scopesOf(kr *Keyring) []string {
	if kr.Name() == KEKOps {
		return []string{string(ScopePlatformOps)}
	}
	return []string{string(ScopeTenant), string(ScopePlatform)}
}

// DestroyExpired erases every secret version past its expiry (job of the worker, platform pool: all tenants). It
// returns the number of versions erased.
func (s *Store) DestroyExpired(ctx context.Context) (int64, error) {
	var n int64
	err := s.db.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		var err error
		n, err = q.DestroyExpiredSecrets(ctx)
		return err
	})
	if err != nil {
		return 0, fmt.Errorf("secrets: destroy expired: %w", err)
	}
	if n > 0 {
		s.log.Info("secrets: expired secret versions destroyed", "secret_versions", n)
	}
	return n, nil
}

// Probe unwraps one DEK per (scope, kek_id) still in use, for every scope whose keyring this process holds: it fails
// when a keyring lacks a KEK the database needs or holds a different key under the same kek_id. It is the
// "SecretStore (giải mã thử)" readiness check of §16.2 and the reload drill of P2-T04a.
func (s *Store) Probe(ctx context.Context) error {
	return s.db.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		rows, err := q.ListDEKProbes(ctx)
		if err != nil {
			return fmt.Errorf("secrets: probe: %w", err)
		}
		for _, k := range rows {
			owner := Owner{Scope: Scope(k.Scope)}
			if k.TenantID != nil {
				owner.Tenant = *k.TenantID
			}
			if _, err := s.keyring(owner.Scope); errors.Is(err, ErrNoKeyring) {
				continue // platform_ops in the api: not its keyring (and RLS hides the rows anyway)
			}
			if _, err := s.dekAEAD(k, owner); err != nil {
				return fmt.Errorf("secrets: probe: DEK %s (%s v%d, kek_id %s): %w", k.ID, k.Scope, k.Version, k.KekID, err)
			}
		}
		return nil
	})
}

// KEKUse is the number of live DEKs of one scope wrapped by one KEK.
type KEKUse struct {
	Scope Scope
	KEKID string
	DEKs  int64
}

// KEKUsage lists which KEKs the DEKs visible to this process still need (the api does not see platform_ops).
func (s *Store) KEKUsage(ctx context.Context) ([]KEKUse, error) {
	var out []KEKUse
	err := s.db.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		rows, err := q.CountDEKsByKEK(ctx)
		for _, r := range rows {
			out = append(out, KEKUse{Scope: Scope(r.Scope), KEKID: r.KekID, DEKs: r.Deks})
		}
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("secrets: KEK usage: %w", err)
	}
	return out, nil
}
