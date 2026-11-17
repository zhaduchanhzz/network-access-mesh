// Package secrets is the SecretStore of the Management Plane (§7.6, ADR-17): envelope encryption in PostgreSQL.
//
// Business tables hold only references mgsec://<tenant_id|platform>/<name>#<version> (§6.1); the values live in the
// table secrets, each version encrypted with AES-256-GCM under a data-encryption key (DEK) and bound by its AAD
// "mgsec/v1|<tenant_id|platform>|<name>|<version>". DEKs (table tenant_keys) are versioned per owner — one series per
// tenant plus the platform series "platform" (secrets the api needs) and "platform_ops" (secrets only the worker
// uses) — and stored wrapped by a key-encryption key (KEK) with AAD "mgdek/v1|<scope>|<tenant_id>|<version>", so a
// wrapped DEK swapped between tenants or rows does not unwrap. KEKs never reach the database or its backups: they come
// from two keyrings of file secrets, kek-app (api and worker; tenant and platform DEKs) and kek-ops (worker only;
// platform_ops DEK), each a directory with one file per KEK version and a file ACTIVE (LoadKeyring).
//
// Every query goes through internal/store: tenant secrets in store.WithTenantTx (the tenant pool, RLS limited to that
// tenant), platform secrets and the key-management jobs in store.WithPlatformTx. On top of RLS the mg_api_* roles
// cannot see platform_ops rows at all, and only the worker roles may update tenant_keys — rotating a DEK, rewrapping
// after a KEK rotation and destroying a tenant's DEKs (crypto-shredding) are worker jobs.
//
// Wiring (P2-T16): api — LoadKeyring(KEKApp, cfg.KEKAppDir) and New(db, Options{App: app}); worker — also
// LoadKeyring(KEKOps, cfg.KEKOpsDir) as Options.Ops. Probe is the "SecretStore (giải mã thử)" readiness check (§16.2).
package secrets

import (
	"bytes"
	"context"
	"crypto/cipher"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// SecretStore stores and resolves secrets by reference (§7.6). Driver for the MVP: *Store (envelope encryption in
// PostgreSQL); an OpenBao/Vault driver is a Phase 7 option.
type SecretStore interface {
	// Put stores value as version 1 of a new secret (ErrExists if that version exists).
	Put(ctx context.Context, ref Ref, value []byte, opts ...Option) error
	// Get decrypts the secret version ref names.
	Get(ctx context.Context, ref Ref) (Plaintext, error)
	// Rotate stores value as the next version after ref, which must be the latest version (ErrConflict otherwise),
	// and returns the new reference. Older versions stay readable until destroyed.
	Rotate(ctx context.Context, ref Ref, value []byte, opts ...Option) (Ref, error)
	// Destroy irreversibly erases the ciphertext of the version ref names (idempotent).
	Destroy(ctx context.Context, ref Ref) error
}

// Errors. An error of this package wraps one of these or a database error (store.SQLState gives its code, e.g. 42501
// when the role of the pool lacks a privilege); none carries a secret value or key material.
var (
	ErrInvalid      = errors.New("invalid argument")
	ErrNotFound     = errors.New("secret not found")
	ErrExists       = errors.New("secret version already exists")
	ErrConflict     = errors.New("not the latest version of the secret")
	ErrDestroyed    = errors.New("secret version destroyed")
	ErrExpired      = errors.New("secret version expired")
	ErrKeyDestroyed = errors.New("data encryption key destroyed")
	ErrIntegrity    = errors.New("integrity check failed")
	ErrUnknownKEK   = errors.New("key-encryption key not loaded")
	ErrNoKeyring    = errors.New("keyring of this scope not loaded in this process")
)

const (
	stateDestroyed  = "destroyed"
	uniqueViolation = "23505"
)

// Options configures a Store.
type Options struct {
	App    *Keyring         // kek-app: required (api and worker)
	Ops    *Keyring         // kek-ops: worker only — nil in the api (§7.6)
	Logger *slog.Logger     // nil discards; values and key material are never logged
	Now    func() time.Time // clock for expiry checks; nil = time.Now
	// OnIntegrity is called for every operation refused with ErrIntegrity (tampered row, AAD, DEK of another owner,
	// failed authentication), AFTER the operation's transaction ended — its writes rolled back — so it may write in a
	// transaction of its own: the processes record a security event (P2-T08 open item, wired in P2-T16). nil: the
	// failure is only logged.
	OnIntegrity func(ctx context.Context, f IntegrityFailure)
}

// IntegrityFailure describes an operation refused with ErrIntegrity — never a value or key material.
type IntegrityFailure struct {
	Op  string // put, get, rotate, destroy, latest, probe
	Ref Ref    // the reference of the operation; zero for probe (a DEK of the process)
}

// Store is the PostgreSQL envelope-encryption SecretStore.
type Store struct {
	db  *store.Store
	app *Keyring
	ops *Keyring
	log *slog.Logger
	now func() time.Time
	// integrity: Options.OnIntegrity
	integrity func(ctx context.Context, f IntegrityFailure)
}

var _ SecretStore = (*Store)(nil)

// New returns a Store on db (the process's two pools).
func New(db *store.Store, o Options) (*Store, error) {
	switch {
	case db == nil:
		return nil, errors.New("secrets: a store is required")
	case o.App == nil || o.App.Name() != KEKApp:
		return nil, fmt.Errorf("secrets: Options.App must be the %s keyring", KEKApp)
	case o.Ops != nil && o.Ops.Name() != KEKOps:
		return nil, fmt.Errorf("secrets: Options.Ops must be the %s keyring", KEKOps)
	}
	s := &Store{db: db, app: o.App, ops: o.Ops, log: o.Logger, now: o.Now, integrity: o.OnIntegrity}
	if s.log == nil {
		s.log = slog.New(slog.DiscardHandler)
	}
	if s.now == nil {
		s.now = time.Now
	}
	return s, nil
}

// Option adjusts Put and Rotate.
type Option func(*writeOptions)

type writeOptions struct {
	expires     *time.Time
	platformOps bool
}

// WithExpiry makes the version unreadable (ErrExpired) from t on; DestroyExpired erases it afterwards. Used for
// show-once secrets kept for idempotent replays (§13.1).
func WithExpiry(t time.Time) Option {
	return func(o *writeOptions) { o.expires = &t }
}

// WithPlatformOps puts a new platform secret under the platform_ops DEK: only the worker (kek-ops, mg_worker_*)
// can read it (§7.6). Rotate keeps the scope of the first version.
func WithPlatformOps() Option {
	return func(o *writeOptions) { o.platformOps = true }
}

func (s *Store) writeOptions(ref Ref, value []byte, opts []Option) (writeOptions, error) {
	var o writeOptions
	for _, f := range opts {
		f(&o)
	}
	switch {
	case len(value) == 0 || len(value) > MaxValueSize:
		return o, fmt.Errorf("%w: a secret value must hold 1–%d bytes", ErrInvalid, MaxValueSize)
	case o.platformOps && !ref.IsPlatform():
		return o, fmt.Errorf("%w: WithPlatformOps applies to platform secrets only", ErrInvalid)
	case o.expires != nil && !o.expires.After(s.now()):
		return o, fmt.Errorf("%w: expiry is not in the future", ErrInvalid)
	}
	return o, nil
}

// Put stores value as version 1 of the secret ref names. A tenant gets its DEK on its first secret (§13.3).
func (s *Store) Put(ctx context.Context, ref Ref, value []byte, opts ...Option) error {
	if err := ref.Validate(); err != nil {
		return fmt.Errorf("secrets: put: %w", err)
	}
	o, err := s.writeOptions(ref, value, opts)
	if err != nil {
		return fmt.Errorf("secrets: put %s: %w", ref, err)
	}
	if ref.Version != 1 {
		return fmt.Errorf("secrets: put %s: %w: Put creates version 1, later versions come from Rotate", ref, ErrInvalid)
	}
	owner := TenantOwner(ref.Tenant)
	if ref.IsPlatform() {
		owner = PlatformOwner
		if o.platformOps {
			owner = PlatformOpsOwner
		}
	}
	var created *sqlcdb.TenantKey
	err = s.tx(ctx, ref.Tenant, func(q *sqlcdb.Queries) error {
		var err error
		created, err = s.insertVersion(ctx, q, owner, ref, value, o.expires)
		return err
	})
	s.reportIntegrity(ctx, "put", ref, err)
	if err != nil {
		return fmt.Errorf("secrets: put %s: %w", ref, err)
	}
	s.logCreated(created)
	s.log.Debug("secrets: secret stored", "ref", ref.String(), "scope", string(owner.Scope))
	return nil
}

// Get decrypts the secret version ref names. The AAD is recomputed from ref, never taken from the row.
func (s *Store) Get(ctx context.Context, ref Ref) (Plaintext, error) {
	if err := ref.Validate(); err != nil {
		return nil, fmt.Errorf("secrets: get: %w", err)
	}
	var out Plaintext
	err := s.tx(ctx, ref.Tenant, func(q *sqlcdb.Queries) error {
		row, err := s.row(ctx, q, ref)
		if err != nil {
			return err
		}
		owner, err := rowOwner(row, ref)
		if err != nil {
			return err
		}
		switch {
		case row.DestroyedAt != nil:
			return ErrDestroyed
		case row.ExpiresAt != nil && !s.now().Before(*row.ExpiresAt):
			return ErrExpired
		}
		k, err := q.GetDEK(ctx, row.DekID)
		if errors.Is(err, store.ErrNoRows) {
			// FK (tenant_id, dek_id) forbids it; RLS hides the DEK of another tenant if the FK was bypassed
			s.integrityFailure(ref, row.DekID, "the DEK of the row is not visible to its owner")
			return fmt.Errorf("%w: DEK of the row not visible to its owner", ErrIntegrity)
		}
		if err != nil {
			return err
		}
		aead, err := s.dekAEAD(k, owner)
		if err != nil {
			return err
		}
		aad := secretAAD(ref)
		if !bytes.Equal(row.Aad, aad) {
			s.integrityFailure(ref, k.ID, "stored AAD differs from the reference")
			return fmt.Errorf("%w: stored AAD differs from the reference", ErrIntegrity)
		}
		pt, err := open(aead, row.Nonce, row.Ciphertext, aad)
		if err != nil {
			s.integrityFailure(ref, k.ID, "ciphertext failed authentication")
			return err
		}
		out = pt
		return nil
	})
	s.reportIntegrity(ctx, "get", ref, err)
	if err != nil {
		return nil, fmt.Errorf("secrets: get %s: %w", ref, err)
	}
	return out, nil
}

// Rotate stores value as version ref.Version+1; ref must name the latest version. Two concurrent rotations of the
// same version: one wins, the other gets ErrConflict.
func (s *Store) Rotate(ctx context.Context, ref Ref, value []byte, opts ...Option) (Ref, error) {
	if err := ref.Validate(); err != nil {
		return Ref{}, fmt.Errorf("secrets: rotate: %w", err)
	}
	o, err := s.writeOptions(ref, value, opts)
	if err != nil {
		return Ref{}, fmt.Errorf("secrets: rotate %s: %w", ref, err)
	}
	if ref.Version == math.MaxInt32 {
		return Ref{}, fmt.Errorf("secrets: rotate %s: %w: no version after this one", ref, ErrInvalid)
	}
	next := ref
	next.Version++
	var created *sqlcdb.TenantKey
	err = s.tx(ctx, ref.Tenant, func(q *sqlcdb.Queries) error {
		latest, err := s.latestRow(ctx, q, ref)
		if err != nil {
			return err
		}
		if latest.Version != ref.Version {
			return ErrConflict
		}
		owner, err := rowOwner(latest, ref)
		if err != nil {
			return err
		}
		if o.platformOps && owner.Scope != ScopePlatformOps {
			return fmt.Errorf("%w: the scope of a secret is fixed by its first version", ErrInvalid)
		}
		created, err = s.insertVersion(ctx, q, owner, next, value, o.expires)
		if errors.Is(err, ErrExists) {
			return ErrConflict
		}
		return err
	})
	s.reportIntegrity(ctx, "rotate", ref, err)
	if err != nil {
		return Ref{}, fmt.Errorf("secrets: rotate %s: %w", ref, err)
	}
	s.logCreated(created)
	s.log.Info("secrets: secret rotated", "ref", next.String())
	return next, nil
}

// Destroy erases the ciphertext of one version (the row stays: it holds the version number and the audit trail).
func (s *Store) Destroy(ctx context.Context, ref Ref) error {
	if err := ref.Validate(); err != nil {
		return fmt.Errorf("secrets: destroy: %w", err)
	}
	var n int64
	err := s.tx(ctx, ref.Tenant, func(q *sqlcdb.Queries) error {
		row, err := s.row(ctx, q, ref)
		if err != nil {
			return err
		}
		if _, err := rowOwner(row, ref); err != nil {
			return err
		}
		n, err = q.DestroySecret(ctx, row.ID)
		return err
	})
	s.reportIntegrity(ctx, "destroy", ref, err)
	if err != nil {
		return fmt.Errorf("secrets: destroy %s: %w", ref, err)
	}
	if n > 0 {
		s.log.Info("secrets: secret version destroyed", "ref", ref.String())
	}
	return nil
}

// insertVersion encrypts value under owner's active DEK (created if owner has none yet) and inserts the row. It
// returns the DEK it created, if any, for logging after commit.
func (s *Store) insertVersion(ctx context.Context, q *sqlcdb.Queries, owner Owner, ref Ref, value []byte,
	expires *time.Time,
) (*sqlcdb.TenantKey, error) {
	k, created, err := s.activeDEK(ctx, q, owner)
	if err != nil {
		return nil, err
	}
	aead, err := s.dekAEAD(k, owner)
	if err != nil {
		return nil, err
	}
	aad := secretAAD(ref)
	nonce, ct, err := seal(aead, value, aad)
	if err != nil {
		return nil, err
	}
	_, err = q.InsertSecret(ctx, sqlcdb.InsertSecretParams{
		TenantID: owner.tenantPtr(), Scope: string(owner.Scope), Name: ref.Name, Version: ref.Version,
		Ciphertext: ct, Nonce: nonce, Aad: aad, DekID: k.ID, ExpiresAt: expires,
	})
	if store.SQLState(err) == uniqueViolation {
		return nil, ErrExists
	}
	if err != nil {
		return nil, err
	}
	if created {
		return &k, nil
	}
	return nil, nil
}

// row reads the row of one version (tenant secrets: the tenant pool, so RLS already limits it to that tenant).
func (s *Store) row(ctx context.Context, q *sqlcdb.Queries, ref Ref) (sqlcdb.Secret, error) {
	var (
		row sqlcdb.Secret
		err error
	)
	if ref.IsPlatform() {
		row, err = q.GetPlatformSecret(ctx, sqlcdb.GetPlatformSecretParams{Name: ref.Name, Version: ref.Version})
	} else {
		id := ref.Tenant
		row, err = q.GetTenantSecret(ctx, sqlcdb.GetTenantSecretParams{TenantID: &id, Name: ref.Name, Version: ref.Version})
	}
	if errors.Is(err, store.ErrNoRows) {
		return row, ErrNotFound
	}
	return row, err
}

func (s *Store) latestRow(ctx context.Context, q *sqlcdb.Queries, ref Ref) (sqlcdb.Secret, error) {
	var (
		row sqlcdb.Secret
		err error
	)
	if ref.IsPlatform() {
		row, err = q.GetLatestPlatformSecret(ctx, ref.Name)
	} else {
		id := ref.Tenant
		row, err = q.GetLatestTenantSecret(ctx, sqlcdb.GetLatestTenantSecretParams{TenantID: &id, Name: ref.Name})
	}
	if errors.Is(err, store.ErrNoRows) {
		return row, ErrNotFound
	}
	return row, err
}

// rowOwner checks that the row belongs where ref says and returns the owner of its DEK series.
func rowOwner(row sqlcdb.Secret, ref Ref) (Owner, error) {
	if ref.IsPlatform() {
		if row.TenantID == nil && (row.Scope == string(ScopePlatform) || row.Scope == string(ScopePlatformOps)) {
			return Owner{Scope: Scope(row.Scope)}, nil
		}
	} else if row.TenantID != nil && *row.TenantID == ref.Tenant && row.Scope == string(ScopeTenant) {
		return TenantOwner(ref.Tenant), nil
	}
	return Owner{}, fmt.Errorf("%w: the row does not belong to the reference", ErrIntegrity)
}

// tx runs fn in the tenant's transaction (tenant pool) or, for uuid.Nil, in a platform transaction.
func (s *Store) tx(ctx context.Context, tenant uuid.UUID, fn func(*sqlcdb.Queries) error) error {
	if tenant == uuid.Nil {
		return s.db.WithPlatformTx(ctx, fn)
	}
	return s.db.WithTenantTx(ctx, tenant, fn)
}

// keyring returns the keyring that wraps the DEKs of scope sc.
func (s *Store) keyring(sc Scope) (*Keyring, error) {
	switch sc {
	case ScopeTenant, ScopePlatform:
		return s.app, nil
	case ScopePlatformOps:
		if s.ops == nil {
			return nil, ErrNoKeyring
		}
		return s.ops, nil
	}
	return nil, fmt.Errorf("%w: unknown scope", ErrInvalid)
}

// dekAEAD unwraps DEK row k, which must belong to owner, and returns its cipher (the raw DEK is cleared).
func (s *Store) dekAEAD(k sqlcdb.TenantKey, owner Owner) (cipher.AEAD, error) {
	if k.Scope != string(owner.Scope) || !sameTenant(k.TenantID, owner) {
		s.log.Warn("secrets: DEK of another owner", "owner", owner.String(), "dek_id", k.ID.String())
		return nil, fmt.Errorf("%w: the DEK belongs to another owner", ErrIntegrity)
	}
	if k.State == stateDestroyed || k.WrappedDek == nil {
		return nil, ErrKeyDestroyed
	}
	kr, err := s.keyring(owner.Scope)
	if err != nil {
		return nil, err
	}
	dek, err := kr.unwrap(k.KekID, k.WrapNonce, k.WrappedDek, wrapAAD(k.Scope, k.TenantID, k.Version))
	if err != nil {
		s.log.Warn("secrets: DEK cannot be unwrapped", "owner", owner.String(), "dek_id", k.ID.String(),
			"dek_version", k.Version, "keyring", kr.Name(), "kek_id", k.KekID, "error", err.Error())
		return nil, err
	}
	defer clear(dek)
	return newAEAD(dek)
}

func sameTenant(col *uuid.UUID, o Owner) bool {
	if o.Scope == ScopeTenant {
		return col != nil && *col == o.Tenant
	}
	return col == nil
}

// reportIntegrity hands an ErrIntegrity of operation op to Options.OnIntegrity — called after the operation's
// transaction ended, detached from the caller's cancellation.
func (s *Store) reportIntegrity(ctx context.Context, op string, ref Ref, err error) {
	if err == nil || s.integrity == nil || !errors.Is(err, ErrIntegrity) {
		return
	}
	s.integrity(context.WithoutCancel(ctx), IntegrityFailure{Op: op, Ref: ref})
}

func (s *Store) integrityFailure(ref Ref, dekID uuid.UUID, what string) {
	s.log.Warn("secrets: integrity check failed", "ref", ref.String(), "dek_id", dekID.String(), "reason", what)
}

func (s *Store) logCreated(k *sqlcdb.TenantKey) {
	if k == nil {
		return
	}
	s.log.Info("secrets: DEK created", "scope", k.Scope, "tenant_id", tenantString(k.TenantID),
		"dek_version", k.Version, "kek_id", k.KekID)
}

func tenantString(id *uuid.UUID) string {
	if id == nil {
		return ""
	}
	return id.String()
}
