package deprovision

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/idp"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// ShredInterval is how often tenant.keys_destroy runs (a platform job of the maintenance queue).
const ShredInterval = time.Hour

// ShredderConfig configures the crypto-shredding of deleted tenants.
type ShredderConfig struct {
	Store   *store.Store
	Secrets SecretStore
	IdP     IdPDrivers
	Logger  *slog.Logger
	// Batch bounds the tenants of one run (default 20); the next run takes the rest.
	Batch       int
	CallTimeout time.Duration // one IdP call (default 2 min)
	Now         func() time.Time
}

// Shredder is tenant.keys_destroy: for every deleted tenant whose keys_destroy_after has passed and that still holds
// key material, (1) the issuers of the tenant are purged at their IdP (keycloak: the realm — named by the slug — is
// deleted with the secrets the driver used; external: the client secret destroyed), then (2) every DEK and every secret
// version of the tenant is destroyed (secrets.Store.DestroyTenantKeys — crypto-shredding, §6.1), read back, and audited
// (platform.tenant.keys_destroyed). An IdP that cannot be purged now leaves the tenant for the next run (the DEK is
// destroyed only after the realm is gone: the slug — the realm's name — stays reserved until then).
type Shredder struct {
	cfg ShredderConfig
}

// NewShredder checks the configuration.
func NewShredder(cfg ShredderConfig) (*Shredder, error) {
	if cfg.Store == nil || cfg.Secrets == nil || cfg.IdP == nil {
		return nil, errors.New("deprovision: the shredder needs a store, the SecretStore and the IdP drivers")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	if cfg.Batch <= 0 {
		cfg.Batch = 20
	}
	if cfg.CallTimeout <= 0 {
		cfg.CallTimeout = 2 * time.Minute
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Shredder{cfg: cfg}, nil
}

// Register schedules tenant.keys_destroy on the worker (jobs.Worker.RegisterPeriodic, every ShredInterval).
func (s *Shredder) Register(w *jobs.Worker) error {
	return w.RegisterPeriodic(KindKeysDestroy, ShredInterval, func(ctx context.Context) error {
		r, err := s.Sweep(ctx)
		if err != nil {
			return jobs.Transient("registry_unavailable", err)
		}
		if r.Failed > 0 {
			// the others were shredded; the next run retries the failed ones
			return jobs.Transient("keys_destroy_incomplete", fmt.Errorf("%d tenant(s) not shredded", r.Failed))
		}
		return nil
	})
}

// ShredResult is the outcome of one sweep.
type ShredResult struct {
	Tenants   []uuid.UUID // tenants whose keys were destroyed
	DEKs      int64       // DEK versions destroyed
	Secrets   int64       // secret versions destroyed
	IdPs      int         // issuers purged
	Failed    int         // tenants left for the next run (IdP or SecretStore failure)
	Remaining bool        // more due tenants than the batch
}

// Sweep shreds the tenants due now (at most Batch).
func (s *Shredder) Sweep(ctx context.Context) (ShredResult, error) {
	var (
		res ShredResult
		due []sqlcdb.ListTenantsDueForKeyDestructionRow
	)
	now := s.cfg.Now().UTC()
	if err := s.cfg.Store.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		var err error
		due, err = q.ListTenantsDueForKeyDestruction(ctx, sqlcdb.ListTenantsDueForKeyDestructionParams{Now: now,
			RowLimit: int32(s.cfg.Batch + 1)}) //nolint:gosec // small bound
		return err
	}); err != nil {
		return res, err
	}
	if len(due) > s.cfg.Batch {
		due, res.Remaining = due[:s.cfg.Batch], true
	}
	for _, t := range due {
		idps, report, err := s.shred(ctx, t)
		if err != nil {
			res.Failed++
			s.cfg.Logger.ErrorContext(ctx, "tenant.keys_destroy: a tenant was not shredded", "tenant_id", t.ID.String(),
				"slug", t.Slug, "error", err.Error())
			continue
		}
		res.Tenants = append(res.Tenants, t.ID)
		res.DEKs += report.DEKs
		res.Secrets += report.Secrets
		res.IdPs += idps
	}
	return res, nil
}

// shred purges the tenant's issuers then destroys its keys, reads back and audits.
func (s *Shredder) shred(ctx context.Context, t sqlcdb.ListTenantsDueForKeyDestructionRow) (int, shredReport, error) {
	var rows []sqlcdb.ListTenantIdentityProvidersRow
	if err := s.cfg.Store.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		var err error
		rows, err = q.ListTenantIdentityProviders(ctx, t.ID)
		return err
	}); err != nil {
		return 0, shredReport{}, err
	}
	purged := 0
	for _, r := range rows {
		reg := registration(t.ID, r)
		if reg.DriverRef == "" && r.Driver != idp.DriverExternal {
			continue // a keycloak issuer never created (no realm)
		}
		drv, err := s.cfg.IdP.Driver(r.Driver)
		if err != nil {
			return purged, shredReport{}, err
		}
		cctx, cancel := context.WithTimeout(ctx, s.cfg.CallTimeout)
		_, err = drv.RemoveIssuer(cctx, reg, idp.RemovePurge)
		cancel()
		if err != nil && idp.CodeOf(err) != idp.CodeNotFound {
			return purged, shredReport{}, fmt.Errorf("purge the issuer %s: %w", r.ID, err)
		}
		purged++
	}
	rep, err := s.cfg.Secrets.DestroyTenantKeys(ctx, t.ID)
	if err != nil {
		return purged, shredReport{}, err
	}
	var left sqlcdb.CountTenantLiveKeysRow
	err = s.cfg.Store.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		var err error
		if left, err = q.CountTenantLiveKeys(ctx, t.ID); err != nil {
			return err
		}
		if left.Deks+left.Secrets > 0 {
			return fmt.Errorf("%d DEK(s), %d secret version(s) still hold key material", left.Deks, left.Secrets)
		}
		return audit.Record(ctx, q, audit.Event{Action: AuditKeysDestroyed, ActorType: audit.ActorSystem, ResourceType: "tenant",
			ResourceID: t.ID.String(), Details: audit.Details{"tenant_id": t.ID, "slug": t.Slug, "deleted_at": t.DeletedAt,
				"keys_destroy_after": t.KeysDestroyAfter, "deks_destroyed": rep.DEKs, "secret_versions_destroyed": rep.Secrets,
				"issuers_purged": purged}})
	})
	if err != nil {
		return purged, shredReport{}, err
	}
	s.cfg.Logger.WarnContext(ctx, "tenant.keys_destroy: tenant keys destroyed (crypto-shredding)", "tenant_id", t.ID.String(),
		"slug", t.Slug, "deks", rep.DEKs, "secret_versions", rep.Secrets, "issuers_purged", purged)
	return purged, shredReport{DEKs: rep.DEKs, Secrets: rep.Secrets}, nil
}

type shredReport struct{ DEKs, Secrets int64 }
