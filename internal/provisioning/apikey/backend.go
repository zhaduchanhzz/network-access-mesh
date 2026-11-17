package apikey

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// instanceState is what the registry knows of an instance when a rotation starts.
type instanceState struct {
	TenantID, InstanceID uuid.UUID
	Slug                 string
	TenantStatus         string
	Status               string     // tenant_instances.status
	Ref                  string     // api_key_secret_ref ("" = none recorded)
	Prefix               string     // api_key_prefix
	ExpiresAt            *time.Time // api_key_expires_at
	LifecycleBusy        bool       // a lifecycle job of the tenant is running (§13.5 (d))
}

// swapSpec is the conditional change of step 7.
type swapSpec struct {
	TenantID, InstanceID uuid.UUID
	OldRef               string // the reference read at the start ("" = none)
	NewRef               string
	NewPrefix            string
	NewExpiresAt         time.Time
}

// expiry is one row of the schedule and the expiry gauge.
type expiry struct {
	TenantID, InstanceID uuid.UUID
	Prefix               string
	ExpiresAt            *time.Time
}

var (
	errNotFound     = errors.New("apikey: instance not found")
	errSwapConflict = errors.New("apikey: the instance's key reference changed during the rotation")
)

// backend is the database side of the rotation: dbBackend (the worker's store) in production, a fake in the unit tests.
type backend interface {
	// lock runs fn under the instance's API key lock (LockName), waiting at most wait.
	lock(ctx context.Context, tenantID uuid.UUID, wait time.Duration, fn func(context.Context) error) error
	load(ctx context.Context, tenantID, instanceID uuid.UUID) (instanceState, error)
	// requested commits "<ev.Action>.requested" and returns the operation (§6.1).
	requested(ctx context.Context, ev audit.Event) (audit.Operation, error)
	// swap applies sw and op's ".succeeded" event in one transaction; errSwapConflict when the row changed.
	swap(ctx context.Context, sw swapSpec, op audit.Operation, details audit.Details) error
	// currentRef reads the instance's key reference again (after a swap whose outcome is unknown).
	currentRef(ctx context.Context, tenantID, instanceID uuid.UUID) (string, error)
	failed(ctx context.Context, op audit.Operation, reason string, details audit.Details) error
	expiries(ctx context.Context) ([]expiry, error)
	// enqueue writes an apikey.rotate job; created is false when an unfinished job of the slot exists.
	enqueue(ctx context.Context, tenantID, instanceID uuid.UUID, slot int64, in Input) (created bool, err error)
}

// dbBackend is the backend on the worker's store: platform transactions (only the platform roles may update
// tenant_instances; audit events of a platform transaction are platform events), the lock on the tenant pool.
type dbBackend struct{ st *store.Store }

func (b dbBackend) lock(ctx context.Context, tenantID uuid.UUID, wait time.Duration, fn func(context.Context) error) error {
	return b.st.WithTenantLock(ctx, tenantID, LockName, wait, fn)
}

func (b dbBackend) load(ctx context.Context, tenantID, instanceID uuid.UUID) (instanceState, error) {
	var row sqlcdb.GetInstanceForKeyRotationRow
	err := b.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		var err error
		row, err = q.GetInstanceForKeyRotation(ctx, sqlcdb.GetInstanceForKeyRotationParams{ID: instanceID, TenantID: tenantID})
		return err
	})
	switch {
	case errors.Is(err, store.ErrNoRows):
		return instanceState{}, errNotFound
	case err != nil:
		return instanceState{}, err
	}
	return instanceState{TenantID: row.TenantID, InstanceID: row.ID, Slug: row.Slug, TenantStatus: row.TenantStatus,
		Status: row.Status, Ref: deref(row.ApiKeySecretRef), Prefix: deref(row.ApiKeyPrefix), ExpiresAt: row.ApiKeyExpiresAt,
		LifecycleBusy: row.LifecycleBusy}, nil
}

func (b dbBackend) requested(ctx context.Context, ev audit.Event) (audit.Operation, error) {
	var op audit.Operation
	err := b.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		var err error
		op, err = audit.Requested(ctx, q, ev)
		return err
	})
	return op, err
}

func (b dbBackend) swap(ctx context.Context, sw swapSpec, op audit.Operation, details audit.Details) error {
	return b.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		p := sqlcdb.SwapInstanceAPIKeyParams{NewRef: sw.NewRef, NewPrefix: sw.NewPrefix, NewExpiresAt: sw.NewExpiresAt,
			ID: sw.InstanceID, TenantID: sw.TenantID}
		if sw.OldRef != "" {
			old := sw.OldRef
			p.OldRef = &old
		}
		if _, err := q.SwapInstanceAPIKey(ctx, p); err != nil {
			if errors.Is(err, store.ErrNoRows) {
				return errSwapConflict
			}
			return err
		}
		return op.Succeeded(ctx, q, details)
	})
}

func (b dbBackend) currentRef(ctx context.Context, tenantID, instanceID uuid.UUID) (string, error) {
	var ref *string
	err := b.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		var err error
		ref, err = q.GetInstanceAPIKeyRef(ctx, sqlcdb.GetInstanceAPIKeyRefParams{ID: instanceID, TenantID: tenantID})
		return err
	})
	return deref(ref), err
}

func (b dbBackend) failed(ctx context.Context, op audit.Operation, reason string, details audit.Details) error {
	return b.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error { return op.Failed(ctx, q, reason, details) })
}

func (b dbBackend) expiries(ctx context.Context) ([]expiry, error) {
	var rows []sqlcdb.ListAPIKeyExpiriesRow
	if err := b.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		var err error
		rows, err = q.ListAPIKeyExpiries(ctx)
		return err
	}); err != nil {
		return nil, err
	}
	out := make([]expiry, 0, len(rows))
	for _, r := range rows {
		out = append(out, expiry{TenantID: r.TenantID, InstanceID: r.ID, Prefix: deref(r.ApiKeyPrefix), ExpiresAt: r.ApiKeyExpiresAt})
	}
	return out, nil
}

func (b dbBackend) enqueue(ctx context.Context, tenantID, instanceID uuid.UUID, slot int64, in Input) (bool, error) {
	var created bool
	err := b.st.WithTenantJobTx(ctx, tenantID, func(tx *store.Tx) error {
		e, err := jobs.Enqueue(ctx, tx, jobs.Spec{Kind: Kind, TenantID: &tenantID, InstanceID: &instanceID,
			Slot: strconv.FormatInt(slot, 10), Input: in, Resource: &jobs.Resource{Type: "instance", ID: instanceID.String()}})
		created = e.Created
		return err
	})
	return created, err
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
