package identity

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// SessionGCKind is the job kind of the session clean-up (§13.5: grant.expire / session.gc / retention.sweep).
const SessionGCKind = "session.gc"

// Retention of §6.4 and the schedule of the job.
const (
	DefaultSessionRetention     = 30 * 24 * time.Hour // a session is deleted 30 days after it expired or was revoked
	DefaultAuthRequestRetention = time.Hour           // an auth request is deleted 1 hour after expires_at
	DefaultSessionGCInterval    = time.Hour
	DefaultSessionGCBatch       = 1000
)

// PeriodicRegistrar is the part of the job registry (internal/jobs, P2-T12) that session.gc needs: run fn every
// interval under the given kind. The worker adapts its River registration to it.
type PeriodicRegistrar interface {
	RegisterPeriodic(kind string, interval time.Duration, fn func(ctx context.Context) error) error
}

// SessionGC deletes dead sessions and stale auth requests (§6.4). It runs in the worker with the worker store
// (platform pool mg_worker_platform: SELECT and DELETE on sessions and auth_requests only). Deletes go in batches
// so no long lock is held; running it twice is harmless (idempotent).
type SessionGC struct {
	store                *store.Store
	log                  *slog.Logger
	now                  func() time.Time
	SessionRetention     time.Duration
	AuthRequestRetention time.Duration
	Interval             time.Duration
	Batch                int
}

// NewSessionGC returns the job with the defaults of §6.4; log and now may be nil.
func NewSessionGC(st *store.Store, log *slog.Logger, now func() time.Time) *SessionGC {
	if log == nil {
		log = slog.Default()
	}
	if now == nil {
		now = time.Now
	}
	return &SessionGC{
		store: st, log: log.With("job", SessionGCKind), now: now,
		SessionRetention: DefaultSessionRetention, AuthRequestRetention: DefaultAuthRequestRetention,
		Interval: DefaultSessionGCInterval, Batch: DefaultSessionGCBatch,
	}
}

// Register schedules the job on the worker's registry.
func (g *SessionGC) Register(r PeriodicRegistrar) error {
	return r.RegisterPeriodic(SessionGCKind, g.Interval, func(ctx context.Context) error {
		_, err := g.Run(ctx)
		return err
	})
}

// GCResult counts the rows deleted by one run.
type GCResult struct {
	Sessions     int64
	AuthRequests int64
}

// Run deletes, batch by batch, sessions revoked or expired before now − SessionRetention and auth requests that
// expired before now − AuthRequestRetention.
func (g *SessionGC) Run(ctx context.Context) (GCResult, error) {
	if g.Batch <= 0 || g.Batch > 100000 {
		return GCResult{}, errors.New("identity: session.gc batch size out of range")
	}
	now := g.now()
	batch := int32(g.Batch) //nolint:gosec // bounded above
	var res GCResult
	for {
		var n int64
		err := g.store.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
			var err error
			n, err = q.DeleteDeadSessions(ctx, sqlcdb.DeleteDeadSessionsParams{Cutoff: now.Add(-g.SessionRetention), BatchSize: batch})
			return err
		})
		if err != nil {
			return res, err
		}
		res.Sessions += n
		if n < int64(batch) {
			break
		}
	}
	for {
		var n int64
		err := g.store.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
			var err error
			n, err = q.DeleteStaleAuthRequests(ctx, sqlcdb.DeleteStaleAuthRequestsParams{Cutoff: now.Add(-g.AuthRequestRetention), BatchSize: batch})
			return err
		})
		if err != nil {
			return res, err
		}
		res.AuthRequests += n
		if n < int64(batch) {
			break
		}
	}
	g.log.InfoContext(ctx, "session.gc done", "sessions_deleted", res.Sessions, "auth_requests_deleted", res.AuthRequests)
	return res, nil
}
