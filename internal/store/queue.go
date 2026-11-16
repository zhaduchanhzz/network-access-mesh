package store

// Job queue (River — §4.3, ST-01, ADR-21; P2-T12). River's tables live in their own schema (QueueSchema, created by
// migration 0006 and owned by mg_migrator); River's own migrator creates them right after goose (MigrateQueue), then
// database/river/grants.sql grants each process exactly what it needs. Business modules never touch River's driver:
// they enqueue through internal/jobs inside WithTenantJobTx / WithPlatformJobTx — the same transaction as the business
// change (§13.5) — and the worker process runs the QueueClient built here.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
	"github.com/riverqueue/river/rivermigrate"

	"github.com/zhaduchanhzz/network-access-mesh/database"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// QueueSchema is the PostgreSQL schema of the River job queue (§6.3): River's tables only, holding no business data
// beyond the provisioning_jobs.id reference (and the job kind) carried in the job args.
const QueueSchema = "river"

// queueMigrateLock serialises concurrent queue migrations with a session-level lock held by the migrate job, like
// goose's own lock around the goose step (a different key, so the two steps never wait on each other). Jobs never use
// advisory locks (§11.3) — this only guards the one-shot migrate job.
const queueMigrateLock int64 = 0x6d675f7269766572 // "mg_river"

// MigrateQueue applies River's own migrations to QueueSchema (rivermigrate with the pgx driver, one transaction per
// version) and then database/river/grants.sql, as mg_migrator. It returns the River versions applied by this call —
// none when the schema is current; the privileges are re-applied either way (idempotent).
func MigrateQueue(ctx context.Context, rawURL string, cred Credentials) ([]int, error) {
	pool, err := newPool(ctx, rawURL, cred, 3)
	if err != nil {
		return nil, fmt.Errorf("store: queue migrator: %w", err)
	}
	defer pool.Close()
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("store: queue migrator: %w", err)
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", queueMigrateLock); err != nil {
		return nil, fmt.Errorf("store: queue migrator: lock: %w", err)
	}
	defer func() {
		_, _ = conn.Exec(context.WithoutCancel(ctx), "SELECT pg_advisory_unlock($1)", queueMigrateLock)
	}()

	migrator, err := rivermigrate.New(riverpgxv5.New(pool), &rivermigrate.Config{
		Schema: QueueSchema,
		Logger: slog.New(slog.DiscardHandler),
	})
	if err != nil {
		return nil, fmt.Errorf("store: queue migrator: %w", err)
	}
	res, err := migrator.Migrate(ctx, rivermigrate.DirectionUp, nil)
	if err != nil {
		return nil, fmt.Errorf("store: queue migrate: %w", err)
	}
	applied := make([]int, 0, len(res.Versions))
	for _, v := range res.Versions {
		applied = append(applied, v.Version)
	}
	grants, err := database.River.ReadFile("river/grants.sql")
	if err != nil {
		return applied, err
	}
	if _, err := pool.Exec(ctx, string(grants)); err != nil { // no arguments ⇒ simple protocol, several statements
		return applied, fmt.Errorf("store: queue grants: %w", err)
	}
	return applied, nil
}

// MigrateAll is the migrate job of §6.1 (the `migrate` job of mg-core, wired in P2-T16): every pending goose migration
// (Migrate), then River's schema and its privileges (MigrateQueue) — all as mg_migrator.
func MigrateAll(ctx context.Context, rawURL string, cred Credentials) error {
	db, err := OpenMigrator(rawURL, cred)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	if err := Migrate(ctx, db); err != nil {
		return err
	}
	_, err = MigrateQueue(ctx, rawURL, cred)
	return err
}

// newInserter returns an insert-only River client: no pool, so it can never work jobs or run maintenance, only insert
// into the caller's transaction (InsertTx).
func newInserter(log *slog.Logger) (*river.Client[pgx.Tx], error) {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return river.NewClient(riverpgxv5.New(nil), &river.Config{Schema: QueueSchema, Logger: log})
}

// Tx is one transaction opened by WithTenantJobTx or WithPlatformJobTx: the sqlc queries bound to it (Q) and the job
// queue bound to the same transaction, so a job commits or rolls back together with the business change (§13.5).
type Tx struct {
	Q     *sqlcdb.Queries
	tx    pgx.Tx
	queue *river.Client[pgx.Tx]
}

// WithTenantJobTx is WithTenantTx for code that also enqueues jobs (internal/jobs.Enqueue): same pool, same app.*
// settings, same commit/rollback rule.
func (s *Store) WithTenantJobTx(ctx context.Context, tenantID uuid.UUID, fn func(tx *Tx) error) error {
	return s.tenantTx(ctx, tenantID, func(tx pgx.Tx) error { return fn(s.jobTx(tx)) })
}

// WithPlatformJobTx is WithPlatformTx for code that also enqueues jobs or inspects the queue (job.reaper).
func (s *Store) WithPlatformJobTx(ctx context.Context, fn func(tx *Tx) error) error {
	return s.platformTx(ctx, func(tx pgx.Tx) error { return fn(s.jobTx(tx)) })
}

func (s *Store) jobTx(tx pgx.Tx) *Tx { return &Tx{Q: sqlcdb.New(tx), tx: tx, queue: s.inserter} }

// InsertQueueJob inserts a River job in this transaction and returns its ID. Only internal/jobs calls it, pairing the
// River job with the provisioning_jobs row it carries.
func (t *Tx) InsertQueueJob(ctx context.Context, args river.JobArgs, opts *river.InsertOpts) (int64, error) {
	res, err := t.queue.InsertTx(ctx, t.tx, args, opts)
	if err != nil {
		return 0, fmt.Errorf("store: enqueue: %w", err)
	}
	return res.Job.ID, nil
}

// QueueJobStates returns the River state (available, scheduled, pending, running, retryable, completed, cancelled,
// discarded) of every given River job that still exists; job.reaper uses it to find jobs the queue dropped.
func (t *Tx) QueueJobStates(ctx context.Context, ids []int64) (map[int64]string, error) {
	out := make(map[int64]string, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := t.tx.Query(ctx, "SELECT id, state::text FROM "+QueueSchema+".river_job WHERE id = ANY($1)", ids)
	if err != nil {
		return nil, fmt.Errorf("store: queue job states: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var (
			id    int64
			state string
		)
		if err := rows.Scan(&id, &state); err != nil {
			return nil, fmt.Errorf("store: queue job states: %w", err)
		}
		out[id] = state
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: queue job states: %w", err)
	}
	return out, nil
}

// QueueClient is the River client of a worker process: it works the configured queues and, while elected leader, runs
// River's maintenance in QueueSchema (rescue of stuck jobs, scheduling of retries and snoozes, periodic jobs, cleanup
// of finished River rows). It has its own pool, logged in as the platform role of the process (mg_worker_platform —
// River's tables hold no tenant data and have no RLS), so River's connections, one of them held for LISTEN, never
// starve WithPlatformTx.
type QueueClient struct {
	client *river.Client[pgx.Tx]
	pool   *pgxpool.Pool
}

// NewQueueClient builds the worker's River client from cfg — workers, queues, periodic jobs and the explicit timeouts
// come from internal/jobs; cfg.Schema is set to QueueSchema.
func (s *Store) NewQueueClient(ctx context.Context, cfg *river.Config, maxConns int32) (*QueueClient, error) {
	if cfg == nil {
		return nil, errors.New("store: queue client: nil config")
	}
	if cfg.Schema != "" && cfg.Schema != QueueSchema {
		return nil, fmt.Errorf("store: queue client: the schema must be %s", QueueSchema)
	}
	cfg.Schema = QueueSchema
	pool, err := newPool(ctx, s.cfg.URL, s.cfg.Platform, maxConns)
	if err != nil {
		return nil, fmt.Errorf("store: queue client: %w", err)
	}
	if err := checkPoolRole(ctx, pool, GroupPlatform); err != nil {
		pool.Close()
		return nil, fmt.Errorf("store: queue client: %w", err)
	}
	client, err := river.NewClient(riverpgxv5.New(pool), cfg)
	if err != nil {
		pool.Close()
		return nil, fmt.Errorf("store: queue client: %w", err)
	}
	return &QueueClient{client: client, pool: pool}, nil
}

// Start starts working jobs (and maintenance when elected leader).
func (c *QueueClient) Start(ctx context.Context) error { return c.client.Start(ctx) }

// Stop stops fetching jobs and waits for running jobs (River's SoftStopTimeout, then their contexts are cancelled).
func (c *QueueClient) Stop(ctx context.Context) error { return c.client.Stop(ctx) }

// StopAndCancel cancels the contexts of running jobs at once, then stops.
func (c *QueueClient) StopAndCancel(ctx context.Context) error { return c.client.StopAndCancel(ctx) }

// Close closes the client's pool; call it after Stop.
func (c *QueueClient) Close() { c.pool.Close() }
