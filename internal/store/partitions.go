package store

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// PartitionedTables are the monthly range-partitioned parents kept by the partition.maintain job (§6.1, §13.5).
// usage_records joins with migration 0016 (P6-T11).
var PartitionedTables = []string{"audit_events"}

// PartitionMonthsAhead is how many months beyond the current one partition.maintain keeps ready (§6.1).
const PartitionMonthsAhead = 3

// PartitionMaintainer runs partition.maintain on its own pool, logged in as mg_partition_maint (separate DSN —
// §6.1, §14.2), which owns the partitioned parents and their partitions and has no other privilege.
type PartitionMaintainer struct {
	pool *pgxpool.Pool
}

// PartitionReport is the outcome for one parent table.
type PartitionReport struct {
	Table   string
	Created []string // partitions created by this run (schema "partitions")
	// DefaultRows > 0 means rows fell into the DEFAULT partition because a month had no partition: alert (§6.1).
	DefaultRows int64
}

// OpenPartitionMaintainer creates the pool and checks that the role owns every parent in PartitionedTables.
func OpenPartitionMaintainer(ctx context.Context, rawURL string, cred Credentials) (*PartitionMaintainer, error) {
	pool, err := newPool(ctx, rawURL, cred, 2)
	if err != nil {
		return nil, fmt.Errorf("store: partition maintainer: %w", err)
	}
	for _, t := range PartitionedTables {
		var owns, privileged bool
		err := pool.QueryRow(ctx, `SELECT c.relowner = r.oid, r.rolsuper OR r.rolbypassrls
			FROM pg_class c, pg_roles r WHERE c.oid = to_regclass($1) AND r.rolname = current_user`, t).Scan(&owns, &privileged)
		if err == nil && (!owns || privileged) {
			err = fmt.Errorf("the login role must own %s and be neither superuser nor BYPASSRLS", t)
		}
		if err != nil {
			pool.Close()
			return nil, fmt.Errorf("store: partition maintainer: %w", err)
		}
	}
	return &PartitionMaintainer{pool: pool}, nil
}

// Close closes the pool.
func (m *PartitionMaintainer) Close() { m.pool.Close() }

// Maintain creates the missing monthly partitions for the current month and monthsAhead months after it (idempotent)
// and reports how many rows sit in each DEFAULT partition. Export + drop of partitions past retention is not part of
// this function yet (first due ≥ 400 days after go-live — §6.4).
func (m *PartitionMaintainer) Maintain(ctx context.Context, monthsAhead int) ([]PartitionReport, error) {
	reports := make([]PartitionReport, 0, len(PartitionedTables))
	for _, t := range PartitionedTables {
		r := PartitionReport{Table: t}
		if err := m.pool.QueryRow(ctx, `SELECT mg_partition_maintain($1::regclass, $2)`, t, monthsAhead).Scan(&r.Created); err != nil {
			return reports, fmt.Errorf("store: partition.maintain %s: %w", t, err)
		}
		if err := m.pool.QueryRow(ctx, `SELECT mg_partition_default_rows($1::regclass)`, t).Scan(&r.DefaultRows); err != nil {
			return reports, fmt.Errorf("store: partition.maintain %s: default rows: %w", t, err)
		}
		reports = append(reports, r)
	}
	return reports, nil
}
