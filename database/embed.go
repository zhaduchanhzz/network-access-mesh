// Package database embeds the SQL of the Management Plane database (§6): the forward-only goose migrations, the
// superuser bootstrap and the CI checks. The .sql files are the source of truth; internal/store runs them.
package database

import "embed"

// Migrations holds migrations/NNNN_*.sql (goose format, forward-only — no Down sections).
//
//go:embed migrations/*.sql
var Migrations embed.FS

// Bootstrap holds bootstrap/superuser.sql, run once by the cluster superuser before the first migration.
//
//go:embed bootstrap/*.sql
var Bootstrap embed.FS

// Checks holds checks/*.sql: read-only queries whose every result row is a violation (CI requires zero rows).
//
//go:embed checks/*.sql
var Checks embed.FS
