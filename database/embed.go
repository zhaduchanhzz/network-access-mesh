// Package database embeds the SQL of the Management Plane database (§6): the forward-only goose migrations, the
// seeds applied after them, the superuser bootstrap, the privileges of the job queue schema and the CI checks. The
// .sql files are the source of truth; internal/store runs them.
package database

import "embed"

// Migrations holds migrations/NNNN_*.sql (goose format, forward-only — no Down sections).
//
//go:embed migrations/*.sql
var Migrations embed.FS

// Seeds holds seeds/*.sql: idempotent reference data applied after every migration run, in file-name order
// (seeds/plans.sql — the default plan, inserted only when missing, P3-T06; seeds/rbac.sql — roles, permissions and
// grants generated from §8.4–§8.6 by tools/openapi_lint.py, P2-T07).
//
//go:embed seeds/*.sql
var Seeds embed.FS

// Bootstrap holds bootstrap/superuser.sql, run once by the cluster superuser before the first migration.
//
//go:embed bootstrap/*.sql
var Bootstrap embed.FS

// Checks holds checks/*.sql: read-only queries whose every result row is a violation (CI requires zero rows).
//
//go:embed checks/*.sql
var Checks embed.FS

// River holds river/grants.sql, the privileges on the River job queue schema, applied after every River migration
// (the tables are created by River's own migrator, not by goose — P2-T12).
//
//go:embed river/*.sql
var River embed.FS
