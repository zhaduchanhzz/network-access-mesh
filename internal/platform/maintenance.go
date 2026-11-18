package platform

// Maintenance mode of the Management Plane (P3-T17, §17.2): while it is on, the api answers 503 maintenance to every
// request but the platform sign-in on admin.<domain> (httpapi.Options.Maintenance) and the worker runs no job and no
// schedule (apps/internal/runner). Two switches, either one on ⇒ maintenance:
//
//   - the startup switch MG_MAINTENANCE (config.Config.Maintenance) — independent of the database, so api and worker
//     started on a database just restored from an older dump (which does not hold the flag below) are in maintenance
//     from their first request;
//   - the persisted flag, system_settings key `maintenance` (MaintenanceKey): `meshguard admin maintenance on|off`
//     (audited platform.maintenance.enable / .disable) and the first step of `meshguard admin post-restore-reconcile`,
//     which writes it into the restored database (with the post_restore record) so that dropping the startup switch
//     never reopens the API before the reconcile was reviewed. Every process polls it (MaintenanceGate).
//
// Turning the flag off is refused while a post-restore reconcile is recorded running or failed (ErrPostRestorePending)
// unless forced: the reconcile revokes what the restore brought back to life, the API must not serve before it.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// MaintenanceKey is the system_settings key of the persisted maintenance flag.
const MaintenanceKey = "maintenance"

// Audit actions of the flag (platform events, actor_type system — host commands).
const (
	ActionMaintenanceEnable  = "platform.maintenance.enable"
	ActionMaintenanceDisable = "platform.maintenance.disable"
)

// ReasonPostRestore is the reason the post-restore reconcile writes.
const ReasonPostRestore = "post_restore"

// Statuses of the post-restore record.
const (
	PostRestoreRunning    = "running"    // a reconcile started and has not finished (or died)
	PostRestoreReconciled = "reconciled" // the last run finished (Incomplete lists what it could not check)
	PostRestoreFailed     = "failed"     // the last run stopped on an error
)

// DefaultMaintenancePoll is how often a process reads the persisted flag.
const DefaultMaintenancePoll = 5 * time.Second

// reasonRE bounds the reason of `maintenance on` (a stable code or a short slug — never free text).
var reasonRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,63}$`)

// ErrPostRestorePending: the flag cannot be turned off while the post-restore reconcile is running or failed.
var ErrPostRestorePending = errors.New("platform: the post-restore reconcile has not completed")

// Maintenance is the value of system_settings `maintenance` (absent = off).
type Maintenance struct {
	Enabled     bool         `json:"enabled"`
	Reason      string       `json:"reason,omitempty"`
	Since       *time.Time   `json:"since,omitempty"`
	By          string       `json:"by,omitempty"` // the command (or job) that set it
	PostRestore *PostRestore `json:"post_restore,omitempty"`
}

// PostRestore records the reconcile of a PostgreSQL restore (`meshguard admin post-restore-reconcile`).
type PostRestore struct {
	RestorePoint time.Time  `json:"restore_point"` // when the dump was taken (manifest started_at)
	RunID        uuid.UUID  `json:"run_id"`
	Status       string     `json:"status"`
	Runs         int        `json:"runs"`
	StartedAt    time.Time  `json:"started_at"`
	FinishedAt   *time.Time `json:"finished_at,omitempty"`
	// Incomplete names the steps the last run could not complete (agent unreachable, an instance unreachable…).
	Incomplete []string `json:"incomplete,omitempty"`
	// ReviewRequired counts the tenants flagged for review (policy newer on Headscale, orphan instance…).
	ReviewRequired int `json:"review_required,omitempty"`
	// GapRecorded: the audit.gap events of this restore point are written (a later run does not write them again).
	GapRecorded bool `json:"gap_recorded,omitempty"`
}

// ReadMaintenance reads the flag in a platform transaction (absent ⇒ the zero value: off).
func ReadMaintenance(ctx context.Context, q *sqlcdb.Queries) (Maintenance, error) {
	row, err := q.GetSystemSetting(ctx, MaintenanceKey)
	if errors.Is(err, store.ErrNoRows) {
		return Maintenance{}, nil
	}
	if err != nil {
		return Maintenance{}, err
	}
	var m Maintenance
	if err := json.Unmarshal(row.Value, &m); err != nil {
		// an unreadable value is treated as ON: a damaged flag never opens the API
		return Maintenance{Enabled: true, Reason: "unreadable_setting"}, fmt.Errorf("platform: system_settings %s: %w", MaintenanceKey, err)
	}
	return m, nil
}

// LockMaintenance serialises the writers of the flag (transaction-scoped advisory lock).
func LockMaintenance(ctx context.Context, q *sqlcdb.Queries) error {
	return q.LockSystemSettingKey(ctx, MaintenanceKey)
}

// WriteMaintenance stores the flag in the platform transaction q.
func WriteMaintenance(ctx context.Context, q *sqlcdb.Queries, m Maintenance) error {
	raw, err := json.Marshal(m)
	if err != nil {
		return err
	}
	_, err = q.UpsertSystemSetting(ctx, sqlcdb.UpsertSystemSettingParams{Key: MaintenanceKey, Value: raw})
	return err
}

// MaintenanceChange is one `meshguard admin maintenance on|off`.
type MaintenanceChange struct {
	Enable bool
	Reason string // stable code or a short text (on), [a-z0-9_.-], ≤ 64
	// Force turns the flag off although the post-restore reconcile is recorded running or failed.
	Force bool
	Actor SystemActor
}

// MaintenanceResult is the flag before and after a change.
type MaintenanceResult struct {
	Before, After Maintenance
	Changed       bool
}

// Maintenance reads the persisted flag.
func (s *Service) Maintenance(ctx context.Context) (Maintenance, error) {
	var m Maintenance
	err := s.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		var err error
		m, err = ReadMaintenance(ctx, q)
		return err
	})
	return m, err
}

// SetMaintenance turns the persisted flag on or off, audited in the same platform transaction. Setting the state it
// already has changes and audits nothing. Off is refused with ErrPostRestorePending while a post-restore reconcile is
// running or failed, unless forced (the event then says so).
func (s *Service) SetMaintenance(ctx context.Context, c MaintenanceChange) (MaintenanceResult, error) {
	reason := strings.TrimSpace(c.Reason)
	if c.Enable && reason == "" {
		reason = "operator"
	}
	if reason != "" && !reasonRE.MatchString(reason) {
		return MaintenanceResult{}, fmt.Errorf("%w: reason must be 1–64 characters of [a-z0-9_.-]", ErrInvalid)
	}
	var res MaintenanceResult
	err := s.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		if err := LockMaintenance(ctx, q); err != nil {
			return err
		}
		before, err := ReadMaintenance(ctx, q)
		if err != nil && !c.Enable {
			return err // never turn off a flag that cannot be read
		}
		res.Before = before
		after := before
		pending := before.PostRestore != nil && (before.PostRestore.Status == PostRestoreRunning ||
			before.PostRestore.Status == PostRestoreFailed)
		switch {
		case c.Enable && before.Enabled:
			res.After = before
			return nil
		case !c.Enable && !before.Enabled && err == nil:
			res.After = before
			return nil
		case !c.Enable && pending && !c.Force:
			return fmt.Errorf("%w (status %s, restore point %s): run it again or pass --force", ErrPostRestorePending,
				before.PostRestore.Status, before.PostRestore.RestorePoint.UTC().Format(time.RFC3339))
		}
		now, err := q.PostRestoreNow(ctx)
		if err != nil {
			return err
		}
		after.Enabled = c.Enable
		if c.Enable {
			after.Reason, after.Since, after.By = reason, &now, c.Actor.Command
		} else {
			after.Reason, after.Since, after.By = "", nil, ""
		}
		if err := WriteMaintenance(ctx, q, after); err != nil {
			return err
		}
		action, details := ActionMaintenanceEnable, audit.Details{"reason": reason}
		if !c.Enable {
			action = ActionMaintenanceDisable
			details = audit.Details{"previous_reason": before.Reason, "forced": c.Force && pending}
		}
		if before.PostRestore != nil {
			details["post_restore_status"] = before.PostRestore.Status
			details["restore_point"] = before.PostRestore.RestorePoint.UTC()
		}
		if err := audit.Record(ctx, q, audit.Event{ActorType: audit.ActorSystem, ActorDisplay: c.Actor.Command,
			RequestID: c.Actor.RequestID, Action: action, ResourceType: "system_setting", ResourceID: MaintenanceKey,
			Details: details}); err != nil {
			return err
		}
		res.After, res.Changed = after, true
		return nil
	})
	return res, err
}

// MaintenanceGate is a process's view of maintenance mode: the startup switch OR the persisted flag, read every Poll.
type MaintenanceGate struct {
	st     *store.Store
	forced bool
	poll   time.Duration
	log    *slog.Logger

	on      atomic.Bool
	mu      sync.Mutex
	persist Maintenance
	known   bool
	listen  []func(on bool)
}

// MaintenanceGateOptions configure a gate.
type MaintenanceGateOptions struct {
	Forced bool          // MG_MAINTENANCE
	Poll   time.Duration // 0 ⇒ DefaultMaintenancePoll
	Logger *slog.Logger
}

// NewMaintenanceGate returns a gate over st's platform pool. Until its first successful read it reports ON (fail
// closed): call Refresh at start-up.
func NewMaintenanceGate(st *store.Store, opts MaintenanceGateOptions) *MaintenanceGate {
	g := &MaintenanceGate{st: st, forced: opts.Forced, poll: opts.Poll, log: opts.Logger}
	if g.poll <= 0 {
		g.poll = DefaultMaintenancePoll
	}
	if g.log == nil {
		g.log = slog.New(slog.DiscardHandler)
	}
	g.on.Store(true)
	return g
}

// On reports whether the process is in maintenance mode now.
func (g *MaintenanceGate) On() bool { return g.on.Load() }

// Forced reports whether the startup switch is set.
func (g *MaintenanceGate) Forced() bool { return g.forced }

// State returns the persisted flag as last read and whether it was read at all.
func (g *MaintenanceGate) State() (Maintenance, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.persist, g.known
}

// OnChange registers fn, called (from the polling goroutine or Refresh) after every transition with the new state.
func (g *MaintenanceGate) OnChange(fn func(on bool)) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.listen = append(g.listen, fn)
}

// Refresh reads the persisted flag and updates the state. A read error keeps the previous state (ON before the first
// successful read) and is returned.
func (g *MaintenanceGate) Refresh(ctx context.Context) (bool, error) {
	var m Maintenance
	err := g.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		var err error
		m, err = ReadMaintenance(ctx, q)
		return err
	})
	if err != nil && !m.Enabled {
		return g.On(), err
	}
	g.mu.Lock()
	g.persist, g.known = m, true
	listeners := append([]func(bool){}, g.listen...)
	g.mu.Unlock()
	now := g.forced || m.Enabled
	if was := g.on.Swap(now); was != now {
		g.log.Warn("maintenance mode changed", "on", now, "startup_switch", g.forced, "persisted", m.Enabled,
			"reason", m.Reason)
		for _, fn := range listeners {
			fn(now)
		}
	}
	return now, err
}

// Run polls the flag until ctx is cancelled.
func (g *MaintenanceGate) Run(ctx context.Context) error {
	t := time.NewTicker(g.poll)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
		if _, err := g.Refresh(ctx); err != nil && ctx.Err() == nil {
			g.log.Warn("maintenance flag unreadable — previous state kept", "on", g.On(), "error", err.Error())
		}
	}
}
