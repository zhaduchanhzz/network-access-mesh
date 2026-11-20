// Package auditsync is the job idp.audit_sync (P3-T15; §8.2 "Quản trị IdP không được là cửa sau vào tenant", §13.5):
// every minute it reads the admin events and the relevant login events of every realm of the platform-hosted Keycloak
// and imports each event exactly once:
//
//   - the realm of a tenant's IdP (identity_providers, driver keycloak) ⇒ one audit_events row of that tenant
//     (actor_type system, occurred_at = the event's time, actor_ip = the address Keycloak saw, details: the classified
//     operation, who acted — the realm's driver, the provisioning identity or a Keycloak administrator of the master
//     realm —, the affected user and the allow-listed fields of the representation, never the representation itself),
//     a notification idp.admin_change to the Tenant Owners (every change a person made, and the sensitive ones —
//     credentials, roles, clients, the realm — whoever made them) and a tenant security event for an impersonation
//     (critical) and for a credential reset or removal by a non-tenant actor (high);
//   - the realm of the platform IdP ⇒ the same as platform events (no Owner to notify);
//   - the master realm ⇒ platform events: every sign-in to the Keycloak administration (console or admin CLI) is a
//     platform audit row idp.console.login, a security event idp.console_login (high; a failed one medium) and a
//     platform notification idp.console_login to the Super Admins and Platform Operators — grouped per source
//     (account, client, address) and window (Config.ConsoleLoginWindow, consolewindow.go: the first sign-in at once,
//     the next ones of the window in one summary — F-G3-2); its admin events are platform audit rows (role mappings
//     and clients of master raise security events).
//
// Reading: through the keycloak driver (the narrow platform route to auth.<domain>, the provisioning identity — it holds
// view-events of every realm it created or adopted, and exactly view-events of master-realm and of the platform realm:
// Bootstrap, infrastructure/idp/realm-update.sh). Pages of at most 100 events, oldest first, from a cursor (time in
// milliseconds + the ids already imported at that millisecond) kept per realm and kind in system_settings
// (idp.audit_sync.<admin|events>.<realm>). Exactly once: the audit row, the security event and the notification of an
// event are written in one transaction that first takes an advisory lock on the event and checks that no audit row of
// it exists — the cursor only saves re-reading; a lost or stale cursor never duplicates an event.
//
// A realm that cannot be read (no view-events, IdP down) is skipped with a security event idp.audit_sync_failed
// (deduplicated per realm and day) and a metric; a realm whose events or admin events are switched off raises
// idp.audit_events_disabled (high). Before the provisioning identity is bootstrapped the job does nothing.
package auditsync

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/idp"
	"github.com/zhaduchanhzz/network-access-mesh/internal/idp/keycloak"
	"github.com/zhaduchanhzz/network-access-mesh/internal/notifications"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// JobKind is the job of §13.5; Interval its schedule.
const (
	JobKind  = "idp.audit_sync"
	Interval = time.Minute
)

// Defaults.
const (
	// DefaultLookback is how far back the first sync of a realm reads: Keycloak keeps events 30 days (realm template
	// eventsExpiration/adminEventsExpiration — P2-T05).
	DefaultLookback = 30 * 24 * time.Hour
	// DefaultMaxPages bounds the pages read per realm and kind in one run; the rest waits for the next run.
	DefaultMaxPages = 20
	// failureDedupe is the window of the security events about a realm that cannot be read or audits nothing.
	failureDedupe = 24 * time.Hour
	source        = "idp.audit_sync"
)

// Source reads the events of the platform-hosted Keycloak (*keycloak.Driver).
type Source interface {
	AdminEvents(ctx context.Context, realm string, q keycloak.EventQuery) ([]keycloak.AdminEvent, error)
	UserEvents(ctx context.Context, realm string, q keycloak.EventQuery) ([]keycloak.UserEvent, error)
	EventsConfig(ctx context.Context, realm string) (keycloak.EventsConfig, error)
	ClientUUID(ctx context.Context, realm, clientID string) (string, error)
	ProvisionerUserID(ctx context.Context) (string, error)
	ProvisionerClientID() string
	RealmOfIssuer(issuer string) (string, bool)
}

var _ Source = (*keycloak.Driver)(nil)

// Config configures the Syncer. Source is required.
type Config struct {
	Source   Source
	Notifier notifications.Enqueuer // nil ⇒ notifications.Default
	Lookback time.Duration          // 0 ⇒ DefaultLookback
	MaxPages int                    // 0 ⇒ DefaultMaxPages
	PageSize int                    // 0 ⇒ keycloak.EventPageMax

	// ConsoleLoginWindow groups the console sign-in e-mails per source (consolewindow.go): 0 ⇒ one e-mail per sign-in
	// (no grouping). The worker sets MG_IDP_CONSOLE_LOGIN_NOTIFY_WINDOW (default 10m — internal/config).
	ConsoleLoginWindow time.Duration

	Now        func() time.Time
	Logger     *slog.Logger
	Registerer prometheus.Registerer // nil ⇒ metrics not registered
}

// Syncer is the job.
type Syncer struct {
	st  *store.Store
	cfg Config
	log *slog.Logger
	mu  sync.Mutex // one run at a time in this process (the scheduler may start a run while the last one still reads)
	m   metrics
}

type metrics struct {
	imported *prometheus.CounterVec // {scope, kind}
	logins   *prometheus.CounterVec // {outcome}
	failures *prometheus.CounterVec // {reason}
	last     prometheus.Gauge
}

// New returns the job over st (the worker's store).
func New(st *store.Store, cfg Config) (*Syncer, error) {
	if st == nil || cfg.Source == nil {
		return nil, errors.New("auditsync: a store and a source are required")
	}
	if cfg.Notifier == nil {
		cfg.Notifier = notifications.Default
	}
	if cfg.Lookback <= 0 {
		cfg.Lookback = DefaultLookback
	}
	if cfg.MaxPages <= 0 {
		cfg.MaxPages = DefaultMaxPages
	}
	if cfg.PageSize <= 0 || cfg.PageSize > keycloak.EventPageMax {
		cfg.PageSize = keycloak.EventPageMax
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	s := &Syncer{st: st, cfg: cfg, log: cfg.Logger.With("module", "idp", "job", JobKind)}
	s.m = metrics{
		imported: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "meshguard_idp_audit_events_imported_total",
			Help: "Keycloak events imported into audit_events by idp.audit_sync (scope: tenant, platform, master; kind: admin, user)."},
			[]string{"scope", "kind"}),
		logins: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "meshguard_idp_console_logins_total",
			Help: "Sign-ins to the Keycloak administration (master realm) seen by idp.audit_sync, by outcome."},
			[]string{"outcome"}),
		failures: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "meshguard_idp_audit_sync_failures_total",
			Help: "Realms idp.audit_sync could not read or write, by reason."}, []string{"reason"}),
		last: prometheus.NewGauge(prometheus.GaugeOpts{Name: "meshguard_idp_audit_sync_last_success_timestamp_seconds",
			Help: "Unix time of the last idp.audit_sync run that read every realm."}),
	}
	if cfg.Registerer != nil {
		for _, c := range []prometheus.Collector{s.m.imported, s.m.logins, s.m.failures, s.m.last} {
			if err := cfg.Registerer.Register(c); err != nil {
				return nil, fmt.Errorf("auditsync: metrics: %w", err)
			}
		}
	}
	return s, nil
}

// Target is one realm to read.
type Target struct {
	Realm    string
	Kind     RealmKind
	IdPID    uuid.UUID  // identity_providers.id (uuid.Nil for master)
	TenantID *uuid.UUID // the tenant of a tenant realm
}

func (t Target) scope() string {
	return map[RealmKind]string{RealmTenant: "tenant", RealmPlatform: "platform", RealmMaster: "master"}[t.Kind]
}

// Summary is what one run did.
type Summary struct {
	Skipped  bool // the provisioning identity is not bootstrapped yet
	Realms   int
	Failed   []string // realms that could not be read
	Imported int
}

// Run is one pass over every realm (the handler of the periodic job; `meshguard-worker admin idp-audit-sync` runs it
// once). A realm that cannot be read is recorded and skipped; an error is returned only when the database fails.
func (s *Syncer) Run(ctx context.Context) error {
	_, err := s.RunOnce(ctx)
	return err
}

// RunOnce is Run with its summary.
func (s *Syncer) RunOnce(ctx context.Context) (Summary, error) {
	if !s.mu.TryLock() {
		s.log.InfoContext(ctx, "idp.audit_sync: a run is still in progress in this process — skipped")
		return Summary{Skipped: true}, nil
	}
	defer s.mu.Unlock()
	var sum Summary
	// the windows of the console sign-in e-mails that ended are flushed first, whatever the IdP's state (F-G3-2)
	if err := s.flushConsoleWindows(ctx); err != nil {
		return sum, err
	}
	prov, err := s.cfg.Source.ProvisionerUserID(ctx)
	if err != nil {
		if c := idp.CodeOf(err); c == idp.CodeCredentials || c == idp.CodeUnauthenticated {
			s.log.WarnContext(ctx, "idp.audit_sync: the provisioning identity is not usable (not bootstrapped?) — nothing read",
				"code", string(c))
			s.m.failures.WithLabelValues("provisioner").Inc()
			sum.Skipped = true
			return sum, nil
		}
		s.m.failures.WithLabelValues("idp_unavailable").Inc()
		s.log.WarnContext(ctx, "idp.audit_sync: the IdP is not reachable — nothing read", "code", string(idp.CodeOf(err)))
		sum.Skipped = true
		return sum, nil
	}
	targets, err := s.Targets(ctx)
	if err != nil {
		return sum, err
	}
	sum.Realms = len(targets)
	for _, t := range targets {
		n, err := s.syncRealm(ctx, t, prov)
		sum.Imported += n
		var dbErr *dbError
		switch {
		case errors.As(err, &dbErr):
			return sum, dbErr.err
		case err != nil:
			sum.Failed = append(sum.Failed, t.Realm)
			s.realmFailed(ctx, t, err)
		}
	}
	if len(sum.Failed) == 0 {
		s.m.last.SetToCurrentTime()
	}
	s.log.InfoContext(ctx, "idp.audit_sync: run done", "realms", sum.Realms, "imported", sum.Imported,
		"failed", strings.Join(sum.Failed, ","))
	return sum, nil
}

// dbError marks a failure of our own database (the run fails and the job retries) — every other error is the IdP's.
type dbError struct{ err error }

func (e *dbError) Error() string { return "auditsync: database: " + e.err.Error() }
func (e *dbError) Unwrap() error { return e.err }

// Targets lists the realms to read: master first (console logins), then every IdP the platform hosts (driver
// keycloak), deduplicated by realm.
func (s *Syncer) Targets(ctx context.Context) ([]Target, error) {
	out := []Target{{Realm: keycloak.MasterRealm, Kind: RealmMaster}}
	seen := map[string]bool{keycloak.MasterRealm: true}
	err := s.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		rows, err := q.ListKeycloakIdentityProviders(ctx)
		if err != nil {
			return err
		}
		for _, r := range rows {
			realm, ok := s.cfg.Source.RealmOfIssuer(r.Issuer)
			if !ok || seen[realm] {
				if !ok {
					s.log.WarnContext(ctx, "idp.audit_sync: a keycloak IdP whose issuer is not of the platform IdP — skipped",
						"idp_id", r.ID.String())
				}
				continue
			}
			seen[realm] = true
			t := Target{Realm: realm, IdPID: r.ID, Kind: RealmPlatform}
			if r.Scope == "tenant" && r.TenantID != nil {
				t.Kind, t.TenantID = RealmTenant, r.TenantID
			}
			out = append(out, t)
		}
		return nil
	})
	return out, err
}

// syncRealm reads and imports the events of one realm; it returns how many it imported.
func (s *Syncer) syncRealm(ctx context.Context, t Target, provisionerUserID string) (int, error) {
	src := s.cfg.Source
	cfg, err := src.EventsConfig(ctx, t.Realm)
	if err != nil {
		return 0, err
	}
	if !cfg.EventsEnabled || !cfg.AdminEventsEnabled {
		s.security(ctx, t, audit.SecurityEvent{Kind: KindAuditDisabled, Severity: audit.SeverityHigh, Source: source,
			Details:   audit.Details{"realm": t.Realm, "events_enabled": cfg.EventsEnabled, "admin_events_enabled": cfg.AdminEventsEnabled},
			DedupeKey: KindAuditDisabled + ":" + t.Realm, DedupeWindow: failureDedupe})
	}
	actors := Actors{ProvisionerUserID: provisionerUserID}
	if t.Kind == RealmTenant {
		// the realm's own driver service account; a realm the identity cannot list clients of leaves it unknown (its
		// actions are then attributed to a user of the realm — still imported, still notified)
		if id, err := src.ClientUUID(ctx, t.Realm, keycloak.DriverClientID); err == nil {
			actors.DriverClientUUID = id
		}
	}
	n1, err := s.syncAdmin(ctx, t, actors)
	if err != nil {
		return n1, err
	}
	n2, err := s.syncUser(ctx, t, src.ProvisionerClientID())
	return n1 + n2, err
}

// syncAdmin imports the admin events of t from its cursor.
func (s *Syncer) syncAdmin(ctx context.Context, t Target, actors Actors) (int, error) {
	return s.page(ctx, t, "admin", nil, func(q keycloak.EventQuery) ([]event, error) {
		evs, err := s.cfg.Source.AdminEvents(ctx, t.Realm, q)
		out := make([]event, 0, len(evs))
		for _, ev := range evs {
			out = append(out, event{id: ev.ID, ms: ev.Time, admin: &ev})
		}
		return out, err
	}, func(e event) (Record, bool) {
		return classifyAdmin(*e.admin, t.Kind, actors.ActorOf(*e.admin, t.Kind)), true
	})
}

// syncUser imports the login/user events of t of the types that matter for its kind.
func (s *Syncer) syncUser(ctx context.Context, t Target, provisionerClient string) (int, error) {
	types := realmEventTypes
	if t.Kind == RealmMaster {
		types = masterEventTypes
	}
	return s.page(ctx, t, "events", types, func(q keycloak.EventQuery) ([]event, error) {
		evs, err := s.cfg.Source.UserEvents(ctx, t.Realm, q)
		out := make([]event, 0, len(evs))
		for _, ev := range evs {
			out = append(out, event{id: ev.ID, ms: ev.Time, user: &ev})
		}
		return out, err
	}, func(e event) (Record, bool) { return classifyUser(*e.user, t.Kind, provisionerClient) })
}

type event struct {
	id    string
	ms    int64
	admin *keycloak.AdminEvent
	user  *keycloak.UserEvent
}

// page reads pages of events of one kind from the cursor and imports each one, saving the cursor after every page.
func (s *Syncer) page(ctx context.Context, t Target, kind string, types []string, read func(keycloak.EventQuery) ([]event, error),
	classify func(event) (Record, bool),
) (int, error) {
	key := CursorKey(kind, t.Realm)
	cur, err := s.loadCursor(ctx, key)
	if err != nil {
		return 0, &dbError{err}
	}
	if cur.TimeMs == 0 {
		cur.TimeMs = s.cfg.Now().Add(-s.cfg.Lookback).UnixMilli()
	}
	from, imported := cur.TimeMs, 0
	for p := 0; p < s.cfg.MaxPages; p++ {
		evs, err := read(keycloak.EventQuery{FromMillis: from, First: p * s.cfg.PageSize, Max: s.cfg.PageSize, Types: types})
		if err != nil {
			return imported, err
		}
		slices.SortStableFunc(evs, func(a, b event) int { // Keycloak sorts by time; ties keep its order
			switch {
			case a.ms < b.ms:
				return -1
			case a.ms > b.ms:
				return 1
			}
			return 0
		})
		for _, e := range evs {
			if cur.Done(e.id, e.ms) {
				continue
			}
			if r, ok := classify(e); ok {
				wrote, err := s.write(ctx, t, r)
				if err != nil {
					_ = s.saveCursor(ctx, key, cur) // keep what is done
					return imported, &dbError{err}
				}
				if wrote {
					imported++
					s.m.imported.WithLabelValues(t.scope(), kind).Inc()
					if r.Action == "idp.console.login" {
						s.m.logins.WithLabelValues(r.Outcome).Inc()
					}
				}
			}
			cur.Advance(e.id, e.ms)
		}
		if err := s.saveCursor(ctx, key, cur); err != nil {
			return imported, &dbError{err}
		}
		if len(evs) < s.cfg.PageSize {
			break
		}
	}
	return imported, nil
}

// write imports one record in one transaction (tenant scope for a tenant realm, platform otherwise): advisory lock on
// the event, the audit row if none exists yet, the security event, the notification. It reports whether it wrote.
func (s *Syncer) write(ctx context.Context, t Target, r Record) (bool, error) {
	if r.EventID == "" || r.At.IsZero() {
		return false, nil
	}
	r.Details["idp_realm"] = t.Realm
	var wrote bool
	fn := func(tx *store.Tx) error {
		q := tx.Q
		if err := q.LockIdPEvent(ctx, "meshguard:idp-event:"+t.Realm+":"+r.EventID); err != nil {
			return err
		}
		var done bool
		var err error
		if t.TenantID != nil {
			done, err = q.TenantIdPEventImported(ctx, sqlcdb.TenantIdPEventImportedParams{TenantID: *t.TenantID,
				OccurredAt: r.At, EventID: r.EventID})
		} else {
			done, err = q.PlatformIdPEventImported(ctx, sqlcdb.PlatformIdPEventImportedParams{OccurredAt: r.At, EventID: r.EventID})
		}
		if err != nil || done {
			return err
		}
		user := ""
		if r.UserSub != "" && t.IdPID != uuid.Nil {
			idt, err := q.GetIdentityBySubject(ctx, sqlcdb.GetIdentityBySubjectParams{IdpID: t.IdPID, Subject: r.UserSub})
			switch {
			case err == nil:
				r.Details["identity_id"] = idt.ID
				user = displayOf(idt)
			case !errors.Is(err, store.ErrNoRows):
				return err
			}
		}
		ev := audit.Event{TenantID: t.TenantID, ActorType: audit.ActorSystem, ActorDisplay: r.ActorDisplay,
			ActorIP: r.ActorIP, Action: r.Action, ResourceType: r.ResourceType, ResourceID: r.ResourceID,
			Outcome: r.Outcome, Details: r.Details, OccurredAt: r.At}
		if err := audit.Record(ctx, q, ev); err != nil {
			return err
		}
		if r.Security != nil {
			d := audit.Details{"idp_event_id": r.EventID, "idp_realm": t.Realm, "action": r.Action,
				"idp_actor_kind": r.ActorKind, "occurred_at": r.At}
			for _, k := range []string{"idp_user_id", "identity_id", "idp_client", "username", "idp_error"} {
				if v, ok := r.Details[k]; ok {
					d[k] = v
				}
			}
			if r.ActorIP.IsValid() {
				d["ip"] = r.ActorIP
			}
			if _, err := audit.RecordSecurityEvent(ctx, q, audit.SecurityEvent{TenantID: t.TenantID, Kind: r.Security.Kind,
				Severity: r.Security.Severity, Source: source, Details: d, DedupeKey: "idp-event:" + r.EventID,
				DedupeWindow: DefaultLookback}); err != nil {
				return err
			}
		}
		if r.Notify {
			var ns []notifications.Event
			switch {
			case t.Kind == RealmTenant && t.TenantID != nil:
				n := notifications.IdPAdminChange(*t.TenantID, r.EventID, r.Action, r.ActorDisplay, user, r.At)
				if r.ActorKind != "" { // the Portal names the actor by kind in the reader's language (G4b-E13)
					n.Payload["actor_kind"] = r.ActorKind
				}
				ns = append(ns, n)
			case r.ConsoleLogin:
				ip := ""
				if r.ActorIP.IsValid() {
					ip = r.ActorIP.String()
				}
				if ns, err = s.consoleLoginNotices(ctx, q, r, ip); err != nil {
					return err
				}
			}
			for _, n := range ns {
				if _, err := s.cfg.Notifier.Enqueue(ctx, tx, n); err != nil {
					return err
				}
			}
		}
		wrote = true
		return nil
	}
	var err error
	if t.TenantID != nil {
		err = s.st.WithTenantJobTx(ctx, *t.TenantID, fn)
	} else {
		err = s.st.WithPlatformJobTx(ctx, fn)
	}
	if err != nil {
		return false, err
	}
	if wrote && r.Security != nil {
		s.log.WarnContext(ctx, "idp.audit_sync: security event", "kind", r.Security.Kind, "severity", r.Security.Severity,
			"realm", t.Realm, "event_id", r.EventID, "action", r.Action)
	}
	return wrote, nil
}

// displayOf is the name of an identity shown to the Owners (never its subject alone when a name exists).
func displayOf(i sqlcdb.Identity) string {
	for _, v := range []*string{i.DisplayName, i.Email} {
		if v != nil && *v != "" && len(*v) <= 200 && !strings.ContainsAny(*v, "\r\n") && !strings.Contains(*v, "://") {
			return *v
		}
	}
	return i.Subject
}

// realmFailed records a realm that could not be read: a metric, a log line and a platform security event (one per
// realm and day — a realm the provisioning identity cannot read is a gap in the audit trail).
func (s *Syncer) realmFailed(ctx context.Context, t Target, err error) {
	code := string(idp.CodeOf(err))
	s.m.failures.WithLabelValues(code).Inc()
	s.log.WarnContext(ctx, "idp.audit_sync: realm not read", "realm", t.Realm, "code", code, "error", err.Error())
	s.security(ctx, Target{Kind: RealmPlatform}, audit.SecurityEvent{Kind: KindAuditSyncFailed, Severity: audit.SeverityMedium,
		Source: source, Details: audit.Details{"realm": t.Realm, "code": code},
		DedupeKey: KindAuditSyncFailed + ":" + t.Realm, DedupeWindow: failureDedupe})
}

// security writes a security event in a transaction of its own (tenant scope for a tenant target).
func (s *Syncer) security(ctx context.Context, t Target, ev audit.SecurityEvent) {
	ev.TenantID = t.TenantID
	fn := func(q *sqlcdb.Queries) error {
		_, err := audit.RecordSecurityEvent(ctx, q, ev)
		return err
	}
	var err error
	if t.TenantID != nil {
		err = s.st.WithTenantTx(ctx, *t.TenantID, fn)
	} else {
		err = s.st.WithPlatformTx(ctx, fn)
	}
	if err != nil {
		s.log.ErrorContext(ctx, "idp.audit_sync: security event not recorded", "kind", ev.Kind, "error", err.Error())
	}
}

// ---------------------------------------------------------------- cursor

// Cursor is where the reading of one realm and kind stands: the time of the newest event imported (milliseconds) and
// the ids of the events of that very millisecond already imported (Keycloak's dateFrom is inclusive).
type Cursor struct {
	TimeMs int64    `json:"time_ms"`
	IDs    []string `json:"ids,omitempty"`
}

// Done reports whether the event (id, ms) is at or before the cursor.
func (c Cursor) Done(id string, ms int64) bool {
	return ms < c.TimeMs || (ms == c.TimeMs && slices.Contains(c.IDs, id))
}

// Advance moves the cursor past the event (id, ms) (events come oldest first).
func (c *Cursor) Advance(id string, ms int64) {
	switch {
	case ms > c.TimeMs:
		c.TimeMs, c.IDs = ms, []string{id}
	case ms == c.TimeMs && !slices.Contains(c.IDs, id) && len(c.IDs) < 1000:
		c.IDs = append(c.IDs, id)
	}
}

// CursorKey is the system_settings key of a cursor (keys allow [a-z0-9_.]; realm names [a-z0-9-]).
func CursorKey(kind, realm string) string {
	return "idp.audit_sync." + kind + "." + strings.ReplaceAll(realm, "-", "_")
}

func (s *Syncer) loadCursor(ctx context.Context, key string) (Cursor, error) {
	var c Cursor
	err := s.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		row, err := q.GetSystemSetting(ctx, key)
		if errors.Is(err, store.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if json.Unmarshal(row.Value, &c) != nil || c.TimeMs < 0 {
			s.log.WarnContext(ctx, "idp.audit_sync: unreadable cursor — reading from the lookback", "key", key)
			c = Cursor{}
		}
		return nil
	})
	if c.TimeMs > s.cfg.Now().Add(time.Hour).UnixMilli() { // a cursor in the future would hide events: never trusted
		s.log.WarnContext(ctx, "idp.audit_sync: cursor in the future — reading from the lookback", "key", key)
		c = Cursor{}
	}
	return c, err
}

func (s *Syncer) saveCursor(ctx context.Context, key string, c Cursor) error {
	b, err := json.Marshal(c)
	if err != nil {
		return err
	}
	return s.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		_, err := q.UpsertSystemSetting(ctx, sqlcdb.UpsertSystemSettingParams{Key: key, Value: b})
		return err
	})
}
