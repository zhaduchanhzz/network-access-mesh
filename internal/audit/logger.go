package audit

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// Defaults of Config.
const (
	DefaultTimeout              = 3 * time.Second
	DefaultCrossTenantThreshold = 5
	DefaultCrossTenantWindow    = 10 * time.Minute
	// criticalTargets distinct target tenants within the window raise the security event to critical (probing
	// across tenants rather than a stale link to one).
	criticalTargets = 3
)

// Config tunes a Logger; the zero value is valid.
type Config struct {
	Log        *slog.Logger          // nil discards
	Registerer prometheus.Registerer // nil: the metrics are kept but not registered
	// Timeout bounds one write of the detached, committed or security path, measured from the call — not from the
	// request, whose cancellation those writes ignore. 0 = DefaultTimeout.
	Timeout time.Duration
	// CrossTenantThreshold and CrossTenantWindow are the rule of §8.8 "chuỗi từ chối chéo tenant bất thường": an actor
	// denied CrossTenantThreshold times on tenants other than its own within CrossTenantWindow raises one security
	// event per window. 0 = DefaultCrossTenantThreshold / DefaultCrossTenantWindow.
	CrossTenantThreshold int
	CrossTenantWindow    time.Duration
}

// Logger is the AuditLogger of §4.2: it owns the detached path (store.AuditWriter, mg_audit_writer) and uses the
// application pools of the process for events reported after their commit, security events and the checks of Finish.
// Record and Requested (package functions) need no Logger: they write in the caller's business transaction.
type Logger struct {
	st  *store.Store
	w   *store.AuditWriter
	cfg Config
	log *slog.Logger
	m   *metrics
}

// New returns a Logger writing denied and failure events through w and everything else through st.
func New(st *store.Store, w *store.AuditWriter, cfg Config) (*Logger, error) {
	if st == nil || w == nil {
		return nil, errors.New("audit: a store and the detached audit writer are required")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultTimeout
	}
	if cfg.CrossTenantThreshold <= 0 {
		cfg.CrossTenantThreshold = DefaultCrossTenantThreshold
	}
	if cfg.CrossTenantWindow <= 0 {
		cfg.CrossTenantWindow = DefaultCrossTenantWindow
	}
	l := &Logger{st: st, w: w, cfg: cfg, log: cfg.Log, m: newMetrics(cfg.Registerer)}
	if l.log == nil {
		l.log = slog.New(slog.DiscardHandler)
	}
	return l, nil
}

// Write paths, the label of meshguard_audit_write_failures_total.
const (
	pathDetached  = "detached"
	pathCommitted = "committed"
	pathSecurity  = "security"
	pathRule      = "cross_tenant_rule"
	pathPairing   = "pairing"
)

// writeContext detaches a write from the cancellation of the request (a client that goes away must not erase the
// audit of its denial) and bounds it by Config.Timeout.
func (l *Logger) writeContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), l.cfg.Timeout)
}

// RecordDetached writes a denied or failure event on the detached path (§6.1): its own connection as mg_audit_writer,
// outside any business transaction and of the request's cancellation, so the event survives a rollback. The tenant is
// never inherited from the request scope (Event.TenantID); other unset fields are. A denial of a tenant other than the
// actor's (TargetTenantID set) then feeds the cross-tenant rule (Config.CrossTenantThreshold). A failed write is
// logged at ERROR and counted (meshguard_audit_write_failures_total) besides being returned.
func (l *Logger) RecordDetached(ctx context.Context, ev Event) error {
	fill(ctx, &ev, RequestFrom(ctx), false)
	err := ev.normalize()
	if err == nil && ev.Outcome == OutcomeSuccess {
		err = fmt.Errorf("%w: the detached path is for denied and failure events (§6.1)", ErrInvalidEvent)
	}
	var p sqlcdb.AppendAuditEventParams
	if err == nil {
		p, err = ev.params()
	}
	if err == nil {
		wctx, cancel := l.writeContext(ctx)
		err = l.w.Append(wctx, p)
		cancel()
	}
	if err != nil {
		l.failed(ctx, pathDetached, ev, err)
		return err
	}
	if ev.Outcome == OutcomeDenied && ev.TargetTenantID != nil {
		l.crossTenantRule(ctx, ev)
	}
	return nil
}

// RecordCommitted writes an event reported after its business transaction committed — the identity module calls its
// Auditor after commit (P2-T06) — in a transaction of its own with the application role (RLS checks the tenant). Use
// Record when the business transaction is at hand: only it commits the event with the change.
func (l *Logger) RecordCommitted(ctx context.Context, ev Event) error {
	fill(ctx, &ev, RequestFrom(ctx), false)
	wctx, cancel := l.writeContext(ctx)
	defer cancel()
	err := l.inScope(wctx, ev.TenantID, func(q *sqlcdb.Queries) error { return appendTx(wctx, q, &ev) })
	if err != nil {
		l.failed(ctx, pathCommitted, ev, err)
	}
	return err
}

// inScope runs fn in a transaction of tenant (nil = platform) on the application pools.
func (l *Logger) inScope(ctx context.Context, tenant *uuid.UUID, fn func(*sqlcdb.Queries) error) error {
	if tenant != nil {
		return l.st.WithTenantTx(ctx, *tenant, fn)
	}
	return l.st.WithPlatformTx(ctx, fn)
}

// Result is how a request ended, as the HTTP audit middleware saw it.
type Result struct {
	Outcome string // "" = the handler succeeded; OutcomeDenied or OutcomeFailure
	Reason  string // stable code: the authz reason or the problem code
	Status  int    // HTTP status of the problem; 0 on success
	Skip    bool   // nothing to audit: an operation without handler (501), an anonymous request (401 without principal)
}

// Gap reasons, the label of meshguard_audit_gaps_total.
const (
	gapNoEvent  = "no_event"  // a write succeeded without recording any event
	gapLeftOpen = "left_open" // a request succeeded leaving an operation without outcome and not handed off
)

// Finish closes the audit of one request once its handler returned (or panicked):
//   - every operation the request started (Requested) and did not hand off is checked in the database: still open
//     after a failed request ⇒ "<action>.failed" on the detached path; still open after a successful one ⇒ a gap;
//     its *.requested rolled back ⇒ nothing (it never started);
//   - denied: one denied event on the detached path under the ACTOR's tenant (nil for platform staff), with the tenant
//     of the path as TargetTenantID when they differ — a cross-tenant denial never reaches the target's audit (§6.1);
//   - failure of a write: one failure event on the detached path in the tenant of the path; failures of reads are
//     left to the access log;
//   - a write that succeeded without any event: a gap.
//
// The *.failed events of the request's operations replace its denied/failure event. Gaps are logged at ERROR and
// counted (meshguard_audit_gaps_total): the business change has committed, nothing can be undone here.
func (l *Logger) Finish(ctx context.Context, r *Request, res Result) {
	if r == nil || res.Skip {
		return
	}
	recorded, ops := r.snapshot()
	failedOps := 0
	for _, t := range ops {
		if t.handedOff {
			continue
		}
		st, err := l.operationState(ctx, t.op)
		switch {
		case err != nil:
			l.failed(ctx, pathPairing, Event{Action: t.op.Action, OperationID: &t.op.ID}, err)
		case !st.Requested || st.Finished:
		case res.Outcome == "":
			l.gap(ctx, gapLeftOpen, r, t.op.ID.String())
		default:
			if t.op.FailedDetached(ctx, l, res.Reason, Details{"status": res.Status}) == nil {
				failedOps++
			}
		}
	}
	switch {
	case res.Outcome == "":
		if !r.ReadOnly && recorded == 0 && len(ops) == 0 {
			l.gap(ctx, gapNoEvent, r, "")
		}
		return
	case failedOps > 0, res.Outcome == OutcomeFailure && r.ReadOnly:
		return
	}
	ev := Event{
		ActorType: r.ActorType, ActorIdentityID: r.ActorIdentityID, SupportGrantID: r.SupportGrantID,
		ActorDisplay: r.ActorDisplay, ActorIP: r.ClientIP, Action: r.Action, ResourceType: r.ResourceType,
		ResourceID: r.ResourceID, RequestID: r.RequestID, Outcome: res.Outcome,
		Details: Details{"reason": res.Reason, "status": res.Status},
	}
	if res.Outcome == OutcomeDenied {
		ev.TenantID, ev.TargetTenantID = r.ActorTenantID, r.TenantID // normalize drops the target when equal
	} else {
		ev.TenantID = r.TenantID
	}
	_ = l.RecordDetached(ctx, ev) // logged and counted inside
}

// operationState reads, in the operation's scope, whether its *.requested committed and whether it has an outcome.
func (l *Logger) operationState(ctx context.Context, op Operation) (sqlcdb.OperationStateRow, error) {
	var st sqlcdb.OperationStateRow
	wctx, cancel := l.writeContext(ctx)
	defer cancel()
	err := l.inScope(wctx, op.TenantID, func(q *sqlcdb.Queries) error {
		var err error
		st, err = q.OperationState(wctx, op.ID)
		return err
	})
	return st, err
}

// OpenOperations lists the operations of one tenant (nil = platform operations) whose *.requested is older than
// olderThan and still has no *.succeeded / *.failed — a process died halfway (§6.1): the input of reconcile, oldest
// first, at most limit (1–1000).
func (l *Logger) OpenOperations(ctx context.Context, tenant *uuid.UUID, olderThan time.Duration, limit int) ([]Operation, error) {
	if limit < 1 || limit > 1000 {
		return nil, fmt.Errorf("audit: limit %d out of 1–1000", limit)
	}
	var rows []sqlcdb.AuditEvent
	err := l.inScope(ctx, tenant, func(q *sqlcdb.Queries) error {
		var err error
		rows, err = q.ListOpenOperations(ctx, sqlcdb.ListOpenOperationsParams{
			TenantID: tenant, OlderThanSeconds: olderThan.Seconds(), RowLimit: int32(limit), //nolint:gosec // 1–1000
		})
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("audit: open operations: %w", err)
	}
	ops := make([]Operation, 0, len(rows))
	for _, e := range rows {
		if e.OperationID == nil {
			continue
		}
		op := Operation{
			ID: *e.OperationID, Action: strings.TrimSuffix(e.Action, SuffixRequested), TenantID: e.TenantID,
			ActorType: e.ActorType, ActorIdentityID: e.ActorIdentityID, SupportGrantID: e.SupportGrantID,
			ResourceType: e.ResourceType, ResourceID: deref(e.ResourceID), RequestID: deref(e.RequestID),
			ActorDisplay: deref(e.ActorDisplay),
		}
		if e.ActorIp != nil {
			op.ActorIP = *e.ActorIp
		}
		ops = append(ops, op)
	}
	return ops, nil
}

// crossTenantRule is the rule of §8.8 (P2-T08): after a denial of a tenant other than the actor's, count the actor's
// cross-tenant denials within the window — in the actor's own scope (its tenant, or the platform for staff), where
// they are recorded — and from CrossTenantThreshold on raise one platform-scope security event per actor and window:
// high, or critical when the denials reach criticalTargets distinct target tenants. Runs on the application pools
// (mg_audit_writer cannot read).
func (l *Logger) crossTenantRule(ctx context.Context, ev Event) {
	if ev.ActorIdentityID == nil {
		return
	}
	wctx, cancel := l.writeContext(ctx)
	defer cancel()
	var row sqlcdb.CountCrossTenantDenialsRow
	err := l.inScope(wctx, ev.TenantID, func(q *sqlcdb.Queries) error {
		var err error
		row, err = q.CountCrossTenantDenials(wctx, sqlcdb.CountCrossTenantDenialsParams{
			TenantID: ev.TenantID, ActorIdentityID: *ev.ActorIdentityID, WindowSeconds: l.cfg.CrossTenantWindow.Seconds(),
		})
		return err
	})
	if err != nil {
		l.failed(ctx, pathRule, ev, err)
		return
	}
	if row.Denials < int64(l.cfg.CrossTenantThreshold) {
		return
	}
	severity := SeverityHigh
	if row.Targets >= criticalTargets {
		severity = SeverityCritical
	}
	actorTenant := "platform"
	if ev.TenantID != nil {
		actorTenant = ev.TenantID.String()
	}
	_, _ = l.RecordSecurityEvent(ctx, SecurityEvent{
		Kind: KindCrossTenantDenials, Severity: severity, Source: SourceAudit,
		Details: Details{
			"actor_identity_id": *ev.ActorIdentityID, "actor_tenant": actorTenant, "denials": row.Denials,
			"target_tenants": row.Targets, "threshold": l.cfg.CrossTenantThreshold,
			"window_seconds": int64(l.cfg.CrossTenantWindow.Seconds()), "last_action": ev.Action,
			"last_request_id": ev.RequestID,
		},
		DedupeKey: KindCrossTenantDenials + ":" + ev.ActorIdentityID.String(), DedupeWindow: l.cfg.CrossTenantWindow,
	})
}

// failed logs and counts a write that did not happen.
func (l *Logger) failed(ctx context.Context, path string, ev Event, err error) {
	l.m.failures.WithLabelValues(path).Inc()
	attrs := []any{"path", path, "action", ev.Action, "outcome", ev.Outcome, "sqlstate", store.SQLState(err), "error", err}
	if ev.OperationID != nil {
		attrs = append(attrs, "operation_id", ev.OperationID.String())
	}
	l.log.ErrorContext(ctx, "audit: write failed", attrs...)
}

// gap logs and counts an audit gap left by a handler.
func (l *Logger) gap(ctx context.Context, reason string, r *Request, operationID string) {
	l.m.gaps.WithLabelValues(reason).Inc()
	attrs := []any{"reason", reason, "operation", r.Operation, "action", r.Action}
	if operationID != "" {
		attrs = append(attrs, "operation_id", operationID)
	}
	l.log.ErrorContext(ctx, "audit: gap", attrs...)
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// metrics of the audit trail (§16.3 "ghi audit thất bại").
type metrics struct {
	failures *prometheus.CounterVec // path
	security *prometheus.CounterVec // kind, severity
	gaps     *prometheus.CounterVec // reason
}

func newMetrics(reg prometheus.Registerer) *metrics {
	m := &metrics{
		failures: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "meshguard_audit_write_failures_total",
			Help: "Audit or security events that could not be written, by path (detached, committed, security, cross_tenant_rule, pairing).",
		}, []string{"path"}),
		security: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "meshguard_security_events_total", Help: "Security events written, by kind and severity.",
		}, []string{"kind", "severity"}),
		gaps: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "meshguard_audit_gaps_total",
			Help: "Requests that left the audit trail incomplete (no_event: a write without event; left_open: an operation without outcome).",
		}, []string{"reason"}),
	}
	if reg != nil {
		reg.MustRegister(m.failures, m.security, m.gaps)
	}
	return m
}
