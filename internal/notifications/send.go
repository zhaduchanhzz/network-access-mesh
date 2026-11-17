package notifications

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// SenderConfig are the collaborators of the notification.send handler (worker process).
type SenderConfig struct {
	// Mailer delivers the e-mails; nil = no SMTP relay configured (MG_SMTP_ADDR unset — allowed outside production):
	// e-mail rows are then settled cancelled (the Portal record stays readable) and a warning is logged.
	Mailer Mailer
	// PortalURL (https://app.<domain>) and ConsoleURL (https://admin.<domain>): the only links the templates use.
	PortalURL  string
	ConsoleURL string
	// MessageIDDomain is the right-hand side of Message-ID (default: the portal host or "meshguard.invalid").
	MessageIDDomain string
	Logger          *slog.Logger
}

// Sender is the notification.send handler.
type Sender struct {
	st   *store.Store
	cfg  SenderConfig
	tmpl *templates
	log  *slog.Logger
}

// NewSender returns the handler of notification.send on the worker's store.
func NewSender(st *store.Store, cfg SenderConfig) (*Sender, error) {
	if st == nil {
		return nil, errors.New("notifications: a store is required")
	}
	t, err := parseTemplates()
	if err != nil {
		return nil, err
	}
	log := cfg.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	if cfg.MessageIDDomain == "" {
		cfg.MessageIDDomain = "meshguard.invalid"
	}
	return &Sender{st: st, cfg: cfg, tmpl: t, log: log}, nil
}

// Register registers the notification.send handler on the worker (jobs imports no module — §13.6).
func (s *Sender) Register(w *jobs.Worker) error {
	if s.cfg.Mailer == nil {
		s.log.Warn("notifications: no SMTP relay configured (MG_SMTP_ADDR): e-mail notifications are cancelled, " +
			"only the Portal records are delivered")
	}
	return w.Register(JobKind, jobs.HandlerFunc(s.run))
}

// Outcome of one send (job output).
type sendOutput struct {
	Status   string `json:"status"`
	Attempts int32  `json:"attempts"`
	Reason   string `json:"reason,omitempty"`
}

// run delivers one outbox row. It is idempotent per row: a row that is no longer pending (sent, failed, cancelled —
// an earlier attempt or delivery finished it) is left alone, so a job delivered twice never sends twice after a
// recorded success. The window between the relay's 250 and the commit of `sent` is the only duplicate risk (at-least-
// once): the retry then carries the same Message-ID (<row id@domain>), which lets mail systems drop the copy.
//
//	relay 4xx / network / timeout → transient: the job retries with backoff (§11.3), the row stays pending
//	relay 5xx, invalid address    → the row is failed, the job fails (alert — §11.3 step 19)
//	last attempt still transient  → the row is failed, the job fails (alert)
//	no relay configured           → the row is cancelled (Portal record kept), the job succeeds
func (s *Sender) run(ctx context.Context, run *jobs.Run) error {
	var in sendInput
	if err := run.DecodeInput(&in); err != nil || in.NotificationID == uuid.Nil {
		return jobs.Permanent("invalid_input", errors.New("notification.send needs notification_id"))
	}
	row, pending, err := s.claim(ctx, run.TenantID, in.NotificationID)
	if errors.Is(err, store.ErrNoRows) {
		return jobs.Permanent("notification_not_found", errors.New("the outbox row does not exist in the job's scope"))
	}
	if err != nil {
		return jobs.Transient("outbox_unavailable", err)
	}
	if !pending {
		return run.SetOutput(sendOutput{Status: row.Status, Attempts: row.Attempts, Reason: "already_settled"})
	}
	switch {
	case row.RecipientEmail == nil || *row.RecipientEmail == "":
		return s.settle(ctx, run, row, StatusSent, "portal_only", nil)
	case s.cfg.Mailer == nil:
		s.log.WarnContext(ctx, "notifications: e-mail not sent: no SMTP relay configured", "notification_id", row.ID, "kind", row.Kind)
		return s.settle(ctx, run, row, StatusCancelled, "smtp_not_configured", nil)
	}
	msg, err := s.message(row)
	if err != nil {
		return s.settle(ctx, run, row, StatusFailed, "template_error", jobs.Permanent("template_error", err))
	}
	err = s.cfg.Mailer.Send(ctx, msg)
	switch {
	case err == nil:
		return s.settle(ctx, run, row, StatusSent, "", nil)
	case IsPermanent(err):
		return s.settle(ctx, run, row, StatusFailed, "smtp_rejected", jobs.Permanent("smtp_rejected", err))
	case run.Attempt >= run.MaxAttempts:
		return s.settle(ctx, run, row, StatusFailed, "smtp_unavailable", jobs.Transient("smtp_unavailable", err))
	}
	s.log.WarnContext(ctx, "notifications: e-mail delivery failed; the job retries", "notification_id", row.ID,
		"attempt", run.Attempt, "error", err.Error())
	return jobs.Transient("smtp_unavailable", err)
}

// claim locks the row, counts the attempt when it is still pending and returns it.
func (s *Sender) claim(ctx context.Context, tenantID *uuid.UUID, id uuid.UUID) (row sqlcdb.NotificationOutbox, pending bool, err error) {
	err = s.tx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		var err error
		row, err = q.LockNotificationForSend(ctx, sqlcdb.LockNotificationForSendParams{ID: id, TenantID: tenantID})
		if err != nil || row.Status != StatusPending {
			return err
		}
		pending = true
		row.Attempts++
		return q.CountNotificationAttempt(ctx, id)
	})
	return row, pending, err
}

// settle records the final status of the row (only from pending) and returns cause (nil = the job succeeds).
func (s *Sender) settle(ctx context.Context, run *jobs.Run, row sqlcdb.NotificationOutbox, status, reason string, cause error) error {
	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), settleTimeout)
	defer cancel()
	err := s.tx(wctx, row.TenantID, func(q *sqlcdb.Queries) error {
		_, err := q.FinishNotification(wctx, sqlcdb.FinishNotificationParams{Status: status, ID: row.ID})
		return err
	})
	if err != nil {
		// Not recorded: retry the whole send (the row is still pending; Message-ID dedupes a second copy).
		return jobs.Transient("outbox_unavailable", fmt.Errorf("record %s: %w", status, err))
	}
	if cause != nil {
		s.log.ErrorContext(ctx, "notifications: e-mail not delivered", "notification_id", row.ID, "kind", row.Kind,
			"status", status, "reason", reason, "error", cause.Error())
		return cause
	}
	return run.SetOutput(sendOutput{Status: status, Attempts: row.Attempts, Reason: reason})
}

// settleTimeout bounds the write that records an outcome (detached from the job's deadline).
const settleTimeout = 10 * time.Second

// tx runs fn in the scope of the row: the tenant's transaction for a tenant notification, the platform's otherwise.
func (s *Sender) tx(ctx context.Context, tenantID *uuid.UUID, fn func(q *sqlcdb.Queries) error) error {
	if tenantID != nil {
		return s.st.WithTenantTx(ctx, *tenantID, fn)
	}
	return s.st.WithPlatformTx(ctx, fn)
}

// message renders the e-mail of a row in its locale.
func (s *Sender) message(row sqlcdb.NotificationOutbox) (Message, error) {
	var data map[string]any
	if err := json.Unmarshal(row.Payload, &data); err != nil {
		return Message{}, fmt.Errorf("payload: %w", err)
	}
	locale, _ := data["locale"].(string)
	data["portal_url"], data["console_url"] = s.cfg.PortalURL, s.cfg.ConsoleURL
	subject, body, err := s.tmpl.render(Kind(row.Kind), locale, data)
	if err != nil {
		return Message{}, err
	}
	return Message{To: *row.RecipientEmail, Subject: subject, Body: body,
		MessageID: "<" + row.ID.String() + "@" + s.cfg.MessageIDDomain + ">"}, nil
}
