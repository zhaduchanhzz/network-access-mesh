package main

import (
	"context"
	"errors"
	"log/slog"
	"time"
)

// daemon is the service's own schedule (no host cron or systemd timer, not a Worker/Agent job — P2-T03a): one
// backup a day at DailyAt (UTC); immediately at start-up when the status file shows no success within the last 24
// hours (first start, or the host was down at the scheduled time); after a failure, again after RetryAfter (but never
// later than the next daily slot). A configuration error at start-up or before a run stops the process with exit
// status 2 without writing anything — the container restarts and its logs say why (fail loudly).
func daemon(ctx context.Context, cfg *Config, log *slog.Logger) int {
	tools, err := cfg.Preflight(ctx)
	if err != nil {
		log.Error("refusing to start — nothing written", "err", err)
		return 2
	}
	b := &Backuper{Cfg: cfg, Log: log, Tools: tools, Now: time.Now}
	now := time.Now().UTC()
	next := nextDaily(now, cfg.DailyAt)
	if _, st, err := ReadStatus(cfg.Dest); err != nil || st.LastSuccess == nil || now.Sub(st.LastSuccess.FinishedAt) > 24*time.Hour {
		next = now
	}
	log.Info("scheduler started", "daily_at_utc", cfg.DailyAtString(), "next", next, "recipient", cfg.Recipient, "tools", tools)
	for {
		if !sleepUntil(ctx, next) {
			log.Info("stopping")
			return 0
		}
		m, err := b.Run(ctx, LabelScheduled)
		now = time.Now().UTC()
		switch {
		case errors.Is(err, ErrConfig):
			log.Error("refusing to run — nothing written", "err", err)
			return 2
		case ctx.Err() != nil:
			log.Info("stopping")
			return 0
		case err != nil:
			next = minTime(now.Add(cfg.RetryAfter), nextDaily(now, cfg.DailyAt))
			log.Error("backup failed", "err", err, "retry_at", next)
		default:
			next = nextDaily(now, cfg.DailyAt)
			log.Info("backup done", "id", m.ID, "files", len(m.Files), "bytes", m.TotalBytes(), "next", next)
		}
	}
}

// nextDaily is the first time strictly after now at offset at from midnight UTC.
func nextDaily(now time.Time, at time.Duration) time.Time {
	now = now.UTC()
	t := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC).Add(at)
	if !t.After(now) {
		t = t.AddDate(0, 0, 1)
	}
	return t
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

// sleepUntil waits for the wall clock to reach t (in steps of at most a minute, so a clock change or a suspended
// host does not delay the run by the full interval); false when ctx ends first.
func sleepUntil(ctx context.Context, t time.Time) bool {
	for {
		d := time.Until(t)
		if d <= 0 {
			return ctx.Err() == nil
		}
		timer := time.NewTimer(min(d, time.Minute))
		select {
		case <-ctx.Done():
			timer.Stop()
			return false
		case <-timer.C:
		}
	}
}
