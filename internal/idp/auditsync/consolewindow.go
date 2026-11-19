package auditsync

// Grouping of the console sign-in e-mails (F-G3-2 of G3): every sign-in to the Keycloak administration stays one
// platform audit row and one security event idp.console_login (high), but the e-mail to the Super Admins and Platform
// Operators is grouped per source — account (case-insensitive), client and address — and time window
// (Config.ConsoleLoginWindow, MG_IDP_CONSOLE_LOGIN_NOTIFY_WINDOW):
//
//   - the first sign-in of a source with no open window is notified at once, as before, and opens a window: a new
//     account, a new client (the interactive console after the admin CLI of a script) or a new address is never
//     delayed;
//   - the sign-ins of that source inside the window are held back: counted, with their times;
//   - when the window ends (checked at every run of the job, i.e. every minute), the held-back sign-ins are sent as one
//     summary e-mail (idp.console_login with count, sources, first_at, window_minutes) and a new window opens with it —
//     a script signing in every few seconds (kcadm of realm-update.sh, create-user.sh) costs one e-mail per window,
//     never one per sign-in; a window that ends with nothing held back closes, and the next sign-in of the source is
//     again notified at once.
//
// A window keeps the length it was opened with (a change of the setting applies to the windows opened after it). With
// the grouping off (window 0) every sign-in is notified at once, and the windows still open when it was turned off end
// at the next run: their held-back sign-ins are sent as summaries, never dropped.
//
// The windows are internal state in system_settings (consoleWindowKey, under the cursor prefix: never served by
// /platform/settings), read and written in the transaction of the event under one advisory lock, so a held-back
// sign-in is counted exactly once with its audit row and two processes running the job never lose a count.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/zhaduchanhzz/network-access-mesh/internal/notifications"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

const (
	// consoleWindowKey is the system_settings row of the open windows.
	consoleWindowKey = "idp.audit_sync.console_login_window"
	// consoleWindowLock serialises the windows (advisory, transaction scope).
	consoleWindowLock = "meshguard:idp-console-login-window"
	// maxSources bounds the distinct sources listed in a summary (the others are counted).
	maxSources = 8
	// maxSourcesText bounds the sources text of a summary (a payload value holds at most 256 characters).
	maxSourcesText = 200
	// maxSourceBytes bounds one source ("client ip") in it.
	maxSourceBytes = 80
	// maxWindows bounds the windows kept: a source beyond it is notified at every sign-in (never held back untracked).
	maxWindows = 200
)

// consoleWindow is the open window of one source (account, client, address).
type consoleWindow struct {
	Account     string   `json:"account"`
	StartMs     int64    `json:"start_ms"`            // when the window opened (the worker's clock)
	WindowMs    int64    `json:"window_ms,omitempty"` // its length (Config.ConsoleLoginWindow when it opened)
	Count       int      `json:"count"`               // sign-ins held back since StartMs
	FirstMs     int64    `json:"first_ms,omitempty"`
	LastMs      int64    `json:"last_ms,omitempty"`
	LastEventID string   `json:"last_event_id,omitempty"`
	LastClient  string   `json:"last_client,omitempty"`
	Sources     []string `json:"sources,omitempty"`
	MoreSources int      `json:"more_sources,omitempty"` // held-back sign-ins whose source was not listed (list full)
}

// hold counts one sign-in in the window.
func (w *consoleWindow) hold(r Record, ip string) {
	w.Count++
	ms := r.At.UnixMilli()
	if w.FirstMs == 0 || ms < w.FirstMs {
		w.FirstMs = ms
	}
	if ms >= w.LastMs {
		w.LastMs, w.LastEventID, w.LastClient = ms, r.EventID, r.Client
	}
	src := r.Client
	if ip != "" {
		src += " " + ip
	}
	switch {
	case slices.Contains(w.Sources, src):
	case len(w.Sources) < maxSources:
		w.Sources = append(w.Sources, src)
	default:
		w.MoreSources++
	}
}

// windowKey is the key of a source: the account (Keycloak usernames are case-insensitive), the client and the address.
func windowKey(username, client, ip string) string {
	return strings.ToLower(username) + "|" + client + "|" + ip
}

// consoleLoginNotices returns the notifications of one console sign-in, in the transaction of the event (q): the
// immediate e-mail when no window of its source is open (preceded by the summary of a window that ended but was not
// flushed yet), nothing when the sign-in is held back in an open window.
func (s *Syncer) consoleLoginNotices(ctx context.Context, q *sqlcdb.Queries, r Record, ip string) ([]notifications.Event, error) {
	now := notifications.IdPConsoleLogin(r.EventID, r.Username, r.Client, ip, r.At)
	window := s.cfg.ConsoleLoginWindow
	if window <= 0 {
		return []notifications.Event{now}, nil
	}
	if err := q.LockIdPEvent(ctx, consoleWindowLock); err != nil {
		return nil, err
	}
	ws, err := s.loadWindows(ctx, q)
	if err != nil {
		return nil, err
	}
	key, at := windowKey(r.Username, r.Client, ip), s.cfg.Now()
	w := ws[key]
	if w != nil && at.Before(time.UnixMilli(w.StartMs).Add(w.length(window))) {
		w.hold(r, ip)
		return nil, s.saveWindows(ctx, q, ws)
	}
	var out []notifications.Event
	if w != nil && w.Count > 0 {
		out = append(out, s.summary(key, w))
	}
	if w == nil && len(ws) >= maxWindows {
		return []notifications.Event{now}, nil
	}
	ws[key] = &consoleWindow{Account: r.Username, StartMs: at.UnixMilli(), WindowMs: window.Milliseconds()}
	return append(out, now), s.saveWindows(ctx, q, ws)
}

// flushConsoleWindows sends the summary of every window that has ended with sign-ins held back (a new window opens
// with it) and closes the windows that ended empty. It runs at the start of every run, whatever the IdP's state. With
// the grouping off (window 0) every stored window ends now: the sign-ins it held back are sent as its summary and the
// window closes (no new one opens) — turning the grouping off never drops a held-back sign-in.
func (s *Syncer) flushConsoleWindows(ctx context.Context) error {
	window := s.cfg.ConsoleLoginWindow
	return s.st.WithPlatformJobTx(ctx, func(tx *store.Tx) error {
		q := tx.Q
		if err := q.LockIdPEvent(ctx, consoleWindowLock); err != nil {
			return err
		}
		ws, err := s.loadWindows(ctx, q)
		if err != nil || len(ws) == 0 {
			return err
		}
		at := s.cfg.Now()
		changed := false
		for _, k := range slices.Sorted(maps.Keys(ws)) {
			w := ws[k]
			if window > 0 && at.Before(time.UnixMilli(w.StartMs).Add(w.length(window))) {
				continue
			}
			changed = true
			if w.Count > 0 {
				if _, err := s.cfg.Notifier.Enqueue(ctx, tx, s.summary(k, w)); err != nil {
					return err
				}
			}
			if w.Count == 0 || window <= 0 {
				delete(ws, k)
				continue
			}
			ws[k] = &consoleWindow{Account: w.Account, StartMs: at.UnixMilli(), WindowMs: window.Milliseconds()}
		}
		if !changed {
			return nil
		}
		return s.saveWindows(ctx, q, ws)
	})
}

// summary is the grouped e-mail of a window (key: its source); its ref is unique per source and window.
func (s *Syncer) summary(key string, w *consoleWindow) notifications.Event {
	sum := sha256.Sum256([]byte(key))
	return notifications.IdPConsoleLoginSummary(notifications.ConsoleLoginSummary{
		Ref:           "idp-console-window:" + hex.EncodeToString(sum[:8]) + ":" + strconv.FormatInt(w.StartMs, 10),
		LastEventID:   w.LastEventID,
		Username:      w.Account,
		Client:        w.LastClient,
		Count:         w.Count,
		Sources:       sourceList(w.Sources, w.MoreSources),
		First:         time.UnixMilli(w.FirstMs).UTC(),
		Last:          time.UnixMilli(w.LastMs).UTC(),
		WindowMinutes: int((w.length(s.cfg.ConsoleLoginWindow) + time.Minute - 1) / time.Minute),
	})
}

// length is the window the sign-ins of w are held under: the length it opened with; for a window stored before its
// length was, the configured one (configured, a duration of the setting); with the grouping off as well, the time it
// actually held sign-ins (at least a minute).
func (w *consoleWindow) length(configured time.Duration) time.Duration {
	switch {
	case w.WindowMs > 0:
		return time.Duration(w.WindowMs) * time.Millisecond
	case configured > 0:
		return configured
	}
	return max(time.Minute, time.Duration(w.LastMs-w.StartMs)*time.Millisecond)
}

// sourceList is the sources of a summary as one payload text (at most maxSourcesText characters — a payload value is
// bounded): "client ip, client ip (+N)" where N counts the held-back sign-ins whose source is not listed.
func sourceList(sources []string, more int) string {
	var b strings.Builder
	for i, src := range sources {
		for len(src) > maxSourceBytes { // whole runes only: a payload value is valid UTF-8
			_, size := utf8.DecodeLastRuneInString(src)
			src = src[:len(src)-size]
		}
		if b.Len()+len(src)+2 > maxSourcesText {
			more += len(sources) - i
			break
		}
		if b.Len() > 0 {
			b.WriteString(", ")
		}
		b.WriteString(src)
	}
	if more > 0 {
		b.WriteString(" (+" + strconv.Itoa(more) + ")")
	}
	return b.String()
}

func (s *Syncer) loadWindows(ctx context.Context, q *sqlcdb.Queries) (map[string]*consoleWindow, error) {
	ws := map[string]*consoleWindow{}
	row, err := q.GetSystemSetting(ctx, consoleWindowKey)
	switch {
	case errors.Is(err, store.ErrNoRows):
		return ws, nil
	case err != nil:
		return nil, err
	}
	if json.Unmarshal(row.Value, &ws) != nil {
		s.log.WarnContext(ctx, "idp.audit_sync: unreadable console sign-in windows — starting afresh", "key", consoleWindowKey)
		return map[string]*consoleWindow{}, nil
	}
	for k, w := range ws {
		if w == nil {
			delete(ws, k)
		}
	}
	return ws, nil
}

func (s *Syncer) saveWindows(ctx context.Context, q *sqlcdb.Queries, ws map[string]*consoleWindow) error {
	b, err := json.Marshal(ws)
	if err != nil {
		return err
	}
	_, err = q.UpsertSystemSetting(ctx, sqlcdb.UpsertSystemSettingParams{Key: consoleWindowKey, Value: b})
	return err
}
