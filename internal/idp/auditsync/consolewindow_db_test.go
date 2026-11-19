package auditsync

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/zhaduchanhzz/network-access-mesh/internal/idp/keycloak"
)

// TestConsoleLoginWindows (F-G3-2): every console sign-in stays one audit row and one high security event, but the
// e-mail to the platform staff is grouped per source (account case-insensitive, client, address) and window: the first
// sign-in of a source at once, the next ones of the window in one summary when it ends (count, sources, first and last
// time) — concurrent runs count each sign-in once —, a new window opening with the summary; a window that ends empty
// closes, and the next sign-in is again notified at once. Another account, another client (the interactive console
// after the admin CLI of a script) or another address is never held back by the window of the first.
func TestConsoleLoginWindows(t *testing.T) {
	f := newFx(t)
	src := newSource()
	t0 := f.now.Truncate(time.Minute)
	f.now = t0
	login := func(id, user, client, ip string, at time.Time) keycloak.UserEvent {
		return keycloak.UserEvent{ID: id, Time: at.UnixMilli(), Type: "LOGIN", ClientID: client, UserID: adminUID,
			IPAddress: ip, Details: map[string]string{"username": user}}
	}
	add := func(evs ...keycloak.UserEvent) {
		src.mu.Lock()
		src.user["master"] = append(src.user["master"], evs...)
		src.mu.Unlock()
	}
	for i := range 5 { // a script signing in every 20 s (kcadm of realm-update.sh, create-user.sh)
		at := t0.Add(-2*time.Minute + time.Duration(i)*20*time.Second)
		add(login(fmt.Sprintf("k%d", i), "kcadm-admin", "admin-cli", "192.0.2.10", at))
	}
	add(login("o1", "other-admin", "admin-cli", "192.0.2.20", t0.Add(-time.Minute)),
		login("x1", "kcadm-admin", "security-admin-console", "192.0.2.10", t0.Add(-30*time.Second))) // interactive console
	syncer := func() *Syncer {
		s, err := New(f.st, Config{Source: src, PageSize: 2, Now: func() time.Time { return f.now },
			ConsoleLoginWindow: 10 * time.Minute})
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	run := func() {
		t.Helper()
		if _, err := syncer().RunOnce(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	mails := func() int {
		return f.count(`SELECT count(*) FROM notification_outbox WHERE tenant_id IS NULL AND kind = 'idp.console_login'`)
	}
	notifiedAlone := func(eventID string) int {
		return f.count(`SELECT count(*) FROM notification_outbox WHERE kind = 'idp.console_login'
			AND payload ->> 'event_id' = $1 AND payload ->> 'count' IS NULL`, eventID)
	}
	var wg sync.WaitGroup
	for range 3 { // the periodic job and `admin idp-audit-sync` overlapping
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := syncer().RunOnce(context.Background()); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if n := f.count(`SELECT count(*) FROM security_events WHERE tenant_id IS NULL AND kind = $1 AND severity = 'high'`,
		KindConsoleLogin); n != 7 {
		t.Errorf("security events %d, want one per sign-in (7)", n)
	}
	if n := f.count(`SELECT count(*) FROM audit_events WHERE tenant_id IS NULL AND action = 'idp.console.login'`); n != 7 {
		t.Errorf("audit rows %d, want 7", n)
	}
	if n := mails(); n != 3 {
		t.Errorf("e-mails %d after the first sign-ins, want 3 (the first of each source, at once)", n)
	}
	if notifiedAlone("k0") != 1 || notifiedAlone("o1") != 1 || notifiedAlone("x1") != 1 {
		t.Error("the first sign-in of a source was not notified on its own")
	}
	f.now = t0.Add(5 * time.Minute) // inside the window: nothing more
	run()
	if n := mails(); n != 3 {
		t.Errorf("e-mails %d inside the window, want 3", n)
	}
	f.now = t0.Add(10*time.Minute + time.Second) // the windows end: one summary of 4; the others close empty
	run()
	if n := mails(); n != 4 {
		t.Fatalf("e-mails %d after the window, want 4", n)
	}
	if n := f.count(`SELECT count(*) FROM notification_outbox WHERE kind = 'idp.console_login'
		AND payload ->> 'count' = '4' AND payload ->> 'username' = 'kcadm-admin' AND payload ->> 'event_id' = 'k4'
		AND payload ->> 'client' = 'admin-cli' AND payload ->> 'window_minutes' = '10'
		AND payload ->> 'sources' = 'admin-cli 192.0.2.10'
		AND (payload ->> 'first_at')::timestamptz = $1 AND (payload ->> 'occurred_at')::timestamptz = $2
		AND payload ->> 'ref' LIKE 'idp-console-window:%'`,
		t0.Add(-100*time.Second), t0.Add(-40*time.Second)); n != 1 {
		var p string
		_ = f.su.QueryRow(context.Background(), `SELECT payload::text FROM notification_outbox WHERE payload ? 'count'`).Scan(&p)
		t.Errorf("summary: %d (%s)", n, p)
	}
	run() // flushed once
	if n := mails(); n != 4 {
		t.Errorf("e-mails %d after a second run, want 4", n)
	}
	// the summary opened a new window for the script (any case of the account): held back; other-admin's window is
	// closed and a new address of the script's account opens its own: both at once
	f.now = t0.Add(11 * time.Minute)
	add(login("k5", "KCADM-admin", "admin-cli", "192.0.2.10", f.now.Add(-10*time.Second)),
		login("o2", "other-admin", "admin-cli", "192.0.2.20", f.now),
		login("n1", "kcadm-admin", "admin-cli", "192.0.2.11", f.now))
	run()
	if n := mails(); n != 6 || notifiedAlone("o2") != 1 || notifiedAlone("n1") != 1 {
		t.Errorf("e-mails %d, want 6 (other-admin and the new address at once, the script held back)", n)
	}
	f.now = t0.Add(21 * time.Minute) // summary of 1; the windows of o2 and n1 end empty
	run()
	if n := mails(); n != 7 {
		t.Errorf("e-mails %d, want 7", n)
	}
	f.now = t0.Add(32 * time.Minute) // the script's window after the summary ends empty: closed
	run()
	add(login("k6", "kcadm-admin", "admin-cli", "192.0.2.10", f.now))
	run()
	if n := mails(); n != 8 || notifiedAlone("k6") != 1 {
		t.Errorf("e-mails %d, want 8 (a sign-in after a quiet window is notified at once)", n)
	}
	if n := f.count(`SELECT count(*) FROM security_events WHERE tenant_id IS NULL AND kind = $1`, KindConsoleLogin); n != 11 {
		t.Errorf("security events %d, want 11", n)
	}
	if n := f.count(`SELECT count(*) FROM system_settings WHERE key = $1`, consoleWindowKey); n != 1 {
		t.Errorf("window row: %d", n)
	}
	// a lost window state never duplicates an event; with the grouping off every sign-in is notified at once
	f.exec(`DELETE FROM system_settings WHERE key LIKE 'idp.audit_sync.%'`)
	run()
	if n := mails(); n != 8 {
		t.Errorf("e-mails %d after losing the state, want 8", n)
	}
	off, err := New(f.st, Config{Source: src, PageSize: 100, Now: func() time.Time { return f.now }})
	if err != nil {
		t.Fatal(err)
	}
	add(login("k7", "kcadm-admin", "admin-cli", "192.0.2.10", f.now),
		login("k8", "kcadm-admin", "admin-cli", "192.0.2.10", f.now.Add(time.Second)))
	if _, err := off.RunOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	if n := mails(); n != 10 {
		t.Errorf("e-mails %d with the grouping off, want 10", n)
	}
}

// TestConsoleLoginWindowsKeepTheirLength (C11): a window keeps the length it was opened with, and turning the grouping
// off (window 0) never drops the sign-ins an open window held back. A window opened at 10 minutes ends at 10 minutes
// and announces 10 minutes even after the setting became 30; the first run with the grouping off sends the held-back
// sign-ins of every open window as one summary (with the length they were held under) and clears the stored windows;
// later runs send nothing more, and every new sign-in is notified at once. Each sign-in stays one high security event.
func TestConsoleLoginWindowsKeepTheirLength(t *testing.T) {
	f := newFx(t)
	src := newSource()
	t0 := f.now.Truncate(time.Minute)
	f.now = t0
	add := func(id string, at time.Time) {
		src.mu.Lock()
		src.user["master"] = append(src.user["master"], keycloak.UserEvent{ID: id, Time: at.UnixMilli(), Type: "LOGIN",
			ClientID: "admin-cli", UserID: adminUID, IPAddress: "192.0.2.10", Details: map[string]string{"username": "kcadm-admin"}})
		src.mu.Unlock()
	}
	run := func(window time.Duration) {
		t.Helper()
		s, err := New(f.st, Config{Source: src, PageSize: 100, Now: func() time.Time { return f.now }, ConsoleLoginWindow: window})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.RunOnce(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	mails := func() int {
		return f.count(`SELECT count(*) FROM notification_outbox WHERE tenant_id IS NULL AND kind = 'idp.console_login'`)
	}
	summaries := func(count, minutes string) int {
		return f.count(`SELECT count(*) FROM notification_outbox WHERE kind = 'idp.console_login'
			AND payload ->> 'count' = $1 AND payload ->> 'window_minutes' = $2`, count, minutes)
	}
	for i := range 3 { // a window of 10 minutes: the first at once, two held back
		add(fmt.Sprintf("k%d", i), t0.Add(time.Duration(i-3)*10*time.Second))
	}
	run(10 * time.Minute)
	if n := mails(); n != 1 {
		t.Fatalf("e-mails %d, want 1 (the first at once)", n)
	}
	f.now = t0.Add(10*time.Minute + time.Second) // the setting became 30 minutes: the window of 10 still ends now
	run(30 * time.Minute)
	if n := mails(); n != 2 || summaries("2", "10") != 1 {
		t.Fatalf("e-mails %d (summary of 2 over 10 minutes: %d), want the summary of the 10-minute window", n, summaries("2", "10"))
	}
	add("k3", f.now) // held back in the window of 30 minutes the summary opened
	add("k4", f.now.Add(time.Second))
	f.now = f.now.Add(time.Minute)
	run(30 * time.Minute)
	if n := mails(); n != 2 {
		t.Fatalf("e-mails %d inside the new window, want 2", n)
	}
	f.now = f.now.Add(time.Minute) // the grouping is turned off: the two held-back sign-ins are sent, not dropped
	run(0)
	if n := mails(); n != 3 || summaries("2", "30") != 1 {
		t.Fatalf("e-mails %d (summary of 2 over 30 minutes: %d), want the held-back sign-ins in one summary", n,
			summaries("2", "30"))
	}
	var state string
	if err := f.su.QueryRow(context.Background(), `SELECT value::text FROM system_settings WHERE key = $1`,
		consoleWindowKey).Scan(&state); err != nil || state != "{}" {
		t.Fatalf("windows after the grouping was turned off: %q, %v — want none", state, err)
	}
	run(0)
	add("k5", f.now)
	run(0)
	if n := f.count(`SELECT count(*) FROM notification_outbox WHERE kind = 'idp.console_login'
		AND payload ->> 'event_id' = 'k5' AND payload ->> 'count' IS NULL`); n != 1 || mails() != 4 {
		t.Errorf("e-mails %d, want 4 (nothing more flushed, the new sign-in at once)", mails())
	}
	if n := f.count(`SELECT count(*) FROM security_events WHERE tenant_id IS NULL AND kind = $1 AND severity = 'high'`,
		KindConsoleLogin); n != 6 {
		t.Errorf("security events %d, want one per sign-in (6)", n)
	}
}

// TestConsoleWindowLength: the length a summary announces — the stored one; for a window stored before its length
// was, the configured one; with the grouping off as well, the span it held (at least a minute).
func TestConsoleWindowLength(t *testing.T) {
	for _, c := range []struct {
		w          consoleWindow
		configured time.Duration
		want       time.Duration
	}{
		{consoleWindow{WindowMs: (10 * time.Minute).Milliseconds()}, 30 * time.Minute, 10 * time.Minute},
		{consoleWindow{WindowMs: (10 * time.Minute).Milliseconds()}, 0, 10 * time.Minute},
		{consoleWindow{StartMs: 1000, LastMs: 2000}, 15 * time.Minute, 15 * time.Minute},
		{consoleWindow{StartMs: 1000, LastMs: 1000 + (150 * time.Second).Milliseconds()}, 0, 150 * time.Second},
		{consoleWindow{StartMs: 1000, LastMs: 2000}, 0, time.Minute},
	} {
		if got := c.w.length(c.configured); got != c.want {
			t.Errorf("%+v at %s: %s, want %s", c.w, c.configured, got, c.want)
		}
	}
}

// TestSourceList: the sources of a summary stay one bounded, valid payload text.
func TestSourceList(t *testing.T) {
	if got := sourceList([]string{"admin-cli 192.0.2.1", "security-admin-console 192.0.2.2"}, 0); got !=
		"admin-cli 192.0.2.1, security-admin-console 192.0.2.2" {
		t.Errorf("%q", got)
	}
	var many []string
	for i := range maxSources {
		many = append(many, fmt.Sprintf("%s 192.0.2.%d", strings.Repeat("c", 60), i))
	}
	got := sourceList(many, 3)
	if len(got) > maxSourcesText+16 || !strings.HasSuffix(got, ")") || !strings.Contains(got, " (+") {
		t.Errorf("%d bytes: %q", len(got), got)
	}
	if got := sourceList([]string{strings.Repeat("ộ", 200)}, 0); !utf8.ValidString(got) || len(got) > maxSourceBytes ||
		len(got) < maxSourceBytes-3 {
		t.Errorf("long source: %d bytes, valid %v", len(got), utf8.ValidString(got))
	}
}
