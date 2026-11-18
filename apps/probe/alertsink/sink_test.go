package alertsink

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/logx"
)

var loopback = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}

// webhook is a notification exactly as Alertmanager v0.34 sends it (fields this sink ignores included).
const webhook = `{"receiver":"meshguard","status":"firing","alerts":[{"status":"firing","labels":{"alertname":"TenantInstanceDown","severity":"critical","slug":"tenant-b","tenant_id":"01a1e611-0000-7000-8000-000000000001"},"annotations":{"summary":"Instance tenant-b không trả lời","url":"https://x/?token=abcdefghijklmnop"},"startsAt":"2026-11-18T03:00:00.123Z","endsAt":"0001-01-01T00:00:00Z","generatorURL":"http://prometheus:9090/graph","fingerprint":"0123456789abcdef"}],"groupLabels":{"alertname":"TenantInstanceDown","slug":"tenant-b"},"commonLabels":{"alertname":"TenantInstanceDown"},"commonAnnotations":{},"externalURL":"http://alertmanager:9093","version":"4","groupKey":"{}:{alertname=\"TenantInstanceDown\"}","truncatedAlerts":0}`

func post(t *testing.T, srv *httptest.Server, ctype, body string) (int, string) {
	t.Helper()
	return do(t, srv, http.MethodPost, RouteAlerts, ctype, body)
}

// do sends one request (with the test's context) and returns status and body.
func do(t *testing.T, srv *httptest.Server, method, path, ctype, body string) (int, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, srv.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestReceiveAndList(t *testing.T) {
	var logs bytes.Buffer
	reg := prometheus.NewRegistry()
	now := time.Date(2026, 11, 18, 3, 2, 0, 0, time.UTC)
	s := New(Options{Callers: loopback, Keep: 3, Registerer: reg, Logger: logx.New(&logs, slog.LevelInfo, "test"),
		Now: func() time.Time { return now }})
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)

	if code, body := post(t, srv, "application/json", webhook); code != 200 || !strings.Contains(body, `"ok":true`) {
		t.Fatalf("receive: %d %s", code, body)
	}
	resolved := strings.Replace(strings.Replace(webhook, `"status":"firing","alerts":[{"status":"firing"`,
		`"status":"resolved","alerts":[{"status":"resolved"`, 1), `"endsAt":"0001-01-01T00:00:00Z"`,
		`"endsAt":"2026-11-18T03:05:00Z"`, 1)
	if code, _ := post(t, srv, "application/json; charset=utf-8", resolved); code != 200 {
		t.Fatalf("resolved: %d", code)
	}
	other := strings.ReplaceAll(webhook, "TenantInstanceDown", "CertificateExpiringSoon")
	if code, _ := post(t, srv, "application/json", other); code != 200 {
		t.Fatalf("other: %d", code)
	}
	n := s.Notifications()
	if len(n) != 3 || n[0].Seq != 1 || n[0].Status != "firing" || n[1].Status != "resolved" ||
		n[0].Receiver != "meshguard" || n[0].ReceivedAt != now || len(n[0].Alerts) != 1 {
		t.Fatalf("notifications %+v", n)
	}
	a := n[0].Alerts[0]
	if a.Labels["alertname"] != "TenantInstanceDown" || a.Labels["slug"] != "tenant-b" || a.Status != "firing" ||
		!a.EndsAt.IsZero() || a.StartsAt.Nanosecond() != 123000000 || a.Fingerprint != "0123456789abcdef" ||
		!strings.Contains(a.Annotations["summary"], "tenant-b") {
		t.Fatalf("alert %+v", a)
	}
	if !n[1].Alerts[0].EndsAt.Equal(time.Date(2026, 11, 18, 3, 5, 0, 0, time.UTC)) {
		t.Fatalf("resolved endsAt %v", n[1].Alerts[0].EndsAt)
	}
	// values are redacted before they are kept and logged
	if strings.Contains(a.Annotations["url"], "abcdefghijklmnop") || strings.Contains(logs.String(), "abcdefghijklmnop") {
		t.Fatalf("token kept or logged: %q\n%s", a.Annotations["url"], logs.String())
	}
	if !strings.Contains(logs.String(), `"alertname":"TenantInstanceDown"`) {
		t.Fatalf("log line:\n%s", logs.String())
	}
	// list, filtered by alert name
	_, listed := do(t, srv, http.MethodGet, RouteNotifications+"?alertname=CertificateExpiringSoon", "", "")
	var got struct{ Notifications []Notification }
	err := json.Unmarshal([]byte(listed), &got)
	if err != nil || len(got.Notifications) != 1 || got.Notifications[0].Seq != 3 {
		t.Fatalf("filtered list %+v %v", got, err)
	}
	// bounded: the oldest is dropped first
	if code, _ := post(t, srv, "application/json", webhook); code != 200 {
		t.Fatal(code)
	}
	if n := s.Notifications(); len(n) != 3 || n[0].Seq != 2 || n[2].Seq != 4 {
		t.Fatalf("keep 3: %+v", n)
	}
	if v := gathered(t, reg, "meshguard_alertsink_notifications_total", map[string]string{"receiver": "meshguard", "status": "firing"}); v != 3 {
		t.Fatalf("firing counter %v", v)
	}
	if v := gathered(t, reg, "meshguard_alertsink_last_notification_timestamp_seconds", nil); v != float64(now.Unix()) {
		t.Fatalf("last %v", v)
	}
}

// gathered is the value of the series name{labels} in reg (-1 when absent).
func gathered(t *testing.T, reg *prometheus.Registry, name string, labels map[string]string) float64 {
	t.Helper()
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
	next:
		for _, m := range mf.GetMetric() {
			got := map[string]string{}
			for _, lp := range m.GetLabel() {
				got[lp.GetName()] = lp.GetValue()
			}
			for k, v := range labels {
				if got[k] != v {
					continue next
				}
			}
			if m.GetGauge() != nil {
				return m.GetGauge().GetValue()
			}
			return m.GetCounter().GetValue()
		}
	}
	return -1
}

func TestRefusals(t *testing.T) {
	s := New(Options{Callers: loopback})
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	for _, c := range []struct {
		name, ctype, body string
		status            int
	}{
		{"not JSON", "text/plain", webhook, 415},
		{"garbage", "application/json", "{", 400},
		{"two objects", "application/json", webhook + webhook, 400},
		{"version 3", "application/json", strings.Replace(webhook, `"version":"4"`, `"version":"3"`, 1), 400},
		{"no alerts", "application/json", `{"version":"4","status":"firing","alerts":[]}`, 400},
		{"bad status", "application/json", strings.Replace(webhook, `"status":"firing","alerts"`, `"status":"x","alerts"`, 1), 400},
		{"too large", "application/json", `{"version":"4","x":"` + strings.Repeat("a", maxBody) + `"}`, 413},
	} {
		if code, _ := post(t, srv, c.ctype, c.body); code != c.status {
			t.Errorf("%s: %d, want %d", c.name, code, c.status)
		}
	}
	for path, want := range map[string]int{RouteNotifications: 405, "/v1/other": 404} {
		if code, _ := do(t, srv, http.MethodPost, path, "application/json", "{}"); code != want {
			t.Errorf("POST %s: %d, want %d", path, code, want)
		}
	}
	if len(s.Notifications()) != 0 {
		t.Fatal("a refused request was kept")
	}
	// callers outside the allow-list (and an empty allow-list) are refused before routing
	for _, callers := range [][]netip.Prefix{{netip.MustParsePrefix("10.0.0.0/8")}, nil} {
		other := httptest.NewServer(New(Options{Callers: callers}).Handler())
		code, _ := post(t, other, "application/json", webhook)
		getCode, _ := do(t, other, http.MethodGet, RouteNotifications, "", "")
		other.Close()
		if code != http.StatusForbidden || getCode != http.StatusForbidden {
			t.Errorf("callers %v: POST %d GET %d", callers, code, getCode)
		}
	}
}

// Values are bounded on a rune boundary; label maps are bounded too.
func TestBounds(t *testing.T) {
	long := strings.Repeat("é", maxValue) // 2 bytes each
	if c := clean(long); len(c) > maxValue+len("…") || !strings.HasSuffix(c, "…") || !strings.HasPrefix(c, "éé") {
		t.Fatalf("clean: %d bytes", len(c))
	}
	m := map[string]string{}
	for i := range maxPairs + 10 {
		m[strings.Repeat("k", i+1)] = "v"
	}
	if got := cleanMap(m); len(got) != maxPairs {
		t.Fatalf("cleanMap kept %d", len(got))
	}
	if cleanMap(nil) != nil {
		t.Fatal("nil map")
	}
}
