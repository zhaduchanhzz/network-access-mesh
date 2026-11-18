package prober

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/logx"
)

// scrape GETs /probe with the given parameters (raw query, so duplicates can be sent) and returns status and body.
func scrape(t *testing.T, srv *httptest.Server, rawQuery string, header ...string) (int, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+RouteScrape+"?"+rawQuery, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(header) == 2 {
		req.Header.Set(header[0], header[1])
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// errCode is the code of a refusal body {"error": {"code", "message"}} ("" when the body is not one).
func errCode(body string) string {
	var doc struct {
		Error *Error `json:"error"`
	}
	if json.Unmarshal([]byte(body), &doc) != nil || doc.Error == nil {
		return ""
	}
	return doc.Error.Code
}

func q(kv ...string) string {
	v := url.Values{}
	for i := 0; i+1 < len(kv); i += 2 {
		v.Add(kv[i], kv[i+1])
	}
	return v.Encode()
}

// value returns the value of a sample line "name{labels} value" or "name value" in a text exposition (-1 if absent).
func value(body, series string) float64 {
	re := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(series) + ` (\S+)$`)
	m := re.FindStringSubmatch(body)
	if m == nil {
		return -1
	}
	f, _ := strconv.ParseFloat(m[1], 64)
	return f
}

func scrapeServer(t *testing.T, l *Local, o ScrapeOptions) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(ScrapeHandler(l, o))
	t.Cleanup(srv.Close)
	return srv
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

// The key module answers the blackbox contract: success, HTTP status, certificate expiry; a failed probe is a 200
// with probe_success 0 and the stable code — never a failed scrape.
func TestScrapeKey(t *testing.T) {
	e := newEdge(t)
	reg := prometheus.NewRegistry()
	srv := scrapeServer(t, New(Options{Allow: loopback, RootCAs: e.CA}), ScrapeOptions{Scrapers: loopback, Registerer: reg})
	addr := e.Addr().String()

	code, body := scrape(t, srv, q("module", "key", "target", addr, "host", e.Host("tenant-a")))
	if code != 200 || value(body, "probe_success") != 1 || value(body, "probe_http_status_code") != 200 ||
		value(body, "probe_duration_seconds") <= 0 {
		t.Fatalf("key tenant-a: %d\n%s", code, body)
	}
	exp := value(body, "probe_ssl_earliest_cert_expiry")
	if d := time.Until(time.Unix(int64(exp), 0)); d < 50*time.Minute || d > 61*time.Minute { // stub leaf: 1 hour
		t.Fatalf("certificate expiry %v (%v from now)", exp, d)
	}
	if strings.Contains(body, "probe_failure_info") {
		t.Fatalf("failure info on success:\n%s", body)
	}
	// the request went out as /key?v=113 with SNI = Host = the tenant's name
	got := e.Requests()
	if len(got) != 1 || got[0].Target != "/key?v=113" || got[0].SNI != e.Host("tenant-a") || got[0].Host != e.Host("tenant-a") {
		t.Fatalf("edge saw %+v", got)
	}
	// capver of the scrape wins over the default
	if code, body = scrape(t, srv, q("module", "key", "target", addr, "host", e.Host("tenant-b"), "capver", "130")); code != 200 ||
		value(body, "probe_success") != 1 || e.Requests()[1].Target != "/key?v=130" {
		t.Fatalf("capver 130: %d %+v\n%s", code, e.Requests(), body)
	}
	// unknown tenant ⇒ the edge's uniform 404 ⇒ failed probe, expectation_failed, certificate still reported
	code, body = scrape(t, srv, q("module", "key", "target", addr, "host", e.Host("ghost")))
	if code != 200 || value(body, "probe_success") != 0 || value(body, "probe_http_status_code") != 404 ||
		value(body, `probe_failure_info{code="expectation_failed"}`) != 1 || value(body, "probe_ssl_earliest_cert_expiry") <= 0 {
		t.Fatalf("ghost tenant: %d\n%s", code, body)
	}
	// SNI without a certificate ⇒ tls_handshake, no status, no expiry
	code, body = scrape(t, srv, q("module", "key", "target", addr, "host", "foreign.example"))
	if code != 200 || value(body, "probe_success") != 0 || value(body, `probe_failure_info{code="tls_handshake"}`) != 1 ||
		value(body, "probe_http_status_code") != -1 || value(body, "probe_ssl_earliest_cert_expiry") != -1 {
		t.Fatalf("foreign SNI: %d\n%s", code, body)
	}
	// outcomes are counted by module (bounded labels)
	if ok, failed := gathered(t, reg, "meshguard_probe_scrapes_total", map[string]string{"module": "key", "outcome": "ok"}),
		gathered(t, reg, "meshguard_probe_scrapes_total", map[string]string{"module": "key", "outcome": "failed"}); ok != 2 || failed != 2 {
		t.Fatalf("scrapes ok %v failed %v", ok, failed)
	}
}

// The tls module only runs the handshake: certificate of any site the edge holds one for; nothing is requested.
func TestScrapeTLS(t *testing.T) {
	e := newEdge(t)
	srv := scrapeServer(t, New(Options{Allow: loopback, RootCAs: e.CA}), ScrapeOptions{Scrapers: loopback})
	code, body := scrape(t, srv, q("module", "tls", "target", e.Addr().String(), "host", e.Host("tenant-a")))
	if code != 200 || value(body, "probe_success") != 1 || value(body, "probe_ssl_earliest_cert_expiry") <= 0 ||
		strings.Contains(body, "probe_http_status_code") {
		t.Fatalf("tls: %d\n%s", code, body)
	}
	if len(e.Requests()) != 0 || e.Conns() != 1 {
		t.Fatalf("tls module sent HTTP: %+v (conns %d)", e.Requests(), e.Conns())
	}
	// CA not trusted ⇒ tls_verify, no expiry (an unverified certificate is never reported)
	srv2 := scrapeServer(t, New(Options{Allow: loopback}), ScrapeOptions{Scrapers: loopback})
	code, body = scrape(t, srv2, q("module", "tls", "target", e.Addr().String(), "host", e.Host("tenant-a")))
	if code != 200 || value(body, "probe_success") != 0 || value(body, `probe_failure_info{code="tls_verify"}`) != 1 ||
		value(body, "probe_ssl_earliest_cert_expiry") != -1 {
		t.Fatalf("untrusted CA: %d\n%s", code, body)
	}
	// closed port ⇒ refused
	closed := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), 1).String()
	if code, body = scrape(t, srv, q("module", "tls", "target", closed, "host", e.Host("tenant-a"))); code != 200 ||
		value(body, `probe_failure_info{code="refused"}`) != 1 {
		t.Fatalf("closed port: %d\n%s", code, body)
	}
}

// Every refusal happens before anything is sent: wrong caller, wrong method, invalid or duplicated parameters, a
// target outside the allow-list. They are failed scrapes (4xx), never probe results.
func TestScrapeRefusals(t *testing.T) {
	e := newEdge(t)
	var logs bytes.Buffer
	l := New(Options{Allow: loopback, RootCAs: e.CA})
	srv := scrapeServer(t, l, ScrapeOptions{Scrapers: loopback, Logger: logx.New(&logs, slog.LevelDebug, "test")})
	addr, host := e.Addr().String(), e.Host("tenant-a")
	for _, c := range []struct {
		name, query string
		status      int
		code        string
	}{
		{"no module", q("target", addr, "host", host), 400, CodeInvalidRequest},
		{"unknown module", q("module", "http", "target", addr, "host", host), 400, CodeInvalidRequest},
		{"unknown parameter", q("module", "key", "target", addr, "host", host, "path", "/admin"), 400, CodeInvalidRequest},
		{"duplicated parameter", q("module", "key", "target", addr, "host", host) + "&host=" + host, 400, CodeInvalidRequest},
		{"name as target", q("module", "key", "target", "edge.example:443", "host", host), 400, CodeInvalidRequest},
		{"IP as host", q("module", "tls", "target", addr, "host", "127.0.0.1"), 400, CodeInvalidRequest},
		{"capver on tls", q("module", "tls", "target", addr, "host", host, "capver", "113"), 400, CodeInvalidRequest},
		{"capver not a number", q("module", "key", "target", addr, "host", host, "capver", "x"), 400, CodeInvalidRequest},
		{"capver out of range", q("module", "key", "target", addr, "host", host, "capver", "0"), 400, CodeInvalidRequest},
		{"target outside the allow-list", q("module", "key", "target", "192.0.2.1:443", "host", host), 403, CodeTargetNotAllowed},
		{"tls target outside the allow-list", q("module", "tls", "target", "[::ffff:192.0.2.1]:443", "host", host), 403, CodeTargetNotAllowed},
	} {
		code, body := scrape(t, srv, c.query)
		if code != c.status || errCode(body) != c.code {
			t.Errorf("%s: %d %q (want %d %s)", c.name, code, body, c.status, c.code)
		}
	}
	preq, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+RouteScrape+"?"+q("module", "key", "target",
		addr, "host", host), nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := srv.Client().Do(preq)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST: %d", resp.StatusCode)
	}
	// caller outside the scrape allow-list ⇒ 403 before anything else (an empty list refuses everyone)
	for _, scrapers := range [][]netip.Prefix{{netip.MustParsePrefix("10.0.0.0/8")}, nil} {
		other := scrapeServer(t, l, ScrapeOptions{Scrapers: scrapers})
		if code, body := scrape(t, other, q("module", "key", "target", addr, "host", host)); code != 403 ||
			errCode(body) != CodeCallerNotAllowed {
			t.Errorf("scrapers %v: %d %q", scrapers, code, body)
		}
	}
	if e.Conns() != 0 {
		t.Fatalf("a refused scrape reached the edge: %d connections", e.Conns())
	}
	if strings.Contains(logs.String(), "/admin") {
		t.Fatalf("refusal echoed the request:\n%s", logs.String())
	}
}

// The scrape budget follows Prometheus's scrape timeout header (less half a second, within 1 s … 15 s).
func TestScrapeBudget(t *testing.T) {
	for in, want := range map[string]time.Duration{"": DefaultHTTPSTimeout, "x": DefaultHTTPSTimeout, "-3": DefaultHTTPSTimeout,
		"10": 9500 * time.Millisecond, "1": time.Second, "0.2": time.Second, "60": MaxTimeout} {
		if got := scrapeBudget(in); got != want {
			t.Errorf("scrapeBudget(%q) = %v, want %v", in, got, want)
		}
	}
	// a slow target fails within the scrape budget, as a timeout
	e := newEdge(t)
	srv := scrapeServer(t, New(Options{Allow: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("192.0.2.0/24")}, RootCAs: e.CA}), ScrapeOptions{Scrapers: loopback})
	start := time.Now()
	code, body := scrape(t, srv, q("module", "tls", "target", "192.0.2.1:443", "host", e.Host("tenant-a")),
		"X-Prometheus-Scrape-Timeout-Seconds", "1.5")
	if d := time.Since(start); code != 200 || value(body, "probe_success") != 0 || d > 3*time.Second ||
		(value(body, `probe_failure_info{code="timeout"}`) != 1 && value(body, `probe_failure_info{code="unreachable"}`) != 1 &&
			value(body, `probe_failure_info{code="network_error"}`) != 1) {
		t.Fatalf("slow target: %d after %v\n%s", code, d, body)
	}
}
