package mailrelay

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// fakeWorker checks a request exactly as infrastructure/mail/cf-worker does (timestamp window, HMAC over
// timestamp + "\n" + hex(sha256(body)), JSON body) and answers from a script.
type fakeWorker struct {
	t       testing.TB
	key     []byte
	mu      sync.Mutex
	got     []sendRequest
	sigs    []string
	answers []fakeAnswer
	delay   time.Duration
}

type fakeAnswer struct {
	status int
	body   string
}

func (w *fakeWorker) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	w.mu.Lock()
	defer w.mu.Unlock()
	ts, sig := r.Header.Get(HeaderTimestamp), r.Header.Get(HeaderSignature)
	sum := sha256.Sum256(body)
	mac := hmac.New(sha256.New, w.key)
	mac.Write([]byte(ts + "\n" + hex.EncodeToString(sum[:])))
	n, err := strconv.ParseInt(ts, 10, 64)
	switch {
	case r.Method != http.MethodPost || r.URL.Path != "/v1/send":
		rw.WriteHeader(http.StatusNotFound)
		return
	case err != nil || time.Since(time.Unix(n, 0)).Abs() > 300*time.Second:
		rw.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(rw, `{"ok":false,"code":"auth_timestamp"}`)
		return
	case !hmac.Equal([]byte(sig), []byte(hex.EncodeToString(mac.Sum(nil)))):
		rw.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(rw, `{"ok":false,"code":"auth_signature"}`)
		return
	}
	var req sendRequest
	if err := json.Unmarshal(body, &req); err != nil || r.Header.Get("Content-Type") != "application/json" {
		w.t.Errorf("bad request body: %v", err)
	}
	w.got = append(w.got, req)
	w.sigs = append(w.sigs, sig)
	if w.delay > 0 {
		time.Sleep(w.delay)
	}
	a := fakeAnswer{200, `{"ok":true,"code":"sent","sent":1,"failed":0}`}
	if len(w.answers) > 0 {
		a, w.answers = w.answers[0], w.answers[1:]
	}
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(a.status)
	_, _ = io.WriteString(rw, a.body)
}

func (w *fakeWorker) requests() []sendRequest {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]sendRequest(nil), w.got...)
}

func keyFile(t testing.TB, value string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "relay_hmac_key")
	if err := os.WriteFile(p, []byte(value), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// testKey is built from a repeated word: no credential-like literal for the secret scan (gitleaks).
var testKey = strings.Repeat("relay-test-", 4)

func newForwarder(t testing.TB, url, key string, m *Metrics) *HTTPForwarder {
	t.Helper()
	f, err := NewHTTPForwarder(ForwarderConfig{URL: url, KeyFile: key, Metrics: m, AttemptTimeout: 2 * time.Second,
		Backoff: []time.Duration{10 * time.Millisecond}})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestForwardSignsAndClassifies(t *testing.T) {
	w := &fakeWorker{t: t, key: []byte(testKey)}
	srv := httptest.NewServer(w)
	defer srv.Close()
	reg := prometheus.NewRegistry()
	m, _ := NewMetrics(reg)
	kf := keyFile(t, testKey+"\n") // trailing newline of `echo > file` is ignored
	f := newForwarder(t, srv.URL+"/v1/send", kf, m)
	raw := []byte("From: no-reply@example.com\r\nSubject: s\r\n\r\nbody\r\n")
	ctx := context.Background()

	out := f.Forward(ctx, "no-reply@example.com", []string{"a@example.org"}, raw)
	if out.Class != Delivered || out.Code != "sent" || out.Sent != 1 || out.Attempts != 1 || out.Status != 200 {
		t.Fatalf("delivered: %+v", out)
	}
	req := w.requests()[0]
	dec, _ := base64.StdEncoding.DecodeString(req.RawB64)
	if req.From != "no-reply@example.com" || len(req.To) != 1 || req.To[0] != "a@example.org" || string(dec) != string(raw) {
		t.Fatalf("request body: %+v", req)
	}

	cases := []struct {
		name     string
		answers  []fakeAnswer
		class    Class
		code     string
		attempts int
	}{
		{"partial", []fakeAnswer{{200, `{"ok":true,"code":"partial","sent":1,"failed":1}`}}, Partial, "partial", 1},
		{"5xx then sent", []fakeAnswer{{503, `{"ok":false,"code":"send_failed"}`}, {200, `{"ok":true,"code":"sent","sent":1}`}}, Delivered, "sent", 2},
		{"429 three times", []fakeAnswer{{429, `{"ok":false,"code":"send_failed"}`}, {429, `{}`}, {429, `{}`}}, Temporary, "http_429", 3},
		{"422 permanent, no retry", []fakeAnswer{{422, `{"ok":false,"code":"send_failed"}`}}, Permanent, "send_failed", 1},
		{"400 permanent", []fakeAnswer{{400, `not json`}}, Permanent, "http_400", 1},
		{"404 wrong URL: temporary, no retry", []fakeAnswer{{404, `{"ok":false,"code":"not_found"}`}}, Temporary, "not_found", 1},
		{"redirect not followed", []fakeAnswer{{302, ``}}, Temporary, "http_302", 1},
		{"strange code is not echoed", []fakeAnswer{{500, `{"code":"<script>"}`}, {500, `{}`}, {500, `{}`}}, Temporary, "http_500", 3},
	}
	for _, tc := range cases {
		w.mu.Lock()
		w.answers, w.got = tc.answers, nil
		w.mu.Unlock()
		out := f.Forward(ctx, "no-reply@example.com", []string{"a@example.org", "b@example.org"}, raw)
		if out.Class != tc.class || out.Code != tc.code || out.Attempts != tc.attempts || len(w.requests()) != tc.attempts {
			t.Errorf("%s: %+v (requests %d)", tc.name, out, len(w.requests()))
		}
	}
	if val(t, m.attempts.WithLabelValues("5xx")) != 4 || val(t, m.attempts.WithLabelValues("429")) != 3 {
		t.Error("forward_attempts_total by status class")
	}

	// two attempts in the same second carry the same signature: the Worker dedupes on the body digest, never on it
	w.mu.Lock()
	w.answers, w.got, w.sigs = []fakeAnswer{{503, `{}`}, {200, `{"code":"sent","sent":1}`}}, nil, nil
	w.mu.Unlock()
	fixed := time.Now()
	f.cfg.Now = func() time.Time { return fixed }
	f.Forward(ctx, "no-reply@example.com", []string{"a@example.org"}, raw)
	w.mu.Lock()
	if len(w.sigs) != 2 || w.sigs[0] != w.sigs[1] {
		t.Error("same timestamp and body must give the same signature")
	}
	w.mu.Unlock()
	f.cfg.Now = time.Now

	// wrong key ⇒ 401 ⇒ temporary (a deployment fault), not retried; the rotated key is used at the next message
	if err := os.WriteFile(kf, []byte("Z"+testKey[1:]), 0o600); err != nil {
		t.Fatal(err)
	}
	if out := f.Forward(ctx, "no-reply@example.com", []string{"a@example.org"}, raw); out.Class != Temporary ||
		out.Code != "auth_signature" || out.Attempts != 1 || out.Status != 401 {
		t.Fatalf("wrong key: %+v", out)
	}
	w.mu.Lock()
	w.key = []byte("Z" + testKey[1:])
	w.mu.Unlock()
	if out := f.Forward(ctx, "no-reply@example.com", []string{"a@example.org"}, raw); out.Class != Delivered {
		t.Fatalf("rotated key without restart: %+v", out)
	}
	// unreadable or short key ⇒ temporary, nothing sent
	for _, bad := range []string{filepath.Join(t.TempDir(), "missing"), keyFile(t, "short")} {
		f2 := newForwarder(t, srv.URL+"/v1/send", bad, nil)
		w.mu.Lock()
		w.got = nil
		w.mu.Unlock()
		if out := f2.Forward(ctx, "no-reply@example.com", []string{"a@example.org"}, raw); out.Class != Temporary ||
			out.Code != "key_unavailable" || len(w.requests()) != 0 {
			t.Fatalf("bad key file %s: %+v", bad, out)
		}
	}
	if KeyReadable(kf) != nil || KeyReadable(filepath.Join(t.TempDir(), "x")) == nil {
		t.Fatal("KeyReadable")
	}
}

func TestForwardTimeoutAndBudget(t *testing.T) {
	w := &fakeWorker{t: t, key: []byte(testKey), delay: 800 * time.Millisecond}
	srv := httptest.NewServer(w)
	defer srv.Close()
	f, err := NewHTTPForwarder(ForwarderConfig{URL: srv.URL + "/v1/send", KeyFile: keyFile(t, testKey),
		AttemptTimeout: 200 * time.Millisecond, Attempts: 5, Backoff: []time.Duration{50 * time.Millisecond}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	t0 := time.Now()
	out := f.Forward(ctx, "no-reply@example.com", []string{"a@example.org"}, []byte("x"))
	if out.Class != Temporary || out.Code != "timeout" || out.Attempts < 2 || time.Since(t0) > 2*time.Second {
		t.Fatalf("timeouts: %+v after %v", out, time.Since(t0))
	}
	// the context budget ends the retries
	ctx2, cancel2 := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel2()
	if out := f.Forward(ctx2, "no-reply@example.com", []string{"a@example.org"}, []byte("x")); out.Class != Temporary ||
		out.Attempts != 1 {
		t.Fatalf("budget: %+v", out)
	}
	if _, err := NewHTTPForwarder(ForwarderConfig{URL: "", KeyFile: "x"}); err == nil {
		t.Fatal("URL required")
	}
}
