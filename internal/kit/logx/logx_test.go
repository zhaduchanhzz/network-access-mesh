package logx

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/requestid"
)

// TestCanarySecretsNeverLogged writes canary secrets through every path a caller might use and asserts none of
// them reaches the output (the "canary secret" test of §25.1 rule 9).
func TestCanarySecretsNeverLogged(t *testing.T) {
	const canary = "CANARY-7f3a9c1e"
	var buf bytes.Buffer
	log := New(&buf, slog.LevelDebug, "test")

	log.Info("login", "password", canary)
	log.Info("call", "Authorization", "Bearer "+canary, "db_password_file", "/run/secrets/x")
	log.Info("pre-auth key issued: hskey-auth-abc123-" + canary)
	log.Info("nested", slog.Group("req", "token", canary, "cookie", canary))
	log.Debug("api", "detail", "using hskey-api-prefix1-"+canary+" for tenant")

	// P2-T14: secrets inside error values and free text (an upstream error quoting a request, a DSN, a cookie).
	log.Error("upstream", "error", fmt.Errorf("headscale: key hskey-api-abc-%s rejected", canary))
	log.Error("upstream", "err", errors.New("GET /api/v1/node: Authorization: Bearer "+canary))
	jwt := "eyJhbGciOiJSUzI1NiJ9" + ".eyJzdWIiOiIx" + canary + ".c2ln" // split so secret scanners see no literal JWT
	log.Warn("idp said: id_token=" + jwt)
	log.Error("db", "error", errors.New("dial postgres://mg_api:"+canary+"@postgres:5432/meshguard failed"))
	log.Info("cookie header", "detail", "__Host-mg_session="+canary+"; __Host-mg_authreq="+canary)
	log.Info("callback", "detail", "/auth/callback?code=x&client_secret="+canary+"&csrf_token="+canary)
	log.Info("upstream body", "detail", `{"error":"invalid_client","client_secret": "`+canary+`"}`)
	log.Info("grouped", slog.Group("x_mg_token", "value", canary))
	log.Info("dsn", "dsn", "host=postgres password="+canary)

	// Whole HTTP values an HTTP hook might log for "debugging".
	h := http.Header{}
	h.Set("Authorization", "Bearer "+canary)
	h.Set("X-Api-Key", canary)
	h.Set("Cookie", "__Host-mg_session="+canary)
	h.Set("Referer", "https://app.example/?token="+canary)
	h.Set("Accept", "application/json")
	log.Info("headers", "headers", h)
	log.Info("query", "query", url.Values{"code": {canary}, "state": {canary}})
	u, err := url.Parse("https://user:" + canary + "@app.example/api/v1/auth/callback?code=" + canary + "#f" + canary)
	if err != nil {
		t.Fatal(err)
	}
	log.Info("url", "url", u)
	log.Info("dashed header name", "X-Mg-Token", canary)

	out := buf.String()
	if strings.Contains(out, canary) {
		t.Fatalf("canary secret leaked into log output:\n%s", out)
	}
	if got := strings.Count(out, Redacted); got < 25 {
		t.Fatalf("expected at least 25 redactions, got %d:\n%s", got, out)
	}
	if !strings.Contains(out, `"service":"test"`) {
		t.Fatalf("service attribute missing:\n%s", out)
	}
	// Redaction keeps the rest of the message readable.
	for _, want := range []string{"headscale: key [REDACTED] rejected", "Bearer [REDACTED]", "mg_api:[REDACTED]@postgres",
		`"Accept":["application/json"]`, `"url":"https://app.example/api/v1/auth/callback?[REDACTED]"`} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

// TestNoFalseRedaction: ordinary values that merely resemble the patterns stay intact.
func TestNoFalseRedaction(t *testing.T) {
	for _, s := range []string{
		"http://host:8080/path", "tokens=5", "token_count=3", "status code=500", "GET /api/v1/tenants",
		"0194f3a2-7c1e-7d40-8a55-0d1b2c3e4f50",
	} {
		if got := RedactString(s); got != s {
			t.Errorf("RedactString(%q) = %q", s, got)
		}
	}
}

func TestRequestIDFromContext(t *testing.T) {
	var buf bytes.Buffer
	log := New(&buf, slog.LevelInfo, "test")
	ctx := requestid.With(context.Background(), "rid-42")

	log.InfoContext(ctx, "with context")
	log.InfoContext(ctx, "explicit", RequestIDKey, "rid-explicit")
	log.With("k", "v").InfoContext(ctx, "derived logger")
	log.Info("no context")

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 4 {
		t.Fatalf("want 4 lines, got %d:\n%s", len(lines), buf.String())
	}
	want := []string{"rid-42", "rid-explicit", "rid-42", ""}
	for i, ln := range lines {
		var rec map[string]any
		if err := json.Unmarshal([]byte(ln), &rec); err != nil {
			t.Fatalf("line %d is not JSON: %v", i, err)
		}
		got, _ := rec[RequestIDKey].(string)
		if got != want[i] || strings.Count(ln, `"`+RequestIDKey+`"`) > 1 {
			t.Errorf("line %d: request_id %q (want %q): %s", i, got, want[i], ln)
		}
	}
}

func TestParseLevel(t *testing.T) {
	for in, want := range map[string]slog.Level{"debug": slog.LevelDebug, "info": slog.LevelInfo, "warn": slog.LevelWarn, "error": slog.LevelError} {
		got, err := ParseLevel(in)
		if err != nil || got != want {
			t.Errorf("ParseLevel(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	if _, err := ParseLevel("verbose"); err == nil {
		t.Error("ParseLevel accepted an unknown level")
	}
}
