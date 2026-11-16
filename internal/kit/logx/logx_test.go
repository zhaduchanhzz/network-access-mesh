package logx

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
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

	out := buf.String()
	if strings.Contains(out, canary) {
		t.Fatalf("canary secret leaked into log output:\n%s", out)
	}
	if got := strings.Count(out, Redacted); got < 6 {
		t.Fatalf("expected at least 6 redactions, got %d:\n%s", got, out)
	}
	if !strings.Contains(out, `"service":"test"`) {
		t.Fatalf("service attribute missing:\n%s", out)
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
