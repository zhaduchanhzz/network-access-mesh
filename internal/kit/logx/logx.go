// Package logx builds the JSON slog logger used by every MeshGuard process. Attributes whose key looks sensitive
// and any Headscale credential found in a string value are replaced before the record is written (§16.5, §25.1):
// secrets must never reach a log line, whatever the caller passes.
package logx

import (
	"io"
	"log/slog"
	"regexp"
	"strings"
)

// Redacted replaces every sensitive value.
const Redacted = "[REDACTED]"

var sensitiveKeyParts = []string{
	"password", "passwd", "secret", "token", "authorization", "cookie",
	"api_key", "apikey", "private_key", "privatekey", "preauth", "pre_auth", "credential",
}

// hskeyPattern matches Headscale API keys, pre-auth keys and web-auth IDs (RT-12, ID-05).
var hskeyPattern = regexp.MustCompile(`hskey-(?:api|auth|authreq)-[A-Za-z0-9_-]+`)

// New returns a JSON logger tagged with the service name.
func New(w io.Writer, level slog.Leveler, service string) *slog.Logger {
	h := slog.NewJSONHandler(w, &slog.HandlerOptions{Level: level, ReplaceAttr: redact})
	return slog.New(h).With("service", service)
}

// ParseLevel accepts debug, info, warn and error.
func ParseLevel(s string) (slog.Level, error) {
	var l slog.Level
	err := l.UnmarshalText([]byte(s))
	return l, err
}

func redact(_ []string, a slog.Attr) slog.Attr {
	key := strings.ToLower(a.Key)
	for _, part := range sensitiveKeyParts {
		if strings.Contains(key, part) {
			return slog.String(a.Key, Redacted)
		}
	}
	if a.Value.Kind() == slog.KindString {
		if v := a.Value.String(); hskeyPattern.MatchString(v) {
			return slog.String(a.Key, hskeyPattern.ReplaceAllString(v, Redacted))
		}
	}
	return a
}
