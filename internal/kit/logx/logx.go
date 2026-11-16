// Package logx builds the JSON slog logger used by every MeshGuard process. Attributes whose key (or enclosing group)
// looks sensitive, and secrets embedded in a string or error value — Headscale credentials, bearer tokens, JWTs,
// passwords inside URLs, Portal cookies, `token=…`/`"secret": "…"` pairs — are replaced before the record is written
// (§16.5, §25.1): secrets must never reach a log line, whatever the caller passes. A whole http.Header, url.Values or
// *url.URL is filtered too (credential headers, every query value and userinfo dropped). Records logged with a
// request context also carry its `request_id` (§13.1, internal/kit/requestid).
package logx

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/requestid"
)

// Redacted replaces every sensitive value.
const Redacted = "[REDACTED]"

// RequestIDKey is the attribute that carries the request id of the context a record was logged with.
const RequestIDKey = "request_id"

var sensitiveKeyParts = []string{
	"password", "passwd", "secret", "token", "authorization", "cookie",
	"api_key", "apikey", "private_key", "privatekey", "preauth", "pre_auth", "credential",
	"dsn", "verifier", "csrf",
}

// hskeyPattern matches Headscale API keys, pre-auth keys and web-auth IDs (RT-12, ID-05).
var hskeyPattern = regexp.MustCompile(`hskey-(?:api|auth|authreq)-[A-Za-z0-9_-]+`)

// sensitiveName is the name part of a `name=value` or JSON `"name": "value"` pair whose value is a secret.
const sensitiveName = `[A-Za-z0-9_]*(?:token|secret|password|passwd|api_?key|code_verifier)`

// valuePatterns rewrite secrets embedded in free text — typically an error message that quotes a request, a URL or
// an upstream response.
var valuePatterns = []struct {
	re   *regexp.Regexp
	repl string
}{
	{hskeyPattern, Redacted},
	{regexp.MustCompile(`(?i)\b(bearer)\s+[A-Za-z0-9._~+/=-]+`), "${1} " + Redacted},
	{regexp.MustCompile(`\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*`), Redacted}, // JWT (ID/access token)
	{regexp.MustCompile(`(\b[A-Za-z][A-Za-z0-9+.-]*://[^\s:/@]*:)[^\s/@]+@`), "${1}" + Redacted + "@"},
	{regexp.MustCompile(`(mg_session|mg_authreq)=[^;\s]+`), "${1}=" + Redacted}, // Portal cookies (§8.3)
	{regexp.MustCompile(`(?i)(` + sensitiveName + `)=[^&\s;,"']+`), "${1}=" + Redacted},
	{regexp.MustCompile(`(?i)("` + sensitiveName + `"\s*:\s*)"[^"]*"`), `${1}"` + Redacted + `"`},
}

// New returns a JSON logger tagged with the service name.
func New(w io.Writer, level slog.Leveler, service string) *slog.Logger {
	h := slog.NewJSONHandler(w, &slog.HandlerOptions{Level: level, ReplaceAttr: redact})
	return slog.New(contextHandler{h}).With("service", service)
}

// ParseLevel accepts debug, info, warn and error.
func ParseLevel(s string) (slog.Level, error) {
	var l slog.Level
	err := l.UnmarshalText([]byte(s))
	return l, err
}

// RedactString applies the free-text patterns to s.
func RedactString(s string) string {
	for _, p := range valuePatterns {
		s = p.re.ReplaceAllString(s, p.repl)
	}
	return s
}

// sensitiveKey matches attribute keys, group names and header names ("X-Api-Key" is read as "x_api_key").
func sensitiveKey(key string) bool {
	key = strings.ReplaceAll(strings.ToLower(key), "-", "_")
	for _, part := range sensitiveKeyParts {
		if strings.Contains(key, part) {
			return true
		}
	}
	return false
}

func redact(groups []string, a slog.Attr) slog.Attr {
	if sensitiveKey(a.Key) {
		return slog.String(a.Key, Redacted)
	}
	for _, g := range groups {
		if sensitiveKey(g) {
			return slog.String(a.Key, Redacted)
		}
	}
	switch a.Value.Kind() {
	case slog.KindString:
		if v := a.Value.String(); v != "" {
			if r := RedactString(v); r != v {
				return slog.String(a.Key, r)
			}
		}
	case slog.KindAny:
		// Values the JSON handler would print without passing through the rules above.
		switch v := a.Value.Any().(type) {
		case error: // printed as its Error() text
			return slog.String(a.Key, RedactString(v.Error()))
		case http.Header: // a whole header map: credential headers dropped, other values filtered
			out := make(map[string][]string, len(v))
			for k, vals := range v {
				if sensitiveKey(k) {
					out[k] = []string{Redacted}
					continue
				}
				for _, s := range vals {
					out[k] = append(out[k], RedactString(s))
				}
			}
			return slog.Any(a.Key, out)
		case url.Values: // a query string: every value is client-supplied (OAuth code, state, cursor…)
			out := make(map[string][]string, len(v))
			for k := range v {
				out[k] = []string{Redacted}
			}
			return slog.Any(a.Key, out)
		case *url.URL: // would be printed field by field, RawQuery and userinfo included
			return slog.String(a.Key, redactURL(v))
		}
	}
	return a
}

// redactURL prints u without userinfo, query or fragment.
func redactURL(u *url.URL) string {
	if u == nil {
		return ""
	}
	c := *u
	hadQuery := c.RawQuery != "" || c.ForceQuery
	c.User, c.RawQuery, c.ForceQuery, c.Fragment, c.RawFragment = nil, "", false, "", ""
	s := RedactString(c.String())
	if hadQuery {
		s += "?" + Redacted
	}
	return s
}

// contextHandler adds the request id of the record's context (requestid.From) unless the record already has one.
type contextHandler struct{ slog.Handler }

func (h contextHandler) Handle(ctx context.Context, r slog.Record) error {
	if id := requestid.From(ctx); id != "" {
		has := false
		r.Attrs(func(a slog.Attr) bool {
			has = a.Key == RequestIDKey
			return !has
		})
		if !has {
			r = r.Clone()
			r.AddAttrs(slog.String(RequestIDKey, id))
		}
	}
	return h.Handler.Handle(ctx, r)
}

func (h contextHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return contextHandler{h.Handler.WithAttrs(attrs)}
}

func (h contextHandler) WithGroup(name string) slog.Handler {
	return contextHandler{h.Handler.WithGroup(name)}
}
