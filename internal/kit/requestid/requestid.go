// Package requestid carries the request id of §13.1 ("X-Request-Id (sinh nếu thiếu) đi xuyên log, audit, job"):
// the HTTP chain (internal/httpapi) accepts a well-formed client value or generates one and stores it in the request
// context; every consumer reads it from there — the logger (internal/kit/logx adds it to each record logged with the
// request context), audit events (P2-T08) and job enqueue (P2-T12). It lives in kit so that base modules may import
// it (§13.6).
package requestid

import (
	"context"
	"strings"

	"github.com/google/uuid"
)

// Header carries the request id in requests and responses.
const Header = "X-Request-Id"

// MaxLen bounds a client-supplied id (audit_events.request_id accepts 200 characters).
const MaxLen = 128

// Valid reports whether a client-supplied id may be reused as is: 1–128 characters of [A-Za-z0-9._:-] starting with
// a letter or a digit, and not shaped like a Headscale credential. Anything else is replaced by a generated id, so
// the value written to logs and to audit_events never carries spaces, control characters, markup or an `hskey-`
// string planted by a client.
func Valid(id string) bool {
	if id == "" || len(id) > MaxLen || strings.Contains(strings.ToLower(id), "hskey") {
		return false
	}
	for i := 0; i < len(id); i++ {
		switch c := id[i]; {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		case i > 0 && (c == '.' || c == '_' || c == ':' || c == '-'):
		default:
			return false
		}
	}
	return true
}

// New returns a fresh id: a UUIDv7, time-ordered, so ids sort roughly by arrival.
func New() string {
	if id, err := uuid.NewV7(); err == nil {
		return id.String()
	}
	return uuid.NewString()
}

type ctxKey struct{}

// With returns a copy of ctx carrying id.
func With(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, ctxKey{}, id)
}

// From returns the request id carried by ctx, or "" outside a request.
func From(ctx context.Context) string {
	id, _ := ctx.Value(ctxKey{}).(string)
	return id
}
