//go:build mgtestfixture

package sessionfixture

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi"
	"github.com/zhaduchanhzz/network-access-mesh/internal/identity"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// UserAgent is the user_agent recorded on minted sessions (GET /auth/sessions shows it).
const UserAgent = "mg-sessionfixture"

// Session is a signed-in client of the API: what the Portal holds after a login. Its cookie value and CSRF token are
// reachable only through CookieValue and CSRFToken — String, GoString and LogValue never print them.
type Session struct {
	Actor             *Actor          // nil for an anonymous client (World.Anonymous)
	Origin            identity.Origin // origin the session is bound to (sessions.origin)
	Host              string          // host the requests go to: the origin's host, unless OnHost changed it
	PublicID          uuid.UUID       // sessions.public_id (GET/DELETE /auth/sessions)
	AuthTime          time.Time
	IdleExpiresAt     time.Time
	AbsoluteExpiresAt time.Time

	cookie, csrf string
}

// LoginOption adjusts a minted session.
type LoginOption func(*loginOptions)

type loginOptions struct {
	authTime time.Time
}

// WithAuthTime sets the auth_time of the session (default: now) — older than 15 minutes, the session is valid but no
// longer satisfies step-up (§8.3 step 7).
func WithAuthTime(t time.Time) LoginOption { return func(o *loginOptions) { o.authTime = t } }

// Login mints a session of a on the origin of its scope, the way the identity module stores one after an OIDC
// callback (32 random bytes, only their SHA-256 in sessions.id_hash, the module's InsertSession query on the api
// platform pool, idle/absolute expiry of the scope), and has the module authenticate it: a session the module would
// refuse fails the test at once. The CSRF token is the module's (identity.Session.CSRFToken).
func (w *World) Login(t testing.TB, a *Actor, opts ...LoginOption) *Session {
	t.Helper()
	var o loginOptions
	for _, fn := range opts {
		fn(&o)
	}
	now := w.now()
	if o.authTime.IsZero() {
		o.authTime = now
	}
	timeouts := identity.DefaultTenantTimeouts
	if a.Scope == identity.ScopePlatform {
		timeouts = identity.DefaultPlatformTimeouts
	}
	absolute := now.Add(timeouts.Absolute)
	idle := now.Add(timeouts.Idle)
	if idle.After(absolute) {
		idle = absolute
	}
	raw := make([]byte, 32)
	_, _ = rand.Read(raw) // crypto/rand.Read never fails (Go ≥ 1.24)
	sum := sha256.Sum256(raw)
	origin := a.Origin()
	ua := UserAgent
	ctx := context.Background()
	var row sqlcdb.Session
	err := w.Store.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		var err error
		row, err = q.InsertSession(ctx, sqlcdb.InsertSessionParams{
			IDHash: sum[:], IdentityID: a.IdentityID, IdpID: a.IdPID, Origin: string(origin), Now: now,
			AuthTime: o.authTime, IdleExpiresAt: idle, AbsoluteExpiresAt: absolute, UserAgent: &ua, Amr: []string{},
		})
		return err
	})
	if err != nil {
		t.Fatalf("sessionfixture: insert the session of %s: %v", a, err)
	}
	cookie := base64.RawURLEncoding.EncodeToString(raw)
	sess, err := w.Identity.Authenticate(ctx, cookie, origin)
	if err != nil {
		t.Fatalf("sessionfixture: the identity module refuses the minted session of %s: %v", a, err)
	}
	if sess.PublicID != row.PublicID || sess.IdentityID != a.IdentityID || sess.Origin != origin {
		t.Fatalf("sessionfixture: the module resolved the session of %s to %v", a, sess)
	}
	return &Session{
		Actor: a, Origin: origin, Host: w.host(origin), PublicID: row.PublicID, AuthTime: row.AuthTime,
		IdleExpiresAt: row.IdleExpiresAt, AbsoluteExpiresAt: row.AbsoluteExpiresAt,
		cookie: cookie, csrf: sess.CSRFToken(),
	}
}

// Anonymous returns a client without session on origin (requests carry no cookie and no CSRF token).
func (w *World) Anonymous(origin identity.Origin) *Session {
	return &Session{Origin: origin, Host: w.host(origin)}
}

// Do sends one request of s through the composed API, in process: path is below /api/v1 ("/tenants/<id>/devices"),
// hdr adds headers (e.g. Idempotency-Key). The request is what the Portal sends (Session.Apply).
func (w *World) Do(t testing.TB, s *Session, method, path string, body io.Reader, hdr http.Header) *httptest.ResponseRecorder {
	t.Helper()
	r := s.Request(context.Background(), method, path, body)
	for k, vs := range hdr {
		for _, v := range vs {
			r.Header.Add(k, v)
		}
	}
	rec := httptest.NewRecorder()
	w.API.ServeHTTP(rec, r)
	return rec
}

// CookieName is the name of the session cookie (__Host-mg_session).
func (s Session) CookieName() string { return identity.SessionCookieName }

// CookieValue is the value of the session cookie ("" for an anonymous client). Never log it.
func (s Session) CookieValue() string { return s.cookie }

// CSRFToken is the X-CSRF-Token of the session ("" for an anonymous client). Never log it.
func (s Session) CSRFToken() string { return s.csrf }

// Cookie returns the session cookie with the attributes the callback sets (Secure; HttpOnly; SameSite=Lax; Path=/).
func (s Session) Cookie() *http.Cookie { return identity.SessionCookie(s.cookie) }

// OriginHeader is the Origin header a browser sends from the session's host.
func (s Session) OriginHeader() string { return "https://" + s.Host }

// OnHost returns a copy that sends the same cookie and token to host — a session of one origin presented on the
// other, for negative tests (a browser never does it: the __Host- cookie is bound to its host).
func (s Session) OnHost(host string) *Session {
	s.Host = host
	return &s
}

// Apply adds to r what the Portal sends with the session: the cookie and, for a state-changing method, Origin:
// https://<host> and X-CSRF-Token (§8.3 step 5). It works on a client request (http.NewRequest, for an API served
// elsewhere — set r.Host to s.Host) as on a server one.
func (s Session) Apply(r *http.Request) {
	if s.cookie != "" {
		r.AddCookie(&http.Cookie{Name: identity.SessionCookieName, Value: s.cookie}) //nolint:gosec // request cookie (attributes only exist in Set-Cookie)
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
	default:
		r.Header.Set("Origin", s.OriginHeader())
		if s.csrf != "" {
			r.Header.Set(identity.CSRFHeader, s.csrf)
		}
	}
}

// Request returns a server-side request (httptest) to path below /api/v1 on the session's host, with Apply's
// headers and, when there is a body, Content-Type: application/json.
func (s Session) Request(ctx context.Context, method, path string, body io.Reader) *http.Request {
	r := httptest.NewRequestWithContext(ctx, method, "https://"+s.Host+httpapi.BaseURL+path, body)
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	s.Apply(r)
	return r
}

// String describes the session without its secrets.
func (s Session) String() string {
	who := "anonymous"
	if s.Actor != nil {
		who = s.Actor.String()
	}
	return "sessionfixture.Session{" + who + " on " + string(s.Origin) + " via " + s.Host + ", public_id=" +
		s.PublicID.String() + "}"
}

// GoString is String (%#v must not print the cookie either).
func (s Session) GoString() string { return s.String() }

// LogValue implements slog.LogValuer without the secrets.
func (s Session) LogValue() slog.Value {
	return slog.StringValue(s.String())
}
