package identity

import (
	"context"
	"net/http"
)

// CSRFHeader carries the CSRF token on state-changing requests (§8.3 step 5).
const CSRFHeader = "X-CSRF-Token"

// RequestInfo is what the middleware learns about a request before any handler runs.
type RequestInfo struct {
	Origin    Origin // from the Host header: app or admin
	ClientIP  string
	UserAgent string
	RequestID string // X-Request-Id set by the request-id middleware (runs first)
	Path      string // URL path only — never the query, which may carry a code or a state
	// FetchSite is the Sec-Fetch-Site header of the request (Fetch Metadata): "" when absent; "invalid" when present
	// in a form no browser sends (empty or repeated). BeginLogin refuses any value but same-origin and none (G2 F1).
	FetchSite string
}

type ctxKey int

const (
	keyInfo ctxKey = iota + 1
	keySession
)

// WithRequestInfo returns ctx carrying info (the middleware does this; exported for callers that build contexts
// outside an HTTP request, such as tests or jobs).
func WithRequestInfo(ctx context.Context, info RequestInfo) context.Context {
	return context.WithValue(ctx, keyInfo, info)
}

// RequestInfoFromContext returns the request information set by Middleware.
func RequestInfoFromContext(ctx context.Context) (RequestInfo, bool) {
	info, ok := ctx.Value(keyInfo).(RequestInfo)
	return info, ok
}

// SessionFromContext returns the authenticated session of the request, set by Middleware only after the session
// passed every check (not revoked, not expired, same origin, identity and IdP usable, CSRF on unsafe methods).
func SessionFromContext(ctx context.Context) (*Session, bool) {
	s, ok := ctx.Value(keySession).(*Session)
	return s, ok && s != nil
}

func withSession(ctx context.Context, s *Session) context.Context {
	return context.WithValue(ctx, keySession, s)
}

// safeMethod reports the methods that must not change state; every other method needs the CSRF token and a
// same-origin Origin/Sec-Fetch-Site (§8.3 step 5).
func safeMethod(m string) bool {
	switch m {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return true
	}
	return false
}

// Middleware is the session layer of the public API (a gen.MiddlewareFunc, func(http.Handler) http.Handler). For
// every request it:
//
//  1. maps the Host header to the origin (app or admin) — any other host is answered 404;
//  2. for a state-changing method, requires the Origin header to be exactly https://<host>, or — when the browser
//     sent no Origin — Sec-Fetch-Site: same-origin; otherwise 403 (CORS stays off: the Portal is same-origin);
//  3. resolves __Host-mg_session: a session that is unknown, revoked, expired, of the other origin or of a disabled
//     identity/IdP is simply not attached (the operation then answers 401 when it needs a session); a database
//     failure answers 500 (fail closed);
//  4. for a state-changing method with a session, requires X-CSRF-Token = HMAC-SHA256(session id, "csrf-v1"),
//     otherwise 403;
//  5. stores RequestInfo and the session in the context (RequestInfoFromContext, SessionFromContext) and sets
//     Cache-Control: no-store.
//
// Its own refusals are answered through Config.ProblemWriter. It must run after the request-id middleware and before
// authorization.
func (s *Service) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqID := truncateUTF8(s.cfg.RequestID(r), 128)
		origin, ok := s.hosts.origin(r.Host)
		if !ok {
			s.writeProblem(w, r, reqID, newErr(KindNotFound, "unknown_host", nil))
			return
		}
		info := RequestInfo{
			Origin: origin, ClientIP: s.cfg.ClientIP(r), UserAgent: truncateUTF8(r.UserAgent(), maxUserAgent),
			RequestID: reqID, Path: r.URL.Path, FetchSite: fetchSite(r),
		}
		ctx := WithRequestInfo(r.Context(), info)
		w.Header().Set("Cache-Control", "no-store")
		unsafe := !safeMethod(r.Method)
		if unsafe {
			if reason := s.checkFetchOrigin(r, origin); reason != "" {
				s.audit.Record(ctx, AuditEvent{Action: ActionSessionCheck, Outcome: OutcomeDenied, Reason: reason,
					Origin: origin, ClientIP: info.ClientIP, RequestID: reqID})
				s.writeProblem(w, r, reqID, forbidden(reason))
				return
			}
		}
		var sess *Session
		if c, err := r.Cookie(SessionCookieName); err == nil && c.Value != "" {
			sess, err = s.Authenticate(ctx, c.Value, origin)
			if err != nil {
				e := AsError(err)
				if e.Kind != KindUnauthenticated {
					s.log.ErrorContext(ctx, "session lookup failed", "reason", e.Reason, "error", errString(e))
					s.writeProblem(w, r, reqID, e)
					return
				}
				if e.Reason == "session_origin_mismatch" || e.Reason == "session_scope_origin_mismatch" {
					s.audit.Record(ctx, AuditEvent{Action: ActionSessionCheck, Outcome: OutcomeDenied, Reason: e.Reason,
						Origin: origin, ClientIP: info.ClientIP, RequestID: reqID})
				}
				sess = nil
			}
		}
		if sess != nil && unsafe && !validCSRF(sess.raw, r.Header.Get(CSRFHeader)) {
			s.audit.Record(ctx, AuditEvent{Action: ActionSessionCheck, Outcome: OutcomeDenied, Reason: "csrf_token_invalid",
				IdentityID: sess.IdentityID, TenantID: sess.TenantID, IdPID: sess.IdPID, SessionID: sess.PublicID,
				Origin: origin, ClientIP: info.ClientIP, RequestID: reqID})
			s.writeProblem(w, r, reqID, forbidden("csrf_token_invalid"))
			return
		}
		if sess != nil {
			ctx = withSession(ctx, sess)
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// writeProblem answers a request the middleware refuses itself: Config.ProblemWriter when set, else WriteProblem.
func (s *Service) writeProblem(w http.ResponseWriter, r *http.Request, reqID string, err error) {
	if s.cfg.ProblemWriter != nil {
		s.cfg.ProblemWriter(w, r, err)
		return
	}
	WriteProblem(w, err, reqID, r.URL.Path)
}

// fetchSite returns the Sec-Fetch-Site header of r: "" when absent, the value when sent once and non-empty, "invalid"
// otherwise (no browser sends an empty or a repeated Sec-Fetch-Site) — RequestInfo.FetchSite.
func fetchSite(r *http.Request) string {
	vs := r.Header.Values("Sec-Fetch-Site")
	switch {
	case len(vs) == 0:
		return ""
	case len(vs) == 1 && vs[0] != "":
		return truncateUTF8(vs[0], 32)
	}
	return "invalid"
}

// checkFetchOrigin returns "" when a state-changing request comes from this origin's own pages.
func (s *Service) checkFetchOrigin(r *http.Request, o Origin) string {
	if got := r.Header.Get("Origin"); got != "" {
		if got != s.hosts.baseURL(o) {
			return "origin_header_mismatch"
		}
		return ""
	}
	switch r.Header.Get("Sec-Fetch-Site") {
	case "same-origin":
		return ""
	case "":
		return "origin_header_missing"
	}
	return "sec_fetch_site_cross_origin"
}
