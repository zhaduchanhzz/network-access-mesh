// Package httpapi assembles the public REST API of the Management Plane (§13): the strict server generated from
// api/openapi.yaml (internal/httpapi/gen, never edited) mounted under BaseURL, behind the middleware chain of §13.1 and
// layer 1 of §8.8. Outermost first:
//
//	requestID          X-Request-Id: reuse a well-formed client value or generate one; response header, context, logs
//	accessLog          one JSON line per request — only values our code controls, through logx redaction
//	recoverer          panic ⇒ 500 internal_error; panic value never logged or sent (runtime errors excepted)
//	limit(byIP)        token bucket per client IP and class (auth, enrollment, sync, default); RateLimit-*, 429
//	limitBody          request body cap (Options.MaxBodyBytes) ⇒ 422 validation_failed
//	Hooks.Session      slot of P2-T06: resolve the session cookie, call SetIdentity (no-op until filled)
//	limit(byIdentity)  token bucket per identity and class
//	Hooks.CSRF         slot of P2-T06: X-CSRF-Token + Origin/Sec-Fetch-Site on unsafe methods (no-op until filled)
//	router             ServeMux: the generated routes + a catch-all answering 404 not_found (unknown path or method)
//	  binding          generated parameter binding ⇒ 422 validation_failed naming the parameter
//	  strict           body decoding ⇒ 422; strict middleware: operation recorder, Hooks.Audit (slot of P2-T08),
//	                   Hooks.Authz (slot of P2-T07)
//	  handler          Handlers (per-domain sets; 501 not_implemented until mounted) ⇒ errors rendered as problems
//
// Every error leaves as RFC 9457 problem+json (internal/httpapi/problem).
package httpapi

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"time"

	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/gen"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/problem"
)

// BaseURL is the prefix of every operation (servers[0].url of api/openapi.yaml).
const BaseURL = "/api/v1"

// DefaultMaxBodyBytes caps a request body when Options.MaxBodyBytes is 0.
const DefaultMaxBodyBytes int64 = 1 << 20

// Hooks are the security slots of the chain filled by other tasks. A nil hook lets every request through.
type Hooks struct {
	// Session (P2-T06) resolves the `__Host-mg_session` cookie, puts the principal in the context and calls SetIdentity;
	// it may answer 401 itself with WriteProblem. Runs after the per-IP limit, before the per-identity limit.
	Session func(http.Handler) http.Handler
	// CSRF (P2-T06) checks X-CSRF-Token and Origin/Sec-Fetch-Site on unsafe methods (§8.3 step 5). Runs before routing.
	CSRF func(http.Handler) http.Handler
	// Authz (P2-T07) receives the Go operation name ("ListDevices"), maps it to its x-permission and checks it against
	// the principal and the tenant of the path (§8.8 layer 1); it denies by returning a *problem.Error. Runs after
	// parameter binding, before the handler.
	Authz gen.StrictMiddlewareFunc
	// Audit (P2-T08, internal/httpapi/auditapi) wraps Authz and the handler: it sets the audit scope of the request and,
	// once they returned, writes the denied/failure event on the detached path and closes the request's paired events
	// (§6.1, §8.8). It sees errors only — a handler reports a failure by returning it.
	Audit gen.StrictMiddlewareFunc
}

// Options configure New.
type Options struct {
	Logger   *slog.Logger // required — use logx.New (redaction, request_id from the context)
	Handlers Handlers     // the extension point; the zero value answers 501 everywhere
	Hooks    Hooks
	// TrustedProxies are the peers whose X-Forwarded-For is believed (the edge on mg-edge, config MG_TRUSTED_PROXIES);
	// empty ⇒ the peer address is the client address.
	TrustedProxies []netip.Prefix
	RateLimits     RateLimits       // nil or missing classes ⇒ DefaultRateLimits
	RateLimitKeys  int              // cap of tracked keys per bucket; 0 ⇒ ratelimit.DefaultMaxKeys
	MaxBodyBytes   int64            // 0 ⇒ DefaultMaxBodyBytes
	Now            func() time.Time // clock of the rate limiter; nil ⇒ time.Now (tests inject a fake clock)
}

type server struct {
	log      *slog.Logger
	trusted  []netip.Prefix
	maxBody  int64
	now      func() time.Time
	limiters map[Class]classLimiters
}

// New returns the handler of the public listener. Mounting a handler set without an Authz hook is refused: an
// operation would otherwise be reachable without any permission check (deny by default, §8.4 invariant 4).
func New(opts Options) (http.Handler, error) {
	if opts.Logger == nil {
		return nil, errors.New("httpapi: Logger is required")
	}
	if opts.Handlers.mounted() && opts.Hooks.Authz == nil {
		return nil, errors.New("httpapi: handlers are mounted but Hooks.Authz is nil — every operation would skip authorization")
	}
	limiters, err := newLimiters(opts.RateLimits, opts.RateLimitKeys)
	if err != nil {
		return nil, err
	}
	s := &server{log: opts.Logger, trusted: opts.TrustedProxies, maxBody: opts.MaxBodyBytes, now: opts.Now, limiters: limiters}
	if s.maxBody <= 0 {
		s.maxBody = DefaultMaxBodyBytes
	}
	if s.now == nil {
		s.now = time.Now
	}

	var middlewares []gen.StrictMiddlewareFunc // the last one runs first: recordOperation → Audit → Authz → handler
	for _, mw := range []gen.StrictMiddlewareFunc{opts.Hooks.Authz, opts.Hooks.Audit, recordOperation} {
		if mw != nil {
			middlewares = append(middlewares, mw)
		}
	}
	strict := gen.NewStrictHandlerWithOptions(newDispatcher(opts.Handlers), middlewares, gen.StrictHTTPServerOptions{
		RequestErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
			WriteProblem(w, r, problem.FromBodyError(err))
		},
		ResponseErrorHandlerFunc: WriteProblem,
	})
	mux := http.NewServeMux()
	gen.HandlerWithOptions(strict, gen.StdHTTPServerOptions{
		BaseURL:    BaseURL,
		BaseRouter: routeRecorder{mux},
		ErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
			WriteProblem(w, r, problem.FromBindError(err))
		},
	})
	// A pattern without method or host matches what no generated route does — unknown paths and methods a path does
	// not declare (no 405 with a non-problem body) — and answers 404 not_found, the only §13.1 code for it.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		WriteProblem(w, r, problem.New(gen.ProblemCodeNotFound, "No operation matches this method and path."))
	})

	var h http.Handler = mux
	for _, mw := range []func(http.Handler) http.Handler{ // innermost first
		opts.Hooks.CSRF, s.limit(byIdentity), opts.Hooks.Session, s.limitBody, s.limit(byIP),
		s.recoverer, s.accessLog, s.requestID,
	} {
		if mw != nil {
			h = mw(h)
		}
	}
	return h, nil
}

// routeRecorder registers the generated routes on the ServeMux and records the matched pattern of each request.
type routeRecorder struct{ *http.ServeMux }

func (m routeRecorder) HandleFunc(pattern string, handler func(http.ResponseWriter, *http.Request)) {
	m.ServeMux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		if info := infoFrom(r.Context()); info != nil {
			info.set(func(i *requestInfo) { i.route = pattern })
		}
		handler(w, r)
	})
}

// recordOperation is the outermost strict middleware: it records the Go operation name for logs, authz and audit.
func recordOperation(f gen.StrictHandlerFunc, operationID string) gen.StrictHandlerFunc {
	return func(ctx context.Context, w http.ResponseWriter, r *http.Request, request any) (any, error) {
		if info := infoFrom(ctx); info != nil {
			info.set(func(i *requestInfo) { i.operation = operationID })
		}
		return f(ctx, w, r, request)
	}
}
