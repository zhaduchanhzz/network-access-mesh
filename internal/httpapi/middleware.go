package httpapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"runtime"
	"runtime/debug"
	"sync"
	"time"

	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/gen"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/problem"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/ratelimit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/requestid"
)

// requestInfo is the per-request record shared by the chain: set up by requestID, filled by the router, the strict
// middleware, the session hook and the rate limiter, read by the access log at the end. Only values our code
// controls go in here — never a header, query or body value of the request.
type requestInfo struct {
	mu        sync.Mutex
	clientIP  netip.Addr
	rec       *recorder
	route     string          // matched pattern, e.g. "GET /api/v1/tenants/{tenantId}/devices"
	operation string          // Go operation name, e.g. "ListDevices"
	identity  string          // set by the session hook (SetIdentity)
	problem   gen.ProblemCode // code of the problem sent, if any
	cause     error           // internal cause of a 5xx problem (logged, redacted)
	limit     *ratelimit.Decision
	denied    string // "<class>/<ip|identity>" of the bucket that answered 429
	aborted   bool
}

type infoKey struct{}

func infoFrom(ctx context.Context) *requestInfo {
	info, _ := ctx.Value(infoKey{}).(*requestInfo)
	return info
}

// SetIdentity records the authenticated identity of the request. The session hook (P2-T06) calls it once it has
// resolved the session, so that per-identity rate limiting and the access log see the caller. key must be a stable,
// non-secret identifier (identities.id) — never a session id, cookie or token.
func SetIdentity(ctx context.Context, key string) {
	if info := infoFrom(ctx); info != nil {
		info.mu.Lock()
		info.identity = key
		info.mu.Unlock()
	}
}

// Operation returns the Go name of the operation being served ("ListDevices"); "" before the strict layer — for the
// authz hook and audit (P2-T07, P2-T08).
func Operation(ctx context.Context) string {
	if info := infoFrom(ctx); info != nil {
		info.mu.Lock()
		defer info.mu.Unlock()
		return info.operation
	}
	return ""
}

// ClientIP returns the client address of the request (X-Forwarded-For is trusted only from Options.TrustedProxies).
func ClientIP(ctx context.Context) netip.Addr {
	if info := infoFrom(ctx); info != nil {
		return info.clientIP
	}
	return netip.Addr{}
}

func (i *requestInfo) set(f func(*requestInfo)) {
	i.mu.Lock()
	f(i)
	i.mu.Unlock()
}

func (i *requestInfo) started() bool {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.rec != nil && i.rec.status != 0
}

// WriteProblem answers the request with err rendered as a problem: a *problem.Error (also when wrapped) as is, any
// other error as 500 internal_error whose text goes to the access log only. Use it from hooks; handlers and strict
// middleware simply return the error. Nothing is written once the response has started.
func WriteProblem(w http.ResponseWriter, r *http.Request, err error) {
	var p *problem.Error
	cause := err // logged for a 5xx: the whole chain, including what wraps the problem
	if !errors.As(err, &p) {
		p = problem.Internal(err)
	} else if p.Cause == nil && errors.Unwrap(err) == nil {
		cause = nil // a bare problem: its code is already on the access line
	}
	if info := infoFrom(r.Context()); info != nil {
		info.set(func(i *requestInfo) {
			i.problem = p.Code
			if p.Status() >= http.StatusInternalServerError && cause != nil {
				i.cause = cause
			}
		})
		if info.started() {
			return
		}
	}
	problem.Write(w, r, p)
}

// recorder captures the status and size of the response for the access log and tells whether it has started.
type recorder struct {
	http.ResponseWriter
	info   *requestInfo
	status int
	bytes  int64
}

func (rw *recorder) WriteHeader(code int) {
	rw.info.mu.Lock()
	if rw.status == 0 && code >= 200 {
		rw.status = code
	}
	rw.info.mu.Unlock()
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *recorder) Write(b []byte) (int, error) {
	rw.info.mu.Lock()
	if rw.status == 0 {
		rw.status = http.StatusOK
	}
	rw.info.mu.Unlock()
	n, err := rw.ResponseWriter.Write(b)
	rw.info.mu.Lock()
	rw.bytes += int64(n)
	rw.info.mu.Unlock()
	return n, err
}

// Unwrap lets http.ResponseController reach the connection's writer (flush, deadlines).
func (rw *recorder) Unwrap() http.ResponseWriter { return rw.ResponseWriter }

// requestID is the outermost middleware: it accepts a well-formed X-Request-Id or generates one, sends it back on
// every response, and puts it — with the requestInfo — in the context (logs, problems, audit and jobs read it there).
func (s *server) requestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get(requestid.Header)
		if !requestid.Valid(id) {
			id = requestid.New()
		}
		w.Header().Set(requestid.Header, id)
		info := &requestInfo{clientIP: clientIP(r, s.trusted)}
		ctx := context.WithValue(requestid.With(r.Context(), id), infoKey{}, info)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// methods are logged as is; any other method token (client-controlled) is logged as OTHER.
var methods = map[string]bool{
	http.MethodGet: true, http.MethodHead: true, http.MethodPost: true, http.MethodPut: true, http.MethodPatch: true,
	http.MethodDelete: true, http.MethodOptions: true, http.MethodConnect: true, http.MethodTrace: true,
}

// accessLog writes one line per request when it ends (also when a panic aborts it). It logs only values our code
// controls — never headers, the query string, the body or the raw path (an unmatched path may carry anything); the
// request id is added by logx from the context and every string goes through logx redaction.
func (s *server) accessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		info := infoFrom(r.Context())
		rec := &recorder{ResponseWriter: w, info: info}
		info.set(func(i *requestInfo) { i.rec = rec })
		defer func() { s.logRequest(r, info, time.Since(start)) }()
		next.ServeHTTP(rec, r)
	})
}

func (s *server) logRequest(r *http.Request, info *requestInfo, d time.Duration) {
	info.mu.Lock()
	defer info.mu.Unlock()
	method := r.Method
	if !methods[method] {
		method = "OTHER"
	}
	status := info.rec.status
	if status == 0 {
		status = http.StatusOK // nothing written: net/http sends 200
	}
	attrs := []slog.Attr{
		slog.String("method", method),
		slog.Int("status", status),
		slog.Int64("bytes", info.rec.bytes),
		slog.Float64("duration_ms", float64(d.Microseconds())/1000),
		slog.String("client_ip", info.clientIP.String()),
	}
	for _, kv := range [][2]string{{"route", info.route}, {"operation", info.operation}, {"identity", info.identity},
		{"problem", string(info.problem)}, {"rate_limited_by", info.denied}} {
		if kv[1] != "" {
			attrs = append(attrs, slog.String(kv[0], kv[1]))
		}
	}
	level := slog.LevelInfo
	switch {
	case info.cause != nil && errors.Is(info.cause, context.Canceled):
		attrs = append(attrs, slog.Bool("canceled", true)) // the client went away: not an incident
	case status == http.StatusNotImplemented:
		// an operation whose handler is not mounted yet: expected until its task lands
	case status == http.StatusBadGateway, status == http.StatusServiceUnavailable, status == http.StatusTooManyRequests:
		level = slog.LevelWarn // a tenant instance rejected the call or is down; a client reached its limit
	case status >= http.StatusInternalServerError:
		level = slog.LevelError
	}
	if info.cause != nil {
		attrs = append(attrs, slog.Any("error", info.cause))
	}
	if info.aborted {
		attrs = append(attrs, slog.Bool("aborted", true))
	}
	s.log.LogAttrs(r.Context(), level, "http request", attrs...)
}

// recoverer turns a panic into 500 internal_error. The log line has the panic type and the stack — and the message
// only for a runtime error, whose text the runtime writes; any other panic value may hold request data and is never
// logged or sent. A panic after the response started aborts the connection (the client sees a truncated response).
func (s *server) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			v := recover()
			if v == nil {
				return
			}
			err, _ := v.(error)
			if errors.Is(err, http.ErrAbortHandler) {
				panic(v)
			}
			attrs := []slog.Attr{slog.String("panic_type", fmt.Sprintf("%T", v)), slog.String("stack", string(debug.Stack()))}
			var rt runtime.Error
			if errors.As(err, &rt) {
				attrs = append(attrs, slog.String("panic", rt.Error()))
			}
			s.log.LogAttrs(r.Context(), slog.LevelError, "panic recovered", attrs...)
			info := infoFrom(r.Context())
			if info != nil && info.started() {
				info.set(func(i *requestInfo) { i.aborted = true })
				panic(http.ErrAbortHandler)
			}
			WriteProblem(w, r, problem.Internal(nil))
		}()
		next.ServeHTTP(w, r)
	})
}

// limitBody rejects a declared Content-Length above the limit at once and caps the body actually read (chunked
// bodies) with http.MaxBytesReader; the strict handler maps the resulting error to the same 422 problem.
func (s *server) limitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ContentLength > s.maxBody {
			WriteProblem(w, r, problem.BodyTooLarge(s.maxBody))
			return
		}
		r.Body = http.MaxBytesReader(innermost(w), r.Body, s.maxBody)
		next.ServeHTTP(w, r)
	})
}

// innermost unwraps w down to the connection's writer, so that MaxBytesReader can tell the server to close the
// connection after an oversized body (it looks for an unexported method our wrappers cannot forward).
func innermost(w http.ResponseWriter) http.ResponseWriter {
	for range 16 {
		u, ok := w.(interface{ Unwrap() http.ResponseWriter })
		if !ok {
			break
		}
		w = u.Unwrap()
	}
	return w
}
