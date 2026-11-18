package httpapi

import (
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/gen"
	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/problem"
)

// MaintenanceRetryAfter is the Retry-After of a maintenance answer.
const MaintenanceRetryAfter = 60 * time.Second

// Maintenance configures the maintenance answer of the API (P3-T17, §17.2): while On reports true, every request —
// the public operations and the internal routes of the edge (the Keycloak console gate) alike — is answered 503
// maintenance before any session is resolved, except the platform sign-in on the admin origin (the operators who
// review the post-restore reconcile sign in again: every session was revoked). The health endpoints are on the
// internal listener and never pass here.
type Maintenance struct {
	// On reports the current state (platform.MaintenanceGate.On); nil = never in maintenance.
	On func() bool
	// AdminHost is admin.<domain>: the only host whose sign-in is served in maintenance ("" = none). The identity module
	// refuses a platform login on any other origin, and a tenant login on this one (scope ↔ origin, §8.3).
	AdminHost string
}

// signIn are the operations of the platform sign-in served in maintenance (method, path under BaseURL).
var signIn = map[string]bool{
	"GET " + BaseURL + "/auth/login":   true,
	"POST " + BaseURL + "/auth/logout": true,
	"GET " + BaseURL + "/auth/session": true,
}

// allowed reports whether r is part of the platform sign-in on the admin origin.
func (m Maintenance) allowed(r *http.Request) bool {
	if m.AdminHost == "" || !strings.EqualFold(hostOnly(r.Host), m.AdminHost) {
		return false
	}
	if signIn[r.Method+" "+r.URL.Path] {
		return true
	}
	rest, ok := strings.CutPrefix(r.URL.Path, BaseURL+"/auth/callback/")
	return ok && r.Method == http.MethodGet && rest != "" && !strings.Contains(rest, "/")
}

func hostOnly(h string) string {
	if host, _, err := net.SplitHostPort(h); err == nil {
		return host
	}
	return h
}

// middleware answers 503 maintenance while the gate is on.
func (m Maintenance) middleware(next http.Handler) http.Handler {
	if m.On == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if m.On() && !m.allowed(r) {
			WriteProblem(w, r, &problem.Error{Code: gen.ProblemCodeMaintenance, RetryAfter: MaintenanceRetryAfter,
				Detail: "The platform is in maintenance (a database restore is being reconciled); only the platform " +
					"sign-in is served. Try again later."})
			return
		}
		next.ServeHTTP(w, r)
	})
}
