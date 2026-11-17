package identity

import (
	"net"
	"strings"
)

// Origin is the Portal origin a request arrives on and a session is bound to (§8.3): app.<domain> (Tenant Portal)
// or admin.<domain> (Platform Console). Values match sessions.origin and SessionOrigin of the API.
type Origin string

const (
	OriginApp   Origin = "app"
	OriginAdmin Origin = "admin"
)

// Scope is the scope of an IdP and of the identities it authenticates (§8.4 invariant 1).
type Scope string

const (
	ScopePlatform Scope = "platform"
	ScopeTenant   Scope = "tenant"
)

// originForScope is the only origin a scope may log in on: tenant identities on app, platform staff on admin.
func originForScope(s Scope) Origin {
	if s == ScopePlatform {
		return OriginAdmin
	}
	return OriginApp
}

// hosts maps the two public host names to origins.
type hosts struct {
	app, admin string
}

// origin returns the origin of a request Host header; unknown hosts are rejected.
func (h hosts) origin(host string) (Origin, bool) {
	switch normalizeHost(host) {
	case h.app:
		return OriginApp, true
	case h.admin:
		return OriginAdmin, true
	}
	return "", false
}

// host returns the public host name of an origin.
func (h hosts) host(o Origin) string {
	if o == OriginAdmin {
		return h.admin
	}
	return h.app
}

// baseURL returns https://<host> of an origin — the value browsers send in the Origin header.
func (h hosts) baseURL(o Origin) string { return "https://" + h.host(o) }

// normalizeHost lower-cases a Host header value and removes a port and a trailing dot.
func normalizeHost(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	if hp, _, err := net.SplitHostPort(host); err == nil {
		host = hp
	}
	return strings.TrimSuffix(host, ".")
}
