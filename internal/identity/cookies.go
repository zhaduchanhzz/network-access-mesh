package identity

import (
	"net/http"
	"time"
)

// Cookie names (§8.3). The __Host- prefix makes browsers require Secure, Path=/ and no Domain attribute, so the
// cookie is bound to exactly one host: a session of app.<domain> is never sent to admin.<domain>.
const (
	SessionCookieName     = "__Host-mg_session"
	AuthRequestCookieName = "__Host-mg_authreq"
)

// SessionCookie returns the session cookie for an encoded session id: Secure; HttpOnly; SameSite=Lax; Path=/, no
// Domain, no Max-Age (the browser drops it with the browsing session; the server enforces the timeouts).
func SessionCookie(value string) *http.Cookie {
	return &http.Cookie{
		Name: SessionCookieName, Value: value, Path: "/",
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	}
}

// AuthRequestCookie returns the browser-binding cookie of a pending login. SameSite=Lax (not Strict) because the
// callback is a top-level navigation coming back from the IdP, which may be another site.
func AuthRequestCookie(value string, ttl time.Duration) *http.Cookie {
	return &http.Cookie{
		Name: AuthRequestCookieName, Value: value, Path: "/", MaxAge: int(ttl / time.Second),
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	}
}

// ExpiredCookie returns a Set-Cookie that deletes the named __Host- cookie (Max-Age=0 and an expiry in the past).
func ExpiredCookie(name string) *http.Cookie {
	return &http.Cookie{
		Name: name, Value: "", Path: "/", MaxAge: -1, Expires: time.Unix(0, 0),
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	}
}
