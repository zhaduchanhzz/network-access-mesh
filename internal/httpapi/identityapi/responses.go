package identityapi

import (
	"bytes"
	"encoding/json"
	"net/http"

	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/gen"
	"github.com/zhaduchanhzz/network-access-mesh/internal/identity"
)

// The generated 302 responses of authLogin/authCallback hold exactly one Set-Cookie value, but the callback must set
// the session cookie AND delete the binding cookie (P2-T02 evidence, item 11). The strict server accepts any value
// implementing the operation's Visit…Response method, so the types below write the headers themselves.

// redirectResponse is a 302 with any number of cookies. It is never cached and sends no Referer onwards.
type redirectResponse struct {
	location string
	cookies  []*http.Cookie
}

func (r redirectResponse) write(w http.ResponseWriter) error {
	h := w.Header()
	h.Set("Location", r.location)
	for _, c := range r.cookies {
		h.Add("Set-Cookie", c.String())
	}
	h.Set("Cache-Control", "no-store")
	h.Set("Referrer-Policy", "no-referrer")
	w.WriteHeader(http.StatusFound)
	return nil
}

// VisitAuthLoginResponse implements gen.AuthLoginResponseObject.
func (r redirectResponse) VisitAuthLoginResponse(w http.ResponseWriter) error { return r.write(w) }

// VisitAuthCallbackResponse implements gen.AuthCallbackResponseObject.
func (r redirectResponse) VisitAuthCallbackResponse(w http.ResponseWriter) error { return r.write(w) }

// problemResponse is an RFC 9457 error of any auth operation, optionally deleting cookies.
type problemResponse struct {
	problem identity.Problem
	cookies []*http.Cookie
}

func (p problemResponse) write(w http.ResponseWriter) error {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(p.problem); err != nil {
		return err
	}
	h := w.Header()
	for _, c := range p.cookies {
		h.Add("Set-Cookie", c.String())
	}
	h.Set("Content-Type", "application/problem+json")
	h.Set("Cache-Control", "no-store")
	if p.problem.RequestID != "" {
		h.Set("X-Request-Id", p.problem.RequestID)
	}
	w.WriteHeader(p.problem.Status)
	_, err := buf.WriteTo(w)
	return err
}

// VisitAuthLoginResponse implements gen.AuthLoginResponseObject.
func (p problemResponse) VisitAuthLoginResponse(w http.ResponseWriter) error { return p.write(w) }

// VisitAuthCallbackResponse implements gen.AuthCallbackResponseObject.
func (p problemResponse) VisitAuthCallbackResponse(w http.ResponseWriter) error { return p.write(w) }

// VisitAuthLogoutResponse implements gen.AuthLogoutResponseObject.
func (p problemResponse) VisitAuthLogoutResponse(w http.ResponseWriter) error { return p.write(w) }

// VisitGetAuthSessionResponse implements gen.GetAuthSessionResponseObject.
func (p problemResponse) VisitGetAuthSessionResponse(w http.ResponseWriter) error { return p.write(w) }

// VisitListAuthSessionsResponse implements gen.ListAuthSessionsResponseObject.
func (p problemResponse) VisitListAuthSessionsResponse(w http.ResponseWriter) error {
	return p.write(w)
}

// VisitRevokeAuthSessionResponse implements gen.RevokeAuthSessionResponseObject.
func (p problemResponse) VisitRevokeAuthSessionResponse(w http.ResponseWriter) error {
	return p.write(w)
}

// sessionResponse is the 200 of GET /auth/session; it carries the CSRF token, so it is never cached.
type sessionResponse gen.Session

// VisitGetAuthSessionResponse implements gen.GetAuthSessionResponseObject.
func (s sessionResponse) VisitGetAuthSessionResponse(w http.ResponseWriter) error {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(gen.Session(s)); err != nil {
		return err
	}
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, err := buf.WriteTo(w)
	return err
}

// logoutResponse is the 204 of POST /auth/logout: it deletes the session cookie.
type logoutResponse struct{}

// VisitAuthLogoutResponse implements gen.AuthLogoutResponseObject.
func (logoutResponse) VisitAuthLogoutResponse(w http.ResponseWriter) error {
	h := w.Header()
	h.Add("Set-Cookie", identity.ExpiredCookie(identity.SessionCookieName).String())
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
	return nil
}

var (
	_ gen.AuthLoginResponseObject         = redirectResponse{}
	_ gen.AuthCallbackResponseObject      = redirectResponse{}
	_ gen.AuthLoginResponseObject         = problemResponse{}
	_ gen.AuthCallbackResponseObject      = problemResponse{}
	_ gen.AuthLogoutResponseObject        = problemResponse{}
	_ gen.GetAuthSessionResponseObject    = problemResponse{}
	_ gen.ListAuthSessionsResponseObject  = problemResponse{}
	_ gen.RevokeAuthSessionResponseObject = problemResponse{}
	_ gen.GetAuthSessionResponseObject    = sessionResponse{}
	_ gen.AuthLogoutResponseObject        = logoutResponse{}
)
