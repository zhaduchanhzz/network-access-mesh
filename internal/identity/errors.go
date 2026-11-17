package identity

import (
	"encoding/json"
	"errors"
	"net/http"
)

// Kind classifies an Error for the HTTP layer: it fixes the status and the stable Problem.code (§13.1).
type Kind uint8

const (
	KindUnauthenticated Kind = iota + 1 // 401 unauthenticated
	KindReauthRequired                  // 401 reauth_required (step-up, §8.3 step 7)
	KindForbidden                       // 403 forbidden (CSRF/origin, claim policy, disabled identity)
	KindNotFound                        // 404 not_found
	KindInvalid                         // 422 validation_failed
	KindUpstream                        // 502 upstream_rejected (IdP unreachable or malformed answer)
	KindInternal                        // 500 internal_error
)

// Status returns the HTTP status of the kind.
func (k Kind) Status() int {
	switch k {
	case KindUnauthenticated, KindReauthRequired:
		return http.StatusUnauthorized
	case KindForbidden:
		return http.StatusForbidden
	case KindNotFound:
		return http.StatusNotFound
	case KindInvalid:
		return http.StatusUnprocessableEntity
	case KindUpstream:
		return http.StatusBadGateway
	default:
		return http.StatusInternalServerError
	}
}

// Code returns the ProblemCode of the kind (api/openapi.yaml).
func (k Kind) Code() string {
	switch k {
	case KindUnauthenticated:
		return "unauthenticated"
	case KindReauthRequired:
		return "reauth_required"
	case KindForbidden:
		return "forbidden"
	case KindNotFound:
		return "not_found"
	case KindInvalid:
		return "validation_failed"
	case KindUpstream:
		return "upstream_rejected"
	default:
		return "internal_error"
	}
}

// title is the fixed Problem.title of each kind — the title internal/httpapi/problem gives the same code (one title per
// code, api/openapi.yaml; identityapi's tests compare the two).
func (k Kind) title() string {
	switch k {
	case KindUnauthenticated:
		return "Unauthenticated"
	case KindReauthRequired:
		return "Re-authentication required"
	case KindForbidden:
		return "Forbidden"
	case KindNotFound:
		return "Not found"
	case KindInvalid:
		return "Validation failed"
	case KindUpstream:
		return "Upstream service error"
	default:
		return "Internal error"
	}
}

// detail is the generic Problem.detail of each kind. It never carries the precise reason of an authentication
// failure (that goes to the log and the audit event) nor anything an IdP returned.
func (k Kind) detail() string {
	switch k {
	case KindUnauthenticated:
		return "The session is missing, expired or revoked, or the sign-in could not be completed."
	case KindReauthRequired:
		return "This action requires a recent sign-in; sign in again and retry."
	case KindForbidden:
		return "The request is not allowed."
	case KindNotFound:
		return "The resource does not exist."
	case KindInvalid:
		return "The request is invalid."
	case KindUpstream:
		return "The identity provider could not be reached or answered unexpectedly."
	default:
		return "An unexpected error occurred."
	}
}

// Error is the error type of the identity module. Reason is a stable machine-readable cause for logs and audit
// (for example "idp_mismatch", "nonce_mismatch"); it is never shown to the client. Field names the invalid input of
// a KindInvalid error.
type Error struct {
	Kind   Kind
	Reason string
	Field  string
	cause  error
}

func (e *Error) Error() string {
	msg := "identity: " + e.Kind.Code() + ": " + e.Reason
	if e.cause != nil {
		msg += ": " + e.cause.Error()
	}
	return msg
}

func (e *Error) Unwrap() error { return e.cause }

func newErr(k Kind, reason string, cause error) *Error {
	return &Error{Kind: k, Reason: reason, cause: cause}
}

func unauthenticated(reason string) *Error { return newErr(KindUnauthenticated, reason, nil) }

func forbidden(reason string) *Error { return newErr(KindForbidden, reason, nil) }

func invalid(field, reason string) *Error {
	return &Error{Kind: KindInvalid, Reason: reason, Field: field}
}

// ErrReauthRequired is returned by RequireRecentAuth when the session's auth_time is outside the step-up window.
var ErrReauthRequired = &Error{Kind: KindReauthRequired, Reason: "auth_time_outside_step_up_window"}

// ErrUnauthenticated is returned when an operation needs a session and none is attached to the request.
var ErrUnauthenticated = &Error{Kind: KindUnauthenticated, Reason: "no_session"}

// AsError returns err as an *Error; any other error becomes KindInternal.
func AsError(err error) *Error {
	var e *Error
	if errors.As(err, &e) {
		return e
	}
	return newErr(KindInternal, "internal", err)
}

// Problem is the RFC 9457 body of every error answered by this module — same fields as the Problem schema of
// api/openapi.yaml.
type Problem struct {
	Type      string       `json:"type"`
	Title     string       `json:"title"`
	Status    int          `json:"status"`
	Detail    string       `json:"detail,omitempty"`
	Instance  string       `json:"instance,omitempty"`
	Code      string       `json:"code"`
	RequestID string       `json:"request_id"`
	Errors    []FieldError `json:"errors,omitempty"`
}

// FieldError is one entry of Problem.errors.
type FieldError struct {
	Field   string `json:"field"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

// NewProblem builds the problem for err. instance must be the request path only (never the query string, which may
// hold an authorization code or a state).
func NewProblem(err error, requestID, instance string) Problem {
	e := AsError(err)
	p := Problem{
		Type:      "urn:meshguard:problem:" + e.Kind.Code(),
		Title:     e.Kind.title(),
		Status:    e.Kind.Status(),
		Detail:    e.Kind.detail(),
		Instance:  instance,
		Code:      e.Kind.Code(),
		RequestID: requestID,
	}
	if e.Kind == KindInvalid && e.Field != "" {
		p.Errors = []FieldError{{Field: e.Field, Code: e.Reason, Message: "invalid value"}}
	}
	return p
}

// WriteProblem writes the problem for err as application/problem+json.
func WriteProblem(w http.ResponseWriter, err error, requestID, instance string) {
	p := NewProblem(err, requestID, instance)
	h := w.Header()
	h.Set("Content-Type", "application/problem+json")
	h.Set("Cache-Control", "no-store")
	if requestID != "" {
		h.Set("X-Request-Id", requestID)
	}
	w.WriteHeader(p.Status)
	_ = json.NewEncoder(w).Encode(p)
}
