package idp

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/url"
	"strconv"
)

// Code is the stable error code of the module. Callers branch on it (errors.As + Error.Code, or CodeOf); the API layer
// maps it to a problem type. It never carries upstream content.
type Code string

// Error codes.
const (
	// CodeInvalidArgument: the caller's input is invalid (spec, URL syntax, realm name…).
	CodeInvalidArgument Code = "invalid_argument"
	// CodeUnknownDriver: no driver is registered under the identity_providers.driver value.
	CodeUnknownDriver Code = "unknown_driver"
	// CodeUnsupported: the driver does not offer this operation (external: InviteUser), or the IdP answered 501.
	CodeUnsupported Code = "unsupported"
	// CodeDestinationRefused: T-21 — scheme, port, host or resolved address refused by the egress policy.
	CodeDestinationRefused Code = "destination_refused"
	// CodeRedirectRefused: the IdP answered with a redirect; no redirect is ever followed (§8.2).
	CodeRedirectRefused Code = "redirect_refused"
	// CodeResponseTooLarge: a response exceeded the size limit.
	CodeResponseTooLarge Code = "response_too_large"
	// CodeTimeout: the call did not complete in time.
	CodeTimeout Code = "timeout"
	// CodeUnavailable: DNS failure, connection failure or 5xx from the IdP.
	CodeUnavailable Code = "unavailable"
	// CodeTLS: the TLS handshake or the certificate check failed.
	CodeTLS Code = "tls_failed"
	// CodeDiscoveryInvalid: the discovery document or the JWKS is malformed or violates a rule.
	CodeDiscoveryInvalid Code = "discovery_invalid"
	// CodeIssuerMismatch: the issuer of the discovery document is not the stored issuer.
	CodeIssuerMismatch Code = "issuer_mismatch"
	// CodeCredentials: the SecretStore could not provide a credential the driver needs.
	CodeCredentials Code = "credentials_unavailable"
	// CodeSecretRefNotOwned: the client_secret_ref of a registration does not name the IdP's own client secret (another
	// owner, another secret of the owner, or not a reference at all — Registration.OwnClientSecretRef, G2 F3). Nothing
	// was read from or destroyed in the SecretStore.
	CodeSecretRefNotOwned Code = "secret_ref_not_owned"
	// CodeUnauthenticated: the IdP refused the driver's credentials (HTTP 401, invalid_client).
	CodeUnauthenticated Code = "idp_unauthenticated"
	// CodeForbidden: the IdP refused the operation (HTTP 403), e.g. a realm the provisioning identity does not manage.
	CodeForbidden Code = "idp_forbidden"
	// CodeNotFound: the object does not exist at the IdP.
	CodeNotFound Code = "not_found"
	// CodeConflict: the IdP holds a conflicting object (realm of another IdP id, disabled user…).
	CodeConflict Code = "conflict"
	// CodeDrift: the IdP holds a state the driver does not repair on its own (structure of an authentication flow).
	CodeDrift Code = "drift"
	// CodeUpstream: unexpected status or malformed response from the IdP.
	CodeUpstream Code = "upstream_error"
	// CodeEmailFailed: the IdP could not send the required-actions e-mail (no SMTP).
	CodeEmailFailed Code = "email_failed"
	// CodeInternal: a bug or an impossible state on our side.
	CodeInternal Code = "internal"
)

// Error is the error type of the module and its drivers. Error() is "idp: <op>: <code> (<reason>)": Op names the
// operation, Reason is a value from a fixed vocabulary of this module (e.g. "address_private", "http_502") and Status
// the HTTP status the IdP answered (0 when none). Nothing in it comes from an upstream response body, so it may be
// logged and its code shown to users; the wrapped cause (Unwrap) is for logs only and is built the same way.
type Error struct {
	Code   Code
	Op     string
	Reason string
	Status int
	err    error
}

func (e *Error) Error() string {
	s := "idp: " + e.Op + ": " + string(e.Code)
	if e.Reason != "" {
		s += " (" + e.Reason + ")"
	}
	return s
}

// Unwrap returns the cause (a transport, DNS, TLS or SecretStore error) — for logs, never for users.
func (e *Error) Unwrap() error { return e.err }

// Is lets errors.Is(err, &Error{Code: c}) match any error of the same code.
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	return ok && t.Code == e.Code && (t.Op == "" || t.Op == e.Op) && (t.Reason == "" || t.Reason == e.Reason)
}

// NewError returns an *Error; cause may be nil.
func NewError(code Code, op, reason string, cause error) *Error {
	return &Error{Code: code, Op: op, Reason: reason, err: cause}
}

// CodeOf returns the code of err ("" for nil, CodeInternal for an error of another type).
func CodeOf(err error) Code {
	if err == nil {
		return ""
	}
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return CodeInternal
}

// StatusError maps an unexpected HTTP status of the IdP to an *Error (the body is never read into it).
func StatusError(op string, status int) *Error {
	e := &Error{Op: op, Status: status, Reason: "http_" + strconv.Itoa(status)}
	switch {
	case status == 400:
		e.Code = CodeUpstream
	case status == 401:
		e.Code = CodeUnauthenticated
	case status == 403:
		e.Code = CodeForbidden
	case status == 404:
		e.Code = CodeNotFound
	case status == 409:
		e.Code = CodeConflict
	case status == 501:
		e.Code = CodeUnsupported
	case status >= 500:
		e.Code = CodeUnavailable
	case status >= 300 && status < 400:
		e.Code = CodeRedirectRefused
	default:
		e.Code = CodeUpstream
	}
	return e
}

// Classify turns any error returned by an HTTP call through the clients of this module into an *Error: refusals of
// the egress policy keep their code; timeouts, TLS and DNS failures get their own code; everything else is
// CodeUnavailable. op names the operation for errors that are not already an *Error.
func Classify(op string, err error) *Error {
	if err == nil {
		return nil
	}
	var e *Error
	if errors.As(err, &e) {
		return e
	}
	var (
		ue      *url.Error
		dnsErr  *net.DNSError
		certErr *tls.CertificateVerificationError
		hostErr x509.HostnameError
		uaErr   x509.UnknownAuthorityError
		ciErr   x509.CertificateInvalidError
		recErr  tls.RecordHeaderError
		alert   tls.AlertError
	)
	switch {
	case errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ue) && ue.Timeout()):
		return &Error{Code: CodeTimeout, Op: op, Reason: "deadline", err: err}
	case errors.Is(err, context.Canceled):
		return &Error{Code: CodeUnavailable, Op: op, Reason: "canceled", err: err}
	case errors.As(err, &certErr), errors.As(err, &hostErr), errors.As(err, &uaErr), errors.As(err, &ciErr),
		errors.As(err, &recErr), errors.As(err, &alert):
		return &Error{Code: CodeTLS, Op: op, Reason: "tls", err: err}
	case errors.As(err, &dnsErr):
		return &Error{Code: CodeUnavailable, Op: op, Reason: "dns", err: err}
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return &Error{Code: CodeTimeout, Op: op, Reason: "deadline", err: err}
	}
	return &Error{Code: CodeUnavailable, Op: op, Reason: "network", err: err}
}
