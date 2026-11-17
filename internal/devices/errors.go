package devices

import (
	"context"
	"errors"

	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
)

// Problem codes (§13.1) carried by Error. The HTTP adapter maps them one to one.
const (
	CodeNotFound            = "not_found"
	CodeConflict            = "conflict"
	CodeValidationFailed    = "validation_failed"
	CodeIdempotencyKeyReuse = "idempotency_key_reuse"
	CodeInstanceUnavailable = "instance_unavailable"
	CodeUpstreamRejected    = "upstream_rejected"
	CodeInternal            = "internal_error"
)

// Reasons: stable machine-readable causes (audit details, logs) — never shown as Problem.detail.
const (
	ReasonNoDevice             = "no_device"              // no live device with this ID in the tenant
	ReasonNotOwnResource       = "not_own_resource"       // own-only caller, device of someone else or tagged (§8.4 3b)
	ReasonNodeGone             = "node_gone"              // the device's node no longer exists on the instance
	ReasonRevocationInProgress = "revocation_in_progress" // another kind of revocation is pending
	ReasonJobInProgress        = "job_in_progress"        // a revocation job of the device is still finishing
	ReasonNoInstance           = "no_instance"            // the tenant has no live instance
	ReasonReadbackMismatch     = "readback_mismatch"      // Headscale answered but the read-back does not show it
)

// Error is a failure of a device operation with the Problem code the API answers.
type Error struct {
	Code   string // CodeNotFound …
	Reason string // Reason… or the code of the adapter error
	Field  string // validation_failed: the invalid parameter or body field
	Detail string // client-facing text written here (never an upstream message)
	Err    error  // cause, for the internal log only
}

func (e *Error) Error() string {
	s := "devices: " + e.Code
	if e.Reason != "" {
		s += " (" + e.Reason + ")"
	}
	if e.Err != nil {
		s += ": " + e.Err.Error()
	}
	return s
}

func (e *Error) Unwrap() error { return e.Err }

// AsError returns the *Error inside err.
func AsError(err error) (*Error, bool) {
	var e *Error
	ok := errors.As(err, &e)
	return e, ok
}

func notFound(reason string) *Error {
	return &Error{Code: CodeNotFound, Reason: reason, Detail: "The resource does not exist."}
}

func invalid(field, detail string) *Error {
	return &Error{Code: CodeValidationFailed, Reason: "invalid_" + field, Field: field, Detail: detail}
}

func conflict(reason, detail string) *Error {
	return &Error{Code: CodeConflict, Reason: reason, Detail: detail}
}

func unavailable(reason string, err error) *Error {
	return &Error{Code: CodeInstanceUnavailable, Reason: reason, Err: err,
		Detail: "The tenant's control plane is not responding; try again later."}
}

// fromAdapter maps an error of internal/headscale (or of the context) to an Error with its Problem code (§13.4 rule
// 5): Headscale's own message stays in the cause, the client only gets the filtered detail of the adapter.
func fromAdapter(err error) *Error {
	if err == nil {
		return nil
	}
	if e, ok := AsError(err); ok {
		return e
	}
	he, ok := headscale.AsError(err)
	if !ok {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			return unavailable("timeout", err)
		}
		return &Error{Code: CodeInternal, Reason: "internal", Err: err}
	}
	e := &Error{Code: he.ProblemCode(), Reason: string(he.Kind), Err: err, Detail: he.Detail()}
	if he.Kind == headscale.KindNotFound {
		e.Reason = ReasonNodeGone
	}
	if e.Code == CodeValidationFailed {
		e.Field = "body"
	}
	return e
}

// transient reports whether a failure may go away by itself — the instance not answering, a timeout, our own
// plumbing (locator, database) — so that a job retries it; a refusal by Headscale is final.
func transient(err error) bool {
	e := fromAdapter(err)
	return e.Code == CodeInstanceUnavailable || e.Code == CodeInternal
}

// isGone reports whether err says the node does not exist on the instance.
func isGone(err error) bool { return errors.Is(err, headscale.ErrNotFound) }
