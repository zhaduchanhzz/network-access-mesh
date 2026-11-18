// Package problem renders every error of the public API as RFC 9457 `application/problem+json` (§13.1, §13.3):
// {type, title, status, detail, instance, code, request_id, errors[]} with the stable codes of §13.1.
//
// What reaches the client is written by our code only: Detail comes from the code that raised the error and must
// never hold a secret, a stack trace, a raw upstream or library message or a request value; field errors name the
// parameter but never echo its value; the Cause of an Error is for the internal log only. The status of a problem is
// always the status §13.1 assigns to its code, so a client can rely on either.
package problem

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/zhaduchanhzz/network-access-mesh/internal/httpapi/gen"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/requestid"
)

// ContentType of every error response.
const ContentType = "application/problem+json"

// TypePrefix + code is the problem type URI (Problem.type in api/openapi.yaml).
const TypePrefix = "urn:meshguard:problem:"

type entry struct {
	status int
	title  string
}

// catalog is §13.1: one status and one fixed title per code.
var catalog = map[gen.ProblemCode]entry{
	gen.ProblemCodeUnauthenticated:      {http.StatusUnauthorized, "Unauthenticated"},
	gen.ProblemCodeReauthRequired:       {http.StatusUnauthorized, "Re-authentication required"},
	gen.ProblemCodeForbidden:            {http.StatusForbidden, "Forbidden"},
	gen.ProblemCodeTenantSuspended:      {http.StatusForbidden, "Tenant suspended"},
	gen.ProblemCodeQuotaExceeded:        {http.StatusForbidden, "Quota exceeded"},
	gen.ProblemCodeNotFound:             {http.StatusNotFound, "Not found"},
	gen.ProblemCodeConflict:             {http.StatusConflict, "Conflict"},
	gen.ProblemCodePreconditionFailed:   {http.StatusPreconditionFailed, "Precondition failed"},
	gen.ProblemCodePreconditionRequired: {http.StatusPreconditionRequired, "Precondition required"},
	gen.ProblemCodeValidationFailed:     {http.StatusUnprocessableEntity, "Validation failed"},
	gen.ProblemCodeIdempotencyKeyReuse:  {http.StatusUnprocessableEntity, "Idempotency key reused"},
	gen.ProblemCodeRateLimited:          {http.StatusTooManyRequests, "Too many requests"},
	gen.ProblemCodeInternalError:        {http.StatusInternalServerError, "Internal error"},
	gen.ProblemCodeNotImplemented:       {http.StatusNotImplemented, "Not implemented"},
	gen.ProblemCodeUpstreamRejected:     {http.StatusBadGateway, "Upstream service error"},
	gen.ProblemCodeInstanceUnavailable:  {http.StatusServiceUnavailable, "Tenant instance unavailable"},
	gen.ProblemCodeMaintenance:          {http.StatusServiceUnavailable, "Maintenance"},
}

// Status returns the HTTP status §13.1 assigns to code (500 for an unknown code).
func Status(code gen.ProblemCode) int {
	if e, ok := catalog[code]; ok {
		return e.status
	}
	return http.StatusInternalServerError
}

// Error is an API error: return it from a strict handler or a strict middleware, or pass it to
// httpapi.WriteProblem; the chain renders it as a problem.
type Error struct {
	Code       gen.ProblemCode
	Detail     string           // for the client; written by our code (see the package comment)
	Fields     []gen.FieldError // validation_failed: one entry per invalid field
	RetryAfter time.Duration    // > 0 ⇒ Retry-After: rate_limited, conflict on an in-flight Idempotency-Key, instance_unavailable
	Cause      error            // internal log only, never sent
}

func (e *Error) Error() string {
	s := string(e.Code)
	if e.Detail != "" {
		s += ": " + e.Detail
	}
	if e.Cause != nil {
		s += ": " + e.Cause.Error()
	}
	return s
}

func (e *Error) Unwrap() error { return e.Cause }

// Status is the HTTP status of the problem.
func (e *Error) Status() int { return Status(e.Code) }

// New returns a problem with a fixed detail.
func New(code gen.ProblemCode, detail string) *Error { return &Error{Code: code, Detail: detail} }

// Field describes one invalid field (FieldError of the spec): the field or parameter name, a short machine code
// (`required`, `invalid_format`, `too_large`…) and a message that never quotes the submitted value.
func Field(name, code, message string) gen.FieldError {
	return gen.FieldError{Field: name, Code: code, Message: message}
}

// Validation returns a validation_failed problem (422).
func Validation(detail string, fields ...gen.FieldError) *Error {
	return &Error{Code: gen.ProblemCodeValidationFailed, Detail: detail, Fields: fields}
}

// Internal returns the generic internal_error problem (500); cause goes to the internal log only.
func Internal(cause error) *Error {
	return &Error{Code: gen.ProblemCodeInternalError, Detail: "An unexpected error occurred; quote the request_id when reporting it.", Cause: cause}
}

// NotImplemented answers an operation whose handler is not mounted yet (operation is the Go operation name):
// 501 not_implemented (ProblemCode of api/openapi.yaml since the Phase 2 integration).
func NotImplemented(operation string) *Error {
	return New(gen.ProblemCodeNotImplemented, "Operation "+operation+" is not implemented yet.")
}

// BodyTooLarge answers a request body above the limit of the chain (422 validation_failed, field `body`).
func BodyTooLarge(limit int64) *Error {
	return Validation("The request body is too large.", Field("body", "too_large", fmt.Sprintf("must not exceed %d bytes", limit)))
}

// FromBindError maps a parameter-binding error of the generated router (path, query, header or cookie parameter) to
// 422 validation_failed naming the parameter. The generated error text quotes the raw value, so it is never used —
// neither in the response nor as Cause.
func FromBindError(err error) *Error {
	var (
		required *gen.RequiredParamError
		header   *gen.RequiredHeaderError
		many     *gen.TooManyValuesForParamError
		format   *gen.InvalidParamFormatError
		unmarsh  *gen.UnmarshalingParamError
		cookie   *gen.UnescapedCookieParamError
		f        gen.FieldError
	)
	const invalid = "has an invalid format"
	switch {
	case errors.As(err, &required):
		f = Field(required.ParamName, "required", "is required")
	case errors.As(err, &header):
		f = Field(header.ParamName, "required", "is required")
	case errors.As(err, &many):
		f = Field(many.ParamName, "too_many_values", "must be given once")
	case errors.As(err, &format):
		f = Field(format.ParamName, "invalid_format", invalid)
	case errors.As(err, &unmarsh):
		f = Field(unmarsh.ParamName, "invalid_format", invalid)
	case errors.As(err, &cookie):
		f = Field(cookie.ParamName, "invalid_format", invalid)
	default:
		f = Field("request", "invalid", "the request parameters are invalid")
	}
	return Validation("The request parameters are invalid.", f)
}

// jsonPath is a field path that is safe to echo: dotted identifiers only (a map key chosen by the client is not).
var jsonPath = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}(\.[A-Za-z_][A-Za-z0-9_]{0,63}){0,7}$`)

// FromBodyError maps a JSON body decoding error of the strict handler to 422 validation_failed. Library messages
// (which may quote the submitted value) are never used.
func FromBodyError(err error) *Error {
	var (
		tooLarge *http.MaxBytesError
		syntax   *json.SyntaxError
		typ      *json.UnmarshalTypeError
	)
	const detail = "The request body is invalid."
	switch {
	case errors.As(err, &tooLarge):
		return BodyTooLarge(tooLarge.Limit)
	case errors.Is(err, io.EOF):
		return Validation(detail, Field("body", "required", "a JSON body is required"))
	case errors.As(err, &syntax), errors.Is(err, io.ErrUnexpectedEOF):
		return Validation(detail, Field("body", "invalid_json", "is not valid JSON"))
	case errors.As(err, &typ):
		name := "body"
		if jsonPath.MatchString(typ.Field) {
			name = typ.Field
		}
		return Validation(detail, Field(name, "invalid_type", "has the wrong type"))
	default:
		return Validation(detail, Field("body", "invalid_value", "contains an invalid value"))
	}
}

// Seconds rounds d up to whole seconds, the unit of Retry-After and RateLimit-Reset (0 for d ≤ 0).
func Seconds(d time.Duration) int64 {
	if d <= 0 {
		return 0
	}
	return int64((d + time.Second - 1) / time.Second)
}

// Write sends e as the response. Use it only when nothing has been written yet. The request id comes from the request
// context (internal/kit/requestid), instance is the request path without its query string (which may hold a
// credential such as an OAuth code). An unknown code is sent as internal_error.
func Write(w http.ResponseWriter, r *http.Request, e *Error) {
	if e == nil {
		e = Internal(nil)
	}
	ent, ok := catalog[e.Code]
	if !ok {
		e = Internal(nil)
		ent = catalog[e.Code]
	}
	p := gen.Problem{
		Type:      TypePrefix + string(e.Code),
		Title:     ent.title,
		Status:    ent.status,
		Code:      e.Code,
		RequestId: requestid.From(r.Context()),
	}
	if p.RequestId == "" {
		p.RequestId = w.Header().Get(requestid.Header)
	}
	if path := r.URL.EscapedPath(); path != "" {
		p.Instance = &path
	}
	if e.Detail != "" {
		detail := e.Detail
		p.Detail = &detail
	}
	if len(e.Fields) > 0 {
		fields := e.Fields
		p.Errors = &fields
	}
	h := w.Header()
	h.Del("Content-Length")
	h.Set("Content-Type", ContentType)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Cache-Control", "no-store")
	if e.RetryAfter > 0 {
		h.Set("Retry-After", strconv.FormatInt(Seconds(e.RetryAfter), 10))
	}
	w.WriteHeader(ent.status)
	_ = json.NewEncoder(w).Encode(p)
}

// quotaRefusal is implemented by the typed quota errors of the services (tenants.QuotaExceededError — P3-T06a), so this
// package needs no service import.
type quotaRefusal interface {
	error
	QuotaResource() string
	QuotaLimit() int64
}

// quotaResource is a quota name that is safe to echo (tenants, devices, max_users…).
var quotaResource = regexp.MustCompile(`^[a-z][a-z_]{0,31}$`)

// FromQuota maps a quota refusal anywhere in err's chain to 403 quota_exceeded (§13.1); ok = false for any other error.
// The detail names the quota and its effective limit — the platform cap or the caller's own plan, never data of another
// tenant.
func FromQuota(err error) (*Error, bool) {
	var q quotaRefusal
	if !errors.As(err, &q) {
		return nil, false
	}
	resource := q.QuotaResource()
	if !quotaResource.MatchString(resource) {
		resource = "resource"
	}
	return &Error{Code: gen.ProblemCodeQuotaExceeded,
		Detail: fmt.Sprintf("The %s quota is reached (limit %d).", resource, q.QuotaLimit())}, true
}
