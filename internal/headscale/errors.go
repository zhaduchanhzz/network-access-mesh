package headscale

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// Op names an adapter operation (one per Instance method).
type Op string

// Operations of the Instance interface.
const (
	OpHealth            Op = "Health"
	OpVersion           Op = "Version"
	OpListUsers         Op = "ListUsers"
	OpCreateUser        Op = "CreateUser"
	OpRenameUser        Op = "RenameUser"
	OpDeleteUser        Op = "DeleteUser"
	OpListNodes         Op = "ListNodes"
	OpGetNode           Op = "GetNode"
	OpRenameNode        Op = "RenameNode"
	OpSetTags           Op = "SetTags"
	OpSetApprovedRoutes Op = "SetApprovedRoutes"
	OpExpireNode        Op = "ExpireNode"
	OpDeleteNode        Op = "DeleteNode"
	OpCreatePreAuthKey  Op = "CreatePreAuthKey"
	OpListPreAuthKeys   Op = "ListPreAuthKeys"
	OpExpirePreAuthKey  Op = "ExpirePreAuthKey"
	OpDeletePreAuthKey  Op = "DeletePreAuthKey"
	OpAuthRegister      Op = "AuthRegister"
	OpAuthApprove       Op = "AuthApprove"
	OpAuthReject        Op = "AuthReject"
	OpGetPolicy         Op = "GetPolicy"
	OpCheckPolicy       Op = "CheckPolicy"
	OpSetPolicy         Op = "SetPolicy"
	OpCreateAPIKey      Op = "CreateAPIKey"
	OpListAPIKeys       Op = "ListAPIKeys"
	OpExpireAPIKey      Op = "ExpireAPIKey"
)

// RetryClass is the retry rule of an operation (§13.4 rule 3).
type RetryClass int

// Retry classes.
const (
	// RetrySafe: read-only GET — retried automatically by the adapter with backoff.
	RetrySafe RetryClass = iota
	// RetryIdempotentWrite: replaying gives the same state (whole-set replacement, explicit time, delete). The adapter
	// does not retry it; the job layer may, with backoff, and must treat not_found on a replayed delete as done.
	RetryIdempotentWrite
	// RetryNever: creates something new (or registers a node); never replayed — reconcile by reading back.
	RetryNever
)

// RetryClass returns the retry rule of op.
func (op Op) RetryClass() RetryClass {
	switch op {
	case OpHealth, OpVersion, OpListUsers, OpListNodes, OpGetNode, OpListPreAuthKeys, OpGetPolicy, OpListAPIKeys,
		OpCheckPolicy: // CheckPolicy is a POST but a dry run with no side effect; still not retried automatically
		return RetrySafe
	case OpSetPolicy, OpExpireNode, OpSetApprovedRoutes, OpSetTags, OpExpirePreAuthKey, OpDeleteNode,
		OpDeletePreAuthKey, OpRenameNode, OpRenameUser, OpExpireAPIKey, OpAuthApprove, OpAuthReject, OpDeleteUser:
		return RetryIdempotentWrite
	default: // CreateUser, CreatePreAuthKey, CreateAPIKey, AuthRegister
		return RetryNever
	}
}

// Kind is the stable classification of an adapter error.
type Kind string

// Error kinds. ProblemCode maps each to a Problem.code of §13.1.
const (
	KindValidation         Kind = "validation"          // input rejected locally or by Headscale (400), Auth ID not pending
	KindNotFound           Kind = "not_found"           // user, node, key does not exist
	KindConflict           Kind = "conflict"            // unique name taken, user still has nodes, OIDC user immutable
	KindPolicyRejected     Kind = "policy_rejected"     // CheckPolicy/SetPolicy refused the document, or SetPolicy failed
	KindNoPolicy           Kind = "no_policy"           // the instance has no stored policy: it is (or will be after restart) allow-all
	KindUpstreamRejected   Kind = "upstream_rejected"   // any other refusal or an unusable answer from Headscale
	KindUnavailable        Kind = "unavailable"         // transport error, timeout, 503/504, edge cannot route, storage failure
	KindCircuitOpen        Kind = "circuit_open"        // the per-instance breaker is open: not called
	KindAPIKeyRejected     Kind = "api_key_rejected"    // 401 after reloading the key: suspect a replaced DB (§13.4)
	KindEdgeRejected       Kind = "edge_rejected"       // the admin listener refused X-MG-Token (platform misconfiguration)
	KindUnsupportedVersion Kind = "unsupported_version" // the instance runs a version outside the supported range
	KindInternal           Kind = "internal"            // misconfiguration on our side (invalid target, locator failure)
)

// Problem codes of §13.1 used by the adapter (the httpapi layer owns the response; these are the stable strings).
const (
	ProblemValidationFailed    = "validation_failed"
	ProblemNotFound            = "not_found"
	ProblemConflict            = "conflict"
	ProblemUpstreamRejected    = "upstream_rejected"
	ProblemInstanceUnavailable = "instance_unavailable"
	ProblemInternalError       = "internal_error"
)

// ProblemCode maps a kind to its Problem.code (§13.1, §13.4 rule 5).
func (k Kind) ProblemCode() string {
	switch k {
	case KindValidation:
		return ProblemValidationFailed
	case KindNotFound:
		return ProblemNotFound
	case KindConflict:
		return ProblemConflict
	case KindPolicyRejected, KindNoPolicy, KindUpstreamRejected:
		return ProblemUpstreamRejected
	case KindUnavailable, KindCircuitOpen, KindAPIKeyRejected, KindEdgeRejected, KindUnsupportedVersion:
		return ProblemInstanceUnavailable
	default:
		return ProblemInternalError
	}
}

// Outcome tells a caller of a write whether the change may have happened despite the error.
type Outcome uint8

// Outcomes.
const (
	// OutcomeNotApplied: Headscale refused the request before changing anything (or it was never sent).
	OutcomeNotApplied Outcome = iota
	// OutcomeUnknown: the change may have been applied — the request was sent and the answer lost, or SetPolicy
	// failed AFTER the instance swapped the policy in memory (V-26). Read back; for SetPolicy re-assert the last
	// applied policy, because GetPolicy reads the database copy and cannot see the live one.
	OutcomeUnknown
)

func (o Outcome) String() string {
	if o == OutcomeUnknown {
		return "unknown"
	}
	return "not_applied"
}

// Sentinels for errors.Is: every *Error matches the sentinel of its kind.
var (
	ErrValidation         = errors.New("headscale: validation failed")
	ErrNotFound           = errors.New("headscale: not found")
	ErrConflict           = errors.New("headscale: conflict")
	ErrPolicyRejected     = errors.New("headscale: policy rejected")
	ErrNoPolicy           = errors.New("headscale: instance has no policy (allow-all)")
	ErrUpstreamRejected   = errors.New("headscale: upstream rejected the request")
	ErrUnavailable        = errors.New("headscale: instance unavailable")
	ErrCircuitOpen        = errors.New("headscale: circuit breaker open")
	ErrAPIKeyRejected     = errors.New("headscale: instance rejected the API key")
	ErrEdgeRejected       = errors.New("headscale: edge admin listener rejected the request")
	ErrUnsupportedVersion = errors.New("headscale: unsupported Headscale version")
	ErrInternal           = errors.New("headscale: adapter misconfiguration")
)

var kindSentinel = map[Kind]error{
	KindValidation: ErrValidation, KindNotFound: ErrNotFound, KindConflict: ErrConflict,
	KindPolicyRejected: ErrPolicyRejected, KindNoPolicy: ErrNoPolicy, KindUpstreamRejected: ErrUpstreamRejected,
	KindUnavailable: ErrUnavailable, KindCircuitOpen: ErrCircuitOpen, KindAPIKeyRejected: ErrAPIKeyRejected,
	KindEdgeRejected: ErrEdgeRejected, KindUnsupportedVersion: ErrUnsupportedVersion, KindInternal: ErrInternal,
}

// Error is the only error type returned by Instance methods and Registry.ForTenant.
type Error struct {
	Op      Op
	Kind    Kind
	Status  int     // HTTP status seen by the adapter (0: no HTTP answer)
	Code    int     // gRPC code of the gateway error body, -1 when the body was not a gateway error
	Outcome Outcome // for writes
	// Upstream is Headscale's own message (or the local reason), with credentials redacted. For internal logs and
	// the platform-only job detail ONLY — never a Problem.detail (§13.4 rule 5). Use Detail for anything shown.
	Upstream string
	Err      error // underlying cause (transport error, context error), may be nil
}

func (e *Error) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "headscale %s: %s", e.Op, e.Kind)
	if e.Status != 0 {
		fmt.Fprintf(&b, " (http %d", e.Status)
		if e.Code >= 0 {
			fmt.Fprintf(&b, ", code %d", e.Code)
		}
		b.WriteString(")")
	}
	if e.Upstream != "" {
		b.WriteString(": ")
		b.WriteString(e.Upstream)
	}
	if e.Err != nil {
		b.WriteString(": ")
		b.WriteString(e.Err.Error())
	}
	return b.String()
}

// Unwrap returns the underlying cause.
func (e *Error) Unwrap() error { return e.Err }

// Is matches the sentinel of the error's kind.
func (e *Error) Is(target error) bool { return kindSentinel[e.Kind] == target }

// ProblemCode is the Problem.code for this error (§13.1).
func (e *Error) ProblemCode() string { return e.Kind.ProblemCode() }

// Detail is a filtered reason that may be shown to a tenant user (Problem.detail): it never contains Headscale's
// message, addresses or identifiers.
func (e *Error) Detail() string {
	switch e.Kind {
	case KindValidation:
		return "the request was rejected as invalid"
	case KindNotFound:
		return "the object does not exist on the tenant's control plane"
	case KindConflict:
		return "the request conflicts with the current state of the tenant's control plane"
	case KindPolicyRejected:
		return "the tenant's control plane rejected the policy"
	case KindNoPolicy:
		return "the tenant's control plane has no stored policy"
	case KindUpstreamRejected:
		return "the tenant's control plane rejected the request"
	case KindInternal:
		return "internal error"
	default:
		return "the tenant's control plane is not responding"
	}
}

// AsError returns the *Error inside err, if any.
func AsError(err error) (*Error, bool) {
	var e *Error
	ok := errors.As(err, &e)
	return e, ok
}

// gRPC codes used by the REST gateway body (google.golang.org/grpc/codes; kept local to avoid the dependency).
const (
	grpcUnknown            = 2
	grpcInvalidArgument    = 3
	grpcDeadlineExceeded   = 4
	grpcNotFound           = 5
	grpcAlreadyExists      = 6
	grpcResourceExhausted  = 8
	grpcFailedPrecondition = 9
	grpcAborted            = 10
	grpcOutOfRange         = 11
	grpcInternal           = 13
	grpcUnavailable        = 14
	grpcUnauthenticated    = 16
)

// gatewayError is the error body of the grpc-gateway behind /api/v1: {"code":5,"message":"node not found","details":[]}.
type gatewayError struct {
	Code    *int   `json:"code"`
	Message string `json:"message"`
}

func parseGatewayError(body []byte) (gatewayError, bool) {
	var g gatewayError
	if len(body) == 0 || body[0] != '{' || json.Unmarshal(body, &g) != nil || g.Code == nil {
		return gatewayError{}, false
	}
	return g, true
}

// classify maps an HTTP answer that is not 2xx to an *Error. It is a pure function of (operation, status, body) so
// the whole table is unit-tested (errors_test.go) with the bodies observed on 0.29.7 (P2-T10).
func classify(op Op, status int, body []byte) *Error {
	e := &Error{Op: op, Status: status, Code: -1, Kind: KindUpstreamRejected}
	g, isGateway := parseGatewayError(body)
	if !isGateway {
		e.Upstream = truncate(strings.TrimSpace(string(body)))
		switch status {
		case http.StatusUnauthorized: // Headscale's auth middleware: text "Unauthorized"
			e.Kind = KindAPIKeyRejected
		case http.StatusForbidden: // edge: X-MG-Token missing or wrong (§14.6)
			e.Kind = KindEdgeRejected
		case http.StatusNotFound, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout,
			http.StatusTooManyRequests:
			// The admin listener answers a bare 404 when it cannot route: unknown X-MG-Instance, path outside the
			// allow-list, and — through handle_errors 502 503 504 — an instance that is stopped or unreachable.
			e.Kind = KindUnavailable
		}
		return e
	}
	e.Code = *g.Code
	e.Upstream = truncate(g.Message)
	msg := strings.ToLower(g.Message)

	// Operation-specific rules first: the same text means different things for different operations.
	switch op {
	case OpAuthRegister, OpAuthApprove, OpAuthReject:
		// §13.4: an Auth ID that is not pending is a validation failure of the caller's input, not a 404.
		if strings.Contains(msg, "registration cache") || strings.Contains(msg, "no pending auth session") ||
			strings.Contains(msg, "auth id has invalid") || strings.Contains(msg, "invalid auth_id") {
			e.Kind = KindValidation
			return e
		}
	case OpSetPolicy:
		e.Kind = KindPolicyRejected
		switch {
		case strings.HasPrefix(msg, "setting policy:"):
			// Rejected by the policy manager, which restores the previous policy: nothing changed.
			e.Outcome = OutcomeNotApplied
		case strings.Contains(msg, "update is disabled"):
			e.Kind, e.Outcome = KindUpstreamRejected, OutcomeNotApplied // policy.mode is not "database"
		default:
			// "verifying SSH rules", storage errors and "reloading policy" happen AFTER the in-memory swap (V-26).
			e.Outcome = OutcomeUnknown
		}
		return e
	case OpCheckPolicy:
		if e.Code == grpcInvalidArgument {
			e.Kind = KindPolicyRejected
			return e
		}
	case OpGetPolicy:
		if strings.Contains(msg, "policy not found") {
			e.Kind = KindNoPolicy
			return e
		}
	case OpDeleteUser:
		if strings.Contains(msg, "user not empty") {
			e.Kind = KindConflict
			return e
		}
	}

	switch e.Code {
	case grpcNotFound:
		e.Kind = KindNotFound
		if g.Message == "Not Found" { // the gateway's router: the path does not exist on this version
			e.Kind = KindUpstreamRejected
		}
		return e
	case grpcAlreadyExists, grpcAborted:
		e.Kind = KindConflict
		return e
	case grpcInvalidArgument, grpcFailedPrecondition, grpcOutOfRange:
		e.Kind = KindValidation
		if containsAny(msg, "node not found", "no longer exists") { // SetApprovedRoutes wraps "not found" as 400
			e.Kind = KindNotFound
		}
		return e
	case grpcUnauthenticated:
		e.Kind = KindAPIKeyRejected
		return e
	case grpcUnavailable, grpcDeadlineExceeded, grpcResourceExhausted:
		e.Kind = KindUnavailable
		return e
	case grpcUnknown, grpcInternal:
		// Headscale returned a plain Go error (HTTP 500): classify by message (§13.4), below.
	default: // Unimplemented, PermissionDenied, DataLoss, …
		if status == http.StatusServiceUnavailable || status == http.StatusGatewayTimeout {
			e.Kind = KindUnavailable
		}
		return e
	}

	switch {
	case containsAny(msg, "unique constraint failed", "already exists", "already in use", "is not unique",
		"cannot edit oidc user", "user not empty"):
		e.Kind = KindConflict
	case containsAny(msg, "record not found", "not found", "no longer exists"):
		e.Kind = KindNotFound
	case containsAny(msg, "not a valid dns label", "invalid", "must start with", "should be lowercase",
		"must not contain", "parsing route", "cannot parse", "outside the years", "cannot set both", "too long",
		"must be either tagged or owned"):
		e.Kind = KindValidation
	case containsAny(msg, "database is locked", "disk is full", "disk i/o error", "pinging database",
		"database or disk", "readonly database"):
		e.Kind = KindUnavailable // storage failure inside the instance (not counted by the breaker — 500)
	}
	return e
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

const maxUpstreamMessage = 512

func truncate(s string) string {
	if len(s) > maxUpstreamMessage {
		return s[:maxUpstreamMessage] + "…"
	}
	return s
}

// localError builds an error for a request rejected before it was sent.
func localError(op Op, kind Kind, reason string) *Error {
	return &Error{Op: op, Kind: kind, Code: -1, Upstream: reason, Outcome: OutcomeNotApplied}
}

// invalid is the common case of localError.
func invalid(op Op, format string, args ...any) *Error {
	return localError(op, KindValidation, fmt.Sprintf(format, args...))
}
