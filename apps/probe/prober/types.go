package prober

import (
	"context"
	"errors"
	"time"
)

// Prober runs the probes. A probe that ran returns its result — OK=false with Error set when it failed — and a nil
// error; the error is for a probe that could not run: invalid request, target outside the allow-list, RPC failure
// (always an *Error, see CodeOf).
type Prober interface {
	STUN(ctx context.Context, req STUNRequest) (STUNResult, error)
	HTTPS(ctx context.Context, req HTTPSRequest) (HTTPSResult, error)
	Edge(ctx context.Context, req EdgeRequest) (EdgeResult, error)
	Relay(ctx context.Context, req RelayRequest) (RelayResult, error)
}

// Stable error codes (the RPC contract and the results). Messages are for people; the code is the stable part.
const (
	// The probe could not run.
	CodeInvalidRequest   = "invalid_request"    // malformed request (HTTP 400)
	CodeTargetNotAllowed = "target_not_allowed" // target outside MG_PROBE_ALLOW_TARGETS (403); nothing was sent
	CodeCallerNotAllowed = "caller_not_allowed" // RPC caller outside MG_PROBE_ALLOW_CALLERS (403)
	CodeBusy             = "busy"               // too many probes in flight (429)
	CodeNotFound         = "not_found"          // unknown RPC route (404)
	CodeRPC              = "rpc_error"          // the RPC answer could not be used (client side)

	// The probe ran and failed.
	CodeTimeout         = "timeout"           // no answer before the deadline (UDP: after every retransmission)
	CodeRefused         = "refused"           // TCP reset, or ICMP port unreachable for UDP
	CodeUnreachable     = "unreachable"       // no route to the host or network
	CodeNetwork         = "network_error"     // any other socket error
	CodeCanceled        = "canceled"          // the caller's context ended
	CodeBadResponse     = "bad_response"      // STUN: malformed answer or Binding Error response
	CodeNoMappedAddress = "no_mapped_address" // STUN: success response without (XOR-)MAPPED-ADDRESS
	CodeTLSHandshake    = "tls_handshake"     // TLS handshake failed (alert, no certificate for the SNI, protocol)
	CodeTLSVerify       = "tls_verify"        // certificate not trusted, not valid for the SNI, or expired
	CodeHTTP            = "http_error"        // malformed or truncated HTTP answer
)

// Error is a typed failure: why a probe failed (inside a result) or could not run (returned).
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message,omitempty"` // short English text, redacted; never contains a credential
}

func (e *Error) Error() string {
	if e.Message == "" {
		return "prober: " + e.Code
	}
	return "prober: " + e.Code + ": " + e.Message
}

// CodeOf returns the code of err when it is (or wraps) an *Error, "" otherwise.
func CodeOf(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

func newError(code, msg string) *Error { return &Error{Code: code, Message: msg} }

// Defaults and limits.
const (
	DefaultSTUNTimeout  = 3 * time.Second
	DefaultHTTPSTimeout = 5 * time.Second
	MaxTimeout          = 15 * time.Second
	// DefaultCapVer is the capability version of the /key probe: the minimum Headscale 0.29.x accepts (RT-09).
	DefaultCapVer = 113
	// DefaultMaxBody bounds the body read of an HTTPS probe; a larger body is reported truncated.
	DefaultMaxBody = 1 << 20
	maxForbidden   = 64
)

// STUNRequest is one STUN Binding Request.
type STUNRequest struct {
	Target    string `json:"target"`               // ip:port of the STUN responder (an IP literal — no name is resolved)
	TimeoutMS int    `json:"timeout_ms,omitempty"` // whole probe, retransmissions included; default 3000, at most 15000
}

// STUNResult is the outcome of a STUN probe.
type STUNResult struct {
	Target    string    `json:"target"`
	OK        bool      `json:"ok"`
	Mapped    string    `json:"mapped,omitempty"` // XOR-MAPPED-ADDRESS: the source address:port the responder saw
	Local     string    `json:"local,omitempty"`  // the local address:port the request left from
	Attempts  int       `json:"attempts"`         // requests sent (retransmissions included)
	RTTMS     float64   `json:"rtt_ms,omitempty"` // send → answer, for the attempt that was answered
	TotalMS   float64   `json:"total_ms"`
	CheckedAt time.Time `json:"checked_at"`
	Error     *Error    `json:"error,omitempty"`
}

// HTTPSRequest is one HTTPS GET to an IP address with an explicit SNI and Host.
type HTTPSRequest struct {
	Address string `json:"address"`        // ip:port dialled as is (no name resolution)
	SNI     string `json:"sni"`            // TLS server name; the certificate must be valid for it
	Host    string `json:"host,omitempty"` // HTTP Host header; "" = SNI
	Path    string `json:"path,omitempty"` // origin-form request target, sent byte for byte ("/key?v=113"); "" = "/"
	// Headers names the response headers to report (at most 16; headers that carry credentials are refused).
	Headers   []string `json:"headers,omitempty"`
	Expect    Expect   `json:"expect,omitzero"`
	TimeoutMS int      `json:"timeout_ms,omitempty"` // default 5000, at most 15000
}

// Expect lists the checks of an HTTPS probe; the zero value checks nothing (any answer is OK).
type Expect struct {
	Status     []int             `json:"status,omitempty"`      // accepted statuses
	Headers    map[string]string `json:"headers,omitempty"`     // header → exact value
	BodySHA256 string            `json:"body_sha256,omitempty"` // lower-case hex
	BodySize   *int64            `json:"body_size,omitempty"`   // exact size in bytes
	// JSONPresent lists top-level keys of a JSON object body whose value must be a non-empty string; JSONEquals the
	// exact string values. The values of both are reported in HTTPSResult.JSON (at most 8 keys in all).
	JSONPresent []string          `json:"json_present,omitempty"`
	JSONEquals  map[string]string `json:"json_equals,omitempty"`
}

// Status classes of an HTTPS answer.
const (
	ClassOK          = "ok"           // 2xx
	ClassRedirect    = "redirect"     // 3xx (never followed)
	ClassNotFound    = "not_found"    // 404: the edge's answer to a path outside its allow-list (§14.6)
	ClassMisdirected = "misdirected"  // 421: SNI and Host name different sites (strict_sni_host)
	ClassClientError = "client_error" // other 4xx
	ClassServerError = "server_error" // 5xx
	ClassOther       = "other"        // 1xx and anything else
)

// ClassOf classifies an HTTP status.
func ClassOf(status int) string {
	switch {
	case status == 404:
		return ClassNotFound
	case status == 421:
		return ClassMisdirected
	case status >= 200 && status < 300:
		return ClassOK
	case status >= 300 && status < 400:
		return ClassRedirect
	case status >= 400 && status < 500:
		return ClassClientError
	case status >= 500 && status < 600:
		return ClassServerError
	}
	return ClassOther
}

// Failure is one expectation that the answer did not meet.
type Failure struct {
	Check string `json:"check"` // status | header:<name> | body_sha256 | body_size | body | json:<key>
	Want  string `json:"want"`
	Got   string `json:"got"`
}

// TLSInfo describes the verified TLS session of an HTTPS probe.
type TLSInfo struct {
	Version  string    `json:"version"`
	Issuer   string    `json:"issuer,omitempty"` // common name of the leaf's issuer
	DNSNames []string  `json:"dns_names,omitempty"`
	NotAfter time.Time `json:"not_after"`
}

// Timing of an HTTPS probe, in milliseconds.
type Timing struct {
	ConnectMS   float64 `json:"connect_ms,omitempty"`
	TLSMS       float64 `json:"tls_ms,omitempty"`
	FirstByteMS float64 `json:"first_byte_ms,omitempty"` // request sent → response headers read
	TotalMS     float64 `json:"total_ms"`
}

// HTTPSResult is the outcome of an HTTPS probe.
type HTTPSResult struct {
	Address       string            `json:"address"`
	SNI           string            `json:"sni"`
	Host          string            `json:"host"`
	Path          string            `json:"path"` // as sent, credentials redacted
	OK            bool              `json:"ok"`   // an answer was read and every expectation is met
	Status        int               `json:"status,omitempty"`
	Class         string            `json:"class,omitempty"`
	Headers       map[string]string `json:"headers,omitempty"`
	BodySize      int64             `json:"body_size"`
	BodySHA256    string            `json:"body_sha256,omitempty"`
	BodyTruncated bool              `json:"body_truncated,omitempty"`
	JSON          map[string]string `json:"json,omitempty"`
	TLS           *TLSInfo          `json:"tls,omitempty"`
	Failures      []Failure         `json:"failures,omitempty"`
	Timing        Timing            `json:"timing"`
	CheckedAt     time.Time         `json:"checked_at"`
	Error         *Error            `json:"error,omitempty"`
}

// EdgeRequest is the edge check of provisioning step 18 for one tenant hostname.
type EdgeRequest struct {
	Address   string   `json:"address"`              // the edge's public listener, ip:port
	Host      string   `json:"host"`                 // the tenant's control hostname (SNI = Host)
	CapVer    int      `json:"capver,omitempty"`     // /key?v=<capver>; default DefaultCapVer
	PublicKey string   `json:"public_key,omitempty"` // expected Noise public key ("mkey:<64 hex>"); "" = any
	Forbidden []string `json:"forbidden,omitempty"`  // paths that must answer 404; nil = DefaultForbidden
	TimeoutMS int      `json:"timeout_ms,omitempty"` // per request
}

// EdgeResult is the outcome of an edge check.
type EdgeResult struct {
	Host      string        `json:"host"`
	OK        bool          `json:"ok"`        // /key answered the key and every forbidden path answered 404
	Key       HTTPSResult   `json:"key"`       // GET /key?v=<capver>
	Forbidden []HTTPSResult `json:"forbidden"` // one per forbidden path, in request order
	Blocked   int           `json:"blocked"`   // forbidden paths that answered 404
	TotalMS   float64       `json:"total_ms"`
	CheckedAt time.Time     `json:"checked_at"`
}

// RelayRequest is the relay check of provisioning step 17 for one tenant hostname.
type RelayRequest struct {
	Address   string `json:"address"`              // the edge's public listener, ip:port
	Host      string `json:"host"`                 // the tenant's control hostname (GET /derp/probe)
	STUN      string `json:"stun"`                 // the shared STUN responder of the public entry, ip:port
	TimeoutMS int    `json:"timeout_ms,omitempty"` // per probe
}

// RelayResult is the outcome of a relay check.
type RelayResult struct {
	Host      string      `json:"host"`
	OK        bool        `json:"ok"`
	DERP      HTTPSResult `json:"derp"`
	STUN      STUNResult  `json:"stun"`
	TotalMS   float64     `json:"total_ms"`
	CheckedAt time.Time   `json:"checked_at"`
}

// DefaultForbidden are the paths the edge must answer 404 on a tenant hostname (§14.6, §11.3 step 18): the list of
// FORBIDDEN_PUBLIC in tests/security/edge/conformance.py (kept in sync by a test) plus GET /api/v1/health.
var DefaultForbidden = []string{
	"/", "/api/v1/apikey", "/api/v1/user", "/api/v1/node", "/api/v1/policy", "/api/v1/health", "/swagger",
	"/swagger/v1/openapiv2.json", "/verify", "/version", "/health", "/metrics", "/debug/pprof/", "/debug/policy",
	"/apple", "/apple/macos", "/windows", "/windows/tailscale.reg", "/register", "/derpx", "/keys", "/ts2021x",
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }
