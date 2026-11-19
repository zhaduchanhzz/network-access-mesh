package enrollment

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/config"
	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// Methods (enrollment_requests.method — §6.3).
const (
	MethodWebAuth    = "web_auth"
	MethodPreauthKey = "preauth_key"
	MethodOIDC       = "oidc"
)

// Column values of enrollment_requests.status (§6.3, transitions of §7.4).
const (
	StatusRequested        = "requested"
	StatusPendingApproval  = "pending_approval"
	StatusApproved         = "approved"
	StatusRejected         = "rejected"
	StatusAwaitingDevice   = "awaiting_device"
	StatusClaimed          = "claimed"
	StatusRegistered       = "registered"
	StatusVerified         = "verified"
	StatusCredentialIssued = "credential_issued"
	StatusConsumed         = "consumed"
	StatusExpired          = "expired"
	StatusRevoked          = "revoked"
	StatusFailed           = "failed"
)

// StatusIssued is the API name of awaiting_device and credential_issued (§6.3: "issued … là tên phía API").
const StatusIssued = "issued"

// APIStatuses is the enum EnrollmentRequestStatus of api/openapi.yaml.
var APIStatuses = []string{StatusRequested, StatusPendingApproval, StatusApproved, StatusRejected, StatusIssued,
	StatusClaimed, StatusRegistered, StatusVerified, StatusConsumed, StatusExpired, StatusRevoked, StatusFailed}

// APIStatus maps a column value to the API status.
func APIStatus(column string) string {
	if column == StatusAwaitingDevice || column == StatusCredentialIssued {
		return StatusIssued
	}
	return column
}

// columnStatuses maps an API status to the column values it stands for.
func columnStatuses(api string) []string {
	if api == StatusIssued {
		return []string{StatusAwaitingDevice, StatusCredentialIssued}
	}
	return []string{api}
}

// final reports whether a column status is terminal.
func final(status string) bool {
	switch status {
	case StatusRejected, StatusVerified, StatusConsumed, StatusExpired, StatusRevoked, StatusFailed:
		return true
	}
	return false
}

// Lifetimes of §7.4 and T-06.
const (
	// WebAuthWindow is how long an enrollment code (and the claim of its Auth ID) is valid after it was issued.
	WebAuthWindow = 10 * time.Minute
	// MaxKeyTTL bounds every pre-auth key the platform issues (T-06: "pre-auth key ≤ 15 phút"; CHECK of 0020).
	MaxKeyTTL = 15 * time.Minute
	// DecisionWindow: a request waiting for a decision, or approved and not started, expires after 24 hours.
	DecisionWindow = 24 * time.Hour
	// stuckAfter: an issuance or a claim that did not finish (process died between two transactions) fails after it.
	stuckAfter = 15 * time.Minute
)

// Job kinds and audit actions of the module (x-audit-action of api/openapi.yaml; §13.5).
const (
	KindReconcile = "enrollment.reconcile"
	KindSync      = "inventory.sync" // the device module's sync (it clamps the node's expiry — §7.4 "Vòng đời khóa")

	ActionRequest   = "enrollment.request"
	ActionKeyCreate = "enrollment.key.create"
	ActionApprove   = "enrollment.approve"
	ActionReject    = "enrollment.reject"
	ActionStart     = "enrollment.start"
	ActionRevoke    = "enrollment.revoke"
	ActionClaim     = "enrollment.claim"
	ActionConsume   = "enrollment.consume" // a pre-auth key was used (job enrollment.reconcile, actor system)

	resourceType = "enrollment_request"
	slotEnroll   = "enroll" // dedupe slot of the inventory.sync a verified claim enqueues
)

// Security events (security_events.kind) raised by the module.
const (
	EventClaimWithoutRequest = "enrollment.claim_without_request" // a claim link opened without a pending request (phishing — §7.4 step 6)
	EventClaimReplay         = "enrollment.claim_replay"          // an Auth ID that was already claimed
	EventNodeMismatch        = "enrollment.node_mismatch"         // a new node failed the checks of step 8: deleted
	EventForeignNode         = "enrollment.foreign_node"          // AuthRegister answered a node that existed before and is not the member's: expired
	securitySource           = "enrollment"
)

// Problem codes (§13.1) carried by Error; the HTTP adapter maps them one to one.
const (
	CodeNotFound            = "not_found"
	CodeConflict            = "conflict"
	CodeValidationFailed    = "validation_failed"
	CodeForbidden           = "forbidden"
	CodeIdempotencyReuse    = "idempotency_key_reuse"
	CodeRateLimited         = "rate_limited"
	CodeUpstreamRejected    = "upstream_rejected"
	CodeInstanceUnavailable = "instance_unavailable"
	CodeSecretGone          = "secret_no_longer_available"
	CodeInternal            = "internal_error"
)

// Error is a refusal or a failure of an enrollment operation with the Problem code the API answers.
type Error struct {
	Code       string
	Reason     string // stable machine-readable cause (audit, logs) — never Problem.detail
	Field      string // validation_failed: the invalid field
	Detail     string // client-facing text written here, never an upstream message
	RetryAfter time.Duration
	Err        error // cause, for the internal log only
}

func (e *Error) Error() string {
	s := "enrollment: " + e.Code
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

func invalid(field, reason, detail string) *Error {
	return &Error{Code: CodeValidationFailed, Reason: reason, Field: field, Detail: detail}
}

func conflict(reason, detail string) *Error {
	return &Error{Code: CodeConflict, Reason: reason, Detail: detail}
}

func forbidden(reason, detail string) *Error {
	return &Error{Code: CodeForbidden, Reason: reason, Detail: detail}
}

// Vault keeps a show-once credential for the replay of an Idempotency-Key until the credential expires (§13.1: the
// stored response holds a secret reference, never the secret). apps/* wires it on the SecretStore (secrets.Store, key of
// the tenant, WithExpiry); enrollment does not import secrets (§13.6).
type Vault interface {
	// Keep stores value for tenantID until expires and returns its reference.
	Keep(ctx context.Context, tenantID uuid.UUID, value []byte, expires time.Time) (string, error)
	// Recall returns the value of a reference Keep returned for tenantID; ErrSecretGone once it expired or was destroyed.
	Recall(ctx context.Context, tenantID uuid.UUID, ref string) ([]byte, error)
}

// ErrSecretGone: the credential of a replayed request is no longer kept (410 secret_no_longer_available).
var ErrSecretGone = errors.New("enrollment: the credential is no longer available")

// TagGate checks requested_tags against the tenant's tag catalog INSIDE the caller's transaction and locks the tags
// until it ends (policies.RequireTags — P4-T15, wired in apps/). It returns the names sorted without duplicates; a
// refusal of the caller's input carries a Validation() (field, reason, tags, ok) method.
type TagGate func(ctx context.Context, q *sqlcdb.Queries, tenantID uuid.UUID, names []string, field string) ([]string, error)

// Config are the collaborators of a Service.
type Config struct {
	// Registry is the only way to reach a tenant's Headscale (§13.4). Required.
	Registry headscale.Registry
	// Vault keeps show-once credentials for Idempotency-Key replays (api). nil ⇒ a replay answers 410.
	Vault Vault
	// Tags checks requested_tags (api). nil ⇒ a key with tags is refused (fail closed).
	Tags TagGate
	// ClaimsPerMinute bounds the web-auth claims of one member (§7.4 limit (5)); default 5.
	ClaimsPerMinute int
	Logger          *slog.Logger
	Now             func() time.Time
}

// Service is the enrollment module.
type Service struct {
	st    *store.Store
	reg   headscale.Registry
	vault Vault
	tags  TagGate
	log   *slog.Logger
	now   func() time.Time

	claimLimit int
	mu         sync.Mutex
	claims     map[uuid.UUID][]time.Time // member → recent claim attempts (one process; the API's limiter is the second layer)
}

// New returns the module on the process's store.
func New(st *store.Store, cfg Config) (*Service, error) {
	if st == nil || cfg.Registry == nil {
		return nil, errors.New("enrollment: a store and the Headscale registry are required")
	}
	s := &Service{st: st, reg: cfg.Registry, vault: cfg.Vault, tags: cfg.Tags, log: cfg.Logger, now: cfg.Now,
		claimLimit: cfg.ClaimsPerMinute, claims: map[uuid.UUID][]time.Time{}}
	if s.log == nil {
		s.log = slog.New(slog.DiscardHandler)
	}
	if s.now == nil {
		s.now = time.Now
	}
	if s.claimLimit <= 0 {
		s.claimLimit = 5
	}
	return s, nil
}

// Actor is the caller of an API operation, as the authorization hook decided it.
type Actor struct {
	IdentityID   uuid.UUID
	MembershipID uuid.UUID
	Display      string
	ClientIP     netip.Addr
	// SessionID is the public id of the caller's Portal session (sessions.public_id): a web-auth code is bound to the
	// session that received it (§7.4 step 4, 6) through its SHA-256.
	SessionID uuid.UUID
	// OwnOnly: the grant has scope own (End User on read/revoke) — only the caller's own requests exist for it.
	OwnOnly bool
	// SelfEnrollOnly: the grant carries the condition self_enroll (End User on tenant.enrollment:request) — refused unless
	// the tenant allows self-enrolment.
	SelfEnrollOnly bool
	// CanApprove: the caller holds tenant.enrollment:approve (its request skips the approval — §7.4).
	CanApprove bool
}

// Idempotency is the Idempotency-Key of a create and the hash of its request (jobs.RequestHash).
type Idempotency struct {
	Key  string
	Hash []byte
}

// Request is the API view of an enrollment request (schema EnrollmentRequest — never a secret).
type Request struct {
	ID                  uuid.UUID  `json:"id"`
	Method              string     `json:"method"`
	Status              string     `json:"status"` // API status (APIStatus)
	DeviceLabel         *string    `json:"device_label,omitempty"`
	Tags                []string   `json:"tags"`
	Ephemeral           bool       `json:"ephemeral"`
	Reusable            bool       `json:"reusable"`
	RequestedBy         uuid.UUID  `json:"requested_by_membership_id"`
	Target              *uuid.UUID `json:"target_membership_id,omitempty"`
	Approver            *uuid.UUID `json:"approver_membership_id,omitempty"`
	ApprovedAt          *time.Time `json:"approved_at,omitempty"`
	IssuedAt            *time.Time `json:"issued_at,omitempty"`
	CredentialExpiresAt *time.Time `json:"credential_expires_at,omitempty"`
	ClaimedAt           *time.Time `json:"claimed_at,omitempty"`
	NodeID              *int64     `json:"node_id,omitempty"`
	FailureCode         *string    `json:"failure_code,omitempty"`
	LoginServer         string     `json:"login_server"`
	CreatedAt           time.Time  `json:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at"`
	Version             int64      `json:"version"`
}

func view(r sqlcdb.EnrollmentRequest, loginServer string) Request {
	tags := r.RequestedTags
	if tags == nil {
		tags = []string{}
	}
	return Request{ID: r.ID, Method: r.Method, Status: APIStatus(r.Status), DeviceLabel: r.DeviceLabel, Tags: tags,
		Ephemeral: r.Ephemeral, Reusable: r.Reusable, RequestedBy: r.RequestedByMembershipID, Target: r.TargetMembershipID,
		Approver: r.ApproverMembershipID, ApprovedAt: r.ApprovedAt, IssuedAt: r.IssuedAt,
		CredentialExpiresAt: r.CredentialExpiresAt, ClaimedAt: r.ClaimedAt, NodeID: r.ConsumedNodeID,
		FailureCode: r.FailureCode, LoginServer: loginServer, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
		Version: r.Version}
}

// Credential kinds (EnrollmentCredential.kind).
const (
	CredentialEnrollCode = "enroll_code"
	CredentialPreauthKey = "preauth_key"
)

// Credential is a credential shown once (schema EnrollmentCredential). The secrets are headscale.Secret: every
// formatting path (fmt, slog, JSON) prints a redaction — only Reveal returns them.
type Credential struct {
	Kind       string
	PreauthKey headscale.Secret
	EnrollCode headscale.Secret
	Hostname   string
	Command    string
	ExpiresAt  time.Time
}

// Issue is the answer of an operation that may issue a credential: the request and, once issued, its credential.
type Issue struct {
	Request    Request
	Credential *Credential
}

// ------------------------------------------------------------------------------------------------- helpers

func digest(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}

// sessionHash is the SHA-256 of the public id of a Portal session (enrollment_requests.session_id_hash).
func sessionHash(id uuid.UUID) []byte { return digest("session:" + id.String()) }

var codeEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// newCode returns a one-time enrollment code: 12 characters of lowercase base32 (60 bits) — the client's hostname is
// mg-<code>, which someone who started the flow on their own machine cannot know in advance (§7.4 step 8).
func newCode() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return strings.ToLower(codeEncoding.EncodeToString(b))[:12], nil
}

// HostnamePrefix starts the hostname of a web-auth enrollment: mg-<code>.
const HostnamePrefix = "mg-"

// codeHash is the stored hash of an enrollment code (enrollment_requests.enroll_code_hash).
func codeHash(code string) []byte { return digest("enroll-code:" + code) }

// authIDHash is the stored hash of an Auth ID (enrollment_requests.auth_id_hash).
func authIDHash(authID string) []byte { return digest("auth-id:" + authID) }

func ptr[T any](v T) *T { return &v }

// settingsOf reads the typed TenantSettings of a stored document (lenient: defaults for missing keys).
func settingsOf(raw []byte) config.TenantSettings {
	d, err := config.ParseSettingsDoc(raw)
	if err != nil {
		d, _ = config.ParseSettingsDoc(nil)
	}
	return d.View()
}

// keyTTL is the lifetime of a pre-auth key: the requested minutes (default and bound: MaxKeyTTL), never above the
// tenant's preauth_key_ttl_max.
func keyTTL(requested int, s config.TenantSettings) (time.Duration, error) {
	ttl := MaxKeyTTL
	if requested != 0 {
		if requested < 1 || requested > int(MaxKeyTTL/time.Minute) {
			return 0, invalid("ttl_minutes", "invalid_ttl", "ttl_minutes must be between 1 and 15")
		}
		ttl = time.Duration(requested) * time.Minute
	}
	if limit := parseTTLMax(s.Enrollment.PreauthKeyTTLMax); limit > 0 && limit < ttl {
		ttl = limit
	}
	return ttl, nil
}

// parseTTLMax reads "<n>m" / "<n>h" (config.CheckPreauthKeyTTLMax already accepted it); 0 when unset.
func parseTTLMax(s string) time.Duration {
	if len(s) < 2 {
		return 0
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 0
	}
	return d
}

// allowClaim is the per-member limit of web-auth claims (§7.4 limit (5): "web-auth/claim bị giới hạn tần suất theo
// membership").
func (s *Service) allowClaim(member uuid.UUID) (bool, time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	recent := s.claims[member][:0]
	for _, t := range s.claims[member] {
		if now.Sub(t) < time.Minute {
			recent = append(recent, t)
		}
	}
	if len(recent) >= s.claimLimit {
		s.claims[member] = recent
		return false, time.Minute - now.Sub(recent[0])
	}
	s.claims[member] = append(recent, now)
	if len(s.claims) > 10000 { // bound the memory of a process under attack: forget everyone (the API limiter remains)
		s.claims = map[uuid.UUID][]time.Time{member: s.claims[member]}
	}
	return true, 0
}
