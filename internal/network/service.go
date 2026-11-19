package network

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/jobs"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// Problem codes (§13.1) carried by Error; the HTTP adapter maps them one to one.
const (
	CodeNotFound            = "not_found"
	CodeConflict            = "conflict"
	CodeValidationFailed    = "validation_failed"
	CodePreconditionFailed  = "precondition_failed"
	CodePreconditionReq     = "precondition_required"
	CodeIdempotencyKeyReuse = "idempotency_key_reuse"
	CodeInstanceUnavailable = "instance_unavailable"
	CodeUpstreamRejected    = "upstream_rejected"
	CodeInternal            = "internal_error"
)

// Error is a refusal or failure of a network operation with the Problem code the API answers.
type Error struct {
	Code       string        // Code…
	Reason     string        // stable machine-readable cause (audit, logs) — never shown as Problem.detail
	Field      string        // validation_failed: the invalid field
	Detail     string        // client-facing text written here (never an upstream message)
	RetryAfter time.Duration // conflict on an Idempotency-Key in progress
	Err        error         // cause, internal log only
}

func (e *Error) Error() string {
	s := "network: " + e.Code
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

func ifMatchRequired(what string) *Error {
	return &Error{Code: CodePreconditionReq, Reason: "if_match_required", Detail: "If-Match with the " + what + " is required."}
}

func stale(reason, detail string) *Error {
	return &Error{Code: CodePreconditionFailed, Reason: reason, Detail: detail}
}

// fromAdapter maps an error of internal/headscale (or of the context) to an Error (§13.4 rule 5): Headscale's own
// message stays in the cause, the client only gets the filtered detail of the adapter.
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
			return &Error{Code: CodeInstanceUnavailable, Reason: "timeout", Err: err,
				Detail: "The tenant's control plane is not responding; try again later."}
		}
		return &Error{Code: CodeInternal, Reason: "internal", Err: err}
	}
	e := &Error{Code: he.ProblemCode(), Reason: string(he.Kind), Err: err, Detail: he.Detail()}
	if he.Kind == headscale.KindNotFound {
		e.Code, e.Reason, e.Detail = CodeNotFound, ReasonNodeGone, "The resource does not exist."
	}
	if e.Code == CodeValidationFailed {
		e.Field = "prefixes"
	}
	return e
}

// Reasons shared by the operations.
const (
	ReasonNoDevice         = "no_device"         // no live device with this ID in the tenant
	ReasonNodeGone         = "node_gone"         // the device's node no longer exists on the instance
	ReasonNoInstance       = "no_instance"       // the tenant has no live instance
	ReasonReadbackMismatch = "readback_mismatch" // Headscale answered but the read-back does not show the change
	ReasonStaleRoutes      = "stale_routes_etag" // If-Match ≠ the hash of the routes Headscale approved NOW
	ReasonNotWired         = "not_wired"         // the process was built without a collaborator (fail closed)
)

// DeviceRegister is the part of the device register (internal/devices owns device_inventory_cache — §13.6) the routes
// and the DNS lint use, inside the caller's tenant transaction q. devices.RouteRegister implements it; apps/ wires it.
type DeviceRegister interface {
	// ListLive returns the live devices of the tenant (not removed).
	ListLive(ctx context.Context, q *sqlcdb.Queries, tenantID uuid.UUID) ([]sqlcdb.DeviceInventoryCache, error)
	// LockLive locks the live device FOR UPDATE until q's transaction ends (store.ErrNoRows when there is none).
	LockLive(ctx context.Context, q *sqlcdb.Queries, tenantID, deviceID uuid.UUID) (sqlcdb.DeviceInventoryCache, error)
	// RecordRoutes stores the approved and advertised routes just read from Headscale on the locked device.
	RecordRoutes(ctx context.Context, q *sqlcdb.Queries, tenantID, deviceID uuid.UUID, approved, advertised []netip.Prefix) error
}

// TagChecker checks tag names against the tenant's catalog inside the caller's transaction q and locks them FOR SHARE
// (policies.RequireTags — P4-T15; network may not import policies, §13.6). It returns the names sorted without
// duplicates; a refusal of the caller's input carries a Validation() (field, reason, tags, ok) method.
type TagChecker func(ctx context.Context, q *sqlcdb.Queries, tenantID uuid.UUID, names []string, field string) ([]string, error)

// ReconfigureRequest is the instance.reconfigure that PUT /dns/settings enqueues.
type ReconfigureRequest struct {
	TenantID, InstanceID uuid.UUID
	Nameservers          []string // normalized, 1..MaxNameservers
	RequestedBy          *uuid.UUID
	Action               string // the operation's x-audit-action (the job closes it)
	Source               string // the operation that changed the setting (job input)
}

// Reconfigurer enqueues instance.reconfigure in the caller's tenant transaction (orchestrator.EnqueueReconfigure —
// P3-T13's internal entry point, wired in apps/). created = false: the unfinished job asking for the same change. A
// refusal is an *Error (the wiring maps the orchestrator's refusals).
type Reconfigurer func(ctx context.Context, tx *store.Tx, req ReconfigureRequest) (job jobs.Job, created bool, err error)

// Config are the collaborators and settings of a Service.
type Config struct {
	// Registry is the Headscale adapter (§13.4): the routes. nil ⇒ the route writes refuse (not_wired).
	Registry headscale.Registry
	// Devices is the device register (routes, DNS lint). nil ⇒ the routes and the DNS records refuse (not_wired).
	Devices DeviceRegister
	// Tags checks the tags of a resource against the catalog. nil ⇒ a resource with tags is refused (not_wired).
	Tags TagChecker
	// Reconfigure enqueues instance.reconfigure (PUT /dns/settings). nil ⇒ refused (not_wired).
	Reconfigure Reconfigurer
	// BaseDomain is the platform's domain (MG_BASE_DOMAIN): a DNS record under it is accepted only inside the tenant's
	// own MagicDNS domain <slug>.tail.<domain> (the Host Agent refuses the rest — agentspec.WriteDNSRecords).
	BaseDomain string
	// Now is the clock of the idempotency bookkeeping; default time.Now.
	Now    func() time.Time
	Logger *slog.Logger
}

// Service is the network module on a store (api: mg_api_tenant; worker: mg_worker_tenant for the records job).
type Service struct {
	st  *store.Store
	cfg Config
	log *slog.Logger
}

// New returns the network module of the process whose store is st.
func New(st *store.Store, cfg Config) (*Service, error) {
	if st == nil {
		return nil, errors.New("network: a store is required")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}
	cfg.BaseDomain = strings.TrimSuffix(strings.ToLower(cfg.BaseDomain), ".")
	return &Service{st: st, cfg: cfg, log: log}, nil
}

// Actor is the caller of a write.
type Actor struct {
	IdentityID uuid.UUID
}

func (a Actor) by() *uuid.UUID {
	if a.IdentityID == uuid.Nil {
		return nil
	}
	id := a.IdentityID
	return &id
}

// Idempotency is the Idempotency-Key of a create request and the SHA-256 of the request (jobs.RequestHash).
type Idempotency struct {
	Key  string
	Hash []byte
}

// idemKey is the key of a request (jobs.IdempotencyKey).
type idemKey = jobs.IdempotencyKey

// idempotencyLock bounds how long a request holds its key while in progress.
const idempotencyLock = 30 * time.Second

// beginIdempotent takes the key of a create (§13.1) in a transaction of its own: a replay decodes the stored body
// into replay and reports true; a key in progress or reused for another request is refused.
func (s *Service) beginIdempotent(ctx context.Context, tenantID uuid.UUID, key jobs.IdempotencyKey, hash []byte, replay any) (bool, error) {
	replayed := false
	err := s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		d, err := jobs.BeginIdempotent(ctx, q, key, hash, idempotencyLock)
		if errors.Is(err, jobs.ErrInvalidIdempotencyKey) {
			return invalid("Idempotency-Key", "invalid_idempotency_key", "The Idempotency-Key is invalid.")
		}
		if err != nil {
			return err
		}
		switch d.Outcome {
		case jobs.IdempotencyReplay:
			if d.Response == nil || json.Unmarshal(d.Response.Body, replay) != nil {
				return errors.New("network: stored response of the Idempotency-Key unreadable")
			}
			replayed = true
		case jobs.IdempotencyInProgress:
			return &Error{Code: CodeConflict, Reason: "idempotency_in_progress", RetryAfter: d.RetryAfter,
				Detail: "A request with this Idempotency-Key is still in progress."}
		case jobs.IdempotencyKeyReuse:
			return &Error{Code: CodeIdempotencyKeyReuse, Reason: "idempotency_key_reuse",
				Detail: "The Idempotency-Key was used for another request."}
		}
		return nil
	})
	return replayed, err
}

// failIdempotent releases the key of a request that failed (best effort: the key expires anyway).
func (s *Service) failIdempotent(ctx context.Context, tenantID uuid.UUID, key jobs.IdempotencyKey, hash []byte) {
	if err := s.st.WithTenantTx(context.WithoutCancel(ctx), tenantID, func(q *sqlcdb.Queries) error {
		return jobs.FailIdempotent(ctx, q, key, hash)
	}); err != nil && !errors.Is(err, jobs.ErrIdempotencyLost) {
		s.log.WarnContext(ctx, "network: Idempotency-Key not released", "operation", key.OperationID, "error", err.Error())
	}
}

// completeIdempotent stores the response of a create in its transaction q.
func completeIdempotent(ctx context.Context, q *sqlcdb.Queries, key jobs.IdempotencyKey, hash []byte, status int, body any,
	res *jobs.Resource) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	return jobs.CompleteIdempotent(ctx, q, key, hash, jobs.StoredResponse{Status: status, Body: b, Resource: res})
}

// versionETag is the entity tag of a row with an optimistic version (§6.1).
func versionETag(v int64) string { return `"` + strconv.FormatInt(v, 10) + `"` }

// normalizeIfMatch is "" for a missing If-Match or "*" (428 — the IfMatch parameter of the spec).
func normalizeIfMatch(s string) string {
	s = strings.TrimSpace(s)
	if s == "*" {
		return ""
	}
	return s
}
