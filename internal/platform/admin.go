package platform

// Platform administration of P4-T03a (§8.2, §8.4 invariant 3, §8.5, §12.2): platform users (users.go), system settings
// (settings.go), subscription plans (plans.go), the registry fields of a tenant (tenantedit.go) and identity providers
// (idps.go). Layer 1 (internal/authz) decided the route before any of these runs — and, for the conditional cells of
// the Super Admin (excludes_super_admin, tenant_idp_dual_control), handed the condition to the operation, which
// enforces it here. Every write runs in one platform transaction with its audit event (§6.1); the writes that touch a
// tenant's own data (a tenant IdP change approved by two Super Admins) run in that tenant's transaction, so the tenant's
// audit lists them (§8.2 "ghi audit hiển thị cho tenant").

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

var (
	// ErrForbidden: the operation refuses this caller or target (403) — a Super Admin target of platform.user:assign
	// (excludes_super_admin), a change of one's own platform user.
	ErrForbidden = errors.New("platform: forbidden")
	// ErrReauthRequired: the operation needs a recent sign-in (401 reauth_required — §8.3 step 7).
	ErrReauthRequired = errors.New("platform: step-up required")
)

// StepUpWindow is the freshness of auth_time the sensitive administration operations require (§8.3 step 7).
const StepUpWindow = 15 * time.Minute

const clockSkew = 2 * time.Minute

// Actor is the caller of an administration operation: its identity and the auth_time of its session.
type Actor struct {
	IdentityID uuid.UUID
	AuthTime   time.Time
	// Condition is the condition of the caller's grant (authz.Decision.Condition): "excludes_super_admin" for the
	// Super Admin on platform.user:assign, "tenant_idp_dual_control" on platform.idp:manage; "" otherwise.
	Condition string
}

// AdminError is a refusal of an administration operation. Kind is one of ErrNotFound, ErrInvalid, ErrConflict,
// ErrForbidden, ErrReauthRequired, ErrPreconditionRequired, ErrPreconditionFailed, ErrIdempotencyKeyReuse,
// ErrIdempotencyInProgress; Reason is a stable code (audit and logs, and the field error code of a 422); Field names
// the body field of a 422.
type AdminError struct {
	Kind       error
	Reason     string
	Field      string
	RetryAfter time.Duration
}

func (e *AdminError) Error() string {
	s := "platform: " + e.Kind.Error() + " (" + e.Reason
	if e.Field != "" {
		s += ", " + e.Field
	}
	return s + ")"
}

func (e *AdminError) Unwrap() error { return e.Kind }

func refuse(kind error, reason string) *AdminError { return &AdminError{Kind: kind, Reason: reason} }

func invalid(field, reason string) *AdminError {
	return &AdminError{Kind: ErrInvalid, Reason: reason, Field: field}
}

// Reasons of the refusals (AdminError.Reason).
const (
	ReasonStepUp            = "step_up_required"
	ReasonSuperAdminTarget  = "super_admin_target"   // excludes_super_admin: a Super Admin is changed only through the 2P operation
	ReasonSelf              = "own_platform_user"    // no change of one's own platform user
	ReasonAlreadyMember     = "platform_user_exists" // the identity already is a platform user
	ReasonNoPlatformIdP     = "no_platform_idp"      // not exactly one active platform IdP
	ReasonIdentityDisabled  = "identity_disabled"
	ReasonState             = "state_unchanged" // the super-admin request asks for the current state
	ReasonLastSuperAdmin    = "last_super_admin"
	ReasonStale             = "target_changed" // the approved target changed since the request
	ReasonReadOnly          = "read_only"
	ReasonKeyTaken          = "plan_key_taken"
	ReasonPlanUnavailable   = "plan_unavailable"
	ReasonNoSubscription    = "no_live_subscription"
	ReasonTenantClosed      = "tenant_deprovisioning"
	ReasonImmutable         = "immutable"
	ReasonInvalid           = "invalid"
	ReasonEmpty             = "empty"
	ReasonConditionMismatch = "condition_mismatch" // the decision carries a condition this operation does not know
)

// stepUp is the step-up of §8.3 step 7 on the caller's session.
func stepUp(a Actor, now time.Time) error {
	if a.AuthTime.IsZero() || now.Sub(a.AuthTime) > StepUpWindow || a.AuthTime.After(now.Add(clockSkew)) {
		return refuse(ErrReauthRequired, ReasonStepUp)
	}
	return nil
}

// versionETag is the strong ETag of a row version (the ETag of GET /tenants/{t}, /platform/tenants/{id} — tenantsapi).
func versionETag(v int64) string { return strconv.Quote(strconv.FormatInt(v, 10)) }

// ifMatchVersion reads an If-Match value against the current version-based ETag (RFC 9110 §13.1.1: a list compared
// strongly; "*" names no version, so it counts as missing).
func ifMatchVersion(ifMatch string, version int64) error {
	return ifMatchETag(ifMatch, versionETag(version))
}

func ifMatchETag(ifMatch, current string) error {
	v := strings.TrimSpace(ifMatch)
	if v == "" || v == "*" {
		return refuse(ErrPreconditionRequired, "if_match_required")
	}
	for _, t := range strings.Split(v, ",") {
		if strings.TrimSpace(t) == current {
			return nil
		}
	}
	return refuse(ErrPreconditionFailed, "if_match_stale")
}

// pageCursor is the opaque cursor of the (created_at, id) lists: version | created_at (µs) | id.
func encodePageCursor(t time.Time, id uuid.UUID) string {
	b := make([]byte, 0, 25)
	b = append(b, 1)
	b = binary.BigEndian.AppendUint64(b, uint64(t.UnixMicro())) //nolint:gosec // timestamps after 1970
	b = append(b, id[:]...)
	return base64.RawURLEncoding.EncodeToString(b)
}

func decodePageCursor(s string) (*time.Time, *uuid.UUID, error) {
	if s == "" {
		return nil, nil, nil
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil || len(b) != 25 || b[0] != 1 {
		return nil, nil, invalid("cursor", "invalid_cursor")
	}
	micros := binary.BigEndian.Uint64(b[1:9])
	if micros > 1<<62 {
		return nil, nil, invalid("cursor", "invalid_cursor")
	}
	id, err := uuid.FromBytes(b[9:])
	if err != nil {
		return nil, nil, invalid("cursor", "invalid_cursor")
	}
	t := time.UnixMicro(int64(micros)).UTC()
	return &t, &id, nil
}

func pageLimit(limit int) (int, error) {
	if limit == 0 {
		return DefaultLimit, nil
	}
	if limit < 1 || limit > MaxLimit {
		return 0, invalid("limit", "invalid_limit")
	}
	return limit, nil
}
