package tenants

// Common parts of the tenant administration of P4-T03a (settings.go, idpconfig.go, deletion.go): the caller, the
// refusals, step-up and If-Match.

import (
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
)

var (
	// ErrReauthRequired: the operation needs a recent sign-in (401 reauth_required — §8.3 step 7).
	ErrReauthRequired = errors.New("tenants: step-up required")
	// ErrPreconditionRequired: a write without the ETag the caller read (428).
	ErrPreconditionRequired = errors.New("tenants: If-Match required")
	// ErrPreconditionFailed: the resource changed since the caller read it (412).
	ErrPreconditionFailed = errors.New("tenants: the resource changed since it was read")
	// ErrStale: an approved change whose target changed since the request (409 target_changed, nothing written).
	ErrStale = errors.New("tenants: the target changed since the request")
	// ErrUnavailable: the operation needs something this process does not have (409 — e.g. no SecretStore).
	ErrUnavailable = errors.New("tenants: not available")
)

// AdminError is a refusal with a stable reason (and, for a 422, the body field). errors.Is(err, Kind).
type AdminError struct {
	Kind   error
	Reason string
	Field  string
}

func (e *AdminError) Error() string {
	s := "tenants: " + e.Kind.Error() + " (" + e.Reason
	if e.Field != "" {
		s += ", " + e.Field
	}
	return s + ")"
}

func (e *AdminError) Unwrap() error { return e.Kind }

func adminRefuse(kind error, reason string) *AdminError {
	return &AdminError{Kind: kind, Reason: reason}
}

func adminInvalid(field, reason string) *AdminError {
	return &AdminError{Kind: ErrInvalid, Reason: reason, Field: field}
}

// Actor is the caller of a tenant administration operation: identity, membership, the auth_time of its session and
// its display name (for the notifications).
type Actor struct {
	IdentityID   uuid.UUID
	MembershipID uuid.UUID
	AuthTime     time.Time
	Display      string
}

// StepUpWindow is the freshness of auth_time the sensitive operations require (§8.3 step 7).
const StepUpWindow = 15 * time.Minute

func (s *Service) stepUp(a Actor) error {
	now := s.now()
	if a.AuthTime.IsZero() || now.Sub(a.AuthTime) > StepUpWindow || a.AuthTime.After(now.Add(2*time.Minute)) {
		return adminRefuse(ErrReauthRequired, "step_up_required")
	}
	return nil
}

// checkIfMatch reads an If-Match value against the current ETag (RFC 9110 §13.1.1, strong comparison; "*" counts as
// missing — it names no version).
func checkIfMatch(ifMatch, current string) error {
	v := strings.TrimSpace(ifMatch)
	if v == "" || v == "*" {
		return adminRefuse(ErrPreconditionRequired, "if_match_required")
	}
	for _, t := range strings.Split(v, ",") {
		if strings.TrimSpace(t) == current {
			return nil
		}
	}
	return adminRefuse(ErrPreconditionFailed, "if_match_stale")
}
