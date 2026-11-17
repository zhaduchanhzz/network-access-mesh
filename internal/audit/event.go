package audit

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"math"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// Outcomes (audit_events.outcome).
const (
	OutcomeSuccess = "success"
	OutcomeDenied  = "denied"
	OutcomeFailure = "failure"
)

// Actor types (audit_events.actor_type).
const (
	ActorIdentity = "identity" // a person with a session
	ActorSystem   = "system"   // a job, a bootstrap command
	ActorSupport  = "support"  // platform staff inside a tenant through a Support Access Grant (§8.7, P4-T13)
)

// Suffixes of the two events of an operation that calls Headscale or runs as a job (§6.1): "<action>.requested",
// committed before the external call, then "<action>.succeeded" or "<action>.failed" with the same operation id.
const (
	SuffixRequested = ".requested"
	SuffixSucceeded = ".succeeded"
	SuffixFailed    = ".failed"
)

// Bounds of the text columns (migration 0004) and of Details.
const (
	maxText        = 200  // resource_id, request_id, actor_display (characters)
	maxAction      = 200  // action
	maxDetailsSize = 8192 // bytes of the JSON object (CHECK of 0004)
	maxDetailKeys  = 32
	maxDetailText  = 256 // bytes of one string value
	maxDetailList  = 32  // elements of one list value
)

// ErrInvalidEvent marks an event the code under test built wrongly (unknown outcome, malformed action, broken
// pairing…): it is refused before reaching the database, whose CHECKs are the second line.
var ErrInvalidEvent = errors.New("audit: invalid event")

var (
	actionRE       = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`)
	resourceTypeRE = regexp.MustCompile(`^[a-z][a-z0-9_.]{0,63}$`)
	detailKeyRE    = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
)

// Details is the free-form part of an event (audit_events.details, security_events.details): stable codes, ids, counts
// and short values — flat, at most 32 keys. Never a secret, token, cookie, OAuth code or state, request or upstream
// body: keys that name such data and values shaped like a credential are dropped before writing and only counted
// (key "_redacted"), whatever the caller passed.
type Details map[string]any

// Event is one row of audit_events.
type Event struct {
	// TenantID is the tenant the event belongs to — the tenant whose audit lists it; nil = a platform event (only
	// GET /platform/audit shows it). Success and failure events of an operation: the tenant of the path (the business
	// transaction's tenant). Denials: the tenant of the ACTOR (nil for platform staff) — never the tenant of the path
	// when they differ (§6.1).
	TenantID *uuid.UUID
	// TargetTenantID is the tenant of the path of a cross-tenant denial; nil otherwise (dropped when equal to TenantID).
	TargetTenantID  *uuid.UUID
	ActorType       string // ActorIdentity (default), ActorSystem, ActorSupport
	ActorIdentityID *uuid.UUID
	SupportGrantID  *uuid.UUID
	ActorDisplay    string // snapshot of the actor's name at write time (§6.1)
	ActorIP         netip.Addr
	Action          string // x-audit-action of the operation, with a pairing suffix for paired events
	ResourceType    string
	ResourceID      string
	RequestID       string     // X-Request-Id (§13.1 "đi xuyên log, audit, job")
	OperationID     *uuid.UUID // pairs *.requested with *.succeeded / *.failed; nil for every other event
	Outcome         string     // OutcomeSuccess (default), OutcomeDenied, OutcomeFailure
	Details         Details
	OccurredAt      time.Time // zero = the database clock
}

// normalize applies the defaults, bounds the free text and checks the event (the CHECKs of 0004, earlier and with a
// clear error).
func (ev *Event) normalize() error {
	if ev.ActorType == "" {
		ev.ActorType = ActorIdentity
	}
	if ev.Outcome == "" {
		ev.Outcome = OutcomeSuccess
	}
	ev.ResourceID = clip(ev.ResourceID, maxText)
	ev.RequestID = clip(ev.RequestID, maxText)
	ev.ActorDisplay = clip(ev.ActorDisplay, maxText)
	if ev.TargetTenantID != nil && ev.TenantID != nil && *ev.TargetTenantID == *ev.TenantID {
		ev.TargetTenantID = nil // not a cross-tenant event
	}
	switch {
	case len(ev.Action) > maxAction || !actionRE.MatchString(ev.Action):
		return fmt.Errorf("%w: action %q is not a dotted lowercase action", ErrInvalidEvent, ev.Action)
	case ev.ActorType != ActorIdentity && ev.ActorType != ActorSystem && ev.ActorType != ActorSupport:
		return fmt.Errorf("%w: actor type %q", ErrInvalidEvent, ev.ActorType)
	case ev.Outcome != OutcomeSuccess && ev.Outcome != OutcomeDenied && ev.Outcome != OutcomeFailure:
		return fmt.Errorf("%w: outcome %q", ErrInvalidEvent, ev.Outcome)
	case !resourceTypeRE.MatchString(ev.ResourceType):
		return fmt.Errorf("%w: resource type %q", ErrInvalidEvent, ev.ResourceType)
	}
	return checkPair(ev.Action, ev.Outcome, ev.OperationID)
}

// checkPair is the pairing rule (CHECK audit_events_operation_pair of 0004).
func checkPair(action, outcome string, op *uuid.UUID) error {
	switch pairSuffix(action) {
	case SuffixRequested, SuffixSucceeded:
		if op == nil || outcome != OutcomeSuccess {
			return fmt.Errorf("%w: %s needs an operation id and outcome success", ErrInvalidEvent, action)
		}
	case SuffixFailed:
		if op == nil || outcome != OutcomeFailure {
			return fmt.Errorf("%w: %s needs an operation id and outcome failure", ErrInvalidEvent, action)
		}
	default:
		if op != nil {
			return fmt.Errorf("%w: only *.requested, *.succeeded and *.failed carry an operation id", ErrInvalidEvent)
		}
	}
	return nil
}

// pairSuffix returns the pairing suffix of action ("" when none).
func pairSuffix(action string) string {
	for _, s := range []string{SuffixRequested, SuffixSucceeded, SuffixFailed} {
		if strings.HasSuffix(action, s) {
			return s
		}
	}
	return ""
}

// params is the row to append, with a fresh UUIDv7 as id.
func (ev *Event) params() (sqlcdb.AppendAuditEventParams, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return sqlcdb.AppendAuditEventParams{}, err
	}
	details, _, err := encodeDetails(ev.Details)
	if err != nil {
		return sqlcdb.AppendAuditEventParams{}, err
	}
	p := sqlcdb.AppendAuditEventParams{
		ID: id, TenantID: ev.TenantID, ActorType: ev.ActorType, ActorIdentityID: ev.ActorIdentityID,
		SupportGrantID: ev.SupportGrantID, Action: ev.Action, ResourceType: ev.ResourceType,
		ResourceID: optional(ev.ResourceID), RequestID: optional(ev.RequestID), OperationID: ev.OperationID,
		TargetTenantID: ev.TargetTenantID, ActorDisplay: optional(ev.ActorDisplay), Outcome: ev.Outcome, Details: details,
	}
	if !ev.OccurredAt.IsZero() {
		at := ev.OccurredAt
		p.OccurredAt = &at
	}
	if ev.ActorIP.IsValid() {
		ip := ev.ActorIP.Unmap()
		p.ActorIp = &ip
	}
	return p, nil
}

// forbiddenKeys name data that never belongs in an audit trail (OAuth code/state/nonce, raw bodies and headers);
// forbiddenKeyParts flag the names of credentials. Matching is on the lower-case key.
var (
	forbiddenKeys = map[string]bool{
		"code": true, "state": true, "nonce": true, "key": true, "body": true, "raw": true, "header": true,
		"headers": true, "query": true, "payload": true, "request": true, "response": true, "upstream": true,
	}
	forbiddenKeyParts = []string{
		"secret", "token", "passw", "cookie", "authoriz", "credential", "private_key", "privkey", "apikey", "api_key",
		"preauth", "bearer", "signature", "verifier", "assertion", "session_id",
	}
)

// allowedKey reports whether a detail key may be written.
func allowedKey(k string) bool {
	if !detailKeyRE.MatchString(k) || forbiddenKeys[k] {
		return false
	}
	for _, p := range forbiddenKeyParts {
		if strings.Contains(k, p) {
			return false
		}
	}
	return true
}

// secretShaped reports a value that looks like a credential: a Headscale key, a JWT/JWS, an Authorization header
// value or a PEM block.
func secretShaped(s string) bool {
	l := strings.ToLower(s)
	return strings.Contains(l, "hskey-") || strings.HasPrefix(s, "eyJ") || strings.HasPrefix(l, "bearer ") ||
		strings.HasPrefix(l, "basic ") || strings.Contains(s, "-----BEGIN")
}

// cleanValue returns the JSON value of v, or false when v must be dropped.
func cleanValue(v any) (any, bool) {
	switch x := v.(type) {
	case nil:
		return nil, true
	case string:
		if len(x) > maxDetailText || !utf8.ValidString(x) || secretShaped(x) {
			return nil, false
		}
		return x, true
	case bool, int, int8, int16, int32, int64, uint8, uint16, uint32:
		return x, true
	case uint:
		return x, uint64(x) <= math.MaxInt64
	case uint64:
		return x, x <= math.MaxInt64
	case float64:
		return x, !math.IsNaN(x) && !math.IsInf(x, 0)
	case uuid.UUID:
		return x.String(), true
	case *uuid.UUID:
		if x == nil {
			return nil, true
		}
		return x.String(), true
	case time.Time:
		return x.UTC().Format(time.RFC3339Nano), true
	case netip.Addr:
		if !x.IsValid() {
			return nil, true
		}
		return x.String(), true
	case []string:
		if len(x) > maxDetailList {
			return nil, false
		}
		out := make([]string, 0, len(x))
		for _, s := range x {
			if len(s) > maxDetailText || !utf8.ValidString(s) || secretShaped(s) {
				return nil, false
			}
			out = append(out, s)
		}
		return out, true
	case []uuid.UUID:
		if len(x) > maxDetailList {
			return nil, false
		}
		out := make([]string, 0, len(x))
		for _, id := range x {
			out = append(out, id.String())
		}
		return out, true
	}
	return nil, false // nested objects, byte slices, errors… never: they may carry anything
}

// encodeDetails filters d (see Details) and encodes it as a JSON object; dropped is how many entries were removed. An
// encoded object above the size bound is replaced by {"_truncated": true}.
func encodeDetails(d Details) (out []byte, dropped int, err error) {
	clean := make(map[string]any, len(d))
	for _, k := range slices.Sorted(maps.Keys(d)) {
		v := d[k]
		if len(clean) >= maxDetailKeys || !allowedKey(k) {
			dropped++
			continue
		}
		cv, ok := cleanValue(v)
		if !ok {
			dropped++
			continue
		}
		clean[k] = cv
	}
	if dropped > 0 {
		clean["_redacted"] = dropped
	}
	out, err = json.Marshal(clean)
	if err != nil {
		return nil, dropped, err
	}
	if len(out) > maxDetailsSize {
		out = []byte(`{"_truncated":true}`)
	}
	return out, dropped, nil
}

// clip returns s cut to at most n bytes on a rune boundary (so at most n characters).
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

func optional(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
