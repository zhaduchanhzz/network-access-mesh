package notifications

import (
	"errors"
	"fmt"
	"maps"
	"net/mail"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
)

// Kind is notification_outbox.kind: the event a notification reports.
type Kind string

// Kinds of P3-T05b (§20). The kinds of Phase 4 (policy 4-eyes approval, security settings, IdP configuration, group
// membership, route approval) are added by the task that builds their producer.
const (
	KindTenantActivated       Kind = "tenant.activated"        // §11.3 step 19 (P3-T05)
	KindInvitation            Kind = "tenant.invitation"       // Owner invitation (§11.3 step 16), invitations (P3-T05a)
	KindTenantSuspended       Kind = "tenant.suspended"        // P3-T08
	KindTenantResumed         Kind = "tenant.resumed"          // P3-T08
	KindDeviceNew             Kind = "device.new"              // a device joined the tailnet (enrollment — P4-T06)
	KindDeviceExpiring        Kind = "device.expiring"         // node key expires soon (inventory.sync — P2-T13)
	KindAPIKeyExpiring        Kind = "instance.apikey_expiring" // platform: instance API key expires soon (P3-T10)
	KindPolicyApplied         Kind = "policy.applied"          // policy core (P3-T08a), policy.apply (P4-T10)
	KindSupportGrantRequested Kind = "support.grant_requested" // a Support Access Grant waits for the tenant's decision (§8.7)
	KindBreakGlass            Kind = "support.break_glass"     // a grant approved by break-glass (§8.7)
	KindSupportGrantUsed      Kind = "support.grant_used"      // platform staff acted inside the tenant (§8.7)
	KindApprovalRequested     Kind = "approval.requested"      // a tenant approval request waits for a decision (P3-T04a)
)

// Tenant and platform role keys of the default recipient rules (§6.3, roles of §8.4).
const (
	RoleTenantOwner      = "tenant_owner"
	RoleTenantAdmin      = "tenant_admin"
	RoleSuperAdmin       = "super_admin"
	RolePlatformOperator = "platform_operator"
)

// Locales of the templates; DefaultLocale when a recipient has none.
const (
	LocaleVI      = "vi"
	LocaleEN      = "en"
	DefaultLocale = LocaleVI
)

// field types of a payload.
type fieldType int

const (
	fString fieldType = iota
	fInt
	fTime
	fUUID
)

// spec is the fixed description of a kind: the payload fields it may carry (and nothing else), whether it is a
// platform kind (tenant_id NULL), and the TenantSettings.notifications key that may switch part of it off.
type spec struct {
	fields   map[string]fieldType
	required []string
	platform bool
	// setting: TenantSettings.notifications.<setting> = false removes the ROLE part of the audience (Tenant Owner /
	// Tenant Admin copies); named members (the device's owner) and explicit addresses always receive it. Kinds without a
	// setting (security notifications — §6.3) cannot be switched off.
	setting string
}

var specs = map[Kind]spec{
	KindTenantActivated: {fields: map[string]fieldType{}},
	KindInvitation: {fields: map[string]fieldType{"invitation_id": fUUID, "role": fString, "expires_at": fTime},
		required: []string{"invitation_id", "role", "expires_at"}},
	KindTenantSuspended: {fields: map[string]fieldType{"job_id": fUUID}, required: []string{"job_id"}},
	KindTenantResumed:   {fields: map[string]fieldType{"job_id": fUUID}, required: []string{"job_id"}},
	KindDeviceNew: {fields: map[string]fieldType{"device_id": fUUID, "device_name": fString, "registered_at": fTime},
		required: []string{"device_id", "device_name"}, setting: "new_device"},
	KindDeviceExpiring: {fields: map[string]fieldType{"device_id": fUUID, "device_name": fString, "expires_at": fTime},
		required: []string{"device_id", "device_name", "expires_at"}},
	KindAPIKeyExpiring: {fields: map[string]fieldType{"instance_id": fUUID, "tenant_slug": fString, "expires_at": fTime},
		required: []string{"instance_id", "tenant_slug", "expires_at"}, platform: true},
	KindPolicyApplied: {fields: map[string]fieldType{"application_id": fUUID, "version_id": fUUID, "version": fInt,
		"policy_kind": fString, "trigger": fString, "applied_sha256": fString},
		required: []string{"application_id", "version", "trigger", "applied_sha256"}, setting: "policy_applied"},
	KindSupportGrantRequested: {fields: map[string]fieldType{"grant_id": fUUID, "staff": fString, "reason": fString,
		"expires_at": fTime}, required: []string{"grant_id", "staff"}},
	KindBreakGlass: {fields: map[string]fieldType{"grant_id": fUUID, "staff": fString, "approver": fString,
		"reason": fString, "expires_at": fTime}, required: []string{"grant_id", "staff"}},
	KindSupportGrantUsed: {fields: map[string]fieldType{"grant_id": fUUID, "staff": fString, "first_used_at": fTime},
		required: []string{"grant_id", "staff"}},
	KindApprovalRequested: {fields: map[string]fieldType{"approval_id": fUUID, "action": fString,
		"requested_by": fString, "expires_at": fTime}, required: []string{"approval_id", "action"}},
}

// Kinds returns every kind, sorted.
func Kinds() []Kind {
	out := slices.Collect(maps.Keys(specs))
	slices.Sort(out)
	return out
}

// Audience is who receives a notification. Every part is resolved in the producer's transaction, in the scope of the
// event's tenant (RLS): a recipient of another tenant can never be selected, whatever the producer passes.
type Audience struct {
	Roles         []string    // active members of the tenant with one of these tenant roles
	Permission    string      // active members whose role grants this tenant permission (scope any) — approvers
	Members       []uuid.UUID // these active members of the tenant (the owner of a device…)
	Emails        []string    // addresses without a membership (an invitation): e-mail only, no Portal record
	PlatformRoles []string    // platform events only: active platform staff with these platform roles
}

func (a Audience) empty() bool {
	return len(a.Roles) == 0 && a.Permission == "" && len(a.Members) == 0 && len(a.Emails) == 0 &&
		len(a.PlatformRoles) == 0
}

// Event is one occurrence to notify (§6.3 notification_outbox). Build it with a constructor of this package (they
// set the recipient rule of §6.3 for the kind) and pass it to Enqueue in the transaction of the event itself.
type Event struct {
	Kind     Kind
	TenantID *uuid.UUID // nil: platform event (platform kinds only)
	// Ref identifies the occurrence: Enqueue writes nothing when a notification of the same (tenant, kind, ref) exists,
	// so a producer that runs again (job retry, command repeated) never notifies twice. Required.
	Ref string
	// Payload: only the fields of the kind (identifiers, names, times) — never a secret, a token or a link with one.
	Payload map[string]any
	// Locale of the e-mail ("vi", "en"); "" = DefaultLocale. Stored in the payload.
	Locale string
	To     Audience
}

// Errors of Enqueue.
var (
	ErrInvalidEvent = errors.New("notifications: invalid event")
	ErrNoTenant     = errors.New("notifications: the tenant of the event does not exist in this scope")
)

var (
	refRE    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,199}$`)
	roleRE   = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	permRE   = regexp.MustCompile(`^tenant\.[a-z_]+:[a-z_]+$`)
	textCtrl = regexp.MustCompile(`[\x00-\x08\x0b-\x1f\x7f]`)
)

// maxText bounds one string value of a payload.
const maxText = 256

// payloadReserved are the keys Enqueue adds itself.
var payloadReserved = map[string]bool{"ref": true, "locale": true, "tenant_name": true, "tenant_slug": true}

// validate checks the event against its kind and returns the payload to store (without the reserved keys).
func (ev Event) validate() (map[string]any, error) {
	sp, ok := specs[ev.Kind]
	if !ok {
		return nil, fmt.Errorf("%w: unknown kind %q", ErrInvalidEvent, ev.Kind)
	}
	switch {
	case sp.platform && ev.TenantID != nil:
		return nil, fmt.Errorf("%w: %s is a platform notification (no tenant)", ErrInvalidEvent, ev.Kind)
	case !sp.platform && (ev.TenantID == nil || *ev.TenantID == uuid.Nil):
		return nil, fmt.Errorf("%w: %s needs a tenant", ErrInvalidEvent, ev.Kind)
	case !refRE.MatchString(ev.Ref):
		return nil, fmt.Errorf("%w: ref must be 1–200 characters [A-Za-z0-9_.:-]", ErrInvalidEvent)
	case ev.Locale != "" && ev.Locale != LocaleVI && ev.Locale != LocaleEN:
		return nil, fmt.Errorf("%w: locale %q", ErrInvalidEvent, ev.Locale)
	case ev.To.empty():
		return nil, fmt.Errorf("%w: %s has no audience", ErrInvalidEvent, ev.Kind)
	case sp.platform && (len(ev.To.Roles) > 0 || ev.To.Permission != "" || len(ev.To.Members) > 0):
		return nil, fmt.Errorf("%w: a platform notification goes to platform staff or addresses only", ErrInvalidEvent)
	case !sp.platform && len(ev.To.PlatformRoles) > 0:
		return nil, fmt.Errorf("%w: a tenant notification never goes to platform staff", ErrInvalidEvent)
	case ev.To.Permission != "" && !permRE.MatchString(ev.To.Permission):
		return nil, fmt.Errorf("%w: permission %q", ErrInvalidEvent, ev.To.Permission)
	}
	for _, r := range slices.Concat(ev.To.Roles, ev.To.PlatformRoles) {
		if !roleRE.MatchString(r) {
			return nil, fmt.Errorf("%w: role %q", ErrInvalidEvent, r)
		}
	}
	for _, m := range ev.To.Members {
		if m == uuid.Nil {
			return nil, fmt.Errorf("%w: nil member", ErrInvalidEvent)
		}
	}
	for _, e := range ev.To.Emails {
		if _, err := normalizeEmail(e); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidEvent, err)
		}
	}
	out := make(map[string]any, len(ev.Payload))
	for k, v := range ev.Payload {
		t, ok := sp.fields[k]
		if !ok {
			return nil, fmt.Errorf("%w: %s does not carry field %q", ErrInvalidEvent, ev.Kind, k)
		}
		cv, err := cleanField(k, t, v)
		if err != nil {
			return nil, err
		}
		out[k] = cv
	}
	for _, k := range sp.required {
		if _, ok := out[k]; !ok {
			return nil, fmt.Errorf("%w: %s needs field %q", ErrInvalidEvent, ev.Kind, k)
		}
	}
	return out, nil
}

// cleanField checks one payload value against its type and the no-secret rule and returns its JSON form.
func cleanField(k string, t fieldType, v any) (any, error) {
	bad := func(why string) error { return fmt.Errorf("%w: field %q %s", ErrInvalidEvent, k, why) }
	switch t {
	case fString:
		s, ok := v.(string)
		if !ok {
			return nil, bad("must be a string")
		}
		if err := checkText(s); err != nil {
			return nil, bad(err.Error())
		}
		return s, nil
	case fInt:
		switch n := v.(type) {
		case int:
			return n, nil
		case int32:
			return int(n), nil
		case int64:
			return n, nil
		}
		return nil, bad("must be an integer")
	case fTime:
		tm, ok := v.(time.Time)
		if !ok || tm.IsZero() {
			return nil, bad("must be a time")
		}
		return tm.UTC().Format(time.RFC3339), nil
	case fUUID:
		switch id := v.(type) {
		case uuid.UUID:
			if id == uuid.Nil {
				return nil, bad("must not be the nil UUID")
			}
			return id.String(), nil
		case string:
			p, err := uuid.Parse(id)
			if err != nil || p == uuid.Nil {
				return nil, bad("must be a UUID")
			}
			return p.String(), nil
		}
		return nil, bad("must be a UUID")
	}
	return nil, bad("has an unknown type")
}

// checkText is the no-secret rule of a text value (§6.3 "không chứa secret"): bounded, UTF-8, single line, and not
// shaped like a credential (Headscale key, JWT, Authorization value, PEM block) or a URL — a link with a token must
// never reach the outbox (links are built by the templates from the platform's own host names).
func checkText(s string) error {
	l := strings.ToLower(s)
	switch {
	case len(s) > maxText || !utf8.ValidString(s):
		return fmt.Errorf("must be valid UTF-8 of at most %d bytes", maxText)
	case textCtrl.MatchString(s) || strings.ContainsAny(s, "\r\n"):
		return errors.New("must be a single line without control characters")
	case strings.Contains(l, "hskey-") || strings.HasPrefix(s, "eyJ") || strings.HasPrefix(l, "bearer ") ||
		strings.HasPrefix(l, "basic ") || strings.Contains(s, "-----BEGIN"):
		return errors.New("looks like a credential")
	case strings.Contains(l, "://"):
		return errors.New("must not be a URL (links are built by the templates)")
	}
	return nil
}

// normalizeEmail returns the bare address of e (lower-cased domain kept as given — citext compares case-insensitively).
func normalizeEmail(e string) (string, error) {
	a, err := mail.ParseAddress(e)
	if err != nil || a.Name != "" || a.Address != strings.TrimSpace(e) || len(a.Address) > 320 ||
		strings.ContainsAny(a.Address, "\r\n") {
		return "", fmt.Errorf("invalid e-mail address")
	}
	return a.Address, nil
}

// unixRef formats a time for a ref.
func unixRef(t time.Time) string { return fmt.Sprintf("%d", t.Unix()) }

// ---------------------------------------------------------------- constructors (recipient rules of §6.3)

func tenantPtr(id uuid.UUID) *uuid.UUID { return &id }

// TenantActivated — §11.3 step 19: the Tenant Owners, and the addresses of the pending Owner invitation (the Owner has
// usually not signed in yet when the tenant becomes active; the producer passes the invitation's address).
func TenantActivated(tenantID uuid.UUID, invitedOwnerEmails ...string) Event {
	return Event{Kind: KindTenantActivated, TenantID: tenantPtr(tenantID), Ref: "tenant.activated",
		To: Audience{Roles: []string{RoleTenantOwner}, Emails: invitedOwnerEmails}}
}

// Invitation — an invitation to the tenant (§11.3 step 16: the Owner; P3-T05a: any role) sent to an address that has
// no membership yet. The e-mail points at the tenant's sign-in page; it carries no invitation token (the outbox never
// holds a secret — §6.3). A resent invitation (new expiry) is a new notification.
func Invitation(tenantID, invitationID uuid.UUID, email, role string, expiresAt time.Time, locale string) Event {
	return Event{Kind: KindInvitation, TenantID: tenantPtr(tenantID), Locale: locale,
		Ref:     "invitation:" + invitationID.String() + ":" + unixRef(expiresAt),
		Payload: map[string]any{"invitation_id": invitationID, "role": role, "expires_at": expiresAt},
		To:      Audience{Emails: []string{email}}}
}

// TenantSuspended / TenantResumed — the Tenant Owners and Admins; ref = the lifecycle job.
func TenantSuspended(tenantID, jobID uuid.UUID) Event {
	return Event{Kind: KindTenantSuspended, TenantID: tenantPtr(tenantID), Ref: "job:" + jobID.String(),
		Payload: map[string]any{"job_id": jobID}, To: Audience{Roles: []string{RoleTenantOwner, RoleTenantAdmin}}}
}

// TenantResumed — see TenantSuspended.
func TenantResumed(tenantID, jobID uuid.UUID) Event {
	return Event{Kind: KindTenantResumed, TenantID: tenantPtr(tenantID), Ref: "job:" + jobID.String(),
		Payload: map[string]any{"job_id": jobID}, To: Audience{Roles: []string{RoleTenantOwner, RoleTenantAdmin}}}
}

// DeviceNew — §6.3: the device's owner + the Tenant Owners (T-06). TenantSettings.notifications.new_device = false
// stops the Owners' copies only; the device's owner is always told.
func DeviceNew(tenantID, deviceID uuid.UUID, owner *uuid.UUID, deviceName string, registeredAt time.Time) Event {
	ev := Event{Kind: KindDeviceNew, TenantID: tenantPtr(tenantID), Ref: "device:" + deviceID.String() + ":new",
		Payload: map[string]any{"device_id": deviceID, "device_name": deviceName},
		To:      Audience{Roles: []string{RoleTenantOwner}}}
	if !registeredAt.IsZero() {
		ev.Payload["registered_at"] = registeredAt
	}
	if owner != nil {
		ev.To.Members = []uuid.UUID{*owner}
	}
	return ev
}

// DeviceExpiring — the node key of a device expires soon: its owner; a device without an owner (tagged) goes to the
// Tenant Owners and Admins. One notification per device and expiry.
func DeviceExpiring(tenantID, deviceID uuid.UUID, owner *uuid.UUID, deviceName string, expiresAt time.Time) Event {
	ev := Event{Kind: KindDeviceExpiring, TenantID: tenantPtr(tenantID),
		Ref:     "device:" + deviceID.String() + ":expiry:" + unixRef(expiresAt),
		Payload: map[string]any{"device_id": deviceID, "device_name": deviceName, "expires_at": expiresAt}}
	if owner != nil {
		ev.To.Members = []uuid.UUID{*owner}
	} else {
		ev.To.Roles = []string{RoleTenantOwner, RoleTenantAdmin}
	}
	return ev
}

// APIKeyExpiring — platform event: the instance API key of a tenant expires soon (apikey.rotate did not replace it):
// Super Admins and Platform Operators.
func APIKeyExpiring(instanceID uuid.UUID, tenantSlug string, expiresAt time.Time) Event {
	return Event{Kind: KindAPIKeyExpiring, Ref: "apikey:" + instanceID.String() + ":" + unixRef(expiresAt),
		Payload: map[string]any{"instance_id": instanceID, "tenant_slug": tenantSlug, "expires_at": expiresAt},
		To:      Audience{PlatformRoles: []string{RoleSuperAdmin, RolePlatformOperator}}}
}

// PolicyApplied — a policy reached Headscale (read-back matched): the Tenant Owners and Admins, unless
// TenantSettings.notifications.policy_applied = false.
func PolicyApplied(tenantID, applicationID, versionID uuid.UUID, version int, policyKind, trigger, appliedSHA256 string) Event {
	return Event{Kind: KindPolicyApplied, TenantID: tenantPtr(tenantID), Ref: "policy_application:" + applicationID.String(),
		Payload: map[string]any{"application_id": applicationID, "version_id": versionID, "version": version,
			"policy_kind": policyKind, "trigger": trigger, "applied_sha256": appliedSHA256},
		To: Audience{Roles: []string{RoleTenantOwner, RoleTenantAdmin}}}
}

// SupportGrantRequested — "yêu cầu duyệt grant" (§8.7): the members who may decide (tenant.support_grant:decide).
func SupportGrantRequested(tenantID, grantID uuid.UUID, staff, reason string, expiresAt time.Time) Event {
	ev := Event{Kind: KindSupportGrantRequested, TenantID: tenantPtr(tenantID), Ref: "grant:" + grantID.String() + ":requested",
		Payload: map[string]any{"grant_id": grantID, "staff": staff},
		To:      Audience{Permission: "tenant.support_grant:decide"}}
	if reason != "" {
		ev.Payload["reason"] = reason
	}
	if !expiresAt.IsZero() {
		ev.Payload["expires_at"] = expiresAt
	}
	return ev
}

// BreakGlass — security notification (§6.3, T-03): every Tenant Owner, cannot be switched off.
func BreakGlass(tenantID, grantID uuid.UUID, staff, approver, reason string, expiresAt time.Time) Event {
	ev := Event{Kind: KindBreakGlass, TenantID: tenantPtr(tenantID), Ref: "grant:" + grantID.String() + ":break_glass",
		Payload: map[string]any{"grant_id": grantID, "staff": staff},
		To:      Audience{Roles: []string{RoleTenantOwner}}}
	if approver != "" {
		ev.Payload["approver"] = approver
	}
	if reason != "" {
		ev.Payload["reason"] = reason
	}
	if !expiresAt.IsZero() {
		ev.Payload["expires_at"] = expiresAt
	}
	return ev
}

// SupportGrantUsed — platform staff used a grant inside the tenant for the first time: every Tenant Owner (security).
func SupportGrantUsed(tenantID, grantID uuid.UUID, staff string, firstUsedAt time.Time) Event {
	return Event{Kind: KindSupportGrantUsed, TenantID: tenantPtr(tenantID), Ref: "grant:" + grantID.String() + ":used",
		Payload: map[string]any{"grant_id": grantID, "staff": staff, "first_used_at": firstUsedAt},
		To:      Audience{Roles: []string{RoleTenantOwner}}}
}

// ApprovalRequested — a tenant approval request (P3-T04a, §8.6) waits for a decision: the members holding the
// deciding permission (tenant.approval:decide unless the action has its own).
func ApprovalRequested(tenantID, approvalID uuid.UUID, action, permission, requestedBy string, expiresAt time.Time) Event {
	if permission == "" {
		permission = "tenant.approval:decide"
	}
	ev := Event{Kind: KindApprovalRequested, TenantID: tenantPtr(tenantID), Ref: "approval:" + approvalID.String(),
		Payload: map[string]any{"approval_id": approvalID, "action": action},
		To:      Audience{Permission: permission}}
	if requestedBy != "" {
		ev.Payload["requested_by"] = requestedBy
	}
	if !expiresAt.IsZero() {
		ev.Payload["expires_at"] = expiresAt
	}
	return ev
}
