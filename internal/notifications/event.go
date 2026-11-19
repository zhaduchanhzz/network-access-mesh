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
	KindTenantActivated       Kind = "tenant.activated"          // §11.3 step 19 (P3-T05)
	KindInvitation            Kind = "tenant.invitation"         // Owner invitation (§11.3 step 16), invitations (P3-T05a)
	KindTenantSuspended       Kind = "tenant.suspended"          // P3-T08
	KindTenantResumed         Kind = "tenant.resumed"            // P3-T08
	KindDeviceNew             Kind = "device.new"                // a device joined the tailnet (enrollment — P4-T06)
	KindDeviceExpiring        Kind = "device.expiring"           // node key expires soon (inventory.sync — P2-T13)
	KindAPIKeyExpiring        Kind = "instance.apikey_expiring"  // platform: instance API key expires soon (P3-T10)
	KindPolicyApplied         Kind = "policy.applied"            // policy core (P3-T08a), policy.apply (P4-T10)
	KindSupportGrantRequested Kind = "support.grant_requested"   // a Support Access Grant waits for the tenant's decision (§8.7)
	KindBreakGlass            Kind = "support.break_glass"       // a grant approved by break-glass (§8.7)
	KindSupportGrantUsed      Kind = "support.grant_used"        // platform staff acted inside the tenant (§8.7)
	KindApprovalRequested     Kind = "approval.requested"        // a tenant approval request waits for a decision (P3-T04a)
	KindIdPAdminChange        Kind = "idp.admin_change"          // a change made at the tenant's IdP through Keycloak's Admin API (P3-T15)
	KindIdPConsoleLogin       Kind = "idp.console_login"         // platform: a sign-in to the Keycloak administration (P3-T15)
	KindInstanceRestored      Kind = "instance.restored"         // the tenant's control plane was restored from a backup (P3-T11, §17.2 step 7)
	KindTenantDeleted         Kind = "tenant.deleted"            // the tenant was deprovisioned (P3-T09, §11.4)
	KindInstanceQuarantined   Kind = "instance.quarantined"      // platform: an instance was quarantined (P3-T18, §11.4)
	KindInstanceReleased      Kind = "instance.released"         // platform: the release (2P) of a quarantined instance ended (P3-T18)
	KindInstanceOpFailed      Kind = "instance.operation_failed" // platform: an instance.restart / instance.upgrade failed (P3-T13a)
	// P4-T03a
	KindIdPConfigChanged              Kind = "idp.config_changed"                 // the claim constraints / client secret of the tenant's IdP changed, or a platform change of it was requested
	KindSecuritySettingsChanged       Kind = "tenant.security_settings_changed"   // PUT /settings/security wrote the security settings (§8.6)
	KindTenantDeletionRequested       Kind = "tenant.deletion_requested"          // a Tenant Owner asked the platform to delete the tenant
	KindPlatformTenantDeletionRequest Kind = "platform.tenant_deletion_requested" // platform: the same request, for Super Admins / Platform Operators
	// P4-T06 follow-up: the decision on an enrollment request that waited for approval (§7.4 "thông báo cho người yêu cầu")
	KindEnrollmentApproved Kind = "enrollment.approved"
	KindEnrollmentRejected Kind = "enrollment.rejected"
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
	KindIdPAdminChange: {fields: map[string]fieldType{"event_id": fString, "action": fString, "actor": fString,
		"user": fString, "occurred_at": fTime}, required: []string{"event_id", "action", "actor", "occurred_at"}},
	KindIdPConsoleLogin: {fields: map[string]fieldType{"event_id": fString, "username": fString, "client": fString,
		"ip": fString, "occurred_at": fTime, "count": fInt, "sources": fString, "first_at": fTime, "window_minutes": fInt},
		required: []string{"event_id", "client", "occurred_at"}, platform: true},
	KindInstanceRestored: {fields: map[string]fieldType{"job_id": fUUID, "backup_created_at": fTime, "owner_review": fString},
		required: []string{"job_id", "backup_created_at", "owner_review"}},
	KindTenantDeleted: {fields: map[string]fieldType{"job_id": fUUID, "keys_destroy_after": fTime, "final_backup": fString},
		required: []string{"job_id", "keys_destroy_after", "final_backup"}},
	KindInstanceOpFailed: {fields: map[string]fieldType{"instance_id": fUUID, "tenant_slug": fString, "job_id": fUUID,
		"operation": fString, "code": fString, "outcome": fString},
		required: []string{"instance_id", "tenant_slug", "job_id", "operation", "code", "outcome"}, platform: true},
	KindIdPConfigChanged: {fields: map[string]fieldType{"idp_id": fUUID, "stage": fString, "origin": fString,
		"actor": fString, "changed": fString, "approval_id": fUUID}, required: []string{"idp_id", "stage", "origin", "changed"}},
	KindSecuritySettingsChanged: {fields: map[string]fieldType{"changed": fString, "actor": fString, "approval_id": fUUID},
		required: []string{"changed"}},
	KindTenantDeletionRequested: {fields: map[string]fieldType{"requested_by": fString, "requested_at": fTime},
		required: []string{"requested_at"}},
	KindPlatformTenantDeletionRequest: {fields: map[string]fieldType{"tenant_id": fUUID, "tenant_slug": fString,
		"requested_by": fString, "requested_at": fTime}, required: []string{"tenant_id", "tenant_slug", "requested_at"},
		platform: true},
	KindInstanceQuarantined: {fields: map[string]fieldType{"instance_id": fUUID, "tenant_slug": fString, "job_id": fUUID,
		"outcome": fString}, required: []string{"instance_id", "tenant_slug", "job_id", "outcome"}, platform: true},
	KindInstanceReleased: {fields: map[string]fieldType{"instance_id": fUUID, "tenant_slug": fString, "job_id": fUUID,
		"outcome": fString}, required: []string{"instance_id", "tenant_slug", "job_id", "outcome"}, platform: true},
	KindEnrollmentApproved: {fields: map[string]fieldType{"request_id": fUUID, "method": fString, "device_label": fString,
		"decided_by": fString, "expires_at": fTime}, required: []string{"request_id", "method", "expires_at"}},
	KindEnrollmentRejected: {fields: map[string]fieldType{"request_id": fUUID, "method": fString, "device_label": fString,
		"decided_by": fString}, required: []string{"request_id", "method"}},
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
			return nil, fmt.Errorf("%w: %w", ErrInvalidEvent, err)
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

// IdPAdminChange — security notification (§8.2 "không là cửa sau vào tenant", P3-T15): a change was made at the
// tenant's platform-hosted IdP through Keycloak's Admin API (a credential reset, a user, role mapping or client change,
// an impersonation attempt…) — every Tenant Owner, cannot be switched off. One notification per Keycloak event
// (ref = its id): the job that imports the events may run again without notifying twice. action is the audit action
// (idp.user.credential_reset…), actor who did it as the platform describes it, user the affected member when known.
func IdPAdminChange(tenantID uuid.UUID, eventID, action, actor, user string, occurredAt time.Time) Event {
	ev := Event{Kind: KindIdPAdminChange, TenantID: tenantPtr(tenantID), Ref: "idp-event:" + eventID,
		Payload: map[string]any{"event_id": eventID, "action": action, "actor": actor, "occurred_at": occurredAt},
		To:      Audience{Roles: []string{RoleTenantOwner}}}
	if user != "" {
		ev.Payload["user"] = user
	}
	return ev
}

// IdPConsoleLogin — platform security notification (P3-T15, §16.3 "Bảo mật"): someone signed in to the
// administration of the platform-hosted Keycloak (its admin console, or the admin CLI with the break-glass account):
// Super Admins and Platform Operators. One per Keycloak login event that opens a window of its source (account,
// client, address); the sign-ins held back in that window come later as one IdPConsoleLoginSummary (F-G3-2,
// internal/idp/auditsync).
func IdPConsoleLogin(eventID, username, client, ip string, occurredAt time.Time) Event {
	ev := Event{Kind: KindIdPConsoleLogin, Ref: "idp-event:" + eventID,
		Payload: map[string]any{"event_id": eventID, "client": client, "occurred_at": occurredAt},
		To:      Audience{PlatformRoles: []string{RoleSuperAdmin, RolePlatformOperator}}}
	if username != "" {
		ev.Payload["username"] = username
	}
	if ip != "" {
		ev.Payload["ip"] = ip
	}
	return ev
}

// ConsoleLoginSummary is the content of a grouped idp.console_login (F-G3-2): the sign-ins of one source (account,
// client, address) to the Keycloak administration held back during one window, after the first was notified alone.
type ConsoleLoginSummary struct {
	Ref           string // unique per source and window (idp-console-window:<source hash>:<window start>)
	LastEventID   string // the Keycloak event of the last sign-in held back
	Username      string
	Client        string // the client of the last one
	Count         int    // how many were held back
	Sources       string // their distinct sources ("client ip, …"), bounded
	First, Last   time.Time
	WindowMinutes int
}

// IdPConsoleLoginSummary — the grouped idp.console_login (F-G3-2): same kind, recipients and template as
// IdPConsoleLogin, with the count, the sources, the first time and the window; occurred_at is the last sign-in.
func IdPConsoleLoginSummary(s ConsoleLoginSummary) Event {
	ev := Event{Kind: KindIdPConsoleLogin, Ref: s.Ref,
		Payload: map[string]any{"event_id": s.LastEventID, "client": s.Client, "occurred_at": s.Last, "count": s.Count,
			"first_at": s.First, "window_minutes": s.WindowMinutes},
		To: Audience{PlatformRoles: []string{RoleSuperAdmin, RolePlatformOperator}}}
	if s.Username != "" {
		ev.Payload["username"] = s.Username
	}
	if s.Sources != "" {
		ev.Payload["sources"] = s.Sources
	}
	return ev
}

// Outcomes of the quarantine notifications (payload "outcome").
const (
	OutcomeIsolated   = "isolated"   // instance.quarantined: the host isolation is verified
	OutcomeIncomplete = "incomplete" // instance.quarantined: the job could not isolate it — act by hand (RUNBOOK)
	OutcomeReleased   = "released"   // instance.released: serving again after the start guard and the post-start gate
	OutcomeRefused    = "refused"    // instance.released: a check failed — the instance stays quarantined
)

// InstanceQuarantined — platform security notification (§11.4 Quarantine, P3-T18): the quarantine job of an instance
// ended — isolated, or incomplete (Critical: the instance may still serve): Super Admins and Platform Operators. One per
// job.
func InstanceQuarantined(instanceID uuid.UUID, tenantSlug string, jobID uuid.UUID, outcome string) Event {
	return Event{Kind: KindInstanceQuarantined, Ref: "job:" + jobID.String(),
		Payload: map[string]any{"instance_id": instanceID, "tenant_slug": tenantSlug, "job_id": jobID, "outcome": outcome},
		To:      Audience{PlatformRoles: []string{RoleSuperAdmin, RolePlatformOperator}}}
}

// InstanceReleased — platform notification (P3-T18): the release job (2P) of a quarantined instance ended — released,
// or refused (still quarantined): Super Admins and Platform Operators. One per job.
func InstanceReleased(instanceID uuid.UUID, tenantSlug string, jobID uuid.UUID, outcome string) Event {
	return Event{Kind: KindInstanceReleased, Ref: "job:" + jobID.String(),
		Payload: map[string]any{"instance_id": instanceID, "tenant_slug": tenantSlug, "job_id": jobID, "outcome": outcome},
		To:      Audience{PlatformRoles: []string{RoleSuperAdmin, RolePlatformOperator}}}
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

// InstanceRestored — §17.2 step 7: the Tenant Owners and Admins (a security notification: not switchable); ref = the
// restore job. ownerReview is "required" when PostgreSQL was older than the backup (revocations after the backup's
// time are not known to the platform: the Owner reviews members and devices — §17.2 step 4), "none" otherwise.
func InstanceRestored(tenantID, jobID uuid.UUID, backupCreatedAt time.Time, ownerReview bool) Event {
	review := "none"
	if ownerReview {
		review = "required"
	}
	return Event{Kind: KindInstanceRestored, TenantID: tenantPtr(tenantID), Ref: "job:" + jobID.String(),
		Payload: map[string]any{"job_id": jobID, "backup_created_at": backupCreatedAt.UTC(), "owner_review": review},
		To:      Audience{Roles: []string{RoleTenantOwner, RoleTenantAdmin}}}
}

// InstanceOperationFailed — platform event (P3-T13a): an operation of the platform on a tenant's instance failed —
// operation "restart" or "upgrade", code the job's error code, outcome what became of the instance ("rolled_back": the
// previous state is back — for an upgrade, the cold backup restored on the previous image; "rollback_failed": the
// rollback itself failed — Critical, the job waits for /rollback; "resumable": the retries are spent, the lock is held
// until /retry or /rollback). Super Admins and Platform Operators; ref = the job and the outcome.
func InstanceOperationFailed(instanceID, jobID uuid.UUID, tenantSlug, operation, code, outcome string) Event {
	return Event{Kind: KindInstanceOpFailed, Ref: "job:" + jobID.String() + ":" + outcome,
		Payload: map[string]any{"instance_id": instanceID, "tenant_slug": tenantSlug, "job_id": jobID, "operation": operation,
			"code": code, "outcome": outcome},
		To: Audience{PlatformRoles: []string{RoleSuperAdmin, RolePlatformOperator}}}
}

// TenantDeleted — §11.4 Deprovision (P3-T09): the Tenant Owners and Admins (a security notification: not switchable);
// ref = the deprovision job. keysDestroyAfter is when the tenant's keys are destroyed (crypto-shredding — nothing can be
// restored online after it); finalBackup is "kept" (a final backup exists, kept until then and per retention) or
// "skipped" (the operator deprovisioned without one, an audited override of the approval).
func TenantDeleted(tenantID, jobID uuid.UUID, keysDestroyAfter time.Time, finalBackupKept bool) Event {
	fb := "skipped"
	if finalBackupKept {
		fb = "kept"
	}
	return Event{Kind: KindTenantDeleted, TenantID: tenantPtr(tenantID), Ref: "job:" + jobID.String(),
		Payload: map[string]any{"job_id": jobID, "keys_destroy_after": keysDestroyAfter.UTC(), "final_backup": fb},
		To:      Audience{Roles: []string{RoleTenantOwner, RoleTenantAdmin}}}
}

// IdP change origins and stages (payload of idp.config_changed).
const (
	IdPChangeByTenant   = "tenant"    // PATCH /tenants/{t}/identity-provider by a Tenant Owner
	IdPChangeByPlatform = "platform"  // PATCH /platform/identity-providers/{id} on the tenant's row (2P)
	IdPStageRequested   = "requested" // a platform change waits for its second Super Admin — not in effect
	IdPStageApplied     = "applied"   // the change is in effect
)

// IdPConfigChanged — security notification (§8.2 "mọi thay đổi do nền tảng khởi xướng lên IdP của tenant … ghi audit
// hiển thị cho tenant + thông báo Owner", P4-T03a): the Tenant Owners, cannot be switched off. ref = the approval and
// the stage (a platform change) or the IdP version written (a tenant change). changed lists the fields
// (comma-separated); actor is the person as the platform describes it.
func IdPConfigChanged(tenantID, idpID uuid.UUID, stage, origin, changed, actor string, approvalID *uuid.UUID, version int64) Event {
	ref := fmt.Sprintf("idp:%s:v%d", idpID, version)
	if approvalID != nil {
		ref = "approval:" + approvalID.String() + ":" + stage
	}
	ev := Event{Kind: KindIdPConfigChanged, TenantID: tenantPtr(tenantID), Ref: ref,
		Payload: map[string]any{"idp_id": idpID, "stage": stage, "origin": origin, "changed": changed},
		To:      Audience{Roles: []string{RoleTenantOwner}}}
	if actor != "" {
		ev.Payload["actor"] = actor
	}
	if approvalID != nil {
		ev.Payload["approval_id"] = *approvalID
	}
	return ev
}

// SecuritySettingsChanged — security notification (§8.6 tenant.settings:update_security "step-up + audit + thông
// báo"): Tenant Owners and Admins, cannot be switched off. ref = the settings ETag written (one per state).
func SecuritySettingsChanged(tenantID uuid.UUID, etag, changed, actor string, approvalID *uuid.UUID) Event {
	ev := Event{Kind: KindSecuritySettingsChanged, TenantID: tenantPtr(tenantID), Ref: "settings:" + strings.Trim(etag, `"`),
		Payload: map[string]any{"changed": changed},
		To:      Audience{Roles: []string{RoleTenantOwner, RoleTenantAdmin}}}
	if actor != "" {
		ev.Payload["actor"] = actor
	}
	if approvalID != nil {
		ev.Payload["approval_id"] = *approvalID
	}
	return ev
}

// TenantDeletionRequested — a Tenant Owner asked the platform to delete the tenant (POST /request-deletion): every
// Tenant Owner; one per tenant and UTC day.
func TenantDeletionRequested(tenantID uuid.UUID, requestedBy string, at time.Time) Event {
	ev := Event{Kind: KindTenantDeletionRequested, TenantID: tenantPtr(tenantID), Ref: "deletion:" + at.UTC().Format("2006-01-02"),
		Payload: map[string]any{"requested_at": at}, To: Audience{Roles: []string{RoleTenantOwner}}}
	if requestedBy != "" {
		ev.Payload["requested_by"] = requestedBy
	}
	return ev
}

// textOr returns s when it passes the no-secret rule of a payload text (checkText), else fallback: a display name or a
// device name a producer copies from elsewhere never makes the event — and so the operation that writes it — fail.
func textOr(s, fallback string) string {
	if s = strings.TrimSpace(s); s != "" && checkText(s) == nil {
		return s
	}
	return fallback
}

// EnrollmentApproved — §7.4 "Phê duyệt enrollment" (TO/TA/TP gọi /approve … thông báo cho người yêu cầu): the member who
// made the request, and only them; they start it (POST …/start) before startBy — the approval expires 24 hours after
// it was given. One per request (a request is decided once).
func EnrollmentApproved(tenantID, requestID, requester uuid.UUID, method, deviceLabel, decidedBy string, startBy time.Time) Event {
	ev := Event{Kind: KindEnrollmentApproved, TenantID: tenantPtr(tenantID), Ref: "enrollment:" + requestID.String() + ":approved",
		Payload: map[string]any{"request_id": requestID, "method": method, "expires_at": startBy},
		To:      Audience{Members: []uuid.UUID{requester}}}
	enrollmentOptional(ev.Payload, deviceLabel, decidedBy)
	return ev
}

// EnrollmentRejected — the same decision, rejected: the requester only. One per request.
func EnrollmentRejected(tenantID, requestID, requester uuid.UUID, method, deviceLabel, decidedBy string) Event {
	ev := Event{Kind: KindEnrollmentRejected, TenantID: tenantPtr(tenantID), Ref: "enrollment:" + requestID.String() + ":rejected",
		Payload: map[string]any{"request_id": requestID, "method": method},
		To:      Audience{Members: []uuid.UUID{requester}}}
	enrollmentOptional(ev.Payload, deviceLabel, decidedBy)
	return ev
}

func enrollmentOptional(p map[string]any, deviceLabel, decidedBy string) {
	if s := textOr(deviceLabel, ""); s != "" {
		p["device_label"] = s
	}
	if s := textOr(decidedBy, ""); s != "" {
		p["decided_by"] = s
	}
}

// PlatformTenantDeletionRequested — platform notification of the same request: Super Admins and Platform Operators
// (the deletion itself is DELETE /platform/tenants/{id}, 2P). One per tenant and UTC day.
func PlatformTenantDeletionRequested(tenantID uuid.UUID, slug, requestedBy string, at time.Time) Event {
	ev := Event{Kind: KindPlatformTenantDeletionRequest, Ref: "tenant-deletion:" + tenantID.String() + ":" + at.UTC().Format("2006-01-02"),
		Payload: map[string]any{"tenant_id": tenantID, "tenant_slug": slug, "requested_at": at},
		To:      Audience{PlatformRoles: []string{RoleSuperAdmin, RolePlatformOperator}}}
	if requestedBy != "" {
		ev.Payload["requested_by"] = requestedBy
	}
	return ev
}
