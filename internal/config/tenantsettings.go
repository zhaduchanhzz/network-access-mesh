package config

// TenantSettings — the typed reading of tenants.settings (§4.2 "config: đọc tenants.settings có kiểu", schema
// TenantSettings of §13.3; P4-T03a). The stored document is a JSON object written by TenantCreate (step 16
// tenant.configure), PATCH /tenants/{t}/settings, PUT /tenants/{t}/settings/security and, for dns, PUT /dns/settings
// (P4-T12). Reading is lenient: a missing or ill-typed key reads as its default, so a document written before a key
// existed (or by a later task) never breaks a reader. Writing goes through SettingsDoc: only the named keys change,
// every other key — dns, keys added by later tasks — is kept as stored.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

// Identity modes of TenantSettings.enrollment.identity_mode (§7.4, ID-08).
const (
	IdentityModePortal        = "portal"
	IdentityModeHeadscaleOIDC = "headscale_oidc"
)

// IdentityModes lists the identity modes (enum TenantIdentityMode of api/openapi.yaml).
var IdentityModes = []string{IdentityModePortal, IdentityModeHeadscaleOIDC}

// Bounds of the settings (§13.3; P4-T03a).
const (
	MaxSensitiveGroups  = 100
	MaxNodeExpiryDays   = 3650 // like node_expiry_days of instance.reconfigure (P3-T13)
	MaxPreauthKeyTTLMin = 90 * 24 * 60
	MinPreauthKeyTTLMin = 5
	MaxSettingsBytes    = 8192 // the bound TenantCreate already applies to settings
)

// EnrollmentSettings is TenantSettings.enrollment.
type EnrollmentSettings struct {
	IdentityMode     string // IdentityModePortal unless set
	WebAuthEnabled   bool   // default true
	SelfEnroll       bool   // default false (the conditional cell of End User tenant.enrollment:request — §8.6)
	RequiresApproval bool   // default false
	PreauthKeyTTLMax string // "" = the platform's bound; else "<n>m" or "<n>h"
}

// PolicySettings is TenantSettings.policy.
type PolicySettings struct {
	FourEyes        bool        // policy review by a second person (§7.3)
	SensitiveGroups []uuid.UUID // groups whose members change only through a tenant approval (§7.3, §8.6), sorted
}

// RoutesSettings is TenantSettings.routes.
type RoutesSettings struct {
	FourEyes bool // route approvals through a tenant approval request (§13.2 routes)
}

// NotificationSettings is TenantSettings.notifications: false switches the role part of a kind off (notifications).
type NotificationSettings struct {
	NewDevice     bool // default true
	PolicyApplied bool // default true
}

// TenantSettings is the effective view of tenants.settings.
type TenantSettings struct {
	Enrollment EnrollmentSettings
	// NodeExpiry is "" when the tenant sets none (the instance's rendered node.expiry applies — devices clamp rule),
	// else "0" (never), "<n>d" or "<n>h" (devices.ParseNodeExpiry reads both).
	NodeExpiry    string
	Policy        PolicySettings
	Routes        RoutesSettings
	DNS           json.RawMessage // owned by PUT /dns/settings (P4-T12): shown as stored, "{}" when absent
	Notifications NotificationSettings
}

// SecuritySettings is the part of TenantSettings that only PUT /settings/security changes (tenant.settings:
// update_security — §8.6, §13.3): the identity/enrollment mode, 4-eyes, node_expiry and — P4-T03a — the sensitive groups
// (a key PATCH /settings could change would let tenant.settings:update holders lift the approval of a group's members).
type SecuritySettings struct {
	IdentityMode     string
	WebAuthEnabled   bool
	SelfEnroll       bool
	RequiresApproval bool
	NodeExpiry       string
	PolicyFourEyes   bool
	SensitiveGroups  []uuid.UUID
	RoutesFourEyes   bool
}

// Security returns the security part of s.
func (s TenantSettings) Security() SecuritySettings {
	return SecuritySettings{IdentityMode: s.Enrollment.IdentityMode, WebAuthEnabled: s.Enrollment.WebAuthEnabled,
		SelfEnroll: s.Enrollment.SelfEnroll, RequiresApproval: s.Enrollment.RequiresApproval, NodeExpiry: s.NodeExpiry,
		PolicyFourEyes: s.Policy.FourEyes, SensitiveGroups: slices.Clone(s.Policy.SensitiveGroups),
		RoutesFourEyes: s.Routes.FourEyes}
}

// Equal reports whether two security settings are the same (sensitive groups as sets — both are kept sorted).
func (a SecuritySettings) Equal(b SecuritySettings) bool {
	return a.IdentityMode == b.IdentityMode && a.WebAuthEnabled == b.WebAuthEnabled && a.SelfEnroll == b.SelfEnroll &&
		a.RequiresApproval == b.RequiresApproval && a.NodeExpiry == b.NodeExpiry && a.PolicyFourEyes == b.PolicyFourEyes &&
		a.RoutesFourEyes == b.RoutesFourEyes && slices.Equal(a.SensitiveGroups, b.SensitiveGroups)
}

// Weakenings lists what going from a to b lifts of a second-person control (§8.6: "tắt 4-eyes khi đang bật cần người
// thứ hai duyệt"; P4-T03a: a group taken out of the sensitive groups too — its members would then change without an
// approval): "policy.four_eyes", "routes.four_eyes", "policy.sensitive_groups". Empty ⇒ the change applies at once.
func Weakenings(a, b SecuritySettings) []string {
	var out []string
	if a.PolicyFourEyes && !b.PolicyFourEyes {
		out = append(out, "policy.four_eyes")
	}
	if a.RoutesFourEyes && !b.RoutesFourEyes {
		out = append(out, "routes.four_eyes")
	}
	for _, g := range a.SensitiveGroups {
		if !slices.Contains(b.SensitiveGroups, g) {
			out = append(out, "policy.sensitive_groups")
			break
		}
	}
	return out
}

// Changed lists the keys of the security settings that differ between a and b (dotted paths of TenantSettings).
func (a SecuritySettings) Changed(b SecuritySettings) []string {
	var out []string
	add := func(ok bool, k string) {
		if !ok {
			out = append(out, k)
		}
	}
	add(a.IdentityMode == b.IdentityMode, "enrollment.identity_mode")
	add(a.WebAuthEnabled == b.WebAuthEnabled, "enrollment.web_auth_enabled")
	add(a.SelfEnroll == b.SelfEnroll, "enrollment.self_enroll")
	add(a.RequiresApproval == b.RequiresApproval, "enrollment.requires_approval")
	add(a.NodeExpiry == b.NodeExpiry, "node_expiry")
	add(a.PolicyFourEyes == b.PolicyFourEyes, "policy.four_eyes")
	add(slices.Equal(a.SensitiveGroups, b.SensitiveGroups), "policy.sensitive_groups")
	add(a.RoutesFourEyes == b.RoutesFourEyes, "routes.four_eyes")
	return out
}

// SettingsDoc is a stored tenants.settings document: the typed view reads it, the setters change named keys and keep
// every other key.
type SettingsDoc struct{ m map[string]any }

// ErrSettingsDocument marks a stored document that is not a JSON object.
var ErrSettingsDocument = errors.New("config: tenants.settings is not a JSON object")

// ParseSettingsDoc reads a stored document; NULL, empty or "null" is the empty object.
func ParseSettingsDoc(raw []byte) (SettingsDoc, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || string(raw) == "null" {
		return SettingsDoc{m: map[string]any{}}, nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil || m == nil || dec.More() {
		return SettingsDoc{}, ErrSettingsDocument
	}
	return SettingsDoc{m: m}, nil
}

func (d SettingsDoc) obj(key string) map[string]any {
	o, _ := d.m[key].(map[string]any)
	return o
}

func boolOf(o map[string]any, key string, def bool) bool {
	if v, ok := o[key].(bool); ok {
		return v
	}
	return def
}

func stringOf(o map[string]any, key string) string {
	if v, ok := o[key].(string); ok {
		return v
	}
	return ""
}

// View is the effective TenantSettings of the document (defaults for missing or ill-typed keys; an invalid node_expiry
// or pre-auth TTL bound reads as unset, an invalid group id is dropped — readers never act on a malformed value).
func (d SettingsDoc) View() TenantSettings {
	e, p, r, n := d.obj("enrollment"), d.obj("policy"), d.obj("routes"), d.obj("notifications")
	s := TenantSettings{
		Enrollment: EnrollmentSettings{IdentityMode: IdentityModePortal, WebAuthEnabled: boolOf(e, "web_auth_enabled", true),
			SelfEnroll: boolOf(e, "self_enroll", false), RequiresApproval: boolOf(e, "requires_approval", false)},
		Policy:        PolicySettings{FourEyes: boolOf(p, "four_eyes", false), SensitiveGroups: []uuid.UUID{}},
		Routes:        RoutesSettings{FourEyes: boolOf(r, "four_eyes", false)},
		Notifications: NotificationSettings{NewDevice: boolOf(n, "new_device", true), PolicyApplied: boolOf(n, "policy_applied", true)},
		DNS:           json.RawMessage(`{}`),
	}
	if m := stringOf(e, "identity_mode"); slices.Contains(IdentityModes, m) {
		s.Enrollment.IdentityMode = m
	}
	if t := stringOf(e, "preauth_key_ttl_max"); CheckPreauthKeyTTLMax(t) == nil {
		s.Enrollment.PreauthKeyTTLMax = t
	}
	if v, ok := d.m["node_expiry"].(string); ok && CheckNodeExpiry(v) == nil {
		s.NodeExpiry = v
	}
	if gs, ok := p["sensitive_groups"].([]any); ok {
		for _, g := range gs {
			str, _ := g.(string)
			if id, err := uuid.Parse(str); err == nil && id.String() == str && !slices.Contains(s.Policy.SensitiveGroups, id) {
				s.Policy.SensitiveGroups = append(s.Policy.SensitiveGroups, id)
			}
		}
		sortUUIDs(s.Policy.SensitiveGroups)
	}
	if o := d.obj("dns"); o != nil {
		if b, err := json.Marshal(o); err == nil {
			s.DNS = b
		}
	}
	return s
}

func sortUUIDs(ids []uuid.UUID) {
	slices.SortFunc(ids, func(a, b uuid.UUID) int { return strings.Compare(a.String(), b.String()) })
}

// set writes value at the dotted path (one or two levels), creating the parent object (an ill-typed parent is
// replaced: the typed view already ignored it).
func (d *SettingsDoc) set(path string, value any) {
	parent, key, nested := strings.Cut(path, ".")
	if !nested {
		if value == nil {
			delete(d.m, parent)
			return
		}
		d.m[parent] = value
		return
	}
	o := d.obj(parent)
	if o == nil {
		o = map[string]any{}
		d.m[parent] = o
	}
	if value == nil {
		delete(o, key)
		return
	}
	o[key] = value
}

// SetSecurity writes the security settings s (PUT /settings/security, or the approved request of it).
func (d *SettingsDoc) SetSecurity(s SecuritySettings) {
	groups := make([]any, 0, len(s.SensitiveGroups))
	for _, g := range s.SensitiveGroups {
		groups = append(groups, g.String())
	}
	d.set("enrollment.identity_mode", s.IdentityMode)
	d.set("enrollment.web_auth_enabled", s.WebAuthEnabled)
	d.set("enrollment.self_enroll", s.SelfEnroll)
	d.set("enrollment.requires_approval", s.RequiresApproval)
	if s.NodeExpiry == "" {
		d.set("node_expiry", nil)
	} else {
		d.set("node_expiry", s.NodeExpiry)
	}
	d.set("policy.four_eyes", s.PolicyFourEyes)
	d.set("policy.sensitive_groups", groups)
	d.set("routes.four_eyes", s.RoutesFourEyes)
}

// SettingsPatch is PATCH /settings: the regular keys (tenant.settings:update — §8.6); nil = unchanged. PreauthKeyTTLMax
// "" removes the bound.
type SettingsPatch struct {
	PreauthKeyTTLMax *string
	NewDevice        *bool
	PolicyApplied    *bool
}

// Empty reports a patch that changes nothing.
func (p SettingsPatch) Empty() bool {
	return p.PreauthKeyTTLMax == nil && p.NewDevice == nil && p.PolicyApplied == nil
}

// Apply writes the patch.
func (d *SettingsDoc) Apply(p SettingsPatch) {
	if p.PreauthKeyTTLMax != nil {
		if *p.PreauthKeyTTLMax == "" {
			d.set("enrollment.preauth_key_ttl_max", nil)
		} else {
			d.set("enrollment.preauth_key_ttl_max", *p.PreauthKeyTTLMax)
		}
	}
	if p.NewDevice != nil {
		d.set("notifications.new_device", *p.NewDevice)
	}
	if p.PolicyApplied != nil {
		d.set("notifications.policy_applied", *p.PolicyApplied)
	}
}

// JSON encodes the document (no HTML escaping; at most MaxSettingsBytes).
func (d SettingsDoc) JSON() ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(d.m); err != nil {
		return nil, err
	}
	out := bytes.TrimSpace(buf.Bytes())
	if len(out) > MaxSettingsBytes {
		return nil, fmt.Errorf("config: tenants.settings would be %d bytes, at most %d", len(out), MaxSettingsBytes)
	}
	return out, nil
}

// SettingsETag is the entity tag of a tenant's settings: a quoted hex prefix of the SHA-256 of the stored document in
// a key-sorted encoding (encoding/json sorts map keys) — any change of the settings, and nothing else of the tenant
// row, changes it.
func SettingsETag(raw []byte) string {
	d, err := ParseSettingsDoc(raw)
	var b []byte
	if err == nil {
		b, err = d.JSON()
	}
	if err != nil {
		b = raw
	}
	sum := sha256.Sum256(append([]byte("tenant-settings/v1\n"), b...))
	return `"` + hex.EncodeToString(sum[:16]) + `"`
}

var (
	nodeExpiryRE = regexp.MustCompile(`^(0|[1-9][0-9]{0,3}d|[1-9][0-9]{0,5}h)$`)
	ttlRE        = regexp.MustCompile(`^[1-9][0-9]{0,6}(m|h)$`)
)

// CheckNodeExpiry validates TenantSettings.node_expiry: "0" (never), "<n>d" (1–3650 days) or "<n>h" (1 hour – 3650
// days) — the two forms devices.ParseNodeExpiry reads ("" = unset is checked by the caller).
func CheckNodeExpiry(s string) error {
	if !nodeExpiryRE.MatchString(s) {
		return errors.New(`node_expiry: "0", "<days>d" or "<hours>h"`)
	}
	if s == "0" {
		return nil
	}
	n, _ := strconv.Atoi(s[:len(s)-1])
	if (s[len(s)-1] == 'd' && n > MaxNodeExpiryDays) || (s[len(s)-1] == 'h' && n > MaxNodeExpiryDays*24) {
		return fmt.Errorf("node_expiry: at most %d days", MaxNodeExpiryDays)
	}
	return nil
}

// CheckPreauthKeyTTLMax validates TenantSettings.enrollment.preauth_key_ttl_max: "<n>m" or "<n>h", 5 minutes – 90 days.
func CheckPreauthKeyTTLMax(s string) error {
	if !ttlRE.MatchString(s) {
		return errors.New(`preauth_key_ttl_max: "<minutes>m" or "<hours>h"`)
	}
	n, _ := strconv.Atoi(s[:len(s)-1])
	if s[len(s)-1] == 'h' {
		n *= 60
	}
	if n < MinPreauthKeyTTLMin || n > MaxPreauthKeyTTLMin {
		return errors.New("preauth_key_ttl_max: between 5 minutes and 90 days")
	}
	return nil
}
