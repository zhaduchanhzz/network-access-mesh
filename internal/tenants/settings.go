package tenants

// Tenant settings (P4-T03a; §8.6 tenant.settings:read / :update / :update_security, §13.3 TenantSettings):
//
//	GET   /settings           the effective TenantSettings and their ETag (config.SettingsETag of the stored document)
//	PATCH /settings           the regular keys (pre-auth key TTL bound, notifications) — If-Match
//	PUT   /settings/security  every security key — Tenant Owner, step-up, If-Match. A change that lifts a second-person
//	                          control (policy.four_eyes or routes.four_eyes turned off, a group taken out of
//	                          policy.sensitive_groups) is not written: the caller gets the payload of a tenant approval
//	                          request (action tenant.settings.update_security), and ExecuteSecuritySettings writes it
//	                          once another Owner or Admin approved it — only if the settings still have the ETag the
//	                          request was made on.
//
// Every write locks the tenant row and runs in the tenant's own job-capable transaction (migration 0025 grants the
// tenant pool UPDATE (settings…) on its own row): the change, its audit event and — security settings — the
// notification of the Owners and Admins commit together.

import (
	"context"
	"errors"
	"slices"
	"strings"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/config"
	"github.com/zhaduchanhzz/network-access-mesh/internal/notifications"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// Audit actions and the approval action of the settings.
const (
	ActionSettingsUpdate         = "tenant.settings.update"
	ActionSecuritySettingsUpdate = "tenant.settings.security_update"
	// SecuritySettingsApprovalAction is approval_requests.action of a security settings change that lifts a
	// second-person control (§8.6 "tắt 4-eyes"); the deciding permission is tenant.approval:decide itself — "một
	// Owner hoặc Admin khác".
	SecuritySettingsApprovalAction = "tenant.settings.update_security"
)

// SettingsView is schema TenantSettingsView.
type SettingsView struct {
	Settings config.TenantSettings
	ETag     string
}

func settingsView(raw []byte) (SettingsView, error) {
	d, err := config.ParseSettingsDoc(raw)
	if err != nil {
		return SettingsView{}, err
	}
	return SettingsView{Settings: d.View(), ETag: config.SettingsETag(raw)}, nil
}

// GetSettings is GET /tenants/{t}/settings.
func (s *Service) GetSettings(ctx context.Context, tenantID uuid.UUID) (SettingsView, error) {
	var out SettingsView
	err := s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		r, err := q.GetTenantSettingsRow(ctx, tenantID)
		if errors.Is(err, store.ErrNoRows) || (err == nil && r.ID != tenantID) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		out, err = settingsView(r.Settings)
		return err
	})
	return out, err
}

// lockSettings locks the tenant row and checks If-Match against the settings ETag.
func lockSettings(ctx context.Context, q *sqlcdb.Queries, tenantID uuid.UUID, ifMatch string) (sqlcdb.LockTenantSettingsRow, config.SettingsDoc, error) {
	r, err := q.LockTenantSettings(ctx, tenantID)
	if errors.Is(err, store.ErrNoRows) || (err == nil && r.ID != tenantID) {
		return r, config.SettingsDoc{}, ErrNotFound
	}
	if err != nil {
		return r, config.SettingsDoc{}, err
	}
	if err := checkIfMatch(ifMatch, config.SettingsETag(r.Settings)); err != nil {
		return r, config.SettingsDoc{}, err
	}
	d, err := config.ParseSettingsDoc(r.Settings)
	return r, d, err
}

// PatchSettings is PATCH /tenants/{t}/settings: the regular keys only (the handler refuses the security and dns keys).
func (s *Service) PatchSettings(ctx context.Context, tenantID uuid.UUID, p config.SettingsPatch, ifMatch string) (SettingsView, error) {
	if p.Empty() {
		return SettingsView{}, adminInvalid("body", "empty")
	}
	if p.PreauthKeyTTLMax != nil && *p.PreauthKeyTTLMax != "" && config.CheckPreauthKeyTTLMax(*p.PreauthKeyTTLMax) != nil {
		return SettingsView{}, adminInvalid("enrollment.preauth_key_ttl_max", "invalid_duration")
	}
	var out SettingsView
	err := s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		_, d, err := lockSettings(ctx, q, tenantID, ifMatch)
		if err != nil {
			return err
		}
		before := d.View()
		d.Apply(p)
		raw, err := d.JSON()
		if err != nil {
			return adminInvalid("body", "too_large")
		}
		after := d.View()
		var changed []string
		if before.Enrollment.PreauthKeyTTLMax != after.Enrollment.PreauthKeyTTLMax {
			changed = append(changed, "enrollment.preauth_key_ttl_max")
		}
		if before.Notifications.NewDevice != after.Notifications.NewDevice {
			changed = append(changed, "notifications.new_device")
		}
		if before.Notifications.PolicyApplied != after.Notifications.PolicyApplied {
			changed = append(changed, "notifications.policy_applied")
		}
		if len(changed) > 0 {
			nr, err := q.UpdateTenantSettingsDoc(ctx, sqlcdb.UpdateTenantSettingsDocParams{Settings: raw, Now: s.now().UTC(), ID: tenantID})
			if err != nil {
				return err
			}
			raw = nr.Settings
		} else {
			changed = []string{}
		}
		if out, err = settingsView(raw); err != nil {
			return err
		}
		return audit.Record(ctx, q, audit.Event{Action: ActionSettingsUpdate, TenantID: &tenantID, ResourceType: "settings",
			ResourceID: tenantID.String(), Details: audit.Details{"changed": changed,
				"before_preauth_key_ttl_max": before.Enrollment.PreauthKeyTTLMax, "after_preauth_key_ttl_max": after.Enrollment.PreauthKeyTTLMax,
				"before_new_device": before.Notifications.NewDevice, "after_new_device": after.Notifications.NewDevice,
				"before_policy_applied": before.Notifications.PolicyApplied, "after_policy_applied": after.Notifications.PolicyApplied}})
	})
	return out, err
}

// SecuritySettingsPayload is the payload of an approval request tenant.settings.update_security: the ETag of the
// settings the request was made on and the security settings to write — what the second person approves, and the only
// input of the execution.
type SecuritySettingsPayload struct {
	IfMatch          string      `json:"if_match"`
	IdentityMode     string      `json:"identity_mode"`
	WebAuthEnabled   bool        `json:"web_auth_enabled"`
	SelfEnroll       bool        `json:"self_enroll"`
	RequiresApproval bool        `json:"requires_approval"`
	NodeExpiry       string      `json:"node_expiry"` // "" = unset
	PolicyFourEyes   bool        `json:"policy_four_eyes"`
	SensitiveGroups  []uuid.UUID `json:"sensitive_groups"`
	RoutesFourEyes   bool        `json:"routes_four_eyes"`
	Weakens          []string    `json:"weakens"` // the controls the change lifts (shown to the approver)
}

// Settings returns the security settings of the payload.
func (p SecuritySettingsPayload) Settings() config.SecuritySettings {
	return config.SecuritySettings{IdentityMode: p.IdentityMode, WebAuthEnabled: p.WebAuthEnabled, SelfEnroll: p.SelfEnroll,
		RequiresApproval: p.RequiresApproval, NodeExpiry: p.NodeExpiry, PolicyFourEyes: p.PolicyFourEyes,
		SensitiveGroups: slices.Clone(p.SensitiveGroups), RoutesFourEyes: p.RoutesFourEyes}
}

// Validate implements approvals.Validator (shape only — the tenant's state is checked again at execution).
func (p SecuritySettingsPayload) Validate() error {
	if p.IfMatch == "" || len(p.IfMatch) > 64 || len(p.Weakens) == 0 {
		return errors.New("security settings payload: if_match and the lifted controls are required")
	}
	return checkSecurityShape(p.Settings())
}

func checkSecurityShape(st config.SecuritySettings) error {
	switch {
	case !slices.Contains(config.IdentityModes, st.IdentityMode):
		return adminInvalid("enrollment.identity_mode", "invalid_identity_mode")
	case st.NodeExpiry != "" && config.CheckNodeExpiry(st.NodeExpiry) != nil:
		return adminInvalid("node_expiry", "invalid_node_expiry")
	case len(st.SensitiveGroups) > config.MaxSensitiveGroups:
		return adminInvalid("policy.sensitive_groups", "too_many")
	}
	for i, g := range st.SensitiveGroups {
		if g == uuid.Nil || slices.Contains(st.SensitiveGroups[:i], g) {
			return adminInvalid("policy.sensitive_groups", "invalid_group")
		}
	}
	return nil
}

// SecurityResult is the answer to PUT /settings/security: the settings as written (View), or — for a change that lifts
// a second-person control — the payload of the approval request the caller must make (Approval set, nothing written).
type SecurityResult struct {
	View     SettingsView
	Approval *SecuritySettingsPayload
}

// normalizeSecurity sorts the sensitive groups (the stored form) of a submitted value.
func normalizeSecurity(st config.SecuritySettings) config.SecuritySettings {
	st.SensitiveGroups = slices.Clone(st.SensitiveGroups)
	slices.SortFunc(st.SensitiveGroups, func(a, b uuid.UUID) int { return strings.Compare(a.String(), b.String()) })
	if st.SensitiveGroups == nil {
		st.SensitiveGroups = []uuid.UUID{}
	}
	return st
}

// checkSecurityState checks a security change against the tenant's state in tx q: headscale_oidc (method C) is not
// available in this build; identity_mode is immutable once the tenant has its first Headscale user or device (ID-08);
// every sensitive group is a group of the tenant.
func checkSecurityState(ctx context.Context, q *sqlcdb.Queries, tenantID uuid.UUID, before, after config.SecuritySettings) error {
	if after.IdentityMode != before.IdentityMode {
		if after.IdentityMode == config.IdentityModeHeadscaleOIDC {
			return adminInvalid("enrollment.identity_mode", "identity_mode_unavailable")
		}
		has, err := q.TenantHasHeadscaleUsers(ctx, tenantID)
		if err != nil {
			return err
		}
		if has != nil && *has {
			return adminRefuse(ErrConflict, "identity_mode_immutable")
		}
	}
	if len(after.SensitiveGroups) > 0 {
		ids, err := q.ListTenantGroupIDs(ctx, sqlcdb.ListTenantGroupIDsParams{TenantID: tenantID, Ids: after.SensitiveGroups})
		if err != nil {
			return err
		}
		if len(ids) != len(after.SensitiveGroups) {
			return adminInvalid("policy.sensitive_groups", "unknown_group")
		}
	}
	return nil
}

// PutSecuritySettings is PUT /tenants/{t}/settings/security (Tenant Owner): step-up, If-Match, the checks of
// checkSecurityState; nothing changed ⇒ the current settings (an audit event, no write); a change that lifts a
// second-person control ⇒ SecurityResult.Approval (nothing written — the handler makes the approval request); else
// the settings are written with their audit event and the notification of the Owners and Admins.
func (s *Service) PutSecuritySettings(ctx context.Context, a Actor, tenantID uuid.UUID, want config.SecuritySettings, ifMatch string) (SecurityResult, error) {
	want = normalizeSecurity(want)
	if err := checkSecurityShape(want); err != nil {
		return SecurityResult{}, err
	}
	if err := s.stepUp(a); err != nil {
		return SecurityResult{}, err
	}
	var out SecurityResult
	err := s.st.WithTenantJobTx(ctx, tenantID, func(tx *store.Tx) error {
		q := tx.Q
		r, d, err := lockSettings(ctx, q, tenantID, ifMatch)
		if err != nil {
			return err
		}
		before := d.View().Security()
		if err := checkSecurityState(ctx, q, tenantID, before, want); err != nil {
			return err
		}
		if before.Equal(want) {
			if out.View, err = settingsView(r.Settings); err != nil {
				return err
			}
			return audit.Record(ctx, q, audit.Event{Action: ActionSecuritySettingsUpdate, TenantID: &tenantID,
				ResourceType: "settings", ResourceID: tenantID.String(), Details: audit.Details{"changed": []string{}}})
		}
		if w := config.Weakenings(before, want); len(w) > 0 {
			out.Approval = &SecuritySettingsPayload{IfMatch: config.SettingsETag(r.Settings), IdentityMode: want.IdentityMode,
				WebAuthEnabled: want.WebAuthEnabled, SelfEnroll: want.SelfEnroll, RequiresApproval: want.RequiresApproval,
				NodeExpiry: want.NodeExpiry, PolicyFourEyes: want.PolicyFourEyes, SensitiveGroups: want.SensitiveGroups,
				RoutesFourEyes: want.RoutesFourEyes, Weakens: w}
			return nil
		}
		out.View, err = s.writeSecurity(ctx, tx, tenantID, d, before, want, securityOrigin{actor: a})
		return err
	})
	return out, err
}

// securityOrigin is who wrote the security settings: the caller (direct) or the approval (requester and decider).
type securityOrigin struct {
	actor       Actor
	approvalID  *uuid.UUID
	requestedBy uuid.UUID
	decidedBy   uuid.UUID
}

func (s *Service) writeSecurity(ctx context.Context, tx *store.Tx, tenantID uuid.UUID, d config.SettingsDoc,
	before, after config.SecuritySettings, o securityOrigin) (SettingsView, error) {
	q := tx.Q
	d.SetSecurity(after)
	raw, err := d.JSON()
	if err != nil {
		return SettingsView{}, adminInvalid("body", "too_large")
	}
	nr, err := q.UpdateTenantSettingsDoc(ctx, sqlcdb.UpdateTenantSettingsDocParams{Settings: raw, Now: s.now().UTC(), ID: tenantID})
	if err != nil {
		return SettingsView{}, err
	}
	view, err := settingsView(nr.Settings)
	if err != nil {
		return SettingsView{}, err
	}
	changed := before.Changed(after)
	details := audit.Details{"changed": changed,
		"before_policy_four_eyes": before.PolicyFourEyes, "after_policy_four_eyes": after.PolicyFourEyes,
		"before_routes_four_eyes": before.RoutesFourEyes, "after_routes_four_eyes": after.RoutesFourEyes,
		"before_sensitive_groups": before.SensitiveGroups, "after_sensitive_groups": after.SensitiveGroups,
		"before_identity_mode": before.IdentityMode, "after_identity_mode": after.IdentityMode,
		"before_web_auth_enabled": before.WebAuthEnabled, "after_web_auth_enabled": after.WebAuthEnabled,
		"before_self_enroll": before.SelfEnroll, "after_self_enroll": after.SelfEnroll,
		"before_requires_approval": before.RequiresApproval, "after_requires_approval": after.RequiresApproval,
		"before_node_expiry": before.NodeExpiry, "after_node_expiry": after.NodeExpiry}
	actor := o.actor.Display
	if o.approvalID != nil {
		details["approval_id"] = *o.approvalID
		details["requested_by_identity_id"] = o.requestedBy
		details["decided_by_identity_id"] = o.decidedBy
	}
	if err := audit.Record(ctx, q, audit.Event{Action: ActionSecuritySettingsUpdate, TenantID: &tenantID,
		ResourceType: "settings", ResourceID: tenantID.String(), Details: details}); err != nil {
		return SettingsView{}, err
	}
	if _, err := notifications.Enqueue(ctx, tx, notifications.SecuritySettingsChanged(tenantID, view.ETag,
		strings.Join(changed, ", "), actor, o.approvalID)); err != nil {
		return SettingsView{}, err
	}
	return view, nil
}

// ApprovalExecution names an executed approval request: its id, who asked and who decided.
type ApprovalExecution struct {
	ApprovalID  uuid.UUID
	RequestedBy uuid.UUID
	DecidedBy   uuid.UUID
}

// ExecuteSecuritySettings runs an approved tenant.settings.update_security request in the approval's tenant
// transaction tx: the settings must still have the ETag of the request (else ErrStale — nothing written), the state
// checks run again, and the settings are written with the audit event (both persons) and the notification.
func (s *Service) ExecuteSecuritySettings(ctx context.Context, tx *store.Tx, tenantID uuid.UUID, e ApprovalExecution, p SecuritySettingsPayload) error {
	if err := p.Validate(); err != nil {
		return err
	}
	r, err := tx.Q.LockTenantSettings(ctx, tenantID)
	if errors.Is(err, store.ErrNoRows) {
		return ErrStale
	}
	if err != nil {
		return err
	}
	if config.SettingsETag(r.Settings) != p.IfMatch {
		return ErrStale
	}
	d, err := config.ParseSettingsDoc(r.Settings)
	if err != nil {
		return err
	}
	before, want := d.View().Security(), normalizeSecurity(p.Settings())
	if err := checkSecurityState(ctx, tx.Q, tenantID, before, want); err != nil {
		return err
	}
	id := e.ApprovalID
	_, err = s.writeSecurity(ctx, tx, tenantID, d, before, want, securityOrigin{approvalID: &id, requestedBy: e.RequestedBy,
		decidedBy: e.DecidedBy})
	return err
}
