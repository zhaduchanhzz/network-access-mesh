package tenants

// The claim constraints of a tenant's identity provider (P4-T03a; §8.2 MVP: "PATCH /identity-provider chỉ sửa
// claim_mapping, required_claims, allowed_email_domains và client secret của hàng active"; issuer and client_id are
// immutable — changing the IdP is the migration of P7-T06).
//
//	GET   /tenants/{t}/identity-provider   the active row of the tenant (tenant.idp:read — TO, TA), never a secret
//	PATCH /tenants/{t}/identity-provider   tenant.idp:update (TO): step-up, If-Match; the client secret of an external
//	                                       IdP goes to the SecretStore (ClientSecrets) and only its reference is kept
//
// A change initiated by the platform on a tenant row (PATCH /platform/identity-providers/{id} — internal/platform) is a
// 2P request of two Super Admins; RecordPlatformIdPChangeRequested writes its request and ApplyPlatformIdPChange its
// execution into the TENANT's audit, with a notification of the Owners (§8.2 "ghi audit hiển thị cho tenant + thông báo
// Owner"). Every write here runs in the tenant's own transaction (0025 grants the tenant pool the claim columns of its
// own row).

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/config"
	"github.com/zhaduchanhzz/network-access-mesh/internal/notifications"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// Audit actions of the IdP configuration.
const (
	ActionIdPUpdate                 = "tenant.idp.update"
	ActionIdPPlatformChangeRequest  = "identity_provider.platform_change.request"
	ActionIdPPlatformChangeApplied  = "identity_provider.platform_change.apply"
	PlatformIdPChangeApprovalAction = "platform.idp.update_tenant"
)

// IdPConfig is schema IdentityProvider: the registration and its claim constraints — never a secret (ClientSecretSet
// says whether a client secret reference is recorded).
type IdPConfig struct {
	ID                   uuid.UUID
	Scope                string
	TenantID             *uuid.UUID
	Issuer               string
	ClientID             string
	Driver               string
	Status               string
	RequiredClaims       json.RawMessage
	RequireEmailVerified bool
	AllowedEmailDomains  []string
	ClaimMapping         map[string]string
	ClientSecretSet      bool
	CreatedAt            time.Time
	UpdatedAt            time.Time
	Version              int64
	ETag                 string
}

// IdPETag is the strong ETag of an identity provider row (its version).
func IdPETag(version int64) string { return strconv.Quote(strconv.FormatInt(version, 10)) }

// IdPConfigOf is the view of a row.
func IdPConfigOf(r sqlcdb.IdentityProvider) IdPConfig {
	rc := json.RawMessage(r.RequiredClaims)
	if len(rc) == 0 {
		rc = json.RawMessage(`{}`)
	}
	domains := slices.Clone(r.AllowedEmailDomains)
	if domains == nil {
		domains = []string{}
	}
	return IdPConfig{ID: r.ID, Scope: r.Scope, TenantID: r.TenantID, Issuer: r.Issuer, ClientID: r.ClientID,
		Driver: r.Driver, Status: r.Status, RequiredClaims: rc, RequireEmailVerified: r.RequireEmailVerified,
		AllowedEmailDomains: domains, ClaimMapping: config.ParseClaimMapping(r.ClaimMapping),
		ClientSecretSet: r.ClientSecretRef != nil && *r.ClientSecretRef != "", CreatedAt: r.CreatedAt.UTC(),
		UpdatedAt: r.UpdatedAt.UTC(), Version: r.Version, ETag: IdPETag(r.Version)}
}

// IdPChange is a change of the claim constraints; nil = unchanged.
type IdPChange struct {
	RequiredClaims      []byte
	AllowedEmailDomains *[]string
	ClaimMapping        *map[string]string
}

// Empty reports a change of nothing.
func (c IdPChange) Empty() bool {
	return c.RequiredClaims == nil && c.AllowedEmailDomains == nil && c.ClaimMapping == nil
}

// Resolve validates the change against the current row and returns the constraints after it and the fields that
// actually change (sorted).
func (c IdPChange) Resolve(cur sqlcdb.IdentityProvider) (config.IdPClaims, []string, error) {
	next := config.IdPClaims{AllowedEmailDomains: slices.Clone(cur.AllowedEmailDomains),
		ClaimMapping: config.ParseClaimMapping(cur.ClaimMapping)}
	if next.AllowedEmailDomains == nil {
		next.AllowedEmailDomains = []string{}
	}
	var err error
	if next.RequiredClaims, err = config.ParseRequiredClaims(cur.RequiredClaims); err != nil {
		next.RequiredClaims = map[string]any{} // a stored value the login could not use: replaced only if submitted
	}
	before := next
	var changed []string
	if c.RequiredClaims != nil {
		if next.RequiredClaims, err = config.ParseRequiredClaims(c.RequiredClaims); err != nil {
			return next, nil, claimsInvalid(err)
		}
		if string(config.RequiredClaimsJSON(next.RequiredClaims)) != string(config.RequiredClaimsJSON(before.RequiredClaims)) {
			changed = append(changed, "required_claims")
		}
	}
	if c.AllowedEmailDomains != nil {
		if next.AllowedEmailDomains, err = config.NormalizeEmailDomains(*c.AllowedEmailDomains); err != nil {
			return next, nil, claimsInvalid(err)
		}
		cur := slices.Clone(before.AllowedEmailDomains)
		slices.Sort(cur)
		if !slices.Equal(cur, next.AllowedEmailDomains) {
			changed = append(changed, "allowed_email_domains")
		}
	}
	if c.ClaimMapping != nil {
		if err := config.CheckClaimMapping(*c.ClaimMapping); err != nil {
			return next, nil, claimsInvalid(err)
		}
		next.ClaimMapping = *c.ClaimMapping
		if next.ClaimMapping == nil {
			next.ClaimMapping = map[string]string{}
		}
		if !config.EqualMapping(next.ClaimMapping, before.ClaimMapping) {
			changed = append(changed, "claim_mapping")
		}
	}
	slices.Sort(changed)
	return next, changed, nil
}

func claimsInvalid(err error) error {
	f, code := config.ClaimsErrorField(err)
	if f == "" {
		f, code = "body", "invalid"
	}
	return adminInvalid(f, code)
}

// ClientSecrets stores the client secret of a tenant's external IdP (internal/secrets through the api's SecretStore,
// wired in apps/*: tenants does not import secrets — §13.6). Store returns the reference of a new version under the
// IdP's own name (idp.AdminClientSecretName, owner = the tenant — the CHECK of 0007 and the login callback accept only
// that); Destroy erases a version.
type ClientSecrets interface {
	Store(ctx context.Context, tenantID, idpID uuid.UUID, secret []byte) (string, error)
	Destroy(ctx context.Context, ref string) error
}

// validClientSecret: 16–512 visible ASCII characters (the rule of `meshguard admin set-idp-client-secret`).
func validClientSecret(b []byte) bool {
	if len(b) < 16 || len(b) > 512 {
		return false
	}
	for _, c := range b {
		if c <= ' ' || c > '~' {
			return false
		}
	}
	return true
}

// GetActiveIdP is GET /tenants/{t}/identity-provider.
func (s *Service) GetActiveIdP(ctx context.Context, tenantID uuid.UUID) (IdPConfig, error) {
	var out IdPConfig
	err := s.st.WithTenantTx(ctx, tenantID, func(q *sqlcdb.Queries) error {
		r, err := q.GetTenantActiveIdP(ctx, &tenantID)
		if errors.Is(err, store.ErrNoRows) || (err == nil && (r.TenantID == nil || *r.TenantID != tenantID)) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		out = IdPConfigOf(r)
		return nil
	})
	return out, err
}

// UpdateIdP is PATCH /tenants/{t}/identity-provider (Tenant Owner): step-up, If-Match on the active row, the claim
// constraints and — external IdP only — a new client secret (stored first; its reference recorded in the same
// transaction as the claims, the audit event and the notification; erased again if that transaction fails; the
// replaced version is erased after commit).
func (s *Service) UpdateIdP(ctx context.Context, a Actor, tenantID uuid.UUID, c IdPChange, secret []byte, ifMatch string) (IdPConfig, error) {
	if c.Empty() && secret == nil {
		return IdPConfig{}, adminInvalid("body", "empty")
	}
	if secret != nil && !validClientSecret(secret) {
		return IdPConfig{}, adminInvalid("client_secret", "invalid_client_secret")
	}
	if err := s.stepUp(a); err != nil {
		return IdPConfig{}, err
	}
	cur, err := s.GetActiveIdP(ctx, tenantID)
	if err != nil {
		return IdPConfig{}, err
	}
	if err := checkIfMatch(ifMatch, cur.ETag); err != nil {
		return IdPConfig{}, err
	}
	var newRef string
	if secret != nil {
		switch {
		case cur.Driver != IdPDriverExternal:
			return IdPConfig{}, adminInvalid("client_secret", "client_secret_managed_by_platform")
		case s.secrets == nil:
			return IdPConfig{}, adminRefuse(ErrUnavailable, "secret_store_unavailable")
		}
		if newRef, err = s.secrets.Store(ctx, tenantID, cur.ID, secret); err != nil {
			return IdPConfig{}, err
		}
	}
	var (
		out     IdPConfig
		prevRef string
	)
	err = s.st.WithTenantJobTx(ctx, tenantID, func(tx *store.Tx) error {
		q := tx.Q
		r, err := q.LockTenantActiveIdP(ctx, &tenantID)
		if errors.Is(err, store.ErrNoRows) || (err == nil && r.ID != cur.ID) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if err := checkIfMatch(ifMatch, IdPETag(r.Version)); err != nil {
			return err
		}
		next, changed, err := c.Resolve(r)
		if err != nil {
			return err
		}
		ref := r.ClientSecretRef
		if newRef != "" {
			ref, prevRef = &newRef, deref(r.ClientSecretRef)
			changed = append(changed, "client_secret")
		}
		if len(changed) == 0 {
			out = IdPConfigOf(r)
			return audit.Record(ctx, q, audit.Event{Action: ActionIdPUpdate, TenantID: &tenantID,
				ResourceType: "identity_provider", ResourceID: r.ID.String(), Details: audit.Details{"changed": []string{}}})
		}
		nr, err := q.UpdateIdentityProviderClaims(ctx, sqlcdb.UpdateIdentityProviderClaimsParams{
			RequiredClaims: config.RequiredClaimsJSON(next.RequiredClaims), AllowedEmailDomains: next.AllowedEmailDomains,
			ClaimMapping: config.ClaimMappingJSON(next.ClaimMapping), ClientSecretRef: ref, Now: s.now().UTC(),
			ID: r.ID, Version: r.Version})
		if errors.Is(err, store.ErrNoRows) {
			return adminRefuse(ErrPreconditionFailed, "if_match_stale")
		}
		if err != nil {
			return err
		}
		out = IdPConfigOf(nr)
		if err := audit.Record(ctx, q, audit.Event{Action: ActionIdPUpdate, TenantID: &tenantID,
			ResourceType: "identity_provider", ResourceID: r.ID.String(), Details: idpDetails(r, nr, changed)}); err != nil {
			return err
		}
		_, err = notifications.Enqueue(ctx, tx, notifications.IdPConfigChanged(tenantID, r.ID, notifications.IdPStageApplied,
			notifications.IdPChangeByTenant, strings.Join(changed, ", "), a.Display, nil, nr.Version))
		return err
	})
	if err != nil {
		if newRef != "" {
			_ = s.secrets.Destroy(context.WithoutCancel(ctx), newRef)
		}
		return IdPConfig{}, err
	}
	if prevRef != "" && prevRef != newRef {
		_ = s.secrets.Destroy(context.WithoutCancel(ctx), prevRef) // best effort: the row no longer refers to it
	}
	return out, nil
}

// idpDetails are the audit details of a claim change: fields, before/after — never a secret or a secret reference
// (keys naming a secret are dropped by the audit anyway).
func idpDetails(before, after sqlcdb.IdentityProvider, changed []string) audit.Details {
	return audit.Details{"changed": changed, "version": after.Version,
		"before_required_claims": string(before.RequiredClaims), "after_required_claims": string(after.RequiredClaims),
		"before_allowed_email_domains": before.AllowedEmailDomains, "after_allowed_email_domains": after.AllowedEmailDomains,
		"before_claim_mapping": string(before.ClaimMapping), "after_claim_mapping": string(after.ClaimMapping)}
}

// PlatformIdPChange is the payload of an approval request platform.idp.update_tenant: a change of a tenant's IdP row
// initiated by platform staff (§8.2), at the row version the requester read.
type PlatformIdPChange struct {
	IdPID               uuid.UUID         `json:"idp_id"`
	TenantID            uuid.UUID         `json:"tenant_id"`
	Version             int64             `json:"version"`
	RequiredClaims      map[string]any    `json:"required_claims"`
	AllowedEmailDomains []string          `json:"allowed_email_domains"`
	ClaimMapping        map[string]string `json:"claim_mapping"`
	Changed             []string          `json:"changed"`
}

// Validate implements approvals.Validator.
func (p PlatformIdPChange) Validate() error {
	if p.IdPID == uuid.Nil || p.TenantID == uuid.Nil || p.Version < 1 || len(p.Changed) == 0 {
		return errors.New("platform idp change: idp, tenant, version and the changed fields are required")
	}
	b, err := json.Marshal(p.RequiredClaims)
	if err != nil {
		return err
	}
	if _, err := config.ParseRequiredClaims(b); err != nil {
		return err
	}
	if d, err := config.NormalizeEmailDomains(p.AllowedEmailDomains); err != nil || !slices.Equal(d, p.AllowedEmailDomains) {
		return errors.New("platform idp change: allowed_email_domains not normalized")
	}
	return config.CheckClaimMapping(p.ClaimMapping)
}

// RecordPlatformIdPChangeRequested writes, in the tenant's transaction, the audit event that a platform change of its
// IdP was requested (not in effect) and notifies the Tenant Owners — called once the approval request exists.
func (s *Service) RecordPlatformIdPChangeRequested(ctx context.Context, p PlatformIdPChange, approvalID, requestedBy uuid.UUID,
	requester string, expiresAt time.Time) error {
	return s.st.WithTenantJobTx(ctx, p.TenantID, func(tx *store.Tx) error {
		if err := audit.Record(ctx, tx.Q, audit.Event{Action: ActionIdPPlatformChangeRequest, TenantID: &p.TenantID,
			ResourceType: "identity_provider", ResourceID: p.IdPID.String(), Details: audit.Details{
				"approval_id": approvalID, "requested_by_identity_id": requestedBy, "changed": p.Changed,
				"version": p.Version, "expires_at": expiresAt, "in_effect": false}}); err != nil {
			return err
		}
		_, err := notifications.Enqueue(ctx, tx, notifications.IdPConfigChanged(p.TenantID, p.IdPID,
			notifications.IdPStageRequested, notifications.IdPChangeByPlatform, strings.Join(p.Changed, ", "), requester,
			&approvalID, p.Version))
		return err
	})
}

// ApplyPlatformIdPChange executes an approved platform.idp.update_tenant request in the tenant's own transaction: the
// row must still be at the approved version (else ErrStale, nothing written — unless this very approval already wrote
// it: a retry of an execution whose approval was not marked executed finds version+1 holding the approved values and
// succeeds without writing again); the claims, the tenant's audit event (requester and decider) and the notification
// of the Owners commit together.
func (s *Service) ApplyPlatformIdPChange(ctx context.Context, p PlatformIdPChange, e ApprovalExecution) error {
	if err := p.Validate(); err != nil {
		return err
	}
	return s.st.WithTenantJobTx(ctx, p.TenantID, func(tx *store.Tx) error {
		q := tx.Q
		tid := p.TenantID
		r, err := q.LockTenantIdP(ctx, sqlcdb.LockTenantIdPParams{TenantID: &tid, ID: p.IdPID})
		if errors.Is(err, store.ErrNoRows) {
			return ErrStale
		}
		if err != nil {
			return err
		}
		want := sqlcdb.IdentityProvider{RequiredClaims: config.RequiredClaimsJSON(p.RequiredClaims),
			AllowedEmailDomains: p.AllowedEmailDomains, ClaimMapping: config.ClaimMappingJSON(p.ClaimMapping)}
		if r.Version != p.Version {
			if r.Version == p.Version+1 && sameClaims(r, want) {
				return nil // written by an earlier attempt of this approval
			}
			return ErrStale
		}
		nr, err := q.UpdateIdentityProviderClaims(ctx, sqlcdb.UpdateIdentityProviderClaimsParams{
			RequiredClaims: want.RequiredClaims, AllowedEmailDomains: want.AllowedEmailDomains, ClaimMapping: want.ClaimMapping,
			ClientSecretRef: r.ClientSecretRef, Now: s.now().UTC(), ID: r.ID, Version: r.Version})
		if errors.Is(err, store.ErrNoRows) {
			return ErrStale
		}
		if err != nil {
			return err
		}
		d := idpDetails(r, nr, p.Changed)
		d["approval_id"], d["requested_by_identity_id"], d["decided_by_identity_id"] = e.ApprovalID, e.RequestedBy, e.DecidedBy
		d["in_effect"] = true
		if err := audit.Record(ctx, q, audit.Event{Action: ActionIdPPlatformChangeApplied, TenantID: &tid,
			ResourceType: "identity_provider", ResourceID: r.ID.String(), Details: d}); err != nil {
			return err
		}
		id := e.ApprovalID
		_, err = notifications.Enqueue(ctx, tx, notifications.IdPConfigChanged(tid, r.ID, notifications.IdPStageApplied,
			notifications.IdPChangeByPlatform, strings.Join(p.Changed, ", "), "", &id, nr.Version))
		return err
	})
}

func sameClaims(a, b sqlcdb.IdentityProvider) bool {
	ra, _ := config.ParseRequiredClaims(a.RequiredClaims)
	rb, _ := config.ParseRequiredClaims(b.RequiredClaims)
	da, db := slices.Clone(a.AllowedEmailDomains), slices.Clone(b.AllowedEmailDomains)
	slices.Sort(da)
	slices.Sort(db)
	return string(config.RequiredClaimsJSON(ra)) == string(config.RequiredClaimsJSON(rb)) && slices.Equal(da, db) &&
		config.EqualMapping(config.ParseClaimMapping(a.ClaimMapping), config.ParseClaimMapping(b.ClaimMapping))
}
