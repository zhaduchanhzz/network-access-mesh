package platform

// Identity providers (P4-T03a; §8.2 "Quản trị IdP không được là cửa sau vào tenant", §8.5 platform.idp:read /
// :manage — "✔ (IdP của tenant: 2P)", the condition tenant_idp_dual_control of the Super Admin's grant):
//
//	GET   /platform/identity-providers[/{id}]   every registration, platform and tenant — never a secret
//	PATCH /platform/identity-providers/{id}     the claim constraints (tenants.IdPChange); issuer, client_id and driver
//	                                            are immutable (the handler refuses them — 422). A platform row changes at
//	                                            once (platform.idp.update); a TENANT row never does: UpdateIdP returns
//	                                            the payload of a platform approval request platform.idp.update_tenant
//	                                            (break-glass 2P, a second Super Admin decides), whose execution
//	                                            (tenants.ApplyPlatformIdPChange) writes the row in the tenant's
//	                                            transaction with the tenant's audit and a notification of its Owners.
//
// The client secret is not changed here: the platform IdP's through `meshguard admin set-idp-client-secret`, a
// tenant's by its Owner (PATCH /tenants/{t}/identity-provider).

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/audit"
	"github.com/zhaduchanhzz/network-access-mesh/internal/config"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
)

// ActionIdPUpdate is the audit action of a change of the platform's IdP.
const ActionIdPUpdate = "platform.idp.update"

// IdPFilter holds the query of GET /platform/identity-providers.
type IdPFilter struct {
	Scope  string // "", "platform", "tenant"
	Limit  int
	Cursor string
}

// IdPPage is one page of identity providers.
type IdPPage struct {
	Items      []tenants.IdPConfig
	NextCursor string
}

// ListIdPs is GET /platform/identity-providers (oldest first).
func (s *Service) ListIdPs(ctx context.Context, f IdPFilter) (IdPPage, error) {
	limit, err := pageLimit(f.Limit)
	if err != nil {
		return IdPPage{}, err
	}
	if f.Scope != "" && f.Scope != tenants.IdPScopePlatform && f.Scope != tenants.IdPScopeTenant {
		return IdPPage{}, invalid("scope", "invalid_scope")
	}
	after, afterID, err := decodePageCursor(f.Cursor)
	if err != nil {
		return IdPPage{}, err
	}
	p := IdPPage{Items: []tenants.IdPConfig{}}
	err = s.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		rows, err := q.ListIdentityProvidersPage(ctx, sqlcdb.ListIdentityProvidersPageParams{Scope: optionalString(f.Scope),
			AfterCreatedAt: after, AfterID: afterID, RowLimit: int32(limit + 1)}) //nolint:gosec // limit ≤ MaxLimit
		if err != nil {
			return err
		}
		if len(rows) > limit {
			rows = rows[:limit]
			last := rows[limit-1]
			p.NextCursor = encodePageCursor(last.CreatedAt, last.ID)
		}
		for _, r := range rows {
			p.Items = append(p.Items, tenants.IdPConfigOf(r))
		}
		return nil
	})
	return p, err
}

// GetIdP is GET /platform/identity-providers/{id}.
func (s *Service) GetIdP(ctx context.Context, id uuid.UUID) (tenants.IdPConfig, error) {
	var out tenants.IdPConfig
	err := s.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		r, err := q.GetIdentityProvider(ctx, id)
		if errors.Is(err, store.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		out = tenants.IdPConfigOf(r)
		return nil
	})
	return out, err
}

// IdPUpdateResult is the answer to PATCH /platform/identity-providers/{id}: the row as it is now (View — a platform
// row written, or nothing changed), or the payload of the 2P request a tenant row needs (Approval — nothing written).
type IdPUpdateResult struct {
	View     tenants.IdPConfig
	Approval *tenants.PlatformIdPChange
}

// UpdateIdP is PATCH /platform/identity-providers/{id}: step-up after the row is found (404 first), If-Match on its
// version, the change validated (422). No change ⇒ View, an audit event, no write. A platform row is written with
// platform.idp.update; a tenant row yields IdPUpdateResult.Approval — never written here (§8.2 (1)).
func (s *Service) UpdateIdP(ctx context.Context, a Actor, id uuid.UUID, c tenants.IdPChange, ifMatch string) (IdPUpdateResult, error) {
	if a.Condition != "" && a.Condition != CondTenantIdPDualControl {
		return IdPUpdateResult{}, refuse(ErrForbidden, ReasonConditionMismatch)
	}
	if c.Empty() {
		return IdPUpdateResult{}, invalid("body", ReasonEmpty)
	}
	var out IdPUpdateResult
	err := s.st.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		r, err := q.LockIdentityProvider(ctx, id)
		if errors.Is(err, store.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if err := stepUp(a, time.Now()); err != nil {
			return err
		}
		if err := ifMatchETag(ifMatch, tenants.IdPETag(r.Version)); err != nil {
			return err
		}
		next, changed, err := c.Resolve(r)
		if err != nil {
			var ae *tenants.AdminError
			if errors.As(err, &ae) {
				return invalid(ae.Field, ae.Reason)
			}
			return err
		}
		if len(changed) == 0 {
			out.View = tenants.IdPConfigOf(r)
			ev := audit.Event{Action: ActionIdPUpdate, ResourceType: "identity_provider", ResourceID: id.String(),
				Details: audit.Details{"changed": []string{}, "scope": r.Scope}}
			return audit.Record(ctx, q, ev)
		}
		if r.Scope == tenants.IdPScopeTenant {
			if r.TenantID == nil {
				return errors.New("platform: tenant identity provider without tenant")
			}
			out.Approval = &tenants.PlatformIdPChange{IdPID: r.ID, TenantID: *r.TenantID, Version: r.Version,
				RequiredClaims: next.RequiredClaims, AllowedEmailDomains: next.AllowedEmailDomains,
				ClaimMapping: next.ClaimMapping, Changed: changed}
			return nil // the handler makes the 2P request: the transaction writes nothing
		}
		nr, err := q.UpdateIdentityProviderClaims(ctx, sqlcdb.UpdateIdentityProviderClaimsParams{
			RequiredClaims: config.RequiredClaimsJSON(next.RequiredClaims), AllowedEmailDomains: next.AllowedEmailDomains,
			ClaimMapping: config.ClaimMappingJSON(next.ClaimMapping), ClientSecretRef: r.ClientSecretRef,
			Now: time.Now().UTC(), ID: r.ID, Version: r.Version})
		if errors.Is(err, store.ErrNoRows) {
			return refuse(ErrPreconditionFailed, "if_match_stale")
		}
		if err != nil {
			return err
		}
		out.View = tenants.IdPConfigOf(nr)
		return audit.Record(ctx, q, audit.Event{Action: ActionIdPUpdate, ResourceType: "identity_provider",
			ResourceID: id.String(), Details: audit.Details{"changed": changed, "scope": r.Scope, "version": nr.Version,
				"before_required_claims": string(r.RequiredClaims), "after_required_claims": string(nr.RequiredClaims),
				"before_allowed_email_domains": r.AllowedEmailDomains, "after_allowed_email_domains": nr.AllowedEmailDomains,
				"before_claim_mapping": string(r.ClaimMapping), "after_claim_mapping": string(nr.ClaimMapping)}})
	})
	return out, err
}
