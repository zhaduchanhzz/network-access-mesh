package provisioning

// `meshguard admin revoke-sessions` and `meshguard admin enable-identity` (G2 round 2, A-2 — ASVS 7.4.2, 7.4.3, 7.4.5):
// end every BFF session of one person and keep them out, by (IdP, sub) — never by e-mail (§8.2). Locking a user at the
// IdP (Keycloak: enabled=false, logout of every SSO session) does not reach the BFF sessions, which live up to their
// absolute timeout (12 h / 8 h); this is the host-only way to end them until the automatic reconciliation of IdP
// events (Phase 6, §8.2) and the users API of P4-T09. Offboarding: infrastructure/host/RUNBOOK.md.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/store"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// Audit actions of the identity commands (actor_type = system). The event belongs to the identity's tenant (the
// tenant's audit lists it) or, for platform staff, to the platform.
const (
	ActionRevokeIdentitySessions = "identity.sessions.revoke" // paired: .requested → .succeeded / .failed
	ActionEnableIdentity         = "identity.enable"          // single event
)

// identities.status values (P2-T06, CHECK of 0002).
const (
	identityActive   = "active"
	identityDisabled = "disabled"
)

// ErrIdentityNotFound: no identity (IdP, sub) — the person never signed in and was never seeded, so no session of
// theirs can exist (nothing to revoke); nothing was written.
var ErrIdentityNotFound = errors.New("no such identity")

// IdentityAdmin runs the identity commands on the store of the api process: identities and sessions are written on the
// platform pool (mg_api_platform: UPDATE (status, updated_at) of identities and UPDATE of sessions — grants of 0002).
type IdentityAdmin struct {
	Store *store.Store
	Audit Auditor          // nil: LogAuditor{Log}
	Log   *slog.Logger     // nil discards
	Now   func() time.Time // nil: time.Now
}

func (a *IdentityAdmin) defaults() {
	if a.Log == nil {
		a.Log = slog.New(slog.DiscardHandler)
	}
	if a.Audit == nil {
		a.Audit = LogAuditor{Logger: a.Log}
	}
	if a.Now == nil {
		a.Now = time.Now
	}
}

// RevokeSessionsRequest names the person by (IdP, sub).
type RevokeSessionsRequest struct {
	IdPID   uuid.UUID
	Subject string
	// KeepEnabled revokes the sessions without locking the identity: the person signs in again once the IdP lets
	// them — after a password or OTP reset (lost device, A-7), a stolen session cookie. Default: lock (offboarding).
	KeepEnabled bool
}

// RevokeSessionsResult describes what revoke-sessions did.
type RevokeSessionsResult struct {
	IdentityID      uuid.UUID
	Scope           string
	TenantID        *uuid.UUID
	StatusBefore    string
	Status          string // after the command
	SessionsRevoked int64  // sessions that were not yet revoked
	OperationID     uuid.UUID
}

// RevokeSessions revokes every session of the identity (IdP, sub) and, unless KeepEnabled, sets it disabled — in one
// platform transaction holding the identity's row lock, so a login completing meanwhile either commits before (and
// its session is revoked here) or waits and then finds the identity disabled (callback: identity_disabled). The
// middleware refuses the session of a disabled identity at its next request as well (§8.3 step 8). Audited as a pair:
// "<action>.requested" before any change — a failure to record it aborts the command — then ".succeeded" or
// ".failed". Running it again is harmless (0 sessions, status unchanged).
func (a *IdentityAdmin) RevokeSessions(ctx context.Context, req RevokeSessionsRequest) (RevokeSessionsResult, error) {
	a.defaults()
	var res RevokeSessionsResult
	if req.IdPID == uuid.Nil || !ValidSubject(req.Subject) {
		return res, fmt.Errorf("%w: --idp must be an identity provider id and --subject its `sub` claim", ErrBootstrapRefused)
	}
	ident, err := a.identity(ctx, req.IdPID, req.Subject)
	if err != nil {
		return res, err
	}
	res = RevokeSessionsResult{IdentityID: ident.ID, Scope: ident.Scope, TenantID: ident.TenantID,
		StatusBefore: ident.Status, Status: ident.Status, OperationID: uuid.Must(uuid.NewV7())}
	ev := func(suffix, outcome string, details map[string]any) AuditEvent {
		d := map[string]any{"idp_id": req.IdPID, "identity_scope": ident.Scope, "keep_enabled": req.KeepEnabled}
		for k, v := range details {
			d[k] = v
		}
		op := res.OperationID
		return AuditEvent{Action: ActionRevokeIdentitySessions + suffix, OperationID: &op, Outcome: outcome,
			TenantID: ident.TenantID, ResourceType: "identity", ResourceID: ident.ID.String(), Details: d}
	}
	if err := a.Audit.Record(ctx, ev(SuffixRequested, OutcomeSuccess, nil)); err != nil {
		return res, fmt.Errorf("audit %s%s not recorded — nothing changed: %w", ActionRevokeIdentitySessions, SuffixRequested, err)
	}
	now := a.Now()
	err = a.Store.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		cur, err := q.GetIdentityBySubjectForUpdate(ctx, sqlcdb.GetIdentityBySubjectForUpdateParams{IdpID: req.IdPID,
			Subject: req.Subject})
		if err != nil {
			return err
		}
		res.StatusBefore, res.Status = cur.Status, cur.Status
		if !req.KeepEnabled && cur.Status != identityDisabled {
			if _, err := q.SetIdentityStatus(ctx, sqlcdb.SetIdentityStatusParams{Status: identityDisabled, Now: now,
				ID: cur.ID}); err != nil {
				return err
			}
			res.Status = identityDisabled
		}
		res.SessionsRevoked, err = q.RevokeIdentitySessions(ctx, sqlcdb.RevokeIdentitySessionsParams{Now: now,
			IdentityID: cur.ID})
		return err
	})
	if err != nil {
		if aerr := a.Audit.Record(context.WithoutCancel(ctx), ev(SuffixFailed, OutcomeFailure,
			map[string]any{"reason": "transaction_failed"})); aerr != nil {
			a.Log.Error("revoke-sessions: audit event not recorded", "error", aerr.Error())
		}
		return res, fmt.Errorf("revoke the sessions: %w", err)
	}
	if aerr := a.Audit.Record(ctx, ev(SuffixSucceeded, OutcomeSuccess, map[string]any{
		"sessions_revoked": res.SessionsRevoked, "status_before": res.StatusBefore, "status": res.Status})); aerr != nil {
		a.Log.Error("revoke-sessions: audit event not recorded", "error", aerr.Error())
	}
	a.Log.Info("revoke-sessions: sessions revoked", "identity_id", ident.ID.String(), "sessions", res.SessionsRevoked,
		"status", res.Status)
	return res, nil
}

// EnableIdentityResult describes what enable-identity did.
type EnableIdentityResult struct {
	IdentityID uuid.UUID
	TenantID   *uuid.UUID
	Changed    bool // false: the identity already was active — nothing written, nothing audited
}

// EnableIdentity sets a disabled identity (IdP, sub) active again — the undo of RevokeSessions without KeepEnabled (a
// mistaken offboarding, a person who returns). It does not touch memberships, roles or the IdP account: the person
// signs in only if the IdP lets them and their memberships are still active.
func (a *IdentityAdmin) EnableIdentity(ctx context.Context, idpID uuid.UUID, subject string) (EnableIdentityResult, error) {
	a.defaults()
	var res EnableIdentityResult
	if idpID == uuid.Nil || !ValidSubject(subject) {
		return res, fmt.Errorf("%w: --idp must be an identity provider id and --subject its `sub` claim", ErrBootstrapRefused)
	}
	ident, err := a.identity(ctx, idpID, subject)
	if err != nil {
		return res, err
	}
	res.IdentityID, res.TenantID = ident.ID, ident.TenantID
	err = a.Store.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		n, err := q.SetIdentityStatus(ctx, sqlcdb.SetIdentityStatusParams{Status: identityActive, Now: a.Now(), ID: ident.ID})
		res.Changed = n == 1
		return err
	})
	if err != nil {
		return res, fmt.Errorf("enable the identity: %w", err)
	}
	if res.Changed {
		if aerr := a.Audit.Record(ctx, AuditEvent{Action: ActionEnableIdentity, Outcome: OutcomeSuccess,
			TenantID: ident.TenantID, ResourceType: "identity", ResourceID: ident.ID.String(),
			Details: map[string]any{"idp_id": idpID, "identity_scope": ident.Scope, "status_before": ident.Status}}); aerr != nil {
			a.Log.Error("enable-identity: audit event not recorded", "error", aerr.Error())
		}
	}
	return res, nil
}

// identity reads the identity (IdP, sub).
func (a *IdentityAdmin) identity(ctx context.Context, idpID uuid.UUID, subject string) (sqlcdb.Identity, error) {
	var ident sqlcdb.Identity
	err := a.Store.WithPlatformTx(ctx, func(q *sqlcdb.Queries) error {
		var err error
		ident, err = q.GetIdentityBySubject(ctx, sqlcdb.GetIdentityBySubjectParams{IdpID: idpID, Subject: subject})
		return err
	})
	if errors.Is(err, store.ErrNoRows) {
		return ident, fmt.Errorf("%w: identity provider %s has no identity with subject %q (never signed in, never "+
			"seeded: no session to revoke)", ErrIdentityNotFound, idpID, clipInput(subject))
	}
	return ident, err
}
