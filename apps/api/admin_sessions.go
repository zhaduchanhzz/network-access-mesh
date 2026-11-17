package main

// `meshguard admin revoke-sessions` and `meshguard admin enable-identity` (G2 round 2, A-2): end every session of one
// person — offboarding, a locked or compromised account, a lost second factor — and, for offboarding, keep the
// identity out. The rules live in provisioning.IdentityAdmin; this file parses the flags and prints the result.
// Inputs are identifiers only (the IdP id of the environment file, the `sub` of the IdP user — never an e-mail). Exit
// status: 0 done (also when nothing was left to change), 1 refused or failed, 2 usage.

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning"
)

// identityTarget parses --idp and --subject.
func identityTarget(cmd string, args []string, aio adminIO, extra func(*flag.FlagSet)) (uuid.UUID, string, int) {
	fset := flag.NewFlagSet(cmd, flag.ContinueOnError)
	idp := fset.String("idp", "", "identity_providers.id (MG_IDP_ID_PLATFORM, MG_IDP_ID_<TENANT> of the environment file)")
	subject := fset.String("subject", "", "the sub of the user at that IdP (Keycloak: the user id)")
	if extra != nil {
		extra(fset)
	}
	if err := parseFlags(fset, args); err != nil {
		return uuid.Nil, "", usageError(aio, cmd, "invalid flags")
	}
	if fset.NArg() != 0 {
		return uuid.Nil, "", usageError(aio, cmd, "no positional argument expected")
	}
	id, err := uuid.Parse(*idp)
	if err != nil || id == uuid.Nil || id.String() != *idp {
		return uuid.Nil, "", usageError(aio, cmd, "--idp must be the canonical UUID of an identity provider")
	}
	if msg := identityFlags(*subject, ""); msg != "" {
		return uuid.Nil, "", usageError(aio, cmd, msg)
	}
	return id, *subject, -1
}

func runRevokeSessions(ctx context.Context, args []string, aio adminIO) int {
	const cmd = "revoke-sessions"
	var keep *bool
	idp, subject, rc := identityTarget(cmd, args, aio, func(f *flag.FlagSet) {
		keep = f.Bool("keep-enabled", false, "revoke the sessions but leave the identity active (credential reset)")
	})
	if rc >= 0 {
		return rc
	}
	d, err := openDeps(ctx, aio, false)
	if err != nil {
		return fail(aio, cmd, err)
	}
	defer d.close()
	ia := &provisioning.IdentityAdmin{Store: d.st, Audit: d.auditor(aio), Log: d.log, Now: aio.now}
	res, err := ia.RevokeSessions(ctx, provisioning.RevokeSessionsRequest{IdPID: idp, Subject: subject, KeepEnabled: *keep})
	if err != nil {
		if errors.Is(err, provisioning.ErrIdentityNotFound) {
			_, _ = fmt.Fprintf(aio.stderr, "meshguard admin %s: nothing was written\n", cmd)
		}
		return fail(aio, cmd, err)
	}
	p := func(format string, a ...any) { _, _ = fmt.Fprintf(aio.stdout, format+"\n", a...) }
	p("revoke-sessions: identity %s (%s%s), identity provider %s, subject %s", res.IdentityID, res.Scope,
		tenantSuffix(res.TenantID), idp, subject)
	p("  sessions revoked: %d", res.SessionsRevoked)
	if res.Status == res.StatusBefore {
		p("  status: %s (unchanged)", res.Status)
	} else {
		p("  status: %s → %s — new logins are refused (undo: meshguard admin enable-identity --idp %s --subject %s)",
			res.StatusBefore, res.Status, idp, subject)
	}
	p("  audit: %s.requested + .succeeded (actor_type system, operation %s)", provisioning.ActionRevokeIdentitySessions,
		res.OperationID)
	if *keep {
		p("  note: the identity stays active — it signs in again as soon as the IdP lets it")
	}
	_, _ = io.WriteString(aio.stdout, "OK\n")
	return 0
}

func runEnableIdentity(ctx context.Context, args []string, aio adminIO) int {
	const cmd = "enable-identity"
	idp, subject, rc := identityTarget(cmd, args, aio, nil)
	if rc >= 0 {
		return rc
	}
	d, err := openDeps(ctx, aio, false)
	if err != nil {
		return fail(aio, cmd, err)
	}
	defer d.close()
	ia := &provisioning.IdentityAdmin{Store: d.st, Audit: d.auditor(aio), Log: d.log, Now: aio.now}
	res, err := ia.EnableIdentity(ctx, idp, subject)
	if err != nil {
		return fail(aio, cmd, err)
	}
	state := "already active: nothing changed"
	if res.Changed {
		state = "disabled → active (audit " + provisioning.ActionEnableIdentity + ", actor_type system)"
	}
	_, _ = fmt.Fprintf(aio.stdout, "enable-identity: identity %s%s — %s\nOK\n", res.IdentityID, tenantSuffix(res.TenantID), state)
	return 0
}

func tenantSuffix(t *uuid.UUID) string {
	if t == nil {
		return ""
	}
	return ", tenant " + t.String()
}
