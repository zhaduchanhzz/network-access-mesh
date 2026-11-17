package main

// `meshguard admin bootstrap-super-admin` and `meshguard admin seed-membership` (P2-T11a, §8.2 "Khởi tạo ban đầu"):
// the first two Super Admins by (platform IdP, sub), and the Tenant Owner / Tenant Admin memberships of the test
// tenants A and B by (the tenant's IdP, sub) — without tenant_invitations. The rules live in
// provisioning.Bootstrapper; this file parses the flags and prints the result. Exit status: 0 done (created, or
// already in place — nothing changed), 1 refused or failed (nothing written by the step that refused), 2 usage.

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning"
)

func runBootstrapSuperAdmin(ctx context.Context, args []string, aio adminIO) int {
	const cmd = "bootstrap-super-admin"
	fset := flag.NewFlagSet(cmd, flag.ContinueOnError)
	subject := fset.String("subject", "", "the sub of the user in the platform realm (Keycloak: the user id)")
	name := fset.String("display-name", "", "display name until the first login")
	if err := parseFlags(fset, args); err != nil {
		return usageError(aio, cmd, "invalid flags")
	}
	if fset.NArg() != 0 {
		return usageError(aio, cmd, "no positional argument expected")
	}
	if msg := identityFlags(*subject, *name); msg != "" {
		return usageError(aio, cmd, msg)
	}
	idp, err := idpID(aio, "MG_IDP_ID_PLATFORM")
	if err != nil {
		return fail(aio, cmd, err)
	}
	d, err := openDeps(ctx, aio, false)
	if err != nil {
		return fail(aio, cmd, err)
	}
	defer d.st.Close()
	b := &provisioning.Bootstrapper{Store: d.st, Log: d.log}
	res, err := b.BootstrapSuperAdmin(ctx, provisioning.SuperAdminRequest{PlatformIdP: idp, Subject: *subject,
		DisplayName: *name})
	if err != nil {
		if errors.Is(err, provisioning.ErrBootstrapClosed) {
			_, _ = fmt.Fprintf(aio.stderr, "meshguard admin %s: the bootstrap path is closed — nothing was written\n", cmd)
		}
		return fail(aio, cmd, err)
	}
	p := func(format string, a ...any) { _, _ = fmt.Fprintf(aio.stdout, format+"\n", a...) }
	p("bootstrap-super-admin: platform identity provider %s (issuer %s)", res.IdPID, res.Issuer)
	p("  identity: %s (subject %s) — %s", res.IdentityID, *subject, createdOr(res.IdentityCreated, "existing"))
	if res.Created {
		p("  platform user: %s — super_admin, active — created", res.PlatformUserID)
		p("  audit: %s (actor_type system, request %s)", provisioning.ActionBootstrapSuperAdmin, res.RequestID)
	} else {
		p("  platform user: %s — already an active Super Admin: nothing changed", res.PlatformUserID)
	}
	p("  active Super Admins: %d (this command refuses from %d on)", res.ActiveSupers, provisioning.SuperAdminThreshold)
	if res.ActiveSupers < provisioning.SuperAdminThreshold {
		p("  WARNING: fewer than %d active Super Admins — dual-control (2P) operations cannot be approved until the "+
			"next one is bootstrapped", provisioning.SuperAdminThreshold)
	}
	_, _ = io.WriteString(aio.stdout, "OK\n")
	return 0
}

func runSeedMembership(ctx context.Context, args []string, aio adminIO) int {
	const cmd = "seed-membership"
	fset := flag.NewFlagSet(cmd, flag.ContinueOnError)
	tenant := fset.String("tenant", "", "slug or id of the tenant")
	role := fset.String("role", "", "tenant_owner or tenant_admin")
	subject := fset.String("subject", "", "the sub of the user in the tenant's realm (Keycloak: the user id)")
	name := fset.String("display-name", "", "display name until the first login")
	if err := parseFlags(fset, args); err != nil {
		return usageError(aio, cmd, "invalid flags")
	}
	switch {
	case fset.NArg() != 0:
		return usageError(aio, cmd, "no positional argument expected")
	case *tenant == "":
		return usageError(aio, cmd, "--tenant is required")
	case *role != provisioning.RoleTenantOwner && *role != provisioning.RoleTenantAdmin:
		return usageError(aio, cmd, "--role must be tenant_owner or tenant_admin (platform roles: bootstrap-super-admin, "+
			"then the API)")
	}
	if msg := identityFlags(*subject, *name); msg != "" {
		return usageError(aio, cmd, msg)
	}
	d, err := openDeps(ctx, aio, false)
	if err != nil {
		return fail(aio, cmd, err)
	}
	defer d.st.Close()
	b := &provisioning.Bootstrapper{Store: d.st, Log: d.log}
	res, err := b.SeedMembership(ctx, provisioning.MembershipRequest{Tenant: *tenant, Role: *role, Subject: *subject,
		DisplayName: *name})
	p := func(format string, a ...any) { _, _ = fmt.Fprintf(aio.stdout, format+"\n", a...) }
	if err != nil {
		if res.IdentityCreated { // the first step committed: say so (a re-run completes the seed)
			p("seed-membership: identity %s of tenant %s created (audit %s, request %s); the membership was NOT "+
				"created", res.IdentityID, res.Slug, provisioning.ActionSeedIdentity, res.RequestID)
		}
		return fail(aio, cmd, err)
	}
	p("seed-membership: tenant %s (%s), identity provider %s (issuer %s)", res.Slug, res.TenantID, res.IdPID, res.Issuer)
	p("  identity: %s (subject %s) — %s", res.IdentityID, *subject, createdOr(res.IdentityCreated, "existing"))
	if res.Created {
		p("  membership: %s — %s, active — created", res.MembershipID, res.Role)
	} else {
		p("  membership: %s — already %s, active: nothing changed", res.MembershipID, res.Role)
	}
	switch {
	case res.Created && res.IdentityCreated:
		p("  audit: %s + %s (actor_type system, request %s)", provisioning.ActionSeedIdentity,
			provisioning.ActionSeedMembership, res.RequestID)
	case res.Created:
		p("  audit: %s (actor_type system, request %s)", provisioning.ActionSeedMembership, res.RequestID)
	case res.IdentityCreated:
		p("  audit: %s (actor_type system, request %s)", provisioning.ActionSeedIdentity, res.RequestID)
	}
	_, _ = io.WriteString(aio.stdout, "OK\n")
	return 0
}

// identityFlags checks --subject and --display-name before anything is opened ("" = valid).
func identityFlags(subject, name string) string {
	switch {
	case subject == "":
		return "--subject is required (the sub of the IdP user — never an e-mail address)"
	case !provisioning.ValidSubject(subject):
		return fmt.Sprintf("--subject must be 1–%d visible ASCII characters", provisioning.MaxSubjectLen)
	case !provisioning.ValidDisplayName(name):
		return fmt.Sprintf("--display-name must be 1–%d printable characters", provisioning.MaxDisplayName)
	}
	return ""
}

func createdOr(created bool, other string) string {
	if created {
		return "created"
	}
	return other
}
