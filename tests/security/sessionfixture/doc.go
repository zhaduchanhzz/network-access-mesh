//go:build mgtestfixture

// Package sessionfixture is the test-session fixture of P2-T15a (§20, §22.1 "Security"): it gives the security tests
// — the authorization matrix and the isolation suite of P2-T15 first — a signed-in client for each of the nine roles
// of §8.4, without a browser and without an IdP.
//
// New migrates a fresh database like a deployment (internal/store/storetest: goose, RBAC seed, River — and the only
// sanctioned way for a test to lock the cluster and derive role passwords), then creates two active tenants A and B,
// each with its own active IdP, the active platform IdP, and one actor per role: the five tenant roles in A and in B
// (an identity of the tenant's IdP + an active tenant_memberships row) and the four platform roles (an identity of the
// platform IdP + an active platform_users row). It composes the public API as the api process does — httpapi.New
// with the auth handlers of identityapi and the hooks of authzhook (session layer of identity, decisions of authz) —
// on the api role pools (mg_api_tenant / mg_api_platform).
//
// Login mints a session the way the identity module stores one at the end of an OIDC callback: 32 random bytes,
// only their SHA-256 in sessions.id_hash — written with the module's own InsertSession query through the api
// platform pool —, the idle and absolute expiry of the identity's scope, on the origin of that scope (tenant
// identities on app, platform staff on admin, §8.3). The identity module then authenticates the cookie
// (identity.Service.Authenticate): a session the module would refuse fails the test at once, and the CSRF token comes
// from the module itself. A Session holds what a client sends — cookie name and value, CSRF token, Host and Origin —
// and never prints its secrets.
//
// Support Access Grants (§8.7) are not minted yet: their table arrives with migration 0015 (P4-T13); until then a
// platform actor on a tenant route is refused (403), which is AC-05a.
//
// Build tag: every Go file of this package — and of every package that imports it — starts with
// //go:build mgtestfixture. Without the tag the package has no Go file at all, so no production build can import it;
// internal/archtest checks the constraints and that `go list -deps` of apps/api and apps/worker, with and without
// the tag, never contains it. Run the tagged tests with
//
//	go test -race -count=1 -tags mgtestfixture ./tests/...
//
// (MG_TEST_PG_ADMIN_URL as for every PostgreSQL test). A consumer's TestMain calls storetest.Cleanup after m.Run.
package sessionfixture
