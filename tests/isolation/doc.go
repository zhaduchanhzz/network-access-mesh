//go:build mgtestfixture

// Package isolation holds the isolation tests of P2-T15 (§5.2) that run on the composed API and PostgreSQL, with the
// sessions and the world of tests/security/sessionfixture: IT-01 through a real (fake-IdP) login on the composed API,
// IT-03 completeness of the composite tenant foreign keys over the whole catalog, IT-12a through GET …/audit. IT-02
// and the response scan of IT-10 are the authorization matrix (tests/security/authzmatrix); IT-06, IT-10 (API key)
// and IT-20 run against two real Headscale instances (tests/isolation/headscale). The tests of the other tasks that
// prove parts of these ITs are listed in docs/planning/evidence/P2-T15.md and run by `make isolation`.
//
// Only test files live here; this file carries the package documentation and the build tag.
package isolation
