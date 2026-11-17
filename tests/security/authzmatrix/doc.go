//go:build mgtestfixture

// Package authzmatrix is the authorization matrix of P2-T15 (IT-02, §5.2): every operation of api/openapi.yaml
// (internal/authz.Operations, generated from the spec and checked against it by tools/openapi_lint.py) × every role
// of §8.4 plus an anonymous client, a session presented on the other origin and a cross-site request × the tenant of
// the path (own, other, missing) × the object of the path (own, another member's, another tenant's, missing) is sent
// through the composed API of the api process with sessions minted by tests/security/sessionfixture — no browser.
//
// The expected outcome of every request is derived from the matrices of §8.5/§8.6, encoded by hand in master_test.go
// independently of database/seeds/rbac.sql (the seed is what the API decides with; a wrong seed must fail the test,
// not silently become the expectation). TestHandTablesMatchTheMaster keeps the hand encoding identical to the master
// document and TestEveryOperationHasAnExpectation fails as soon as the spec gains an operation without one.
//
// Only test files live here; this file carries the package documentation and the build tag.
package authzmatrix
