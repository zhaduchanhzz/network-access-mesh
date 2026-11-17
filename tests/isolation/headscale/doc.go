// Package hsisolation holds the isolation tests of P2-T15 that need two real Headscale instances behind the admin
// listener of the edge (tests/isolation/headscale/run.sh prepares them): IT-06 (a policy applied to A through
// Registry.ForTenant leaves the sha256 of B's GetPolicy unchanged), IT-10 (the API key of A is refused by instance B)
// and IT-20 (registry faults between A and B ⇒ every call through ForTenant fails, nothing of the other tenant is
// returned) — at the level of the target the adapter receives, and on the production Locator of P2-T11 with the
// registry in a PostgreSQL of the run and the API keys in the real SecretStore, the faults injected into the rows.
// Without the environment of run.sh the tests skip, like the contract tests of P2-T10. Only test files live here.
package hsisolation
