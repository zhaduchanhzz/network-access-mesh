// Package hsisolation holds the isolation tests of P2-T15 that need two real Headscale instances behind the admin
// listener of the edge (tests/isolation/headscale/run.sh prepares them): IT-06 (a policy applied to A through
// Registry.ForTenant leaves the sha256 of B's GetPolicy unchanged), IT-10 (the API key of A is refused by instance B)
// and IT-20 (address or API key swapped between A and B in the registry ⇒ every call through ForTenant fails, nothing
// of the other tenant is returned). Without the environment of run.sh the tests skip, like the contract tests of
// P2-T10. Only test files live here.
package hsisolation
