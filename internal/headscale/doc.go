// Package headscale is the only boundary between the management plane (api, worker) and the Headscale instance of
// a tenant (§13.4 of the master plan). Everything that talks to Headscale goes through an Instance obtained from
// Registry.ForTenant — there is no other constructor that accepts an address, so no request input can choose where
// a call goes (§13.4 rule 1).
//
// Transport: REST only (gRPC is never used — RT-11), through the internal admin listener of the shared edge
// (§14.6): every request carries X-MG-Token (the listener's own token), X-MG-Instance (the tenant slug, which the
// edge maps to hs-<slug>:8080) and, for /api/v1/*, Authorization: Bearer <instance API key>. The edge strips the
// two X-MG-* headers before Headscale; only /api/v1/* and GET /version are routed.
//
// Behaviour encoded here and pinned by the contract tests in tests/integration/headscale (P2-T10):
//
//   - Errors are mapped to stable kinds and Problem codes (§13.1): the REST gateway answers most business errors
//     with HTTP 500, so classification looks at the gateway body {code, message} and per-operation message
//     patterns. The upstream message is kept only for internal logs, with credentials redacted.
//   - A per-instance circuit breaker counts only transport errors, timeouts, 503/504 and the edge's "cannot route"
//     answer; every call has a timeout; only safe GETs are retried (with backoff). Idempotent writes are retried by
//     the job layer, never here; non-idempotent writes are never retried (reconcile by reading back).
//   - Local checks before a call: Auth ID format, user name rules (ID-08), DNS label for node names, tag format,
//     canonical route prefixes, explicit expiration on every key (V-06), and a guard against the policy decoder's
//     leniency (V-06: case-insensitive keys, "#"-prefixed keys silently dropped, "grants": null = allow-all).
//   - A version layer (RT-11): the instance's version is read from GET /version and must be inside a supported
//     range before an implementation is chosen; 0.30 will need its own implementation.
//
// Credentials (instance API key, edge token, new API keys and pre-auth keys) are carried as Secret, whose
// formatting and JSON never reveal the value; nothing in this package logs a header or a body.
package headscale
