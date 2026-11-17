// Package prober is the library of the Prober (P3-T03a; §14.4, §16.1, §11.3 steps 17–18 of the master plan): the
// synthetic checks the platform runs against its own public entry points, for the worker (provisioning steps
// relay.assign and edge.verify, the relay service of P3-T05c) and later for monitoring (P3-T16, P6-T01 — reused, not
// rewritten).
//
// Probes (every probe returns a typed result with its timing; a probe that ran and failed is a result with OK=false and
// an Error code, never a Go error):
//
//   - STUN: one RFC 5389 Binding Request to ip:port — the shared STUN responder of the public entry (stund, §10.1) —
//     with retransmissions (RTO 500 ms, doubled); the result is the XOR-MAPPED-ADDRESS the responder saw. The request
//     carries SOFTWARE "tailnode" + FINGERPRINT, without which Tailscale's stund (and the embedded DERP's STUN) ignore
//     it. blackbox_exporter has no UDP prober (ST-08), hence this one.
//   - HTTPS: one GET to an IP address with an explicit TLS server name (SNI) and Host — exactly the bytes asked for, no
//     redirect, no proxy, no connection reuse, HTTP/1.1 only — checked against expectations (status, header values,
//     body SHA-256 or size, top-level JSON string fields). TLS verification is always on: the roots are the system's
//     or, for the dev/CI stack, one CA file chosen by the process configuration (never by a request). The body is never
//     returned, only its size, SHA-256 and the JSON fields asked for. Statuses are classified: ok (2xx), not_found (404
//     — the edge's answer to every path outside its allow-list, §14.6), misdirected (421 — SNI and Host differ), …
//   - Edge: the check of provisioning step 18 (edge.verify, §11.3): GET /key?v=<capver> through the edge's public
//     listener answers 200 with the instance's Noise public key, and every path of a forbidden list (default
//     DefaultForbidden — the list of tests/security/edge/conformance.py and of step 18) answers 404.
//   - Relay: the check of step 17 (relay.assign): GET /derp/probe of the tenant answers 200 and the shared STUN
//     responder answers a Binding Request.
//
// Targets are IP literals only (the prober resolves no name, so CI needs no public DNS — and a request cannot steer
// it through DNS) and must be inside the allow-list given to the prober (MG_PROBE_ALLOW_TARGETS); anything else is
// refused before a packet is sent (target_not_allowed). The prober holds no secret (§14.4) and never sends one: there
// is no request header field, and response headers that carry credentials cannot be asked for. Paths and values that
// reach a result or a log line go through logx.RedactString.
//
// Two implementations of Prober: Local runs the probes in-process (the service, CLI runs, tests with the stub servers
// of apps/probe/stub — no DNS, no network beyond loopback) and Client calls the service's internal RPC API (Handler):
// POST /v1/stun, /v1/https, /v1/edge, /v1/relay with the request as JSON, 200 + the result, or 4xx + {"error": {code,
// message}} when the probe could not run. Only callers inside an allow-list (MG_PROBE_ALLOW_CALLERS — the worker's
// network) are served.
package prober
