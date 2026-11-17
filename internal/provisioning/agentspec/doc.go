// Package agentspec is the validation layer of the Host Agent (P3-T01; master plan §11.1, §11.5, ADR-05).
//
// The agent is the only component with the Docker socket — equivalent to root on the host (R-15) — so nothing it
// receives is trusted. This package turns every request of api/agent/v1 into a validated Go value or a typed
// *Refusal (reason + field path, never the refused value):
//
//   - Validator: closed parameter sets — canonical UUIDs (the only input of every path), the slug rule of §14.5
//     (the only input of every Docker name), an image digest that must be in the host's allowlist, run_uid, net_cidr
//     and the fallback STUN port inside the host's ranges, numeric bounds, sizes, enum values;
//   - UnknownField: a field or enum value the agent does not know is refused, never ignored (fail closed);
//   - Host.Names: derivation of every path (/opt/meshguard/tenants/<instance_id>/…) and name (mg-t-<slug>,
//     mg-hs-<slug>, hs-<slug>) — the same invariants as the Phase 1 scripts (infrastructure/host/tenant-*.sh,
//     tools/render_instance.py);
//   - Guard: before an existing directory, network or container is touched it must belong to the same instance
//     (meta/instance.json written by the agent, labels meshguard.instance_id / meshguard.tenant_id); run_uid, slug
//     and net_cidr must not be used by another instance; otherwise the call is refused — never adopted;
//   - Host.Plan: the planned actions of a dry run.
//
// It has no Docker client and writes nothing: apps/agent calls it before the infrastructure driver (the compose
// driver of P3-T02 implements Inventory and consumes the validated values).
package agentspec
