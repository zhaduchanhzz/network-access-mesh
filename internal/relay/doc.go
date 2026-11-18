// Package relay is the relay plane module of the Management Plane (§4.2 module `relay`, §10; P3-T05c of the master
// plan): RelayService reads the relay regions and their assignments (relay_regions, relay_assignments — migration 0010,
// written only by step 17 relay.assign of the Tenant Orchestrator) together with the result of the last relay probe,
// and records those probes (job relay.probe). Two read models serve the API: GET /tenants/{t}/relay (the relays of the
// tenant of the path, on the tenant pool — RLS) and GET /platform/relay-regions (every region, on the platform pool;
// read-only in the MVP — writes are P7-T04). The HTTP adapter is internal/httpapi/relayapi.
//
// What is measured, and what is not (§10.6 — never a fake figure): the embedded DERP of Headscale exports no relay
// metric, so the only measurement is the synthetic probe of the prober (P3-T03a) — GET /derp/probe of the region's
// hostname through the edge's public listener and a STUN binding to the region's STUN address (the shared responder of
// the public entry) — with the time it started (checked_at), the HTTP status, the prober's error code and the duration
// of each check as seen from the prober inside the platform (not the latency a client sees). Relay bytes, throughput,
// concurrent connections, authentication failures and client-side latency have no source: every read model lists them
// in Unavailable with the reason, never as a number.
//
// Dependencies (§13.6, internal/archtest): relay imports only base modules (store, jobs). It reaches the prober through
// the Prober interface declared here and implemented in apps/* over the prober's RPC client (apps/probe/prober), so it
// never imports apps/* nor the Headscale adapter.
//
// Probe (relay.probe, one job per probed region and period, dedupe relay:<region>:probe:<slot>):
//
//  1. a short platform transaction reads the region and the database clock — checked_at. Only embedded regions are
//     probed in this release (their DERP runs inside the tenant's instance, behind the edge); the region must be
//     active and served by a running instance, with a STUN address — otherwise the job records nothing (skipped);
//  2. the Prober runs outside any transaction (§13.5), bounded by ProbeTimeout (below the job's timeout). A probe that
//     could not run (prober unreachable, target refused by its allow-list) records nothing: it says nothing about the
//     relay — the job fails and the read side eventually reports the last result stale;
//  3. the result — status, a stable reason, and per check (derp, stun) whether it passed, the HTTP status, the error
//     code and the duration — is written to relay_regions.last_probe with last_probe_at = checked_at, unless a probe
//     that started later has already been recorded. The region's version/updated_at (its administrative state) do not
//     change.
//
// Schedule (Scheduler, worker process, only when a prober is configured — MG_PROBER_URL): every Tick the probe targets
// are listed; each region is probed once per Interval at its own offset (a hash of the region id salted with the job
// kind — §13.5 "Giãn tải"); a region never probed yet is probed at the first tick that sees it (a tenant provisioned a
// moment ago shows a result within a tick, not within an interval).
//
// Read side: the health shown for a region (HealthOf) is the verdict of the last recorded probe while it is younger
// than StaleAfter; otherwise — and for a region that is not active, not served by a running instance, of a kind not
// probed in this release, never probed, or holding an unknown record — the status is unknown with the reason.
package relay
