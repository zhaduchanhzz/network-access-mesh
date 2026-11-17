// Package monitoring is the health and dashboard module of the Management Plane (§4.2 module `monitoring`, §16; P2-T13a
// of the master plan): HealthService probes every tenant instance (job health.probe) and records the result, and the
// two read models of the API are built here — GET /tenants/{t}/dashboard (Tenant Dashboard) and GET /platform/health
// (Platform Health). Every figure carries the time it was observed (checked_at for health, synced_at for devices) and
// a section without a real source is reported unavailable with a reason, never filled with a number (§12.3, §16.1,
// §16.4). The HTTP adapter is internal/httpapi/monitoringapi.
//
// Dependencies (§13.6, internal/archtest): monitoring imports only base modules (store, jobs). It reaches the tenant's
// Headscale and the device register through two interfaces declared here and implemented in apps/* — Prober over
// headscale.CachingRegistry.Probe (version, GET /api/v1/health, breaker state) and DeviceCounter over
// devices.Service.Summary — so it never imports internal/headscale nor internal/devices, and never reads the devices'
// tables.
//
// Probe (health.probe, one job per running instance and period, dedupe instance:<id>:health:<slot>):
//
//  1. a short platform transaction reads the instance (it must still be running) and the database clock — checked_at;
//  2. the Prober checks the instance outside any transaction (§13.5), bounded by ProbeTimeout (below the job's timeout:
//     an instance that does not answer in time is recorded unhealthy, the job does not run out of time);
//  3. the result — status, stable reason, reported version, database connectivity, breaker state — is written to
//     tenant_instances.last_health with last_health_at = checked_at, unless a probe that started later has already
//     been recorded (a slow probe never overwrites a newer one). The instance's version/updated_at (its ETag) do not
//     change. An unhealthy instance is a successful job (the result is the health); the job fails only when the
//     result cannot be recorded.
//
// Schedule (Scheduler, worker process): every Tick the running instances are listed; each one is probed once per
// Interval at its own offset (a hash of the instance id salted with the job kind — §13.5 "Giãn tải"), the first
// probe after a worker start at that offset.
//
// Read side: the health shown for an instance (HealthOf) is the last recorded probe while it is younger than
// StaleAfter; otherwise, and for an instance that is not running, never probed or holds an unknown record, the
// status is unknown with the reason. The tenant dashboard is read on the tenant pool (RLS), with the tenant taken
// only from the path; the platform health on the platform pool, which cannot read tenant-internal tables (device
// counts are never part of it).
package monitoring
