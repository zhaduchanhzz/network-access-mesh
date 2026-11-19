// Dữ liệu giả cho test của các màn hình P4-T03 (instances, hosts, health, relay regions, settings, platform users, IdP,
// plans) — có kiểu từ schema sinh từ api/openapi.yaml (lệch hợp đồng ⇒ lỗi typecheck). Dữ liệu của test, không phải số
// liệu hiển thị (§12.4).
import type { components } from "../api/schema";
import { HOST1, INST1, ME, OTHER_STAFF, T1 } from "./platformFixtures";

type S = components["schemas"];

export const HOST2 = "0190f300-0000-7000-8000-000000000002";
export const CV1 = "0190f600-0000-7000-8000-000000000001";
export const CV2 = "0190f600-0000-7000-8000-000000000002";
export const BK1 = "0190f700-0000-7000-8000-000000000001";
export const PU_ME = "0190f800-0000-7000-8000-0000000000e1";
export const PU_OTHER = "0190f800-0000-7000-8000-0000000000e9";
export const PU_SA = "0190f800-0000-7000-8000-0000000000aa";
export const IDP_P = "0190f900-0000-7000-8000-000000000001";
export const IDP_T = "0190f900-0000-7000-8000-000000000002";
export const PLAN1 = "0190fa00-0000-7000-8000-000000000001";
export const DIGEST = `sha256:${"a".repeat(64)}`;

export function configVersions(): S["InstanceConfigVersionList"] {
  return {
    items: [
      {
        id: CV2,
        version: 2,
        status: "applied",
        current: true,
        template_version: "hs-0.29/v3",
        config_sha256: "b".repeat(64),
        params: { log_level: "LOG_LEVEL_INFO", node_expiry_days: 90, nameservers: ["1.1.1.1"] },
        created_at: "2026-11-18T02:00:00Z",
        applied_at: "2026-11-18T02:01:00Z",
        created_by: null,
      },
      {
        id: CV1,
        version: 1,
        status: "superseded",
        current: false,
        template_version: "hs-0.29/v3",
        config_sha256: "c".repeat(64),
        params: {},
        created_at: "2026-11-01T02:00:00Z",
        applied_at: "2026-11-01T02:01:00Z",
        created_by: null,
      },
    ],
    next_cursor: null,
  };
}

export function backup(): S["Backup"] {
  return {
    id: BK1,
    kind: "instance",
    status: "succeeded",
    tenant_id: T1,
    instance_id: INST1,
    sequence: 7,
    method: "vacuum_into",
    size_bytes: 204800,
    sha256: "d".repeat(64),
    manifest_sha256: "e".repeat(64),
    headscale_version: "v0.29.7",
    storage_uri: "file:///backups/x",
    started_at: "2026-11-18T03:00:00Z",
    finished_at: "2026-11-18T03:00:10Z",
    expires_at: null,
    verified_at: "2026-11-18T03:00:11Z",
    job_id: null,
  };
}

export function host(id: string = HOST1, stunFree: number | null = 37): S["Host"] {
  return {
    id,
    name: id === HOST1 ? "edge-hn-1" : "edge-hn-2",
    region: "lab",
    status: id === HOST1 ? "active" : "draining",
    capacity: { max_instances: 40 },
    public_entry: { ipv4: "192.0.2.10", mode: "direct" },
    run_uid_range: { first: 30000, last: 30999 },
    ...(stunFree === null ? {} : { stun_port_range: { first: 3480, last: 3519 } }),
    tenant_net_pool: "10.250.0.0/16",
    usage: { live_instances: 3, by_status: { running: 2, quarantined: 1 }, run_uids_free: 997, net_slots_free: 8189, stun_ports_free: stunFree },
    last_heartbeat_at: "2026-11-19T01:59:30Z",
    created_at: "2026-10-01T00:00:00Z",
    updated_at: "2026-10-02T00:00:00Z",
    etag: '"h1"',
  };
}

export function health(): S["PlatformHealth"] {
  return {
    checked_at: "2026-11-19T02:00:00Z",
    components: [
      { name: "postgres", status: "healthy", checked_at: "2026-11-19T02:00:00Z" },
      { name: "agent", status: "unhealthy", checked_at: "2026-11-19T01:58:00Z", reason: "heartbeat_stale" },
      { name: "edge", status: "unknown", checked_at: null, reason: "no_probe" },
    ],
    tenants: { total: 3, by_status: { active: 2, suspended: 1 } },
    instances: { total: 3, by_status: { running: 2, quarantined: 1 }, unhealthy: 1, by_health: { healthy: 1, unhealthy: 1, unknown: 1 }, by_version: { "v0.29.7": 2 } },
    jobs: { checked_at: "2026-11-19T02:00:00Z", unfinished: { queued: 2, running: 1 }, failed_last_24h: 4 },
  };
}

export function settings(): S["SystemSettingList"] {
  return {
    items: [
      { key: "approval.ttl_hours", value: 24, default: 24, writable: true, description: "Lifetime of a new approval request, in hours (1–168)", version: 2, updated_at: "2026-11-10T00:00:00Z", etag: '"2"' },
      { key: "maintenance", value: null, writable: false, description: "Persistent maintenance flag", version: 0, etag: '"0"' },
      { key: "quota.max_tenants", value: null, writable: true, description: "Maximum number of tenants", version: 0, etag: '"0"' },
    ],
  };
}

export function platformUser(id: string, over: Partial<S["PlatformUser"]> = {}): S["PlatformUser"] {
  const identity = id === PU_ME ? ME : id === PU_OTHER ? OTHER_STAFF : "0190e000-0000-7000-8000-0000000000aa";
  return {
    id,
    identity_id: identity,
    subject: `sub-${id.slice(-4)}`,
    display_name: id === PU_ME ? "Ops Staff" : id === PU_OTHER ? "Second Admin" : "Root Admin",
    role: "platform_viewer",
    status: "active",
    created_at: "2026-11-01T00:00:00Z",
    updated_at: "2026-11-01T00:00:00Z",
    version: 3,
    etag: '"3"',
    ...over,
  };
}

export function idp(id: string = IDP_P, over: Partial<S["IdentityProvider"]> = {}): S["IdentityProvider"] {
  const tenantRow = id === IDP_T;
  return {
    id,
    scope: tenantRow ? "tenant" : "platform",
    ...(tenantRow ? { tenant_id: T1 } : {}),
    issuer: tenantRow ? "https://id.example.test/realms/tenant-acme" : "https://id.example.test/realms/platform",
    client_id: "meshguard-portal",
    driver: "keycloak",
    status: "active",
    required_claims: { groups: ["staff"] },
    require_email_verified: true,
    allowed_email_domains: ["example.test"],
    claim_mapping: {},
    client_secret_set: true,
    created_at: "2026-11-01T00:00:00Z",
    updated_at: "2026-11-01T00:00:00Z",
    version: 5,
    etag: '"5"',
    ...over,
  };
}

export function plan(over: Partial<S["Plan"]> = {}): S["Plan"] {
  return {
    id: PLAN1,
    key: "standard",
    name: "Standard",
    limits: { max_devices: 100, max_users: 50, max_tagged_devices: 20, max_live_enrollment_credentials: 10, instance: { cpus: 1, memory_mb: 512 } },
    is_active: true,
    tenant_count: 2,
    created_at: "2026-11-01T00:00:00Z",
    updated_at: "2026-11-01T00:00:00Z",
    version: 1,
    etag: '"1"',
    ...over,
  };
}
