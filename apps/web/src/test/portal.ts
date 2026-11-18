// Dữ liệu mẫu của Tenant Portal (P4-T04) — đúng schema của api/openapi.yaml (type sinh), chỉ dùng trong test.
import type { components } from "../api/schema";
import { TENANT_A } from "./helpers";

export type Device = components["schemas"]["Device"];
export type Notification = components["schemas"]["Notification"];

export const DEV_1 = "0190a100-0000-7000-8000-000000000001";
export const DEV_2 = "0190a100-0000-7000-8000-000000000002";
export const DEV_TAGGED = "0190a100-0000-7000-8000-000000000003";
export const JOB_1 = "0190a200-0000-7000-8000-000000000001";
export const SYNCED = "2026-11-19T01:00:00Z";

export function device(id: string, over: Partial<Device> = {}): Device {
  return {
    id,
    name: `host-${id.slice(-1)}`,
    given_name: `laptop-${id.slice(-1)}`,
    ip_addresses: [`100.64.0.${id.slice(-1)}`, "fd7a:115c:a1e0::1"],
    owner: { membership_id: "0190d000-0000-7000-8000-000000000000", display_name: "Nguyễn Văn A" },
    tags: [],
    register_method: "authkey",
    online: true,
    last_seen: "2026-11-19T00:59:00Z",
    expiry: "2027-02-17T00:00:00Z",
    routes: { advertised: [], approved: [], etag: "r0" },
    tags_etag: "t0",
    revocation: { state: "none" },
    synced_at: SYNCED,
    ...over,
  };
}

export function tagged(): Device {
  const d = device(DEV_TAGGED, { tags: ["tag:server"], expiry: null, given_name: "build-server" });
  delete d.owner; // node thuộc tag: không có chủ (PL-09)
  return d;
}

export function job(status: components["schemas"]["JobStatus"]): components["schemas"]["Job"] {
  return { id: JOB_1, kind: "inventory.sync", tenant_id: TENANT_A, status, current_step: null, steps: [], created_at: SYNCED };
}

export function notification(id: string, over: Partial<Notification> = {}): Notification {
  return {
    id,
    kind: "device.expiring",
    payload: { device_id: DEV_1, device_name: "laptop-1", expires_at: "2026-11-25T00:00:00Z", tenant_name: "Tenant A", tenant_slug: "tenant-a", locale: "vi" },
    created_at: "2026-11-19T00:00:00Z",
    read_at: null,
    ...over,
  };
}

export const DASHBOARD: components["schemas"]["TenantDashboard"] = {
  devices: { total: 3, online: 2, synced_at: SYNCED },
  instance: { status: "unhealthy", checked_at: "2026-11-19T01:01:00Z", reason: "api_key_rejected" },
  unavailable: [
    { section: "policies", reason: "no_source" },
    { section: "relay", reason: "not_served", detail: "relay figures are served by GET /relay" },
  ],
};

export const RELAY: components["schemas"]["TenantRelay"] = {
  assignments: [
    {
      id: "0190a300-0000-7000-8000-000000000001",
      priority: 0,
      status: "active",
      region: {
        id: "0190a300-0000-7000-8000-000000000002",
        code: "mg-tenant-a",
        name: "MeshGuard tenant-a",
        kind: "embedded",
        derp_region_id: 901,
        hostname: "tenant-a.mesh.example.test",
        ipv4: "203.0.113.10",
        stun_port: 3478,
        derp_port: 443,
        verify_mode: "in_process",
        status: "active",
      },
      health: {
        status: "unhealthy",
        checked_at: "2026-11-19T01:02:00Z",
        reason: "stun_probe_failed",
        derp: { ok: true, status: 200, duration_ms: 12 },
        stun: { ok: false, code: "timeout", duration_ms: 2000 },
      },
    },
  ],
  unavailable: [
    { metric: "traffic_bytes", reason: "unsupported" },
    { metric: "client_latency", reason: "no_source" },
  ],
};
