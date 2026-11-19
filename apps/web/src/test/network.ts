// Dữ liệu mẫu của ba màn hình mạng (P4-T12: Routes, DNS, Tài nguyên mạng) — đúng schema của api/openapi.yaml (type
// sinh), chỉ dùng trong test.
import type { components } from "../api/schema";
import { TENANT_A } from "./helpers";

type S = components["schemas"];

export const GW = "0190a500-0000-7000-8000-000000000001";
export const LAPTOP = "0190a500-0000-7000-8000-000000000002";
export const NET_JOB = "0190a600-0000-7000-8000-000000000001";
export const APPROVAL_ID = "0190a700-0000-7000-8000-000000000001";
export const RECORD_1 = "0190a800-0000-7000-8000-000000000001";
export const RESOURCE_1 = "0190a900-0000-7000-8000-000000000001";
export const GROUP_1 = "0190aa00-0000-7000-8000-000000000001";
export const NET_SYNCED = "2026-11-19T02:00:00Z";

/** Router có tag: 10.0.0.0/24 đã duyệt; 192.168.1.0/24 và exit node chờ duyệt; 192.168.1.0/24 chồng lấn với LAPTOP. */
export function gateway(over: Partial<S["RouteDevice"]> = {}): S["RouteDevice"] {
  return {
    device_id: GW,
    name: "gw-hn",
    given_name: "gw-1",
    tags: ["tag:router"],
    online: true,
    advertised_routes: ["0.0.0.0/0", "10.0.0.0/24", "192.168.1.0/24", "::/0"],
    approved_routes: ["10.0.0.0/24"],
    pending_routes: ["0.0.0.0/0", "192.168.1.0/24", "::/0"],
    exit_node: { advertised: true, approved: false },
    routes_etag: '"etag-gw-1"',
    synced_at: NET_SYNCED,
    warnings: [
      { code: "exit_node" },
      { code: "overlap", prefix: "192.168.1.0/24", other_device_id: LAPTOP, other_prefix: "192.168.0.0/16" },
    ],
    ...over,
  };
}

/** Router không tag (node của người dùng), quảng bá 192.168.0.0/16. */
export function laptopRouter(over: Partial<S["RouteDevice"]> = {}): S["RouteDevice"] {
  return {
    device_id: LAPTOP,
    name: "laptop-an",
    given_name: "laptop-an",
    tags: [],
    online: false,
    advertised_routes: ["192.168.0.0/16"],
    approved_routes: [],
    pending_routes: ["192.168.0.0/16"],
    exit_node: { advertised: false, approved: false },
    routes_etag: '"etag-laptop-1"',
    synced_at: NET_SYNCED,
    warnings: [
      { code: "untagged_router" },
      { code: "overlap", prefix: "192.168.0.0/16", other_device_id: GW, other_prefix: "192.168.1.0/24" },
    ],
    ...over,
  };
}

export function approvalRequest(): S["ApprovalRequest"] {
  return {
    id: APPROVAL_ID,
    scope: "tenant",
    action: "tenant.route.approve",
    resource_type: "device",
    resource_id: GW,
    payload: { device_id: GW, prefixes: ["192.168.1.0/24"] },
    payload_sha256: "0".repeat(64),
    status: "pending",
    requested_by: { identity_id: "0190c000-0000-7000-8000-0000000000c1", display_name: "Nguyễn Văn A" },
    expires_at: "2026-11-20T02:00:00Z",
    created_at: NET_SYNCED,
  };
}

export function netJob(kind: string, status: S["JobStatus"]): S["Job"] {
  return { id: NET_JOB, kind, tenant_id: TENANT_A, status, current_step: null, steps: [], created_at: NET_SYNCED };
}

export function dnsView(over: Partial<S["DnsView"]> = {}): S["DnsView"] {
  return {
    magic_dns: true,
    base_domain: "tenant-a.tail.example.test",
    nameservers: ["1.1.1.1", "9.9.9.9"],
    config_version: 3,
    etag: '"dns-v3"',
    pending: null,
    records: 1,
    ...over,
  };
}

export function dnsRecord(over: Partial<S["DnsRecord"]> = {}): S["DnsRecord"] {
  return { id: RECORD_1, name: "nas.tenant-a.tail.example.test", type: "A", value: "100.64.0.5", created_at: NET_SYNCED, ...over };
}

export function resource(over: Partial<S["NetworkResource"]> = {}): S["NetworkResource"] {
  return {
    id: RESOURCE_1,
    name: "web-prod",
    kind: "service",
    address: "10.0.0.10",
    ports: ["443", "8000-8100"],
    protocol: "tcp",
    tags: ["tag:server"],
    owner_group_id: GROUP_1,
    description: "Web production",
    version: 2,
    etag: '"v2"',
    created_at: NET_SYNCED,
    updated_at: NET_SYNCED,
    ...over,
  };
}

export function tag(name: string, i: number): S["Tag"] {
  return {
    id: `0190ab00-0000-7000-8000-00000000000${i}`,
    name,
    purpose: "server",
    platform_managed: false,
    version: 1,
    etag: '"1"',
    created_at: NET_SYNCED,
    updated_at: NET_SYNCED,
  };
}

export function group(): S["Group"] {
  return { id: GROUP_1, name: "ops", source: "portal", sensitive: false, member_count: 2, version: 1, created_at: NET_SYNCED, updated_at: NET_SYNCED };
}
