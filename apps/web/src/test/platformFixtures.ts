// Dữ liệu giả cho test của Platform Console (P4-T02) — mỗi fixture có kiểu từ schema sinh từ api/openapi.yaml, nên
// lệch hợp đồng là lỗi typecheck. Đây là dữ liệu của test, không phải số liệu hiển thị ("không mock metrics" — §12.4).
import type { components } from "../api/schema";
import { PROVISION_STEPS } from "../api/jobs";

type S = components["schemas"];

export const T1 = "0190f000-0000-7000-8000-000000000001";
export const T2 = "0190f000-0000-7000-8000-000000000002";
export const JOB1 = "0190f100-0000-7000-8000-000000000001";
export const JOB2 = "0190f100-0000-7000-8000-000000000002";
export const INST1 = "0190f200-0000-7000-8000-000000000001";
export const HOST1 = "0190f300-0000-7000-8000-000000000001";
export const APPR1 = "0190f400-0000-7000-8000-000000000001";
export const OTHER_STAFF = "0190e000-0000-7000-8000-0000000000e9";
/** identity_id của platformSession() (src/test/helpers.tsx) */
export const ME = "0190e000-0000-7000-8000-0000000000e1";

export function tenant(id: string, slug: string, status: S["TenantStatus"] = "active"): S["Tenant"] {
  return {
    id,
    slug,
    name: `Tenant ${slug}`,
    status,
    deployment_region: "lab",
    plan: "standard",
    limits: { max_devices: 50, max_users: 20, instance: { cpus: 1 } },
    control_url: `https://${slug}.mesh.example.test`,
    created_at: "2026-11-01T08:00:00Z",
    updated_at: "2026-11-02T08:00:00Z",
    version: 3,
  };
}

export function instance(tenantId: string): S["Instance"] {
  return {
    id: INST1,
    tenant_id: tenantId,
    host_id: HOST1,
    status: "running",
    headscale_version: "v0.29.7",
    image_digest: `sha256:${"a".repeat(64)}`,
    control_hostname: "acme.mesh.example.test",
    server_url: "https://acme.mesh.example.test",
    derp_region_id: 901,
    run_uid: 30001,
    net_cidr: "10.250.0.0/29",
    api_key_expires_at: "2027-02-01T00:00:00Z",
    health: { status: "healthy", checked_at: "2026-11-19T01:00:00Z" },
    version: 4,
  };
}

export function relayList(tenantId: string): S["RelayRegionList"] {
  return {
    items: [
      {
        region: {
          id: "0190f500-0000-7000-8000-000000000001",
          code: "mg-acme",
          name: "MeshGuard acme",
          kind: "embedded",
          derp_region_id: 901,
          hostname: "acme.mesh.example.test",
          derp_port: 443,
          verify_mode: "in_process",
          status: "active",
        },
        tenant_id: tenantId,
        assignments: [],
        health: { status: "unknown", checked_at: null, reason: "never_checked" },
        created_at: "2026-11-01T08:00:00Z",
        updated_at: "2026-11-01T08:00:00Z",
        version: 1,
      },
    ],
    next_cursor: null,
    unavailable: [{ metric: "traffic_bytes", reason: "unsupported", detail: "embedded DERP exports no relay metrics" }],
  };
}

const at = "2026-11-19T02:00:00Z";

/** Job tenant.provision vừa tạo: bước 1–2 xong ở API (§11.3). */
export function provisionJob(id: string, tenantId: string, status: S["JobStatus"] = "queued"): S["PlatformJob"] {
  return {
    id,
    kind: "tenant.provision",
    tenant_id: tenantId,
    status,
    current_step: status === "queued" ? null : "placement.allocate",
    steps: [
      { name: "validate", status: "succeeded", attempt: 1, started_at: at, finished_at: at, message: null },
      { name: "registry.create", status: "succeeded", attempt: 1, started_at: at, finished_at: at, message: null },
    ],
    created_at: at,
  };
}

/** Job tenant.provision đã chạy hết 19 bước. */
export function provisionedJob(id: string, tenantId: string): S["PlatformJob"] {
  return {
    id,
    kind: "tenant.provision",
    tenant_id: tenantId,
    status: "succeeded",
    current_step: null,
    steps: PROVISION_STEPS.map((name) => ({ name, status: "succeeded" as const, attempt: 1, started_at: at, finished_at: at, message: null })),
    created_at: at,
  };
}

/** Job lỗi chờ xử lý: bước edge.attach lỗi, có chi tiết thô + lỗi gốc (chỉ phía platform). */
export function failedJob(id: string, tenantId: string): S["PlatformJob"] {
  const job = provisionJob(id, tenantId, "failed_resumable");
  job.current_step = "placement.allocate";
  job.steps.push({
    name: "placement.allocate",
    status: "failed",
    attempt: 3,
    started_at: at,
    finished_at: at,
    message: "Failed (agent_unavailable)",
    detail: { error: "dial unix agent.sock: connection refused" },
  });
  job.error = { code: "agent_unavailable", message: "host agent unreachable", detail: { attempts: 3 } };
  return job;
}

export function safeJob(j: S["PlatformJob"]): S["Job"] {
  return {
    id: j.id,
    kind: j.kind,
    tenant_id: j.tenant_id,
    status: j.status,
    current_step: j.current_step,
    steps: j.steps.map(({ name, status, attempt, started_at, finished_at, message }) => ({ name, status, attempt, started_at, finished_at, message })),
    created_at: j.created_at,
  };
}

/** Payload xóa tenant (deprovision.Payload) + hash JSON chuẩn hóa (vector tính bằng mã Go của internal/authz/approvals — xem src/api/canonical.test.ts). */
export const DELETE_PAYLOAD = { skip_final_backup: false, slug: "acme", tenant_id: T1 };
export const DELETE_PAYLOAD_SHA256 = "8849b3e4f9be00afd652626bbad0ea938cb8af66ac5afd3820a7a2621be07d06";

export function approval(over: Partial<S["ApprovalRequest"]> = {}): S["ApprovalRequest"] {
  return {
    id: APPR1,
    scope: "platform",
    action: "platform.tenant.delete",
    resource_type: "tenant",
    resource_id: T1,
    payload: DELETE_PAYLOAD,
    payload_sha256: DELETE_PAYLOAD_SHA256,
    status: "pending",
    reason: "ticket #42",
    requested_by: { identity_id: OTHER_STAFF, display_name: "Second Admin" },
    expires_at: "2026-11-20T02:00:00Z",
    created_at: at,
    ...over,
  };
}
