// Dữ liệu mẫu của Users / Groups / Invitations (P4-T09a) — đúng schema của api/openapi.yaml (type sinh), chỉ dùng trong test.
import type { components } from "../api/schema";
import { TENANT_A } from "./helpers";

export type Membership = components["schemas"]["Membership"];
export type Group = components["schemas"]["Group"];
export type Invitation = components["schemas"]["Invitation"];
export type ApprovalRequest = components["schemas"]["ApprovalRequest"];

/** membership_id của người gọi trong tenantSession (chỉ số 0). */
export const ME = "0190d000-0000-7000-8000-000000000000";
export const OWNER_2 = "0190d100-0000-7000-8000-000000000001";
export const ADMIN_2 = "0190d100-0000-7000-8000-000000000002";
export const OPERATOR = "0190d100-0000-7000-8000-000000000003";
export const END_USER = "0190d100-0000-7000-8000-000000000004";
export const OFFBOARDED = "0190d100-0000-7000-8000-000000000005";
export const GROUP_1 = "0190d200-0000-7000-8000-000000000001";
export const INV_1 = "0190d300-0000-7000-8000-000000000001";
export const INV_ADMIN = "0190d300-0000-7000-8000-000000000002";
export const APPROVAL_1 = "0190d400-0000-7000-8000-000000000001";
export const OFFBOARD_JOB = "0190d500-0000-7000-8000-000000000001";
export const INVITE_JOB = "0190d500-0000-7000-8000-000000000002";

export function member(id: string, role: string, over: Partial<Membership> = {}): Membership {
  const n = id.slice(-1);
  return {
    id,
    identity_id: `0190d900-0000-7000-8000-00000000000${n}`,
    display_name: `Người ${n}`,
    email: `u${n}@example.test`,
    role,
    status: "active",
    headscale_username: `mg-${id}`,
    version: 3,
    ...over,
  };
}

export const MEMBERS = {
  me: (role: string) => member(ME, role, { display_name: "Nguyễn Văn A", email: "a@example.test" }),
  owner2: member(OWNER_2, "tenant_owner"),
  admin2: member(ADMIN_2, "tenant_admin"),
  operator: member(OPERATOR, "tenant_operator"),
  endUser: member(END_USER, "end_user"),
  offboarded: member(OFFBOARDED, "end_user", { status: "offboarded", offboarding: { state: "applied", job_id: OFFBOARD_JOB } }),
};

export function group(over: Partial<Group> = {}): Group {
  return {
    id: GROUP_1,
    name: "engineering",
    description: "Đội kỹ thuật",
    source: "portal",
    sensitive: false,
    member_count: 1,
    members: [{ membership_id: OPERATOR, display_name: "Người 3", email: "u3@example.test", role: "tenant_operator", status: "active" }],
    version: 4,
    created_at: "2026-11-18T00:00:00Z",
    updated_at: "2026-11-19T00:00:00Z",
    ...over,
  };
}

export function invitation(id: string, role: string, over: Partial<Invitation> = {}): Invitation {
  return {
    id,
    email: `inv-${id.slice(-1)}@example.test`,
    role,
    status: "pending",
    expires_at: "2026-11-26T00:00:00Z",
    invited_by: { identity_id: "0190c000-0000-7000-8000-0000000000c1", display_name: "Nguyễn Văn A" },
    created_at: "2026-11-19T00:00:00Z",
    updated_at: "2026-11-19T00:00:00Z",
    ...over,
  };
}

export function approval(over: Partial<ApprovalRequest> = {}): ApprovalRequest {
  return {
    id: APPROVAL_1,
    scope: "tenant",
    action: "tenant.group.set_members",
    resource_type: "group",
    resource_id: GROUP_1,
    payload: { group_id: GROUP_1, membership_ids: [END_USER, OPERATOR] },
    payload_sha256: "a".repeat(64),
    status: "pending",
    requested_by: { identity_id: "0190c000-0000-7000-8000-0000000000c1", display_name: "Nguyễn Văn A" },
    expires_at: "2026-11-20T00:00:00Z",
    created_at: "2026-11-19T00:00:00Z",
    ...over,
  };
}

export function job(id: string, kind: string, status: components["schemas"]["JobStatus"], resource?: { type: string; id: string }): components["schemas"]["Job"] {
  return { id, kind, tenant_id: TENANT_A, status, current_step: null, steps: [], created_at: "2026-11-19T00:00:00Z", ...(resource ? { resource } : {}) };
}
