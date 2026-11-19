// Quy tắc role phía UI (P4-T09a) đối chiếu nguồn sự thật: thứ bậc role = cột `rank` của database/seeds/rbac.sql; bảng
// "ai được làm gì với ai" của §8.4 bất biến 3/3a và §8.6 (assign chỉ dưới Admin, assign_admin chỉ Owner).
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { can } from "../../auth/permissions";
import {
  assignableRoles,
  canActOnMember,
  canTransferOwnership,
  invitableRoles,
  memberSet,
  outranks,
  roleOperation,
  sameSet,
  TENANT_ROLE_RANK,
  TENANT_ROLES,
  type Membership,
} from "./model";

const ME = "0190d000-0000-7000-8000-000000000000";
const m = (role: string, over: Partial<Membership> = {}): Membership => ({
  id: "0190d100-0000-7000-8000-000000000001",
  identity_id: "0190d900-0000-7000-8000-000000000001",
  display_name: "X",
  role,
  status: "active",
  headscale_username: "mg-0190d100-0000-7000-8000-000000000001",
  version: 1,
  ...over,
});

describe("thứ bậc role", () => {
  it("trùng cột rank của database/seeds/rbac.sql (phạm vi tenant)", () => {
    const sql = readFileSync(join(import.meta.dirname, "../../../../../database/seeds/rbac.sql"), "utf8");
    const seed: Record<string, number> = Object.fromEntries(
      [...sql.matchAll(/\('tenant', '([a-z_]+)', '[^']+', (\d+), true\)/g)].map((x): [string, number] => [x[1] ?? "", Number(x[2])]),
    );
    expect(seed).toEqual(TENANT_ROLE_RANK);
    expect([...TENANT_ROLES]).toEqual(Object.keys(seed).sort((a, b) => (seed[b] ?? 0) - (seed[a] ?? 0)));
  });

  it("3a: Owner tác động mọi role; người khác chỉ role thấp hơn hẳn; role lạ ⇒ không", () => {
    expect(TENANT_ROLES.every((r) => outranks("tenant_owner", r))).toBe(true);
    expect(outranks("tenant_admin", "tenant_admin")).toBe(false);
    expect(outranks("tenant_admin", "tenant_owner")).toBe(false);
    expect(outranks("tenant_admin", "tenant_operator")).toBe(true);
    expect(outranks("tenant_operator", "tenant_viewer")).toBe(true);
    expect(outranks("tenant_admin", "support_admin")).toBe(false);
    expect(outranks("super_admin", "end_user")).toBe(false);
  });
});

describe("operation đổi role (§8.4 bất biến 4)", () => {
  it.each([
    ["end_user", "tenant_viewer", "role"],
    ["tenant_operator", "end_user", "role"],
    ["end_user", "tenant_admin", "admin-role"],
    ["tenant_admin", "tenant_viewer", "admin-role"],
    ["tenant_owner", "tenant_admin", "admin-role"],
    ["tenant_owner", "end_user", "admin-role"],
    ["end_user", "tenant_owner", null],
    ["tenant_viewer", "tenant_viewer", null],
  ])("%s → %s ⇒ %s", (cur, next, op) => {
    expect(roleOperation(cur, next)).toBe(op);
  });
});

describe("role gán được", () => {
  const as = (role: string) => (p: string) => can(role, p);
  it("Owner: Admin + các role dưới Admin (trừ role hiện tại); hạ Owner khác được; không trên chính mình", () => {
    expect(assignableRoles("tenant_owner", as("tenant_owner"), m("end_user"), ME)).toEqual(["tenant_admin", "tenant_operator", "tenant_viewer"]);
    expect(assignableRoles("tenant_owner", as("tenant_owner"), m("tenant_owner"), ME)).toEqual(["tenant_admin", "tenant_operator", "tenant_viewer", "end_user"]);
    expect(assignableRoles("tenant_owner", as("tenant_owner"), m("tenant_owner", { id: ME }), ME)).toEqual([]);
  });
  it("Admin: chỉ role dưới Admin, đích dưới Admin; Admin/Owner khác ⇒ không gì", () => {
    expect(assignableRoles("tenant_admin", as("tenant_admin"), m("tenant_viewer"), ME)).toEqual(["tenant_operator", "end_user"]);
    expect(assignableRoles("tenant_admin", as("tenant_admin"), m("tenant_admin"), ME)).toEqual([]);
    expect(assignableRoles("tenant_admin", as("tenant_admin"), m("tenant_owner"), ME)).toEqual([]);
  });
  it("Operator/Viewer (không có quyền assign) và membership đã offboard ⇒ không gì", () => {
    expect(assignableRoles("tenant_operator", as("tenant_operator"), m("end_user"), ME)).toEqual([]);
    expect(assignableRoles("tenant_owner", as("tenant_owner"), m("end_user", { status: "offboarded" }), ME)).toEqual([]);
  });
  it("thao tác giữ role, mời, chuyển quyền sở hữu", () => {
    expect(canActOnMember("tenant_admin", ME, m("tenant_operator"))).toBe(true);
    expect(canActOnMember("tenant_admin", ME, m("tenant_admin"))).toBe(false);
    expect(canActOnMember("tenant_owner", ME, m("tenant_owner"))).toBe(true);
    expect(canActOnMember("tenant_owner", ME, m("tenant_viewer", { id: ME }))).toBe(false);
    expect(canActOnMember("tenant_owner", ME, m("end_user", { status: "offboarded" }))).toBe(false);
    expect(invitableRoles("tenant_owner")).toEqual(["tenant_admin", "tenant_operator", "tenant_viewer", "end_user"]);
    expect(invitableRoles("tenant_admin")).toEqual(["tenant_operator", "tenant_viewer", "end_user"]);
    expect(invitableRoles("end_user")).toEqual([]);
    expect(canTransferOwnership("tenant_owner", as("tenant_owner"), m("tenant_admin"), ME)).toBe(true);
    expect(canTransferOwnership("tenant_owner", as("tenant_owner"), m("tenant_admin", { status: "locked" }), ME)).toBe(false);
    expect(canTransferOwnership("tenant_owner", as("tenant_owner"), m("tenant_owner"), ME)).toBe(false);
    expect(canTransferOwnership("tenant_admin", as("tenant_admin"), m("end_user"), ME)).toBe(false);
  });
  it("tập thành viên: sắp xếp, bỏ trùng, so sánh không theo thứ tự", () => {
    expect(memberSet(["b", "a", "b"])).toEqual(["a", "b"]);
    expect(sameSet(["a", "b"], ["b", "a"])).toBe(true);
    expect(sameSet(["a"], ["a", "b"])).toBe(false);
  });
});
