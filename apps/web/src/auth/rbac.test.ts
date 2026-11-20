// Bảng role → permission của SPA (rbac.gen.ts) khớp seed RBAC đã commit; điều hướng chỉ dùng permission có thật và
// trỏ tới task có thật ở §20 của master.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { OUT, renderRbac, SEED } from "../../scripts/gen-rbac.mjs";
import { PLATFORM_NAV, TENANT_NAV, visibleItems } from "../nav/navModel";
import { can } from "./permissions";
import { GRANT_COUNT, ROLE_PERMISSIONS } from "./rbac.gen";

describe("rbac.gen.ts", () => {
  it("khớp database/seeds/rbac.sql (chạy `npm run gen:rbac` khi lệch)", () => {
    expect(readFileSync(OUT, "utf8")).toBe(renderRbac(readFileSync(SEED, "utf8")));
  });

  it("đủ 11 role và 289 grant như seed", () => {
    expect(Object.keys(ROLE_PERMISSIONS)).toHaveLength(11);
    expect(GRANT_COUNT).toBe(289);
  });

  it("fail-closed: role lạ, rỗng hay khóa của Object.prototype không có quyền", () => {
    expect(can("hacker", "tenant.device:read")).toBe(false);
    expect(can(null, "tenant.device:read")).toBe(false);
    expect(can("constructor", "tenant.device:read")).toBe(false);
    expect(can("tenant_owner", "toString")).toBe(false);
  });

  it("vài ô của ma trận §8.6/§8.5", () => {
    expect(can("end_user", "tenant.device:read")).toBe(true);
    expect(can("end_user", "tenant.dashboard:read")).toBe(false);
    expect(can("tenant_admin", "tenant.billing:read")).toBe(false);
    expect(can("tenant_owner", "tenant.billing:read")).toBe(true);
    expect(can("support_operator", "tenant.audit:read")).toBe(true);
    expect(can("platform_support", "platform.settings:read")).toBe(false);
    expect(can("super_admin", "tenant.device:read")).toBe(false); // không có quyền tenant ngầm định (§8.4 bất biến 2)
  });
});

describe("điều hướng", () => {
  const master = readFileSync(join(import.meta.dirname, "../../../../docs/planning/implementation-master-plan.md"), "utf8");

  it("mọi permission của nav thuộc seed và đúng phạm vi", () => {
    const all = new Set(Object.values(ROLE_PERMISSIONS).flatMap((g) => Object.keys(g)));
    for (const i of TENANT_NAV) expect(all.has(i.permission) && i.permission.startsWith("tenant."), i.path).toBe(true);
    for (const i of PLATFORM_NAV) expect(all.has(i.permission) && i.permission.startsWith("platform."), i.path).toBe(true);
  });

  it("mọi task của nav là một hàng của §20", () => {
    for (const i of [...TENANT_NAV, ...PLATFORM_NAV]) {
      expect(master.includes(`| ${i.task} |`), i.task).toBe(true);
    }
  });

  it("đường dẫn duy nhất trong mỗi console", () => {
    for (const items of [TENANT_NAV, PLATFORM_NAV]) {
      expect(new Set(items.map((i) => i.path)).size).toBe(items.length);
    }
  });

  it("End User: thiết bị, thêm thiết bị, thông báo, chẩn đoán (thiết bị của mình) — không users/policies/audit", () => {
    expect(visibleItems(TENANT_NAV, "end_user").map((i) => i.path)).toEqual(["devices", "enroll", "notifications", "diagnostics"]);
  });

  it("role platform không thấy mục tenant và ngược lại", () => {
    expect(visibleItems(TENANT_NAV, "super_admin")).toEqual([]);
    expect(visibleItems(PLATFORM_NAV, "tenant_owner")).toEqual([]);
  });
});
