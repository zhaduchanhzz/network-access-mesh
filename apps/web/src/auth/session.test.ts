import { describe, expect, it } from "vitest";
import { hasCsrfToken } from "../api/client";
import { CSRF, json, mockApi, platformSession, problem, TENANT_A, TENANT_B, tenantSession } from "../test/helpers";
import { fetchSession, loginUrl, safeReturnTo, tenantRole } from "./session";

describe("loginUrl / return_to", () => {
  it("tenant và platform", () => {
    expect(loginUrl({ console: "tenant", tenantSlug: "tenant-a" })).toBe("/api/v1/auth/login?scope=tenant&tenant=tenant-a");
    expect(loginUrl({ console: "platform", tenantSlug: "tenant-a", reauth: true })).toBe(
      "/api/v1/auth/login?scope=platform&reauth=true",
    );
    expect(() => loginUrl({ console: "tenant", tenantSlug: "Tenant A" })).toThrow();
  });

  it("chỉ nhận đường dẫn tương đối cùng origin (pattern của spec)", () => {
    for (const ok of ["/", "/t/x/devices", "/tenants?x=1"]) expect(safeReturnTo(ok)).toBe(ok);
    for (const bad of ["//evil.example", "/\\evil", "https://evil.example/", "javascript:alert(1)", "/a b", "", null, "/login", "/" + "a".repeat(600)]) {
      expect(safeReturnTo(bad)).toBeNull();
    }
  });
});

describe("fetchSession", () => {
  it("200 ⇒ session + CSRF trong bộ nhớ; 401 ⇒ null và xóa CSRF", async () => {
    mockApi({ "GET /auth/session": json(200, tenantSession([])) });
    expect((await fetchSession())?.csrf_token).toBe(CSRF);
    expect(hasCsrfToken()).toBe(true);
    mockApi({ "GET /auth/session": problem(401, "unauthenticated") });
    expect(await fetchSession()).toBeNull();
    expect(hasCsrfToken()).toBe(false);
  });

  it("lỗi khác 401 ⇒ ném lỗi (không coi là đăng xuất)", async () => {
    mockApi({ "GET /auth/session": problem(503, "maintenance", {}, { "Retry-After": "30" }) });
    await expect(fetchSession()).rejects.toMatchObject({ status: 503, code: "maintenance", retryAfter: 30 });
  });
});

describe("tenantRole", () => {
  it("app.: role của membership; admin.: effective_role của grant còn hạn", () => {
    const s = tenantSession([{ tenantId: TENANT_A, slug: "tenant-a", name: "A", role: "tenant_operator" }]);
    expect(tenantRole(s, TENANT_A, "tenant")).toBe("tenant_operator");
    expect(tenantRole(s, TENANT_B, "tenant")).toBeNull();
    expect(tenantRole(s, TENANT_A, "platform")).toBeNull();
    const p = platformSession("platform_support", [
      { id: "0190a100-0000-7000-8000-000000000001", tenant_id: TENANT_A, effective_role: "support_admin", expires_at: new Date(Date.now() + 60_000).toISOString() },
      { id: "0190a100-0000-7000-8000-000000000002", tenant_id: TENANT_B, effective_role: "support_admin", expires_at: new Date(Date.now() - 1).toISOString() },
    ]);
    expect(tenantRole(p, TENANT_A, "platform")).toBe("support_admin");
    expect(tenantRole(p, TENANT_B, "platform")).toBeNull();
    expect(tenantRole(p, TENANT_A, "tenant")).toBeNull();
  });
});
