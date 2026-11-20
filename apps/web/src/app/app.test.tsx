// Luồng của vỏ app: đăng nhập, chọn tenant, nav theo role, 404 thống nhất, Platform Console chỉ trên admin.,
// step-up, tenant suspended, 429, session hết hạn, đăng xuất.
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { api, call } from "../api/client";
import { browser } from "./console";
import {
  CSRF,
  json,
  mockApi,
  platformSession,
  problem,
  renderApp,
  TENANT_A,
  TENANT_B,
  tenantBody,
  tenantSession,
} from "../test/helpers";

const twoTenants = tenantSession([
  { tenantId: TENANT_A, slug: "tenant-a", name: "Tenant A", role: "tenant_admin" },
  { tenantId: TENANT_B, slug: "tenant-b", name: "Tenant B", role: "end_user" },
]);

function nav() {
  return screen.getByRole("navigation", { name: "Điều hướng chính" });
}

describe("đăng nhập", () => {
  it("chưa có session ⇒ /login; tenant portal hỏi slug và chuyển top-level tới /api/v1/auth/login", async () => {
    mockApi({ "GET /auth/session": problem(401, "unauthenticated") });
    const assign = vi.spyOn(browser, "assign").mockImplementation(() => undefined);
    const { router } = renderApp({ path: "/t/" + TENANT_A + "/devices" });
    const input = await screen.findByLabelText("Mã tenant (slug)");
    expect(router.state.location.pathname).toBe("/login");
    await userEvent.type(input, "Bad Slug");
    await userEvent.click(screen.getByRole("button", { name: "Tiếp tục tới trang đăng nhập" }));
    expect(assign).not.toHaveBeenCalled();
    expect(input).toHaveAttribute("aria-invalid", "true");
    await userEvent.clear(input);
    await userEvent.type(input, "tenant-a");
    await userEvent.click(screen.getByRole("button", { name: "Tiếp tục tới trang đăng nhập" }));
    expect(assign).toHaveBeenCalledWith(
      `/api/v1/auth/login?scope=tenant&tenant=tenant-a&return_to=${encodeURIComponent("/t/" + TENANT_A + "/devices")}&ui_locales=vi`,
    );
  });

  it("Platform Console đăng nhập scope=platform", async () => {
    mockApi({ "GET /auth/session": problem(401, "unauthenticated") });
    const assign = vi.spyOn(browser, "assign").mockImplementation(() => undefined);
    renderApp({ path: "/login", console: "platform" });
    await userEvent.click(await screen.findByRole("button", { name: "Tiếp tục tới trang đăng nhập" }));
    expect(assign).toHaveBeenCalledWith("/api/v1/auth/login?scope=platform&ui_locales=vi");
    expect(screen.queryByLabelText("Mã tenant (slug)")).toBeNull();
  });

  it("return_to lạ (open redirect) bị bỏ", async () => {
    mockApi({ "GET /auth/session": problem(401, "unauthenticated") });
    const assign = vi.spyOn(browser, "assign").mockImplementation(() => undefined);
    renderApp({ path: "/login?tenant=tenant-a&return_to=%2F%2Fevil.example", console: "tenant" });
    await userEvent.click(await screen.findByRole("button", { name: "Tiếp tục tới trang đăng nhập" }));
    expect(assign).toHaveBeenCalledWith("/api/v1/auth/login?scope=tenant&tenant=tenant-a&ui_locales=vi");
  });
});

describe("tenant context", () => {
  it("nhiều membership ⇒ trang chọn tenant; chọn ⇒ /t/<id>/overview (Tổng quan của P4-T04)", async () => {
    mockApi({
      "GET /auth/session": json(200, twoTenants),
      [`GET /tenants/${TENANT_A}`]: json(200, tenantBody(TENANT_A, "tenant-a")),
      [`GET /tenants/${TENANT_A}/dashboard`]: json(200, {
        devices: { total: 3, online: 1, synced_at: "2026-11-19T01:00:00Z" },
        instance: { status: "healthy", checked_at: "2026-11-19T01:00:00Z" },
        unavailable: [],
      }),
    });
    const { router } = renderApp({ path: "/" });
    await userEvent.click(await screen.findByRole("link", { name: /Tenant A/ }));
    await screen.findByRole("heading", { name: "Tổng quan", level: 1 });
    expect(router.state.location.pathname).toBe(`/t/${TENANT_A}/overview`);
    expect(await screen.findByTestId("dash-total")).toHaveTextContent("3");
    expect(screen.queryByTestId("unavailable")).toBeNull();
    expect(screen.getByTestId("shell-context")).toHaveTextContent("Tenant A");
  });

  it("một membership ⇒ vào thẳng tenant", async () => {
    mockApi({
      "GET /auth/session": json(200, tenantSession([{ tenantId: TENANT_A, slug: "tenant-a", name: "Tenant A", role: "tenant_viewer" }])),
      [`GET /tenants/${TENANT_A}`]: json(200, tenantBody(TENANT_A, "tenant-a")),
    });
    const { router } = renderApp({ path: "/" });
    await screen.findByRole("heading", { name: "Tổng quan", level: 1 });
    expect(router.state.location.pathname).toBe(`/t/${TENANT_A}/overview`);
  });

  it("tenant không thuộc session ⇒ 404 thống nhất, không gọi API của tenant đó", async () => {
    const { requests } = mockApi({ "GET /auth/session": json(200, twoTenants) });
    const other = "0190f000-0000-7000-8000-00000000000f";
    renderApp({ path: `/t/${other}/devices` });
    await screen.findByRole("heading", { name: "Không tìm thấy", level: 1 });
    expect(requests.some((r) => r.url.includes(other))).toBe(false);
  });

  it("GET /tenants/{id} trả 404 ⇒ cùng trang 404", async () => {
    mockApi({ "GET /auth/session": json(200, twoTenants), [`GET /tenants/${TENANT_A}`]: problem(404, "not_found") });
    renderApp({ path: `/t/${TENANT_A}/devices` });
    await screen.findByRole("heading", { name: "Không tìm thấy", level: 1 });
  });

  it("đường dẫn lạ ⇒ 404 thống nhất", async () => {
    mockApi({ "GET /auth/session": json(200, twoTenants) });
    renderApp({ path: "/khong-ton-tai" });
    await screen.findByRole("heading", { name: "Không tìm thấy", level: 1 });
  });
});

describe("nav theo role", () => {
  it("Tenant Admin thấy users/policies; End User chỉ thấy thiết bị của mình, không có dashboard", async () => {
    mockApi({
      "GET /auth/session": json(200, twoTenants),
      [`GET /tenants/${TENANT_A}`]: json(200, tenantBody(TENANT_A, "tenant-a")),
      [`GET /tenants/${TENANT_B}`]: json(200, tenantBody(TENANT_B, "tenant-b")),
    });
    const { router } = renderApp({ path: `/t/${TENANT_A}` });
    await screen.findByRole("heading", { name: "Tổng quan", level: 1 });
    for (const name of ["Người dùng", "Policy truy cập", "Audit log", "Enrollment key"]) {
      expect(within(nav()).getByRole("link", { name: new RegExp(name) })).toBeInTheDocument();
    }
    expect(within(nav()).queryByRole("link", { name: /Gói và thanh toán/ })).toBeNull(); // billing: chỉ Owner

    await router.navigate(`/t/${TENANT_B}`);
    await screen.findByRole("heading", { name: "Thiết bị", level: 1 });
    expect(router.state.location.pathname).toBe(`/t/${TENANT_B}/devices`);
    const links = within(nav()).getAllByRole("link").map((a) => a.textContent);
    expect(links.some((l) => l.includes("Người dùng"))).toBe(false);
    expect(links.some((l) => l.includes("Policy truy cập"))).toBe(false);
    expect(links.some((l) => l.includes("Tổng quan"))).toBe(false);

    await router.navigate(`/t/${TENANT_B}/users`);
    await screen.findByRole("heading", { name: "Không có quyền", level: 1 });
  });

  it("Platform Console: Super Admin thấy toàn bộ; Platform Support không thấy settings/users; mục sau MVP ghi task", async () => {
    mockApi({ "GET /auth/session": json(200, platformSession("super_admin")) });
    const { router, unmount } = renderApp({ path: "/", console: "platform" });
    await screen.findByRole("heading", { name: "Platform Health", level: 1 });
    expect(router.state.location.pathname).toBe("/platform/health");
    expect(within(nav()).getByRole("link", { name: /Nhân sự nền tảng/ })).toBeInTheDocument();
    // G4b-E18: "Platform Console" chỉ một lần ở header (badge), không lặp làm ngữ cảnh
    expect(within(screen.getByRole("banner")).getAllByText("Platform Console")).toHaveLength(1);
    expect(screen.queryByTestId("shell-context")).toBeNull();
    await router.navigate("/platform/security-events");
    // chờ trang mới (trang trước cũng có data-testid="unavailable")
    await screen.findByRole("heading", { name: "Security Events", level: 1 });
    expect(screen.getByTestId("unavailable")).toHaveAttribute("data-task", "P6-T02a");
    expect(screen.getByTestId("unavailable")).not.toHaveTextContent("P6-T02a"); // G4b-E11: mã task không hiện cho người dùng
    expect(screen.getByTestId("unavailable")).toHaveTextContent("sau MVP");
    unmount();

    mockApi({ "GET /auth/session": json(200, platformSession("platform_support")) });
    renderApp({ path: "/platform/tenants", console: "platform" });
    await screen.findByRole("heading", { name: "Tenant", level: 1 });
    expect(within(nav()).queryByRole("link", { name: /Thiết lập hệ thống/ })).toBeNull();
    expect(within(nav()).queryByRole("link", { name: /Nhân sự nền tảng/ })).toBeNull();
  });

  it("Platform Console không tồn tại trên app. ⇒ 404 thống nhất", async () => {
    mockApi({ "GET /auth/session": json(200, twoTenants) });
    renderApp({ path: "/platform/tenants", console: "tenant" });
    await screen.findByRole("heading", { name: "Không tìm thấy", level: 1 });
    expect(screen.queryByRole("navigation", { name: "Điều hướng chính" })).toBeNull();
  });

  it("admin.: vào tenant chỉ qua support grant còn hiệu lực", async () => {
    const future = new Date(Date.now() + 3600_000).toISOString();
    const past = new Date(Date.now() - 1000).toISOString();
    mockApi({
      "GET /auth/session": json(200, platformSession("platform_support", [
        { id: "0190a100-0000-7000-8000-000000000001", tenant_id: TENANT_A, effective_role: "support_operator", expires_at: future },
        { id: "0190a100-0000-7000-8000-000000000002", tenant_id: TENANT_B, effective_role: "support_admin", expires_at: past },
      ])),
      [`GET /tenants/${TENANT_A}`]: json(200, tenantBody(TENANT_A, "tenant-a")),
    });
    const { router } = renderApp({ path: `/t/${TENANT_A}`, console: "platform" });
    await screen.findByRole("heading", { name: "Tổng quan", level: 1 });
    expect(screen.getByTestId("shell-context")).toHaveTextContent("TENANT-A");
    await router.navigate(`/t/${TENANT_B}/devices`);
    await screen.findByRole("heading", { name: "Không tìm thấy", level: 1 });
  });
});

describe("xử lý lỗi API", () => {
  it("401 reauth_required ⇒ lời nhắc step-up, nút xác thực lại mang reauth=true và return_to", async () => {
    mockApi({
      "GET /auth/session": json(200, twoTenants),
      [`GET /tenants/${TENANT_A}`]: json(200, tenantBody(TENANT_A, "tenant-a")),
      "POST /auth/logout": problem(401, "reauth_required"),
    });
    const assign = vi.spyOn(browser, "assign").mockImplementation(() => undefined);
    renderApp({ path: `/t/${TENANT_A}/audit` });
    await screen.findByRole("heading", { name: "Audit log", level: 1 });
    await userEvent.click(screen.getByRole("button", { name: "Đăng xuất" }));
    const dialog = await screen.findByRole("alertdialog", { name: "Cần xác thực lại" });
    await userEvent.click(within(dialog).getByRole("button", { name: "Xác thực lại" }));
    expect(assign).toHaveBeenCalledWith(
      `/api/v1/auth/login?scope=tenant&tenant=tenant-a&return_to=${encodeURIComponent(`/t/${TENANT_A}/audit`)}&reauth=true&ui_locales=vi`,
    );
  });

  it("tenant suspended (trạng thái hoặc 403 tenant_suspended) ⇒ banner chỉ-đọc", async () => {
    mockApi({
      "GET /auth/session": json(200, twoTenants),
      [`GET /tenants/${TENANT_A}`]: json(200, tenantBody(TENANT_A, "tenant-a", "suspended")),
    });
    renderApp({ path: `/t/${TENANT_A}/devices` });
    expect(await screen.findByTestId("tenant-suspended")).toHaveTextContent("tạm ngưng");
  });

  it("403 tenant_suspended từ một thao tác ghi ⇒ banner cho đúng tenant đó", async () => {
    mockApi({
      "GET /auth/session": json(200, twoTenants),
      [`GET /tenants/${TENANT_A}`]: json(200, tenantBody(TENANT_A, "tenant-a")),
      [`POST /tenants/${TENANT_A}/devices/sync`]: problem(403, "tenant_suspended", { instance: `/api/v1/tenants/${TENANT_A}/devices/sync` }),
    });
    renderApp({ path: `/t/${TENANT_A}/devices` });
    await screen.findByRole("heading", { name: "Thiết bị", level: 1 });
    expect(screen.queryByTestId("tenant-suspended")).toBeNull();
    await expect(
      call(api.POST("/tenants/{tenantId}/devices/sync", { params: { path: { tenantId: TENANT_A }, header: { "Idempotency-Key": "k-1" } } })),
    ).rejects.toMatchObject({ status: 403, code: "tenant_suspended" });
    expect(await screen.findByTestId("tenant-suspended")).toBeInTheDocument();
  });

  it("429 + Retry-After ⇒ thông báo kèm số giây chờ", async () => {
    mockApi({
      "GET /auth/session": json(200, twoTenants),
      [`GET /tenants/${TENANT_A}`]: problem(429, "rate_limited", {}, { "Retry-After": "42" }),
    });
    renderApp({ path: `/t/${TENANT_A}/devices` });
    // banner toàn cục (RateLimitNotice) + chi tiết của lỗi (ProblemAlert)
    expect(await screen.findByText(/^Bạn đã gửi quá nhiều yêu cầu\. Hãy thử lại sau 4[12] giây\.$/)).toBeInTheDocument();
    expect(screen.getByText(/^Thử lại sau 42 giây\.$/)).toBeInTheDocument();
    expect(screen.getAllByText(/req-problem-1/).length).toBeGreaterThan(0);
  });

  it("401 unauthenticated giữa phiên ⇒ về /login?reason=expired với return_to", async () => {
    mockApi({
      "GET /auth/session": json(200, twoTenants),
      [`GET /tenants/${TENANT_A}`]: problem(401, "unauthenticated"),
    });
    const { router } = renderApp({ path: `/t/${TENANT_A}/devices` });
    await screen.findByText("Phiên đăng nhập đã hết hạn hoặc đã bị thu hồi. Hãy đăng nhập lại.");
    expect(router.state.location.pathname).toBe("/login");
    expect(router.state.location.search).toContain("reason=expired");
    expect(router.state.location.search).toContain(encodeURIComponent(`/t/${TENANT_A}/devices`));
  });

  it("lỗi máy chủ không phải problem+json ⇒ thông báo chung, không lộ body", async () => {
    mockApi({
      "GET /auth/session": json(200, twoTenants),
      [`GET /tenants/${TENANT_A}`]: new Response("<html>stack trace secret</html>", { status: 500, headers: { "Content-Type": "text/html" } }),
    });
    renderApp({ path: `/t/${TENANT_A}/devices` });
    expect(await screen.findByText("Máy chủ trả lời không như mong đợi.")).toBeInTheDocument();
    expect(screen.queryByText(/stack trace/)).toBeNull();
  });
});

describe("đăng xuất", () => {
  it("POST /auth/logout mang X-CSRF-Token rồi điều hướng tới redirect_to (https) của IdP", async () => {
    const redirect = "https://auth.example.test/realms/tenant-a/protocol/openid-connect/logout?client_id=portal";
    const { requests } = mockApi({
      "GET /auth/session": json(200, twoTenants),
      "POST /auth/logout": json(200, { redirect_to: redirect }),
    });
    const assign = vi.spyOn(browser, "assign").mockImplementation(() => undefined);
    renderApp({ path: "/tenants" });
    await userEvent.click(await screen.findByRole("button", { name: "Đăng xuất" }));
    await waitFor(() => {
      expect(assign).toHaveBeenCalledWith(redirect);
    });
    const post = requests.find((r) => r.method === "POST");
    expect(post?.headers.get("X-CSRF-Token")).toBe(CSRF);
    expect(requests.filter((r) => r.method === "GET").every((r) => r.headers.get("X-CSRF-Token") === null)).toBe(true);
  });

  it("redirect_to không phải https ⇒ về trang chủ", async () => {
    mockApi({
      "GET /auth/session": json(200, twoTenants),
      "POST /auth/logout": json(200, { redirect_to: "javascript:alert(1)" }),
    });
    const assign = vi.spyOn(browser, "assign").mockImplementation(() => undefined);
    renderApp({ path: "/tenants" });
    await userEvent.click(await screen.findByRole("button", { name: "Đăng xuất" }));
    await waitFor(() => {
      expect(assign).toHaveBeenCalledWith("/");
    });
  });
});
