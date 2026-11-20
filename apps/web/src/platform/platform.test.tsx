// Platform Console (P4-T02) qua toàn bộ App + router + QueryClient, API giả ở tầng fetch theo hợp đồng của spec
// (fixture có kiểu từ schema): tenants (danh sách, wizard, chi tiết + thao tác), job timeline, hàng chờ 2P.
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { browser } from "../app/console";
import { CSRF, json, mockApi, platformSession, problem, renderApp } from "../test/helpers";
import {
  approval,
  APPR1,
  DELETE_PAYLOAD_SHA256,
  failedJob,
  instance,
  JOB1,
  JOB2,
  ME,
  provisionedJob,
  provisionJob,
  relayList,
  safeJob,
  T1,
  T2,
  tenant,
} from "../test/platformFixtures";

// luồng dài (nhiều bước UI, axe, route lazy): trên runner chậm / nhiều file song song vượt 5 s mặc định của Vitest
vi.setConfig({ testTimeout: 30_000 });

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

function session(role = "super_admin") {
  return { "GET /auth/session": json(200, platformSession(role)) };
}

function detailRoutes(status: Parameters<typeof tenant>[2] = "active") {
  return {
    [`GET /platform/tenants/${T1}`]: json(200, tenant(T1, "acme", status), { ETag: '"3"' }),
    [`GET /platform/tenants/${T1}/instances`]: json(200, { items: [instance(T1)], next_cursor: null }),
    [`GET /platform/tenants/${T1}/relay-regions`]: json(200, relayList(T1)),
    [`GET /platform/tenants/${T1}/jobs`]: json(200, { items: [safeJob(provisionedJob(JOB2, T1))], next_cursor: null }),
  };
}

describe("Tenants — danh sách", () => {
  it("dữ liệu thật của API, lọc trạng thái + tìm, phân trang con trỏ; nút tạo theo quyền", async () => {
    const { requests } = mockApi({
      ...session(),
      "GET /platform/tenants": (req) => {
        const q = new URL(req.url).searchParams;
        if (q.get("cursor") === "next-1") return json(200, { items: [tenant(T2, "beta", "suspended")], next_cursor: null });
        if (q.get("status") === "failed") return json(200, { items: [], next_cursor: null });
        return json(200, { items: [tenant(T1, "acme")], next_cursor: "next-1" });
      },
    });
    renderApp({ path: "/platform/tenants", console: "platform" });
    expect(await screen.findByRole("link", { name: "acme" })).toHaveAttribute("href", `/platform/tenants/${T1}`);
    expect(screen.getByRole("link", { name: "Tạo tenant" })).toBeInTheDocument();
    const row = screen.getByRole("link", { name: "acme" }).closest("tr")!;
    expect(within(row).getByText("Hoạt động")).toHaveAttribute("data-status", "active");

    await userEvent.click(screen.getByRole("button", { name: "Trang sau" }));
    expect(await screen.findByRole("link", { name: "beta" })).toBeInTheDocument();
    expect(screen.getByText("Trang 2")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Trang trước" }));
    expect(await screen.findByRole("link", { name: "acme" })).toBeInTheDocument();

    await userEvent.selectOptions(screen.getByLabelText("Trạng thái"), "failed");
    expect(await screen.findByTestId("empty")).toHaveTextContent("Không có tenant khớp bộ lọc");
    await userEvent.type(screen.getByLabelText("Tìm theo slug hoặc tên"), "ac");
    await userEvent.click(screen.getByRole("button", { name: "Lọc" }));
    await waitFor(() => {
      expect(requests.some((r) => new URL(r.url).search === "?limit=25&status=failed&q=ac")).toBe(true);
    });
    const listCalls = requests.filter((r) => new URL(r.url).pathname === "/api/v1/platform/tenants");
    expect(listCalls.map((r) => new URL(r.url).search)).toContain("?limit=25&cursor=next-1");
  });

  it("Platform Support: không có nút tạo; lỗi API ⇒ thông báo + thử lại", async () => {
    let calls = 0;
    mockApi({
      ...session("platform_support"),
      "GET /platform/tenants": () => (++calls === 1 ? problem(503, "instance_unavailable") : json(200, { items: [], next_cursor: null })),
    });
    renderApp({ path: "/platform/tenants", console: "platform" });
    expect(await screen.findByRole("alert")).toHaveTextContent("Control plane");
    expect(screen.queryByRole("link", { name: "Tạo tenant" })).toBeNull();
    await userEvent.click(screen.getByRole("button", { name: "Thử lại" }));
    expect(await screen.findByTestId("empty")).toHaveTextContent("Chưa có tenant nào");
  });
});

describe("Wizard tạo tenant → job timeline", () => {
  async function fillDetails(slug = "acme") {
    await userEvent.type(await screen.findByLabelText("Slug"), slug);
    await userEvent.type(screen.getByLabelText("Tên hiển thị"), "Acme Corp");
    await userEvent.type(screen.getByLabelText("Email Tenant Owner"), "owner@acme.example");
  }

  it("kiểm tra từng bước, POST với Idempotency-Key + CSRF, 202 Location ⇒ timeline 19 bước", async () => {
    const posts: Request[] = [];
    let fail = true;
    const { requests } = mockApi({
      ...session(),
      "POST /platform/tenants": async (req) => {
        posts.push(req.clone());
        if (fail) {
          fail = false;
          throw new TypeError("network down");
        }
        await req.json();
        return json(202, safeJob(provisionJob(JOB1, T1)), { Location: `/api/v1/platform/jobs/${JOB1}` });
      },
      [`GET /platform/jobs/${JOB1}`]: json(200, provisionJob(JOB1, T1)),
      "GET /platform/tenants": json(200, { items: [], next_cursor: null }),
    });
    const { router } = renderApp({ path: "/platform/tenants/new", console: "platform" });
    await screen.findByRole("heading", { name: "Tạo tenant", level: 1 });
    expect(screen.getByText("Bước 1: Thông tin tenant").closest("li")).toHaveAttribute("aria-current", "step");

    // slug sai ⇒ lỗi gắn với trường (aria-invalid + aria-describedby), không sang bước sau
    await fillDetails("1bad");
    await userEvent.click(screen.getByRole("button", { name: "Tiếp" }));
    expect(screen.getByLabelText("Slug")).toHaveAttribute("aria-invalid", "true");
    expect(screen.getByLabelText("Slug")).toHaveAccessibleDescription(/Slug không hợp lệ/);
    await userEvent.clear(screen.getByLabelText("Slug"));
    await userEvent.type(screen.getByLabelText("Slug"), "acme");
    await userEvent.click(screen.getByRole("button", { name: "Tiếp" }));

    // bước 2: IdP ngoài cần issuer https, client id, secret
    await screen.findByRole("heading", { name: "Identity Provider", level: 2 });
    await userEvent.click(screen.getByRole("radio", { name: /IdP của tenant/ }));
    await userEvent.type(screen.getByLabelText("Issuer (https://…)"), "http://idp.acme.example");
    await userEvent.click(screen.getByRole("button", { name: "Tiếp" }));
    expect(screen.getByLabelText("Issuer (https://…)")).toHaveAttribute("aria-invalid", "true");
    expect(screen.getByLabelText("Client secret")).toHaveAttribute("aria-invalid", "true");
    await userEvent.clear(screen.getByLabelText("Issuer (https://…)"));
    await userEvent.type(screen.getByLabelText("Issuer (https://…)"), "https://idp.acme.example");
    await userEvent.type(screen.getByLabelText("Client ID"), "mg-portal");
    await userEvent.type(screen.getByLabelText("Client secret"), "s3cret-value-xyz");
    await userEvent.type(screen.getByLabelText("Domain email được phép"), "acme.example, ACME.test");
    await userEvent.click(screen.getByRole("button", { name: "Tiếp" }));

    // bước 3: xem lại — secret không bao giờ hiển thị
    await screen.findByRole("heading", { name: "Xem lại và tạo", level: 2 });
    expect(document.body.textContent).not.toContain("s3cret-value-xyz");
    expect(screen.getByText("Đã nhập (ẩn)")).toBeInTheDocument();

    // lần 1: lỗi mạng ⇒ thông báo; lần 2 (cùng nội dung) ⇒ CÙNG Idempotency-Key
    await userEvent.click(screen.getByRole("button", { name: "Tạo tenant" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Không kết nối được tới máy chủ");
    await userEvent.click(screen.getByRole("button", { name: "Tạo tenant" }));

    await screen.findByRole("heading", { name: "Job tenant.provision", level: 1 });
    expect(router.state.location.pathname).toBe(`/platform/jobs/${JOB1}`);
    expect(posts).toHaveLength(2);
    const keys = posts.map((p) => p.headers.get("Idempotency-Key"));
    expect(keys[0]).toMatch(UUID);
    expect(keys[1]).toBe(keys[0]);
    expect(posts[1]!.headers.get("X-CSRF-Token")).toBe(CSRF);
    expect(await posts[1]!.json()).toEqual({
      slug: "acme",
      name: "Acme Corp",
      plan_key: "standard",
      owner_email: "owner@acme.example",
      identity_provider: {
        driver: "external",
        issuer: "https://idp.acme.example",
        client_id: "mg-portal",
        client_secret: "s3cret-value-xyz",
        allowed_email_domains: ["acme.example", "acme.test"],
      },
    });

    // timeline: 19 bước, 2 xong ở API, 17 chưa chạy; job còn chạy ⇒ đang tự cập nhật
    expect(screen.getByTestId("tenant-created")).toHaveTextContent("registry");
    const steps = within(screen.getByRole("list", { name: "Timeline của job" })).getAllByRole("listitem");
    expect(steps).toHaveLength(19);
    expect(steps[0]).toHaveAttribute("data-step-status", "succeeded");
    expect(steps[1]).toHaveAttribute("data-step", "registry.create");
    expect(steps[2]).toHaveAttribute("data-step-status", "pending");
    expect(steps[18]).toHaveAttribute("data-step", "activate");
    expect(screen.getByTestId("progress")).toHaveTextContent("2/19");
    expect(screen.getByTestId("poll-status")).toHaveTextContent("Đang tự cập nhật");
    expect(screen.getByRole("button", { name: "Hủy job" })).toBeInTheDocument();
    // secret không còn ở đâu trong DOM; mọi request cùng origin /api/v1
    expect(document.body.innerHTML).not.toContain("s3cret-value-xyz");
    for (const r of requests) expect(new URL(r.url).pathname.startsWith("/api/v1/")).toBe(true);
  });

  it("409/422 của server hiện nguyên văn kèm lỗi theo trường; sửa nội dung ⇒ Idempotency-Key mới", async () => {
    const keys: (string | null)[] = [];
    mockApi({
      ...session(),
      "POST /platform/tenants": (req) => {
        keys.push(req.headers.get("Idempotency-Key"));
        return problem(422, "validation_failed", {
          detail: "The request is invalid.",
          errors: [{ field: "slug", code: "reserved", message: "slug is reserved" }],
        });
      },
    });
    renderApp({ path: "/platform/tenants/new", console: "platform" });
    await fillDetails("admin");
    await userEvent.click(screen.getByRole("button", { name: "Tiếp" }));
    await userEvent.click(await screen.findByRole("button", { name: "Tiếp" }));
    await userEvent.click(await screen.findByRole("button", { name: "Tạo tenant" }));
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("slug is reserved");
    await userEvent.click(screen.getByRole("button", { name: "Quay lại" }));
    await userEvent.click(screen.getByRole("button", { name: "Quay lại" }));
    await userEvent.type(screen.getByLabelText("Tên hiển thị"), " 2");
    await userEvent.click(screen.getByRole("button", { name: "Tiếp" }));
    await userEvent.click(await screen.findByRole("button", { name: "Tiếp" }));
    await userEvent.click(await screen.findByRole("button", { name: "Tạo tenant" }));
    await waitFor(() => {
      expect(keys).toHaveLength(2);
    });
    expect(keys[1]).not.toBe(keys[0]);
  });

  it("role không có platform.tenant:create ⇒ không có quyền (và không gọi POST)", async () => {
    const { requests } = mockApi(session("platform_viewer"));
    renderApp({ path: "/platform/tenants/new", console: "platform" });
    await screen.findByRole("heading", { name: "Không có quyền", level: 1 });
    expect(requests.some((r) => r.method === "POST")).toBe(false);
  });
});

describe("Chi tiết tenant", () => {
  it("registry + instance + relay (số đo không có nguồn ⇒ không khả dụng) + job gần đây", async () => {
    mockApi({ ...session(), ...detailRoutes() });
    renderApp({ path: `/platform/tenants/${T1}`, console: "platform" });
    await screen.findByRole("heading", { name: "Tenant acme", level: 1 });
    const inst = await screen.findByTestId("instance");
    expect(within(inst).getByText("v0.29.7")).toBeInTheDocument();
    expect(within(inst).getByText("Khỏe")).toHaveAttribute("data-status", "healthy");
    expect(await screen.findByText("mg-acme")).toBeInTheDocument();
    // lý do health dịch theo mã, mã thô chỉ ở tooltip (G4b-E11)
    const reason = document.querySelector('[data-reason="never_checked"]');
    expect(reason).toHaveAttribute("title", "never_checked");
    expect(reason).not.toHaveTextContent("never_checked");
    // G4b-E12: cùng nhãn đã dịch với trang Relay Region; khóa thô chỉ ở tooltip
    expect(screen.getByTestId("relay-unavailable")).toHaveTextContent("Lưu lượng (byte)");
    expect(screen.getByTestId("relay-unavailable")).toHaveTextContent("không khả dụng — Thành phần không cung cấp số đo này");
    expect(screen.getByTestId("relay-unavailable")).not.toHaveTextContent("traffic_bytes");
    expect(screen.getByTitle("traffic_bytes (unsupported)")).toBeInTheDocument();
    expect(await screen.findByRole("link", { name: "tenant.provision" })).toHaveAttribute("href", `/platform/jobs/${JOB2}`);
    expect(screen.getByRole("button", { name: "Tạm ngưng" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Xóa tenant…" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Khôi phục" })).toBeNull();
  });

  it("tenant lạ (404) ⇒ 404 thống nhất; id không phải UUID ⇒ 404 không gọi API", async () => {
    const { requests } = mockApi({ ...session(), [`GET /platform/tenants/${T2}`]: problem(404, "not_found") });
    const { router } = renderApp({ path: `/platform/tenants/${T2}`, console: "platform" });
    await screen.findByRole("heading", { name: "Không tìm thấy", level: 1 });
    await router.navigate("/platform/tenants/khong-phai-uuid");
    await screen.findByRole("heading", { name: "Không tìm thấy", level: 1 });
    expect(requests.some((r) => r.url.includes("khong-phai-uuid"))).toBe(false);
  });

  it("Platform Viewer: chỉ đọc — không có thao tác vòng đời", async () => {
    mockApi({ ...session("platform_viewer"), ...detailRoutes() });
    renderApp({ path: `/platform/tenants/${T1}`, console: "platform" });
    await screen.findByTestId("instance");
    expect(screen.queryByRole("group", { name: "Thao tác vòng đời" })).toBeNull();
  });

  it("Suspend: xác nhận ⇒ POST /suspend (Idempotency-Key) ⇒ chuyển tới job", async () => {
    const posts: Request[] = [];
    mockApi({
      ...session(),
      ...detailRoutes(),
      [`POST /platform/tenants/${T1}/suspend`]: (req) => {
        posts.push(req);
        return json(202, { ...safeJob(provisionJob(JOB1, T1)), kind: "tenant.suspend", steps: [] }, { Location: `/api/v1/platform/jobs/${JOB1}` });
      },
      [`GET /platform/jobs/${JOB1}`]: json(200, { ...provisionJob(JOB1, T1), kind: "tenant.suspend", steps: [] }),
    });
    const { router } = renderApp({ path: `/platform/tenants/${T1}`, console: "platform" });
    await userEvent.click(await screen.findByRole("button", { name: "Tạm ngưng" }));
    const dialog = await screen.findByRole("alertdialog", { name: "Tạm ngưng tenant acme?" });
    await userEvent.click(within(dialog).getByRole("button", { name: "Tạm ngưng" }));
    await screen.findByRole("heading", { name: "Job tenant.suspend", level: 1 });
    expect(router.state.location.pathname).toBe(`/platform/jobs/${JOB1}`);
    expect(posts).toHaveLength(1);
    expect(posts[0]!.headers.get("Idempotency-Key")).toMatch(UUID);
    expect(posts[0]!.headers.get("X-CSRF-Token")).toBe(CSRF);
  });

  it("job xong ⇒ chi tiết tenant được làm mới (không giữ trạng thái cũ trong cache) — lỗi thấy ở E2E thật", async () => {
    let suspended = false;
    mockApi({
      ...session(),
      ...detailRoutes(),
      [`GET /platform/tenants/${T1}`]: () => json(200, tenant(T1, "acme", suspended ? "suspended" : "active")),
      [`POST /platform/tenants/${T1}/suspend`]: () =>
        json(202, { ...safeJob(provisionJob(JOB1, T1)), kind: "tenant.suspend", steps: [] }, { Location: `/api/v1/platform/jobs/${JOB1}` }),
      [`GET /platform/jobs/${JOB1}`]: () => {
        suspended = true; // worker đã chạy xong
        return json(200, { ...provisionJob(JOB1, T1, "succeeded"), kind: "tenant.suspend", steps: [] });
      },
    });
    const { router } = renderApp({ path: `/platform/tenants/${T1}`, console: "platform" });
    await userEvent.click(await screen.findByRole("button", { name: "Tạm ngưng" }));
    const dialog = await screen.findByRole("alertdialog", { name: "Tạm ngưng tenant acme?" });
    await userEvent.click(within(dialog).getByRole("button", { name: "Tạm ngưng" }));
    await screen.findByRole("heading", { name: "Job tenant.suspend", level: 1 });
    await router.navigate(`/platform/tenants/${T1}`);
    expect(await screen.findByRole("button", { name: "Khôi phục" })).toBeInTheDocument();
  });

  it("Suspend bị từ chối vì step-up (401 reauth_required) ⇒ lời nhắc xác thực lại + lỗi trong hộp", async () => {
    mockApi({ ...session(), ...detailRoutes(), [`POST /platform/tenants/${T1}/suspend`]: problem(401, "reauth_required") });
    renderApp({ path: `/platform/tenants/${T1}`, console: "platform" });
    await userEvent.click(await screen.findByRole("button", { name: "Tạm ngưng" }));
    const dialog = await screen.findByRole("alertdialog", { name: "Tạm ngưng tenant acme?" });
    await userEvent.click(within(dialog).getByRole("button", { name: "Tạm ngưng" }));
    expect(await within(dialog).findByRole("alert")).toHaveTextContent("Cần xác thực lại");
    // lời nhắc chung ở đầu trang bị lớp modal che ⇒ hộp có nút xác thực lại, quay về đúng trang
    const assign = vi.spyOn(browser, "assign").mockImplementation(() => undefined);
    await userEvent.click(within(dialog).getByRole("button", { name: "Xác thực lại" }));
    expect(assign).toHaveBeenCalledWith(`/api/v1/auth/login?scope=platform&return_to=%2Fplatform%2Ftenants%2F${T1}&reauth=true&ui_locales=vi`);
  });

  it("Resume chỉ hiện khi suspended", async () => {
    mockApi({ ...session(), ...detailRoutes("suspended") });
    renderApp({ path: `/platform/tenants/${T1}`, console: "platform" });
    expect(await screen.findByRole("button", { name: "Khôi phục" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Tạm ngưng" })).toBeNull();
  });

  it("Xóa (2P): gõ lại slug + lý do ⇒ DELETE body đúng hợp đồng ⇒ 202 Location ⇒ trang phê duyệt", async () => {
    const deletes: Request[] = [];
    mockApi({
      ...session(),
      ...detailRoutes(),
      [`DELETE /platform/tenants/${T1}`]: (req) => {
        deletes.push(req.clone());
        return json(202, approval({ requested_by: { identity_id: ME, display_name: "Ops Staff" } }), {
          Location: `/api/v1/platform/approvals/${APPR1}`,
        });
      },
      [`GET /platform/approvals/${APPR1}`]: json(200, approval({ requested_by: { identity_id: ME, display_name: "Ops Staff" } })),
    });
    const { router } = renderApp({ path: `/platform/tenants/${T1}`, console: "platform" });
    await userEvent.click(await screen.findByRole("button", { name: "Xóa tenant…" }));
    const dialog = await screen.findByRole("alertdialog", { name: "Xin xóa tenant acme" });
    const send = within(dialog).getByRole("button", { name: "Gửi yêu cầu xóa" });
    await userEvent.type(within(dialog).getByLabelText("Gõ lại slug của tenant để xác nhận"), "acme");
    expect(send).toBeDisabled(); // còn thiếu lý do
    await userEvent.type(within(dialog).getByLabelText("Lý do (ticket, yêu cầu của khách hàng)"), "ticket #42");
    expect(send).toBeEnabled();
    await userEvent.click(send);
    await screen.findByTestId("approval-requested");
    expect(router.state.location.pathname).toBe(`/platform/approvals/${APPR1}`);
    expect(deletes[0]!.headers.get("Idempotency-Key")).toMatch(UUID);
    expect(await deletes[0]!.json()).toEqual({ confirm_slug: "acme", reason: "ticket #42", skip_final_backup: false });
    // người yêu cầu xem yêu cầu của chính mình: không có nút duyệt
    expect(await screen.findByTestId("self-request")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Duyệt" })).toBeNull();
  });
});

describe("Job timeline", () => {
  it("failed_resumable: lỗi gốc + chi tiết thô của bước; Retry/Rollback (không Cancel); retry ⇒ Location job mới", async () => {
    const posts: Request[] = [];
    mockApi({
      ...session(),
      [`GET /platform/jobs/${JOB1}`]: json(200, failedJob(JOB1, T1)),
      [`POST /platform/jobs/${JOB1}/retry`]: (req) => {
        posts.push(req);
        return json(202, safeJob(provisionJob(JOB2, T1)), { Location: `/api/v1/platform/jobs/${JOB2}` });
      },
      [`GET /platform/jobs/${JOB2}`]: json(200, provisionJob(JOB2, T1, "running")),
    });
    const { router } = renderApp({ path: `/platform/jobs/${JOB1}`, console: "platform" });
    await screen.findByRole("heading", { name: "Job tenant.provision", level: 1 });
    expect(screen.getByRole("heading", { name: "Lỗi: agent_unavailable", level: 2 })).toBeInTheDocument();
    expect(screen.getByText("host agent unreachable")).toBeInTheDocument();
    expect(screen.getByTestId("poll-status")).toHaveTextContent("trạng thái cuối");
    const failed = document.querySelector('[data-step="placement.allocate"]')!;
    expect(failed).toHaveAttribute("data-step-status", "failed");
    expect(failed).toHaveAttribute("aria-current", "step");
    await userEvent.click(within(failed as HTMLElement).getByText("Chi tiết thô (đã che secret)"));
    expect(failed.textContent).toContain("connection refused");
    expect(screen.queryByRole("button", { name: "Hủy job" })).toBeNull();
    expect(screen.getByRole("button", { name: "Hoàn tác" })).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Chạy lại" }));
    const dialog = await screen.findByRole("alertdialog", { name: "Chạy lại job tenant.provision?" });
    await userEvent.click(within(dialog).getByRole("button", { name: "Chạy lại" }));
    await waitFor(() => {
      expect(router.state.location.pathname).toBe(`/platform/jobs/${JOB2}`);
    });
    expect(posts[0]!.headers.get("Idempotency-Key")).toMatch(UUID);
  });

  it("job đang chạy được poll tới khi xong; Platform Support không có nút điều khiển", async () => {
    let n = 0;
    mockApi({
      ...session("platform_support"),
      [`GET /platform/jobs/${JOB1}`]: () => json(200, ++n === 1 ? provisionJob(JOB1, T1, "running") : provisionedJob(JOB1, T1)),
    });
    renderApp({ path: `/platform/jobs/${JOB1}`, console: "platform" });
    expect(await screen.findByTestId("poll-status")).toHaveTextContent("Đang tự cập nhật");
    expect(screen.queryByRole("group", { name: "Điều khiển job" })).toBeNull();
    await waitFor(
      () => {
        expect(screen.getByTestId("progress")).toHaveTextContent("19/19");
      },
      { timeout: 4000 },
    );
    expect(screen.getByTestId("poll-status")).toHaveTextContent("trạng thái cuối");
    const before = n;
    await new Promise((r) => setTimeout(r, 2500));
    expect(n).toBe(before); // trạng thái cuối ⇒ ngừng poll
  });

  it("danh sách job: lọc kind (pattern của spec), trạng thái; link tới tenant", async () => {
    const { requests } = mockApi({
      ...session(),
      "GET /platform/jobs": json(200, { items: [safeJob(provisionedJob(JOB2, T1))], next_cursor: null }),
    });
    renderApp({ path: "/platform/jobs", console: "platform" });
    expect(await screen.findByRole("link", { name: T1 })).toHaveAttribute("href", `/platform/tenants/${T1}`);
    await userEvent.type(screen.getByLabelText("Kind"), "BAD kind");
    expect(screen.getByLabelText("Kind")).toHaveAttribute("aria-invalid", "true");
    expect(screen.getByRole("button", { name: "Lọc" })).toBeDisabled();
    await userEvent.clear(screen.getByLabelText("Kind"));
    await userEvent.type(screen.getByLabelText("Kind"), "tenant.provision");
    await userEvent.selectOptions(screen.getByLabelText("Trạng thái"), "succeeded");
    await userEvent.click(screen.getByRole("button", { name: "Lọc" }));
    await waitFor(() => {
      expect(requests.map((r) => new URL(r.url).search)).toContain("?limit=25&status=succeeded&kind=tenant.provision");
    });
  });
});

describe("Hàng chờ phê duyệt 2P", () => {
  it("danh sách mặc định status=pending; đánh dấu yêu cầu của chính mình", async () => {
    const { requests } = mockApi({
      ...session(),
      "GET /platform/approvals": json(200, {
        items: [approval(), approval({ id: JOB2, requested_by: { identity_id: ME, display_name: "Ops Staff" } })],
        next_cursor: null,
      }),
    });
    renderApp({ path: "/platform/approvals", console: "platform" });
    const links = await screen.findAllByRole("link", { name: /Xóa tenant/ });
    expect(links[0]).toHaveAttribute("href", `/platform/approvals/${APPR1}`);
    expect(screen.getByText("(bạn)")).toBeInTheDocument();
    expect(new URL(requests.find((r) => r.url.includes("/platform/approvals"))!.url).search).toBe("?limit=25&status=pending");
  });

  it("người duyệt thứ hai: payload + hash khớp (tính trong trình duyệt) ⇒ duyệt gửi đúng hash, gõ lại slug", async () => {
    const decisions: Request[] = [];
    mockApi({
      ...session(),
      [`GET /platform/approvals/${APPR1}`]: json(200, approval()),
      [`POST /platform/approvals/${APPR1}/approve`]: (req) => {
        decisions.push(req.clone());
        return json(200, approval({ status: "executed", job_id: JOB1, decided_by: { identity_id: ME, display_name: "Ops Staff" }, decided_at: "2026-11-19T03:00:00Z" }));
      },
    });
    renderApp({ path: `/platform/approvals/${APPR1}`, console: "platform" });
    await screen.findByRole("heading", { name: "Yêu cầu phê duyệt", level: 1 });
    expect(screen.getByTestId("server-hash")).toHaveTextContent(DELETE_PAYLOAD_SHA256);
    await waitFor(() => {
      expect(screen.getByTestId("local-hash")).toHaveTextContent(DELETE_PAYLOAD_SHA256);
    });
    expect(screen.getByTestId("hash-check")).toHaveTextContent("Hash khớp");
    await userEvent.click(screen.getByRole("button", { name: "Duyệt" }));
    const dialog = await screen.findByRole("alertdialog", { name: "Duyệt yêu cầu này?" });
    const confirm = within(dialog).getByRole("button", { name: "Duyệt" });
    expect(confirm).toBeDisabled();
    await userEvent.type(within(dialog).getByLabelText("Gõ lại slug của tenant sẽ bị xóa"), "acme");
    await userEvent.click(confirm);
    expect(await screen.findByRole("link", { name: JOB1 })).toHaveAttribute("href", `/platform/jobs/${JOB1}`);
    expect(await decisions[0]!.json()).toEqual({ payload_sha256: DELETE_PAYLOAD_SHA256 });
    expect(decisions[0]!.headers.get("X-CSRF-Token")).toBe(CSRF);
    expect(screen.getByText(/Yêu cầu ở trạng thái Đã thực thi/)).toBeInTheDocument();
  });

  it("hash của server không khớp payload ⇒ không duyệt được (vẫn từ chối được)", async () => {
    mockApi({ ...session(), [`GET /platform/approvals/${APPR1}`]: json(200, approval({ payload_sha256: "0".repeat(64) })) });
    renderApp({ path: `/platform/approvals/${APPR1}`, console: "platform" });
    await waitFor(() => {
      expect(screen.getByTestId("hash-check")).toHaveTextContent("Hash KHÔNG khớp");
    });
    expect(screen.getByRole("button", { name: "Duyệt" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Từ chối" })).toBeEnabled();
  });

  it("Platform Operator không duyệt được xóa tenant (quyền của chính thao tác) — server vẫn là nơi quyết định", async () => {
    mockApi({ ...session("platform_operator"), [`GET /platform/approvals/${APPR1}`]: json(200, approval()) });
    renderApp({ path: `/platform/approvals/${APPR1}`, console: "platform" });
    expect(await screen.findByTestId("not-permitted")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Duyệt" })).toBeNull();
  });

  it("từ chối: POST /reject; 403 của server (ví dụ tự duyệt) hiện trong hộp", async () => {
    mockApi({
      ...session(),
      [`GET /platform/approvals/${APPR1}`]: json(200, approval()),
      [`POST /platform/approvals/${APPR1}/reject`]: problem(403, "forbidden"),
    });
    renderApp({ path: `/platform/approvals/${APPR1}`, console: "platform" });
    await userEvent.click(await screen.findByRole("button", { name: "Từ chối" }));
    const dialog = await screen.findByRole("alertdialog", { name: "Từ chối yêu cầu này?" });
    await userEvent.click(within(dialog).getByRole("button", { name: "Từ chối" }));
    expect(await within(dialog).findByRole("alert")).toHaveTextContent("Bạn không có quyền");
  });
});
