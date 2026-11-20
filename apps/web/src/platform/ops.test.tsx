// Platform Console P4-T03 qua toàn bộ App + router + QueryClient, API giả ở tầng fetch theo hợp đồng của spec (fixture
// có kiểu từ schema): instances (+ thao tác: job / 2P), hosts, Platform Health, relay regions, thiết lập (ETag/412),
// nhân sự nền tảng (role dưới SA, SA luôn 2P, không tự sửa mình), IdP (bất biến, IdP tenant ⇒ 202 + 2P), gói dịch vụ,
// sửa tenant (If-Match).
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { CSRF, json, mockApi, platformSession, problem, renderApp } from "../test/helpers";
import { approval, APPR1, HOST1, INST1, instance, JOB1, ME, provisionJob, relayList, T1, tenant } from "../test/platformFixtures";
import {
  backup,
  BK1,
  configVersions,
  DIGEST,
  health,
  host,
  HOST2,
  idp,
  IDP_P,
  IDP_T,
  plan,
  PLAN1,
  platformUser,
  PU_ME,
  PU_OTHER,
  PU_SA,
  settings,
} from "../test/opsFixtures";

vi.setConfig({ testTimeout: 30_000 });

const UUID4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

function session(role = "super_admin") {
  return { "GET /auth/session": json(200, platformSession(role)) };
}

function instanceRoutes(status: "running" | "quarantined" = "running") {
  return {
    [`GET /platform/instances/${INST1}`]: json(200, { ...instance(T1), status }),
    [`GET /platform/instances/${INST1}/config-versions`]: json(200, configVersions()),
    "GET /platform/backups": json(200, { items: [backup()], next_cursor: null }),
  };
}

const jobOf = (kind: string) => ({ ...provisionJob(JOB1, T1), kind, steps: [] });

describe("Instances", () => {
  it("danh sách: query thật (status, host từ ?host=, con trỏ), health kèm lý do + checked_at, link chi tiết", async () => {
    const { requests } = mockApi({
      ...session("platform_viewer"),
      "GET /platform/instances": (req) => {
        const q = new URL(req.url).searchParams;
        const unhealthy = { ...instance(T1), health: { status: "unhealthy" as const, checked_at: "2026-11-19T01:00:00Z", reason: "api_key_rejected" } };
        return q.get("cursor") === "c2" ? json(200, { items: [instance(T1)], next_cursor: null }) : json(200, { items: [unhealthy], next_cursor: "c2" });
      },
    });
    renderApp({ path: `/platform/instances?host=${HOST1}`, console: "platform" });
    const link = await screen.findByRole("link", { name: "acme.mesh.example.test" });
    expect(link).toHaveAttribute("href", `/platform/instances/${INST1}`);
    const row = link.closest("tr")!;
    expect(within(row).getByTestId("health")).toHaveAttribute("data-health", "unhealthy");
    expect(within(row).getByText("API key của nền tảng bị từ chối.")).toBeInTheDocument();
    expect(within(row).getByText(/Kiểm tra lúc|Kiểm lúc/)).toBeInTheDocument();
    expect(screen.getByTestId("host-filter")).toHaveTextContent(HOST1);
    await userEvent.selectOptions(screen.getByLabelText("Trạng thái"), "running");
    await userEvent.click(await screen.findByRole("button", { name: "Trang sau" }));
    await waitFor(() => {
      expect(requests.map((r) => new URL(r.url).search)).toContain(`?limit=25&status=running&host=${HOST1}&cursor=c2`);
    });
    expect(requests.map((r) => new URL(r.url).search)).toContain(`?limit=25&host=${HOST1}`);
  });

  it("chi tiết: version, digest, health có checked_at, version cấu hình hiện hành + tham số, backup; Viewer không có thao tác", async () => {
    mockApi({ ...session("platform_viewer"), ...instanceRoutes() });
    renderApp({ path: `/platform/instances/${INST1}`, console: "platform" });
    await screen.findByRole("heading", { name: "acme.mesh.example.test", level: 1 });
    expect(screen.getByText("v0.29.7")).toBeInTheDocument();
    expect(screen.getByTestId("image-digest")).toHaveTextContent(DIGEST);
    expect(await screen.findByTestId("config-current")).toHaveTextContent("version 2");
    const rows = screen.getAllByTestId("config-version");
    expect(rows[0]).toHaveAttribute("aria-current", "true");
    expect(within(rows[0]!).getByText("Đang hiệu lực")).toHaveAttribute("data-status", "applied");
    expect(within(rows[1]!).getByText("Đã thay")).toBeInTheDocument();
    expect(screen.getByText(/LOG_LEVEL_INFO/)).toBeInTheDocument();
    expect(await screen.findByText("vacuum_into")).toBeInTheDocument();
    expect(screen.queryByRole("group", { name: "Thao tác vận hành" })).toBeNull();
  });

  it("id không phải UUID ⇒ 404 không gọi API; instance lạ ⇒ 404 thống nhất", async () => {
    const { requests } = mockApi({ ...session() });
    const { router } = renderApp({ path: "/platform/instances/khong-phai-uuid", console: "platform" });
    await screen.findByRole("heading", { name: "Không tìm thấy", level: 1 });
    expect(requests.some((r) => r.url.includes("/platform/instances/"))).toBe(false);
    await router.navigate(`/platform/instances/${INST1}`);
    await waitFor(() => {
      expect(requests.some((r) => r.url.endsWith(`/platform/instances/${INST1}`))).toBe(true);
    });
    expect(await screen.findByRole("heading", { name: "Không tìm thấy", level: 1 })).toBeInTheDocument();
  });

  it("restart: POST không body + Idempotency-Key + CSRF; lỗi mạng ⇒ gửi lại CÙNG khóa; 202 Location ⇒ timeline job", async () => {
    const posts: Request[] = [];
    let fail = true;
    mockApi({
      ...session("platform_operator"),
      ...instanceRoutes(),
      [`POST /platform/instances/${INST1}/restart`]: (req) => {
        posts.push(req.clone());
        if (fail) {
          fail = false;
          throw new TypeError("network down");
        }
        return json(202, jobOf("instance.restart"), { Location: `/api/v1/platform/jobs/${JOB1}` });
      },
      [`GET /platform/jobs/${JOB1}`]: json(200, jobOf("instance.restart")),
    });
    const { router } = renderApp({ path: `/platform/instances/${INST1}`, console: "platform" });
    await userEvent.click(await screen.findByRole("button", { name: "Restart" }));
    const dialog = await screen.findByRole("alertdialog", { name: "Restart instance acme.mesh.example.test?" });
    await userEvent.click(within(dialog).getByRole("button", { name: "Restart" }));
    expect(await within(dialog).findByRole("alert")).toHaveTextContent("Không kết nối được");
    await userEvent.click(within(dialog).getByRole("button", { name: "Restart" }));
    await screen.findByRole("heading", { name: "Job instance.restart", level: 1 });
    expect(router.state.location.pathname).toBe(`/platform/jobs/${JOB1}`);
    expect(posts).toHaveLength(2);
    const k = posts.map((p) => p.headers.get("Idempotency-Key"));
    expect(k[0]).toMatch(UUID4);
    expect(k[1]).toBe(k[0]);
    expect(posts[0]!.headers.get("X-CSRF-Token")).toBe(CSRF);
    expect(await posts[1]!.text()).toBe("");
  });

  it("reconfigure: kiểm tra trường, chỉ gửi trường đã điền; upgrade: digest sai/trùng bị chặn ở client", async () => {
    const bodies: unknown[] = [];
    mockApi({
      ...session(),
      ...instanceRoutes(),
      [`POST /platform/instances/${INST1}/reconfigure`]: async (req) => {
        bodies.push(await req.json());
        return json(202, jobOf("instance.reconfigure"), { Location: `/api/v1/platform/jobs/${JOB1}` });
      },
      [`GET /platform/jobs/${JOB1}`]: json(200, jobOf("instance.reconfigure")),
    });
    renderApp({ path: `/platform/instances/${INST1}`, console: "platform" });
    await userEvent.click(await screen.findByRole("button", { name: "Nâng cấp…" }));
    let dialog = await screen.findByRole("dialog", { name: "Nâng cấp instance acme.mesh.example.test" });
    await userEvent.type(within(dialog).getByLabelText("Image digest đích"), "nginx:latest");
    await userEvent.click(within(dialog).getByRole("button", { name: "Nâng cấp" }));
    expect(within(dialog).getByLabelText("Image digest đích")).toHaveAccessibleDescription(/sha256:<64 ký tự hex thường>/);
    await userEvent.clear(within(dialog).getByLabelText("Image digest đích"));
    await userEvent.type(within(dialog).getByLabelText("Image digest đích"), DIGEST);
    await userEvent.click(within(dialog).getByRole("button", { name: "Nâng cấp" }));
    expect(within(dialog).getByText("Instance đang chạy đúng image này.")).toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole("button", { name: "Hủy" }));

    await userEvent.click(screen.getByRole("button", { name: "Đổi cấu hình…" }));
    dialog = await screen.findByRole("dialog", { name: "Đổi cấu hình instance acme.mesh.example.test" });
    await userEvent.click(within(dialog).getByRole("button", { name: "Áp dụng cấu hình" }));
    expect(within(dialog).getByText("Chưa có thay đổi nào.")).toBeInTheDocument();
    await userEvent.type(within(dialog).getByLabelText("Hạn node (ngày)"), "0");
    await userEvent.click(within(dialog).getByRole("button", { name: "Áp dụng cấu hình" }));
    expect(within(dialog).getByLabelText("Hạn node (ngày)")).toHaveAttribute("aria-invalid", "true");
    await userEvent.clear(within(dialog).getByLabelText("Hạn node (ngày)"));
    await userEvent.type(within(dialog).getByLabelText("Hạn node (ngày)"), "30");
    await userEvent.type(within(dialog).getByLabelText("Nameserver"), "9.9.9.9, 1.1.1.1");
    await userEvent.selectOptions(within(dialog).getByLabelText("Log level"), "warn");
    await userEvent.click(within(dialog).getByRole("button", { name: "Áp dụng cấu hình" }));
    await screen.findByRole("heading", { name: "Job instance.reconfigure", level: 1 });
    expect(bodies).toEqual([{ log_level: "warn", node_expiry_days: 30, nameservers: ["9.9.9.9", "1.1.1.1"] }]);
  });

  it("restore 2P: chọn backup + lý do ⇒ POST body đúng ⇒ 202 Location ⇒ trang phê duyệt (người yêu cầu)", async () => {
    let body: unknown = null;
    const restoreApproval = approval({ action: "platform.instance.restore", resource_type: "instance", resource_id: INST1, requested_by: { identity_id: ME, display_name: "Ops Staff" } });
    mockApi({
      ...session(),
      ...instanceRoutes(),
      [`POST /platform/instances/${INST1}/restore`]: async (req) => {
        body = await req.json();
        expect(req.headers.get("Idempotency-Key")).toMatch(UUID4);
        return json(202, restoreApproval, { Location: `/api/v1/platform/approvals/${APPR1}` });
      },
      [`GET /platform/approvals/${APPR1}`]: json(200, restoreApproval),
    });
    const { router } = renderApp({ path: `/platform/instances/${INST1}`, console: "platform" });
    await userEvent.click(await screen.findByRole("button", { name: "Xin restore…" }));
    const dialog = await screen.findByRole("dialog", { name: "Xin restore instance acme.mesh.example.test" });
    expect(within(dialog).getByText(/thao tác 2P/)).toBeInTheDocument();
    const submit = within(dialog).getByRole("button", { name: "Gửi yêu cầu restore" });
    expect(await within(dialog).findByRole("radio")).toBeChecked();
    expect(submit).toBeDisabled();
    await userEvent.click(within(dialog).getByLabelText(/CŨ HƠN/));
    await userEvent.type(within(dialog).getByLabelText("Lý do (ticket, yêu cầu của khách hàng)"), "INC-7");
    await userEvent.click(submit);
    await screen.findByTestId("approval-requested");
    expect(router.state.location.pathname).toBe(`/platform/approvals/${APPR1}`);
    expect(body).toEqual({ backup_id: BK1, restore_point_older_than_backup: true, reason: "INC-7" });
    expect(screen.getByTestId("self-request")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: `instance:${INST1}` })).toHaveAttribute("href", `/platform/instances/${INST1}`);
  });

  it("quarantine: gõ lại hostname + lý do ⇒ job; instance quarantined ⇒ chỉ còn xin gỡ (2P) và restore", async () => {
    mockApi({
      ...session(),
      ...instanceRoutes("quarantined"),
      [`POST /platform/instances/${INST1}/release`]: json(202, approval({ action: "platform.instance.release" }), { Location: `/api/v1/platform/approvals/${APPR1}` }),
      [`GET /platform/approvals/${APPR1}`]: json(200, approval({ action: "platform.instance.release" })),
    });
    renderApp({ path: `/platform/instances/${INST1}`, console: "platform" });
    const group = await screen.findByRole("group", { name: "Thao tác vận hành" });
    expect(within(group).getAllByRole("button").map((b) => b.textContent)).toEqual(["Xin restore…", "Quarantine…", "Xin gỡ quarantine…"]);
    await userEvent.click(within(group).getByRole("button", { name: "Quarantine…" }));
    const dialog = await screen.findByRole("alertdialog");
    const confirm = within(dialog).getByRole("button", { name: "Quarantine" });
    await userEvent.type(within(dialog).getByLabelText("Lý do (ticket, yêu cầu của khách hàng)"), "nghi bị chiếm");
    expect(confirm).toBeDisabled();
    await userEvent.type(within(dialog).getByLabelText("Gõ lại control hostname để xác nhận"), "acme.mesh.example.test");
    expect(confirm).toBeEnabled();
    await userEvent.click(within(dialog).getByRole("button", { name: "Hủy" }));
    await userEvent.click(within(group).getByRole("button", { name: "Xin gỡ quarantine…" }));
    const rel = await screen.findByRole("alertdialog");
    await userEvent.type(within(rel).getByLabelText("Lý do (ticket, yêu cầu của khách hàng)"), "đã điều tra");
    await userEvent.click(within(rel).getByRole("button", { name: "Gửi yêu cầu gỡ" }));
    expect(await screen.findByTestId("approval-requested")).toBeInTheDocument();
  });
});

describe("Hosts", () => {
  it("capacity, cổng STUN còn trống (số / STUN chung), chi tiết + instance theo host (?host=)", async () => {
    const { requests } = mockApi({
      ...session("platform_support"),
      "GET /platform/hosts": json(200, { items: [host(HOST1, 37), host(HOST2, null)], next_cursor: null }),
      [`GET /platform/hosts/${HOST1}`]: json(200, host(HOST1, 37)),
      "GET /platform/instances": json(200, { items: [instance(T1)], next_cursor: null }),
    });
    const { router } = renderApp({ path: "/platform/hosts", console: "platform" });
    const rows = await screen.findAllByTestId("host-row");
    expect(within(rows[0]!).getByTestId("capacity")).toHaveTextContent("3 / 40 instance");
    expect(within(rows[0]!).getByTestId("stun-free")).toHaveTextContent("37");
    expect(within(rows[1]!).getByTestId("stun-free")).toHaveTextContent("STUN chung");
    expect(within(rows[1]!).getByText("Đang rút (không nhận mới)")).toBeInTheDocument();
    await userEvent.click(within(rows[0]!).getByRole("link", { name: "edge-hn-1" }));
    await screen.findByRole("heading", { name: "edge-hn-1", level: 1 });
    expect(router.state.location.pathname).toBe(`/platform/hosts/${HOST1}`);
    expect(screen.getByText("3480–3519")).toBeInTheDocument();
    expect(await screen.findByRole("link", { name: "acme.mesh.example.test" })).toBeInTheDocument();
    expect(requests.map((r) => new URL(r.url).search)).toContain(`?limit=25&host=${HOST1}`);
  });
});

describe("Platform Health", () => {
  it("số liệu thật kèm checked_at; thành phần không có nguồn ⇒ 'không khả dụng' kèm lý do; làm mới định kỳ", async () => {
    mockApi({ ...session("platform_viewer"), "GET /platform/health": json(200, health()) });
    renderApp({ path: "/platform/health", console: "platform" });
    expect(await screen.findByTestId("health-tenants")).toHaveTextContent("3");
    expect(screen.getByTestId("unhealthy")).toHaveTextContent("1 instance lỗi health");
    expect(screen.getByTestId("failed-24h")).toHaveTextContent("4 job lỗi/lùi trong 24 giờ");
    expect(screen.getByTestId("health-jobs")).toHaveTextContent("3");
    const unavailable = screen.getByTestId("components-unavailable");
    expect(within(unavailable).getByTestId("unavailable-section")).toHaveTextContent("edge: không khả dụng");
    expect(within(unavailable).getByText(/Chưa có probe cho thành phần này/)).toBeInTheDocument();
    const measured = screen.getByTestId("components-measured");
    expect(within(measured).getByText("Heartbeat đã cũ.")).toBeInTheDocument();
    expect(screen.getAllByText(/Kiểm tra lúc|Kiểm lúc/).length).toBeGreaterThanOrEqual(3);
  });

  it("API lỗi ⇒ thông báo + thử lại, không số nào", async () => {
    mockApi({ ...session(), "GET /platform/health": problem(503, "maintenance") });
    renderApp({ path: "/platform/health", console: "platform" });
    expect(await screen.findByRole("alert")).toHaveTextContent("Nền tảng đang bảo trì");
    expect(screen.queryByTestId("health-tenants")).toBeNull();
  });
});

describe("Relay Regions", () => {
  it("chỉ đọc; số đo không có nguồn ⇒ không khả dụng kèm lý do", async () => {
    mockApi({ ...session("platform_viewer"), "GET /platform/relay-regions": json(200, relayList(T1)) });
    renderApp({ path: "/platform/relay-regions", console: "platform" });
    expect(await screen.findByTestId("relay-row")).toHaveTextContent("mg-acme");
    expect(screen.getByTestId("relay-unavailable")).toHaveTextContent("không khả dụng");
    expect(screen.queryByRole("button", { name: /Sửa|Tạo|Xóa/ })).toBeNull();
  });
});

describe("Thiết lập hệ thống", () => {
  it("PUT với If-Match = etag đã đọc; ngoài miền bị chặn; 412 ⇒ hiện giá trị mới nhất, dùng bản mới rồi gửi lại với ETag mới", async () => {
    let version = 2;
    let value = 24;
    const puts: { ifMatch: string | null; body: unknown }[] = [];
    mockApi({
      ...session(),
      "GET /platform/settings": () => {
        const s = settings();
        s.items[0] = { ...s.items[0]!, value, version, etag: `"${String(version)}"` };
        return json(200, s);
      },
      "PUT /platform/settings/approval.ttl_hours": async (req) => {
        const b = (await req.json()) as { value: number };
        puts.push({ ifMatch: req.headers.get("If-Match"), body: b });
        if (req.headers.get("If-Match") !== `"${String(version)}"`) return problem(412, "precondition_failed");
        value = b.value;
        version += 1;
        return json(200, { ...settings().items[0]!, value, version, etag: `"${String(version)}"` });
      },
    });
    renderApp({ path: "/platform/settings", console: "platform" });
    const row = (await screen.findAllByTestId("setting-row")).find((r) => r.dataset.key === "approval.ttl_hours")!;
    expect(within(row).getByTestId("setting-value")).toHaveTextContent("24");
    const maint = screen.getAllByTestId("setting-row").find((r) => r.dataset.key === "maintenance")!;
    expect(within(maint).getByText("Chỉ đọc (lệnh host)")).toBeInTheDocument();
    expect(within(maint).queryByRole("button")).toBeNull();

    await userEvent.click(within(row).getByRole("button", { name: "Sửa approval.ttl_hours" }));
    const dialog = await screen.findByRole("dialog", { name: "Sửa thiết lập approval.ttl_hours" });
    const input = within(dialog).getByLabelText("Giá trị (JSON)");
    expect(input).toHaveFocus();
    await userEvent.clear(input);
    await userEvent.type(input, "500");
    await userEvent.click(within(dialog).getByRole("button", { name: "Lưu" }));
    expect(input).toHaveAttribute("aria-invalid", "true");
    expect(puts).toHaveLength(0);

    // người khác sửa trong lúc hộp đang mở ⇒ bản đã đọc cũ
    version = 3;
    value = 72;
    await userEvent.clear(input);
    await userEvent.type(input, "48");
    await userEvent.click(within(dialog).getByRole("button", { name: "Lưu" }));
    const stale = await within(dialog).findByTestId("stale-setting");
    expect(stale).toHaveTextContent("Dữ liệu đã bị thay đổi bởi người khác");
    await waitFor(() => {
      expect(within(stale).getByTestId("latest-value")).toHaveTextContent("72");
    });
    expect(puts[0]).toEqual({ ifMatch: '"2"', body: { value: 48 } });
    expect(within(dialog).getByRole("button", { name: "Lưu" })).toBeDisabled();
    await userEvent.click(within(stale).getByRole("button", { name: "Dùng bản mới nhất rồi sửa lại" }));
    expect(within(dialog).getByLabelText("Giá trị (JSON)")).toHaveValue("72");
    await userEvent.clear(within(dialog).getByLabelText("Giá trị (JSON)"));
    await userEvent.type(within(dialog).getByLabelText("Giá trị (JSON)"), "48");
    await userEvent.click(within(dialog).getByRole("button", { name: "Lưu" }));
    await waitFor(() => {
      expect(screen.queryByRole("dialog")).toBeNull();
    });
    expect(puts[1]).toEqual({ ifMatch: '"3"', body: { value: 48 } });
    await waitFor(() => {
      expect(within(screen.getAllByTestId("setting-row")[0]!).getByTestId("setting-value")).toHaveTextContent("48");
    });
  });

  it("Platform Operator chỉ xem (không nút sửa); step-up 401 ⇒ nút xác thực lại trong hộp", async () => {
    mockApi({ ...session("platform_operator"), "GET /platform/settings": json(200, settings()) });
    const { unmount } = renderApp({ path: "/platform/settings", console: "platform" });
    await screen.findAllByTestId("setting-row");
    expect(screen.queryByRole("button", { name: /^Sửa/ })).toBeNull();
    expect(screen.getByText("Role của bạn chỉ xem được thiết lập.")).toBeInTheDocument();
    unmount();

    mockApi({
      ...session(),
      "GET /platform/settings": json(200, settings()),
      "PUT /platform/settings/quota.max_tenants": problem(401, "reauth_required"),
    });
    renderApp({ path: "/platform/settings", console: "platform" });
    await userEvent.click(await screen.findByRole("button", { name: "Sửa quota.max_tenants" }));
    const dialog = await screen.findByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("Giá trị (JSON)"), "10");
    await userEvent.click(within(dialog).getByRole("button", { name: "Lưu" }));
    expect(await within(dialog).findByRole("button", { name: "Xác thực lại" })).toBeInTheDocument();
  });
});

describe("Nhân sự nền tảng", () => {
  const users = () => ({
    items: [platformUser(PU_ME, { role: "super_admin" }), platformUser(PU_OTHER), platformUser(PU_SA, { role: "super_admin" })],
    next_cursor: null,
  });

  it("không tự sửa mình; SA khác chỉ có 'gỡ SA'; gán SA ⇒ PUT {super_admin, reason} ⇒ 202 ⇒ trang phê duyệt", async () => {
    let body: unknown = null;
    const saApproval = approval({ action: "platform.user.super_admin", resource_type: "platform_user", resource_id: PU_OTHER, payload: { grant: true }, requested_by: { identity_id: ME, display_name: "Ops Staff" } });
    mockApi({
      ...session(),
      "GET /platform/users": json(200, users()),
      [`PUT /platform/users/${PU_OTHER}/super-admin-role`]: async (req) => {
        body = await req.json();
        return json(202, saApproval, { Location: `/api/v1/platform/approvals/${APPR1}` });
      },
      [`GET /platform/approvals/${APPR1}`]: json(200, saApproval),
    });
    const { router } = renderApp({ path: "/platform/users", console: "platform" });
    const rows = await screen.findAllByTestId("platform-user");
    expect(within(rows[0]!).getByText("(bạn)")).toBeInTheDocument();
    expect(within(rows[0]!).queryByRole("button")).toBeNull();
    expect(within(rows[0]!).getByText("Không tự sửa chính mình")).toBeInTheDocument();
    expect(within(rows[2]!).getAllByRole("button").map((b) => b.textContent)).toEqual(["Gỡ Super Admin…"]);
    expect(within(rows[1]!).getAllByRole("button").map((b) => b.textContent)).toEqual(["Sửa…", "Khóa…", "Gán Super Admin…"]);

    await userEvent.click(within(rows[1]!).getByRole("button", { name: "Gán Super Admin cho Second Admin" }));
    const dialog = await screen.findByRole("dialog", { name: "Xin gán Super Admin cho Second Admin" });
    expect(within(dialog).getByText(/một Super Admin khác phải duyệt/)).toBeInTheDocument();
    const submit = within(dialog).getByRole("button", { name: "Gửi yêu cầu phê duyệt" });
    expect(submit).toBeDisabled();
    await userEvent.type(within(dialog).getByLabelText("Lý do (người duyệt sẽ đọc)"), "on-call rotation");
    await userEvent.click(submit);
    await screen.findByTestId("approval-requested");
    expect(router.state.location.pathname).toBe(`/platform/approvals/${APPR1}`);
    expect(body).toEqual({ super_admin: true, reason: "on-call rotation" });
    expect(screen.getByText("Gán/gỡ Super Admin")).toBeInTheDocument();
    expect(screen.getByTestId("self-request")).toBeInTheDocument();
  });

  it("phê duyệt gán SA: Platform Operator không có nút (thiếu quyền của chính thao tác), SA khác có", async () => {
    const pending = approval({ action: "platform.user.super_admin", resource_type: "platform_user", resource_id: PU_OTHER });
    mockApi({ ...session("platform_operator"), [`GET /platform/approvals/${APPR1}`]: json(200, pending) });
    const { unmount } = renderApp({ path: `/platform/approvals/${APPR1}`, console: "platform" });
    expect(await screen.findByTestId("not-permitted")).toBeInTheDocument();
    unmount();
    mockApi({ ...session(), [`GET /platform/approvals/${APPR1}`]: json(200, pending) });
    renderApp({ path: `/platform/approvals/${APPR1}`, console: "platform" });
    await waitFor(() => {
      expect(screen.getByTestId("hash-check")).toBeInTheDocument();
    });
    expect(screen.queryByTestId("not-permitted")).toBeNull();
    expect(screen.getByRole("button", { name: "Từ chối" })).toBeInTheDocument();
  });

  it("thêm (POST + Idempotency-Key, role không có super_admin), sửa (PATCH If-Match chỉ trường đổi), khóa (DELETE If-Match)", async () => {
    const calls: { m: string; key: string | null; ifMatch: string | null; body: unknown }[] = [];
    const rec = async (req: Request, status: number, out: unknown) => {
      calls.push({ m: req.method, key: req.headers.get("Idempotency-Key"), ifMatch: req.headers.get("If-Match"), body: req.method === "DELETE" ? null : await req.json() });
      return json(status, out);
    };
    mockApi({
      ...session(),
      "GET /platform/users": json(200, users()),
      "POST /platform/users": (req) => rec(req, 201, platformUser(PU_OTHER)),
      [`PATCH /platform/users/${PU_OTHER}`]: (req) => rec(req, 200, platformUser(PU_OTHER, { role: "platform_support" })),
      [`DELETE /platform/users/${PU_OTHER}`]: (req) => rec(req, 200, platformUser(PU_OTHER, { status: "disabled" })),
    });
    renderApp({ path: "/platform/users", console: "platform" });
    await userEvent.click(await screen.findByRole("button", { name: "Thêm nhân sự" }));
    let dialog = await screen.findByRole("dialog", { name: "Thêm nhân sự nền tảng" });
    const roles = within(dialog).getByLabelText("Role");
    expect(within(roles).getAllByRole("option").map((o) => o.getAttribute("value"))).toEqual(["platform_operator", "platform_support", "platform_viewer"]);
    await userEvent.type(within(dialog).getByLabelText("Subject (sub) ở IdP platform"), "0d8c0b5e-1111-4222-8333-444455556666");
    await userEvent.selectOptions(roles, "platform_operator");
    await userEvent.click(within(dialog).getByRole("button", { name: "Thêm nhân sự" }));
    await waitFor(() => {
      expect(screen.queryByRole("dialog")).toBeNull();
    });
    const rows = screen.getAllByTestId("platform-user");
    await userEvent.click(within(rows[1]!).getByRole("button", { name: "Sửa Second Admin" }));
    dialog = await screen.findByRole("dialog", { name: "Sửa Second Admin" });
    expect(within(dialog).getByRole("button", { name: "Lưu" })).toBeDisabled();
    await userEvent.selectOptions(within(dialog).getByLabelText("Role"), "platform_support");
    await userEvent.click(within(dialog).getByRole("button", { name: "Lưu" }));
    await waitFor(() => {
      expect(screen.queryByRole("dialog")).toBeNull();
    });
    await userEvent.click(within(screen.getAllByTestId("platform-user")[1]!).getByRole("button", { name: "Khóa Second Admin" }));
    const confirm = await screen.findByRole("alertdialog", { name: "Khóa Second Admin?" });
    await userEvent.click(within(confirm).getByRole("button", { name: "Khóa…" }));
    await waitFor(() => {
      expect(calls).toHaveLength(3);
    });
    expect(calls[0]).toMatchObject({ m: "POST", ifMatch: null, body: { subject: "0d8c0b5e-1111-4222-8333-444455556666", role: "platform_operator" } });
    expect(calls[0]!.key).toMatch(UUID4);
    expect(calls[1]).toEqual({ m: "PATCH", key: null, ifMatch: '"3"', body: { role: "platform_support" } });
    expect(calls[2]).toEqual({ m: "DELETE", key: null, ifMatch: '"3"', body: null });
  });

  it("Platform Operator / Viewer: xem danh sách, không có nút nào", async () => {
    mockApi({ ...session("platform_operator"), "GET /platform/users": json(200, users()) });
    renderApp({ path: "/platform/users", console: "platform" });
    await screen.findAllByTestId("platform-user");
    expect(screen.queryByRole("button", { name: /Thêm nhân sự|Sửa|Khóa|Super Admin/ })).toBeNull();
  });
});

describe("Identity Providers", () => {
  it("issuer/client_id/driver chỉ đọc; IdP tenant ⇒ PATCH chỉ trường đổi + If-Match ⇒ 202 ⇒ trang phê duyệt", async () => {
    let req: { ifMatch: string | null; body: unknown } | null = null;
    const idpApproval = approval({ action: "platform.idp.update_tenant", resource_type: "identity_provider", resource_id: IDP_T, payload: { idp_id: IDP_T } });
    mockApi({
      ...session(),
      "GET /platform/identity-providers": json(200, { items: [idp(IDP_P), idp(IDP_T)], next_cursor: null }),
      [`GET /platform/identity-providers/${IDP_T}`]: json(200, idp(IDP_T), { ETag: '"5"' }),
      [`PATCH /platform/identity-providers/${IDP_T}`]: async (r) => {
        req = { ifMatch: r.headers.get("If-Match"), body: await r.json() };
        return json(202, idpApproval, { Location: `/api/v1/platform/approvals/${APPR1}` });
      },
      [`GET /platform/approvals/${APPR1}`]: json(200, idpApproval),
    });
    const { router } = renderApp({ path: "/platform/identity-providers", console: "platform" });
    const rows = await screen.findAllByTestId("idp-row");
    expect(rows).toHaveLength(2);
    await userEvent.click(within(rows[1]!).getByRole("link", { name: "https://id.example.test/realms/tenant-acme" }));
    expect(await screen.findByTestId("idp-issuer")).toHaveTextContent("tenant-acme");
    expect(screen.getByText("Đã đặt (không bao giờ hiển thị)")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Sửa ràng buộc claim…" }));
    const dialog = await screen.findByRole("dialog", { name: "Sửa ràng buộc claim" });
    expect(within(dialog).getByTestId("tenant-idp-2p")).toBeInTheDocument();
    expect(within(dialog).queryByLabelText(/Issuer/)).toBeNull();
    const rc = within(dialog).getByLabelText("Claim bắt buộc (JSON)");
    await userEvent.clear(rc);
    await userEvent.paste('{"sub": "x"}');
    await userEvent.click(within(dialog).getByRole("button", { name: "Gửi yêu cầu thay đổi" }));
    expect(rc).toHaveAttribute("aria-invalid", "true");
    expect(req).toBeNull();
    await userEvent.clear(rc);
    await userEvent.paste('{"groups": ["staff"]}');
    await userEvent.type(within(dialog).getByLabelText("Domain email được phép"), "{enter}Acme.Example");
    await userEvent.click(within(dialog).getByRole("button", { name: "Gửi yêu cầu thay đổi" }));
    await screen.findByTestId("approval-requested");
    expect(router.state.location.pathname).toBe(`/platform/approvals/${APPR1}`);
    expect(req).toEqual({ ifMatch: '"5"', body: { allowed_email_domains: ["acme.example", "example.test"] } });
    expect(screen.getByRole("link", { name: `identity_provider:${IDP_T}` })).toHaveAttribute("href", `/platform/identity-providers/${IDP_T}`);
  });

  it("IdP platform ⇒ 200 áp dụng ngay (ở lại trang); Viewer không có nút sửa", async () => {
    let patched = 0;
    mockApi({
      ...session(),
      [`GET /platform/identity-providers/${IDP_P}`]: () => json(200, idp(IDP_P, patched ? { claim_mapping: { name: "preferred_username" } } : {}), { ETag: '"5"' }),
      [`PATCH /platform/identity-providers/${IDP_P}`]: async (r) => {
        patched += 1;
        expect(await r.json()).toEqual({ claim_mapping: { name: "preferred_username" } });
        return json(200, idp(IDP_P, { claim_mapping: { name: "preferred_username" } }));
      },
    });
    const { router, unmount } = renderApp({ path: `/platform/identity-providers/${IDP_P}`, console: "platform" });
    await userEvent.click(await screen.findByRole("button", { name: "Sửa ràng buộc claim…" }));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).queryByTestId("tenant-idp-2p")).toBeNull();
    await userEvent.type(within(dialog).getByLabelText("Trường name ← claim"), "preferred_username");
    await userEvent.click(within(dialog).getByRole("button", { name: "Lưu" }));
    await waitFor(() => {
      expect(screen.queryByRole("dialog")).toBeNull();
    });
    expect(await screen.findByText("preferred_username")).toBeInTheDocument();
    expect(router.state.location.pathname).toBe(`/platform/identity-providers/${IDP_P}`);
    expect(patched).toBe(1);
    unmount();
    mockApi({ ...session("platform_viewer"), [`GET /platform/identity-providers/${IDP_P}`]: json(200, idp(IDP_P), { ETag: '"5"' }) });
    renderApp({ path: `/platform/identity-providers/${IDP_P}`, console: "platform" });
    await screen.findByTestId("idp-issuer");
    expect(screen.queryByRole("button", { name: "Sửa ràng buộc claim…" })).toBeNull();
  });
});

describe("Gói dịch vụ", () => {
  it("tạo: thiếu khóa quota bị chặn ở client; POST Idempotency-Key + PlanLimits đúng; sửa: PATCH If-Match chỉ trường đổi", async () => {
    const calls: { m: string; key: string | null; ifMatch: string | null; body: unknown }[] = [];
    mockApi({
      ...session(),
      "GET /platform/plans": json(200, { items: [plan()] }),
      "POST /platform/plans": async (req) => {
        calls.push({ m: "POST", key: req.headers.get("Idempotency-Key"), ifMatch: null, body: await req.json() });
        return json(201, plan({ key: "pro" }));
      },
      [`PATCH /platform/plans/${PLAN1}`]: async (req) => {
        calls.push({ m: "PATCH", key: null, ifMatch: req.headers.get("If-Match"), body: await req.json() });
        return json(200, plan());
      },
    });
    renderApp({ path: "/platform/plans", console: "platform" });
    const row = await screen.findByTestId("plan-row");
    expect(row).toHaveTextContent("Thiết bị tối đa: 100");
    await userEvent.click(screen.getByRole("button", { name: "Tạo gói" }));
    let dialog = await screen.findByRole("dialog", { name: "Tạo gói dịch vụ" });
    await userEvent.type(within(dialog).getByLabelText("Khóa gói"), "pro");
    await userEvent.type(within(dialog).getByLabelText("Tên gói"), "Pro");
    for (const [label, v] of [["Thiết bị tối đa", "500"], ["Người dùng tối đa", "200"], ["Thiết bị gắn tag tối đa", "50"]] as const) {
      await userEvent.type(within(dialog).getByLabelText(label), v);
    }
    await userEvent.click(within(dialog).getByRole("button", { name: "Tạo gói" }));
    expect(within(dialog).getByLabelText("Mã enrollment còn hiệu lực tối đa")).toHaveAttribute("aria-invalid", "true");
    await userEvent.type(within(dialog).getByLabelText("Mã enrollment còn hiệu lực tối đa"), "20");
    await userEvent.type(within(dialog).getByLabelText("CPU của instance"), "1.5");
    await userEvent.click(within(dialog).getByRole("button", { name: "Tạo gói" }));
    await waitFor(() => {
      expect(screen.queryByRole("dialog")).toBeNull();
    });
    expect(calls[0]!.key).toMatch(UUID4);
    expect(calls[0]!.body).toEqual({ key: "pro", name: "Pro", is_active: true, limits: { max_devices: 500, max_users: 200, max_tagged_devices: 50, max_live_enrollment_credentials: 20, instance: { cpus: 1.5 } } });

    await userEvent.click(screen.getByRole("button", { name: "Sửa gói standard" }));
    dialog = await screen.findByRole("dialog", { name: "Sửa gói standard" });
    expect(within(dialog).getByLabelText("Khóa gói")).toHaveAttribute("readonly");
    await userEvent.click(within(dialog).getByLabelText("Đang mở (nhận tenant mới)"));
    await userEvent.click(within(dialog).getByRole("button", { name: "Lưu" }));
    await waitFor(() => {
      expect(calls).toHaveLength(2);
    });
    expect(calls[1]).toEqual({ m: "PATCH", key: null, ifMatch: '"1"', body: { is_active: false } });
  });
});

describe("Sửa tenant", () => {
  it("PATCH với If-Match = ETag của chi tiết; gói chọn từ danh sách gói đang mở; 412 ⇒ báo + tải lại", async () => {
    const patches: { ifMatch: string | null; body: unknown }[] = [];
    let n = 0;
    mockApi({
      ...session("platform_operator"),
      [`GET /platform/tenants/${T1}`]: () => json(200, tenant(T1, "acme"), { ETag: n > 0 ? '"4"' : '"3"' }),
      [`GET /platform/tenants/${T1}/instances`]: json(200, { items: [], next_cursor: null }),
      [`GET /platform/tenants/${T1}/relay-regions`]: json(200, { items: [], next_cursor: null, unavailable: [] }),
      [`GET /platform/tenants/${T1}/jobs`]: json(200, { items: [], next_cursor: null }),
      "GET /platform/plans": json(200, { items: [plan(), plan({ id: "0190fa00-0000-7000-8000-000000000002", key: "pro", name: "Pro" }), plan({ id: "0190fa00-0000-7000-8000-000000000003", key: "old", name: "Old", is_active: false })] }),
      [`PATCH /platform/tenants/${T1}`]: async (req) => {
        patches.push({ ifMatch: req.headers.get("If-Match"), body: await req.json() });
        n += 1;
        return n === 1 ? problem(412, "precondition_failed") : json(200, tenant(T1, "acme"));
      },
    });
    renderApp({ path: `/platform/tenants/${T1}`, console: "platform" });
    await userEvent.click(await screen.findByRole("button", { name: "Sửa…" }));
    const dialog = await screen.findByRole("dialog", { name: "Sửa tenant acme" });
    const planSel = within(dialog).getByLabelText("Gói dịch vụ (plan_key)");
    expect(within(planSel).getAllByRole("option").map((o) => o.getAttribute("value"))).toEqual(["standard", "pro"]);
    await userEvent.selectOptions(planSel, "pro");
    await userEvent.click(within(dialog).getByRole("button", { name: "Lưu" }));
    expect(await within(dialog).findByRole("alert")).toHaveTextContent("Dữ liệu đã bị thay đổi");
    await userEvent.click(within(dialog).getByRole("button", { name: "Hủy" }));
    await userEvent.click(screen.getByRole("button", { name: "Sửa…" }));
    const again = await screen.findByRole("dialog", { name: "Sửa tenant acme" });
    await userEvent.selectOptions(within(again).getByLabelText("Gói dịch vụ (plan_key)"), "pro");
    await userEvent.click(within(again).getByLabelText("Thay toàn bộ override hạn mức"));
    await userEvent.type(within(again).getByLabelText("Thiết bị tối đa"), "75");
    await userEvent.click(within(again).getByRole("button", { name: "Lưu" }));
    await waitFor(() => {
      expect(screen.queryByRole("dialog")).toBeNull();
    });
    expect(patches).toEqual([
      { ifMatch: '"3"', body: { plan_key: "pro" } },
      { ifMatch: '"4"', body: { plan_key: "pro", limits_override: { max_devices: 75 } } },
    ]);
  });
});

describe("Điều hướng P4-T03", () => {
  it("mọi mục của P4-T03 đã xây; Platform Support không thấy thiết lập/nhân sự/IdP", async () => {
    const { PLATFORM_NAV } = await import("../nav/navModel");
    expect(PLATFORM_NAV.filter((i) => i.task === "P4-T03").every((i) => i.available)).toBe(true);
    mockApi({ ...session("platform_support"), "GET /platform/hosts": json(200, { items: [], next_cursor: null }) });
    renderApp({ path: "/platform/hosts", console: "platform" });
    await screen.findByTestId("empty");
    const nav = screen.getByRole("navigation", { name: "Điều hướng chính" });
    expect(within(nav).getByRole("link", { name: /Host/ })).toBeInTheDocument();
    expect(within(nav).queryByRole("link", { name: /Thiết lập hệ thống|Nhân sự nền tảng|Identity Provider/ })).toBeNull();
  });
});
