// Tenant Portal (P4-T04): dashboard, devices (lọc/phân trang, chi tiết, rename, thu hồi hai pha, xóa, sync), Relay,
// hộp thông báo (danh sách, đánh dấu đã đọc, badge) — chạy cả App trên router bộ nhớ với API giả ở tầng fetch theo
// đúng hợp đồng của spec (JSON / problem+json, header). Mọi query key bắt đầu bằng tenantId (queryKeyHashFn từ chối
// key khác — một key sai làm test hỏng).
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { i18n } from "../i18n";
import { CSRF, json, mockApi, problem, renderApp, TENANT_A, tenantBody, tenantSession } from "../test/helpers";
import { DASHBOARD, DEV_1, DEV_2, device, JOB_1, job, notification, RELAY, SYNCED, tagged } from "../test/portal";

const ROLE_MEMBERSHIP = "0190d000-0000-7000-8000-000000000000"; // membership_id của tenantSession (chỉ số 0)
const base = `/tenants/${TENANT_A}`;

function session(role: string) {
  return json(200, tenantSession([{ tenantId: TENANT_A, slug: "tenant-a", name: "Tenant A", role }]));
}

function routes(role: string, extra: Record<string, Response | ((r: Request) => Response | Promise<Response>)> = {}) {
  return {
    "GET /auth/session": session(role),
    [`GET ${base}`]: json(200, tenantBody(TENANT_A, "tenant-a")),
    [`GET ${base}/notifications`]: json(200, { items: [], next_cursor: null }),
    ...extra,
  };
}

const list = (items: unknown[], next: string | null = null) => json(200, { items, next_cursor: next });

describe("dashboard", () => {
  it("số liệu thật kèm synced_at/checked_at; mục không có nguồn ⇒ không khả dụng kèm lý do; thẻ rà soát tagged node", async () => {
    const { requests } = mockApi(
      routes("tenant_owner", {
        [`GET ${base}/dashboard`]: json(200, DASHBOARD),
        [`GET ${base}/devices`]: list([tagged()]),
      }),
    );
    renderApp({ path: `/t/${TENANT_A}/overview` });
    expect(await screen.findByTestId("dash-total")).toHaveTextContent("3");
    expect(screen.getByTestId("dash-online")).toHaveTextContent("2");
    const devices = screen.getByTestId("dash-devices");
    expect(within(devices).getByText(/Đồng bộ từ Headscale lúc/)).toBeInTheDocument();
    expect(devices.querySelector(`time[datetime="${SYNCED}"]`)).not.toBeNull();
    expect(screen.getByTestId("dash-instance-status")).toHaveTextContent("Lỗi");
    expect(screen.getByTestId("dash-instance")).toHaveTextContent("API key của nền tảng bị từ chối.");
    const unavailable = screen.getAllByTestId("unavailable-section").map((e) => e.textContent);
    expect(unavailable).toHaveLength(2);
    expect(unavailable[0]).toContain("Nền tảng chưa có nguồn dữ liệu");
    expect(unavailable[0]).toContain("no_source");
    expect(await screen.findByTestId("dash-review-count")).toHaveTextContent("1");
    const review = requests.find((r) => r.url.includes("/devices"));
    expect(new URL(review!.url).searchParams.get("tagged")).toBe("true");
    expect(new URL(review!.url).searchParams.get("has_expiry")).toBe("false");
  });

  it("sổ thiết bị chưa từng sync ⇒ không hiện số đếm (không số giả)", async () => {
    mockApi(
      routes("tenant_viewer", {
        [`GET ${base}/dashboard`]: json(200, {
          devices: { total: 0, online: 0, synced_at: null },
          instance: { status: "unknown", checked_at: null, reason: "never_checked" },
          unavailable: [{ section: "devices", reason: "never_synced" }],
        }),
        [`GET ${base}/devices`]: list([]),
      }),
    );
    renderApp({ path: `/t/${TENANT_A}/overview` });
    const box = await screen.findByTestId("dash-devices");
    await waitFor(() => expect(within(box).getByTestId("unavailable-section")).toHaveTextContent("chưa từng được đồng bộ"));
    expect(screen.queryByTestId("dash-total")).toBeNull();
    expect(screen.getByTestId("dash-instance")).toHaveTextContent("chưa từng");
  });
});

describe("devices", () => {
  it("danh sách: cột thật, không cột OS/phiên bản client (HS-14), bộ lọc ⇒ tham số API, phân trang cursor", async () => {
    const { requests } = mockApi(
      routes("tenant_admin", {
        [`GET ${base}/devices`]: (req) => {
          const c = new URL(req.url).searchParams.get("cursor");
          return c === "c2" ? list([device(DEV_2)]) : list([device(DEV_1), tagged()], "c2");
        },
      }),
    );
    renderApp({ path: `/t/${TENANT_A}/devices` });
    const table = await screen.findByTestId("devices-table");
    const headers = within(table).getAllByRole("columnheader").map((h) => h.textContent);
    expect(headers).toEqual(["Tên", "Chủ sở hữu", "Tag", "Địa chỉ tailnet", "Trạng thái", "Thấy lần cuối", "Hạn"]);
    expect(screen.getByText(/Headscale API không cung cấp/)).toBeInTheDocument();
    expect(within(table).getByText("tag:server")).toBeInTheDocument();
    expect(within(table).getByText("Thuộc tag (không có chủ)")).toBeInTheDocument();
    expect(within(table).getAllByText("Không hết hạn")).toHaveLength(1);

    await userEvent.click(screen.getByRole("button", { name: "Trang sau" }));
    await waitFor(() => expect(screen.getAllByTestId("device-row")).toHaveLength(1));
    expect(requests.some((r) => new URL(r.url).searchParams.get("cursor") === "c2")).toBe(true);
    await userEvent.click(screen.getByRole("button", { name: "Trang trước" }));
    await waitFor(() => expect(screen.getAllByTestId("device-row")).toHaveLength(2));

    await userEvent.selectOptions(screen.getByLabelText("Trạng thái"), "no");
    await userEvent.click(screen.getByLabelText("Chỉ thiết bị của tôi"));
    await waitFor(() => {
      const last = new URL(requests.filter((r) => r.url.includes("/devices"))[requests.filter((r) => r.url.includes("/devices")).length - 1]!.url);
      expect(last.searchParams.get("online")).toBe("false");
      expect(last.searchParams.get("owner")).toBe(ROLE_MEMBERSHIP);
    });
    await userEvent.type(screen.getByLabelText("Tag"), "server");
    expect(screen.getByText(/Tag phải có dạng/)).toBeInTheDocument();
  });

  it("báo cáo rà soát: ?view=review ⇒ tagged=true&has_expiry=false", async () => {
    const { requests } = mockApi(routes("tenant_viewer", { [`GET ${base}/devices`]: list([tagged()]) }));
    renderApp({ path: `/t/${TENANT_A}/devices?view=review` });
    await screen.findByTestId("review-banner");
    await screen.findByTestId("devices-table");
    const q = new URL(requests.find((r) => r.url.includes("/devices"))!.url).searchParams;
    expect(q.get("tagged")).toBe("true");
    expect(q.get("has_expiry")).toBe("false");
    expect(screen.queryByRole("button", { name: "Đồng bộ từ Headscale" })).toBeNull(); // TV: không có device:sync
  });

  it("làm mới từ Headscale: fresh=true trang 1", async () => {
    const { requests } = mockApi(routes("tenant_operator", { [`GET ${base}/devices`]: list([device(DEV_1)]) }));
    renderApp({ path: `/t/${TENANT_A}/devices` });
    await screen.findByTestId("devices-table");
    await userEvent.click(screen.getByRole("button", { name: "Làm mới từ Headscale" }));
    await waitFor(() => expect(requests.some((r) => new URL(r.url).searchParams.get("fresh") === "true")).toBe(true));
    const f = requests.find((r) => new URL(r.url).searchParams.get("fresh") === "true")!;
    expect(new URL(f.url).searchParams.get("cursor")).toBeNull();
  });

  it("đồng bộ: POST sync (CSRF + Idempotency-Key) ⇒ 202 Location ⇒ poll job tới succeeded ⇒ tải lại danh sách", async () => {
    let jobCalls = 0;
    const { requests } = mockApi(
      routes("tenant_operator", {
        [`GET ${base}/devices`]: list([device(DEV_1)]),
        [`POST ${base}/devices/sync`]: json(202, job("queued"), { Location: `/api/v1/tenants/${TENANT_A}/jobs/${JOB_1}` }),
        [`GET ${base}/jobs/${JOB_1}`]: () => json(200, job(++jobCalls > 1 ? "succeeded" : "running")),
      }),
    );
    renderApp({ path: `/t/${TENANT_A}/devices` });
    await screen.findByTestId("devices-table");
    const before = requests.filter((r) => r.method === "GET" && r.url.includes("/devices")).length;
    await userEvent.click(screen.getByRole("button", { name: "Đồng bộ từ Headscale" }));
    await waitFor(() => expect(screen.getByTestId("sync-status")).toHaveTextContent("Thành công"), { timeout: 6000 });
    const post = requests.find((r) => r.method === "POST")!;
    expect(post.headers.get("X-CSRF-Token")).toBe(CSRF);
    expect(post.headers.get("Idempotency-Key")).toMatch(/^[0-9a-f-]{36}$/);
    await waitFor(() => expect(requests.filter((r) => r.method === "GET" && r.url.includes("/devices")).length).toBeGreaterThan(before));
  });

  it("End User: không nút đồng bộ; không có bộ lọc theo chủ khác (server lọc thiết bị của chính mình)", async () => {
    const { requests } = mockApi(routes("end_user", { [`GET ${base}/devices`]: list([device(DEV_1)]) }));
    renderApp({ path: `/t/${TENANT_A}/devices` });
    await screen.findByTestId("devices-table");
    expect(screen.queryByRole("button", { name: "Đồng bộ từ Headscale" })).toBeNull();
    expect(new URL(requests.find((r) => r.url.includes("/devices"))!.url).searchParams.get("owner")).toBeNull();
  });
});

describe("device detail", () => {
  it("expire hai pha: xác nhận ⇒ POST expire (Idempotency-Key) ⇒ pending (chưa 'đã áp dụng') ⇒ poll ⇒ applied", async () => {
    let reads = 0;
    const pending = device(DEV_1, { revocation: { state: "pending", kind: "expire", requested_at: SYNCED } });
    const applied = device(DEV_1, { revocation: { state: "applied", kind: "expire", requested_at: SYNCED, verified_at: "2026-11-19T01:00:03Z" } });
    const { requests } = mockApi(
      routes("end_user", {
        [`GET ${base}/devices/${DEV_1}`]: () => json(200, reads++ === 0 ? device(DEV_1) : reads > 2 ? applied : pending),
        [`POST ${base}/devices/${DEV_1}/expire`]: json(202, pending, { Location: `/api/v1/tenants/${TENANT_A}/jobs/${JOB_1}` }),
      }),
    );
    renderApp({ path: `/t/${TENANT_A}/devices/${DEV_1}` });
    await screen.findByRole("heading", { name: "laptop-1", level: 1 });
    await userEvent.click(screen.getByRole("button", { name: "Thu hồi (expire)" }));
    const dialog = screen.getByRole("alertdialog");
    expect(within(dialog).getByRole("button", { name: "Hủy" })).toHaveFocus();
    await userEvent.click(within(dialog).getByRole("button", { name: "Thu hồi (expire)" }));
    const panel = await screen.findByTestId("revocation-panel");
    expect(panel).toHaveTextContent("đang chờ Headscale xác nhận");
    expect(panel).not.toHaveTextContent("Đã áp dụng");
    expect(screen.queryByRole("alertdialog")).toBeNull();
    const post = requests.find((r) => r.method === "POST")!;
    expect(post.headers.get("Idempotency-Key")).toMatch(/^[0-9a-f-]{36}$/);
    expect(post.headers.get("X-CSRF-Token")).toBe(CSRF);
    await waitFor(() => expect(screen.getByTestId("revocation-panel")).toHaveTextContent("Đã áp dụng thu hồi (expire)"), { timeout: 8000 });
    expect(screen.getByTestId("revocation-panel")).toHaveTextContent("Xác nhận lúc");
  }, 15_000);

  it("expire lỗi ⇒ bấm lại dùng CÙNG Idempotency-Key; Hủy ⇒ khóa mới", async () => {
    let n = 0;
    const { requests } = mockApi(
      routes("tenant_admin", {
        [`GET ${base}/devices/${DEV_1}`]: json(200, device(DEV_1)),
        [`POST ${base}/devices/${DEV_1}/expire`]: () => (++n === 1 ? problem(503, "instance_unavailable") : problem(409, "conflict")),
      }),
    );
    renderApp({ path: `/t/${TENANT_A}/devices/${DEV_1}` });
    await screen.findByRole("heading", { name: "laptop-1", level: 1 });
    await userEvent.click(screen.getByRole("button", { name: "Thu hồi (expire)" }));
    const confirm = () => userEvent.click(within(screen.getByRole("alertdialog")).getByRole("button", { name: "Thu hồi (expire)" }));
    await confirm();
    await within(screen.getByRole("alertdialog")).findByRole("alert");
    await confirm();
    await waitFor(() => expect(requests.filter((r) => r.method === "POST")).toHaveLength(2));
    const keys = requests.filter((r) => r.method === "POST").map((r) => r.headers.get("Idempotency-Key"));
    expect(keys[0]).toBe(keys[1]);
    await userEvent.keyboard("{Escape}");
    expect(screen.queryByRole("alertdialog")).toBeNull();
    await userEvent.click(screen.getByRole("button", { name: "Thu hồi (expire)" }));
    await confirm();
    await waitFor(() => expect(requests.filter((r) => r.method === "POST")).toHaveLength(3));
    expect(requests.filter((r) => r.method === "POST")[2]!.headers.get("Idempotency-Key")).not.toBe(keys[0]);
  });

  it("xóa: xác nhận ⇒ DELETE ⇒ pending ⇒ đọc lại 404 ⇒ 'đã xóa' (Headscale xác nhận)", async () => {
    let deleted = false;
    const pending = device(DEV_1, { revocation: { state: "pending", kind: "delete", requested_at: SYNCED } });
    mockApi(
      routes("tenant_owner", {
        [`GET ${base}/devices/${DEV_1}`]: () => (deleted ? problem(404, "not_found") : json(200, device(DEV_1))),
        [`DELETE ${base}/devices/${DEV_1}`]: () => {
          deleted = true;
          return json(202, pending, { Location: `/api/v1/tenants/${TENANT_A}/jobs/${JOB_1}` });
        },
      }),
    );
    renderApp({ path: `/t/${TENANT_A}/devices/${DEV_1}` });
    await screen.findByRole("heading", { name: "laptop-1", level: 1 });
    await userEvent.click(screen.getByRole("button", { name: "Xóa thiết bị" }));
    expect(screen.getByRole("alertdialog")).toHaveTextContent("Xóa thiết bị laptop-1?");
    await userEvent.click(within(screen.getByRole("alertdialog")).getByRole("button", { name: "Xóa thiết bị" }));
    expect(await screen.findByTestId("revocation-panel")).toHaveTextContent("đang chờ");
    expect(await screen.findByTestId("device-deleted", {}, { timeout: 6000 })).toBeInTheDocument();
  }, 12_000);

  it("rename: nhãn DNS sai ⇒ không gửi; đúng ⇒ PATCH {given_name} ⇒ hiển thị tên mới", async () => {
    const { requests } = mockApi(
      routes("tenant_operator", {
        [`GET ${base}/devices/${DEV_1}`]: json(200, device(DEV_1)),
        [`PATCH ${base}/devices/${DEV_1}`]: async (req) => {
          const body = (await req.json()) as { given_name: string };
          return json(200, device(DEV_1, { given_name: body.given_name }));
        },
      }),
    );
    renderApp({ path: `/t/${TENANT_A}/devices/${DEV_1}` });
    await screen.findByRole("heading", { name: "laptop-1", level: 1 });
    const input = screen.getByLabelText("Tên trong tailnet (nhãn DNS)");
    await userEvent.clear(input);
    await userEvent.type(input, "-bad-");
    expect(input).toHaveAttribute("aria-invalid", "true");
    expect(screen.getByRole("button", { name: "Lưu tên" })).toBeDisabled();
    await userEvent.clear(input);
    await userEvent.type(input, "Build-01");
    await userEvent.click(screen.getByRole("button", { name: "Lưu tên" }));
    await screen.findByRole("heading", { name: "build-01", level: 1 });
    const patch = requests.find((r) => r.method === "PATCH")!;
    expect(await patch.json()).toEqual({ given_name: "build-01" });
    expect(patch.headers.get("X-CSRF-Token")).toBe(CSRF);
  });

  it("quyền theo role: Tenant Viewer không có rename/expire/delete; Operator không có delete", async () => {
    mockApi(routes("tenant_viewer", { [`GET ${base}/devices/${DEV_1}`]: json(200, device(DEV_1)) }));
    const { unmount } = renderApp({ path: `/t/${TENANT_A}/devices/${DEV_1}` });
    await screen.findByRole("heading", { name: "laptop-1", level: 1 });
    expect(screen.queryByLabelText("Tên trong tailnet (nhãn DNS)")).toBeNull();
    expect(screen.queryByRole("button", { name: "Thu hồi (expire)" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Xóa thiết bị" })).toBeNull();
    unmount();
    mockApi(routes("tenant_operator", { [`GET ${base}/devices/${DEV_1}`]: json(200, device(DEV_1)) }));
    renderApp({ path: `/t/${TENANT_A}/devices/${DEV_1}` });
    await screen.findByRole("heading", { name: "laptop-1", level: 1 });
    expect(screen.getByRole("button", { name: "Thu hồi (expire)" })).toBeEnabled();
    expect(screen.queryByRole("button", { name: "Xóa thiết bị" })).toBeNull();
  });

  it("thiết bị không thấy được (thiết bị của người khác với End User, tenant khác) ⇒ 404 thống nhất; id không phải UUID ⇒ 404 không gọi API", async () => {
    const { requests } = mockApi(routes("end_user", { [`GET ${base}/devices/${DEV_2}`]: problem(404, "not_found") }));
    const { router } = renderApp({ path: `/t/${TENANT_A}/devices/${DEV_2}` });
    await screen.findByRole("heading", { name: "Không tìm thấy", level: 1 });
    await router.navigate(`/t/${TENANT_A}/devices/khong-phai-uuid`);
    await screen.findByRole("heading", { name: "Không tìm thấy", level: 1 });
    expect(requests.some((r) => r.url.includes("khong-phai-uuid"))).toBe(false);
  });

  it("tenant suspended (banner chỉ-đọc): mọi nút ghi bị khóa", async () => {
    mockApi({
      ...routes("tenant_owner", { [`GET ${base}/devices/${DEV_1}`]: json(200, device(DEV_1)) }),
      [`GET ${base}`]: json(200, tenantBody(TENANT_A, "tenant-a", "suspended")),
    });
    renderApp({ path: `/t/${TENANT_A}/devices/${DEV_1}` });
    await screen.findByTestId("tenant-suspended");
    await screen.findByRole("heading", { name: "laptop-1", level: 1 });
    expect(screen.getByRole("button", { name: "Thu hồi (expire)" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Xóa thiết bị" })).toBeDisabled();
    expect(screen.getByLabelText("Tên trong tailnet (nhãn DNS)")).toBeDisabled();
  });
});

describe("relay", () => {
  it("region được gán + health kèm checked_at + phép kiểm; số đo không có nguồn ⇒ không khả dụng kèm lý do", async () => {
    mockApi(routes("tenant_viewer", { [`GET ${base}/relay`]: json(200, RELAY) }));
    renderApp({ path: `/t/${TENANT_A}/relay` });
    const card = await screen.findByTestId("relay-assignment");
    expect(card).toHaveTextContent("mg-tenant-a");
    expect(card).toHaveTextContent("DERP 443 · STUN 3478");
    expect(within(card).getByTestId("relay-health")).toHaveTextContent("Lỗi");
    expect(card).toHaveTextContent("Probe STUN không đạt.");
    expect(card).toHaveTextContent("timeout");
    expect(card.querySelector('time[datetime="2026-11-19T01:02:00Z"]')).not.toBeNull();
    const u = screen.getAllByTestId("unavailable-section").map((e) => e.textContent);
    expect(u).toHaveLength(2);
    expect(u[0]).toContain("DERP nhúng không xuất metrics relay");
  });

  it("chưa có relay ⇒ thông báo rỗng; End User không có mục Relay", async () => {
    mockApi(routes("tenant_admin", { [`GET ${base}/relay`]: json(200, { assignments: [], unavailable: [] }) }));
    const { unmount } = renderApp({ path: `/t/${TENANT_A}/relay` });
    await screen.findByTestId("relay-empty");
    unmount();
    mockApi(routes("end_user"));
    renderApp({ path: `/t/${TENANT_A}/relay` });
    await screen.findByRole("heading", { name: "Không có quyền", level: 1 });
  });
});

describe("notifications", () => {
  const N1 = "0190a400-0000-7000-8000-000000000001";
  const N2 = "0190a400-0000-7000-8000-000000000002";

  it("danh sách + câu theo kind; đánh dấu đã đọc ⇒ POST …/{id}/read (CSRF) ⇒ badge giảm", async () => {
    let read = false;
    const items = () => [
      notification(N1, { read_at: read ? SYNCED : null }),
      notification(N2, { kind: "policy.applied", payload: { version: 7, trigger: "manual", tenant_name: "<script>x</script>" }, read_at: SYNCED }),
    ];
    const { requests } = mockApi(
      routes("end_user", {
        [`GET ${base}/notifications`]: (req) => {
          const unread = new URL(req.url).searchParams.get("unread") === "true";
          return list(items().filter((n) => !unread || n.read_at === null));
        },
        [`POST ${base}/notifications/${N1}/read`]: () => {
          read = true;
          return json(200, notification(N1, { read_at: SYNCED }));
        },
      }),
    );
    renderApp({ path: `/t/${TENANT_A}/notifications` });
    const rows = await screen.findAllByTestId("notification");
    expect(rows[0]).toHaveTextContent("Thiết bị laptop-1 sẽ hết hạn lúc");
    expect(rows[1]).toHaveTextContent("Policy phiên bản 7 đã được áp dụng (trigger manual).");
    expect(within(rows[0]!).getByRole("link", { name: "Xem thiết bị" })).toHaveAttribute("href", `/t/${TENANT_A}/devices/${DEV_1}`);
    expect(document.querySelector("script")).toBeNull();
    expect(await screen.findByTestId("nav-count")).toHaveTextContent("1");
    await userEvent.click(within(rows[0]!).getByRole("button", { name: "Đánh dấu đã đọc" }));
    await waitFor(() => expect(screen.queryByTestId("nav-count")).toBeNull());
    const post = requests.find((r) => r.method === "POST")!;
    expect(new URL(post.url).pathname).toBe(`/api/v1${base}/notifications/${N1}/read`);
    expect(post.headers.get("X-CSRF-Token")).toBe(CSRF);
    await waitFor(() => expect(screen.queryByRole("button", { name: "Đánh dấu đã đọc" })).toBeNull());
  });

  it("lọc chưa đọc ⇒ ?unread=true; kind lạ ⇒ câu chung; 'tải thêm' theo cursor", async () => {
    const { requests } = mockApi(
      routes("tenant_viewer", {
        [`GET ${base}/notifications`]: (req) => {
          const q = new URL(req.url).searchParams;
          if (q.get("cursor") === "n2") return list([notification(N2, { kind: "future.kind", payload: {} })]);
          return list([notification(N1)], q.get("limit") === "20" ? "n2" : null);
        },
      }),
    );
    renderApp({ path: `/t/${TENANT_A}/notifications` });
    await screen.findAllByTestId("notification");
    await userEvent.click(screen.getByRole("button", { name: "Tải thêm" }));
    expect(await screen.findByText("Thông báo future.kind.")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Chưa đọc" }));
    await waitFor(() =>
      expect(requests.some((r) => new URL(r.url).searchParams.get("unread") === "true" && new URL(r.url).searchParams.get("limit") === "20")).toBe(true),
    );
  });

  it("badge 99+ khi còn trang sau; tenant suspended ⇒ nút đánh dấu bị khóa", async () => {
    mockApi({
      ...routes("tenant_owner", {
        [`GET ${base}/notifications`]: (req) =>
          new URL(req.url).searchParams.get("limit") === "99"
            ? list(Array.from({ length: 99 }, (_, i) => notification(`0190a400-0000-7000-8000-${String(i).padStart(12, "0")}`)), "more")
            : list([notification(N1)]),
        [`GET ${base}/dashboard`]: json(200, DASHBOARD),
        [`GET ${base}/devices`]: list([]),
      }),
      [`GET ${base}`]: json(200, tenantBody(TENANT_A, "tenant-a", "suspended")),
    });
    renderApp({ path: `/t/${TENANT_A}/notifications` });
    expect(await screen.findByTestId("nav-count")).toHaveTextContent("99+");
    await screen.findByTestId("tenant-suspended");
    expect(await screen.findByRole("button", { name: "Đánh dấu đã đọc" })).toBeDisabled();
  });

  it("tiếng Anh", async () => {
    await i18n.changeLanguage("en");
    mockApi(routes("tenant_owner", { [`GET ${base}/notifications`]: list([notification(N1)]) }));
    renderApp({ path: `/t/${TENANT_A}/notifications` });
    expect(await screen.findByTestId("notification")).toHaveTextContent("Device laptop-1 expires at");
  });
});
