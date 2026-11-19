// Ba màn hình mạng của Tenant Portal (P4-T12): Routes (duyệt/gỡ duyệt — If-Match + Idempotency-Key, exit node bắt buộc
// xác nhận rủi ro, 202 4-eyes, 412), DNS (đổi nameserver — If-Match + hộp xác nhận restart + poll job; extra records —
// 422 theo field, xóa ⇒ job), Tài nguyên mạng (cursor, PATCH If-Match chỉ trường đổi, POST Idempotency-Key, 422 theo
// field). Chạy cả App trên router bộ nhớ, API giả ở tầng fetch theo đúng hợp đồng của spec.
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { CSRF, json, mockApi, problem, renderApp, TENANT_A, tenantBody, tenantSession } from "../../test/helpers";
import {
  APPROVAL_ID,
  approvalRequest,
  dnsRecord,
  dnsView,
  gateway,
  group,
  GW,
  laptopRouter,
  NET_JOB,
  NET_SYNCED,
  netJob,
  RECORD_1,
  resource,
  RESOURCE_1,
  GROUP_1,
  tag,
} from "../../test/network";
import { DEV_1, device } from "../../test/portal";

const base = `/tenants/${TENANT_A}`;
type Routes = Record<string, Response | ((r: Request) => Response | Promise<Response>)>;

function apiFor(role: string, extra: Routes = {}, status: "active" | "suspended" = "active"): Routes {
  return {
    "GET /auth/session": json(200, tenantSession([{ tenantId: TENANT_A, slug: "tenant-a", name: "Tenant A", role }])),
    [`GET ${base}`]: json(200, tenantBody(TENANT_A, "tenant-a", status)),
    [`GET ${base}/notifications`]: json(200, { items: [], next_cursor: null }),
    ...extra,
  };
}

const writes = (requests: Request[], method: string) => requests.filter((r) => r.method === method);
const UUID_RE = /^[0-9a-f-]{36}$/;

describe("routes", () => {
  const list = () => json(200, { items: [gateway(), laptopRouter()] });

  it("bảng router: route quảng bá/đã duyệt/chờ duyệt, exit node, synced_at, cảnh báo; Tenant Viewer chỉ đọc", async () => {
    mockApi(apiFor("tenant_viewer", { [`GET ${base}/routes`]: list() }));
    renderApp({ path: `/t/${TENANT_A}/routes` });
    const table = await screen.findByTestId("routes-table");
    const rows = within(table).getAllByTestId("route-row");
    expect(rows).toHaveLength(2);
    const gw = rows[0]!;
    expect(gw).toHaveTextContent("gw-1");
    expect(gw).toHaveTextContent("tag:router");
    expect(within(gw).getByTestId("pending-routes")).toHaveTextContent("192.168.1.0/24");
    expect(within(gw).getByTestId("pending-routes")).not.toHaveTextContent("10.0.0.0/24");
    expect(gw).toHaveTextContent("Quảng bá, chờ duyệt");
    expect(gw.querySelector(`time[datetime="${NET_SYNCED}"]`)).not.toBeNull();
    expect(gw).toHaveTextContent("192.168.1.0/24 chồng lấn với 192.168.0.0/16 của thiết bị laptop-an.");
    expect(rows[1]).toHaveTextContent("Router không có tag");
    expect(rows[1]).toHaveTextContent("192.168.0.0/16 chồng lấn với 192.168.1.0/24 của thiết bị gw-1.");
    // TV: không có route:approve, không có device:sync
    expect(within(table).queryByRole("columnheader", { name: "Thao tác" })).toBeNull();
    expect(screen.queryByRole("button", { name: /Duyệt|Gỡ duyệt/ })).toBeNull();
    expect(screen.queryByRole("button", { name: "Đồng bộ từ Headscale" })).toBeNull();
  });

  it("Tenant Operator: có nút đồng bộ (dùng lại sync thiết bị) nhưng không duyệt; End User không có mục", async () => {
    mockApi(apiFor("tenant_operator", { [`GET ${base}/routes`]: list() }));
    const { unmount } = renderApp({ path: `/t/${TENANT_A}/routes` });
    await screen.findByTestId("routes-table");
    expect(screen.getByRole("button", { name: "Đồng bộ từ Headscale" })).toBeEnabled();
    expect(screen.queryByRole("button", { name: /Duyệt|Gỡ duyệt/ })).toBeNull();
    unmount();
    mockApi(apiFor("end_user"));
    renderApp({ path: `/t/${TENANT_A}/routes` });
    await screen.findByRole("heading", { name: "Không có quyền", level: 1 });
  });

  it("duyệt route: hộp xác nhận nêu cảnh báo chồng lấn ⇒ POST approve với If-Match = routes_etag, Idempotency-Key, body {device_id, prefixes}", async () => {
    let approved = false;
    const after = gateway({ approved_routes: ["10.0.0.0/24", "192.168.1.0/24"], pending_routes: ["0.0.0.0/0", "::/0"], routes_etag: '"etag-gw-2"' });
    const { requests } = mockApi(
      apiFor("tenant_admin", {
        [`GET ${base}/routes`]: () => json(200, { items: [approved ? after : gateway(), laptopRouter()] }),
        [`POST ${base}/routes/approve`]: () => {
          approved = true;
          return json(200, after, { ETag: after.routes_etag });
        },
      }),
    );
    renderApp({ path: `/t/${TENANT_A}/routes` });
    await screen.findByTestId("routes-table");
    await userEvent.click(screen.getByRole("button", { name: "Duyệt route của gw-1" }));
    const dialog = screen.getByRole("alertdialog");
    expect(within(dialog).getByTestId("dialog-warnings")).toHaveTextContent("192.168.1.0/24 chồng lấn với 192.168.0.0/16 của thiết bị laptop-an.");
    expect(within(dialog).queryByTestId("exit-risk")).toBeNull();
    expect(within(dialog).getByLabelText("192.168.1.0/24")).toBeChecked();
    expect(within(dialog).queryByLabelText("0.0.0.0/0")).toBeNull(); // exit node chỉ qua hộp riêng
    await userEvent.click(within(dialog).getByRole("button", { name: "Duyệt route" }));
    expect(await screen.findByTestId("routes-done")).toHaveTextContent("Đã duyệt 192.168.1.0/24 trên gw-1");
    expect(screen.queryByRole("alertdialog")).toBeNull();
    const post = writes(requests, "POST")[0]!;
    expect(new URL(post.url).pathname).toBe(`/api/v1${base}/routes/approve`);
    expect(post.headers.get("If-Match")).toBe('"etag-gw-1"');
    expect(post.headers.get("Idempotency-Key")).toMatch(UUID_RE);
    expect(post.headers.get("X-CSRF-Token")).toBe(CSRF);
    expect(await post.json()).toEqual({ device_id: GW, prefixes: ["192.168.1.0/24"] });
    const row = screen.getAllByTestId("route-row")[0]!;
    await waitFor(() => expect(within(row).getByTestId("pending-routes")).not.toHaveTextContent("192.168.1.0/24"));
  });

  it("exit node: bắt buộc xác nhận rủi ro trước khi gửi ⇒ body có confirm_exit_node: true", async () => {
    const { requests } = mockApi(
      apiFor("tenant_owner", {
        [`GET ${base}/routes`]: list(),
        [`POST ${base}/routes/approve`]: json(200, gateway({ approved_routes: ["0.0.0.0/0", "10.0.0.0/24", "::/0"], exit_node: { advertised: true, approved: true } })),
      }),
    );
    renderApp({ path: `/t/${TENANT_A}/routes` });
    await screen.findByTestId("routes-table");
    await userEvent.click(screen.getByRole("button", { name: "Duyệt exit node gw-1" }));
    const dialog = screen.getByRole("alertdialog");
    expect(within(dialog).getByTestId("exit-risk")).toHaveTextContent("toàn bộ lưu lượng Internet");
    const confirm = within(dialog).getByRole("button", { name: "Duyệt exit node" });
    expect(confirm).toBeDisabled();
    await userEvent.click(confirm);
    expect(writes(requests, "POST")).toHaveLength(0);
    await userEvent.click(within(dialog).getByLabelText(/Tôi hiểu rủi ro/));
    expect(confirm).toBeEnabled();
    await userEvent.click(confirm);
    await screen.findByTestId("routes-done");
    const post = writes(requests, "POST")[0]!;
    expect(await post.json()).toEqual({ device_id: GW, prefixes: ["0.0.0.0/0", "::/0"], confirm_exit_node: true });
    expect(post.headers.get("If-Match")).toBe('"etag-gw-1"');
  });

  it("tenant bật 4-eyes: 202 ⇒ báo đã tạo yêu cầu phê duyệt (id từ Location), không báo đã duyệt", async () => {
    mockApi(
      apiFor("tenant_admin", {
        [`GET ${base}/routes`]: list(),
        [`POST ${base}/routes/approve`]: json(202, approvalRequest(), { Location: `/api/v1/tenants/${TENANT_A}/approvals/${APPROVAL_ID}` }),
      }),
    );
    renderApp({ path: `/t/${TENANT_A}/routes` });
    await screen.findByTestId("routes-table");
    await userEvent.click(screen.getByRole("button", { name: "Duyệt route của laptop-an" }));
    const dialog = screen.getByRole("alertdialog");
    expect(within(dialog).getByTestId("dialog-warnings")).toHaveTextContent("Router không có tag");
    await userEvent.click(within(dialog).getByRole("button", { name: "Duyệt route" }));
    const notice = await screen.findByTestId("approval-created");
    expect(notice).toHaveTextContent("Đã tạo yêu cầu phê duyệt — chưa có thay đổi nào");
    expect(within(notice).getByTestId("approval-id")).toHaveTextContent(APPROVAL_ID);
    expect(notice).toHaveTextContent("Chờ duyệt");
    expect(screen.queryByTestId("routes-done")).toBeNull();
  });

  it("412 ⇒ báo dữ liệu đã đổi, tải lại; xác nhận lại gửi ETag mới với Idempotency-Key mới", async () => {
    let reads = 0;
    let posts = 0;
    const { requests } = mockApi(
      apiFor("tenant_admin", {
        [`GET ${base}/routes`]: () => json(200, { items: [++reads > 1 ? gateway({ routes_etag: '"etag-gw-9"' }) : gateway(), laptopRouter()] }),
        [`POST ${base}/routes/approve`]: () => (++posts === 1 ? problem(412, "precondition_failed") : json(200, gateway())),
      }),
    );
    renderApp({ path: `/t/${TENANT_A}/routes` });
    await screen.findByTestId("routes-table");
    await userEvent.click(screen.getByRole("button", { name: "Duyệt route của gw-1" }));
    const confirm = () => userEvent.click(within(screen.getByRole("alertdialog")).getByRole("button", { name: "Duyệt route" }));
    await confirm();
    const dialog = screen.getByRole("alertdialog");
    expect(await within(dialog).findByRole("alert")).toHaveTextContent("Dữ liệu đã bị thay đổi bởi người khác");
    expect(dialog).toHaveTextContent("đã tải lại dữ liệu mới");
    await waitFor(() => expect(reads).toBeGreaterThan(1));
    await confirm();
    await screen.findByTestId("routes-done");
    const [first, second] = writes(requests, "POST");
    expect(first!.headers.get("If-Match")).toBe('"etag-gw-1"');
    expect(second!.headers.get("If-Match")).toBe('"etag-gw-9"');
    expect(second!.headers.get("Idempotency-Key")).not.toBe(first!.headers.get("Idempotency-Key"));
  });

  it("422 ⇒ ProblemAlert trong hộp; gỡ duyệt ⇒ POST revoke với If-Match, chỉ prefix đã chọn", async () => {
    let revokes = 0;
    const { requests } = mockApi(
      apiFor("tenant_owner", {
        [`GET ${base}/routes`]: list(),
        [`POST ${base}/routes/revoke`]: () =>
          ++revokes === 1
            ? problem(422, "validation_failed", { errors: [{ field: "prefixes", code: "route_not_approved", message: "these prefixes are not approved on the device: 10.0.0.0/24" }] })
            : json(200, gateway({ approved_routes: [] })),
      }),
    );
    renderApp({ path: `/t/${TENANT_A}/routes` });
    await screen.findByTestId("routes-table");
    await userEvent.click(screen.getByRole("button", { name: "Gỡ duyệt route của gw-1" }));
    const dialog = screen.getByRole("alertdialog");
    const confirm = within(dialog).getByRole("button", { name: "Gỡ duyệt" });
    expect(confirm).toBeDisabled(); // chưa chọn gì
    await userEvent.click(within(dialog).getByLabelText("10.0.0.0/24"));
    await userEvent.click(confirm);
    expect(await within(dialog).findByRole("alert")).toHaveTextContent("these prefixes are not approved");
    await userEvent.click(confirm);
    expect(await screen.findByTestId("routes-done")).toHaveTextContent("Đã gỡ duyệt 10.0.0.0/24 trên gw-1");
    const post = writes(requests, "POST")[1]!;
    expect(new URL(post.url).pathname).toBe(`/api/v1${base}/routes/revoke`);
    expect(post.headers.get("If-Match")).toBe('"etag-gw-1"');
    expect(post.headers.get("Idempotency-Key")).toBeNull();
    expect(await post.json()).toEqual({ device_id: GW, prefixes: ["10.0.0.0/24"] });
  });

  it("chi tiết thiết bị có route ⇒ liên kết tới Routes (role có tenant.route:read); End User không có", async () => {
    const withRoutes = device(DEV_1, { routes: { advertised: ["10.0.0.0/24"], approved: [], etag: "r0" } });
    mockApi(apiFor("tenant_admin", { [`GET ${base}/devices/${DEV_1}`]: json(200, withRoutes) }));
    const { unmount } = renderApp({ path: `/t/${TENANT_A}/devices/${DEV_1}` });
    expect(await screen.findByTestId("device-routes-link")).toHaveAttribute("href", `/t/${TENANT_A}/routes`);
    unmount();
    mockApi(apiFor("end_user", { [`GET ${base}/devices/${DEV_1}`]: json(200, withRoutes) }));
    renderApp({ path: `/t/${TENANT_A}/devices/${DEV_1}` });
    await screen.findByRole("heading", { name: "laptop-1", level: 1 });
    expect(screen.queryByTestId("device-routes-link")).toBeNull();
  });

  it("tenant suspended ⇒ nút duyệt/gỡ duyệt bị khóa", async () => {
    mockApi(apiFor("tenant_owner", { [`GET ${base}/routes`]: list() }, "suspended"));
    renderApp({ path: `/t/${TENANT_A}/routes` });
    await screen.findByTestId("tenant-suspended");
    await screen.findByTestId("routes-table");
    expect(screen.getByRole("button", { name: "Duyệt route của gw-1" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Duyệt exit node gw-1" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Gỡ duyệt route của gw-1" })).toBeDisabled();
  });
});

describe("dns", () => {
  it("MagicDNS + base_domain + nameserver + bản ghi; Tenant Viewer chỉ đọc", async () => {
    mockApi(
      apiFor("tenant_viewer", {
        [`GET ${base}/dns`]: json(200, dnsView(), { ETag: '"dns-v3"' }),
        [`GET ${base}/dns/records`]: json(200, { items: [dnsRecord()] }),
      }),
    );
    renderApp({ path: `/t/${TENANT_A}/dns` });
    const settings = await screen.findByTestId("dns-settings");
    expect(settings).toHaveTextContent("Luôn bật");
    expect(within(settings).getByTestId("dns-base-domain")).toHaveTextContent("tenant-a.tail.example.test");
    expect(within(settings).getByTestId("dns-nameservers")).toHaveTextContent("1.1.1.1");
    const row = await screen.findByTestId("record-row");
    expect(row).toHaveTextContent("nas.tenant-a.tail.example.test");
    expect(row).toHaveTextContent("100.64.0.5");
    expect(screen.queryByRole("button", { name: "Đổi nameserver…" })).toBeNull();
    expect(screen.queryByTestId("record-form")).toBeNull();
    expect(screen.queryByRole("button", { name: /Xóa bản ghi/ })).toBeNull();
  });

  it("đổi nameserver: hộp xác nhận restart + ngắt relay ⇒ PUT If-Match = etag ⇒ 202 ⇒ poll job ⇒ chỉ báo đã áp dụng khi succeeded", async () => {
    let put = false;
    let jobReads = 0;
    const NEW = ["8.8.8.8", "1.0.0.1"];
    const { requests } = mockApi(
      apiFor("tenant_admin", {
        [`GET ${base}/dns`]: () =>
          json(
            200,
            !put
              ? dnsView()
              : jobReads < 2
                ? dnsView({ pending: { job_id: NET_JOB, status: "running", nameservers: NEW } })
                : dnsView({ nameservers: NEW, config_version: 4, etag: '"dns-v4"' }),
          ),
        [`GET ${base}/dns/records`]: json(200, { items: [] }),
        [`PUT ${base}/dns/settings`]: () => {
          put = true;
          return json(202, netJob("instance.reconfigure", "queued"), { Location: `/api/v1/tenants/${TENANT_A}/jobs/${NET_JOB}` });
        },
        [`GET ${base}/jobs/${NET_JOB}`]: () => json(200, netJob("instance.reconfigure", ++jobReads >= 2 ? "succeeded" : "running")),
      }),
    );
    renderApp({ path: `/t/${TENANT_A}/dns` });
    const input = await screen.findByLabelText(/Nameserver \(1–8 địa chỉ IP/);
    await userEvent.clear(input);
    await userEvent.type(input, "8.8.8.8{enter}8.8.8.8");
    expect(screen.getByText("Có nameserver bị lặp lại.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Đổi nameserver…" })).toBeDisabled();
    await userEvent.clear(input);
    await userEvent.type(input, "8.8.8.8{enter}1.0.0.1");
    await userEvent.click(screen.getByRole("button", { name: "Đổi nameserver…" }));
    const dialog = screen.getByRole("alertdialog");
    expect(within(dialog).getByTestId("dns-restart-warning")).toHaveTextContent("restart có kiểm soát");
    expect(dialog).toHaveTextContent("phiên relay (DERP) của tenant bị ngắt");
    expect(within(dialog).getByRole("button", { name: "Hủy" })).toHaveFocus();
    await userEvent.click(within(dialog).getByRole("button", { name: "Restart và áp dụng" }));
    const progress = await screen.findByTestId("dns-job");
    expect(progress).toHaveTextContent("Đang áp dụng — chưa có hiệu lực");
    expect(progress).not.toHaveTextContent("Đã áp dụng");
    const req = writes(requests, "PUT")[0]!;
    expect(req.headers.get("If-Match")).toBe('"dns-v3"');
    expect(req.headers.get("X-CSRF-Token")).toBe(CSRF);
    expect(await req.json()).toEqual({ nameservers: NEW });
    await waitFor(() => expect(screen.getByTestId("dns-job")).toHaveTextContent("Đã áp dụng — instance đang chạy với nameserver mới."), { timeout: 8000 });
    expect(jobReads).toBeGreaterThanOrEqual(2);
    await waitFor(() => expect(screen.getByTestId("dns-nameservers")).toHaveTextContent("1.0.0.1"));
  }, 15_000);

  it("thêm bản ghi: 422 field value ⇒ lỗi hiện ngay tại ô Giá trị; sửa lại (khóa mới) ⇒ 503 ⇒ bấm lại CÙNG Idempotency-Key ⇒ 201 ⇒ trạng thái job ghi file", async () => {
    let posts = 0;
    let jobReads = 0;
    const { requests } = mockApi(
      apiFor("tenant_owner", {
        [`GET ${base}/dns`]: json(200, dnsView()),
        [`GET ${base}/dns/records`]: json(200, { items: [dnsRecord()] }),
        [`POST ${base}/dns/records`]: () =>
          ++posts === 1
            ? problem(422, "validation_failed", {
                errors: [{ field: "value", code: "value_not_in_tailnet", message: "value must be the tailnet address of one of the tenant's devices" }],
              })
            : posts === 2
              ? problem(503, "instance_unavailable")
              : json(201, { record: dnsRecord({ id: "0190a800-0000-7000-8000-000000000002", name: "git.corp.example", value: "100.64.0.7" }), job: netJob("dns.records_write", "queued") }),
        [`GET ${base}/jobs/${NET_JOB}`]: () => json(200, netJob("dns.records_write", ++jobReads >= 2 ? "succeeded" : "running")),
      }),
    );
    renderApp({ path: `/t/${TENANT_A}/dns` });
    const form = await screen.findByTestId("record-form");
    await userEvent.type(within(form).getByLabelText("Tên (FQDN)"), "Git.Corp.Example");
    await userEvent.type(within(form).getByLabelText("Giá trị"), "203.0.113.9");
    await userEvent.click(within(form).getByRole("button", { name: "Thêm bản ghi" }));
    const value = within(form).getByLabelText("Giá trị");
    await waitFor(() => expect(value).toHaveAttribute("aria-invalid", "true"));
    expect(value).toHaveAccessibleDescription(/địa chỉ tailnet của một thiết bị của tenant/);
    expect(within(form).getByLabelText("Tên (FQDN)")).toHaveAttribute("aria-invalid", "false");
    await userEvent.clear(value);
    await userEvent.type(value, "100.64.0.7");
    await userEvent.click(within(form).getByRole("button", { name: "Thêm bản ghi" }));
    expect(await within(form).findByRole("alert")).toHaveTextContent("Control plane của tenant tạm thời không phản hồi.");
    await userEvent.click(within(form).getByRole("button", { name: "Thêm bản ghi" }));
    const job = await screen.findByTestId("record-job");
    expect(job).toHaveTextContent("Ghi file bản ghi (thêm)");
    await waitFor(() => expect(screen.getByTestId("record-job")).toHaveTextContent("Đã ghi file bản ghi"), { timeout: 8000 });
    const [first, second, third] = writes(requests, "POST");
    expect(await first!.json()).toEqual({ name: "git.corp.example", type: "A", value: "203.0.113.9" });
    expect(await second!.json()).toEqual({ name: "git.corp.example", type: "A", value: "100.64.0.7" });
    expect(first!.headers.get("Idempotency-Key")).toMatch(UUID_RE);
    expect(second!.headers.get("Idempotency-Key")).not.toBe(first!.headers.get("Idempotency-Key")); // nội dung đổi ⇒ khóa mới
    expect(third!.headers.get("Idempotency-Key")).toBe(second!.headers.get("Idempotency-Key")); // gửi lại cùng nội dung ⇒ cùng khóa
    expect(within(form).getByLabelText("Giá trị")).toHaveValue(""); // 201 ⇒ form về trống (ý định mới)
  }, 15_000);

  it("xóa bản ghi: hộp xác nhận ⇒ DELETE ⇒ 202 + job", async () => {
    const { requests } = mockApi(
      apiFor("tenant_admin", {
        [`GET ${base}/dns`]: json(200, dnsView()),
        [`GET ${base}/dns/records`]: json(200, { items: [dnsRecord()] }),
        [`DELETE ${base}/dns/records/${RECORD_1}`]: json(202, netJob("dns.records_write", "queued"), { Location: `/api/v1/tenants/${TENANT_A}/jobs/${NET_JOB}` }),
        [`GET ${base}/jobs/${NET_JOB}`]: json(200, netJob("dns.records_write", "running")),
      }),
    );
    renderApp({ path: `/t/${TENANT_A}/dns` });
    await userEvent.click(await screen.findByRole("button", { name: "Xóa bản ghi A nas.tenant-a.tail.example.test" }));
    const dialog = screen.getByRole("alertdialog");
    expect(dialog).toHaveTextContent("100.64.0.5");
    await userEvent.click(within(dialog).getByRole("button", { name: "Xóa" }));
    expect(await screen.findByTestId("record-job")).toHaveTextContent("Ghi file bản ghi (xóa)");
    expect(screen.getByTestId("record-job")).not.toHaveTextContent("Đã ghi file");
    expect(writes(requests, "DELETE")).toHaveLength(1);
  });
});

describe("resources", () => {
  const tags = () => json(200, { items: [tag("tag:server", 1), tag("tag:db", 2)], next_cursor: null });
  const groups = () => json(200, { items: [group()], next_cursor: null });

  it("danh sách phân trang cursor (api/pagination); Tenant Viewer chỉ đọc", async () => {
    const { requests } = mockApi(
      apiFor("tenant_viewer", {
        [`GET ${base}/resources`]: (req) =>
          new URL(req.url).searchParams.get("cursor") === "r2"
            ? json(200, { items: [resource({ id: "0190a900-0000-7000-8000-000000000002", name: "db-net", kind: "subnet", address: "10.1.0.0/24", ports: [], protocol: "any", tags: [] })], next_cursor: null })
            : json(200, { items: [resource()], next_cursor: "r2" }),
        [`GET ${base}/groups`]: groups(),
      }),
    );
    renderApp({ path: `/t/${TENANT_A}/resources` });
    const row = await screen.findByTestId("resource-row");
    expect(row).toHaveTextContent("web-prod");
    expect(row).toHaveTextContent("Service");
    expect(row).toHaveTextContent("443, 8000-8100");
    expect(row).toHaveTextContent("TCP");
    expect(row).toHaveTextContent("tag:server");
    await waitFor(() => expect(row).toHaveTextContent("ops")); // tên nhóm từ GET /groups
    expect(screen.queryByRole("button", { name: "Thêm tài nguyên" })).toBeNull();
    expect(screen.queryByRole("button", { name: /Sửa tài nguyên|Xóa tài nguyên/ })).toBeNull();
    await userEvent.click(screen.getByRole("button", { name: "Tiếp" }));
    await waitFor(() => expect(screen.getByTestId("resource-row")).toHaveTextContent("db-net"));
    expect(screen.getByTestId("resource-row")).toHaveTextContent("Mọi cổng");
    const q = new URL(requests.filter((r) => r.url.includes("/resources")).at(-1)!.url).searchParams;
    expect(q.get("cursor")).toBe("r2");
    expect(q.get("limit")).toBe("50");
  });

  it("sửa: PATCH chỉ trường đã đổi + If-Match = etag", async () => {
    const { requests } = mockApi(
      apiFor("tenant_admin", {
        [`GET ${base}/resources`]: json(200, { items: [resource()], next_cursor: null }),
        [`GET ${base}/tags`]: tags(),
        [`GET ${base}/groups`]: groups(),
        [`PATCH ${base}/resources/${RESOURCE_1}`]: json(200, resource({ ports: ["443"], version: 3, etag: '"v3"' }), { ETag: '"v3"' }),
      }),
    );
    renderApp({ path: `/t/${TENANT_A}/resources` });
    await userEvent.click(await screen.findByRole("button", { name: "Sửa tài nguyên web-prod" }));
    const dialog = screen.getByRole("dialog");
    expect(within(dialog).getByRole("button", { name: "Lưu" })).toBeDisabled(); // chưa đổi gì
    expect(await within(dialog).findByLabelText("tag:db")).not.toBeChecked();
    expect(within(dialog).getByLabelText("tag:server")).toBeChecked();
    expect(within(dialog).getByLabelText("Nhóm sở hữu")).toHaveValue(GROUP_1);
    const ports = within(dialog).getByLabelText("Cổng");
    await userEvent.clear(ports);
    await userEvent.type(ports, "443");
    await userEvent.click(within(dialog).getByRole("button", { name: "Lưu" }));
    expect(await screen.findByTestId("resources-notice")).toHaveTextContent("Đã lưu tài nguyên web-prod.");
    const patch = writes(requests, "PATCH")[0]!;
    expect(patch.headers.get("If-Match")).toBe('"v2"');
    expect(patch.headers.get("X-CSRF-Token")).toBe(CSRF);
    expect(await patch.json()).toEqual({ ports: ["443"] });
  });

  it("thêm: chọn tag từ danh mục + nhóm sở hữu, POST Idempotency-Key; 422 hiện tại ô Địa chỉ", async () => {
    let posts = 0;
    const { requests } = mockApi(
      apiFor("tenant_owner", {
        [`GET ${base}/resources`]: json(200, { items: [], next_cursor: null }),
        [`GET ${base}/tags`]: tags(),
        [`GET ${base}/groups`]: groups(),
        [`POST ${base}/resources`]: () =>
          ++posts === 1
            ? problem(422, "validation_failed", { errors: [{ field: "address", code: "address_not_canonical", message: "the prefix must have no host bits set" }] })
            : json(201, resource({ name: "db-net", kind: "subnet", address: "10.1.0.0/24", ports: [], protocol: "any", tags: ["tag:db"] })),
      }),
    );
    renderApp({ path: `/t/${TENANT_A}/resources` });
    await screen.findByTestId("empty");
    await userEvent.click(screen.getByRole("button", { name: "Thêm tài nguyên" }));
    const dialog = screen.getByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("Tên"), "db-net");
    await userEvent.selectOptions(within(dialog).getByLabelText("Loại"), "subnet");
    await userEvent.type(within(dialog).getByLabelText("Địa chỉ"), "10.1.0.1/24");
    await userEvent.click(await within(dialog).findByLabelText("tag:db"));
    await userEvent.selectOptions(within(dialog).getByLabelText("Nhóm sở hữu"), GROUP_1);
    await userEvent.click(within(dialog).getByRole("button", { name: "Thêm" }));
    const address = within(dialog).getByLabelText("Địa chỉ");
    await waitFor(() => expect(address).toHaveAttribute("aria-invalid", "true"));
    expect(address).toHaveAccessibleDescription(/Prefix không được có bit host/);
    await userEvent.clear(address);
    await userEvent.type(address, "10.1.0.0/24");
    await userEvent.click(within(dialog).getByRole("button", { name: "Thêm" }));
    expect(await screen.findByTestId("resources-notice")).toHaveTextContent("Đã thêm tài nguyên db-net.");
    const [first, second] = writes(requests, "POST");
    expect(await second!.json()).toEqual({ name: "db-net", kind: "subnet", address: "10.1.0.0/24", protocol: "any", tags: ["tag:db"], owner_group_id: GROUP_1 });
    expect(first!.headers.get("Idempotency-Key")).toMatch(UUID_RE);
    expect(second!.headers.get("Idempotency-Key")).not.toBe(first!.headers.get("Idempotency-Key"));
  });

  it("xóa: If-Match; 412 ⇒ báo đã đổi và tải lại danh sách", async () => {
    let reads = 0;
    const { requests } = mockApi(
      apiFor("tenant_admin", {
        [`GET ${base}/resources`]: () => {
          reads++;
          return json(200, { items: [resource()], next_cursor: null });
        },
        [`GET ${base}/groups`]: groups(),
        [`DELETE ${base}/resources/${RESOURCE_1}`]: problem(412, "precondition_failed"),
      }),
    );
    renderApp({ path: `/t/${TENANT_A}/resources` });
    await userEvent.click(await screen.findByRole("button", { name: "Xóa tài nguyên web-prod" }));
    await userEvent.click(within(screen.getByRole("alertdialog")).getByRole("button", { name: "Xóa" }));
    expect(await screen.findByTestId("resources-notice")).toHaveTextContent("Tài nguyên đã bị thay đổi bởi người khác");
    expect(screen.queryByRole("alertdialog")).toBeNull();
    expect(writes(requests, "DELETE")[0]!.headers.get("If-Match")).toBe('"v2"');
    await waitFor(() => expect(reads).toBeGreaterThan(1));
  });
});
