// Trang Policies + Tags (P4-T11) — cả App trên router bộ nhớ, API giả ở tầng fetch theo đúng hợp đồng của spec
// (JSON / problem+json, header ETag/Location). Kiểm: trạng thái hiện hành (đã áp dụng ≠ client hội tụ), lịch sử, soạn
// bản nháp (Idempotency-Key), editor form (principal theo id, If-Match), 412, báo cáo L4 + xác nhận, HuJSON (export,
// L2 không gửi, L1 từ server, import giữ xác nhận), 4-eyes, self-review, apply (202 + job + làm mới), 409 stale_base,
// step-up 401, rollback, danh mục tag (tạo, 409 còn tham chiếu kèm số lượng, tag nền tảng chỉ đọc).
import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { CSRF, json, mockApi, problem, renderApp, TENANT_A } from "../../test/helpers";
import {
  base,
  common,
  current,
  G_ENG,
  JOB,
  job,
  M_OWNER,
  OTHER_IDENTITY,
  R_DB,
  RESOURCES,
  SHA_A,
  SOURCE,
  T_ROUTER,
  T_WEB,
  tag,
  TAGS,
  V1,
  V2,
  V3,
  version,
} from "../../test/policies";

const UUID4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const vpath = (id: string) => `${base}/policies/${id}`;
const etagged = (v: ReturnType<typeof version>) => json(200, v, { ETag: v.etag });

async function bodyOf(r: Request): Promise<Record<string, unknown>> {
  return JSON.parse(await r.clone().text()) as Record<string, unknown>;
}

function find(requests: Request[], method: string, suffix: string): Request[] {
  return requests.filter((r) => r.method === method && new URL(r.url).pathname.endsWith(suffix));
}

describe("trang Policies", () => {
  it("trạng thái hiện hành: đã áp dụng lên Headscale lúc …, sha256 đọc lại; client hội tụ không quan sát được; lịch sử", async () => {
    mockApi(common("tenant_viewer"));
    renderApp({ path: `/t/${TENANT_A}/policies` });
    const cur = await screen.findByTestId("policy-current");
    expect(await within(cur).findByText(/Đã áp dụng lên Headscale lúc/)).toBeInTheDocument();
    expect(within(cur).getByTestId("current-applied-sha")).toHaveTextContent("b".repeat(12));
    expect(within(cur).getByText(/Không quan sát được từ Headscale/)).toBeInTheDocument();
    expect(within(cur).getByTestId("current-review")).toHaveTextContent("4-eyes: tắt");
    const rows = within(await screen.findByTestId("policy-versions")).getAllByRole("row");
    expect(rows).toHaveLength(3);
    expect(rows[1]).toHaveAttribute("data-state", "draft");
    expect(within(rows[2]!).getByText("Đang mong muốn")).toBeInTheDocument();
    expect(within(rows[2]!).getByText(/Duyệt: Nguyễn Văn A \(tự xác nhận\)/)).toBeInTheDocument();
    // Viewer: không soạn
    expect(screen.queryByRole("button", { name: "Soạn version mới" })).toBeNull();
  });

  it("soạn version mới: Idempotency-Key UUID v4, nội dung khởi đầu = version mong muốn, mở bản nháp", async () => {
    const { requests } = mockApi({
      ...common("tenant_admin"),
      [`POST ${base}/policies`]: json(201, version(V3), { ETag: '"1"' }),
      [`GET ${vpath(V3)}`]: etagged(version(V3)),
      [`GET ${vpath(V3)}/diff`]: json(200, { version_id: V3, lines: [], lines_omitted: false, grants_added: [], grants_removed: [], report_blocking: false }),
    });
    const { router } = renderApp({ path: `/t/${TENANT_A}/policies` });
    await screen.findByTestId("current-applied");
    await userEvent.click(screen.getByRole("button", { name: "Soạn version mới" }));
    await screen.findByRole("heading", { name: "Version 3", level: 1 });
    expect(router.state.location.pathname).toBe(`/t/${TENANT_A}/policies/${V3}`);
    const post = find(requests, "POST", "/policies")[0]!;
    expect(post.headers.get("Idempotency-Key")).toMatch(UUID4);
    expect(post.headers.get("X-CSRF-Token")).toBe(CSRF);
    expect(await bodyOf(post)).toEqual({ source: SOURCE });
  });
});

describe("editor dạng form", () => {
  const diff = json(200, { version_id: V2, lines: [{ op: "added", text: '"grants": []' }], lines_omitted: false, grants_added: ["g+"], grants_removed: [], report_blocking: false });

  it("thêm principal theo id và theo địa chỉ, sửa ip ⇒ PATCH với If-Match = ETag, source có kiểu", async () => {
    const saved = version(V2, { revision: 2 });
    const { requests } = mockApi({
      ...common("tenant_admin"),
      [`GET ${vpath(V2)}`]: etagged(version(V2)),
      [`GET ${vpath(V2)}/diff`]: diff,
      [`PATCH ${vpath(V2)}`]: json(200, saved, { ETag: '"2"' }),
    });
    renderApp({ path: `/t/${TENANT_A}/policies/${V2}` });
    await screen.findByRole("heading", { name: "Version 2", level: 1 });
    // G4b-E15: "Dựa trên" hiện số version (không phải tiền tố UUID)
    expect(await screen.findByRole("link", { name: "Version 1" })).toHaveAttribute("href", `/t/${TENANT_A}/policies/${V1}`);
    const dst = "Đích (dst) của luật 1";
    await userEvent.selectOptions(screen.getByLabelText(`Kiểu principal — ${dst}`), "cidr");
    await userEvent.type(screen.getByLabelText(`Giá trị — ${dst}`), "10.0.0.0/24");
    await userEvent.click(screen.getByRole("button", { name: `Thêm vào ${dst}` }));
    const src = "Nguồn (src) của luật 1";
    await userEvent.selectOptions(screen.getByLabelText(`Kiểu principal — ${src}`), "user");
    await userEvent.selectOptions(screen.getByLabelText(`Giá trị — ${src}`), M_OWNER);
    await userEvent.click(screen.getByRole("button", { name: `Thêm vào ${src}` }));
    const ip = screen.getByLabelText("Giao thức/cổng (ip) của luật 1");
    await userEvent.clear(ip);
    await userEvent.type(ip, "tcp:443, udp:53");
    expect(screen.getByText("Chưa lưu")).toBeInTheDocument();
    // vòng đời bị khóa khi còn thay đổi chưa lưu
    expect(screen.getByRole("button", { name: "Kiểm tra" })).toBeDisabled();
    await userEvent.click(screen.getByRole("button", { name: "Lưu bản nháp" }));
    await waitFor(() => expect(find(requests, "PATCH", `/policies/${V2}`)).toHaveLength(1));
    const patch = find(requests, "PATCH", `/policies/${V2}`)[0]!;
    expect(patch.headers.get("If-Match")).toBe('"1"');
    expect(await bodyOf(patch)).toEqual({
      source: {
        grants: [
          {
            src: [{ type: "group", ref: G_ENG }, { type: "user", ref: M_OWNER }],
            dst: [{ type: "tag", ref: T_WEB }, { type: "cidr", ref: "10.0.0.0/24" }],
            ip: ["tcp:443", "udp:53"],
          },
        ],
        ssh: [],
      },
    });
    expect(await screen.findByTestId("version-etag")).toHaveTextContent('"2"');
    expect(screen.queryByText("Chưa lưu")).toBeNull();
  });

  // G4b-E4: bộ chọn tài nguyên của Biểu mẫu đọc danh mục GET /resources (P4-T12) — không còn câu "chưa có API đọc"
  it("đích kiểu tài nguyên: chọn từ danh mục GET /resources ⇒ PATCH với ref = id tài nguyên", async () => {
    const { requests } = mockApi({
      ...common("tenant_admin"),
      [`GET ${base}/resources`]: json(200, RESOURCES),
      [`GET ${vpath(V2)}`]: etagged(version(V2)),
      [`GET ${vpath(V2)}/diff`]: diff,
      [`PATCH ${vpath(V2)}`]: json(200, version(V2, { revision: 2 }), { ETag: '"2"' }),
    });
    renderApp({ path: `/t/${TENANT_A}/policies/${V2}` });
    await screen.findByRole("heading", { name: "Version 2", level: 1 });
    const dst = "Đích (dst) của luật 1";
    await userEvent.selectOptions(screen.getByLabelText(`Kiểu principal — ${dst}`), "resource");
    const value = await screen.findByLabelText(`Giá trị — ${dst}`);
    expect(within(value).getByRole("option", { name: "db (10.20.0.5)" })).toBeInTheDocument();
    expect(screen.queryByText(/chưa có API đọc/)).toBeNull();
    await userEvent.selectOptions(value, R_DB);
    await userEvent.click(screen.getByRole("button", { name: `Thêm vào ${dst}` }));
    await userEvent.click(screen.getByRole("button", { name: "Lưu bản nháp" }));
    await waitFor(() => expect(find(requests, "PATCH", `/policies/${V2}`)).toHaveLength(1));
    const body = await bodyOf(find(requests, "PATCH", `/policies/${V2}`)[0]!);
    expect(JSON.stringify(body)).toContain(JSON.stringify({ type: "resource", ref: R_DB }));
    expect(find(requests, "GET", "/resources")).toHaveLength(1);
  });

  it.each([
    ["danh mục rỗng", json(200, { items: [], next_cursor: null }), "Tenant chưa có tài nguyên mạng nào"],
    ["đọc lỗi (403)", problem(403, "forbidden"), "Không đọc được danh mục tài nguyên mạng"],
  ])("đích kiểu tài nguyên — %s ⇒ câu đúng, các danh mục khác vẫn dùng được", async (_n, response, text) => {
    mockApi({ ...common("tenant_admin"), [`GET ${base}/resources`]: response, [`GET ${vpath(V2)}`]: etagged(version(V2)), [`GET ${vpath(V2)}/diff`]: diff });
    renderApp({ path: `/t/${TENANT_A}/policies/${V2}` });
    await screen.findByRole("heading", { name: "Version 2", level: 1 });
    const dst = "Đích (dst) của luật 1";
    await userEvent.selectOptions(screen.getByLabelText(`Kiểu principal — ${dst}`), "resource");
    expect(await screen.findByTestId("no-choices")).toHaveTextContent(text);
    const src = "Nguồn (src) của luật 1";
    await userEvent.selectOptions(screen.getByLabelText(`Kiểu principal — ${src}`), "user");
    expect(within(screen.getByLabelText(`Giá trị — ${src}`)).getByRole("option", { name: /Trần Thị B/ })).toBeInTheDocument();
  });

  it("địa chỉ sai và ip sai bị chặn trước khi gửi", async () => {
    const { requests } = mockApi({ ...common("tenant_admin"), [`GET ${vpath(V2)}`]: etagged(version(V2)), [`GET ${vpath(V2)}/diff`]: diff });
    renderApp({ path: `/t/${TENANT_A}/policies/${V2}` });
    await screen.findByRole("heading", { name: "Version 2", level: 1 });
    const dst = "Đích (dst) của luật 1";
    await userEvent.selectOptions(screen.getByLabelText(`Kiểu principal — ${dst}`), "cidr");
    await userEvent.type(screen.getByLabelText(`Giá trị — ${dst}`), "10.0.0.0/40");
    expect(screen.getByRole("button", { name: `Thêm vào ${dst}` })).toBeDisabled();
    const ip = screen.getByLabelText("Giao thức/cổng (ip) của luật 1");
    await userEvent.clear(ip);
    await userEvent.type(ip, "tcp:abc");
    expect(ip).toHaveAttribute("aria-invalid", "true");
    expect(screen.getByTestId("local-problems")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Lưu bản nháp" })).toBeDisabled();
    expect(find(requests, "PATCH", `/policies/${V2}`)).toHaveLength(0);
  });

  it("412 (revision cũ) ⇒ cảnh báo + tải lại bản mới nhất bỏ thay đổi", async () => {
    let reads = 0;
    mockApi({
      ...common("tenant_admin"),
      [`GET ${vpath(V2)}`]: () => {
        reads++;
        return reads === 1 ? etagged(version(V2)) : etagged(version(V2, { revision: 5, source: { grants: [] } }));
      },
      [`GET ${vpath(V2)}/diff`]: diff,
      [`PATCH ${vpath(V2)}`]: problem(412, "precondition_failed", { detail: "The version changed since it was read; read it again." }),
    });
    renderApp({ path: `/t/${TENANT_A}/policies/${V2}` });
    await screen.findByRole("heading", { name: "Version 2", level: 1 });
    await userEvent.click(screen.getByRole("button", { name: "Thêm luật" }));
    await userEvent.click(screen.getByRole("button", { name: "Gỡ luật 2" }));
    await userEvent.click(screen.getByRole("button", { name: "Gỡ luật 1" }));
    await userEvent.click(screen.getByRole("button", { name: "Lưu bản nháp" }));
    const stale = await screen.findByTestId("stale-revision");
    expect(stale).toHaveTextContent("412");
    await userEvent.click(within(stale).getByRole("button", { name: "Tải lại bản mới nhất" }));
    expect(await screen.findByTestId("version-etag")).toHaveTextContent('"5"');
    expect(screen.queryByTestId("stale-revision")).toBeNull();
    expect(screen.getByText(/chặn mọi kết nối/)).toBeInTheDocument();
  });

  it("validate: L4 hiện ở báo cáo và cạnh luật; xác nhận L4 kèm lý do ⇒ PATCH có acknowledgements", async () => {
    const wildcard = { grants: [{ src: [{ type: "autogroup" as const, ref: "member" }], dst: [{ type: "cidr" as const, ref: "*" }], ip: ["*"] }], ssh: [] };
    const report = {
      engine: "p4-t10",
      result: "failed" as const,
      errors: [{ rule: "L4", severity: "error" as const, code: "wildcard_destination_ack_required", path: "grants[0].dst[0]", message: "wildcard", requires_ack: true, owner_only: true }],
      warnings: [],
      info: [],
      tests: [],
      check: "skipped" as const,
      revision: 2,
    };
    const { requests } = mockApi({
      ...common("tenant_admin"),
      [`GET ${vpath(V2)}`]: etagged(version(V2, { source: wildcard })),
      [`GET ${vpath(V2)}/diff`]: diff,
      [`POST ${vpath(V2)}/validate`]: json(200, version(V2, { revision: 2, source: wildcard, validation_report: report }), { ETag: '"2"' }),
      [`PATCH ${vpath(V2)}`]: json(200, version(V2, { revision: 3, source: wildcard }), { ETag: '"3"' }),
    });
    renderApp({ path: `/t/${TENANT_A}/policies/${V2}` });
    await screen.findByRole("heading", { name: "Version 2", level: 1 });
    await userEvent.click(screen.getByRole("button", { name: "Kiểm tra" }));
    const rep = await screen.findByTestId("policy-report");
    await waitFor(() => expect(within(rep).getByTestId("report-result")).toHaveTextContent("Không đạt"));
    expect(within(rep).getByTestId("report-check")).toHaveTextContent("Bỏ qua");
    const l4 = within(rep).getAllByTestId("findings")[0]!.querySelector("[data-rule=L4]");
    expect(l4).not.toBeNull();
    expect(l4).toHaveTextContent("grants[0].dst[0]");
    expect(l4).toHaveTextContent("Tenant Owner xác nhận");
    // câu chính là mô tả; mã luật/mã phát hiện chỉ ở dòng chi tiết kỹ thuật (G4b-E11)
    expect(l4!.querySelector('[data-testid="finding-technical"]')).toHaveTextContent("L4 · wildcard_destination_ack_required");
    expect(l4!.firstElementChild).not.toHaveTextContent("L4");
    expect(within(screen.getByTestId("grant-0")).getByText("grants[0].dst[0]")).toBeInTheDocument();
    const validate = find(requests, "POST", "/validate")[0]!;
    expect(validate.headers.get("If-Match")).toBe('"1"');
    // xác nhận L4
    const acks = screen.getByTestId("acks");
    expect(within(acks).getAllByText("báo cáo yêu cầu")).toHaveLength(1);
    // tên luật đã dịch, mã luật chỉ ở tooltip (G4b-E11)
    const ackL4 = within(acks).getByRole("checkbox", { name: /Xác nhận: đích \* hoặc route mặc định/ });
    expect(acks.querySelector('[data-rule="L4"]')).toHaveAttribute("title", "Mã luật: L4");
    expect(acks).not.toHaveTextContent(/\bL4\b/);
    await userEvent.click(ackL4);
    await userEvent.type(within(acks).getByLabelText("Lý do xác nhận (đích * hoặc route mặc định)"), "đã thống nhất với khách");
    await userEvent.click(screen.getByRole("button", { name: "Lưu bản nháp" }));
    await waitFor(() => expect(find(requests, "PATCH", `/policies/${V2}`)).toHaveLength(1));
    const patch = find(requests, "PATCH", `/policies/${V2}`)[0]!;
    expect(patch.headers.get("If-Match")).toBe('"2"');
    expect((await bodyOf(patch)).source).toEqual({ ...wildcard, acknowledgements: [{ rule: "L4", reason: "đã thống nhất với khách" }] });
  });
});

describe("chế độ HuJSON (bộ dịch phía server)", () => {
  it("export ⇒ văn bản; rỗng ⇒ L2 tại chỗ, không gửi; thiếu grants ⇒ L1 từ server; dịch được ⇒ form (giữ xác nhận) ⇒ lưu", async () => {
    const withAck = { ...SOURCE, acknowledgements: [{ rule: "L10" as const, reason: "phiên quản trị" }] };
    const imported = { grants: [{ src: [{ type: "user" as const, ref: M_OWNER }], dst: [{ type: "resource" as const, ref: R_DB }], ip: ["tcp:5432"] }], ssh: [] };
    const { requests } = mockApi({
      ...common("tenant_admin"),
      [`GET ${vpath(V2)}`]: etagged(version(V2, { source: withAck })),
      [`GET ${vpath(V2)}/diff`]: json(200, { version_id: V2, lines: [], lines_omitted: false, grants_added: [], grants_removed: [], report_blocking: false }),
      [`POST ${base}/policies/export`]: json(200, { hujson: '{\n  "grants": []\n}\n', warnings: [], principals: [] }),
      [`POST ${base}/policies/import`]: async (r) => {
        const { hujson } = (await r.clone().json()) as { hujson: string };
        if (!hujson.includes('"grants"'))
          return json(200, {
            result: "failed",
            errors: [{ rule: "L1", severity: "error", code: "missing_grants", path: "grants", message: "no grants" }],
            warnings: [],
            principals: [],
          });
        return json(200, { result: "passed", source: imported, errors: [], warnings: [], principals: [{ type: "resource", ref: R_DB, name: "db" }] });
      },
      [`PATCH ${vpath(V2)}`]: json(200, version(V2, { revision: 2 }), { ETag: '"2"' }),
    });
    renderApp({ path: `/t/${TENANT_A}/policies/${V2}` });
    await screen.findByRole("heading", { name: "Version 2", level: 1 });
    await userEvent.click(screen.getByRole("radio", { name: "HuJSON" }));
    const text = await screen.findByLabelText("Văn bản HuJSON");
    expect(text).toHaveValue('{\n  "grants": []\n}\n');
    const exp = find(requests, "POST", "/policies/export")[0]!;
    expect((await bodyOf(exp)).source).toEqual(withAck);
    // rỗng ⇒ L2, không gửi
    fireEvent.change(text, { target: { value: "   " } });
    await userEvent.click(screen.getByRole("button", { name: "Dịch sang biểu mẫu" }));
    expect(await screen.findByTestId("hujson-empty")).toHaveTextContent("L2");
    expect(find(requests, "POST", "/policies/import")).toHaveLength(0);
    // thiếu grants ⇒ L1 (server), form không đổi
    fireEvent.change(text, { target: { value: '{"ssh": []}' } });
    await userEvent.click(screen.getByRole("button", { name: "Dịch sang biểu mẫu" }));
    const errs = await screen.findByTestId("import-errors");
    expect(errs).toHaveTextContent("L1");
    expect(errs).toHaveTextContent("Thiếu khóa grants");
    expect(screen.getByLabelText("Văn bản HuJSON")).toBeInTheDocument();
    // dịch được ⇒ form, xác nhận giữ nguyên
    fireEvent.change(text, { target: { value: '// comment\n{"grants": [{"src": ["b@example.test"], "dst": ["db"], "ip": ["tcp:5432"]}]}' } });
    await userEvent.click(screen.getByRole("button", { name: "Dịch sang biểu mẫu" }));
    await screen.findByTestId("policy-form");
    expect(within(screen.getByTestId("grant-0")).getByText("db")).toBeInTheDocument();
    expect(within(screen.getByTestId("grant-0")).getByText("b@example.test")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Lưu bản nháp" }));
    await waitFor(() => expect(find(requests, "PATCH", `/policies/${V2}`)).toHaveLength(1));
    expect((await bodyOf(find(requests, "PATCH", `/policies/${V2}`)[0]!)).source).toEqual({ ...imported, acknowledgements: withAck.acknowledgements });
    const imports = find(requests, "POST", "/policies/import");
    expect(imports).toHaveLength(2);
    expect(imports[0]!.headers.get("X-CSRF-Token")).toBe(CSRF);
  });

  it("version của nền tảng (HuJSON, không có source): chỉ xem văn bản, không có editor", async () => {
    mockApi({
      ...common("tenant_admin"),
      [`GET ${vpath(V2)}`]: etagged(version(V2, { kind: "baseline", source: undefined, hujson: '{"grants": []}', state: "approved", approved_at: "x" })),
      [`GET ${vpath(V2)}/diff`]: json(200, { version_id: V2, lines: [], lines_omitted: false, grants_added: [], grants_removed: [], report_blocking: false }),
    });
    renderApp({ path: `/t/${TENANT_A}/policies/${V2}` });
    expect(await screen.findByText(/Version của nền tảng/)).toBeInTheDocument();
    expect(screen.queryByTestId("policy-form")).toBeNull();
    expect(screen.queryByRole("button", { name: "Lưu bản nháp" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Rollback về nội dung này" })).toBeNull();
  });
});

describe("duyệt (4-eyes / self-review)", () => {
  const diff = json(200, { version_id: V2, lines: [], lines_omitted: false, grants_added: [], grants_removed: [], report_blocking: false });

  it("4-eyes: người soạn/gửi không có nút Duyệt, thấy giải thích; vẫn từ chối được", async () => {
    mockApi({
      ...common("tenant_admin", undefined, current({ four_eyes: true, apply_step_up: true })),
      [`GET ${vpath(V2)}`]: etagged(version(V2, { state: "pending_approval", submitted_by: "0190c000-0000-7000-8000-0000000000c1" })),
      [`GET ${vpath(V2)}/diff`]: diff,
    });
    renderApp({ path: `/t/${TENANT_A}/policies/${V2}` });
    expect(await screen.findByTestId("four-eyes-self")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Duyệt" })).toBeNull();
    expect(screen.getByRole("button", { name: "Từ chối" })).toBeInTheDocument();
  });

  it("4-eyes: người khác duyệt — phải đánh dấu đã xem; gửi content_sha256 + If-Match", async () => {
    const { requests } = mockApi({
      ...common("tenant_owner", OTHER_IDENTITY, current({ four_eyes: true })),
      [`GET ${vpath(V2)}`]: etagged(version(V2, { state: "pending_approval", revision: 3, submitted_by: "0190c000-0000-7000-8000-0000000000c1" })),
      [`GET ${vpath(V2)}/diff`]: diff,
      [`POST ${vpath(V2)}/approve`]: json(200, version(V2, { state: "approved", revision: 4, approved_by: OTHER_IDENTITY, approved_at: "2026-11-19T03:00:00Z", review_mode: "peer" }), { ETag: '"4"' }),
    });
    renderApp({ path: `/t/${TENANT_A}/policies/${V2}` });
    await userEvent.click(await screen.findByRole("button", { name: "Duyệt" }));
    const dialog = await screen.findByRole("alertdialog", { name: "Duyệt version 2?" });
    expect(dialog).toHaveTextContent(SHA_A);
    const confirm = within(dialog).getByRole("button", { name: "Duyệt" });
    expect(confirm).toBeDisabled();
    await userEvent.click(within(dialog).getByRole("checkbox"));
    await userEvent.click(confirm);
    await waitFor(() => expect(screen.getByTestId("version-state")).toHaveTextContent("Đã duyệt"));
    const req = find(requests, "POST", "/approve")[0]!;
    expect(req.headers.get("If-Match")).toBe('"3"');
    expect(await bodyOf(req)).toEqual({ content_sha256: SHA_A });
    expect(screen.getByTestId("approved-by")).toHaveTextContent("Trần Thị B");
  });

  it("tắt 4-eyes: người soạn tự xác nhận; 403 của server hiện trong hộp", async () => {
    mockApi({
      ...common("tenant_admin"),
      [`GET ${vpath(V2)}`]: etagged(version(V2, { state: "validated" })),
      [`GET ${vpath(V2)}/diff`]: diff,
      [`POST ${vpath(V2)}/approve`]: problem(403, "forbidden", { detail: "The version acknowledges a rule only a Tenant Owner may accept (L4/L12): an Owner approves it." }),
    });
    renderApp({ path: `/t/${TENANT_A}/policies/${V2}` });
    await userEvent.click(await screen.findByRole("button", { name: "Xác nhận và duyệt" }));
    const dialog = await screen.findByRole("alertdialog");
    expect(dialog).toHaveTextContent("review_mode = self");
    await userEvent.click(within(dialog).getByRole("checkbox"));
    await userEvent.click(within(dialog).getByRole("button", { name: "Duyệt" }));
    // giao diện vi: câu dịch theo code, không in `detail` tiếng Anh của 403 (G4b-E3)
    expect(await within(dialog).findByText("Bạn không có quyền thực hiện thao tác này.")).toBeInTheDocument();
    expect(dialog).not.toHaveTextContent("an Owner approves it");
  });

  it("4-eyes: gửi duyệt với If-Match", async () => {
    const { requests } = mockApi({
      ...common("tenant_admin", undefined, current({ four_eyes: true })),
      [`GET ${vpath(V2)}`]: etagged(version(V2, { state: "validated", revision: 2 })),
      [`GET ${vpath(V2)}/diff`]: diff,
      [`POST ${vpath(V2)}/submit`]: json(200, version(V2, { state: "pending_approval", revision: 3, submitted_by: "0190c000-0000-7000-8000-0000000000c1" }), { ETag: '"3"' }),
    });
    renderApp({ path: `/t/${TENANT_A}/policies/${V2}` });
    expect(screen.queryByRole("button", { name: "Xác nhận và duyệt" })).toBeNull();
    await userEvent.click(await screen.findByRole("button", { name: "Gửi duyệt" }));
    await screen.findByTestId("four-eyes-self");
    expect(find(requests, "POST", "/submit")[0]!.headers.get("If-Match")).toBe('"2"');
  });
});

describe("áp dụng / rollback", () => {
  const diff = json(200, { version_id: V2, lines: [], lines_omitted: false, grants_added: [], grants_removed: [], report_blocking: false });
  const approved = version(V2, { state: "approved", approved_by: "0190c000-0000-7000-8000-0000000000c1", approved_at: "2026-11-19T03:00:00Z", review_mode: "self" });

  it("202 + Location ⇒ job policy.apply poll tới succeeded ⇒ trạng thái áp dụng làm mới", async () => {
    let polls = 0;
    let currents = 0;
    let atApply = -1;
    const { requests } = mockApi({
      ...common("tenant_admin"),
      [`GET ${base}/policies/current`]: () => {
        currents++;
        return json(200, currents === 1 ? current() : current({ desired: { ...approved, desired: true }, applied: { ...current().applied!, policy_version_id: V2, applied_sha256: "c".repeat(64) } }));
      },
      [`GET ${vpath(V2)}`]: etagged(approved),
      [`GET ${vpath(V2)}/diff`]: diff,
      [`POST ${vpath(V2)}/apply`]: () => {
        atApply = currents;
        return json(202, { version: { ...approved, desired: true }, job: job("queued") }, { Location: `/api/v1/tenants/${TENANT_A}/jobs/${JOB}` });
      },
      [`GET ${base}/jobs/${JOB}`]: () => {
        polls++;
        return json(200, job(polls < 2 ? "running" : "succeeded"));
      },
    });
    const { router } = renderApp({ path: `/t/${TENANT_A}/policies/${V2}` });
    await userEvent.click(await screen.findByRole("button", { name: "Áp dụng" }));
    const dialog = await screen.findByRole("alertdialog", { name: "Áp dụng version 2?" });
    expect(dialog).toHaveTextContent("không có nghĩa mọi client");
    await userEvent.click(within(dialog).getByRole("button", { name: "Áp dụng" }));
    await waitFor(() => expect(router.state.location.search).toBe(`?job=${JOB}`));
    await waitFor(() => expect(screen.getByTestId("apply-job")).toHaveAttribute("data-status", "succeeded"), { timeout: 8000 });
    expect(screen.getByTestId("apply-done")).toBeInTheDocument();
    expect(find(requests, "POST", "/apply")[0]!.headers.get("Idempotency-Key")).toMatch(UUID4);
    // trạng thái áp dụng được đọc lại hai lần: khi 202 về (version thành desired) và khi job tới trạng thái cuối
    await waitFor(() => expect(currents).toBeGreaterThanOrEqual(atApply + 2));
  }, 15_000);

  it("409 stale_base ⇒ giải thích + soạn lại từ nội dung này (POST /policies)", async () => {
    const stale = { ...approved, parent_version_id: "0190f000-0000-7000-8000-0000000000ee" };
    const { requests } = mockApi({
      ...common("tenant_admin"),
      [`GET ${vpath(V2)}`]: etagged(stale),
      [`GET ${vpath(V2)}/diff`]: diff,
      [`POST ${vpath(V2)}/apply`]: problem(409, "conflict", { detail: "The version is not based on the current desired version (stale_base): rebase it." }),
      [`POST ${base}/policies`]: json(201, version(V3), { ETag: '"1"' }),
      [`GET ${vpath(V3)}`]: etagged(version(V3)),
      [`GET ${vpath(V3)}/diff`]: diff,
    });
    renderApp({ path: `/t/${TENANT_A}/policies/${V2}` });
    expect(await screen.findByText("base đã cũ")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Áp dụng" }));
    const dialog = await screen.findByRole("alertdialog");
    await userEvent.click(within(dialog).getByRole("button", { name: "Áp dụng" }));
    expect(await within(dialog).findByTestId("stale-base-dialog")).toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole("button", { name: "Hủy" }));
    expect(await screen.findByTestId("stale-base")).toHaveTextContent("409 stale_base");
    // version đã duyệt chỉ đọc: soạn lại qua "Tạo bản nháp từ version này" (G4b-E15)
    await userEvent.click(within(screen.getByTestId("policy-sealed")).getByRole("button", { name: "Tạo bản nháp từ version này" }));
    await screen.findByRole("heading", { name: "Version 3", level: 1 });
    expect((await bodyOf(find(requests, "POST", "/policies")[0]!)).source).toEqual(SOURCE);
  });

  it("step-up: 401 reauth_required ⇒ nút xác thực lại trong hộp", async () => {
    mockApi({
      ...common("tenant_admin", undefined, current({ four_eyes: true, apply_step_up: true })),
      [`GET ${vpath(V2)}`]: etagged(approved),
      [`GET ${vpath(V2)}/diff`]: diff,
      [`POST ${vpath(V2)}/apply`]: problem(401, "reauth_required", { detail: "This operation needs a recent sign-in (step-up)." }),
    });
    renderApp({ path: `/t/${TENANT_A}/policies/${V2}` });
    await userEvent.click(await screen.findByRole("button", { name: "Áp dụng" }));
    const dialog = await screen.findByRole("alertdialog");
    expect(dialog).toHaveTextContent("15 phút");
    await userEvent.click(within(dialog).getByRole("button", { name: "Áp dụng" }));
    expect(await within(dialog).findByRole("button", { name: "Xác thực lại" })).toBeInTheDocument();
  });

  it("rollback ⇒ 202 ⇒ mở version mới kèm job", async () => {
    const old = version(V2, { state: "superseded", approved_at: "2026-11-18T00:00:00Z", approved_by: OTHER_IDENTITY });
    const rolled = version(V3, { state: "approved", desired: true, rollback_of: V2, approved_at: "2026-11-18T00:00:00Z" });
    const { router, requests } = (() => {
      const m = mockApi({
        ...common("tenant_admin"),
        [`GET ${vpath(V2)}`]: etagged(old),
        [`GET ${vpath(V2)}/diff`]: diff,
        [`POST ${vpath(V2)}/rollback`]: json(202, { version: rolled, job: job("queued") }, { Location: `/api/v1/tenants/${TENANT_A}/jobs/${JOB}` }),
        [`GET ${vpath(V3)}`]: etagged(rolled),
        [`GET ${vpath(V3)}/diff`]: diff,
        [`GET ${base}/jobs/${JOB}`]: json(200, job("succeeded")),
      });
      return { ...renderApp({ path: `/t/${TENANT_A}/policies/${V2}` }), requests: m.requests };
    })();
    expect(screen.queryByRole("button", { name: "Áp dụng" })).toBeNull();
    await userEvent.click(await screen.findByRole("button", { name: "Rollback về nội dung này" }));
    const dialog = await screen.findByRole("alertdialog", { name: "Rollback về nội dung của version 2?" });
    await userEvent.click(within(dialog).getByRole("button", { name: "Rollback về nội dung này" }));
    await screen.findByRole("heading", { name: "Version 3", level: 1 });
    expect(router.state.location.pathname).toBe(`/t/${TENANT_A}/policies/${V3}`);
    expect(router.state.location.search).toBe(`?job=${JOB}`);
    expect(await screen.findByTestId("apply-done")).toBeInTheDocument();
    expect(find(requests, "POST", "/rollback")[0]!.headers.get("Idempotency-Key")).toMatch(UUID4);
  });

  it("version đã duyệt: Biểu mẫu chỉ đọc (không Thêm/Gỡ luật, không Lưu), tạo bản nháp từ version này (G4b-E15)", async () => {
    const { requests } = mockApi({
      ...common("tenant_admin"),
      [`GET ${vpath(V2)}`]: etagged(approved),
      [`GET ${vpath(V2)}/diff`]: diff,
      [`POST ${base}/policies`]: json(201, version(V3), { ETag: '"1"' }),
      [`GET ${vpath(V3)}`]: etagged(version(V3)),
      [`GET ${vpath(V3)}/diff`]: diff,
    });
    const { router } = renderApp({ path: `/t/${TENANT_A}/policies/${V2}` });
    const sealed = await screen.findByTestId("policy-sealed");
    expect(sealed).toHaveTextContent("Đã duyệt");
    for (const name of [/^Thêm luật/, /^Gỡ luật/, "Lưu bản nháp", "Kiểm tra", "Tạo bản nháp mới từ nội dung này"]) {
      expect(screen.queryByRole("button", { name })).toBeNull();
    }
    // áp dụng vẫn còn (quyền áp dụng của version đã duyệt)
    expect(screen.getByRole("button", { name: "Áp dụng" })).toBeEnabled();
    await userEvent.click(within(sealed).getByRole("button", { name: "Tạo bản nháp từ version này" }));
    await screen.findByRole("heading", { name: "Version 3", level: 1 });
    expect(router.state.location.pathname).toBe(`/t/${TENANT_A}/policies/${V3}`);
    const post = find(requests, "POST", "/policies")[0]!;
    expect(post.headers.get("Idempotency-Key")).toMatch(UUID4);
    expect(await bodyOf(post)).toEqual({ source: SOURCE });
    // không PATCH nào lên version đã duyệt
    expect(requests.filter((r) => r.method === "PATCH")).toHaveLength(0);
    // bản nháp mới: Biểu mẫu sửa được
    expect(await screen.findByRole("button", { name: "Lưu bản nháp" })).toBeInTheDocument();
    expect(screen.queryByTestId("policy-sealed")).toBeNull();
  });

  it("Viewer: không có nút soạn/duyệt/áp dụng; tenant tạm ngưng ⇒ chỉ đọc", async () => {
    mockApi({ ...common("tenant_viewer"), [`GET ${vpath(V2)}`]: etagged(approved), [`GET ${vpath(V2)}/diff`]: diff });
    renderApp({ path: `/t/${TENANT_A}/policies/${V2}` });
    await screen.findByTestId("policy-actions");
    for (const name of ["Áp dụng", "Kiểm tra", "Xác nhận và duyệt", "Tạo bản nháp mới từ nội dung này", "Lưu bản nháp"]) {
      expect(screen.queryByRole("button", { name })).toBeNull();
    }
    expect(screen.queryByRole("button", { name: /Thêm vào/ })).toBeNull();
  });
});

describe("danh mục tag", () => {
  it("danh sách; tag nền tảng chỉ đọc; tạo với Idempotency-Key; xóa còn tham chiếu ⇒ 409 kèm số lượng", async () => {
    const { requests } = mockApi({
      ...common("tenant_admin"),
      [`POST ${base}/tags`]: json(201, tag("0190e200-0000-7000-8000-000000000009", "tag:db", { purpose: "custom" }), { ETag: '"1"' }),
      [`DELETE ${base}/tags/${T_WEB}`]: problem(409, "conflict", {
        detail: "The tag is still in use: 2 device(s), 0 enrollment key(s), 0 network resource(s), 1 policy version(s) or applied policies refer to it.",
      }),
    });
    renderApp({ path: `/t/${TENANT_A}/tags` });
    const table = await screen.findByTestId("tag-table");
    const router = within(table).getByText("tag:router").closest("tr")!;
    expect(within(router).getByText("chỉ đọc")).toBeInTheDocument();
    expect(within(router).queryByRole("button")).toBeNull();
    // tạo
    const name = screen.getByLabelText("Tên tag");
    await userEvent.type(name, "db");
    await userEvent.click(screen.getByRole("button", { name: "Khai báo" }));
    expect(await screen.findByTestId("tag-created")).toHaveTextContent("tag:db");
    const post = find(requests, "POST", "/tags")[0]!;
    expect(post.headers.get("Idempotency-Key")).toMatch(UUID4);
    expect(await bodyOf(post)).toEqual({ name: "tag:db", purpose: "custom" });
    // xóa còn tham chiếu
    await userEvent.click(screen.getByRole("button", { name: "Xóa tag:web" }));
    const dialog = await screen.findByRole("alertdialog", { name: "Xóa tag tag:web?" });
    await userEvent.click(within(dialog).getByRole("button", { name: "Xóa" }));
    expect(await within(dialog).findByText(/2 device\(s\).*1 policy version/)).toBeInTheDocument();
    expect(within(dialog).getByTestId("tag-in-use")).toBeInTheDocument();
    const del = find(requests, "DELETE", `/tags/${T_WEB}`)[0]!;
    expect(del.headers.get("If-Match")).toBe('"1"');
  });

  it("sửa mô tả: PATCH If-Match; 412 ⇒ báo tải lại; tên sai không gửi", async () => {
    const { requests } = mockApi({
      ...common("tenant_admin"),
      [`PATCH ${base}/tags/${T_WEB}`]: problem(412, "precondition_failed"),
    });
    renderApp({ path: `/t/${TENANT_A}/tags` });
    await userEvent.click(await screen.findByRole("button", { name: "Sửa mô tả của tag:web" }));
    const dialog = await screen.findByRole("dialog", { name: "Mô tả của tag:web" });
    const box = within(dialog).getByLabelText("Mô tả");
    await userEvent.clear(box);
    await userEvent.type(box, "máy chủ web");
    await userEvent.click(within(dialog).getByRole("button", { name: "Lưu" }));
    expect(await within(dialog).findByText(/được sửa ở nơi khác/)).toBeInTheDocument();
    const patch = find(requests, "PATCH", `/tags/${T_WEB}`)[0]!;
    expect(patch.headers.get("If-Match")).toBe('"1"');
    expect(await bodyOf(patch)).toEqual({ description: "máy chủ web" });
    await userEvent.click(within(dialog).getByRole("button", { name: "Hủy" }));
    const name = screen.getByLabelText("Tên tag");
    await userEvent.clear(name);
    await userEvent.type(name, "tag:Bad Name");
    expect(screen.getByRole("button", { name: "Khai báo" })).toBeDisabled();
    expect(TAGS.items[1]!.id).toBe(T_ROUTER);
  });

  it("Viewer: không tạo/sửa/xóa", async () => {
    mockApi(common("tenant_viewer"));
    renderApp({ path: `/t/${TENANT_A}/tags` });
    await screen.findByTestId("tag-table");
    expect(screen.queryByLabelText("Tên tag")).toBeNull();
    expect(screen.queryByRole("button", { name: /Xóa/ })).toBeNull();
  });
});

describe("điều hướng", () => {
  it("mục Policies và Danh mục tag hiện theo quyền; id version không phải UUID ⇒ 404 không gọi API", async () => {
    const { requests } = mockApi(common("tenant_admin"));
    renderApp({ path: `/t/${TENANT_A}/policies/khong-phai-uuid` });
    expect(await screen.findByRole("link", { name: "Policy truy cập" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Danh mục tag" })).toBeInTheDocument();
    expect(await screen.findByRole("heading", { level: 1 })).toBeInTheDocument();
    expect(requests.some((r) => r.url.includes("/policies/khong"))).toBe(false);
  });

  it("End User không có quyền đọc policy ⇒ không có mục, trang trả 403", async () => {
    mockApi(common("end_user"));
    renderApp({ path: `/t/${TENANT_A}/policies` });
    expect(await screen.findByText(/không có quyền/i)).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Policy truy cập" })).toBeNull();
  });
});
