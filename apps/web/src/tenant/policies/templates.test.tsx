// Template least-privilege + tests sinh tự động trong editor policy (P5-T01) — App trên router bộ nhớ, API giả ở tầng
// fetch theo đúng hợp đồng của spec. Kiểm: danh mục từ server, ghi chú V-24, tham số (group/tài nguyên/cổng — `*` bị chặn
// trước khi gửi), POST /policies/templates/render đúng thân, đoạn được THÊM vào bản nháp (rồi PATCH như mọi lần sửa),
// deny-all THAY bản nháp, 422 của server hiện ra, role không soạn không thấy panel; báo cáo hiện các ca tests và lý do bỏ.
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import type { components } from "../../api/schema";
import { json, mockApi, problem, renderApp, TENANT_A } from "../../test/helpers";
import { base, common, G_ENG, R_DB, RESOURCES, SOURCE, T_WEB, version, V2 } from "../../test/policies";
import { mergeTemplate, templatePortProblems } from "./TemplatePanel";

type S = components["schemas"];
const vpath = `${base}/policies/${V2}`;
const diff = json(200, { version_id: V2, lines: [], lines_omitted: false, grants_added: [], grants_removed: [], report_blocking: false });

function rendered(over: Partial<S["PolicyTemplateRender"]> = {}): S["PolicyTemplateRender"] {
  return {
    template_id: "group-to-resource",
    version: 1,
    mode: "append",
    source: { grants: [{ src: [{ type: "group", ref: G_ENG }], dst: [{ type: "resource", ref: R_DB }], ip: ["tcp:443", "tcp:8443"] }], ssh: [] },
    report: { engine: "p4-t10", result: "passed", errors: [], warnings: [], info: [], tests: [{ grant: 0, skipped: "no_source_device" }] },
    ...over,
  };
}

async function bodyOf(r: Request): Promise<unknown> {
  return JSON.parse(await r.clone().text()) as unknown;
}

function find(requests: Request[], method: string, suffix: string): Request[] {
  return requests.filter((r) => r.method === method && new URL(r.url).pathname.endsWith(suffix));
}

describe("hàm thuần của template", () => {
  it("cổng: cú pháp ip, không nhận * hay proto:*", () => {
    expect(templatePortProblems("tcp:22, tcp:443 udp:53")).toEqual([]);
    expect(templatePortProblems("tcp:22, *, tcp:*, ssh")).toEqual(["*", "tcp:*", "ssh"]);
  });

  it("append thêm luật vào cuối (giữ xác nhận), replace thay toàn bộ", () => {
    const draft: S["PolicySource"] = { ...SOURCE, acknowledgements: [{ rule: "L10", reason: "cần SSH" }] };
    const frag = rendered().source;
    const merged = mergeTemplate(draft, { mode: "append", source: frag });
    expect(merged.grants).toEqual([...SOURCE.grants, ...frag.grants]);
    expect(merged.acknowledgements).toEqual(draft.acknowledgements);
    expect(mergeTemplate(draft, { mode: "replace", source: { grants: [], ssh: [] } })).toEqual({ grants: [], ssh: [] });
  });
});

describe("template trong editor", () => {
  it("group → tài nguyên: tham số từ danh mục, render ở server, đoạn được thêm vào bản nháp rồi PATCH", async () => {
    const saved = version(V2, { revision: 2 });
    const { requests } = mockApi({
      ...common("tenant_admin"),
      [`GET ${vpath}`]: json(200, version(V2), { ETag: '"1"' }),
      [`GET ${vpath}/diff`]: diff,
      [`GET ${base}/resources`]: json(200, RESOURCES),
      [`POST ${base}/policies/templates/render`]: json(200, rendered()),
      [`PATCH ${vpath}`]: json(200, saved, { ETag: '"2"' }),
    });
    renderApp({ path: `/t/${TENANT_A}/policies/${V2}` });
    const panel = await screen.findByTestId("policy-templates");
    await userEvent.selectOptions(await within(panel).findByLabelText("Template"), "group-to-resource");
    const form = within(panel).getByTestId("template-form");
    const apply = within(form).getByRole("button", { name: "Thêm vào bản nháp" });
    expect(apply).toBeDisabled(); // group và tài nguyên chưa chọn
    await userEvent.selectOptions(within(form).getByLabelText("Group được cấp quyền"), G_ENG);
    await userEvent.selectOptions(await within(form).findByLabelText("Tài nguyên mạng"), await within(form).findByRole("option", { name: "db (10.20.0.5)" }));
    const ports = within(form).getByLabelText("Giao thức/cổng");
    expect(ports).toHaveValue("tcp:443"); // gợi ý least-privilege của template
    await userEvent.type(ports, ", tcp:8443");
    await userEvent.click(apply);
    await waitFor(() => expect(find(requests, "POST", "/policies/templates/render")).toHaveLength(1));
    expect(await bodyOf(find(requests, "POST", "/policies/templates/render")[0]!)).toEqual({
      template_id: "group-to-resource",
      version: 1,
      params: { group_id: G_ENG, resource_id: R_DB, ports: ["tcp:443", "tcp:8443"] },
    });
    expect(await screen.findByRole("status")).toHaveTextContent("Đã thêm 1 luật từ “Group → tài nguyên theo cổng” (v1) vào bản nháp");
    // luật mới hiện trong form với tên của group và tài nguyên
    const g2 = await screen.findByTestId("grant-1");
    expect(within(g2).getByText("group:eng")).toBeInTheDocument();
    expect(within(g2).getByText("db")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Lưu bản nháp" }));
    await waitFor(() => expect(find(requests, "PATCH", `/policies/${V2}`)).toHaveLength(1));
    expect(await bodyOf(find(requests, "PATCH", `/policies/${V2}`)[0]!)).toEqual({
      source: { grants: [...SOURCE.grants, ...rendered().source.grants], ssh: [] },
    });
  });

  it("ghi chú V-24 của template self/via; cổng * bị chặn trước khi gửi; 422 của server hiện ra", async () => {
    const { requests } = mockApi({
      ...common("tenant_admin"),
      [`GET ${vpath}`]: json(200, version(V2), { ETag: '"1"' }),
      [`GET ${vpath}/diff`]: diff,
      [`POST ${base}/policies/templates/render`]: problem(422, "validation_failed", {
        errors: [{ field: "params.tag_id", code: "not_found", message: "has an invalid value" }],
      }),
    });
    renderApp({ path: `/t/${TENANT_A}/policies/${V2}` });
    const panel = await screen.findByTestId("policy-templates");
    const select = await within(panel).findByLabelText("Template");
    await userEvent.selectOptions(select, "own-devices");
    expect(within(panel).getByTestId("template-notes")).toHaveTextContent("KHÔNG khẳng định được quyền tới autogroup:self");
    const ports = within(panel).getByLabelText("Giao thức/cổng");
    await userEvent.clear(ports);
    await userEvent.type(ports, "tcp:*");
    expect(within(panel).getByTestId("template-ports-invalid")).toHaveTextContent("tcp:*");
    expect(ports).toHaveAttribute("aria-invalid", "true");
    expect(within(panel).getByRole("button", { name: "Thêm vào bản nháp" })).toBeDisabled();

    await userEvent.selectOptions(select, "exit-node");
    const notes = within(panel).getByTestId("template-notes");
    expect(notes).toHaveTextContent("KHÔNG khẳng định được quyền đi qua via");
    expect(notes).toHaveTextContent("Route của router/exit node vẫn phải được duyệt riêng");
    await userEvent.selectOptions(within(panel).getByLabelText("Group được cấp quyền"), G_ENG);
    await userEvent.selectOptions(within(panel).getByLabelText("Tag của router / exit node (via)"), T_WEB);
    await userEvent.click(within(panel).getByRole("button", { name: "Thêm vào bản nháp" }));
    await within(panel).findByRole("alert");
    expect(find(requests, "POST", "/policies/templates/render")).toHaveLength(1);
    expect(await bodyOf(find(requests, "POST", "/policies/templates/render")[0]!)).toEqual({
      template_id: "exit-node",
      version: 1,
      params: { group_id: G_ENG, tag_id: T_WEB },
    });
    expect(screen.queryByText("Chưa lưu")).toBeNull(); // không có gì được thêm
  });

  it("deny-all thay toàn bộ bản nháp", async () => {
    mockApi({
      ...common("tenant_admin"),
      [`GET ${vpath}`]: json(200, version(V2), { ETag: '"1"' }),
      [`GET ${vpath}/diff`]: diff,
      [`POST ${base}/policies/templates/render`]: json(
        200,
        rendered({ template_id: "deny-all", mode: "replace", source: { grants: [], ssh: [] }, report: { engine: "p4-t10", result: "passed", errors: [], warnings: [], info: [], tests: [] } }),
      ),
    });
    renderApp({ path: `/t/${TENANT_A}/policies/${V2}` });
    const panel = await screen.findByTestId("policy-templates");
    await userEvent.selectOptions(await within(panel).findByLabelText("Template"), "deny-all");
    expect(within(panel).getByTestId("template-notes")).toHaveTextContent("Thay toàn bộ luật của bản nháp.");
    await userEvent.click(within(panel).getByRole("button", { name: "Thay bản nháp" }));
    expect(await screen.findByRole("status")).toHaveTextContent("Bản nháp đã được thay bằng “Baseline deny-all” (v1)");
    expect(screen.getByText("Không có luật nào: policy này chặn mọi kết nối (deny-all).")).toBeInTheDocument();
    expect(screen.queryByTestId("grant-0")).toBeNull();
    expect(screen.getByText("Chưa lưu")).toBeInTheDocument();
  });

  it("role chỉ đọc không thấy template", async () => {
    mockApi({ ...common("tenant_viewer"), [`GET ${vpath}`]: json(200, version(V2), { ETag: '"1"' }), [`GET ${vpath}/diff`]: diff });
    renderApp({ path: `/t/${TENANT_A}/policies/${V2}` });
    await screen.findByTestId("policy-form");
    expect(screen.queryByTestId("policy-templates")).toBeNull();
  });
});

describe("tests sinh tự động trong báo cáo", () => {
  it("các ca (nguồn, phải được phép / phải bị chặn) và luật không có ca kèm lý do V-24 / PL-04", async () => {
    const report: S["PolicyValidationReport"] = {
      engine: "p4-t10",
      result: "passed",
      errors: [],
      warnings: [],
      info: [{ rule: "tests", severity: "info", code: "via_not_asserted", path: "grants[1]", message: "m" }],
      tests: [
        { grant: 0, src: "group:eng", proto: "tcp", accept: ["tag:web:443"], deny: ["tag:web:65535"] },
        { grant: 1, skipped: "via_not_assertable" },
        { grant: 2, skipped: "no_source_device" },
      ],
      check: "passed",
      revision: 1,
    };
    mockApi({
      ...common("tenant_admin"),
      [`GET ${vpath}`]: json(200, version(V2, { state: "validated", validation_report: report }), { ETag: '"1"' }),
      [`GET ${vpath}/diff`]: diff,
    });
    renderApp({ path: `/t/${TENANT_A}/policies/${V2}` });
    const tests = await screen.findByTestId("generated-tests");
    expect(tests).toHaveAttribute("data-count", "1");
    expect(tests).toHaveTextContent("1 ca được sinh · 2 luật không có ca");
    expect(tests).toHaveTextContent("KHÔNG khẳng định được quyền từ via hay autogroup:self — không phải mô phỏng");
    const made = within(tests).getByText("group:eng").closest("li")!;
    expect(made).toHaveTextContent("phải được phép: tag:web:443");
    expect(made).toHaveTextContent("phải bị chặn: tag:web:65535");
    expect(tests.querySelector('[data-skipped="via_not_assertable"]')).toHaveTextContent("Luật 2: có via — tests không thấy");
    expect(tests.querySelector('[data-skipped="no_source_device"]')).toHaveTextContent("Luật 3: chưa nguồn nào có thiết bị");
    // phát hiện Info V-24 có bản dịch
    expect(screen.getAllByText("tests sinh tự động không khẳng định được quyền đi qua via của luật này.").length).toBeGreaterThan(0);
  });
});
