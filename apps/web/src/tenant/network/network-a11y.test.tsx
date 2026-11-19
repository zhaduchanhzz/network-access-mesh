// a11y + i18n của ba màn hình mạng (P4-T12): axe-core (WCAG 2.0/2.1 A + AA + best-practice; color-contrast kiểm trong
// trình duyệt thật ở P4-T14) trên Routes (+ hộp duyệt exit node), DNS (+ hộp xác nhận đổi nameserver, lỗi field của
// bản ghi), Tài nguyên mạng (+ hộp sửa) — vi và en; khóa i18n động (enum của API mà màn hình dịch) có trong cả hai catalog.
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import axe from "axe-core";
import { describe, expect, it } from "vitest";
import type { components } from "../../api/schema";
import { i18n } from "../../i18n";
import en from "../../i18n/locales/en.json";
import vi from "../../i18n/locales/vi.json";
import { json, mockApi, problem, renderApp, TENANT_A, tenantBody, tenantSession } from "../../test/helpers";
import { APPROVAL_ID, approvalRequest, dnsRecord, dnsView, gateway, group, laptopRouter, resource, tag } from "../../test/network";
import { RESOURCE_KINDS, RESOURCE_PROTOCOLS } from "./ResourcesPage";

async function violations(): Promise<string[]> {
  const r = await axe.run(document.body, {
    runOnly: { type: "tag", values: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "best-practice"] },
    rules: { "color-contrast": { enabled: false } },
  });
  return r.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(" ")).join(", ")}`);
}

const base = `/tenants/${TENANT_A}`;
const api = {
  "GET /auth/session": json(200, tenantSession([{ tenantId: TENANT_A, slug: "tenant-a", name: "Tenant A", role: "tenant_owner" }])),
  [`GET ${base}`]: json(200, tenantBody(TENANT_A, "tenant-a")),
  [`GET ${base}/notifications`]: json(200, { items: [], next_cursor: null }),
  [`GET ${base}/routes`]: json(200, { items: [gateway(), laptopRouter()] }),
  [`GET ${base}/dns`]: json(200, dnsView({ pending: { job_id: "0190a600-0000-7000-8000-000000000009", status: "running" } })),
  [`GET ${base}/jobs/0190a600-0000-7000-8000-000000000009`]: json(200, {
    id: "0190a600-0000-7000-8000-000000000009",
    kind: "instance.reconfigure",
    tenant_id: TENANT_A,
    status: "running",
    current_step: null,
    steps: [],
    created_at: "2026-11-19T02:00:00Z",
  }),
  [`GET ${base}/dns/records`]: json(200, { items: [dnsRecord()] }),
  [`POST ${base}/dns/records`]: problem(422, "validation_failed", { errors: [{ field: "value", code: "value_not_in_tailnet", message: "x" }] }),
  [`GET ${base}/resources`]: json(200, { items: [resource()], next_cursor: "r2" }),
  [`GET ${base}/tags`]: json(200, { items: [tag("tag:server", 1), tag("tag:db", 2)], next_cursor: null }),
  [`GET ${base}/groups`]: json(200, { items: [group()], next_cursor: null }),
};

describe.each(["vi", "en"] as const)("axe màn hình mạng (%s)", (lng) => {
  it("Routes + hộp duyệt exit node", async () => {
    await i18n.changeLanguage(lng);
    mockApi(api);
    renderApp({ path: `/t/${TENANT_A}/routes` });
    await screen.findByTestId("routes-table");
    expect(await violations()).toEqual([]);
    await userEvent.click(screen.getByRole("button", { name: lng === "vi" ? "Duyệt exit node gw-1" : "Approve exit node gw-1" }));
    await screen.findByTestId("exit-risk");
    expect(await violations()).toEqual([]);
  });

  it("Routes + hộp duyệt route (cảnh báo)", async () => {
    await i18n.changeLanguage(lng);
    mockApi(api);
    renderApp({ path: `/t/${TENANT_A}/routes` });
    await screen.findByTestId("routes-table");
    await userEvent.click(screen.getByRole("button", { name: lng === "vi" ? "Duyệt route của laptop-an" : "Approve routes of laptop-an" }));
    await screen.findByTestId("dialog-warnings");
    expect(await violations()).toEqual([]);
  });

  it("Routes: 202 (4-eyes) ⇒ khung 'chưa hiệu lực' + link tới trang phê duyệt", async () => {
    await i18n.changeLanguage(lng);
    mockApi({
      ...api,
      [`POST ${base}/routes/approve`]: json(202, approvalRequest(), { Location: `/api/v1/tenants/${TENANT_A}/approvals/${APPROVAL_ID}` }),
      [`GET ${base}/approvals/${APPROVAL_ID}`]: json(200, approvalRequest()),
    });
    renderApp({ path: `/t/${TENANT_A}/routes` });
    await screen.findByTestId("routes-table");
    await userEvent.click(screen.getByRole("button", { name: lng === "vi" ? "Duyệt route của laptop-an" : "Approve routes of laptop-an" }));
    const dialog = screen.getByRole("alertdialog");
    await userEvent.click(within(dialog).getByRole("button", { name: lng === "vi" ? "Duyệt route" : "Approve routes" }));
    const notice = await screen.findByTestId("approval-created");
    expect(within(notice).getByTestId("approval-link")).toHaveAttribute("href", `/t/${TENANT_A}/approvals/${APPROVAL_ID}`);
    expect(await violations()).toEqual([]);
  });

  it("DNS + lỗi field của bản ghi + hộp xác nhận đổi nameserver", async () => {
    await i18n.changeLanguage(lng);
    mockApi(api);
    renderApp({ path: `/t/${TENANT_A}/dns` });
    await screen.findByTestId("record-row");
    await screen.findByTestId("dns-job");
    expect(await violations()).toEqual([]);
    const form = screen.getByTestId("record-form");
    const [name, value] = within(form).getAllByRole("textbox");
    await userEvent.type(name!, "nas.corp.example");
    await userEvent.type(value!, "203.0.113.9");
    await userEvent.click(within(form).getByRole("button"));
    await waitFor(() => expect(value).toHaveAttribute("aria-invalid", "true"));
    expect(await violations()).toEqual([]);
  });

  it("DNS: hộp xác nhận đổi nameserver", async () => {
    await i18n.changeLanguage(lng);
    mockApi({ ...api, [`GET ${base}/dns`]: json(200, dnsView()) });
    renderApp({ path: `/t/${TENANT_A}/dns` });
    const textarea = await screen.findByRole("textbox", { name: /Nameserver/ });
    await userEvent.type(textarea, "{enter}8.8.8.8");
    await userEvent.click(screen.getByRole("button", { name: lng === "vi" ? "Đổi nameserver…" : "Change nameservers…" }));
    await screen.findByTestId("dns-restart-warning");
    expect(await violations()).toEqual([]);
  });

  it("Tài nguyên mạng + hộp sửa", async () => {
    await i18n.changeLanguage(lng);
    mockApi(api);
    renderApp({ path: `/t/${TENANT_A}/resources` });
    await screen.findByTestId("resource-row");
    expect(await violations()).toEqual([]);
    await userEvent.click(screen.getByRole("button", { name: lng === "vi" ? "Sửa tài nguyên web-prod" : "Edit resource web-prod" }));
    await screen.findByTestId("resource-form");
    await screen.findByLabelText("tag:db");
    expect(await violations()).toEqual([]);
  });
});

type Tree = { [k: string]: string | Tree };
function has(tree: Tree, key: string): boolean {
  let node: string | Tree | undefined = tree;
  for (const part of key.split(".")) {
    if (typeof node !== "object") return false;
    node = node[part] ?? node[`${part}_other`];
  }
  return typeof node === "string";
}

describe("khóa i18n động của P4-T12", () => {
  it("enum của API mà màn hình dịch có trong vi và en", () => {
    const warnings: components["schemas"]["RouteWarning"]["code"][] = ["overlap", "untagged_router", "exit_node"];
    const approvals: components["schemas"]["ApprovalStatus"][] = ["pending", "approved", "rejected", "expired", "executed"];
    const keys = [
      ...warnings.flatMap((w) => [`network.routes.warningCodes.${w}`, `network.routes.warnings.${w}`]),
      ...RESOURCE_KINDS.map((k) => `network.resources.kinds.${k}`),
      ...RESOURCE_PROTOCOLS.map((p) => `network.resources.protocols.${p}`),
      ...approvals.map((s) => `status.approval.${s}`),
      ...approvals.map((s) => `network.approval.explain.${s}`),
      "network.approval.open",
      "network.approval.sendId",
      "network.routes.approved",
      "network.routes.revoked",
      "network.resources.created",
      "network.resources.updated",
    ];
    expect(keys.filter((k) => !has(vi as Tree, k) || !has(en as Tree, k))).toEqual([]);
  });
});
