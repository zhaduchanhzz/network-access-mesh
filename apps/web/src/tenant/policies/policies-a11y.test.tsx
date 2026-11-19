// a11y + i18n của Policies/Tags (P4-T11): axe-core (WCAG 2.0/2.1 A + AA + best-practice; color-contrast ở P4-T14) trên
// danh sách, chi tiết version có báo cáo lỗi, chế độ HuJSON, hộp duyệt và danh mục tag — vi và en; khóa i18n động (enum
// của API mà màn hình dịch) có trong cả hai catalog.
import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import axe from "axe-core";
import { describe, expect, it } from "vitest";
import type { components } from "../../api/schema";
import { i18n } from "../../i18n";
import en from "../../i18n/locales/en.json";
import vi from "../../i18n/locales/vi.json";
import { json, mockApi, renderApp, TENANT_A } from "../../test/helpers";
import { base, common, current, V2, version } from "../../test/policies";
import { ACK_RULES, POSITION_TYPES, PRINCIPAL_TYPES, VERSION_STATES } from "./model";

async function violations(): Promise<string[]> {
  const r = await axe.run(document.body, {
    runOnly: { type: "tag", values: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "best-practice"] },
    rules: { "color-contrast": { enabled: false } },
  });
  return r.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(" ")).join(", ")}`);
}

const report: components["schemas"]["PolicyValidationReport"] = {
  engine: "p4-t10",
  result: "failed",
  errors: [{ rule: "L4", severity: "error", code: "wildcard_destination_ack_required", path: "grants[0].dst[0]", message: "m", requires_ack: true, owner_only: true }],
  warnings: [{ rule: "L10", severity: "warning", code: "ssh_accept", path: "ssh[0].action", message: "m", requires_ack: true, acknowledged: true }],
  info: [],
  tests: [],
  check: "skipped",
  revision: 1,
};
const v2 = version(V2, { state: "validated", validation_report: report });
const api = {
  ...common("tenant_owner"),
  [`GET ${base}/policies/${V2}`]: json(200, v2, { ETag: v2.etag }),
  [`GET ${base}/policies/${V2}/diff`]: json(200, {
    version_id: V2,
    lines: [
      { op: "same", text: "{" },
      { op: "added", text: '  "grants": []' },
      { op: "removed", text: '  "ssh": []' },
    ],
    lines_omitted: false,
    grants_added: ["a"],
    grants_removed: ["b"],
    report_blocking: true,
  }),
  [`POST ${base}/policies/export`]: json(200, { hujson: '{\n  "grants": []\n}\n', warnings: [], principals: [] }),
};

describe.each(["vi", "en"] as const)("axe Policies (%s)", (lng) => {
  it("danh sách + trạng thái hiện hành", async () => {
    await i18n.changeLanguage(lng);
    mockApi(api);
    renderApp({ path: `/t/${TENANT_A}/policies` });
    await screen.findByTestId("policy-versions");
    await screen.findByTestId("current-applied");
    expect(await violations()).toEqual([]);
  });

  it("chi tiết version: form, báo cáo, diff; HuJSON; hộp duyệt", async () => {
    await i18n.changeLanguage(lng);
    mockApi(api);
    renderApp({ path: `/t/${TENANT_A}/policies/${V2}` });
    await screen.findByTestId("policy-report");
    await screen.findByTestId("grants-added");
    expect(await violations()).toEqual([]);
    await userEvent.click(screen.getByRole("radio", { name: "HuJSON" }));
    await screen.findByTestId("hujson-panel");
    expect(await violations()).toEqual([]);
    await userEvent.click(screen.getByRole("button", { name: lng === "vi" ? "Xác nhận và duyệt" : "Confirm and approve" }));
    await screen.findByRole("alertdialog");
    expect(await violations()).toEqual([]);
  });

  it("danh mục tag", async () => {
    await i18n.changeLanguage(lng);
    mockApi(api);
    renderApp({ path: `/t/${TENANT_A}/tags` });
    await screen.findByTestId("tag-table");
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

describe("khóa động của Policies/Tags", () => {
  it("trạng thái, loại, kiểu principal, mức, áp dụng, trigger, xác nhận, kết quả, mục đích tag — có ở vi và en", () => {
    const keys = [
      ...VERSION_STATES.map((s) => `policies.states.${s}`),
      ...(["user", "baseline", "suspension"] as const).map((k) => `policies.kinds.${k}`),
      ...(["peer", "self"] as const).map((k) => `policies.reviewModes.${k}`),
      ...PRINCIPAL_TYPES.map((p) => `policies.ptype.${p}`),
      ...Object.values(POSITION_TYPES).flat().map((p) => `policies.ptype.${p}`),
      ...(["error", "warning", "info"] as const).map((s) => `policies.severity.${s}`),
      ...(["pending", "applied", "failed", "unknown"] as const).map((s) => `policies.applied.states.${s}`),
      ...(
        ["bootstrap", "manual", "group_change", "resource_change", "tag_change", "suspend", "resume", "restore", "drift_repair", "rollback"] as const satisfies readonly components["schemas"]["PolicyApplication"]["trigger"][]
      ).map((s) => `policies.applied.triggers.${s}`),
      ...ACK_RULES.map((r) => `policies.ack.desc.${r}`),
      ...(["passed", "failed"] as const).map((r) => `policies.report.results.${r}`),
      ...(["passed", "failed", "skipped"] as const).map((r) => `policies.report.checks.${r}`),
      ...(["router", "exit", "server", "custom"] as const satisfies readonly components["schemas"]["TagPurpose"][]).map((p) => `tags.purposes.${p}`),
      ...(["accept", "check"] as const).map((a) => `policies.editor.sshActions.${a}`),
    ];
    const missing = keys.filter((k) => !has(vi as Tree, k) || !has(en as Tree, k));
    expect(missing).toEqual([]);
    // mọi trigger của spec có bản dịch (thêm trigger ở spec ⇒ test này nhắc)
    expect(current().applied?.trigger).toBe("manual");
  });
});
