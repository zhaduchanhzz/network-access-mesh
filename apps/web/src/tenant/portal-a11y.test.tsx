// a11y + i18n của Tenant Portal (P4-T04): axe-core (WCAG 2.0/2.1 A + AA + best-practice; color-contrast kiểm trong
// trình duyệt thật ở P4-T14) trên dashboard, devices, chi tiết + hộp xác nhận, relay, thông báo — vi và en; khóa i18n
// động (enum của API mà màn hình dịch) có trong cả hai catalog.
import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import axe from "axe-core";
import { describe, expect, it } from "vitest";
import type { components } from "../api/schema";
import { i18n } from "../i18n";
import en from "../i18n/locales/en.json";
import vi from "../i18n/locales/vi.json";
import { json, mockApi, renderApp, TENANT_A, tenantBody, tenantSession } from "../test/helpers";
import { DASHBOARD, DEV_1, device, notification, RELAY, tagged } from "../test/portal";
import { i18nKeyOf, i18nKeyOfKind, NOTIFICATION_KINDS } from "./notifications/notificationText";

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
  [`GET ${base}/dashboard`]: json(200, DASHBOARD),
  [`GET ${base}/devices`]: json(200, { items: [device(DEV_1), tagged()], next_cursor: "c2" }),
  [`GET ${base}/devices/${DEV_1}`]: json(200, device(DEV_1, { revocation: { state: "failed", kind: "expire", requested_at: "2026-11-19T00:00:00Z" } })),
  [`GET ${base}/relay`]: json(200, RELAY),
  [`GET ${base}/notifications`]: json(200, { items: [notification("0190a400-0000-7000-8000-000000000001")], next_cursor: null }),
};

describe.each(["vi", "en"] as const)("axe Tenant Portal (%s)", (lng) => {
  it.each([
    ["overview", "dash-total"],
    ["devices", "devices-table"],
    ["relay", "relay-assignment"],
    ["notifications", "notification"],
  ])("%s", async (path, testId) => {
    await i18n.changeLanguage(lng);
    mockApi(api);
    renderApp({ path: `/t/${TENANT_A}/${path}` });
    await screen.findAllByTestId(testId);
    expect(await violations()).toEqual([]);
  });

  it("chi tiết thiết bị + hộp xác nhận xóa", async () => {
    await i18n.changeLanguage(lng);
    mockApi(api);
    renderApp({ path: `/t/${TENANT_A}/devices/${DEV_1}` });
    await screen.findByTestId("revocation-panel");
    expect(await violations()).toEqual([]);
    await userEvent.click(screen.getAllByRole("button").find((b) => b.className.includes("btn-danger"))!);
    await screen.findByRole("alertdialog");
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

describe("khóa i18n động của P4-T04", () => {
  it("enum của API mà màn hình dịch có trong vi và en", () => {
    const health: components["schemas"]["HealthStatus"][] = ["healthy", "unhealthy", "unknown"];
    const revocation: components["schemas"]["DeviceRevocation"]["state"][] = ["none", "pending", "applied", "failed"];
    const jobs: components["schemas"]["JobStatus"][] = ["queued", "running", "failed_resumable", "compensating", "rolled_back", "succeeded", "failed", "cancelled"];
    const kinds: components["schemas"]["RelayRegionKind"][] = ["embedded", "standalone", "shared"];
    const admin: components["schemas"]["RelayAdminStatus"][] = ["pending", "active", "disabled"];
    const keys = [
      ...health.map((s) => `health.status.${s}`),
      ...revocation.flatMap((s) => [`devices.revocation.state.${s}`, `devices.revocation.explain.${s}`]),
      "devices.revocation.kind.expire",
      "devices.revocation.kind.delete",
      ...jobs.map((s) => `jobs.status.${s}`),
      ...kinds.map((k) => `relay.kinds.${k}`),
      ...admin.map((s) => `relay.adminStatuses.${s}`),
      "relay.verify.in_process",
      "relay.verify.verify_url",
      ...NOTIFICATION_KINDS.map(i18nKeyOfKind),
      ...["enrollment.approved", "enrollment.rejected"].map((k) => i18nKeyOf(k, { by_support: true })),
      "notif.kinds.unknown",
      ...["never_synced", "no_source", "not_served"].map((r) => `dashboard.reasons.${r}`),
      ...["traffic_bytes", "throughput", "connections", "auth_failures", "client_latency"].map((m) => `relay.metrics.${m}`),
    ];
    expect(keys.filter((k) => !has(vi as Tree, k) || !has(en as Tree, k))).toEqual([]);
  });
});
