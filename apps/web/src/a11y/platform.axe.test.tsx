// a11y của Platform Console (P4-T02): axe-core trên các màn hình mới, hai ngôn ngữ — danh sách/chi tiết tenant, wizard,
// job timeline, hàng chờ + chi tiết phê duyệt, hộp xác nhận thao tác phá hủy đang mở. color-contrast kiểm trong trình
// duyệt thật ở P4-T14 (jsdom không tính màu).
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import axe from "axe-core";
import { describe, expect, it } from "vitest";
import { i18n } from "../i18n";
import { json, mockApi, platformSession, renderApp } from "../test/helpers";
import { approval, APPR1, failedJob, instance, JOB1, JOB2, provisionedJob, relayList, safeJob, T1, tenant } from "../test/platformFixtures";

async function violations(): Promise<string[]> {
  const r = await axe.run(document.body, {
    runOnly: { type: "tag", values: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "best-practice"] },
    rules: { "color-contrast": { enabled: false } },
  });
  return r.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(" ")).join(", ")}`);
}

const routes = {
  "GET /auth/session": json(200, platformSession("super_admin")),
  "GET /platform/tenants": json(200, { items: [tenant(T1, "acme")], next_cursor: "n1" }),
  [`GET /platform/tenants/${T1}`]: json(200, tenant(T1, "acme"), { ETag: '"3"' }),
  [`GET /platform/tenants/${T1}/instances`]: json(200, { items: [instance(T1)], next_cursor: null }),
  [`GET /platform/tenants/${T1}/relay-regions`]: json(200, relayList(T1)),
  [`GET /platform/tenants/${T1}/jobs`]: json(200, { items: [safeJob(provisionedJob(JOB2, T1))], next_cursor: null }),
  "GET /platform/jobs": json(200, { items: [safeJob(failedJob(JOB1, T1))], next_cursor: null }),
  [`GET /platform/jobs/${JOB1}`]: json(200, failedJob(JOB1, T1)),
  "GET /platform/approvals": json(200, { items: [approval()], next_cursor: null }),
  [`GET /platform/approvals/${APPR1}`]: json(200, approval()),
};

describe.each(["vi", "en"] as const)("axe Platform Console (%s)", (lng) => {
  it("tenant: danh sách, chi tiết, hộp xác nhận xóa đang mở", async () => {
    await i18n.changeLanguage(lng);
    mockApi(routes);
    const { router } = renderApp({ path: "/platform/tenants", console: "platform" });
    await screen.findByRole("link", { name: "acme" });
    expect(await violations()).toEqual([]);
    await router.navigate(`/platform/tenants/${T1}`);
    await screen.findByTestId("instance");
    await screen.findByTestId("relay-unavailable");
    expect(await violations()).toEqual([]);
    await userEvent.click(screen.getByRole("button", { name: lng === "vi" ? "Xóa tenant…" : "Delete tenant…" }));
    await screen.findByRole("alertdialog");
    expect(await violations()).toEqual([]);
  });

  it("wizard tạo tenant (bước 1 có lỗi, bước 2)", async () => {
    await i18n.changeLanguage(lng);
    mockApi(routes);
    renderApp({ path: "/platform/tenants/new", console: "platform" });
    const next = await screen.findByRole("button", { name: lng === "vi" ? "Tiếp" : "Next" });
    await userEvent.click(next);
    expect(await violations()).toEqual([]);
  });

  it("job: danh sách + timeline có lỗi và nút điều khiển", async () => {
    await i18n.changeLanguage(lng);
    mockApi(routes);
    const { router } = renderApp({ path: "/platform/jobs", console: "platform" });
    await screen.findAllByRole("link", { name: "tenant.provision" });
    expect(await violations()).toEqual([]);
    await router.navigate(`/platform/jobs/${JOB1}`);
    await screen.findByTestId("poll-status");
    expect(await violations()).toEqual([]);
  });

  it("phê duyệt: hàng chờ + chi tiết (payload, hash)", async () => {
    await i18n.changeLanguage(lng);
    mockApi(routes);
    const { router } = renderApp({ path: "/platform/approvals", console: "platform" });
    await screen.findAllByRole("link");
    await screen.findByRole("table");
    expect(await violations()).toEqual([]);
    await router.navigate(`/platform/approvals/${APPR1}`);
    await waitFor(() => {
      expect(screen.getByTestId("local-hash").textContent).toMatch(/^[0-9a-f]{64}$/);
    });
    expect(await violations()).toEqual([]);
  });
});
