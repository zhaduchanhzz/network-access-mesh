// Platform Console trên admin. với Super Admin thật (phiên từ auth.setup.ts): mọi mục điều hướng role thấy (màn hình
// đã xây: render từ API thật; mục chưa xây: trang "chưa khả dụng"), các trang chi tiết (tenant, job timeline,
// instance, host, IdP), wizard tạo tenant (lỗi kiểm hợp lệ, KHÔNG gửi), hộp sửa thiết lập (mở rồi đóng) — mỗi trang:
// axe WCAG 2.1 AA + i18n + CSP/5xx (fixture guard). Chỉ đọc: không thao tác ghi nào lên stack.
import type { Page, TestInfo } from "@playwright/test";
import { PLATFORM_NAV, visibleItems } from "../src/nav/navModel";
import { ADMIN, cfg, storageFile } from "./env";
import { checkA11y, checkScreen, expect, lngOf, T, test } from "./support";

test.use({ storageState: storageFile("sa") });

async function openFirstDetail(page: Page, testInfo: TestInfo, list: string, hrefPrefix: string, label: string) {
  await page.goto(`${ADMIN}${list}`);
  await checkScreen(page, testInfo, `${label}-list`);
  const link = page.locator(`main tbody a[href^="${hrefPrefix}"]`).first();
  await expect(link, `${label}: danh sách có ít nhất một mục`).toBeVisible();
  await link.click();
  await expect(page).toHaveURL(new RegExp(`${hrefPrefix.replace(/\//g, "\\/")}[0-9a-f-]{36}`));
  await checkScreen(page, testInfo, `${label}-detail`);
}

for (const item of visibleItems(PLATFORM_NAV, "super_admin")) {
  test(`SA: /platform/${item.path}${item.available ? "" : " (chưa khả dụng)"}`, async ({ page }, testInfo) => {
    const lng = lngOf(testInfo);
    await page.goto(`${ADMIN}/platform/${item.path}`);
    const nav = page.getByRole("navigation", { name: T(lng, "shell.navigation") });
    await expect(nav.locator(`a[href="/platform/${item.path}"]`)).toHaveAttribute("aria-current", "page");
    if (item.available) {
      await expect(page.getByTestId("unavailable")).toHaveCount(0);
    } else {
      await expect(page.getByTestId("unavailable")).toBeVisible();
    }
    await checkScreen(page, testInfo, `platform-${item.path}`);
  });
}

test("SA: chi tiết tenant (registry, instance, relay)", async ({ page }, testInfo) => {
  await openFirstDetail(page, testInfo, "/platform/tenants", "/platform/tenants/", "tenant");
});

test("SA: job timeline (chi tiết job)", async ({ page }, testInfo) => {
  await openFirstDetail(page, testInfo, "/platform/jobs", "/platform/jobs/", "job");
});

test("SA: chi tiết instance", async ({ page }, testInfo) => {
  await openFirstDetail(page, testInfo, "/platform/instances", "/platform/instances/", "instance");
});

test("SA: chi tiết host", async ({ page }, testInfo) => {
  await openFirstDetail(page, testInfo, "/platform/hosts", "/platform/hosts/", "host");
});

test("SA: chi tiết Identity Provider", async ({ page }, testInfo) => {
  await openFirstDetail(page, testInfo, "/platform/identity-providers", "/platform/identity-providers/", "idp");
});

test("SA: wizard tạo tenant — bước 1, lỗi kiểm hợp lệ gắn với ô nhập (không gửi)", async ({ page }, testInfo) => {
  const lng = lngOf(testInfo);
  await page.goto(`${ADMIN}/platform/tenants/new`);
  await expect(page.locator("h1")).toHaveText(T(lng, "platform.tenantCreate.title"));
  await checkScreen(page, testInfo, "wizard-step1");
  let posted = false;
  page.on("request", (r) => {
    if (r.method() === "POST" && r.url().endsWith("/api/v1/platform/tenants")) posted = true;
  });
  await page.getByRole("button", { name: T(lng, "common.next") }).click();
  await expect(page.locator("[aria-invalid=true]").first()).toBeVisible();
  await checkA11y(page, testInfo, "wizard-errors");
  expect(posted).toBe(false);
});

test("SA: hộp sửa thiết lập (mở, axe, đóng — không lưu)", async ({ page }, testInfo) => {
  await page.goto(`${ADMIN}/platform/settings`);
  await checkScreen(page, testInfo, "settings");
  const edit = page.locator("[data-testid=setting-row] button").first();
  await expect(edit).toBeVisible();
  await edit.click();
  const dialog = page.getByRole("dialog");
  await expect(dialog).toBeVisible();
  await checkA11y(page, testInfo, "settings-dialog");
  await page.keyboard.press("Escape");
  await expect(dialog).toHaveCount(0);
});

test("SA: hàng chờ 2P → chi tiết yêu cầu của SA khác — hash payload tính trong trình duyệt khớp server (không duyệt)", async ({
  page,
}, testInfo) => {
  const lng = lngOf(testInfo);
  const id = cfg.platformApprovalId;
  await page.goto(`${ADMIN}/platform/approvals`);
  await checkScreen(page, testInfo, "approvals-list");
  await page.locator(`main a[href="/platform/approvals/${id}"]`).first().click();
  await expect(page).toHaveURL(new RegExp(`/platform/approvals/${id}$`));
  await expect(page.getByTestId("hash-check")).toContainText(T(lng, "platform.approval.hashMatch"));
  const server = (await page.getByTestId("server-hash").textContent())?.trim();
  expect(server).toMatch(/^[0-9a-f]{64}$/);
  await expect(page.getByTestId("local-hash")).toHaveText(server ?? "");
  await expect(page.getByTestId("self-request")).toHaveCount(0);
  await checkScreen(page, testInfo, "approval-detail");
});
