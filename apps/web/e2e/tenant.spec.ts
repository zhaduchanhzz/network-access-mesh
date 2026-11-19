// Tenant Portal trên app. với ba vai trò thật của tenant-a (Owner, Admin, End User — phiên từ auth.setup.ts): mọi mục
// điều hướng role thấy, các trang chi tiết (thiết bị, thành viên, group, version policy — editor/diff), hộp thoại mời
// thành viên và form tài nguyên mạng (mở rồi đóng) — mỗi trang: axe WCAG 2.1 AA + i18n + CSP/5xx. Chỉ đọc.
// Mục enrollment (P4-T08) là màn hình thật (danh sách test sinh từ TENANT_NAV); luồng enrollment: enrollment.spec.ts; rà
// soát UX bảo mật G4b (step-up, hai pha, xác nhận thao tác phá hủy): securityux.spec.ts.
import type { Page, TestInfo } from "@playwright/test";
import { TENANT_NAV, visibleItems } from "../src/nav/navModel";
import { APP, cfg, storageFile, type Role } from "./env";
import { checkA11y, checkScreen, expect, lngOf, T, test } from "./support";

const A = cfg.tenantA.id;
const ROLES: { role: Role; key: string; label: string }[] = [
  { role: "owner", key: "tenant_owner", label: "Owner" },
  { role: "admin", key: "tenant_admin", label: "Admin" },
  { role: "member", key: "end_user", label: "End User" },
];

async function openFirstDetail(page: Page, testInfo: TestInfo, section: string, label: string) {
  const prefix = `/t/${A}/${section}/`;
  await page.goto(`${APP}/t/${A}/${section}`);
  await checkScreen(page, testInfo, `${label}-list`);
  const link = page.locator(`main tbody a[href^="${prefix}"]`).first();
  await expect(link, `${label}: danh sách có ít nhất một mục`).toBeVisible();
  await link.click();
  await expect(page).toHaveURL(new RegExp(`${prefix.replace(/\//g, "\\/")}[0-9a-f-]{36}`));
  await checkScreen(page, testInfo, `${label}-detail`);
}

for (const { role, key, label } of ROLES) {
  test.describe(`${label} (${key})`, () => {
    test.use({ storageState: storageFile(role) });

    for (const item of visibleItems(TENANT_NAV, key)) {
      test(`${label}: /t/<A>/${item.path}${item.available ? "" : " (chưa khả dụng)"}`, async ({ page }, testInfo) => {
        const lng = lngOf(testInfo);
        await page.goto(`${APP}/t/${A}/${item.path}`);
        const nav = page.getByRole("navigation", { name: T(lng, "shell.navigation") });
        await expect(nav.locator(`a[href="/t/${A}/${item.path}"]`)).toHaveAttribute("aria-current", "page");
        if (item.available) await expect(page.getByTestId("unavailable")).toHaveCount(0);
        else await expect(page.getByTestId("unavailable")).toBeVisible();
        await checkScreen(page, testInfo, `${role}-${item.path}`);
      });
    }
  });
}

test.describe("Owner: trang chi tiết và hộp thoại", () => {
  test.use({ storageState: storageFile("owner") });

  test("Owner: chi tiết thiết bị (trạng thái hai pha, synced_at)", async ({ page }, testInfo) => {
    await openFirstDetail(page, testInfo, "devices", "device");
  });

  test("Owner: chi tiết thành viên", async ({ page }, testInfo) => {
    await openFirstDetail(page, testInfo, "users", "user");
  });

  test("Owner: chi tiết group", async ({ page }, testInfo) => {
    await openFirstDetail(page, testInfo, "groups", "group");
  });

  test("Owner: version policy (editor form/HuJSON, lint, diff)", async ({ page }, testInfo) => {
    await openFirstDetail(page, testInfo, "policies", "policy");
  });

  test("Owner: hộp thoại mời thành viên (mở, axe, đóng — không gửi)", async ({ page }, testInfo) => {
    const lng = lngOf(testInfo);
    await page.goto(`${APP}/t/${A}/users`);
    await checkScreen(page, testInfo, "users");
    await page.getByRole("button", { name: T(lng, "people.invite.open") }).click();
    const dialog = page.getByRole("dialog");
    await expect(dialog).toBeVisible();
    await checkA11y(page, testInfo, "invite-dialog");
    await page.keyboard.press("Escape");
    await expect(dialog).toHaveCount(0);
  });

  test("Owner: form tài nguyên mạng (mở, axe — không lưu)", async ({ page }, testInfo) => {
    const lng = lngOf(testInfo);
    await page.goto(`${APP}/t/${A}/resources`);
    await checkScreen(page, testInfo, "resources");
    await page.getByRole("button", { name: T(lng, "network.resources.add") }).click();
    await expect(page.getByTestId("resource-form")).toBeVisible();
    await checkA11y(page, testInfo, "resource-form");
  });
});
