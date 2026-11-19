// Cách ly qua UI (§8.4 bất biến 6, §12.1): tenant A không thấy tenant B (URL chứa ID chéo tenant ⇒ trang 404 thống
// nhất, API 404 — không lộ sự tồn tại), Platform Console không mở trên app., SA không vào route tenant khi chưa có
// Support Access Grant, End User không xem được màn hình ngoài quyền; bất biến lưu trữ trên phiên đã dùng lâu.
import { ADMIN, APP, cfg, storageFile } from "./env";
import { apiStatus, checkBrowserStorage, checkScreen, expect, lngOf, T, test } from "./support";

const A = cfg.tenantA.id;
const B = cfg.tenantB.id;

test.describe("Owner tenant-a", () => {
  test.use({ storageState: storageFile("owner") });

  for (const path of ["overview", "devices", "users", "policies", "audit"]) {
    test(`URL tenant-b /t/<B>/${path} ⇒ 404 thống nhất`, async ({ page }, testInfo) => {
      const lng = lngOf(testInfo);
      await page.goto(`${APP}/t/${B}/${path}`);
      await expect(page.locator("h1")).toHaveText(T(lng, "notFound.title"));
      await expect(page.getByText(cfg.tenantB.slug)).toHaveCount(0);
      await checkScreen(page, testInfo, `cross-${path}`);
    });
  }

  test("API của tenant-b ⇒ 404 (cùng cookie phiên của trình duyệt)", async ({ page }) => {
    await page.goto(`${APP}/t/${A}/overview`);
    for (const p of [`/tenants/${B}`, `/tenants/${B}/devices`, `/tenants/${B}/audit`]) {
      expect([p, await apiStatus(page, `/api/v1${p}`)]).toEqual([p, 404]);
    }
  });

  test("Platform Console trên app. ⇒ 404 thống nhất", async ({ page }, testInfo) => {
    const lng = lngOf(testInfo);
    await page.goto(`${APP}/platform/tenants`);
    await expect(page.locator("h1")).toHaveText(T(lng, "notFound.title"));
    await checkScreen(page, testInfo, "platform-on-app");
  });

  test("ID không phải UUID và đường dẫn lạ ⇒ 404 thống nhất", async ({ page }, testInfo) => {
    const lng = lngOf(testInfo);
    await page.goto(`${APP}/t/not-a-uuid/devices`);
    await expect(page.locator("h1")).toHaveText(T(lng, "notFound.title"));
    await page.goto(`${APP}/khong-co-trang-nay`);
    await expect(page.locator("h1")).toHaveText(T(lng, "notFound.title"));
    await checkScreen(page, testInfo, "unknown-path");
  });

  test("bất biến lưu trữ sau khi duyệt nhiều màn hình", async ({ page, context }) => {
    for (const p of ["overview", "devices", "policies", "settings"]) {
      await page.goto(`${APP}/t/${A}/${p}`);
      await expect(page.locator("h1")).toBeVisible();
    }
    await checkBrowserStorage(page, context, APP);
  });
});

test.describe("Super Admin", () => {
  test.use({ storageState: storageFile("sa") });

  test("route tenant trên admin. khi chưa có Support Access Grant ⇒ 404 thống nhất", async ({ page }, testInfo) => {
    const lng = lngOf(testInfo);
    await page.goto(`${ADMIN}/t/${A}/devices`);
    await expect(page.locator("h1")).toHaveText(T(lng, "notFound.title"));
    expect(await apiStatus(page, `/api/v1/tenants/${A}/devices`)).toBe(403);
    await checkScreen(page, testInfo, "sa-tenant-route");
  });

  test("bất biến lưu trữ trên admin.", async ({ page, context }) => {
    await page.goto(`${ADMIN}/platform/tenants`);
    await expect(page.locator("h1")).toBeVisible();
    await checkBrowserStorage(page, context, ADMIN);
  });
});

test.describe("End User", () => {
  test.use({ storageState: storageFile("member") });

  test("màn hình ngoài quyền (Users, Audit) ⇒ trang không có quyền", async ({ page }, testInfo) => {
    const lng = lngOf(testInfo);
    for (const p of ["users", "audit"]) {
      await page.goto(`${APP}/t/${A}/${p}`);
      await expect(page.locator("h1")).toHaveText(T(lng, "forbidden.title"));
    }
    await checkScreen(page, testInfo, "member-forbidden");
  });
});
