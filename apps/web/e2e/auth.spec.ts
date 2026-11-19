// Trang đăng nhập (§8.3) của hai console khi chưa có phiên, mỗi ngôn ngữ: chuyển hướng về /login, CSP của edge, axe +
// i18n; slug không hợp lệ. Đăng nhập + đăng xuất thật: logout.spec.ts.
import { ADMIN, APP } from "./env";
import { apiStatus, checkScreen, expect, lngOf, T, test } from "./support";

for (const [origin, label] of [
  [APP, "Tenant Portal"],
  [ADMIN, "Platform Console"],
] as const) {
  test(`trang đăng nhập ${label} khi chưa có phiên`, async ({ page }, testInfo) => {
    const lng = lngOf(testInfo);
    const root = await page.goto(`${origin}/`);
    expect(root?.headers()["content-security-policy"] ?? "").toContain("frame-ancestors 'none'");
    await expect(page).toHaveURL(/\/login(\?|$)/);
    await expect(page.locator("h1")).toHaveText(
      T(lng, origin === APP ? "login.tenantHeading" : "login.platformHeading"),
    );
    expect(await apiStatus(page, "/api/v1/auth/session")).toBe(401);
    await checkScreen(page, testInfo, `login-${label}`);
  });
}

test("Tenant Portal: slug không hợp lệ ⇒ lỗi gắn với ô nhập (aria), không rời trang", async ({ page }, testInfo) => {
  const lng = lngOf(testInfo);
  await page.goto(`${APP}/login`);
  const input = page.getByLabel(T(lng, "login.tenantLabel"));
  await input.fill("X");
  await page.getByRole("button", { name: T(lng, "login.submit") }).click();
  await expect(page.getByText(T(lng, "login.tenantInvalid"))).toBeVisible();
  await expect(input).toHaveAttribute("aria-invalid", "true");
  await expect(page).toHaveURL(/\/login/);
  await checkScreen(page, testInfo, "login-invalid");
});
