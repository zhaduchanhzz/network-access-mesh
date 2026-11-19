// Đăng nhập thật rồi đăng xuất (§8.3) trên hai console, mỗi ngôn ngữ: phiên bị thu hồi ở SERVER (cookie cũ gửi lại từ
// một trình duyệt khác ⇒ 401), cookie bị xóa, về trang đăng nhập. User riêng (sa2, admin2) để không đụng phiên của các
// spec khác. Mật khẩu nằm trong thao tác fill ⇒ không trace/ảnh cho file này.
import { AUTH_HOST, originOf, type Role } from "./env";
import { apiStatus, checkBrowserStorage, checkScreen, expect, lngOf, login, T, test } from "./support";

test.use({ trace: "off", screenshot: "off" });

const LABEL: Partial<Record<Role, string>> = { sa2: "Platform SA (admin.)", admin2: "Tenant Admin (app.)" };

for (const role of ["sa2", "admin2"] as const) {
  test(`${LABEL[role] ?? role}: đăng nhập → đăng xuất`, async ({ page, context, browser }, testInfo) => {
    const lng = lngOf(testInfo);
    const origin = originOf(role);
    await login(page, role, lng);
    await checkBrowserStorage(page, context, origin);
    await checkScreen(page, testInfo, `home-${role}`);
    const before = (await context.cookies(origin)).filter((c) => c.name.startsWith("__Host-"));
    expect(before.length).toBeGreaterThan(0);

    await page.getByRole("button", { name: T(lng, "shell.signOut") }).click();
    // end_session của Keycloak rồi quay lại SPA (nếu Keycloak hỏi xác nhận thì bấm đăng xuất)
    const deadline = Date.now() + 60_000;
    while (Date.now() < deadline) {
      const url = new URL(page.url());
      if (url.origin === origin && url.pathname.startsWith("/login")) break;
      if (url.hostname === AUTH_HOST && (await page.locator("#kc-logout").isVisible())) {
        await page.locator("#kc-logout").click();
      }
      await page.waitForTimeout(250);
    }
    await expect(page).toHaveURL(new RegExp(`^${origin.replace(/\./g, "\\.")}/login`));
    await expect(page.locator("h1")).toBeVisible();
    expect(await apiStatus(page, "/api/v1/auth/session")).toBe(401);
    expect((await context.cookies(origin)).filter((c) => c.name === "__Host-mg_session")).toEqual([]);

    // cookie cũ trong một trình duyệt khác ⇒ server đã thu hồi phiên (không chỉ xóa cookie ở client)
    const other = await browser.newContext({ ignoreHTTPSErrors: testInfo.project.use.ignoreHTTPSErrors ?? false });
    try {
      await other.addCookies(before);
      const p2 = await other.newPage();
      await p2.goto(`${origin}/login`);
      expect(await apiStatus(p2, "/api/v1/auth/session")).toBe(401);
    } finally {
      await other.close();
    }
  });
}
