// Checklist G4b (b) — lời nhắc step-up (§8.3 bước 7) trong trình duyệt thật: Tenant Owner đăng nhập mới, auth_time của
// phiên bị đẩy về quá 15 phút (harness), đổi role chạm Tenant Admin ⇒ 401 reauth_required ⇒ lời nhắc trong hộp đang mở (và
// banner đầu trang sau lớp modal) ⇒ "Xác thực lại" ⇒ Keycloak hỏi lại mật khẩu + OTP ⇒ về đúng trang ⇒ thao tác lại thành
// công. Phía nền tảng (xin Support Access Grant) và duyệt grant (Owner): enrollment-support.spec.ts.
// Đăng nhập + step-up: mật khẩu nằm trong thao tác fill ⇒ không trace cho file này.
import { APP, cfg } from "./env";
import { ageSession, checkA11y, checkI18n, checkNoSecrets, checkScreen, confirmDialog, ctl, expect, lngOf, login, settle, stepUp, T, test, Tv } from "./support";

test.use({ trace: "off" });

const A = cfg.tenantA.id;

interface Member {
  id: string;
  name: string;
  email: string;
}

// ================================================================================================ (b) step-up
test.describe("G4b — step-up (Tenant Owner, phiên mới)", () => {
  test("Step-up: đổi role chạm Tenant Admin khi auth_time > 15 phút ⇒ 401 ⇒ lời nhắc trong hộp + đầu trang ⇒ xác thực lại (mật khẩu + OTP) ⇒ về đúng trang ⇒ thao tác lại thành công; URL/DOM không mang tham số OIDC hay secret", async ({ page, context, guard }, testInfo) => {
    const lng = lngOf(testInfo);
    await login(page, "owner", lng);
    const m = await ctl<Member>("new_member");
    await page.goto(`${APP}/t/${A}/users/${m.id}`);
    await checkScreen(page, testInfo, "user-stepup");
    await expect(page.locator("h1")).toHaveText(m.name);
    await ageSession(page);
    const roleSelect = page.getByLabel(T(lng, "people.role.newRole"));
    const submit = page.getByRole("button", { name: T(lng, "people.role.submit"), exact: true });
    const dlg = confirmDialog(page);
    const change = async (role: string) => {
      await roleSelect.selectOption(role);
      await submit.click();
      await expect(dlg.getByRole("heading")).toHaveText(Tv(lng, "people.role.confirmTitle", { name: m.name }));
      await expect(dlg).toContainText(T(lng, `roles.${role}`));
      await expect(dlg).toContainText(T(lng, "people.role.sessionsNote"));
      await dlg.getByRole("button", { name: T(lng, "people.role.submit"), exact: true }).click();
    };
    await change("tenant_admin");
    // 401 reauth_required: lỗi trong hộp đang mở + nút "Xác thực lại" (lời nhắc chung ở đầu trang nằm sau lớp modal)
    await expect(dlg.getByRole("alert")).toContainText(T(lng, "problem.reauth_required"));
    await expect(dlg).toContainText(T(lng, "people.role.adminHint"));
    await checkA11y(page, testInfo, "stepup-role-dialog");
    await checkI18n(page, lng, "stepup-role-dialog");
    await expect(page.getByTestId("user-role")).toHaveText(T(lng, "roles.end_user"));
    await stepUp(page, "owner", dlg.getByRole("button", { name: T(lng, "stepUp.action") }));
    await settle(page, lng);
    await checkNoSecrets(context, guard, "after-stepup");
    // sau step-up: thao tác lại ⇒ thành công; rồi trả về End User (auth_time mới — không hỏi lại)
    await change("tenant_admin");
    await expect(page.getByTestId("role-changed")).toHaveText(T(lng, "people.role.done"), { timeout: 30_000 });
    await expect(page.getByTestId("user-role")).toHaveText(T(lng, "roles.tenant_admin"));
    await change("end_user");
    await expect(page.getByTestId("user-role")).toHaveText(T(lng, "roles.end_user"), { timeout: 30_000 });
    await checkScreen(page, testInfo, "user-after-stepup");
    await checkNoSecrets(context, guard, "role-changed");
  });
});
