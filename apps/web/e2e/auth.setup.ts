// Đăng nhập thật một lần cho mỗi vai trò (Keycloak: mật khẩu + TOTP), kiểm bất biến lưu trữ của trình duyệt ngay sau
// đăng nhập, lưu storage state (cookie phiên) vào thư mục làm việc của stack cho các spec dùng lại.
import { originOf, storageFile, type Role } from "./env";
import { checkBrowserStorage, expect, login, test } from "./support";

// mật khẩu nằm trong thao tác fill ⇒ không trace/ảnh cho các test đăng nhập
test.use({ trace: "off", screenshot: "off" });

const ROLES: { role: Role; label: string }[] = [
  { role: "sa", label: "Platform Super Admin (admin.)" },
  { role: "owner", label: "Tenant Owner (app.)" },
  { role: "admin", label: "Tenant Admin (app.)" },
  { role: "member", label: "End User (app.)" },
];

for (const { role, label } of ROLES) {
  test(`đăng nhập ${label}`, async ({ page, context }) => {
    const steps = await login(page, role, "vi");
    expect(steps).toContain("password");
    expect(steps).toContain("otp");
    await checkBrowserStorage(page, context, originOf(role));
    await context.storageState({ path: storageFile(role) });
  });
}
