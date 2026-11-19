// Playwright E2E (P4-T14; §12.4, §22.1 "E2E (UI)"): SPA thật sau edge thật của stack dev/CI (tests/e2e/harness), hai
// vai trò (Platform SA trên admin., Tenant Owner/Admin/End User trên app.) × hai ngôn ngữ (vi + giao diện sáng, en +
// giao diện tối) × axe (WCAG 2.1 AA). Chạy trong image Playwright chính thức pin digest (versions.lock
// [images.playwright]) qua tests/e2e/harness/playwrightui.py — không cài trình duyệt lên host.
//
// Tham số (môi trường):
//   MG_PW_CONFIG  tệp JSON do harness viết (domain, địa chỉ edge, SPKI của CA của lượt chạy, tenant, user test kèm
//                 mật khẩu + khóa TOTP — chỉ nằm trong thư mục làm việc của stack, không bao giờ trong artifact)
//   MG_PW_OUT     thư mục kết quả: html/ (báo cáo), results.json, artifacts/ (trace/ảnh chỉ khi lỗi)
import { defineConfig, devices } from "@playwright/test";
import { loadConfig, MESH_HOSTS } from "./e2e/env";

const cfg = loadConfig();
const out = process.env.MG_PW_OUT ?? "test-results/playwright";
// app./admin./auth.<domain> + login server của hai tenant (tenant-*.<mesh>: link /register/<auth_id> mà client in ra —
// edge v10 chuyển hướng 302 về trang claim của Portal, G4b) — cùng chứng chỉ edge (SAN *.<mesh>), cùng SPKI pin
const hosts = [...["app", "admin", "auth"].map((h) => `${h}.${cfg.domain}`), ...MESH_HOSTS].map((h) => `MAP ${h} ${cfg.edgeIp}`).join(",");
const args = [`--host-resolver-rules=${hosts},EXCLUDE localhost`];
// TLS: chỉ chứng chỉ edge của lượt chạy (SPKI pin — harness lấy qua bắt tay đã kiểm theo CA dùng-một-lần) được nhận;
// không tắt kiểm chứng chỉ cho mọi host.
if (cfg.tlsSpki) args.push(`--ignore-certificate-errors-spki-list=${cfg.tlsSpki}`);

export default defineConfig({
  testDir: "./e2e",
  outputDir: `${out}/artifacts`,
  // Một worker: phiên đăng nhập + bộ đếm TOTP (Keycloak từ chối mã dùng lại) dùng chung, kết quả tất định; giới hạn
  // tốc độ của API không bị chạm.
  workers: 1,
  fullyParallel: false,
  forbidOnly: true,
  retries: 0,
  // ca G4b (enrollment với client thật, step-up qua Keycloak, C4 nhiều vai trò) dài hơn ca chỉ-đọc; bucket `enrollment` của
  // API (5 + 1/5 s mỗi danh tính) ⇒ chờ Retry-After là chuyện thường
  timeout: 300_000,
  expect: { timeout: 15_000 },
  reporter: [
    ["list"],
    ["html", { outputFolder: `${out}/html`, open: "never" }],
    ["json", { outputFile: `${out}/results.json` }],
  ],
  use: {
    ...devices["Desktop Chrome"],
    viewport: { width: 1366, height: 900 },
    ignoreHTTPSErrors: !cfg.tlsSpki,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    video: "off",
    actionTimeout: 15_000,
    navigationTimeout: 30_000,
    launchOptions: { args },
  },
  projects: [
    { name: "setup", testMatch: /auth\.setup\.ts$/, use: { locale: "vi-VN", colorScheme: "light" } },
    {
      name: "vi",
      testMatch: /\.spec\.ts$/,
      dependencies: ["setup"],
      use: { locale: "vi-VN", colorScheme: "light", timezoneId: "Asia/Ho_Chi_Minh" },
    },
    {
      name: "en",
      testMatch: /\.spec\.ts$/,
      dependencies: ["setup"],
      use: { locale: "en-US", colorScheme: "dark", timezoneId: "UTC" },
    },
  ],
});
