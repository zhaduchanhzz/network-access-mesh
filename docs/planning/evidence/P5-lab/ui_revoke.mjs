// P5-T07 — UI hai pha của thu hồi thiết bị trên staging, Chromium thật (playwright-core 1.65.0 của máy vận hành, như
// G4a/ui.mjs). Đăng nhập Owner của tenant thử (SPA /login → Keycloak mật khẩu + TOTP), mở Devices, báo "ready" qua
// thư mục trao đổi, rồi đọc lại dòng của thiết bị mỗi ~1 s trong `seconds` giây (tải lại trang) và ghi mọi trạng thái
// thu hồi thấy được (pending / applied / failed). Python gọi POST /devices/{id}/expire sau "ready".
// Tham số: file cấu hình JSON 0600 (~/.meshguard) — không in mật khẩu/TOTP.
import { chromium } from "playwright-core";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const cfg = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
const H = cfg.handoff;
const step = (name, ok, detail) => console.log(`${ok ? "PASS" : "FAIL"} [ui] ${name} — ${detail}`);
let last = Number(cfg.totp_last || 0);
async function totp() {
  for (;;) {
    const now = Math.floor(Date.now() / 1000 / 30);
    for (const c of [now, now + 1]) {
      if (c > last) {
        last = c;
        fs.writeFileSync(path.join(H, "totp_last"), String(last));
        const buf = Buffer.alloc(8);
        buf.writeBigUInt64BE(BigInt(c));
        const mac = crypto.createHmac("sha1", Buffer.from(cfg.totp_raw, "utf8")).update(buf).digest();
        const o = mac[mac.length - 1] & 0x0f;
        return String((mac.readUInt32BE(o) & 0x7fffffff) % 1000000).padStart(6, "0");
      }
    }
    await new Promise((r) => setTimeout(r, ((now + 1) * 30 - Date.now() / 1000 + 0.5) * 1000));
  }
}

const browser = await chromium.launch({ headless: true });
const context = await browser.newContext({ locale: "en-US", viewport: { width: 1360, height: 900 } });
const page = await context.newPage();
const app = cfg.app;
try {
  await page.goto(`${app}/login`);
  await page.getByLabel("Tenant ID (slug)").fill(cfg.slug);
  await page.getByRole("button", { name: "Continue to sign-in page" }).click();
  const steps = [];
  const deadline = Date.now() + 90_000;
  while (Date.now() < deadline) {
    const u = new URL(page.url());
    if (u.origin === app && !u.pathname.startsWith("/api/") && !u.pathname.startsWith("/login")) break;
    if (u.hostname === cfg.auth_host) {
      if (await page.locator("input[name=otp]").isVisible()) {
        await page.locator("input[name=otp]").fill(await totp());
        await page.locator("#kc-login, button[type=submit], input[type=submit]").first().click();
        await page.locator("input[name=otp]").waitFor({ state: "detached", timeout: 30_000 });
        steps.push("otp");
        continue;
      }
      if (await page.locator("input[name=password]").isVisible()) {
        const user = page.locator("input[name=username]");
        if ((await user.isVisible()) && (await user.isEditable())) await user.fill(cfg.username);
        await page.locator("input[name=password]").fill(cfg.password);
        await page.locator("#kc-login, button[type=submit], input[type=submit]").first().click();
        await page.locator("input[name=password]").waitFor({ state: "detached", timeout: 30_000 });
        steps.push("password");
        continue;
      }
    }
    await page.waitForTimeout(250);
  }
  await page.getByRole("button", { name: "Sign out" }).waitFor({ timeout: 30_000 });
  step("Owner đăng nhập (SPA → Keycloak mật khẩu + TOTP)", steps.includes("password"), `bước ${steps}`);
  const url = `${app}/t/${cfg.tenant_id}/devices`;
  await page.goto(url);
  await page.getByText(cfg.device, { exact: true }).first().waitFor({ timeout: 30_000 });
  fs.writeFileSync(path.join(H, "ready"), "1");
  const seen = [];
  const t0 = Date.now();
  while (Date.now() - t0 < cfg.seconds * 1000) {
    const text = await page.locator("#main").innerText().catch(() => "");
    const row = text.split("\n").map((l) => l.trim());
    const i = row.findIndex((l) => l === cfg.device);
    const ctx = i >= 0 ? row.slice(i, i + 8).join(" | ") : "";
    const m = ctx.match(/revocation[^|]*?(pending|applied|failed)|\b(pending|applied|failed)\b/i);
    const st = m ? (m[1] || m[2]).toLowerCase() : (/expired/i.test(ctx) ? "expired" : "-");
    if (!seen.length || seen[seen.length - 1].st !== st) seen.push({ st, at: ((Date.now() - t0) / 1000).toFixed(1), ctx: ctx.slice(0, 160) });
    if (st === "applied" && seen.length > 1 && Date.now() - t0 > 8000) break;
    await page.waitForTimeout(700);
    await page.reload();
    await page.getByText(cfg.device, { exact: true }).first().waitFor({ timeout: 15_000 }).catch(() => undefined);
  }
  await page.screenshot({ path: path.join(H, "devices.png"), fullPage: true });
  const states = seen.map((s) => s.st);
  step("Devices: dòng thiết bị đổi pending → applied (chỉ hiện 'applied' khi Headscale đã đọc lại)",
    states.includes("applied") && states.indexOf("applied") > Math.max(0, states.indexOf("pending")),
    seen.map((s) => `${s.at}s ${s.st} [${s.ctx}]`).join(" ⇒ "));
} catch (e) {
  step("UI chạy hết", false, String(e).slice(0, 200));
} finally {
  await browser.close();
}
