// G4a — UI tối thiểu trên staging bằng Chromium thật (playwright-core 1.65.0 + Chromium 1254 đã cài trên máy vận hành).
// Đăng nhập Owner của tenant thử qua app.<domain> (DNS công khai → VPS → tunnel → edge) + Keycloak (mật khẩu + TOTP),
// xem Devices/Policies/Audit, rồi web-auth qua SPA: "Add device" ⇒ lệnh mg-<mã> ⇒ (Python chạy client) ⇒ mở link
// /register/<auth_id> trong CHÍNH trình duyệt này ⇒ 302 ⇒ trang claim ⇒ xác nhận ⇒ verified.
// Tham số: đường dẫn file cấu hình JSON (0600, ~/.meshguard) — không in mật khẩu/TOTP/mã/Auth ID.
import { chromium } from "playwright-core";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const cfg = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
const H = cfg.handoff;   // thư mục trao đổi 0700
const shots = cfg.shots;
const out = { steps: [] };
const step = (name, ok, detail) => {
  out.steps.push({ name, ok, detail });
  console.log(`${ok ? "PASS" : "FAIL"} [ui] ${name} — ${detail}`);
};
const secrets = [cfg.password, cfg.totp_raw];
const redact = (s) => secrets.reduce((a, v) => (v ? a.split(v).join("[REDACTED]") : a), String(s))
  .replace(/hskey-(api|auth|authreq)-[A-Za-z0-9_-]+/g, "[REDACTED]").replace(/mg-[a-z2-7]{12}\b/g, "mg-<mã>");

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

async function waitFile(name, ms) {
  const f = path.join(H, name);
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (fs.existsSync(f)) {
      const v = fs.readFileSync(f, "utf8").trim();
      fs.rmSync(f);
      return v;
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  return "";
}

const browser = await chromium.launch({ headless: true });
const context = await browser.newContext({ locale: "en-US", viewport: { width: 1360, height: 900 } });
const page = await context.newPage();
const csp = [];
const errors = [];
page.on("console", (m) => { if (m.type() === "error") (/Content.Security.Policy|Refused to/i.test(m.text()) ? csp : errors).push(m.text().slice(0, 160)); });
page.on("pageerror", (e) => errors.push(String(e.message).slice(0, 160)));
const app = cfg.app;
try {
  // ------------------------------------------------------------------ đăng nhập
  const resp = await page.goto(`${app}/login`);
  const cspHeader = resp?.headers()["content-security-policy"] ?? "";
  await page.getByLabel("Tenant ID (slug)").fill(cfg.slug);
  await page.getByRole("button", { name: "Continue to sign-in page" }).click();
  const stepsLogin = [];
  const deadline = Date.now() + 90_000;
  while (Date.now() < deadline) {
    const u = new URL(page.url());
    if (u.origin === app && !u.pathname.startsWith("/api/") && !u.pathname.startsWith("/login")) break;
    if (u.hostname === cfg.auth_host) {
      if (await page.locator("input[name=otp]").isVisible()) {
        await page.locator("input[name=otp]").fill(await totp());
        await page.locator("#kc-login, button[type=submit], input[type=submit]").first().click();
        await page.locator("input[name=otp]").waitFor({ state: "detached", timeout: 30_000 });
        stepsLogin.push("otp");
        continue;
      }
      if (await page.locator("input[name=password]").isVisible()) {
        const user = page.locator("input[name=username]");
        if ((await user.isVisible()) && (await user.isEditable())) await user.fill(cfg.username);
        await page.locator("input[name=password]").fill(cfg.password);
        await page.locator("#kc-login, button[type=submit], input[type=submit]").first().click();
        await page.locator("input[name=password]").waitFor({ state: "detached", timeout: 30_000 });
        stepsLogin.push("password");
        continue;
      }
    }
    await page.waitForTimeout(250);
  }
  await page.getByRole("button", { name: "Sign out" }).waitFor({ timeout: 30_000 });
  const cookies = (await context.cookies(app)).filter((c) => c.name.startsWith("__Host-"));
  const jsCookie = await page.evaluate(() => document.cookie);
  step("Owner đăng nhập trong Chromium (SPA /login → Keycloak mật khẩu + TOTP → SPA)", stepsLogin.includes("password") && stepsLogin.includes("otp"),
    `bước ${stepsLogin}; CSP header ${cspHeader.includes("default-src 'self'")}; cookie __Host- ${cookies.length} HttpOnly ${cookies.every((c) => c.httpOnly && c.secure)}; document.cookie thấy phiên ${cookies.some((c) => jsCookie.includes(c.name))}`);

  // ------------------------------------------------------------------ Devices / Policies / Audit
  const base = `${app}/t/${cfg.tenant_id}`;
  await page.goto(`${base}/devices`);
  await page.getByText("g4a-vm105").first().waitFor({ timeout: 30_000 });
  await page.waitForTimeout(1500);
  const devText = await page.locator("#main").innerText();
  await page.screenshot({ path: path.join(shots, "devices.png"), fullPage: true });
  step("Devices: thấy D1 g4a-vm105 và D2 g4a-d2-renamed (trạng thái thu hồi)", devText.includes("g4a-vm105") && devText.includes("g4a-d2-renamed"),
    `h1 "${(await page.locator("h1").first().innerText()).trim()}"; dòng: ${redact(devText.split("\n").filter((l) => /g4a-|expire|revok|applied|online|offline/i.test(l)).slice(0, 8).join(" | "))}`);
  await page.goto(`${base}/policies`);
  await page.locator("h1").first().waitFor();
  await page.waitForTimeout(2000);
  const polText = await page.locator("#main").innerText();
  await page.screenshot({ path: path.join(shots, "policies.png"), fullPage: true });
  step("Access policies: trạng thái áp dụng hiện hành", /applied|Applied|rollback|v4|Version/i.test(polText),
    `h1 "${(await page.locator("h1").first().innerText()).trim()}"; ${redact(polText.split("\n").filter((l) => /applied|version|v\d|rollback|desired|sha/i.test(l)).slice(0, 6).join(" | "))}`);
  await page.goto(`${base}/audit`);
  await page.locator("h1").first().waitFor();
  await page.waitForTimeout(2000);
  const audText = await page.locator("#main").innerText();
  await page.screenshot({ path: path.join(shots, "audit.png"), fullPage: true });
  step("Audit log: hành động của luồng thử hiện trong UI", /device\.expire|policy\.|enrollment\./.test(audText),
    `h1 "${(await page.locator("h1").first().innerText()).trim()}"; có device.expire ${audText.includes("device.expire")}, policy. ${audText.includes("policy.")}, enrollment. ${audText.includes("enrollment.")}`);

  // ------------------------------------------------------------------ Add device (web-auth) qua SPA
  await page.goto(`${base}/enroll`);
  await page.getByText("Enroll a new device").first().waitFor({ timeout: 30_000 });
  await page.getByLabel("Linux", { exact: true }).check();
  await page.getByText("Tenant login server").first().waitFor({ timeout: 30_000 }).catch(() => undefined);
  const label = page.getByLabel("Device label (optional)");
  if (await label.count()) await label.fill("g4a-ui");
  await page.getByRole("button", { name: "Create the enrollment command" }).click();
  await page.getByText("Required hostname:").waitFor({ timeout: 30_000 });
  const html = await page.locator("#main").innerText();
  const m = html.match(/mg-[a-z2-7]{12}/);
  const hasLogin = html.includes(`${cfg.slug}.mesh.`);
  const storage = await page.evaluate(() => ({ l: Object.keys(localStorage), s: Object.keys(sessionStorage), url: location.href }));
  step("Add device: wizard Linux + web-auth ⇒ lệnh --hostname mg-<mã> (mã không ở URL/Storage)", !!m && hasLogin && !storage.url.includes(m?.[0] ?? "§")
    && !JSON.stringify(storage).includes(m?.[0] ?? "§"),
    `hostname mg-<12> ${!!m}; lệnh có login server của tenant ${hasLogin}; localStorage ${JSON.stringify(storage.l)} sessionStorage ${JSON.stringify(storage.s)}`);
  if (!m) throw new Error("không thấy hostname");
  fs.writeFileSync(path.join(H, "hostname"), m[0], { mode: 0o600 });
  const tWait = Date.now();
  const link = await waitFile("link", 120_000);
  if (!link) throw new Error("không nhận được link của client");
  // như người dùng thật: chạy lệnh trên máy rồi mới mở link (lượt 1: mở ngay ⇒ 429 ở bước claim — xem kết quả)
  const pause = Number(cfg.pause_ms || 0) - (Date.now() - tWait);
  if (pause > 0) await page.waitForTimeout(pause);
  // mở link của client trong CHÍNH trình duyệt có phiên Portal (đường V-07)
  const nav = await page.goto(link);
  const hops = [];
  for (let rq = nav?.request(); rq; rq = rq.redirectedFrom()) {
    const rs = await rq.response();
    const u = new URL(rq.url());
    hops.unshift(`${rs?.status()} ${u.hostname.split(".")[0]}${u.pathname}${rs?.headers()["cache-control"] ? " (" + rs.headers()["cache-control"] + ")" : ""}`);
  }
  await page.getByText("Confirm a device").first().waitFor({ timeout: 30_000 });
  await page.waitForTimeout(1500);
  const claimUrl = page.url();
  const claimText = await page.locator("#main").innerText();
  step("link /register/<auth_id> ⇒ 302 ⇒ trang claim của SPA; auth_id gỡ khỏi URL; thấy yêu cầu đang chờ", hops[0]?.startsWith("302") && !claimUrl.includes("hskey-authreq")
    && /Waiting request/i.test(claimText),
    `điều hướng ${redact(hops.join(" → "))}; URL sau khi đọc ${redact(new URL(claimUrl).pathname + new URL(claimUrl).search)}; "Waiting request" ${/Waiting request/i.test(claimText)}`);
  await page.screenshot({ path: path.join(shots, "claim-confirm.png"), fullPage: true });
  await page.getByLabel("I just ran the command on my own device and want to add it.").check();
  const final = /Device g4a-ui added\.|The device failed the checks|The link was used|has ended|Warning/;
  const limited = [];
  for (let attempt = 1; attempt <= 5; attempt++) {
    await page.getByRole("button", { name: "Confirm device" }).click();
    const got = await Promise.race([
      page.getByText(final).first().waitFor({ timeout: 60_000 }).then(() => "final"),
      page.getByText("Too many requests").first().waitFor({ timeout: 60_000 }).then(() => "429"),
    ]).catch(() => "timeout");
    if (got !== "429") break;
    limited.push(attempt);
    // UI giữ nút để bấm lại (cùng Idempotency-Key) — chờ thông báo "You can try again now."
    await page.getByText("You can try again now.").first().waitFor({ timeout: 60_000 }).catch(() => undefined);
    await page.waitForTimeout(1000);
  }
  out.rate_limited = limited;
  console.log(`  claim: 429 ở lần bấm ${JSON.stringify(limited)}`);
  await page.getByText(final).first().waitFor({ timeout: 60_000 });
  const result = await page.locator("#main").innerText();
  await page.screenshot({ path: path.join(shots, "claim-result.png"), fullPage: true });
  const traces = await page.evaluate(() => JSON.stringify({ l: { ...localStorage }, s: { ...sessionStorage }, u: location.href, d: document.documentElement.outerHTML.length }));
  const domHasAuth = (await page.content()).includes("hskey-authreq");
  step("xác nhận tường minh ⇒ verified (\"Device g4a-ui added.\"), Auth ID không còn ở DOM/URL/Storage", result.includes("Device g4a-ui added.") && !domHasAuth
    && !traces.includes("hskey-authreq"), `kết quả: ${redact(result.split("\n").filter((l) => /added|failed|used|ended|Warning/.test(l)).slice(0, 2).join(" | "))}; Auth ID ở DOM ${domHasAuth}, ở URL/Storage ${traces.includes("hskey-authreq")}`);
  fs.writeFileSync(path.join(H, "claimed"), "1");
  await page.goto(`${base}/devices`);
  await page.getByText("g4a-ui").first().waitFor({ timeout: 60_000 }).catch(() => undefined);
  const dev2 = await page.locator("#main").innerText();
  await page.screenshot({ path: path.join(shots, "devices-after.png"), fullPage: true });
  step("Devices sau claim: thấy g4a-ui", dev2.includes("g4a-ui"), redact(dev2.split("\n").filter((l) => /g4a-/.test(l)).slice(0, 6).join(" | ")));
} catch (e) {
  step("dừng", false, redact(e.message).slice(0, 400));
  await page.screenshot({ path: path.join(shots, "error.png"), fullPage: true }).catch(() => undefined);
} finally {
  step("không vi phạm CSP / lỗi JS chưa bắt", csp.length === 0, `CSP ${csp.length} ${redact(csp.slice(0, 2).join(" ; "))}; lỗi console/JS ${errors.length} ${redact(errors.slice(0, 3).join(" ; "))}`);
  fs.writeFileSync(path.join(H, "ui-result.json"), JSON.stringify(out));
  await browser.close();
}
