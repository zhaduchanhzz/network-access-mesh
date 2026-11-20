// Công cụ chung của các spec Playwright (P4-T14): fixture `guard` (tự bật cho mọi test) bắt vi phạm CSP, lỗi JS chưa
// bắt, response 5xx của /api/v1; kiểm axe (WCAG 2.1 AA — vi phạm serious/critical ⇒ fail, mức khác đính kèm báo cáo);
// kiểm i18n (lang của tài liệu, không chuỗi của ngôn ngữ kia, không khóa i18n thô); bất biến lưu trữ của trình duyệt;
// đăng nhập thật qua Keycloak (mật khẩu + TOTP).
import AxeBuilder from "@axe-core/playwright";
import { test as base, expect, type Browser, type BrowserContext, type Locator, type Page, type TestInfo } from "@playwright/test";
import { randomBytes } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { ADMIN, AUTH_HOST, cfg, ctlDir, nextTotp, originOf, storageFile, type Role } from "./env";

// ------------------------------------------------------------------------------------------------ i18n catalog
export type Lng = "vi" | "en";
type Tree = { [k: string]: string | Tree };

function readCatalog(lng: Lng): Tree {
  return JSON.parse(fs.readFileSync(new URL(`../src/i18n/locales/${lng}.json`, import.meta.url), "utf8")) as Tree;
}

const CATALOG: Record<Lng, Tree> = { vi: readCatalog("vi"), en: readCatalog("en") };

function flatten(tree: Tree, prefix = "", out = new Map<string, string>()): Map<string, string> {
  for (const [k, v] of Object.entries(tree)) {
    const key = prefix ? `${prefix}.${k}` : k;
    if (typeof v === "string") out.set(key, v);
    else flatten(v, key, out);
  }
  return out;
}

const FLAT: Record<Lng, Map<string, string>> = { vi: flatten(CATALOG.vi), en: flatten(CATALOG.en) };
const VALUES: Record<Lng, Set<string>> = {
  vi: new Set([...FLAT.vi.values()].filter((s) => !s.includes("{{"))),
  en: new Set([...FLAT.en.values()].filter((s) => !s.includes("{{"))),
};
const KEYS = new Set([...FLAT.vi.keys(), ...FLAT.en.keys()].map((k) => k.replace(/_(one|other)$/, "")));

/** Chuỗi của catalog (không nội suy) — để tìm phần tử theo nhãn đúng ngôn ngữ. */
export function T(lng: Lng, key: string): string {
  const v = FLAT[lng].get(key) ?? FLAT[lng].get(`${key}_other`);
  if (v === undefined) throw new Error(`khóa i18n không có: ${key}`);
  return v;
}

/** Chuỗi của catalog có nội suy {{x}} (không định dạng số/ngày). */
export function Tv(lng: Lng, key: string, vars: Record<string, string | number>): string {
  return T(lng, key).replace(/\{\{(\w+)\}\}/g, (_m, k: string) => String(vars[k] ?? `{{${k}}}`));
}

/** Biểu thức chính quy khớp nguyên văn một chuỗi. */
export function lit(s: string): RegExp {
  return new RegExp(s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"));
}

export function lngOf(testInfo: TestInfo): Lng {
  return testInfo.project.name === "en" ? "en" : "vi";
}

// ------------------------------------------------------------------------------------------------ guard
export interface GuardState {
  csp: string[];
  pageErrors: string[];
  serverErrors: string[];
  consoleErrors: string[];
  /** mọi dòng console (mọi mức) của mọi trang đang theo dõi — checkNoSecrets dò secret trong đó */
  consoleAll: string[];
  /** theo dõi thêm một context (vai trò thứ hai, đăng nhập mới — newActor) */
  attach: (context: BrowserContext) => Promise<void>;
}

declare global {
  interface Window {
    __mgCsp?: string[];
  }
}

function watch(page: Page, s: GuardState): void {
  page.on("pageerror", (e) => s.pageErrors.push(`${page.url()}: ${e.message}`));
  page.on("console", (m) => {
    s.consoleAll.push(m.text());
    if (m.type() !== "error") return;
    const text = m.text();
    if (/Content.Security.Policy|Refused to (load|execute|apply|connect|frame)/i.test(text)) s.csp.push(text);
    else s.consoleErrors.push(text);
  });
  page.on("response", (r) => {
    const u = new URL(r.url());
    if (u.pathname.startsWith("/api/v1/") && r.status() >= 500) s.serverErrors.push(`${r.status()} ${u.pathname}`);
  });
}

async function cspFromPage(page: Page): Promise<string[]> {
  try {
    return await page.evaluate(() => window.__mgCsp ?? []);
  } catch {
    return [];
  }
}

export const test = base.extend<{ guard: GuardState }>({
  guard: [
    async ({ context }, use, testInfo) => {
      const pages: Page[] = [];
      const s: GuardState = {
        csp: [],
        pageErrors: [],
        serverErrors: [],
        consoleErrors: [],
        consoleAll: [],
        attach: async (ctx) => {
          // trước mọi trang: ghi lại sự kiện securitypolicyviolation (init script của Playwright không chịu CSP)
          await ctx.addInitScript(() => {
            window.__mgCsp = [];
            document.addEventListener("securitypolicyviolation", (e) => {
              window.__mgCsp?.push(`${e.violatedDirective} ${e.blockedURI}`);
            });
          });
          const hook = (p: Page) => {
            pages.push(p);
            watch(p, s);
          };
          ctx.pages().forEach(hook);
          ctx.on("page", hook);
        },
      };
      await s.attach(context);
      await use(s);
      for (const p of pages) if (!p.isClosed()) s.csp.push(...(await cspFromPage(p)));
      if (s.consoleErrors.length > 0) {
        await testInfo.attach("console-errors.txt", { body: s.consoleErrors.join("\n"), contentType: "text/plain" });
      }
      expect.soft(s.csp, "vi phạm CSP").toEqual([]);
      expect.soft(s.pageErrors, "lỗi JavaScript chưa bắt").toEqual([]);
      expect.soft(s.serverErrors, "response 5xx của /api/v1").toEqual([]);
    },
    { auto: true },
  ],
});

export { expect };

// ------------------------------------------------------------------------------------------------ chờ trang
/** Trang SPA đã render xong: có h1, không còn "Đang tải…", mạng yên (polling của TanStack Query vẫn cho khoảng lặng). */
export async function settle(page: Page, lng: Lng): Promise<void> {
  await expect(page.locator("h1").first()).toBeVisible();
  await expect(page.getByRole("status").filter({ hasText: T(lng, "common.loading") })).toHaveCount(0);
  await page.waitForLoadState("networkidle", { timeout: 10_000 }).catch(() => undefined);
}

// ------------------------------------------------------------------------------------------------ axe
const WCAG = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"];

/** axe-core trong trình duyệt thật (gồm độ tương phản màu — jsdom không tính được): serious/critical ⇒ fail. */
export async function checkA11y(page: Page, testInfo: TestInfo, label: string): Promise<void> {
  const r = await new AxeBuilder({ page }).withTags(WCAG).analyze();
  const rows = r.violations.map((v) => ({
    id: v.id,
    impact: v.impact ?? "unknown",
    help: v.help,
    nodes: v.nodes.slice(0, 8).map((n) => n.target.join(" ")),
  }));
  if (rows.length > 0) {
    await testInfo.attach(`axe-${label}.json`, { body: JSON.stringify(rows, null, 2), contentType: "application/json" });
  }
  for (const v of rows.filter((x) => x.impact !== "serious" && x.impact !== "critical")) {
    testInfo.annotations.push({ type: `axe-${v.impact}`, description: `${label}: ${v.id} (${v.nodes.length} node)` });
  }
  const blocking = rows.filter((x) => x.impact === "serious" || x.impact === "critical");
  expect(blocking.map((v) => `${v.impact} ${v.id}: ${v.help} @ ${v.nodes.join(" | ")}`), `axe ${label}`).toEqual([]);
}

// ------------------------------------------------------------------------------------------------ i18n
/** lang của tài liệu đúng ngôn ngữ; không văn bản/nhãn ARIA nào là chuỗi CHỈ có ở catalog ngôn ngữ kia (chuỗi chưa dịch
 * hoặc hardcode) hay là khóa i18n thô (khóa thiếu). Bỏ qua <code>/<pre> (dữ liệu: kind của job, digest, …). */
export async function checkI18n(page: Page, lng: Lng, label: string): Promise<void> {
  await expect(page.locator("html")).toHaveAttribute("lang", lng);
  const texts = await page.evaluate(() => {
    const out: string[] = [];
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    for (let n = walker.nextNode(); n; n = walker.nextNode()) {
      const el = n.parentElement;
      if (!el || el.closest("code, pre, script, style, [data-i18n-skip]")) continue;
      const s = (n.textContent ?? "").trim();
      if (s) out.push(s);
    }
    for (const el of Array.from(document.body.querySelectorAll("[aria-label], [title], [placeholder], [alt]"))) {
      for (const a of ["aria-label", "title", "placeholder", "alt"]) {
        const v = el.getAttribute(a)?.trim();
        if (v) out.push(v);
      }
    }
    out.push(document.title);
    return out;
  });
  const other: Lng = lng === "vi" ? "en" : "vi";
  const leaks = [...new Set(texts.filter((s) => s.length >= 3 && VALUES[other].has(s) && !VALUES[lng].has(s)))];
  const raw = [...new Set(texts.filter((s) => /^[a-z][A-Za-z0-9]*(\.[A-Za-z0-9_-]+)+$/.test(s) && KEYS.has(s)))];
  expect({ leaks, raw }, `i18n ${label}`).toEqual({ leaks: [], raw: [] });
}

/** Một màn hình: chờ xong, axe, i18n. */
export async function checkScreen(page: Page, testInfo: TestInfo, label: string): Promise<void> {
  const lng = lngOf(testInfo);
  await settle(page, lng);
  await checkA11y(page, testInfo, label);
  await checkI18n(page, lng, label);
}

// ------------------------------------------------------------------------------------------------ trình duyệt
/** Bất biến lưu trữ (§8.3 bước 4, §12.4): Web Storage chỉ có tùy chọn hiển thị; không IndexedDB; cookie phiên
 * __Host- là HttpOnly + Secure + host-only + Path=/ và JavaScript không đọc được cookie nào của phiên. */
export async function checkBrowserStorage(page: Page, context: BrowserContext, origin: string): Promise<void> {
  const storage = await page.evaluate(async () => {
    const keys = (s: Storage) => Array.from({ length: s.length }, (_, i) => s.key(i) ?? "");
    const dbs = typeof indexedDB.databases === "function" ? (await indexedDB.databases()).map((d) => d.name ?? "") : [];
    return { local: keys(localStorage), session: keys(sessionStorage), dbs, cookie: document.cookie };
  });
  expect(storage.local.filter((k) => k !== "mg.pref.theme" && k !== "mg.pref.lang"), "localStorage").toEqual([]);
  expect(storage.session, "sessionStorage").toEqual([]);
  expect(storage.dbs, "IndexedDB").toEqual([]);
  const host = new URL(origin).hostname;
  const cookies = (await context.cookies(origin)).filter((c) => c.domain === host || c.domain === `.${host}`);
  const session = cookies.filter((c) => c.name.startsWith("__Host-"));
  expect(session.length, "cookie __Host- của phiên").toBeGreaterThan(0);
  for (const c of session) {
    expect({ name: c.name, httpOnly: c.httpOnly, secure: c.secure, domain: c.domain, path: c.path }).toEqual({
      name: c.name,
      httpOnly: true,
      secure: true,
      domain: host,
      path: "/",
    });
    expect(storage.cookie, "document.cookie không thấy cookie phiên").not.toContain(c.name);
  }
  // không chuỗi nào trông như token/khóa trong DOM (Headscale API key, pre-auth key, bearer)
  const html = await page.content();
  expect(html).not.toMatch(/hskey-(api|auth|authreq)-[A-Za-z0-9_-]{8,}|Bearer\s+[A-Za-z0-9._~+/=-]{8,}/);
}

/** Status của một GET cùng origin gọi TỪ TRONG trang (cookie, DNS, TLS của Chromium — APIRequestContext của Playwright
 * chạy trong Node, không đi qua host-resolver-rules/SPKI của trình duyệt). Trang phải đang ở origin của `path`. */
export async function apiStatus(page: Page, path: string): Promise<number> {
  return page.evaluate(async (p) => {
    const r = await fetch(p, { credentials: "same-origin", headers: { Accept: "application/json" } });
    return r.status;
  }, path);
}

// ------------------------------------------------------------------------------------------------ đăng nhập
/** Đăng nhập thật: trang /login của SPA → GET /api/v1/auth/login → Keycloak (mật khẩu, TOTP) → callback → SPA.
 * Trả về các bước đã qua (password, otp). Test gọi hàm này phải tắt trace (mật khẩu nằm trong thao tác fill). */
export async function login(page: Page, role: Role, lng: Lng): Promise<string[]> {
  const origin = originOf(role);
  const resp = await page.goto(`${origin}/login`);
  expect(resp?.headers()["content-security-policy"] ?? "").toContain("default-src 'self'");
  await expect(page.locator("h1")).toBeVisible();
  if (origin !== originOf("sa")) {
    await page.getByLabel(T(lng, "login.tenantLabel")).fill(cfg.tenantA.slug);
  }
  await page.getByRole("button", { name: T(lng, "login.submit") }).click();
  const steps = await completeKeycloak(page, role);
  await expect(page.locator("#main")).toBeVisible();
  await expect(page.getByRole("button", { name: T(lng, "shell.signOut") })).toBeVisible();
  return steps;
}

/** Các bước ở Keycloak (mật khẩu, TOTP) sau khi SPA đã chuyển hướng tới IdP — dùng cho đăng nhập và step-up
 * (`reauth=true` ⇒ prompt=login: hỏi lại mật khẩu + OTP); xong khi trình duyệt về lại origin của vai trò (ngoài /api, /login). */
export async function completeKeycloak(page: Page, role: Role): Promise<string[]> {
  const u = cfg.users[role];
  const origin = originOf(role);
  const steps: string[] = [];
  const otp = page.locator("input[name=otp]");
  const pw = page.locator("input[name=password]");
  const user = page.locator("input[name=username]");
  const submit = page.locator("#kc-login, button[type=submit], input[type=submit]").first();
  const deadline = Date.now() + 90_000;
  while (Date.now() < deadline) {
    const url = new URL(page.url());
    if (url.origin === origin && !url.pathname.startsWith("/api/") && !url.pathname.startsWith("/login")) break;
    if (url.hostname === AUTH_HOST) {
      if (await page.locator("input[name=totp]").isVisible()) throw new Error("Keycloak đòi cấu hình TOTP (harness chưa chuẩn bị user)");
      if (await otp.isVisible()) {
        if (steps.filter((x) => x === "otp").length >= 2) throw new Error(`OTP bị từ chối: ${steps.join(",")}`);
        await otp.fill(await nextTotp(role));
        await submit.click();
        await otp.waitFor({ state: "detached", timeout: 30_000 });
        steps.push("otp");
        continue;
      }
      if (await pw.isVisible()) {
        if (steps.filter((x) => x === "password").length >= 2) throw new Error(`mật khẩu bị từ chối: ${steps.join(",")}`);
        if ((await user.isVisible()) && (await user.isEditable())) await user.fill(u.username);
        await pw.fill(u.password);
        await submit.click();
        await pw.waitFor({ state: "detached", timeout: 30_000 });
        steps.push("password");
        continue;
      }
    }
    await page.waitForTimeout(250);
  }
  expect(new URL(page.url()).origin, `đăng nhập ${role}: ${steps.join(",")}`).toBe(origin);
  return steps;
}

// ------------------------------------------------------------------------------------------------ G4b: kênh harness
/** Một thao tác của harness (tests/e2e/harness/pwcontrol.py — thiết bị chạy client chính thức, đẩy auth_time cho step-up,
 * thành viên dùng-một-lần, dọn node): ghi <ctl>/<id>.req.json (tạm + rename), chờ <id>.res.json. */
export async function ctl<R = Record<string, unknown>>(op: string, args: Record<string, unknown> = {}, timeoutMs = 150_000): Promise<R> {
  const dir = ctlDir();
  if (!process.env.MG_PW_CONFIG || !fs.existsSync(dir)) throw new Error("kênh điều khiển của harness không có (chạy qua playwrightui.py)");
  const id = `${Date.now().toString(36)}-${randomBytes(4).toString("hex")}`;
  const tmp = path.join(dir, `${id}.req.tmp`);
  fs.writeFileSync(tmp, JSON.stringify({ ...args, op }), { mode: 0o600 });
  fs.renameSync(tmp, path.join(dir, `${id}.req.json`));
  const res = path.join(dir, `${id}.res.json`);
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (fs.existsSync(res)) {
      const out = JSON.parse(fs.readFileSync(res, "utf8")) as R & { error?: string };
      fs.unlinkSync(res);
      if (out.error) throw new Error(`harness ${op}: ${out.error}`);
      return out;
    }
    await new Promise((r) => setTimeout(r, 250));
  }
  throw new Error(`harness ${op}: quá ${String(timeoutMs)} ms`);
}

/** Chờ điều kiện của harness (vd. client Running) — hỏi lại mỗi `everyMs`. */
export async function ctlUntil<R>(op: string, args: Record<string, unknown>, ok: (r: R) => boolean, timeoutMs = 90_000, everyMs = 2_000): Promise<R> {
  const deadline = Date.now() + timeoutMs;
  let last = await ctl<R>(op, args);
  while (!ok(last) && Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, everyMs));
    last = await ctl<R>(op, args);
  }
  return last;
}

/** Nhãn thiết bị/hostname duy nhất cho một ca (chữ thường, số, gạch ngang — DEVICE_LABEL_RE); tiền tố pw ⇒ harness dọn được. */
export function uniq(kind: string, lng: Lng): string {
  return `pw${kind}-${lng}-${randomBytes(3).toString("hex")}`;
}

// ------------------------------------------------------------------------------------------------ G4b: vai trò thứ hai
export interface Actor {
  context: BrowserContext;
  page: Page;
}

/** Một trình duyệt (context) nữa với tùy chọn của project (ngôn ngữ, giao diện, múi giờ) — phiên của `role` (storage state
 * của auth.setup.ts) hoặc chưa đăng nhập (null) — được fixture guard theo dõi như context chính. Gọi `close()` khi xong. */
export async function newActor(browser: Browser, testInfo: TestInfo, guard: GuardState, role: Role | null): Promise<Actor> {
  const u = testInfo.project.use;
  const context = await browser.newContext({
    locale: u.locale,
    colorScheme: u.colorScheme,
    timezoneId: u.timezoneId,
    viewport: u.viewport ?? { width: 1366, height: 900 },
    ignoreHTTPSErrors: u.ignoreHTTPSErrors ?? false,
    ...(role ? { storageState: storageFile(role) } : {}),
  });
  await guard.attach(context);
  const page = await context.newPage();
  return { context, page };
}

/** identity_id của phiên đang mở trên trang (GET /auth/session từ trong trang). */
export async function identityId(page: Page): Promise<string> {
  const id = await page.evaluate(async () => {
    const r = await fetch("/api/v1/auth/session", { credentials: "same-origin", headers: { Accept: "application/json" } });
    const s = (await r.json()) as { principal?: { identity_id?: string } };
    return s.principal?.identity_id ?? "";
  });
  expect(id, "identity_id của phiên").toMatch(/^[0-9a-f-]{36}$/);
  return id;
}

/** Đẩy auth_time của phiên MỚI NHẤT của danh tính đang đăng nhập trên trang về 20 phút trước (harness, SQL như
 * policylife.py) ⇒ thao tác nhạy cảm kế tiếp nhận 401 reauth_required. Chỉ dùng với phiên vừa đăng nhập trong chính ca. */
export async function ageSession(page: Page): Promise<void> {
  const origin = new URL(page.url()).origin === ADMIN ? "admin" : "app";
  await ctl("age_session", { identity_id: await identityId(page), origin });
}

/** Step-up (§8.3 bước 7): bấm nút "Xác thực lại" ⇒ /auth/login?reauth=true ⇒ Keycloak hỏi lại mật khẩu + OTP ⇒ về đúng
 * trang đang ở (return_to). Trả về URL trước khi bấm. Test gọi hàm này phải tắt trace (mật khẩu nằm trong thao tác fill). */
export async function stepUp(page: Page, role: Role, button: Locator): Promise<string> {
  const before = page.url();
  await button.click();
  await page.waitForURL((u) => u.hostname === AUTH_HOST, { timeout: 30_000 });
  const steps = await completeKeycloak(page, role);
  expect(steps, "step-up hỏi lại mật khẩu và OTP").toEqual(expect.arrayContaining(["password", "otp"]));
  await expect(page.locator("#main")).toBeVisible();
  const back = new URL(page.url());
  expect(back.pathname + back.search, "step-up quay về đúng trang").toBe(new URL(before).pathname + new URL(before).search);
  return before;
}

// ------------------------------------------------------------------------------------------------ G4b: secret
const URL_SECRET = /[?&#](auth_id|code|state|session_state|id_token|access_token|key)=|hskey-/;
// thân token bắt buộc: chuỗi mẫu "hskey-authreq-…" trong gợi ý của ô dán link không phải token
const TOKEN_RE = /hskey-(api|auth|authreq)-[A-Za-z0-9_-]{8,}|Bearer\s+[A-Za-z0-9._~+/=-]{8,}/;

/** Checklist G4b (d): không secret trong DOM, URL, Web Storage, history.state, document.cookie hay console của MỌI trang
 * đang mở của context — mẫu token (hskey-…, Bearer), giá trị cookie phiên (__Host-, Playwright đọc được dù HttpOnly) và
 * các giá trị riêng của ca (`values`: pre-auth key, Auth ID, mã enrollment…); cộng bất biến lưu trữ (checkBrowserStorage).
 * Thông báo lỗi không in giá trị secret. */
export async function checkNoSecrets(context: BrowserContext, guard: GuardState, label: string, values: string[] = []): Promise<void> {
  const cookies = (await context.cookies()).filter((c) => c.name.startsWith("__Host-") && c.value.length >= 16).map((c) => c.value);
  const needles = [...values.filter((v) => v.length >= 8), ...cookies];
  for (const p of context.pages()) {
    if (p.isClosed() || !p.url().startsWith("https://")) continue;
    const url = p.url();
    expect(URL_SECRET.test(url), `${label}: URL không mang secret/tham số OIDC (${new URL(url).pathname})`).toBe(false);
    const html = await p.content();
    expect(TOKEN_RE.test(html), `${label}: DOM không có mẫu token`).toBe(false);
    const dump = await p.evaluate(() =>
      JSON.stringify({ l: Object.entries(localStorage), s: Object.entries(sessionStorage), h: history.state as unknown, c: document.cookie, t: document.title }),
    );
    expect(TOKEN_RE.test(dump), `${label}: Web Storage/history không có mẫu token`).toBe(false);
    needles.forEach((n, i) => {
      expect(html.includes(n), `${label}: DOM chứa giá trị secret #${String(i)}`).toBe(false);
      expect(dump.includes(n), `${label}: Web Storage/history/cookie JS chứa giá trị secret #${String(i)}`).toBe(false);
      expect(url.includes(n), `${label}: URL chứa giá trị secret #${String(i)}`).toBe(false);
    });
    if (new URL(url).hostname.startsWith("app.") || new URL(url).hostname.startsWith("admin.")) {
      await checkBrowserStorage(p, context, new URL(url).origin);
    }
  }
  const text = guard.consoleAll.join("\n");
  expect(TOKEN_RE.test(text), `${label}: console không có mẫu token`).toBe(false);
  needles.forEach((n, i) => {
    expect(text.includes(n), `${label}: console chứa giá trị secret #${String(i)}`).toBe(false);
  });
}

// ------------------------------------------------------------------------------------------------ G4b: thao tác ghi
/** Ghi lại các request ghi (POST/PUT/PATCH/DELETE) tới /api/v1 (trừ /auth/*) của một trang. */
export function watchWrites(page: Page): { list: () => string[]; clear: () => void } {
  const seen: string[] = [];
  page.on("request", (r) => {
    const u = new URL(r.url());
    if (!u.pathname.startsWith("/api/v1/") || u.pathname.startsWith("/api/v1/auth/")) return;
    if (!["GET", "HEAD", "OPTIONS"].includes(r.method())) seen.push(`${r.method()} ${u.pathname}`);
  });
  return {
    list: () => [...seen],
    clear: () => {
      seen.length = 0;
    },
  };
}

/** Hộp xác nhận đang mở (ConfirmDialog — alertdialog có form). Lời nhắc step-up ở đầu trang cũng là alertdialog (banner
 * nằm sau lớp modal, `inert`) nên không định vị hộp bằng role đơn thuần. */
export function confirmDialog(page: Page): Locator {
  return page.getByRole("alertdialog").filter({ has: page.locator("form") });
}

export interface DestructiveCheck {
  label: string;
  /** mở hộp xác nhận (bấm nút của thao tác) */
  open: () => Promise<void>;
  /** tiêu đề nêu đối tượng */
  title: string | RegExp;
  /** đoạn mô tả hậu quả / đối tượng phải có trong hộp */
  mentions: (string | RegExp)[];
  /** nhãn nút xác nhận */
  confirm: string;
  /** phải gõ lại giá trị này (slug, email, tên) trước khi nút xác nhận bật */
  typed?: string;
  /** nút xác nhận khóa lúc mở vì người dùng phải CHỌN đối tượng (vd. prefix cần gỡ duyệt) */
  mustChoose?: boolean;
  /** điền phần bắt buộc khác của hộp (vd. lý do) ở lần mở thứ hai, trước khi gõ xác nhận */
  prepare?: () => Promise<void>;
}

/** Checklist G4b (e): hộp xác nhận của một thao tác phá hủy — alertdialog, tiêu đề nêu ĐỐI TƯỢNG, mô tả HẬU QUẢ, focus đầu
 * vào thao tác an toàn (Hủy) hoặc ô gõ xác nhận, nút xác nhận khóa tới khi gõ đúng, axe; Esc đóng và Hủy đóng — không
 * request ghi nào được gửi. */
export async function checkDestructiveConfirm(page: Page, testInfo: TestInfo, c: DestructiveCheck): Promise<void> {
  const lng = lngOf(testInfo);
  const writes = watchWrites(page);
  await c.open();
  const dlg = confirmDialog(page);
  await expect(dlg).toBeVisible();
  await expect(dlg.getByRole("heading").first()).toHaveText(c.title);
  for (const m of c.mentions) await expect(dlg).toContainText(m);
  const confirm = dlg.getByRole("button", { name: c.confirm, exact: true });
  const cancel = dlg.getByRole("button", { name: T(lng, "ui.cancel"), exact: true });
  if (c.typed !== undefined) {
    await expect(confirm).toBeDisabled();
    await expect(dlg.getByRole("textbox").last()).toBeFocused();
  } else {
    if (c.mustChoose) await expect(confirm).toBeDisabled();
    else await expect(confirm).toBeEnabled();
    await expect(cancel).toBeFocused();
  }
  await checkA11y(page, testInfo, `confirm-${c.label}`);
  await page.keyboard.press("Escape");
  await expect(dlg).toHaveCount(0);
  await c.open();
  await expect(dlg).toBeVisible();
  await c.prepare?.();
  if (c.typed !== undefined) {
    await dlg.getByRole("textbox").last().fill(c.typed.slice(0, -1));
    await expect(confirm).toBeDisabled();
    await dlg.getByRole("textbox").last().fill(c.typed);
    await expect(confirm).toBeEnabled();
  }
  await cancel.click();
  await expect(dlg).toHaveCount(0);
  await page.waitForTimeout(300);
  expect(writes.list(), `${c.label}: Esc/Hủy không gửi thao tác ghi nào`).toEqual([]);
}

/** Bấm một nút ghi; 429 (bucket `enrollment`: 5 + 1/5 s mỗi danh tính — UI giữ nút + Idempotency-Key) ⇒ chờ rồi bấm lại. */
export async function clickUntil(page: Page, lng: Lng, button: Locator, done: Locator, timeoutMs = 120_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  const limited = page.getByRole("alert").filter({ hasText: T(lng, "problem.rate_limited") });
  for (;;) {
    // lượt tự động của màn hình (vd. trang claim — F-G4a-1) có thể đã xong trong lúc chờ
    if (await done.first().isVisible()) return;
    await expect(button.or(done).first()).toBeVisible({ timeout: 30_000 });
    if (await done.first().isVisible()) return;
    await expect(button).toBeEnabled({ timeout: 30_000 });
    await button.click();
    await page.waitForTimeout(500);
    await expect(done.or(limited).first()).toBeVisible({ timeout: 45_000 });
    if (await done.first().isVisible()) return;
    if (Date.now() > deadline) throw new Error("429 không dứt");
    await page.waitForTimeout(6_000);
  }
}
