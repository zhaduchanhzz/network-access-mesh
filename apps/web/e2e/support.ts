// Công cụ chung của các spec Playwright (P4-T14): fixture `guard` (tự bật cho mọi test) bắt vi phạm CSP, lỗi JS chưa
// bắt, response 5xx của /api/v1; kiểm axe (WCAG 2.1 AA — vi phạm serious/critical ⇒ fail, mức khác đính kèm báo cáo);
// kiểm i18n (lang của tài liệu, không chuỗi của ngôn ngữ kia, không khóa i18n thô); bất biến lưu trữ của trình duyệt;
// đăng nhập thật qua Keycloak (mật khẩu + TOTP).
import AxeBuilder from "@axe-core/playwright";
import { test as base, expect, type BrowserContext, type Page, type TestInfo } from "@playwright/test";
import fs from "node:fs";
import { AUTH_HOST, cfg, nextTotp, originOf, type Role } from "./env";

// ------------------------------------------------------------------------------------------------ i18n catalog
type Lng = "vi" | "en";
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

export function lngOf(testInfo: TestInfo): Lng {
  return testInfo.project.name === "en" ? "en" : "vi";
}

// ------------------------------------------------------------------------------------------------ guard
interface GuardState {
  csp: string[];
  pageErrors: string[];
  serverErrors: string[];
  consoleErrors: string[];
}

declare global {
  interface Window {
    __mgCsp?: string[];
  }
}

function watch(page: Page, s: GuardState): void {
  page.on("pageerror", (e) => s.pageErrors.push(`${page.url()}: ${e.message}`));
  page.on("console", (m) => {
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
      const s: GuardState = { csp: [], pageErrors: [], serverErrors: [], consoleErrors: [] };
      // trước mọi trang: ghi lại sự kiện securitypolicyviolation (init script của Playwright không chịu CSP)
      await context.addInitScript(() => {
        window.__mgCsp = [];
        document.addEventListener("securitypolicyviolation", (e) => {
          window.__mgCsp?.push(`${e.violatedDirective} ${e.blockedURI}`);
        });
      });
      const pages: Page[] = [];
      const hook = (p: Page) => {
        pages.push(p);
        watch(p, s);
      };
      context.pages().forEach(hook);
      context.on("page", hook);
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
  expect(html).not.toMatch(/hskey-(api|auth|authreq)-|Bearer\s+[A-Za-z0-9._~+/=-]{8,}/);
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
  const u = cfg.users[role];
  const origin = originOf(role);
  const resp = await page.goto(`${origin}/login`);
  expect(resp?.headers()["content-security-policy"] ?? "").toContain("default-src 'self'");
  await expect(page.locator("h1")).toBeVisible();
  if (origin !== originOf("sa")) {
    await page.getByLabel(T(lng, "login.tenantLabel")).fill(cfg.tenantA.slug);
  }
  await page.getByRole("button", { name: T(lng, "login.submit") }).click();
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
  await expect(page.locator("#main")).toBeVisible();
  await expect(page.getByRole("button", { name: T(lng, "shell.signOut") })).toBeVisible();
  return steps;
}
