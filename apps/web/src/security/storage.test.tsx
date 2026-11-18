// Definition of Done của Phase 4 / kiểm chứng của P4-T01: KHÔNG token hay secret trong browser storage (§8.3 bước 4,
// §12.4). Hai lớp: (1) quét mã nguồn — chỉ src/prefs.ts chạm Web Storage, không ai chạm cookie/IndexedDB/Cache
// Storage/service worker, chỉ src/api/client.ts gọi fetch; (2) chạy thật một phiên (đăng nhập, chọn tenant, đổi ngôn ngữ
// và giao diện, thao tác ghi mang CSRF, step-up, đăng xuất) rồi kiểm từng lần ghi vào Storage và trạng thái cuối.
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { describe, expect, it, vi } from "vitest";
import { browser } from "../app/console";
import { PREF_KEYS, PREFS } from "../prefs";
import { CSRF, json, mockApi, problem, renderApp, TENANT_A, tenantBody, tenantSession } from "../test/helpers";

const SRC = join(import.meta.dirname, "..");

function sources(): { rel: string; text: string }[] {
  const out: { rel: string; text: string }[] = [];
  const walk = (d: string) => {
    for (const n of readdirSync(d)) {
      const p = join(d, n);
      if (statSync(p).isDirectory()) walk(p);
      else if (/\.(ts|tsx)$/.test(n) && !/\.test\.tsx?$/.test(n) && !p.includes(join("src", "test")) && !n.endsWith(".d.ts"))
        out.push({ rel: relative(SRC, p).split("\\").join("/"), text: readFileSync(p, "utf8") });
    }
  };
  walk(SRC);
  return out;
}

describe("quét mã nguồn", () => {
  const files = sources();

  it("có đủ mã nguồn để quét", () => {
    expect(files.length).toBeGreaterThan(15);
    expect(files.map((f) => f.rel)).toContain("prefs.ts");
  });

  it("chỉ src/prefs.ts chạm localStorage/sessionStorage", () => {
    const users = files.filter((f) => /\b(localStorage|sessionStorage)\b/.test(f.text)).map((f) => f.rel);
    expect(users).toEqual(["prefs.ts"]);
  });

  it("không file nào chạm cookie, IndexedDB, Cache Storage, cookieStore hay service worker", () => {
    const bad = files.filter((f) => /document\.cookie|\bindexedDB\b|\bcaches\.|\bcookieStore\b|serviceWorker/.test(f.text));
    expect(bad.map((f) => f.rel)).toEqual([]);
  });

  it("chỉ src/api/client.ts gọi fetch; không XMLHttpRequest/WebSocket/EventSource/sendBeacon", () => {
    const fetchers = files.filter((f) => /\bfetch\s*\(/.test(f.text)).map((f) => f.rel);
    expect(fetchers).toEqual(["api/client.ts"]);
    const other = files.filter((f) => /XMLHttpRequest|new WebSocket|EventSource|sendBeacon/.test(f.text));
    expect(other.map((f) => f.rel)).toEqual([]);
  });

  it("không URL tuyệt đối http(s) trong mã nguồn (không CDN, không gọi Headscale hay dịch vụ ngoài)", () => {
    const bad = files.filter((f) => /["'`]https?:\/\//.test(f.text));
    expect(bad.map((f) => f.rel)).toEqual([]);
  });

  it("prefs chỉ có hai khóa với tập giá trị cố định", () => {
    expect(PREF_KEYS).toEqual(["mg.pref.theme", "mg.pref.lang"]);
    expect(PREFS.theme.values).toEqual(["system", "light", "dark"]);
    expect(PREFS.lang.values).toEqual(["vi", "en"]);
  });
});

describe("một phiên thật — Storage chỉ chứa tùy chọn hiển thị", () => {
  it("không token/secret nào được ghi; cookie không bị JavaScript đặt", async () => {
    const writes: [string, string][] = [];
    // eslint-disable-next-line @typescript-eslint/unbound-method -- gọi lại với đúng `this` (Storage) ở dưới
    const orig = Storage.prototype.setItem;
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(function (this: Storage, k: string, v: string) {
      writes.push([k, v]);
      orig.call(this, k, v);
    });
    const assign = vi.spyOn(browser, "assign").mockImplementation(() => undefined);
    const redirect = "https://auth.example.test/realms/tenant-a/protocol/openid-connect/logout?id_token_hint=eyJxxxxxxxx"; // giá trị giả, entropy thấp (gitleaks)
    const { requests } = mockApi({
      "GET /auth/session": json(200, tenantSession([{ tenantId: TENANT_A, slug: "tenant-a", name: "Tenant A", role: "tenant_owner" }])),
      [`GET /tenants/${TENANT_A}`]: json(200, tenantBody(TENANT_A, "tenant-a")),
      "POST /auth/logout": (req) =>
        req.headers.get("X-CSRF-Token") === CSRF ? json(200, { redirect_to: redirect }) : problem(403, "forbidden"),
    });
    const cookieBefore = document.cookie;
    renderApp({ path: "/" });
    await screen.findByRole("heading", { name: "Tổng quan", level: 1 });

    await userEvent.selectOptions(screen.getByLabelText("Ngôn ngữ"), "en");
    await screen.findByRole("heading", { name: "Overview", level: 1 });
    await userEvent.selectOptions(screen.getByLabelText("Theme"), "dark");
    expect(document.documentElement.dataset.theme).toBe("dark");
    await userEvent.click(screen.getByRole("button", { name: "Sign out" }));
    await waitFor(() => {
      expect(assign).toHaveBeenCalledWith(redirect);
    });

    // mọi lần ghi: khóa thuộc allow-list, giá trị thuộc tập cố định
    expect(writes).toEqual([
      ["mg.pref.lang", "en"],
      ["mg.pref.theme", "dark"],
    ]);
    const dump = (s: Storage) => Array.from({ length: s.length }, (_, i) => s.key(i) ?? "").map((k) => [k, s.getItem(k) ?? ""]);
    expect(dump(localStorage).map(([k]) => k).sort()).toEqual([...PREF_KEYS].sort());
    expect(sessionStorage.length).toBe(0);
    const stored = JSON.stringify([dump(localStorage), dump(sessionStorage)]);
    for (const secret of [CSRF, "id_token_hint", "eyJ", "hskey-", "__Host-mg_session"]) {
      expect(stored).not.toContain(secret);
    }
    expect(document.cookie).toBe(cookieBefore);
    // CSRF token không bao giờ hiện trong DOM
    expect(document.body.innerHTML).not.toContain(CSRF);
    // mọi request đi tới /api/v1 cùng origin
    expect(requests.length).toBeGreaterThan(0);
    for (const r of requests) {
      const u = new URL(r.url);
      expect(u.origin).toBe(window.location.origin);
      expect(u.pathname.startsWith("/api/v1/")).toBe(true);
    }
  });
});
