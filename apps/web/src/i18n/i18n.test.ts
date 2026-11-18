// Catalog vi/en (§12.4): cùng tập khóa, không chuỗi rỗng, cùng biến nội suy; mọi khóa mà mã nguồn dùng đều có mặt
// (t("…") với khóa cố định, labelKey của điều hướng, khóa động problem.* / roles.* / nav.groups.* / prefs.*).
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { KNOWN_CODES } from "../api/problem";
import { ROLE_SCOPE } from "../auth/rbac.gen";
import { NAV_GROUPS, PLATFORM_NAV, TENANT_NAV } from "../nav/navModel";
import { formatDateTime } from "./index";
import en from "./locales/en.json";
import vi from "./locales/vi.json";

type Tree = { [k: string]: string | Tree };
const PLURAL = /_(zero|one|two|few|many|other)$/;

function flatten(t: Tree, prefix = ""): Map<string, string> {
  const out = new Map<string, string>();
  for (const [k, v] of Object.entries(t)) {
    const key = prefix ? `${prefix}.${k}` : k;
    if (typeof v === "string") out.set(key, v);
    else for (const [kk, vv] of flatten(v, key)) out.set(kk, vv);
  }
  return out;
}

const catalogs = { vi: flatten(vi), en: flatten(en) };
const bases = (m: Map<string, string>) => new Set([...m.keys()].map((k) => k.replace(PLURAL, "")));
const vars = (s: string) => [...s.matchAll(/\{\{\s*([a-zA-Z_]+)\s*\}\}/g)].map((m) => m[1]).sort();

function has(lang: "vi" | "en", key: string): boolean {
  const m = catalogs[lang];
  return m.has(key) || m.has(`${key}_other`);
}

describe("catalog", () => {
  it("vi và en có cùng tập khóa (bỏ hậu tố số nhiều)", () => {
    expect([...bases(catalogs.vi)].sort()).toEqual([...bases(catalogs.en)].sort());
  });

  it("tiếng Việt chỉ dùng _other; tiếng Anh có _one + _other cho mọi khóa số nhiều", () => {
    const viPlural = [...catalogs.vi.keys()].filter((k) => PLURAL.test(k));
    expect(viPlural.every((k) => k.endsWith("_other"))).toBe(true);
    for (const k of viPlural) {
      const base = k.replace(PLURAL, "");
      expect(catalogs.en.has(`${base}_one`) && catalogs.en.has(`${base}_other`)).toBe(true);
    }
  });

  it("không chuỗi rỗng; biến nội suy giống nhau giữa hai ngôn ngữ", () => {
    for (const [lang, m] of Object.entries(catalogs)) {
      for (const [k, v] of m) expect(v.trim(), `${lang}:${k}`).not.toBe("");
    }
    for (const base of bases(catalogs.vi)) {
      const viText = catalogs.vi.get(base) ?? catalogs.vi.get(`${base}_other`) ?? "";
      const enText = catalogs.en.get(base) ?? catalogs.en.get(`${base}_other`) ?? "";
      expect(vars(viText), base).toEqual(vars(enText));
    }
  });
});

const SRC = join(import.meta.dirname, "..");
function sourceTexts(): string[] {
  const out: string[] = [];
  const walk = (d: string) => {
    for (const n of readdirSync(d)) {
      const p = join(d, n);
      if (statSync(p).isDirectory()) {
        if (n !== "test") walk(p);
      } else if (/\.(ts|tsx)$/.test(n) && !/\.test\.tsx?$/.test(n)) out.push(readFileSync(p, "utf8"));
    }
  };
  walk(SRC);
  return out;
}

describe("khóa mà mã nguồn dùng", () => {
  it("mọi t(\"…\") với khóa cố định có trong cả hai catalog", () => {
    const used = new Set<string>();
    for (const text of sourceTexts()) {
      for (const m of text.matchAll(/\bt\(\s*"([a-zA-Z0-9_.]+)"/g)) used.add(m[1] ?? "");
    }
    expect(used.size).toBeGreaterThan(30);
    const missing = [...used].filter((k) => !has("vi", k) || !has("en", k));
    expect(missing).toEqual([]);
  });

  it("khóa động: mã lỗi, role, nhóm và mục điều hướng, tùy chọn", () => {
    const keys = [
      ...[...KNOWN_CODES, "network_error", "unexpected_response"].map((c) => `problem.${c}`),
      ...Object.keys(ROLE_SCOPE).map((r) => `roles.${r}`),
      ...NAV_GROUPS.map((g) => `nav.groups.${g}`),
      ...[...TENANT_NAV, ...PLATFORM_NAV].map((i) => i.labelKey),
      "prefs.languages.vi",
      "prefs.languages.en",
      "prefs.themes.system",
      "prefs.themes.light",
      "prefs.themes.dark",
    ];
    expect(keys.filter((k) => !has("vi", k) || !has("en", k))).toEqual([]);
  });

  it("ngày giờ theo locale", () => {
    const iso = "2026-11-19T08:30:00Z";
    expect(formatDateTime(iso, "vi")).not.toEqual(formatDateTime(iso, "en"));
    expect(formatDateTime("không-phải-ngày", "vi")).toBe("không-phải-ngày");
  });
});
