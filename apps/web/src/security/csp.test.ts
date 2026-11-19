// CSP của SPA (§12.4, §14.6): index.html không có script/style inline hay tài nguyên ngoài origin; edge
// (portal_headers + platform_headers của infrastructure/caddy/Caddyfile.tmpl) là NGUỒN DUY NHẤT của header bảo mật cho
// mọi phản hồi của app./admin. — api, SPA và trang lỗi (P4-T01a): đúng một Content-Security-Policy, có frame-ancestors
// 'none', không 'unsafe-inline'/'unsafe-eval', không host ngoài; container web (infrastructure/docker/web/Caddyfile)
// không tự đặt header bảo mật nào.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

// đường dẫn tính từ thư mục của file (URL tương đối trong môi trường jsdom bị phân giải theo origin của trang)
const read = (rel: string) => readFileSync(join(import.meta.dirname, rel), "utf8");
const html = read("../../index.html");
const webCaddy = read("../../../../infrastructure/docker/web/Caddyfile");
const edgeTmpl = read("../../../../infrastructure/caddy/Caddyfile.tmpl");

const csp = (text: string) => [...text.matchAll(/Content-Security-Policy "([^"]+)"/g)].map((m) => m[1] ?? "");

describe("CSP", () => {
  it("index.html: chỉ một script module có src, không inline, không URL ngoài", () => {
    const scripts = [...html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/g)];
    expect(scripts).toHaveLength(1);
    expect(scripts[0]?.[1]).toMatch(/type="module" src="\/src\/main\.tsx"/);
    expect(scripts[0]?.[2]?.trim()).toBe("");
    expect(html).not.toMatch(/<style|\sstyle=|\son[a-z]+=/i);
    expect(html).not.toMatch(/(src|href)="(https?:)?\/\//);
  });

  it("edge là nguồn duy nhất: đúng một CSP chặt ở portal_headers, container web không có", () => {
    const edge = csp(edgeTmpl);
    expect(edge).toHaveLength(1);
    expect(csp(webCaddy)).toHaveLength(0);
    const policy = edge[0] ?? "";
    for (const d of ["default-src 'self'", "base-uri 'none'", "object-src 'none'", "frame-ancestors 'none'", "form-action 'self'"]) {
      expect(policy).toContain(d);
    }
    expect(policy).not.toMatch(/unsafe-inline|unsafe-eval|https?:|\*/);
  });

  it("header bảo mật chỉ ở edge (kể cả trang lỗi); container web chỉ bỏ Server", () => {
    // thân snippet `(name) { … }` của template edge (dấu "}" đóng ở cột 0)
    const snippet = (name: string) => {
      const start = edgeTmpl.indexOf(`\n(${name}) {\n`);
      return start < 0 ? "" : edgeTmpl.slice(start, edgeTmpl.indexOf("\n}\n", start + 1));
    };
    const portal = snippet("portal_headers");
    const platform = snippet("platform_headers");
    expect(portal).toMatch(/X-Frame-Options DENY/);
    expect(portal).toMatch(/Referrer-Policy no-referrer/);
    expect(portal).toMatch(/Cross-Origin-Opener-Policy same-origin/);
    expect(portal).toMatch(/Cross-Origin-Resource-Policy same-origin/);
    expect(portal).toMatch(/Permissions-Policy "camera=\(\), microphone=\(\), geolocation=\(\), payment=\(\), usb=\(\)"/);
    expect(platform).toMatch(/Strict-Transport-Security "max-age=31536000"/);
    expect(platform).toMatch(/X-Content-Type-Options nosniff/);
    expect(platform).toMatch(/-Server/);
    // trang lỗi 503 của edge (api/web không trả lời) mang cùng header
    expect(snippet("portal_site")).toMatch(/handle_errors 502 503 504 \{[\s\S]*import platform_headers[\s\S]*import portal_headers \*/);
    const webDirectives = webCaddy
      .split("\n")
      .filter((l) => !l.trim().startsWith("#"))
      .join("\n");
    for (const h of ["Content-Security-Policy", "Strict-Transport-Security", "X-Content-Type-Options", "X-Frame-Options",
      "Referrer-Policy", "Cross-Origin-Opener-Policy", "Cross-Origin-Resource-Policy", "Permissions-Policy"]) {
      expect(webDirectives).not.toContain(h);
    }
    expect(webCaddy).toMatch(/header -Server/);
  });
});

describe("component nền (react-aria — P4-T02) không cần style inline", () => {
  it("index.html có sẵn phần tử id react-aria-pressable-style (usePress không chèn <style>), quy tắc nằm trong styles.css", () => {
    expect(html).toMatch(/<template id="react-aria-pressable-style"><\/template>/);
    const css = read("../styles.css");
    expect(css).toMatch(/\[data-react-aria-pressable\]\s*\{\s*touch-action: pan-x pan-y pinch-zoom;/);
    // tên id/attribute đúng với bản react-aria đang cài (đổi phiên bản ⇒ test này báo)
    const press = read("../../node_modules/react-aria/dist/private/interactions/usePress.mjs");
    expect(press).toContain("'react-aria-pressable-style'");
    expect(press).toContain("'data-react-aria-pressable'");
    expect(press).toMatch(/getElementById\(\$[0-9a-f]+\$var\$STYLE_ID\)\) return;/);
  });
});
