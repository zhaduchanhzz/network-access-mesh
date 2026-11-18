// CSP của SPA (§12.4, §14.6): index.html không có script/style inline hay tài nguyên ngoài origin; container web
// (infrastructure/docker/web/Caddyfile) và edge (portal_headers của infrastructure/caddy/Caddyfile.tmpl) phát CÙNG
// một Content-Security-Policy, có frame-ancestors 'none', không 'unsafe-inline'/'unsafe-eval', không host ngoài.
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

  it("container web và edge phát cùng một CSP chặt", () => {
    const web = csp(webCaddy);
    const edge = csp(edgeTmpl);
    expect(web).toHaveLength(1);
    expect(edge).toHaveLength(1);
    expect(web[0]).toBe(edge[0]);
    const policy = web[0] ?? "";
    for (const d of ["default-src 'self'", "base-uri 'none'", "object-src 'none'", "frame-ancestors 'none'", "form-action 'self'"]) {
      expect(policy).toContain(d);
    }
    expect(policy).not.toMatch(/unsafe-inline|unsafe-eval|https?:|\*/);
  });

  it("container web: HSTS, nosniff, X-Frame-Options DENY, no-referrer, không lộ Server", () => {
    expect(webCaddy).toMatch(/Strict-Transport-Security "max-age=31536000"/);
    expect(webCaddy).toMatch(/X-Content-Type-Options nosniff/);
    expect(webCaddy).toMatch(/X-Frame-Options DENY/);
    expect(webCaddy).toMatch(/Referrer-Policy no-referrer/);
    expect(webCaddy).toMatch(/-Server/);
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
