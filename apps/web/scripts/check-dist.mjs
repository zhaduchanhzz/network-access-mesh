// Kiểm bản build dist/ có chạy được dưới CSP của edge và của container web hay không (P4-T01, §12.4):
//   default-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'self'
// ⇒ không <script>/<style> inline, không thuộc tính style= hay on*= trong HTML, không tài nguyên ngoài origin
// (http://, https://, //host) hay data: URI trong HTML/CSS, không sourcemap, không eval/new Function trong JS.
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const dist = fileURLToPath(new URL("../dist/", import.meta.url));
const files = [];
const walk = (d) => {
  for (const n of readdirSync(d)) {
    const p = join(d, n);
    if (statSync(p).isDirectory()) walk(p);
    else files.push(p);
  }
};
walk(dist);

const errors = [];
const fail = (file, msg) => errors.push(`${relative(dist, file)}: ${msg}`);
const EXTERNAL = /(?:src|href)\s*=\s*["']?(?:https?:)?\/\/|url\(\s*["']?(?:https?:)?\/\//i;
const DATA_URI = /(?:src|href)\s*=\s*["']?data:|url\(\s*["']?data:/i;

for (const f of files) {
  const text = /\.(html|css|js|svg|json)$/.test(f) ? readFileSync(f, "utf8") : "";
  if (f.endsWith(".map")) fail(f, "sourcemap trong bản build");
  if (f.endsWith(".html")) {
    for (const m of text.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)) {
      if (!/\bsrc=/.test(m[1] ?? "") || (m[2] ?? "").trim() !== "") fail(f, "script inline");
    }
    if (/<style\b/i.test(text)) fail(f, "<style> inline");
    if (/\sstyle\s*=/i.test(text)) fail(f, "thuộc tính style=");
    if (/\son[a-z]+\s*=/i.test(text)) fail(f, "thuộc tính on*= (event handler inline)");
  }
  if (/\.(html|css)$/.test(f)) {
    if (EXTERNAL.test(text)) fail(f, "tài nguyên ngoài origin");
    if (DATA_URI.test(text)) fail(f, "data: URI");
  }
  if (f.endsWith(".js") && /\beval\(|new Function\(/.test(text)) fail(f, "eval/new Function (cần 'unsafe-eval')");
}
if (!files.some((f) => f.endsWith("index.html"))) errors.push("thiếu index.html");

if (errors.length > 0) {
  console.error(`check-dist: ${errors.length} lỗi\n  ${errors.join("\n  ")}`);
  process.exit(1);
}
console.log(`check-dist: ${files.length} file, không inline script/style, không tài nguyên ngoài origin, không sourcemap`);
