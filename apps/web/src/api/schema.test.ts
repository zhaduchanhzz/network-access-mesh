// Type client sinh từ spec khớp bản đã commit (§12.4 "CI fail nếu lệch"): sinh lại src/api/schema.d.ts trong bộ nhớ
// bằng openapi-typescript (cùng bản pin) và so với file đã commit — cùng phép thử với job CI api-types, chạy được
// cục bộ bằng `npm test`. Các lời gọi api.GET/POST trong mã nguồn được tsc kiểm theo đúng type này.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import openapiTS, { astToString } from "openapi-typescript";
import { describe, expect, it } from "vitest";

const SPEC = join(import.meta.dirname, "../../../../api/openapi.yaml");
const COMMITTED = join(import.meta.dirname, "schema.d.ts");

/** Bỏ phần chú thích đầu file mà CLI thêm (không thuộc nội dung type). */
function body(text: string): string {
  const lines = text.replace(/\r\n/g, "\n").split("\n");
  const start = lines.findIndex((l) => !l.startsWith("/**") && !l.startsWith(" *") && l.trim() !== "");
  return lines.slice(start).join("\n").trim();
}

describe("src/api/schema.d.ts", () => {
  it("khớp api/openapi.yaml (chạy `npm run gen:api` khi lệch)", async () => {
    // nội dung (không phải URL): spec một file, không $ref ra ngoài
    const ast = await openapiTS(readFileSync(SPEC, "utf8"));
    expect(body(astToString(ast))).toBe(body(readFileSync(COMMITTED, "utf8")));
  }, 60_000);
});
