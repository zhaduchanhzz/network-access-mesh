// JSON chuẩn hóa của payload phê duyệt (approval_requests.payload, §6.3 — internal/authz/approvals/canonical.go):
// object JSON, khóa sắp theo thứ tự byte UTF-8 ở mọi cấp, không khoảng trắng, không escape HTML, số chỉ là số nguyên
// (≤ 19 chữ số), chuỗi escape như encoding/json của Go (ký tự điều khiển, `"`, `\`, U+2028, U+2029).
// payload_sha256 = SHA-256 (hex thường) của chuỗi đó. Người duyệt gửi lại đúng hash của payload mình đã xem: trình duyệt
// tính lại để chắc payload hiển thị là payload sẽ thực thi (hash do server gửi không được tin mù quáng).

const encoder = new TextEncoder();

function compareBytes(a: string, b: string): number {
  const x = encoder.encode(a);
  const y = encoder.encode(b);
  const n = Math.min(x.length, y.length);
  for (let i = 0; i < n; i++) {
    const d = (x[i] ?? 0) - (y[i] ?? 0);
    if (d !== 0) return d;
  }
  return x.length - y.length;
}

const SHORT: Record<string, string> = { '"': '\\"', "\\": "\\\\", "\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r", "\t": "\\t" };

function quote(s: string): string {
  let out = '"';
  for (const ch of s) {
    const short = SHORT[ch];
    if (short !== undefined) {
      out += short;
      continue;
    }
    const c = ch.codePointAt(0) ?? 0;
    if (c < 0x20 || c === 0x2028 || c === 0x2029) out += `\\u${c.toString(16).padStart(4, "0")}`;
    else out += ch;
  }
  return out + '"';
}

export class CanonicalError extends Error {}

const MAX_DEPTH = 16;

function write(v: unknown, depth: number): string {
  if (depth > MAX_DEPTH) throw new CanonicalError("nested too deep");
  if (v === null) return "null";
  switch (typeof v) {
    case "boolean":
      return v ? "true" : "false";
    case "number":
      // JSON.parse làm tròn số lớn hơn 2^53: không còn chắc là đúng giá trị server đã băm ⇒ không xác minh được
      if (!Number.isSafeInteger(v)) throw new CanonicalError("number is not a safe integer");
      return String(v);
    case "string":
      return quote(v);
    case "object": {
      if (Array.isArray(v)) return `[${v.map((e) => write(e, depth + 1)).join(",")}]`;
      const entries = Object.entries(v as Record<string, unknown>).sort(([a], [b]) => compareBytes(a, b));
      return `{${entries.map(([k, e]) => `${quote(k)}:${write(e, depth + 1)}`).join(",")}}`;
    }
    default:
      throw new CanonicalError(`unexpected JSON value ${typeof v}`);
  }
}

/** Chuỗi JSON chuẩn hóa của một object payload; giá trị không chuẩn hóa được ⇒ CanonicalError. */
export function canonicalJson(payload: unknown): string {
  if (payload === null || typeof payload !== "object" || Array.isArray(payload)) {
    throw new CanonicalError("payload is not a JSON object");
  }
  return write(payload, 0);
}

export async function sha256Hex(text: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(text));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** payload_sha256 tính trong trình duyệt; null khi payload không chuẩn hóa được (không xác minh được). */
export async function payloadSha256(payload: unknown): Promise<string | null> {
  try {
    return await sha256Hex(canonicalJson(payload));
  } catch (e) {
    if (e instanceof CanonicalError) return null;
    throw e;
  }
}
