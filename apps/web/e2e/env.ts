// Tham số của một lượt Playwright (P4-T14) — đọc từ tệp JSON do tests/e2e/harness/playwrightui.py viết (MG_PW_CONFIG).
// Tệp và các storage state (cookie phiên) nằm trong thư mục làm việc của stack (bị xóa khi gỡ stack) — KHÔNG trong
// thư mục kết quả/artifact. Không in mật khẩu, khóa TOTP hay cookie ra log.
import { createHmac } from "node:crypto";
import fs from "node:fs";
import path from "node:path";

export type Role = "sa" | "sa2" | "owner" | "admin" | "admin2" | "member";

export interface TestUser {
  username: string;
  password: string;
  /** khóa TOTP (chuỗi totpSecret Keycloak đưa ở lần cấu hình đầu) */
  totpKey: string;
  /** bộ đếm TOTP lớn nhất đã dùng (Keycloak từ chối mã dùng lại) */
  totpLast: number;
  displayName: string;
}

export interface PwConfig {
  domain: string;
  /** địa chỉ trình duyệt dùng cho app./admin./auth.<domain> (MAP của --host-resolver-rules) */
  edgeIp: string;
  /** base64(sha256(SPKI)) của chứng chỉ edge (lá, ký bởi CA dùng-một-lần của lượt chạy) — Chromium chỉ bỏ qua lỗi
   * "CA không tin cậy" cho chứng chỉ có đúng khóa này */
  tlsSpki: string;
  tenantA: { id: string; slug: string };
  tenantB: { id: string; slug: string };
  /** yêu cầu 2P (platform.user.super_admin) do SA2 tạo, đang chờ — SA1 xem chi tiết, không duyệt */
  platformApprovalId: string;
  users: Record<Role, TestUser>;
}

const FALLBACK: PwConfig = {
  domain: "example.invalid",
  edgeIp: "127.0.0.1",
  tlsSpki: "",
  tenantA: { id: "00000000-0000-4000-8000-00000000000a", slug: "tenant-a" },
  tenantB: { id: "00000000-0000-4000-8000-00000000000b", slug: "tenant-b" },
  platformApprovalId: "00000000-0000-4000-8000-0000000000ab",
  users: {} as Record<Role, TestUser>,
};

let cached: PwConfig | null = null;

/** Cấu hình của lượt chạy; không có MG_PW_CONFIG (vd. `playwright test --list`) ⇒ giá trị giả, mọi đăng nhập sẽ lỗi. */
export function loadConfig(): PwConfig {
  if (cached) return cached;
  const file = process.env.MG_PW_CONFIG;
  const c = file ? (JSON.parse(fs.readFileSync(file, "utf8")) as PwConfig) : FALLBACK;
  // MG_PW_EDGE: địa chỉ mà trình duyệt nối tới thay cho edge (bộ chuyển tiếp TCP của harness — playwrightui.py)
  cached = { ...c, edgeIp: process.env.MG_PW_EDGE ?? c.edgeIp };
  return cached;
}

export const cfg = loadConfig();
export const APP = `https://app.${cfg.domain}`;
export const ADMIN = `https://admin.${cfg.domain}`;
export const AUTH_HOST = `auth.${cfg.domain}`;

function stateDir(): string {
  const file = process.env.MG_PW_CONFIG;
  return file ? path.dirname(file) : path.join(process.cwd(), "test-results", "pw-state");
}

/** storage state (cookie phiên __Host-) của một vai trò — viết ở auth.setup.ts, dùng ở các spec. */
export function storageFile(role: Role): string {
  return path.join(stateDir(), `state-${role}.json`);
}

export function originOf(role: Role): string {
  return role === "sa" || role === "sa2" ? ADMIN : APP;
}

// ------------------------------------------------------------------------------------------------ TOTP (RFC 6238)
function hotp(key: string, counter: number): string {
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const mac = createHmac("sha1", Buffer.from(key, "utf8")).update(msg).digest();
  const o = (mac[mac.length - 1] ?? 0) & 0x0f;
  return String((mac.readUInt32BE(o) & 0x7fffffff) % 1_000_000).padStart(6, "0");
}

function counterFile(): string {
  return path.join(stateDir(), "totp-counters.json");
}

function readCounters(): Record<string, number> {
  try {
    return JSON.parse(fs.readFileSync(counterFile(), "utf8")) as Record<string, number>;
  } catch {
    return {};
  }
}

/** Mã TOTP kế tiếp của user với bộ đếm tăng nghiêm ngặt (lưu ra tệp — sống qua các lượt và khi worker khởi động lại);
 * Keycloak nhận cửa sổ hiện tại và kế tiếp — hết cả hai thì chờ sang cửa sổ mới. */
export async function nextTotp(role: Role): Promise<string> {
  const u = cfg.users[role];
  for (;;) {
    const counters = readCounters();
    const last = Math.max(u.totpLast, counters[role] ?? 0);
    const now = Math.floor(Date.now() / 30_000);
    for (const c of [now, now + 1]) {
      if (c > last) {
        fs.writeFileSync(counterFile(), JSON.stringify({ ...counters, [role]: c }), { mode: 0o600 });
        return hotp(u.totpKey, c);
      }
    }
    await new Promise((r) => setTimeout(r, (now + 1) * 30_000 - Date.now() + 500));
  }
}
