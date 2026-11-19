// Mô hình của màn hình enrollment (P4-T08, §7.4, §12.3): type sinh từ api/openapi.yaml (P4-T06), các mẫu kiểm định dạng
// phía client (chỉ hướng dẫn — server quyết định), tập trạng thái và lý do xung đột ổn định (Problem.errors[0].code của
// 409 — P4-T08). Không giữ secret nào ở đây: pre-auth key, mã enrollment và Auth ID chỉ sống trong state của một màn hình.
import { ApiError } from "../../api/problem";
import { queryKeys } from "../../api/queryClient";
import type { components } from "../../api/schema";

type S = components["schemas"];
export type EnrollmentRequest = S["EnrollmentRequest"];
export type EnrollmentIssue = S["EnrollmentIssue"];
export type EnrollmentCredential = S["EnrollmentCredential"];
export type EnrollmentInstructions = S["EnrollmentInstructions"];
export type EnrollmentOS = S["EnrollmentOS"];
export type EnrollmentStatus = S["EnrollmentRequestStatus"];
export type EnrollmentMethod = S["EnrollmentMethod"];

export const ENROLL_OS: readonly EnrollmentOS[] = ["linux", "windows", "macos", "ios", "android"];
export const MOBILE_OS: ReadonlySet<EnrollmentOS> = new Set<EnrollmentOS>(["ios", "android"]);

export const ENROLLMENT_STATUSES: readonly EnrollmentStatus[] = [
  "requested",
  "pending_approval",
  "approved",
  "rejected",
  "issued",
  "claimed",
  "registered",
  "verified",
  "consumed",
  "expired",
  "revoked",
  "failed",
];
const FINAL: ReadonlySet<EnrollmentStatus> = new Set<EnrollmentStatus>(["rejected", "verified", "consumed", "expired", "revoked", "failed"]);
/** Yêu cầu còn chờ thiết bị (mã/key đã phát) hoặc đang đăng ký — màn hình poll tới khi kết thúc. */
const WAITING: ReadonlySet<EnrollmentStatus> = new Set<EnrollmentStatus>(["issued", "claimed", "registered"]);
/** Thu hồi được (server: yêu cầu chưa kết thúc và không ở giữa một lần claim — 409 claim_in_progress). */
const REVOCABLE: ReadonlySet<EnrollmentStatus> = new Set<EnrollmentStatus>(["requested", "pending_approval", "approved", "issued"]);

export const isFinal = (s: EnrollmentStatus) => FINAL.has(s);
export const isWaiting = (s: EnrollmentStatus) => WAITING.has(s);
export const isRevocable = (s: EnrollmentStatus) => REVOCABLE.has(s);

/** Auth ID của Headscale (ID-05) — cùng mẫu với schema `EnrollmentClaim` và regex của edge v10 (P4-T07). */
export const AUTH_ID_RE = /^hskey-authreq-[A-Za-z0-9_-]{24}$/;
const AUTH_ID_ANYWHERE = /(?:^|[^A-Za-z0-9_-])(hskey-authreq-[A-Za-z0-9_-]{24})(?![A-Za-z0-9_-])/g;
/** Nhãn thiết bị = tên node (DNS label) — `device_label` của spec. */
export const DEVICE_LABEL_RE = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;
export const TTL_MAX = 15;

/** Poll của màn hình enrollment: bucket rate limit `enrollment` của API là 5 request + 1 request/5 s cho mỗi danh tính
 * (internal/httpapi/ratelimit.go) — dùng chung cho mọi tab của cùng người, kể cả lần claim. Một yêu cầu 10 s, danh sách
 * 15 s, và chỉ một nguồn poll trên mỗi màn hình (danh sách không poll khi khung lệnh vừa phát đang theo dõi). */
export const ENROLL_POLL_MS = 10_000;
export const LIST_POLL_MS = 15_000;

export type PasteResult = { ok: true; authId: string } | { ok: false; reason: "none" | "several" | "other_server" };

/**
 * Tách Auth ID từ thứ người dùng dán (phương án lùi của P4-T07 §4): chính Auth ID, link `/register/<auth_id>` mà client
 * in ra, hoặc link trang claim (`…/enroll/claim?tenant=…&auth_id=…`). Link của control plane khác `loginServer`, hoặc link
 * claim của tenant khác `tenantSlug` (khi biết), bị từ chối — Auth ID của tenant khác không được gửi tới tenant này.
 */
export function extractAuthId(text: string, ctx: { loginServer?: string | null; tenantSlug?: string | null } = {}): PasteResult {
  const input = text.trim();
  if (AUTH_ID_RE.test(input)) return { ok: true, authId: input };
  const found = new Set([...input.matchAll(AUTH_ID_ANYWHERE)].map((m) => m[1] ?? ""));
  if (found.size === 0) return { ok: false, reason: "none" };
  if (found.size > 1) return { ok: false, reason: "several" };
  const authId = [...found][0] ?? "";
  const url = parseUrl(input);
  if (url) {
    const expected = ctx.loginServer ? parseUrl(ctx.loginServer)?.host.toLowerCase() : undefined;
    if (expected && url.pathname.startsWith("/register/") && url.host.toLowerCase() !== expected) return { ok: false, reason: "other_server" };
    const slug = url.searchParams.get("tenant");
    if (ctx.tenantSlug && url.pathname.endsWith("/enroll/claim") && slug !== null && slug !== ctx.tenantSlug) return { ok: false, reason: "other_server" };
  }
  return { ok: true, authId };
}

function parseUrl(s: string): URL | null {
  try {
    return new URL(s);
  } catch {
    return null;
  }
}

/** Lý do ổn định của một 409 / 422 (Problem.errors[0].code — P4-T08), hoặc null. */
export function problemReason(error: unknown, code: "conflict" | "validation_failed" = "conflict"): string | null {
  if (!(error instanceof ApiError) || error.code !== code) return null;
  return error.problem?.errors?.[0]?.code ?? null;
}

/** Yêu cầu của chính người gọi (người tạo, hoặc chủ thiết bị của key do người khác phát). */
export function isMine(r: EnrollmentRequest, membershipId: string | null): boolean {
  return membershipId !== null && (r.requested_by_membership_id === membershipId || r.target_membership_id === membershipId);
}

/** Yêu cầu web-auth của chính người gọi đang chờ thiết bị (claim chỉ nhận yêu cầu này — §7.4 bước 6). */
export function pendingWebAuth(items: readonly EnrollmentRequest[], membershipId: string | null, now: number): EnrollmentRequest[] {
  return items.filter(
    (r) =>
      r.method === "web_auth" &&
      r.status === "issued" &&
      r.requested_by_membership_id === membershipId &&
      (r.credential_expires_at === null || r.credential_expires_at === undefined || Date.parse(r.credential_expires_at) > now),
  );
}

/** Hệ điều hành của trình duyệt này (chỉ là lựa chọn mặc định của wizard). */
export function guessOS(userAgent: string): EnrollmentOS {
  if (/iPhone|iPad|iPod/i.test(userAgent)) return "ios";
  if (/Android/i.test(userAgent)) return "android";
  if (/Windows/i.test(userAgent)) return "windows";
  if (/Mac OS X|Macintosh/i.test(userAgent)) return "macos";
  return "linux";
}

export const enrollmentKeys = {
  all: (tenantId: string) => queryKeys.tenant(tenantId, "enrollment"),
  list: (tenantId: string, f: Record<string, unknown> = {}) => queryKeys.tenant(tenantId, "enrollment", "list", f),
  one: (tenantId: string, id: string) => queryKeys.tenant(tenantId, "enrollment", "request", id),
  instructions: (tenantId: string, os: EnrollmentOS) => queryKeys.tenant(tenantId, "enrollment", "instructions", os),
};
