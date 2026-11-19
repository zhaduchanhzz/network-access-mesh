// Câu chữ của một thông báo in-portal (P4-T04): API chỉ trả `kind` + `payload` (id, tên, thời điểm — không secret,
// §13.2); Portal dựng câu theo `kind` và ngôn ngữ của người dùng. Giá trị payload là dữ liệu: React escape khi hiển thị;
// thời điểm RFC 3339 được định dạng theo locale; kind lạ ⇒ câu chung kèm mã kind.
import type { TFunction } from "i18next";
import { isUuid } from "../../api/queryClient";
import { formatDateTime } from "../../i18n";

/** Kind có câu riêng (thông báo phạm vi tenant của P3-T05b — internal/notifications/event.go). */
export const NOTIFICATION_KINDS = [
  "tenant.activated",
  "tenant.invitation",
  "tenant.suspended",
  "tenant.resumed",
  "tenant.deleted",
  "device.new",
  "device.expiring",
  "policy.applied",
  "support.grant_requested",
  "support.break_glass",
  "support.grant_used",
  "approval.requested",
  "idp.admin_change",
  "instance.restored",
  // follow-up P4-T06: người yêu cầu nhận quyết định về yêu cầu enrollment
  "enrollment.approved",
  "enrollment.rejected",
] as const;

const KNOWN: ReadonlySet<string> = new Set(NOTIFICATION_KINDS);
const RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/;
const MAX_VALUE = 120;

export function i18nKeyOfKind(kind: string): string {
  return `notif.kinds.${kind.replaceAll(".", "_")}`;
}

function text(v: unknown, lng: string): string {
  if (typeof v === "string") {
    const s = RFC3339.test(v) ? formatDateTime(v, lng) : v;
    return s.length > MAX_VALUE ? `${s.slice(0, MAX_VALUE)}…` : s;
  }
  if (typeof v === "number" || typeof v === "boolean") return String(v);
  return "—";
}

/** Câu của thông báo theo ngôn ngữ hiện tại. */
export function notificationText(t: TFunction, lng: string, kind: string, payload: Record<string, unknown>): string {
  const values: Record<string, string> = { kind };
  for (const [k, v] of Object.entries(payload)) values[k] = text(v, lng);
  values.tenant = text(payload.tenant_name ?? payload.tenant_slug, lng);
  for (const f of ["device_name", "expires_at", "version", "trigger", "staff", "approver", "action", "actor", "role",
    "backup_created_at", "keys_destroy_after", "device_label"]) {
    values[f] ??= "—";
  }
  return KNOWN.has(kind) ? t(i18nKeyOfKind(kind), values) : t("notif.kinds.unknown", values);
}

/** Thiết bị mà thông báo nói tới (device.new, device.expiring) — để dẫn tới trang chi tiết; id lạ ⇒ null. */
export function deviceOf(kind: string, payload: Record<string, unknown>): string | null {
  if (kind !== "device.new" && kind !== "device.expiring") return null;
  const id = payload.device_id;
  return typeof id === "string" && isUuid(id) ? id.toLowerCase() : null;
}
