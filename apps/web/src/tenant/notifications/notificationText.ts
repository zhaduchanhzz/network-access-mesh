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
  // follow-up P4-T06 (người yêu cầu nhận quyết định) và P4-T12 (T-08: duyệt/gỡ route, exit node)
  "enrollment.approved",
  "enrollment.rejected",
  "route.approved",
  "route.revoked",
] as const;

/** Kind nói về một thiết bị (payload.device_id) — có link "Xem thiết bị". */
const DEVICE_KINDS: ReadonlySet<string> = new Set(["device.new", "device.expiring", "route.approved", "route.revoked"]);

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

/** Quyết định enrollment của nhân viên nền tảng qua Support Access Grant (payload `by_support` — 0028) có câu riêng nói
 * rõ người quyết định là nhân viên hỗ trợ. */
const SUPPORT_DECIDED: ReadonlySet<string> = new Set(["enrollment.approved", "enrollment.rejected"]);

/** Khóa i18n của câu một thông báo đã biết kind. */
export function i18nKeyOf(kind: string, payload: Record<string, unknown>): string {
  const key = i18nKeyOfKind(kind);
  return SUPPORT_DECIDED.has(kind) && payload.by_support === true ? `${key}_support` : key;
}

/** Mô tả tiếng Anh mà nền tảng ghi cho actor hệ thống của IdP (internal/idp/auditsync) — thông báo cũ chưa có `actor_kind`. */
const LEGACY_ACTORS: Readonly<Record<string, string>> = {
  "IdP driver (service account of the realm)": "idp_driver",
  "IdP provisioning identity (platform)": "idp_provisioner",
  "Keycloak administrator (master realm)": "idp_admin",
  "user of the realm": "realm_user",
};

/** Mã actor hệ thống của một thông báo (G4b-E13): `actor_kind` của payload, hoặc suy từ mô tả cũ; null ⇒ actor là người. */
export function systemActorKind(payload: Record<string, unknown>): string | null {
  const k = payload.actor_kind;
  if (typeof k === "string" && /^[a-z][a-z0-9_]{0,63}$/.test(k)) return k;
  const a = payload.actor;
  if (typeof a !== "string") return null;
  const legacy = Object.hasOwn(LEGACY_ACTORS, a) ? LEGACY_ACTORS[a] : undefined;
  if (legacy) return legacy;
  return a.startsWith("Keycloak master: ") ? "idp_admin" : null;
}

/** Câu của thông báo theo ngôn ngữ hiện tại. */
export function notificationText(t: TFunction, lng: string, kind: string, payload: Record<string, unknown>): string {
  const values: Record<string, string> = { kind };
  for (const [k, v] of Object.entries(payload)) values[k] = text(v, lng);
  // actor hệ thống ⇒ nhãn đã dịch theo mã (cùng nhãn với Audit log), không câu tiếng Anh của nền tảng (G4b-E13)
  const actorKind = systemActorKind(payload);
  if (actorKind) values.actor = t(`audit.actorKinds.${actorKind}`, { defaultValue: t("audit.actorKinds.system") });
  values.tenant = text(payload.tenant_name ?? payload.tenant_slug, lng);
  for (const f of ["device_name", "expires_at", "version", "trigger", "staff", "approver", "action", "actor", "role",
    "backup_created_at", "keys_destroy_after", "device_label", "prefixes"]) {
    values[f] ??= "—";
  }
  return KNOWN.has(kind) ? t(i18nKeyOf(kind, payload), values) : t("notif.kinds.unknown", values);
}

/** Thiết bị mà thông báo nói tới (device.*, route.*) — để dẫn tới trang chi tiết; id lạ ⇒ null. */
export function deviceOf(kind: string, payload: Record<string, unknown>): string | null {
  if (!DEVICE_KINDS.has(kind)) return null;
  const id = payload.device_id;
  return typeof id === "string" && isUuid(id) ? id.toLowerCase() : null;
}
