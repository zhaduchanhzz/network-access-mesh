// Giới hạn của gói (PlanLimits — §13.3) và form tạo/sửa gói. checkPlanLimits mirror platform.CheckPlanLimits (Go) /
// CHECK mg_plan_limits_valid của 0012: chỉ các khóa của PlanLimits; max_* số nguyên 0…2³¹−1; backup_interval_minutes
// 1…2³¹−1; instance {cpus 0 < n ≤ 1024, memory_mb / pids 1…2³¹−1}; gói đầy đủ (partial = false) bắt buộc bốn khóa quota.
// Trả về trường đầu tiên có lỗi ("" = hợp lệ) — cùng tên trường mà 422 của server nêu. Chỉ hướng dẫn; server quyết định.
import type { components } from "../../api/schema";

type PlanLimits = components["schemas"]["PlanLimits"];

export const QUOTA_KEYS = ["max_devices", "max_users", "max_tagged_devices", "max_live_enrollment_credentials"] as const;
const INT_MAX = 2147483647;

function isInt(v: unknown, lo: number): boolean {
  return typeof v === "number" && Number.isInteger(v) && v >= lo && v <= INT_MAX;
}

export function checkPlanLimits(limits: unknown, partial: boolean): string {
  if (typeof limits !== "object" || limits === null || Array.isArray(limits)) return "limits";
  const m = limits as Record<string, unknown>;
  if (!partial) for (const k of QUOTA_KEYS) if (!(k in m)) return `limits.${k}`;
  for (const [k, v] of Object.entries(m)) {
    if ((QUOTA_KEYS as readonly string[]).includes(k)) {
      if (!isInt(v, 0)) return `limits.${k}`;
    } else if (k === "backup_interval_minutes") {
      if (!isInt(v, 1)) return `limits.${k}`;
    } else if (k === "instance") {
      if (typeof v !== "object" || v === null || Array.isArray(v)) return "limits.instance";
      for (const [ik, iv] of Object.entries(v as Record<string, unknown>)) {
        if (ik === "cpus") {
          if (typeof iv !== "number" || !Number.isFinite(iv) || iv <= 0 || iv > 1024) return "limits.instance.cpus";
        } else if (ik === "memory_mb" || ik === "pids") {
          if (!isInt(iv, 1)) return `limits.instance.${ik}`;
        } else return `limits.instance.${ik}`;
      }
    } else return `limits.${k}`;
  }
  return "";
}

/** Các ô của form: chuỗi đã gõ, trống = không đặt khóa đó. */
export interface LimitsForm {
  max_devices: string;
  max_users: string;
  max_tagged_devices: string;
  max_live_enrollment_credentials: string;
  backup_interval_minutes: string;
  cpus: string;
  memory_mb: string;
  pids: string;
}

export const LIMIT_FIELDS = [...QUOTA_KEYS, "backup_interval_minutes", "cpus", "memory_mb", "pids"] as const satisfies readonly (keyof LimitsForm)[];

export function limitsFormOf(l: PlanLimits | undefined): LimitsForm {
  const s = (v: number | undefined) => (v === undefined ? "" : String(v));
  return {
    max_devices: s(l?.max_devices),
    max_users: s(l?.max_users),
    max_tagged_devices: s(l?.max_tagged_devices),
    max_live_enrollment_credentials: s(l?.max_live_enrollment_credentials),
    backup_interval_minutes: s(l?.backup_interval_minutes),
    cpus: s(l?.instance?.cpus),
    memory_mb: s(l?.instance?.memory_mb),
    pids: s(l?.instance?.pids),
  };
}

/** Số đã gõ (số thập phân cho cpus, nguyên cho phần còn lại); không phải số ⇒ NaN (checkPlanLimits báo đúng trường). */
function num(raw: string, decimal: boolean): number {
  const v = raw.trim();
  if (decimal ? !/^\d+(\.\d+)?$/.test(v) : !/^\d+$/.test(v)) return Number.NaN;
  return Number(v);
}

/** Form ⇒ PlanLimits (bỏ ô trống). */
export function limitsOf(f: LimitsForm): PlanLimits {
  const out: PlanLimits = {};
  for (const k of [...QUOTA_KEYS, "backup_interval_minutes"] as const) if (f[k].trim() !== "") out[k] = num(f[k], false);
  const inst: Record<string, number> = {};
  if (f.cpus.trim() !== "") inst.cpus = num(f.cpus, true);
  if (f.memory_mb.trim() !== "") inst.memory_mb = num(f.memory_mb, false);
  if (f.pids.trim() !== "") inst.pids = num(f.pids, false);
  if (Object.keys(inst).length > 0) out.instance = inst;
  return out;
}

/** Trường lỗi của checkPlanLimits ⇒ ô của form ("limits.instance.cpus" ⇒ "cpus"). */
export function fieldOfLimitError(path: string): keyof LimitsForm | "limits" {
  const last = path.split(".").pop() ?? "";
  return (LIMIT_FIELDS as readonly string[]).includes(last) ? (last as keyof LimitsForm) : "limits";
}
