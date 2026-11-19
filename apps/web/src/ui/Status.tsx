// Hạ tầng UI dùng chung (P4-T04): nhãn trạng thái và khối "không khả dụng kèm lý do" (§12.4: tính năng không có nguồn
// dữ liệu hiển thị "không khả dụng" kèm lý do — không số giả).
import type { ReactNode } from "react";
import { useTranslation } from "react-i18next";

export type Tone = "ok" | "warn" | "danger" | "neutral" | "info";

const TONE: Record<Tone, string> = {
  ok: "badge badge-ok",
  warn: "badge badge-warn",
  danger: "badge badge-danger",
  neutral: "badge",
  info: "badge badge-info",
};

const TONES: Record<string, Tone> = {
  // tenant / instance / relay / approval / job / step / health
  active: "ok",
  running: "ok",
  succeeded: "ok",
  healthy: "ok",
  executed: "ok",
  approved: "ok",
  provisioning: "warn",
  pending: "warn",
  queued: "warn",
  allocated: "warn",
  starting: "warn",
  suspended: "warn",
  compensating: "warn",
  failed_resumable: "danger",
  deprovisioning: "warn",
  failed: "danger",
  unhealthy: "danger",
  quarantined: "danger",
  rejected: "danger",
  deleted: "neutral",
  removed: "neutral",
  stopped: "neutral",
  disabled: "neutral",
  cancelled: "neutral",
  rolled_back: "neutral",
  expired: "neutral",
  skipped: "neutral",
  unknown: "neutral",
  // policy version / áp dụng (P4-T11)
  draft: "neutral",
  validated: "info",
  pending_approval: "warn",
  superseded: "neutral",
  applied: "ok",
  // yêu cầu enrollment (P4-T08)
  requested: "warn",
  issued: "info",
  claimed: "warn",
  registered: "warn",
  verified: "ok",
  consumed: "ok",
  revoked: "neutral",
};

export function toneOf(status: string): Tone {
  return TONES[status] ?? "neutral";
}

/** Nhãn trạng thái: màu chỉ là phụ — chữ luôn nói trạng thái (WCAG 1.4.1). `tone` tường minh, hoặc `status` (giá trị máy
 * của API — chọn tone theo bảng trên và ghi vào data-status). */
export function StatusBadge({ tone, status, children, testId }: { tone?: Tone; status?: string; children: ReactNode; testId?: string }) {
  return (
    <span className={TONE[tone ?? (status === undefined ? "neutral" : toneOf(status))]} data-testid={testId} data-status={status}>
      {children}
    </span>
  );
}

/** Ô "không khả dụng": tiêu đề + lý do đã dịch (+ mã lý do ổn định của API để đối chiếu). */
export function UnavailableBox({ title, reason, code }: { title: string; reason: string; code?: string }) {
  const { t } = useTranslation();
  return (
    <div className="rounded-md border border-dashed border-line bg-surface p-4" data-testid="unavailable-section">
      <p className="font-medium">
        {title}
        {": "}
        <span className="text-muted">{t("ui.unavailable")}</span>
      </p>
      <p className="mt-1 text-sm text-muted">
        {reason}
        {code ? <code className="ms-1">{`(${code})`}</code> : null}
      </p>
    </div>
  );
}

/** Dịch một mã lý do/enum mở của API: khóa `<prefix>.<code>` nếu có, nếu không thì câu chung kèm mã nguyên văn. */
export function useCodeText() {
  const { t, i18n } = useTranslation();
  return (prefix: string, code: string | null | undefined, fallbackKey = "ui.unknownCode"): string => {
    if (!code) return "";
    const key = `${prefix}.${code}`;
    return i18n.exists(key) ? t(key) : t(fallbackKey, { code });
  };
}
