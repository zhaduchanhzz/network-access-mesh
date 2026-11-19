// Mảnh hiển thị health dùng chung của P4-T03 (instance, thành phần nền tảng, relay): trạng thái + lý do đã dịch (mã ổn
// định của HealthReason — §13.4 quy tắc 5, không bao giờ thông điệp thô) + thời điểm kiểm `checked_at` (§12.2 "Số liệu
// thật, có checked_at"). Chưa từng kiểm ⇒ "chưa từng" — không số giả.
import { useTranslation } from "react-i18next";
import { StatusBadge, useCodeText } from "../../ui/Status";
import { Timestamp } from "../../ui/time";

export interface HealthLike {
  status: "healthy" | "unhealthy" | "unknown";
  checked_at: string | null;
  reason?: string;
}

export function HealthCell({ health, compact = false }: { health: HealthLike; compact?: boolean }) {
  const { t } = useTranslation();
  const code = useCodeText();
  return (
    <div data-testid="health" data-health={health.status}>
      <StatusBadge status={health.status}>{t(`status.health.${health.status}`)}</StatusBadge>
      {health.reason ? (
        <span className="ms-2 text-xs text-muted" data-reason={health.reason}>
          {code("health.reason", health.reason, "health.reasonOther")}
        </span>
      ) : null}
      {compact ? null : (
        <p className="mt-1 text-xs text-muted">
          {t("ui.checkedAt")} <Timestamp iso={health.checked_at} />
        </p>
      )}
    </div>
  );
}
