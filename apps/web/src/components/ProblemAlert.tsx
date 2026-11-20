// Hiển thị một lỗi API (problem+json) theo `code` ổn định, kèm request id để đối chiếu log/audit. `detail` của server
// không bao giờ chứa secret (§13.1) nên được hiện nguyên văn ở dòng phụ — trừ 403 khi giao diện không phải tiếng Anh
// (G4b-E3): `detail` luôn là tiếng Anh, còn lời từ chối đã có câu dịch theo `code` (+ gợi ý riêng của từng màn hình).
import { useTranslation } from "react-i18next";
import { ApiError } from "../api/problem";

export function ProblemAlert({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  const { t, i18n } = useTranslation();
  // lỗi không phải của API (lỗi lập trình khi render) ⇒ thông báo chung, không lộ thông điệp nội bộ
  const e = error instanceof ApiError ? error : new ApiError({ status: 0, code: "unexpected_response" });
  const fields = e.code === "validation_failed" ? (e.problem?.errors ?? []) : [];
  const detail = e.status === 403 && !i18n.language.startsWith("en") ? undefined : e.problem?.detail;
  return (
    <div role="alert" className="rounded-md border border-danger/40 bg-danger-bg p-4 text-fg">
      <p className="font-semibold text-danger">{t(`problem.${e.code}`)}</p>
      {detail ? <p className="mt-1 text-sm">{detail}</p> : null}
      {e.retryAfter !== null ? (
        <p className="mt-1 text-sm">{t("problem.retryAfter", { count: e.retryAfter })}</p>
      ) : null}
      {fields.length > 0 ? (
        <ul className="mt-2 list-disc ps-5 text-sm">
          {fields.map((f) => (
            <li key={`${f.field}:${f.code}`}>
              <code>{f.field}</code>
              {": "}
              {f.message}
            </li>
          ))}
        </ul>
      ) : null}
      {e.requestId ? (
        <p className="mt-2 text-xs text-muted">
          {t("problem.requestId")} <code>{e.requestId}</code>
        </p>
      ) : null}
      {onRetry ? (
        <button type="button" className="btn-secondary mt-3" onClick={onRetry}>
          {t("common.retry")}
        </button>
      ) : null}
    </div>
  );
}
