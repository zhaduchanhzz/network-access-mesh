// Mảnh hiển thị dữ liệu dùng chung (§12.4): nhãn trạng thái (chữ + màu, không chỉ màu), thời điểm theo locale, JSON
// thô, trạng thái rỗng, phân trang con trỏ, khối truy vấn (đang tải / lỗi / rỗng / có dữ liệu).
import type { UseQueryResult } from "@tanstack/react-query";
import type { ReactNode } from "react";
import { useTranslation } from "react-i18next";
import type { CursorPager } from "../api/pagination";
import { formatDateTime } from "../i18n";
import { Loading } from "./Page";
import { ProblemAlert } from "./ProblemAlert";

export type Tone = "ok" | "warn" | "danger" | "neutral";

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
};

export function toneOf(status: string): Tone {
  return TONES[status] ?? "neutral";
}

/** Nhãn trạng thái: `label` đã dịch; `status` (giá trị máy) chỉ chọn màu và nằm trong data-status cho test. */
export function StatusBadge({ status, label }: { status: string; label: string }) {
  return (
    <span className={`badge badge-${toneOf(status)}`} data-status={status}>
      {label}
    </span>
  );
}

/** Thời điểm theo ngôn ngữ đang chọn; `null` ⇒ "—". */
export function DateTime({ value }: { value: string | null | undefined }) {
  const { i18n, t } = useTranslation();
  if (!value) return <span className="text-muted">{t("common.none")}</span>;
  return <time dateTime={value}>{formatDateTime(value, i18n.language)}</time>;
}

/** JSON thô (đã redaction ở server), có thanh cuộn bàn phím được; tiêu đề hiển thị nằm ở chỗ gọi. */
export function JsonBlock({ value }: { value: unknown }) {
  return (
    <pre
      tabIndex={0}
      className="max-h-80 overflow-auto rounded-md border border-line bg-bg p-3 font-mono text-xs whitespace-pre-wrap break-all"
    >
      {JSON.stringify(value, null, 2)}
    </pre>
  );
}

export function EmptyState({ children }: { children: ReactNode }) {
  return (
    <div className="rounded-md border border-dashed border-line bg-surface p-6 text-sm text-muted" data-testid="empty">
      {children}
    </div>
  );
}

/** Trang trước / sau của danh sách con trỏ. */
export function Pager({ pager, nextCursor, label }: { pager: CursorPager; nextCursor: string | null | undefined; label: string }) {
  const { t } = useTranslation();
  if (!pager.hasPrevious && !nextCursor) return null;
  return (
    <nav aria-label={label} className="mt-4 flex items-center justify-between gap-3">
      <button type="button" className="btn-secondary" disabled={!pager.hasPrevious} onClick={pager.previous}>
        {t("common.previous")}
      </button>
      <span className="text-sm text-muted">{t("common.page", { page: pager.page })}</span>
      <button
        type="button"
        className="btn-secondary"
        disabled={!nextCursor}
        onClick={() => {
          if (nextCursor) pager.next(nextCursor);
        }}
      >
        {t("common.next")}
      </button>
    </nav>
  );
}

/** Khối hiển thị một query: đang tải ⇒ Loading, lỗi ⇒ ProblemAlert (nút thử lại), có dữ liệu ⇒ children(data). */
export function QueryBlock<T>({ query, children }: { query: UseQueryResult<T>; children: (data: T) => ReactNode }) {
  if (query.isPending) return <Loading />;
  if (query.isError) return <ProblemAlert error={query.error} onRetry={() => void query.refetch()} />;
  return <>{children(query.data)}</>;
}

/** Cặp nhãn – giá trị (dl). */
export function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="min-w-0">
      <dt className="text-xs font-semibold tracking-wide text-muted uppercase">{label}</dt>
      <dd className="mt-0.5 break-words">{children}</dd>
    </div>
  );
}
