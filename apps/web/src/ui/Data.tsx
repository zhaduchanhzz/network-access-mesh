// Mảnh hiển thị dữ liệu dùng chung (P4-T02, §12.4): JSON thô, trạng thái rỗng, phân trang con trỏ, khối truy vấn (đang tải
// / lỗi / có dữ liệu), cặp nhãn – giá trị. Nhãn trạng thái: ui/Status.tsx; thời điểm: ui/time.tsx.
import type { UseQueryResult } from "@tanstack/react-query";
import type { ReactNode } from "react";
import { useTranslation } from "react-i18next";
import type { CursorPager } from "../api/pagination";
import { Loading } from "../components/Page";
import { ProblemAlert } from "../components/ProblemAlert";

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

/** Trang trước / sau của danh sách con trỏ — cùng nhãn ở Portal và Console (G4b-E18: "Trang trước" / "Trang sau"). */
export function Pager({ pager, nextCursor, label }: { pager: CursorPager; nextCursor: string | null | undefined; label: string }) {
  const { t } = useTranslation();
  if (!pager.hasPrevious && !nextCursor) return null;
  return (
    <nav aria-label={label} className="mt-4 flex items-center justify-between gap-3">
      <button type="button" className="btn-secondary" disabled={!pager.hasPrevious} onClick={pager.previous}>
        {t("ui.prevPage")}
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
        {t("ui.nextPage")}
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
