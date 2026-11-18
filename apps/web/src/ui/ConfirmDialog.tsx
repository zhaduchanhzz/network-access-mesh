// Hạ tầng UI dùng chung (P4-T04): hộp xác nhận cho thao tác phá hủy/nhạy cảm — modal có ARIA (`role="alertdialog"`,
// `aria-modal`, tiêu đề + mô tả), focus vào nút an toàn (Hủy) khi mở, Tab/Shift+Tab không ra khỏi hộp, Escape = Hủy,
// trả focus về phần tử đã mở hộp khi đóng. Không phụ thuộc thư viện ngoài (cây phụ thuộc của vỏ P4-T01 giữ nhỏ).
import { useEffect, useId, useRef, type KeyboardEvent, type ReactNode } from "react";
import { useTranslation } from "react-i18next";

export interface ConfirmDialogProps {
  open: boolean;
  title: string;
  /** hậu quả của thao tác, nói rõ (§12.4 — không mơ hồ) */
  children: ReactNode;
  confirmLabel: string;
  /** nút xác nhận kiểu nguy hiểm (xóa, thu hồi) */
  destructive?: boolean;
  /** đang gửi: khóa nút xác nhận, Escape/Hủy vẫn dùng được */
  busy?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}

const FOCUSABLE = 'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

export function ConfirmDialog({ open, title, children, confirmLabel, destructive, busy, onConfirm, onCancel }: ConfirmDialogProps) {
  const { t } = useTranslation();
  const titleId = useId();
  const descId = useId();
  const boxRef = useRef<HTMLDivElement>(null);
  const cancelRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    if (!open) return;
    const opener = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    cancelRef.current?.focus();
    return () => {
      opener?.focus();
    };
  }, [open]);

  if (!open) return null;

  const onKeyDown = (e: KeyboardEvent<HTMLDivElement>) => {
    if (e.key === "Escape") {
      e.preventDefault();
      onCancel();
      return;
    }
    if (e.key !== "Tab" || !boxRef.current) return;
    const items = [...boxRef.current.querySelectorAll<HTMLElement>(FOCUSABLE)];
    const first = items[0];
    const last = items[items.length - 1];
    if (!first || !last) return;
    if (e.shiftKey && document.activeElement === first) {
      e.preventDefault();
      last.focus();
    } else if (!e.shiftKey && document.activeElement === last) {
      e.preventDefault();
      first.focus();
    }
  };

  return (
    <div className="fixed inset-0 z-40 flex items-center justify-center bg-black/40 p-4">
      <div
        ref={boxRef}
        role="alertdialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={descId}
        className="w-full max-w-md rounded-lg border border-line bg-surface p-5 text-fg shadow-lg"
        onKeyDown={onKeyDown}
      >
        <h2 id={titleId} className="text-lg font-semibold">
          {title}
        </h2>
        <div id={descId} className="mt-2 space-y-2 text-sm">
          {children}
        </div>
        <div className="mt-5 flex flex-wrap justify-end gap-2">
          <button ref={cancelRef} type="button" className="btn-secondary" onClick={onCancel}>
            {t("ui.cancel")}
          </button>
          <button
            type="button"
            className={destructive ? "btn-danger" : "btn-primary"}
            disabled={busy}
            aria-busy={busy}
            onClick={onConfirm}
          >
            {confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}
