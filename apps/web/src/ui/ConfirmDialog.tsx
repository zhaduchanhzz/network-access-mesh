// Xác nhận thao tác phá hủy/nhạy cảm — bản duy nhất (P4-T02 + P4-T04; §12.2 "Xóa: dual control + step-up"): alertdialog
// (React Aria: bẫy focus, Esc, trả focus), focus đầu tiên vào nút an toàn (Hủy) hoặc ô gõ xác nhận, mô tả hậu quả, tùy chọn bắt người dùng GÕ LẠI một giá trị (slug của tenant) trước khi nút xác nhận bật, ô nhập thêm
// (lý do…), lỗi của server hiển thị ngay trong hộp (step-up 401 reauth_required còn có lời nhắc chung ở đầu trang).
// Nút xác nhận chỉ là UX: server mới là nơi quyết định (quyền, 2P, step-up, `confirm_slug`).
import { useId, useState, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { ApiError } from "../api/problem";
import { useStepUp } from "../components/Banners";
import { ProblemAlert } from "../components/ProblemAlert";
import { ModalDialog } from "./Dialog";

export interface ConfirmDialogProps {
  isOpen: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  description: ReactNode;
  confirmLabel: string;
  /** phá hủy (nút đỏ) hay chỉ cần xác nhận */
  destructive?: boolean;
  /** người dùng phải gõ đúng `expected` (phân biệt hoa thường) */
  typedConfirmation?: { expected: string; label: string };
  /** ô nhập/ghi chú thêm (lý do…) */
  children?: ReactNode;
  /** điều kiện thêm của form con (ví dụ lý do không rỗng) */
  canConfirm?: boolean;
  pending?: boolean;
  error?: unknown;
  onConfirm: () => void;
}

export function ConfirmDialog(props: ConfirmDialogProps) {
  const descId = useId();
  return (
    <ModalDialog
      isOpen={props.isOpen}
      onOpenChange={props.onOpenChange}
      title={props.title}
      role="alertdialog"
      busy={props.pending}
      describedBy={descId}
    >
      {/* thân hộp chỉ mount khi mở ⇒ giá trị đã gõ mất khi đóng */}
      <ConfirmBody {...props} descId={descId} />
    </ModalDialog>
  );
}

function ConfirmBody({
  description,
  confirmLabel,
  destructive = false,
  typedConfirmation,
  children,
  canConfirm = true,
  pending = false,
  error,
  onConfirm,
  onOpenChange,
  descId,
}: ConfirmDialogProps & { descId: string }) {
  const { t } = useTranslation();
  const inputId = useId();
  const [typed, setTyped] = useState("");
  const typedOk = !typedConfirmation || typed === typedConfirmation.expected;
  return (
    <form
      className="space-y-3"
      onSubmit={(e) => {
        e.preventDefault();
        if (typedOk && canConfirm && !pending) onConfirm();
      }}
    >
      <div id={descId}>{description}</div>
      {children}
      {typedConfirmation ? (
        <div>
          <label htmlFor={inputId} className="label">
            {typedConfirmation.label}
          </label>
          <input
            id={inputId}
            className="input font-mono"
            // focus đầu tiên vào ô gõ xác nhận (không vào nút phá hủy)
            autoFocus
            autoComplete="off"
            spellCheck={false}
            value={typed}
            aria-invalid={typed !== "" && !typedOk}
            onChange={(e) => {
              setTyped(e.target.value);
            }}
          />
          <p className="hint">{t("confirm.typeHint", { value: typedConfirmation.expected })}</p>
        </div>
      ) : null}
      <DialogProblem error={error} />
      <div className="flex justify-end gap-2 pt-2">
        <button
          type="button"
          className="btn-secondary"
          // alertdialog: focus đầu tiên vào thao tác an toàn khi không có ô gõ xác nhận (WAI-ARIA APG)
          autoFocus={!typedConfirmation}
          disabled={pending}
          onClick={() => {
            onOpenChange(false);
          }}
        >
          {t("ui.cancel")}
        </button>
        <button type="submit" className={destructive ? "btn-danger" : "btn-primary"} disabled={!typedOk || !canConfirm || pending}>
          {pending ? t("common.working") : confirmLabel}
        </button>
      </div>
    </form>
  );
}

/** Lỗi của server trong hộp thoại đang mở + nút xác thực lại khi 401 reauth_required (lời nhắc step-up chung nằm sau
 * lớp modal). Dùng chung cho ConfirmDialog và FormDialog (ui/FormDialog.tsx). */
export function DialogProblem({ error }: { error: unknown }) {
  const { t } = useTranslation();
  const stepUp = useStepUp();
  if (!error) return null;
  return (
    <>
      <ProblemAlert error={error} />
      {error instanceof ApiError && error.code === "reauth_required" ? (
        <button type="button" className="btn-secondary" onClick={stepUp}>
          {t("stepUp.action")}
        </button>
      ) : null}
    </>
  );
}
