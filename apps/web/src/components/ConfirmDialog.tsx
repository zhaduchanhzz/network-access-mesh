// Xác nhận thao tác phá hủy/nhạy cảm (§12.2 "Xóa: dual control + step-up"; dùng lại ở mọi task UI sau): alertdialog,
// mô tả hậu quả, tùy chọn bắt người dùng GÕ LẠI một giá trị (slug của tenant) trước khi nút xác nhận bật, ô nhập thêm
// (lý do…), lỗi của server hiển thị ngay trong hộp (step-up 401 reauth_required còn có lời nhắc chung ở đầu trang).
// Nút xác nhận chỉ là UX: server mới là nơi quyết định (quyền, 2P, step-up, `confirm_slug`).
import { useId, useState, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { ApiError } from "../api/problem";
import { useStepUp } from "./Banners";
import { ProblemAlert } from "./ProblemAlert";
import { ModalDialog } from "./ui/Dialog";

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
  const stepUp = useStepUp();
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
      {error ? <ProblemAlert error={error} /> : null}
      {error instanceof ApiError && error.code === "reauth_required" ? (
        // lời nhắc step-up chung nằm sau lớp modal: cho xác thực lại ngay từ hộp
        <button type="button" className="btn-secondary" onClick={stepUp}>
          {t("stepUp.action")}
        </button>
      ) : null}
      <div className="flex justify-end gap-2 pt-2">
        <button
          type="button"
          className="btn-secondary"
          disabled={pending}
          onClick={() => {
            onOpenChange(false);
          }}
        >
          {t("common.cancel")}
        </button>
        <button type="submit" className={destructive ? "btn-danger" : "btn-primary"} disabled={!typedOk || !canConfirm || pending}>
          {pending ? t("common.working") : confirmLabel}
        </button>
      </div>
    </form>
  );
}
