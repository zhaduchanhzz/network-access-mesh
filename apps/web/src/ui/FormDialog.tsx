// Hộp thoại có form (P4-T03: sửa thiết lập, platform user, gói dịch vụ, IdP, thao tác instance có tham số) trên
// ModalDialog dùng chung (ui/Dialog.tsx — React Aria: bẫy focus, Esc, trả focus). Khác ConfirmDialog (alertdialog, focus
// đầu vào nút an toàn): role dialog, focus đầu tiên vào trường đầu của form (autoFocus ở chỗ gọi), nút gửi là submit
// của form. Lỗi server + nút step-up: DialogProblem của ui/ConfirmDialog.tsx (một bản).
import { useId, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { DialogProblem } from "./ConfirmDialog";
import { ModalDialog } from "./Dialog";

export interface FormDialogProps {
  isOpen: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  /** đoạn mô tả hậu quả (aria-describedby) */
  description?: ReactNode;
  submitLabel: string;
  destructive?: boolean;
  /** form hợp lệ phía client (chỉ hướng dẫn — server quyết định) */
  canSubmit?: boolean;
  pending?: boolean;
  error?: unknown;
  onSubmit: () => void;
  /** các trường; chỉ mount khi hộp mở ⇒ nội dung đã gõ mất khi đóng */
  children: ReactNode;
}

export function FormDialog(props: FormDialogProps) {
  const descId = useId();
  return (
    <ModalDialog
      isOpen={props.isOpen}
      onOpenChange={props.onOpenChange}
      title={props.title}
      busy={props.pending}
      describedBy={props.description ? descId : undefined}
    >
      <FormBody {...props} descId={descId} />
    </ModalDialog>
  );
}

function FormBody({ description, submitLabel, destructive = false, canSubmit = true, pending = false, error, onSubmit, onOpenChange, children, descId }: FormDialogProps & { descId: string }) {
  const { t } = useTranslation();
  return (
    <form
      className="space-y-3"
      noValidate
      onSubmit={(e) => {
        e.preventDefault();
        if (canSubmit && !pending) onSubmit();
      }}
    >
      {description ? <div id={descId}>{description}</div> : null}
      {children}
      <DialogProblem error={error} />
      <div className="flex justify-end gap-2 pt-2">
        <button
          type="button"
          className="btn-secondary"
          disabled={pending}
          onClick={() => {
            onOpenChange(false);
          }}
        >
          {t("ui.cancel")}
        </button>
        <button type="submit" className={destructive ? "btn-danger" : "btn-primary"} disabled={!canSubmit || pending}>
          {pending ? t("common.working") : submitLabel}
        </button>
      </div>
    </form>
  );
}
