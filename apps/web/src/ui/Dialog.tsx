// Hộp thoại modal dùng chung (§4.3 — React Aria Components, §12.4 a11y): bẫy focus, Esc để đóng, nền bị ẩn khỏi cây
// trợ năng (aria-modal), trả focus về nút đã mở khi đóng. Chỉ style bằng class Tailwind (CSP: không style inline do
// thư viện chèn — xem src/styles.css và index.html về usePress).
import type { ReactNode } from "react";
import { Dialog, Heading, Modal, ModalOverlay } from "react-aria-components";

export interface ModalDialogProps {
  isOpen: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  /** alertdialog cho xác nhận thao tác phá hủy/nhạy cảm (WAI-ARIA) */
  role?: "dialog" | "alertdialog";
  /** đang gửi ⇒ không cho đóng bằng Esc/bấm ra ngoài (kết quả chưa về) */
  busy?: boolean;
  /** id của đoạn mô tả (aria-describedby) */
  describedBy?: string;
  children: ReactNode;
}

export function ModalDialog({ isOpen, onOpenChange, title, role = "dialog", busy = false, describedBy, children }: ModalDialogProps) {
  return (
    <ModalOverlay
      isOpen={isOpen}
      onOpenChange={onOpenChange}
      isDismissable={!busy}
      isKeyboardDismissDisabled={busy}
      className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-black/50 p-4 md:items-center"
    >
      <Modal className="w-full max-w-lg rounded-lg border border-line bg-surface text-fg shadow-xl">
        <Dialog role={role} aria-describedby={describedBy} className="p-5 outline-none">
          <Heading slot="title" className="text-lg font-semibold">
            {title}
          </Heading>
          <div className="mt-3 space-y-3 text-sm">{children}</div>
        </Dialog>
      </Modal>
    </ModalOverlay>
  );
}
