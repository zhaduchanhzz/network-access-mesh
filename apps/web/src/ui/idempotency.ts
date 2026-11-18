// Hạ tầng UI dùng chung (P4-T04): `Idempotency-Key` (§13.1) — một khóa cho MỘT ý định của người dùng (mở hộp xác nhận
// → bấm xác nhận), giữ nguyên qua các lần gửi lại của cùng ý định (lỗi mạng, bấm lại sau 409/503) để server trả lại kết
// quả đã lưu thay vì làm lại; ý định mới (hộp xác nhận mở lại, thao tác đã xong) ⇒ khóa mới. Khóa chỉ nằm trong bộ nhớ.
import { useCallback, useRef } from "react";

/** Khóa mới: UUID ngẫu nhiên (khớp pattern `^[\x21-\x7E]+$`, 8–255 ký tự của spec). */
export function newIdempotencyKey(): string {
  return crypto.randomUUID();
}

export interface IdempotencyKey {
  /** khóa của ý định hiện tại (tạo khi gọi lần đầu) */
  current: () => string;
  /** kết thúc ý định: lần gọi `current` sau sẽ tạo khóa mới */
  reset: () => void;
}

export function useIdempotencyKey(): IdempotencyKey {
  const ref = useRef<string | null>(null);
  const current = useCallback(() => {
    ref.current ??= newIdempotencyKey();
    return ref.current;
  }, []);
  const reset = useCallback(() => {
    ref.current = null;
  }, []);
  return { current, reset };
}
