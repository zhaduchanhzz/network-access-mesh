// Idempotency-Key (§13.1): bắt buộc cho POST tạo tài nguyên/job và cho thao tác 2P. Server lưu theo
// (tenant, identity, operation, key) 24 giờ: cùng key + cùng nội dung ⇒ trả lại kết quả đã lưu (thử lại an toàn sau lỗi
// mạng hoặc 409 "đang xử lý"); cùng key + khác nội dung ⇒ 422 idempotency_key_reuse.
//
// Quy tắc phía client: MỘT khóa cho MỘT ý định của người dùng —
//   - lần gửi lại cùng nội dung (bấm lại sau lỗi mạng/429/503/409 đang xử lý) dùng lại đúng khóa đó;
//   - nội dung đổi (người dùng sửa form sau lỗi) ⇒ khóa mới;
//   - thao tác đã thành công ⇒ lần bấm sau là ý định mới ⇒ khóa mới.
// Khóa sinh lúc gửi (trong mutationFn), không lúc render; chỉ nằm trong bộ nhớ của trang (không Web Storage).
import { useMutation, type UseMutationOptions } from "@tanstack/react-query";
import { useCallback, useRef, useState } from "react";

/** Khóa mới: UUID v4 (36 ký tự ASCII in được — khớp `^[\x21-\x7E]+$`, 8–255 của spec). */
export function newIdempotencyKey(): string {
  return crypto.randomUUID();
}

/** Bộ giữ khóa của một thao tác (một nút/một form). */
export class IdempotencyKeys {
  private fingerprint: string | null = null;
  private key = "";

  /** Khóa cho nội dung `fingerprint` (thường là JSON của body + tham số path): cùng nội dung ⇒ cùng khóa. */
  keyFor(fingerprint: string): string {
    if (fingerprint !== this.fingerprint) {
      this.fingerprint = fingerprint;
      this.key = newIdempotencyKey();
    }
    return this.key;
  }

  /** Thao tác đã có kết quả cuối (2xx): lần gửi sau là một ý định mới. */
  settle(): void {
    this.fingerprint = null;
  }
}

/** Biến thể tường minh (P4-T04): `current()` = khóa của ý định đang mở (tạo khi gọi lần đầu), `reset()` khi ý định kết
 * thúc (thành công, hộp xác nhận đóng). */
export interface IdempotencyKey {
  current: () => string;
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

export function useIdempotencyKeys(): IdempotencyKeys {
  const [keys] = useState(() => new IdempotencyKeys());
  return keys;
}

/** Chuỗi ổn định của biến của mutation (khóa object sắp xếp) — dùng làm fingerprint mặc định. */
export function fingerprintOf(value: unknown): string {
  return JSON.stringify(value, (_k, v: unknown) =>
    v !== null && typeof v === "object" && !Array.isArray(v)
      ? Object.fromEntries(Object.entries(v as Record<string, unknown>).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)))
      : v,
  );
}

type Options<TData, TVars> = Omit<UseMutationOptions<TData, Error, TVars>, "mutationFn"> & {
  /** gọi API với Idempotency-Key đã chọn cho biến này */
  mutationFn: (vars: TVars, idempotencyKey: string) => Promise<TData>;
  /** nội dung quyết định khóa (mặc định: toàn bộ biến) */
  fingerprint?: (vars: TVars) => string;
};

/** useMutation + Idempotency-Key theo quy tắc ở đầu file. */
export function useIdempotentMutation<TData, TVars>({ mutationFn, fingerprint, onSuccess, ...rest }: Options<TData, TVars>) {
  const keys = useIdempotencyKeys();
  return useMutation<TData, Error, TVars>({
    ...rest,
    mutationFn: (vars) => mutationFn(vars, keys.keyFor((fingerprint ?? fingerprintOf)(vars))),
    onSuccess: (...args) => {
      keys.settle();
      return onSuccess?.(...args);
    },
  });
}
