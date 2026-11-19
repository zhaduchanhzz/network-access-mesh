// Phân trang con trỏ (§13.1): `?limit=&cursor=<opaque>`, response `{items, next_cursor}`. Con trỏ chỉ đi tới; để
// "trang trước" client giữ ngăn xếp con trỏ đã đi qua. Đổi bộ lọc ⇒ về trang đầu.
import { useState } from "react";

export interface CursorPager {
  /** con trỏ của trang đang xem (undefined = trang đầu) */
  cursor: string | undefined;
  /** số thứ tự trang, từ 1 */
  page: number;
  hasPrevious: boolean;
  next: (nextCursor: string) => void;
  previous: () => void;
}

/** `resetKey`: chuỗi của bộ lọc hiện tại — đổi ⇒ quay về trang đầu (không cần effect). */
export function useCursorPager(resetKey: string): CursorPager {
  const [state, setState] = useState<{ key: string; stack: string[] }>({ key: resetKey, stack: [] });
  const stack = state.key === resetKey ? state.stack : [];
  return {
    cursor: stack.at(-1),
    page: stack.length + 1,
    hasPrevious: stack.length > 0,
    next: (nextCursor) => {
      setState({ key: resetKey, stack: [...stack, nextCursor] });
    },
    previous: () => {
      setState({ key: resetKey, stack: stack.slice(0, -1) });
    },
  };
}
