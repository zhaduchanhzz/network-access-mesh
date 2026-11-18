// Badge số thông báo chưa đọc (P4-T04): GET /tenants/{t}/notifications?unread=true — đếm trang đầu (tối đa
// UNREAD_PAGE), còn trang sau ⇒ "99+". Poll mỗi phút (§12.4 Realtime: polling ở MVP); chỉ khi role có
// tenant.notification:read (support staff không có — §8.6).
import { useQuery } from "@tanstack/react-query";
import { api, call } from "../../api/client";
import { queryKeys } from "../../api/queryClient";
import type { NavCount } from "../../layout/AppShell";

export const UNREAD_PAGE = 99;
export const UNREAD_POLL_MS = 60_000;

export function unreadKey(tenantId: string) {
  return queryKeys.tenant(tenantId, "notifications", "unread-count");
}

export function useUnreadCount(tenantId: string, enabled: boolean) {
  return useQuery({
    queryKey: unreadKey(tenantId),
    queryFn: async (): Promise<NavCount> => {
      const page = await call(
        api.GET("/tenants/{tenantId}/notifications", {
          params: { path: { tenantId }, query: { unread: true, limit: UNREAD_PAGE } },
        }),
      );
      return { count: page.items.length, more: page.next_cursor !== null };
    },
    enabled,
    refetchInterval: UNREAD_POLL_MS,
  });
}
