// Hộp thông báo in-portal (P4-T04, §12.3): GET /tenants/{t}/notifications (chỉ thông báo của chính người gọi — §8.6)
// với lọc tất cả/chưa đọc và "tải thêm" theo cursor; POST …/notifications/{id}/read đánh dấu đã đọc (lũy đẳng). Tenant
// chỉ-đọc (suspended) ⇒ nút đánh dấu bị khóa (server cũng trả 403 tenant_suspended).
import { useInfiniteQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { Link, useSearchParams } from "react-router";
import { api, call } from "../../api/client";
import { queryKeys } from "../../api/queryClient";
import type { components } from "../../api/schema";
import { Loading, Page } from "../../components/Page";
import { ProblemAlert } from "../../components/ProblemAlert";
import { StatusBadge } from "../../ui/Status";
import { Timestamp } from "../../ui/time";
import { useTenant } from "../TenantScope";
import { deviceOf, notificationText } from "./notificationText";
import { unreadKey } from "./useUnreadCount";

type Notification = components["schemas"]["Notification"];
export const NOTIFICATION_PAGE = 20;

export function NotificationsPage() {
  const { t, i18n } = useTranslation();
  const { tenantId, readOnly } = useTenant();
  const queryClient = useQueryClient();
  const [params, setParams] = useSearchParams();
  const unreadOnly = params.get("filter") === "unread";

  const list = useInfiniteQuery({
    queryKey: queryKeys.tenant(tenantId, "notifications", "list", { unread: unreadOnly }),
    queryFn: ({ pageParam }) =>
      call(
        api.GET("/tenants/{tenantId}/notifications", {
          params: {
            path: { tenantId },
            query: { limit: NOTIFICATION_PAGE, ...(unreadOnly ? { unread: true } : {}), ...(pageParam ? { cursor: pageParam } : {}) },
          },
        }),
      ),
    initialPageParam: "",
    getNextPageParam: (last) => last.next_cursor ?? undefined,
  });

  const markRead = useMutation({
    mutationFn: (id: string) =>
      call(api.POST("/tenants/{tenantId}/notifications/{notificationId}/read", { params: { path: { tenantId, notificationId: id } } })),
    onSuccess: () =>
      Promise.all([
        queryClient.invalidateQueries({ queryKey: queryKeys.tenant(tenantId, "notifications", "list") }),
        queryClient.invalidateQueries({ queryKey: unreadKey(tenantId) }),
      ]),
  });

  const items: Notification[] = list.data?.pages.flatMap((p) => p.items) ?? [];
  const setFilter = (unread: boolean) => {
    const next = new URLSearchParams(params);
    if (unread) next.set("filter", "unread");
    else next.delete("filter");
    setParams(next, { replace: true });
  };

  return (
    <Page title={t("nav.tenant.notifications")}>
      <div role="group" aria-label={t("notif.filterLabel")} className="mb-4 flex gap-2">
        <button type="button" className={unreadOnly ? "btn-secondary" : "btn-primary"} aria-pressed={!unreadOnly} onClick={() => setFilter(false)}>
          {t("notif.all")}
        </button>
        <button type="button" className={unreadOnly ? "btn-primary" : "btn-secondary"} aria-pressed={unreadOnly} onClick={() => setFilter(true)}>
          {t("notif.unread")}
        </button>
      </div>
      {readOnly ? <p className="mb-3 text-sm text-muted">{t("ui.readOnlyActions")}</p> : null}
      {markRead.isError ? (
        <div className="mb-3">
          <ProblemAlert error={markRead.error} />
        </div>
      ) : null}
      {list.isPending ? <Loading /> : null}
      {list.isError ? <ProblemAlert error={list.error} onRetry={() => void list.refetch()} /> : null}
      {list.isSuccess && items.length === 0 ? (
        <p className="text-muted" data-testid="notif-empty">
          {unreadOnly ? t("notif.emptyUnread") : t("notif.empty")}
        </p>
      ) : null}
      {items.length > 0 ? (
        <ul className="space-y-2" aria-label={t("nav.tenant.notifications")}>
          {items.map((n) => {
            const device = deviceOf(n.kind, n.payload);
            return (
              <li key={n.id} className="card flex flex-wrap items-start justify-between gap-3" data-testid="notification">
                <div className="min-w-0 flex-1">
                  <p className={n.read_at ? "" : "font-semibold"}>{notificationText(t, i18n.language, n.kind, n.payload)}</p>
                  <p className="mt-1 text-xs text-muted">
                    <Timestamp iso={n.created_at} />
                    {" · "}
                    <code>{n.kind}</code>
                  </p>
                  {device ? (
                    <Link to={`/t/${tenantId}/devices/${device}`} className="link mt-1 inline-block text-sm">
                      {t("notif.openDevice")}
                    </Link>
                  ) : null}
                </div>
                <div className="flex items-center gap-2">
                  {n.read_at ? (
                    <StatusBadge tone="neutral">{t("notif.read")}</StatusBadge>
                  ) : (
                    <>
                      <StatusBadge tone="info">{t("notif.new")}</StatusBadge>
                      <button
                        type="button"
                        className="btn-secondary"
                        disabled={readOnly || (markRead.isPending && markRead.variables === n.id)}
                        onClick={() => {
                          markRead.mutate(n.id);
                        }}
                      >
                        {t("notif.markRead")}
                      </button>
                    </>
                  )}
                </div>
              </li>
            );
          })}
        </ul>
      ) : null}
      {list.hasNextPage ? (
        <p className="mt-4">
          <button type="button" className="btn-secondary" disabled={list.isFetchingNextPage} onClick={() => void list.fetchNextPage()}>
            {t("ui.loadMore")}
          </button>
        </p>
      ) : null}
    </Page>
  );
}
