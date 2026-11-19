// Support Access của tenant (P4-T13, §8.7 bước 2–4): GET /tenants/{t}/support-grants — mọi yêu cầu truy cập hỗ trợ của
// nhân sự nền tảng vào tenant (minh bạch), lọc trạng thái, phân trang con trỏ. Người giữ tenant.support_grant:decide
// (Owner, Admin) duyệt (step-up; chỉ role Support Operator — Support Admin chỉ qua break-glass của hai Super Admin),
// từ chối, thu hồi (kể cả grant break-glass; có hiệu lực ở request kế tiếp của nhân sự). Hành động của nhân sự dưới
// grant nằm ở trang Audit (lọc "support"). Tenant chỉ-đọc ⇒ khóa thao tác ghi (server cũng từ chối).
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Link } from "react-router";
import { api, call } from "../../api/client";
import { useCursorPager } from "../../api/pagination";
import { queryKeys } from "../../api/queryClient";
import { can } from "../../auth/permissions";
import { Page } from "../../components/Page";
import {
  GRANT_PAGE,
  GRANT_STATUSES,
  GrantReason,
  GrantStatusBadge,
  GrantWindow,
  grantOpen,
  isGrantStatus,
  type SupportGrant,
  type SupportGrantStatus,
} from "../../support/grants";
import { ConfirmDialog } from "../../ui/ConfirmDialog";
import { EmptyState, Pager, QueryBlock } from "../../ui/Data";
import { useTenant } from "../TenantScope";

type Decision = "approve" | "reject" | "revoke";

export function SupportAccessPage() {
  const { t } = useTranslation();
  const { tenantId, role, readOnly } = useTenant();
  const [status, setStatus] = useState<SupportGrantStatus | "">("");
  const pager = useCursorPager(status);
  const list = useQuery({
    queryKey: queryKeys.tenant(tenantId, "support-grants", { status, cursor: pager.cursor ?? "" }),
    queryFn: () =>
      call(
        api.GET("/tenants/{tenantId}/support-grants", {
          params: { path: { tenantId }, query: { limit: GRANT_PAGE, status: status || undefined, cursor: pager.cursor } },
        }),
      ),
    placeholderData: (prev) => prev,
  });
  const decider = can(role, "tenant.support_grant:decide") && !readOnly;

  return (
    <Page title={t("nav.tenant.supportAccess")}>
      <p className="mb-2 text-sm text-muted">{t("support.tenantIntro")}</p>
      <p className="mb-4 text-sm">
        <Link to={`/t/${tenantId}/audit?actor_type=support`} className="link">
          {t("support.viewActions")}
        </Link>
      </p>
      {readOnly ? <p className="mb-3 text-sm text-muted">{t("ui.readOnlyActions")}</p> : null}
      <div className="mb-4">
        <label htmlFor="grant-status" className="label">
          {t("support.statusFilter")}
        </label>
        <select
          id="grant-status"
          className="select"
          value={status}
          onChange={(e) => {
            setStatus(isGrantStatus(e.target.value) ? e.target.value : "");
          }}
        >
          <option value="">{t("common.all")}</option>
          {GRANT_STATUSES.map((s) => (
            <option key={s} value={s}>
              {t(`support.status.${s}`)}
            </option>
          ))}
        </select>
      </div>
      <QueryBlock query={list}>
        {(data) =>
          data.items.length === 0 ? (
            <EmptyState>{t("support.empty")}</EmptyState>
          ) : (
            <>
              <div className="overflow-x-auto rounded-lg border border-line bg-surface">
                <table className="data-table">
                  <caption className="sr-only">{t("support.caption")}</caption>
                  <thead>
                    <tr>
                      <th scope="col">{t("support.col.staff")}</th>
                      <th scope="col">{t("support.col.role")}</th>
                      <th scope="col">{t("support.col.reason")}</th>
                      <th scope="col">{t("support.col.window")}</th>
                      <th scope="col">{t("support.col.status")}</th>
                      <th scope="col">{t("support.col.actions")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.items.map((g) => (
                      <tr key={g.id} data-testid="grant-row">
                        <td>
                          {g.grantee.display_name}
                          {g.decided_by ? <span className="hint block">{t("support.decidedBy", { name: g.decided_by.display_name })}</span> : null}
                        </td>
                        <td>{t(`roles.${g.effective_role}`)}</td>
                        <td>
                          <GrantReason grant={g} />
                        </td>
                        <td>
                          <GrantWindow grant={g} />
                        </td>
                        <td>
                          <GrantStatusBadge grant={g} />
                        </td>
                        <td>{decider ? <GrantActions grant={g} /> : null}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <Pager pager={pager} nextCursor={data.next_cursor} label={t("support.pagination")} />
            </>
          )
        }
      </QueryBlock>
    </Page>
  );
}

function GrantActions({ grant: g }: { grant: SupportGrant }) {
  const { t } = useTranslation();
  const { tenantId } = useTenant();
  const queryClient = useQueryClient();
  const [open, setOpen] = useState<Decision | null>(null);
  const path = { params: { path: { tenantId, grantId: g.id } } };
  const decide = useMutation({
    mutationFn: (d: Decision) =>
      d === "approve"
        ? call(api.POST("/tenants/{tenantId}/support-grants/{grantId}/approve", path))
        : d === "reject"
          ? call(api.POST("/tenants/{tenantId}/support-grants/{grantId}/reject", path))
          : call(api.POST("/tenants/{tenantId}/support-grants/{grantId}/revoke", path)),
    onSuccess: async () => {
      setOpen(null);
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: queryKeys.tenant(tenantId, "support-grants") }),
        queryClient.invalidateQueries({ queryKey: queryKeys.tenant(tenantId, "audit") }),
      ]);
    },
  });
  const pending = g.status === "pending";
  const adminRole = g.effective_role === "support_admin";
  return (
    <div className="flex flex-wrap gap-2">
      {pending && !adminRole ? (
        <button
          type="button"
          className="btn-primary"
          onClick={() => {
            setOpen("approve");
          }}
        >
          {t("support.approve")}
        </button>
      ) : null}
      {pending && adminRole ? <span className="hint">{t("support.adminBreakglassOnly")}</span> : null}
      {pending ? (
        <button
          type="button"
          className="btn-secondary"
          onClick={() => {
            setOpen("reject");
          }}
        >
          {t("support.reject")}
        </button>
      ) : null}
      {grantOpen(g) ? (
        <button
          type="button"
          className="btn-danger"
          onClick={() => {
            setOpen("revoke");
          }}
        >
          {t("support.revoke")}
        </button>
      ) : null}
      <ConfirmDialog
        isOpen={open !== null}
        onOpenChange={(o) => {
          if (!o) {
            setOpen(null);
            decide.reset();
          }
        }}
        title={open ? t(`support.confirm.${open}Title`) : ""}
        description={
          <div className="space-y-2">
            <p>{open ? t(`support.confirm.${open}Desc`, { staff: g.grantee.display_name, role: t(`roles.${g.effective_role}`) }) : null}</p>
            <GrantReason grant={g} />
            <GrantWindow grant={g} />
          </div>
        }
        confirmLabel={open ? t(`support.${open}`) : ""}
        destructive={open === "revoke"}
        pending={decide.isPending}
        error={decide.error}
        onConfirm={() => {
          if (open) decide.mutate(open);
        }}
      />
    </div>
  );
}
