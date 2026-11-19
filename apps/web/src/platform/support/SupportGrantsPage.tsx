// Support Access phía nền tảng (P4-T13, §8.7; chỉ trên admin.): GET /platform/support-grants — mọi grant (metadata);
// nhân sự xin truy cập một tenant (POST, Idempotency-Key, step-up: tenant, role hiệu lực, lý do, ticket, thời lượng ≤ 8
// giờ) — tenant phải duyệt trong Portal của họ; break-glass (Super Admin THỨ HAI duyệt khi không liên lạc được tenant —
// security_event mức cao + thông báo Owner; người xin không tự duyệt được, server từ chối 403); Super Admin thu hồi
// grant bất kỳ. Grant đang hiệu lực của chính người gọi mở tenant ở /t/:tenantId (session.support_grants — §8.3 bước 8).
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Link } from "react-router";
import { api, call } from "../../api/client";
import { useIdempotentMutation } from "../../api/idempotency";
import { useCursorPager } from "../../api/pagination";
import { queryKeys } from "../../api/queryClient";
import { can } from "../../auth/permissions";
import { useSession } from "../../auth/session";
import { Page } from "../../components/Page";
import { ProblemAlert } from "../../components/ProblemAlert";
import {
  GRANT_DURATIONS,
  GRANT_PAGE,
  GRANT_ROLES,
  GRANT_STATUSES,
  GrantReason,
  GrantStatusBadge,
  GrantWindow,
  grantOpen,
  isGrantStatus,
  type SupportGrant,
  type SupportGrantCreate,
  type SupportGrantRole,
  type SupportGrantStatus,
} from "../../support/grants";
import { ConfirmDialog } from "../../ui/ConfirmDialog";
import { EmptyState, Pager, QueryBlock } from "../../ui/Data";
import { useTenantList } from "../api";
import { usePlatformRole } from "../PlatformScope";

const supportKey = (...rest: (string | Record<string, unknown>)[]) => queryKeys.platform("support-grants", ...rest);

export function SupportGrantsPage() {
  const { t } = useTranslation();
  const role = usePlatformRole();
  const [status, setStatus] = useState<SupportGrantStatus | "">("");
  const pager = useCursorPager(status);
  const list = useQuery({
    queryKey: supportKey({ status, cursor: pager.cursor ?? "" }),
    queryFn: () =>
      call(api.GET("/platform/support-grants", { params: { query: { limit: GRANT_PAGE, status: status || undefined, cursor: pager.cursor } } })),
    placeholderData: (prev) => prev,
  });
  return (
    <Page title={t("nav.platform.supportAccess")}>
      <p className="mb-4 text-sm text-muted">{t("support.platformIntro")}</p>
      {can(role, "platform.support_grant:request") ? <RequestForm /> : null}
      <div className="my-4">
        <label htmlFor="pgrant-status" className="label">
          {t("support.statusFilter")}
        </label>
        <select
          id="pgrant-status"
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
                      <th scope="col">{t("support.col.tenant")}</th>
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
                          <Link to={`/platform/tenants/${g.tenant_id}`} className="link font-mono text-xs">
                            {g.tenant_slug}
                          </Link>
                        </td>
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
                        <td>
                          <PlatformGrantActions grant={g} />
                        </td>
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

function RequestForm() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [q, setQ] = useState("");
  const tenants = useTenantList({ q: q || undefined });
  const [tenantId, setTenantId] = useState("");
  const [role, setRole] = useState<SupportGrantRole>("support_operator");
  const [reason, setReason] = useState("");
  const [ticket, setTicket] = useState("");
  const [minutes, setMinutes] = useState<number>(60);
  const options = (tenants.data?.items ?? []).filter((x) => x.status === "active" || x.status === "suspended");
  const valid = tenantId !== "" && reason.trim() !== "" && reason.length <= 1000 && ticket.trim() !== "" && ticket.length <= 200 && !/[\n\t]/.test(ticket);
  const create = useIdempotentMutation({
    mutationFn: (body: SupportGrantCreate, key: string) =>
      call(api.POST("/platform/support-grants", { params: { header: { "Idempotency-Key": key } }, body })),
    onSuccess: async () => {
      setReason("");
      setTicket("");
      await queryClient.invalidateQueries({ queryKey: supportKey() });
    },
  });
  return (
    <section aria-labelledby="grant-request" className="card space-y-3">
      <h2 id="grant-request" className="text-lg font-semibold">
        {t("support.requestTitle")}
      </h2>
      <p className="text-sm text-muted">{t("support.requestIntro")}</p>
      <form
        className="grid gap-3 sm:grid-cols-2"
        onSubmit={(e) => {
          e.preventDefault();
          if (valid) {
            create.mutate({ tenant_id: tenantId, effective_role: role, reason: reason.trim(), ticket_ref: ticket.trim(), duration_minutes: minutes });
          }
        }}
      >
        <div>
          <label htmlFor="grant-tenant-q" className="label">
            {t("support.tenantSearch")}
          </label>
          <input id="grant-tenant-q" className="input" value={q} onChange={(e) => { setQ(e.target.value.trim()); }} />
        </div>
        <div>
          <label htmlFor="grant-tenant" className="label">
            {t("support.col.tenant")}
          </label>
          <select id="grant-tenant" className="select" value={tenantId} onChange={(e) => { setTenantId(e.target.value); }}>
            <option value="">{t("support.chooseTenant")}</option>
            {options.map((x) => (
              <option key={x.id} value={x.id}>
                {`${x.slug} — ${x.name}`}
              </option>
            ))}
          </select>
        </div>
        <div>
          <label htmlFor="grant-role" className="label">
            {t("support.col.role")}
          </label>
          <select id="grant-role" className="select" value={role} onChange={(e) => { setRole(e.target.value === "support_admin" ? "support_admin" : "support_operator"); }}>
            {GRANT_ROLES.map((r) => (
              <option key={r} value={r}>
                {t(`roles.${r}`)}
              </option>
            ))}
          </select>
          {role === "support_admin" ? <p className="hint">{t("support.adminBreakglassOnly")}</p> : null}
        </div>
        <div>
          <label htmlFor="grant-duration" className="label">
            {t("support.duration")}
          </label>
          <select id="grant-duration" className="select" value={minutes} onChange={(e) => { setMinutes(Number(e.target.value)); }}>
            {GRANT_DURATIONS.map((m) => (
              <option key={m} value={m}>
                {t("support.minutes", { count: m })}
              </option>
            ))}
          </select>
        </div>
        <div>
          <label htmlFor="grant-ticket" className="label">
            {t("support.ticket")}
          </label>
          <input id="grant-ticket" className="input font-mono" maxLength={200} value={ticket} onChange={(e) => { setTicket(e.target.value); }} />
        </div>
        <div className="sm:col-span-2">
          <label htmlFor="grant-reason" className="label">
            {t("support.reason")}
          </label>
          <textarea id="grant-reason" className="input" rows={3} maxLength={1000} value={reason} onChange={(e) => { setReason(e.target.value); }} />
        </div>
        <div className="space-y-2 sm:col-span-2">
          {create.isError ? <ProblemAlert error={create.error} /> : null}
          {create.isSuccess ? <p role="status">{t("support.requested")}</p> : null}
          <p className="hint">{t("support.stepUpNote")}</p>
          <button type="submit" className="btn-primary" disabled={!valid || create.isPending}>
            {create.isPending ? t("common.working") : t("support.request")}
          </button>
        </div>
      </form>
    </section>
  );
}

function PlatformGrantActions({ grant: g }: { grant: SupportGrant }) {
  const { t } = useTranslation();
  const role = usePlatformRole();
  const session = useSession().data;
  const queryClient = useQueryClient();
  const [open, setOpen] = useState<"breakglass" | "revoke" | null>(null);
  const act = useMutation({
    mutationFn: (a: "breakglass" | "revoke") =>
      a === "breakglass"
        ? call(api.POST("/platform/support-grants/{grantId}/approve-breakglass", { params: { path: { grantId: g.id } } }))
        : call(api.POST("/platform/support-grants/{grantId}/revoke", { params: { path: { grantId: g.id } } })),
    onSuccess: async () => {
      setOpen(null);
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: supportKey() }),
        queryClient.invalidateQueries({ queryKey: queryKeys.session() }),
      ]);
    },
  });
  const mine = session?.support_grants.some((s) => s.id === g.id) ?? false;
  return (
    <div className="flex flex-wrap gap-2">
      {g.active && mine ? (
        <Link to={`/t/${g.tenant_id}`} className="btn-primary">
          {t("support.openTenant")}
        </Link>
      ) : null}
      {g.status === "pending" && can(role, "platform.support_grant:breakglass") ? (
        <button
          type="button"
          className="btn-danger"
          onClick={() => {
            setOpen("breakglass");
          }}
        >
          {t("support.breakglassAction")}
        </button>
      ) : null}
      {grantOpen(g) && can(role, "platform.support_grant:revoke") ? (
        <button
          type="button"
          className="btn-secondary"
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
            act.reset();
          }
        }}
        title={open === "breakglass" ? t("support.confirm.breakglassTitle") : t("support.confirm.revokeTitle")}
        description={
          <div className="space-y-2">
            <p>
              {open === "breakglass"
                ? t("support.confirm.breakglassDesc", { staff: g.grantee.display_name, tenant: g.tenant_slug })
                : t("support.confirm.revokeDesc", { staff: g.grantee.display_name, role: t(`roles.${g.effective_role}`) })}
            </p>
            <GrantReason grant={g} />
          </div>
        }
        confirmLabel={open === "breakglass" ? t("support.breakglassAction") : t("support.revoke")}
        destructive
        typedConfirmation={open === "breakglass" ? { expected: g.tenant_slug, label: t("support.typeSlug") } : undefined}
        pending={act.isPending}
        error={act.error}
        onConfirm={() => {
          if (open) act.mutate(open);
        }}
      />
    </div>
  );
}
