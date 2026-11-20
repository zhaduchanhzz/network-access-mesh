// Hàng chờ phê duyệt phạm vi tenant (P4-T13; §8.6 quy tắc 2P trong tenant, P3-T03a/P4-T03a/P4-T09): GET
// /tenants/{t}/approvals — tắt 4-eyes, bỏ group sensitive, đổi thành viên group sensitive… Chi tiết: người duyệt xem
// ĐÚNG payload sẽ thực thi; trình duyệt tính lại payload_sha256 (api/canonical — cùng hàm với Platform Console) và chỉ
// cho duyệt khi khớp; người yêu cầu không tự duyệt (UI nói lý do — server quyết định: 403 self_approval, step-up 401,
// quyền của chính thao tác).
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Link, useLocation, useParams } from "react-router";
import { payloadSha256 } from "../../api/canonical";
import { api, call } from "../../api/client";
import { useCursorPager } from "../../api/pagination";
import { ApiError } from "../../api/problem";
import { isUuid, queryKeys } from "../../api/queryClient";
import type { components } from "../../api/schema";
import { can } from "../../auth/permissions";
import { useSession } from "../../auth/session";
import { Loading, Page } from "../../components/Page";
import { ProblemAlert } from "../../components/ProblemAlert";
import { NotFoundPage } from "../../pages/StatusPages";
import { ConfirmDialog } from "../../ui/ConfirmDialog";
import { EmptyState, Field, JsonBlock, Pager, QueryBlock } from "../../ui/Data";
import { StatusBadge } from "../../ui/Status";
import { Timestamp } from "../../ui/time";
import { useTenant } from "../TenantScope";

type ApprovalRequest = components["schemas"]["ApprovalRequest"];
type ApprovalStatus = components["schemas"]["ApprovalStatus"];
const STATUSES = ["pending", "approved", "rejected", "expired", "executed"] as const satisfies readonly ApprovalStatus[];
const PAGE = 25;

function isStatus(v: string): v is ApprovalStatus {
  return (STATUSES as readonly string[]).includes(v);
}

/** Thao tác trong tenant đã biết (đã dịch) kèm mã máy. */
export function TenantActionLabel({ action }: { action: string }) {
  const { t } = useTranslation();
  const label = t(`approvals.actions.${action.replaceAll(".", "_")}`, { defaultValue: "" });
  return label ? (
    <span>
      {label} <code className="text-xs text-muted">{action}</code>
    </span>
  ) : (
    <code>{action}</code>
  );
}

export function ApprovalsPage() {
  const { t } = useTranslation();
  const { tenantId } = useTenant();
  const me = useSession().data?.principal.identity_id;
  const [status, setStatus] = useState<ApprovalStatus | "">("pending");
  const pager = useCursorPager(status);
  const list = useQuery({
    queryKey: queryKeys.tenant(tenantId, "approvals", { status, cursor: pager.cursor ?? "" }),
    queryFn: () =>
      call(
        api.GET("/tenants/{tenantId}/approvals", {
          params: { path: { tenantId }, query: { limit: PAGE, status: status || undefined, cursor: pager.cursor } },
        }),
      ),
    placeholderData: (prev) => prev,
  });
  return (
    <Page title={t("nav.tenant.approvals")}>
      <p className="mb-4 text-sm text-muted">{t("approvals.intro")}</p>
      <div className="mb-4">
        <label htmlFor="tenant-approval-status" className="label">
          {t("approvals.status")}
        </label>
        <select
          id="tenant-approval-status"
          className="select"
          value={status}
          onChange={(e) => {
            setStatus(isStatus(e.target.value) ? e.target.value : "");
          }}
        >
          <option value="">{t("common.all")}</option>
          {STATUSES.map((s) => (
            <option key={s} value={s}>
              {t(`status.approval.${s}`)}
            </option>
          ))}
        </select>
      </div>
      <QueryBlock query={list}>
        {(data) =>
          data.items.length === 0 ? (
            <EmptyState>{t("approvals.empty")}</EmptyState>
          ) : (
            <>
              <div className="relative overflow-x-auto rounded-lg border border-line bg-surface">
                <table className="data-table">
                  <caption className="sr-only">{t("approvals.caption")}</caption>
                  <thead>
                    <tr>
                      <th scope="col">{t("approvals.col.action")}</th>
                      <th scope="col">{t("approvals.col.requestedBy")}</th>
                      <th scope="col">{t("approvals.col.status")}</th>
                      <th scope="col">{t("approvals.col.created")}</th>
                      <th scope="col">{t("approvals.col.expires")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.items.map((a) => (
                      <tr key={a.id}>
                        <td>
                          <Link to={`/t/${tenantId}/approvals/${a.id}`} className="link">
                            <TenantActionLabel action={a.action} />
                          </Link>
                        </td>
                        <td>
                          {a.requested_by.display_name}
                          {a.requested_by.identity_id === me ? <span className="hint block">{t("approvals.you")}</span> : null}
                        </td>
                        <td>
                          <StatusBadge status={a.status}>{t(`status.approval.${a.status}`)}</StatusBadge>
                        </td>
                        <td>
                          <Timestamp iso={a.created_at} />
                        </td>
                        <td>
                          <Timestamp iso={a.expires_at} />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <Pager pager={pager} nextCursor={data.next_cursor} label={t("approvals.pagination")} />
            </>
          )
        }
      </QueryBlock>
    </Page>
  );
}

export function ApprovalDetailPage() {
  const { approvalId: raw = "" } = useParams();
  const approvalId = raw.toLowerCase();
  if (!isUuid(approvalId)) return <NotFoundPage />;
  return <ApprovalDetail key={approvalId} approvalId={approvalId} />;
}

function ApprovalDetail({ approvalId }: { approvalId: string }) {
  const { t } = useTranslation();
  const { tenantId } = useTenant();
  const location = useLocation();
  const requested = (location.state as { requested?: boolean } | null)?.requested === true;
  const q = useQuery({
    queryKey: queryKeys.tenant(tenantId, "approval", approvalId),
    queryFn: () => call(api.GET("/tenants/{tenantId}/approvals/{approvalId}", { params: { path: { tenantId, approvalId } } })),
  });
  if (q.isPending) return <Loading />;
  if (q.isError) {
    if (q.error instanceof ApiError && q.error.status === 404) return <NotFoundPage />;
    return (
      <Page title={t("approvals.detailTitle")}>
        <ProblemAlert error={q.error} onRetry={() => void q.refetch()} />
      </Page>
    );
  }
  const a = q.data;
  return (
    <Page title={t("approvals.detailTitle")}>
      <p className="mb-4">
        <Link to={`/t/${tenantId}/approvals`} className="link text-sm">
          {t("approvals.back")}
        </Link>
      </p>
      {requested ? (
        <div role="status" className="banner banner-warn mb-4" data-testid="approval-requested">
          <p>{t("approvals.requestedNotice")}</p>
        </div>
      ) : null}
      <section aria-labelledby="tenant-approval-summary" className="card mb-6">
        <h2 id="tenant-approval-summary" className="mb-3 text-lg font-semibold">
          <TenantActionLabel action={a.action} />
        </h2>
        <dl className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          <Field label={t("approvals.col.status")}>
            <StatusBadge status={a.status} testId="approval-status">
              {t(`status.approval.${a.status}`)}
            </StatusBadge>
          </Field>
          <Field label={t("approvals.col.requestedBy")}>{a.requested_by.display_name}</Field>
          <Field label={t("approvals.col.created")}>
            <Timestamp iso={a.created_at} />
          </Field>
          <Field label={t("approvals.col.expires")}>
            <Timestamp iso={a.expires_at} />
          </Field>
          {a.decided_by ? (
            <Field label={t("approvals.decidedBy")}>
              {a.decided_by.display_name} · <Timestamp iso={a.decided_at} emptyKey="common.none" />
            </Field>
          ) : null}
        </dl>
        {a.reason ? <p className="mt-3 text-sm whitespace-pre-wrap">{a.reason}</p> : null}
      </section>
      <Review approval={a} />
    </Page>
  );
}

function Review({ approval: a }: { approval: ApprovalRequest }) {
  const { t } = useTranslation();
  const { tenantId, role, readOnly } = useTenant();
  const me = useSession().data?.principal.identity_id;
  const queryClient = useQueryClient();
  const [open, setOpen] = useState<"approve" | "reject" | null>(null);
  const local = useQuery({
    queryKey: queryKeys.tenant(tenantId, "approval", a.id, "hash", a.payload_sha256),
    queryFn: () => payloadSha256(a.payload),
    staleTime: Infinity,
  });
  const matches = typeof local.data === "string" && local.data === a.payload_sha256;
  const self = me !== undefined && a.requested_by.identity_id === me;
  const permitted = can(role, "tenant.approval:decide") && !readOnly;
  const path = { tenantId, approvalId: a.id };
  const decide = useMutation({
    mutationFn: (c: "approve" | "reject") =>
      c === "approve"
        ? call(api.POST("/tenants/{tenantId}/approvals/{approvalId}/approve", { params: { path }, body: { payload_sha256: a.payload_sha256 } }))
        : call(api.POST("/tenants/{tenantId}/approvals/{approvalId}/reject", { params: { path } })),
    onSuccess: async (updated) => {
      setOpen(null);
      queryClient.setQueryData(queryKeys.tenant(tenantId, "approval", a.id), updated);
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: queryKeys.tenant(tenantId, "approvals") }),
        queryClient.invalidateQueries({ queryKey: queryKeys.tenant(tenantId, "settings") }),
      ]);
    },
  });
  return (
    <section aria-labelledby="tenant-approval-payload" className="card space-y-3">
      <h2 id="tenant-approval-payload" className="text-lg font-semibold">
        {t("approvals.payload")}
      </h2>
      <p className="text-sm text-muted">{t("approvals.payloadIntro")}</p>
      <JsonBlock value={a.payload} />
      <p role="status" data-testid="hash-check">
        {local.isPending ? (
          t("approvals.hashChecking")
        ) : matches ? (
          <StatusBadge tone="ok">{t("approvals.hashMatch")}</StatusBadge>
        ) : (
          <StatusBadge tone="danger">{t("approvals.hashMismatch")}</StatusBadge>
        )}
      </p>
      {a.status !== "pending" ? (
        <p className="text-sm text-muted">{t("approvals.closed", { status: t(`status.approval.${a.status}`) })}</p>
      ) : self ? (
        <p className="banner banner-warn" data-testid="self-request">
          {t("approvals.selfRequest")}
        </p>
      ) : !permitted ? (
        <p className="text-sm text-muted" data-testid="not-permitted">
          {t("approvals.notPermitted")}
        </p>
      ) : (
        <div className="flex flex-wrap gap-2" role="group" aria-label={t("approvals.decision")}>
          <button
            type="button"
            className="btn-primary"
            disabled={!matches}
            onClick={() => {
              setOpen("approve");
            }}
          >
            {t("approvals.approve")}
          </button>
          <button
            type="button"
            className="btn-secondary"
            onClick={() => {
              setOpen("reject");
            }}
          >
            {t("approvals.reject")}
          </button>
        </div>
      )}
      <ConfirmDialog
        isOpen={open !== null}
        onOpenChange={(o) => {
          if (!o) {
            setOpen(null);
            decide.reset();
          }
        }}
        title={open === "approve" ? t("approvals.approveTitle") : t("approvals.rejectTitle")}
        description={
          <div className="space-y-2">
            <p>{open === "approve" ? t("approvals.approveDesc") : t("approvals.rejectDesc")}</p>
            <p>
              <TenantActionLabel action={a.action} />
            </p>
          </div>
        }
        confirmLabel={open === "approve" ? t("approvals.approve") : t("approvals.reject")}
        canConfirm={open !== "approve" || matches}
        pending={decide.isPending}
        error={decide.error}
        onConfirm={() => {
          if (open) decide.mutate(open);
        }}
      />
    </section>
  );
}
