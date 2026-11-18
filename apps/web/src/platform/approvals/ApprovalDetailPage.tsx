// Một yêu cầu phê duyệt 2P (§8.5, §8.6, §6.3 approval_requests): người duyệt xem ĐÚNG payload sẽ thực thi và
// payload_sha256; trình duyệt tính lại hash của payload hiển thị (JSON chuẩn hóa — src/api/canonical.ts) và chỉ cho
// duyệt khi hai hash khớp; quyết định gửi lại đúng hash đó (server so lần nữa, lệch ⇒ 412). Người yêu cầu không tự duyệt
// được: UI ẩn/khóa nút và nói lý do — server mới quyết định (403 self_approval, step-up 401 reauth_required, quyền của
// chính thao tác, điều kiện restore_only của Platform Operator).
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Link, useLocation, useParams } from "react-router";
import { payloadSha256 } from "../../api/canonical";
import { api, call } from "../../api/client";
import { ApiError } from "../../api/problem";
import { isUuid } from "../../api/queryClient";
import { can } from "../../auth/permissions";
import { useSession } from "../../auth/session";
import { ConfirmDialog } from "../../components/ConfirmDialog";
import { DateTime, Field, JsonBlock, StatusBadge } from "../../components/Data";
import { Loading, Page } from "../../components/Page";
import { ProblemAlert } from "../../components/ProblemAlert";
import { NotFoundPage } from "../../pages/StatusPages";
import { APPROVAL_ACTION_PERMISSION, invalidatePlatform, platformKeys, useApproval, type ApprovalRequest } from "../api";
import { usePlatformRole } from "../PlatformScope";

/** Tên thao tác đã dịch (thao tác đã biết) kèm mã máy. */
export function ActionLabel({ action }: { action: string }) {
  const { t } = useTranslation();
  const label = t(`platform.approvalActions.${action.replaceAll(".", "_")}`, { defaultValue: "" });
  return label ? (
    <span>
      {label} <code className="text-xs text-muted">{action}</code>
    </span>
  ) : (
    <code>{action}</code>
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
  const location = useLocation();
  const q = useApproval(approvalId);
  const requested = (location.state as { requested?: boolean } | null)?.requested === true;

  if (q.isPending) return <Loading />;
  if (q.isError) {
    if (q.error instanceof ApiError && q.error.status === 404) return <NotFoundPage />;
    return (
      <Page title={t("platform.approval.title")}>
        <ProblemAlert error={q.error} onRetry={() => void q.refetch()} />
      </Page>
    );
  }
  const a = q.data;
  return (
    <Page title={t("platform.approval.title")}>
      <p className="mb-4">
        <Link to="/platform/approvals" className="link text-sm">
          {t("platform.approval.back")}
        </Link>
      </p>
      {requested ? (
        <div role="status" className="banner banner-warn mb-4" data-testid="approval-requested">
          <p>{t("platform.approval.requestedNotice")}</p>
        </div>
      ) : null}
      <div className="space-y-6">
        <section aria-labelledby="approval-summary" className="card">
          <h2 id="approval-summary" className="mb-3 text-lg font-semibold">
            <ActionLabel action={a.action} />
          </h2>
          <dl className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            <Field label={t("platform.approvals.col.status")}>
              <StatusBadge status={a.status} label={t(`status.approval.${a.status}`)} />
            </Field>
            <Field label={t("platform.approvals.col.resource")}>
              {a.resource_type === "tenant" && a.resource_id && isUuid(a.resource_id) ? (
                <Link to={`/platform/tenants/${a.resource_id}`} className="link font-mono text-xs">
                  {a.resource_type}
                  {":"}
                  {a.resource_id}
                </Link>
              ) : (
                <code className="text-xs">{`${a.resource_type}${a.resource_id ? `:${a.resource_id}` : ""}`}</code>
              )}
            </Field>
            <Field label={t("platform.approvals.col.requestedBy")}>{a.requested_by.display_name}</Field>
            <Field label={t("platform.approvals.col.created")}>
              <DateTime value={a.created_at} />
            </Field>
            <Field label={t("platform.approvals.col.expires")}>
              <DateTime value={a.expires_at} />
            </Field>
            {a.decided_by ? (
              <Field label={t("platform.approval.decidedBy")}>
                {a.decided_by.display_name} · <DateTime value={a.decided_at} />
              </Field>
            ) : null}
            {a.job_id ? (
              <Field label={t("platform.approval.job")}>
                <Link to={`/platform/jobs/${a.job_id}`} className="link font-mono text-xs">
                  {a.job_id}
                </Link>
              </Field>
            ) : null}
          </dl>
          <div className="mt-4">
            <h3 className="text-sm font-semibold">{t("platform.approval.reason")}</h3>
            <p className="mt-1 text-sm whitespace-pre-wrap">{a.reason ?? t("common.none")}</p>
          </div>
        </section>
        <PayloadSection approval={a} />
      </div>
    </Page>
  );
}

function PayloadSection({ approval: a }: { approval: ApprovalRequest }) {
  const { t } = useTranslation();
  const role = usePlatformRole();
  const me = useSession().data?.principal.identity_id;
  const local = useQuery({
    queryKey: platformKeys.approvalHash(a.id, a.payload_sha256),
    queryFn: () => payloadSha256(a.payload),
    staleTime: Infinity,
  });
  const matches = local.data !== undefined && local.data !== null && local.data === a.payload_sha256;
  const self = me !== undefined && a.requested_by.identity_id === me;
  const actionPermission = APPROVAL_ACTION_PERMISSION[a.action];
  const permitted = can(role, "platform.approval:decide") && (actionPermission === undefined || can(role, actionPermission));

  return (
    <section aria-labelledby="approval-payload" className="card space-y-3">
      <h2 id="approval-payload" className="text-lg font-semibold">
        {t("platform.approval.payload")}
      </h2>
      <p className="text-sm text-muted">{t("platform.approval.payloadIntro")}</p>
      <JsonBlock value={a.payload} />
      <dl className="grid gap-3 sm:grid-cols-2">
        <Field label={t("platform.approval.serverHash")}>
          <code className="text-xs break-all" data-testid="server-hash">
            {a.payload_sha256}
          </code>
        </Field>
        <Field label={t("platform.approval.localHash")}>
          <code className="text-xs break-all" data-testid="local-hash">
            {local.data ?? t("common.none")}
          </code>
        </Field>
      </dl>
      <p role="status" data-testid="hash-check">
        {local.isPending ? (
          t("platform.approval.hashChecking")
        ) : matches ? (
          <StatusBadge status="succeeded" label={t("platform.approval.hashMatch")} />
        ) : local.data === null ? (
          <StatusBadge status="unknown" label={t("platform.approval.hashUnverifiable")} />
        ) : (
          <StatusBadge status="failed" label={t("platform.approval.hashMismatch")} />
        )}
      </p>
      {a.status === "pending" ? (
        <Decision approval={a} self={self} permitted={permitted} reviewedHash={matches ? (local.data ?? null) : null} />
      ) : (
        <p className="text-sm text-muted">{t("platform.approval.closed", { status: t(`status.approval.${a.status}`) })}</p>
      )}
    </section>
  );
}

type Choice = "approve" | "reject";

/** `reviewedHash`: hash tính trong trình duyệt của payload đang hiển thị — chỉ có khi khớp hash của server. */
function Decision({
  approval: a,
  self,
  permitted,
  reviewedHash,
}: {
  approval: ApprovalRequest;
  self: boolean;
  permitted: boolean;
  reviewedHash: string | null;
}) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [open, setOpen] = useState<Choice | null>(null);
  const hashOk = reviewedHash !== null;
  const decide = useMutation({
    mutationFn: (c: Choice) =>
      c === "approve"
        ? reviewedHash === null
          ? Promise.reject(new Error("approve without a verified payload hash"))
          : call(
              api.POST("/platform/approvals/{approvalId}/approve", {
                params: { path: { approvalId: a.id } },
                body: { payload_sha256: reviewedHash },
              }),
            )
        : call(api.POST("/platform/approvals/{approvalId}/reject", { params: { path: { approvalId: a.id } } })),
    onSuccess: async (updated) => {
      setOpen(null);
      queryClient.setQueryData(platformKeys.approval(a.id), updated);
      await Promise.all([
        invalidatePlatform(queryClient, "approvals"),
        invalidatePlatform(queryClient, "tenant"),
        invalidatePlatform(queryClient, "jobs"),
      ]);
    },
  });
  const blocked = self || !permitted;
  const slug = typeof a.payload.slug === "string" ? a.payload.slug : null;
  const destructive = a.action === "platform.tenant.delete";

  return (
    <div className="space-y-3 border-t border-line pt-3">
      {self ? (
        <p className="banner banner-warn" data-testid="self-request">
          {t("platform.approval.selfRequest")}
        </p>
      ) : !permitted ? (
        <p className="text-sm text-muted" data-testid="not-permitted">
          {t("platform.approval.notPermitted")}
        </p>
      ) : (
        <p className="text-sm text-muted">{t("platform.approval.stepUpNote")}</p>
      )}
      {!blocked ? (
        <div className="flex flex-wrap gap-2" role="group" aria-label={t("platform.approval.decision")}>
          <button
            type="button"
            className={destructive ? "btn-danger" : "btn-primary"}
            disabled={!hashOk}
            onClick={() => {
              setOpen("approve");
            }}
          >
            {t("platform.approval.approve")}
          </button>
          <button
            type="button"
            className="btn-secondary"
            onClick={() => {
              setOpen("reject");
            }}
          >
            {t("platform.approval.reject")}
          </button>
        </div>
      ) : null}
      {decide.isSuccess ? <p role="status">{t("platform.approval.decided")}</p> : null}
      <ConfirmDialog
        isOpen={open !== null}
        onOpenChange={(o) => {
          if (!o) {
            setOpen(null);
            decide.reset();
          }
        }}
        title={open === "approve" ? t("platform.approval.approveTitle") : t("platform.approval.rejectTitle")}
        description={
          <div className="space-y-2">
            <p>{open === "approve" ? t("platform.approval.approveDesc") : t("platform.approval.rejectDesc")}</p>
            <p>
              <ActionLabel action={a.action} />
            </p>
            <p className="text-xs">
              {t("platform.approval.hashLabel")} <code className="break-all">{a.payload_sha256}</code>
            </p>
          </div>
        }
        confirmLabel={open === "approve" ? t("platform.approval.approve") : t("platform.approval.reject")}
        destructive={open === "approve" ? destructive : false}
        typedConfirmation={open === "approve" && destructive && slug ? { expected: slug, label: t("platform.approval.typeSlug") } : undefined}
        canConfirm={open !== "approve" || hashOk}
        pending={decide.isPending}
        error={decide.error}
        onConfirm={() => {
          if (open) decide.mutate(open);
        }}
      />
    </div>
  );
}
