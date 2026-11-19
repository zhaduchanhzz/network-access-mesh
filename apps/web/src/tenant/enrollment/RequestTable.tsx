// Bảng yêu cầu enrollment + thao tác (P4-T08): duyệt / từ chối (người quyết khác người yêu cầu — nút ẩn cho chính người
// yêu cầu, server vẫn trả 403 self_approval; nhân viên nền tảng có Support Access Grant thấy nút theo quyền của role hiệu
// lực — §8.6 ô G — và quyết định của họ hiện "bởi nhân viên hỗ trợ", 0028), `/start` cho chính người yêu cầu sau khi
// được duyệt (phát mã/lệnh hoặc key một lần), thu hồi hai pha — cả key reusable đã dùng còn hạn (POST /revoke expire
// key ở Headscale + đọc lại rồi mới trả `revoked`: trong lúc chờ hiện "đang thu hồi"; 502/503 ⇒ yêu cầu giữ nguyên, nói rõ chưa thu hồi). Nút chỉ là UX — server
// quyết định quyền, own-scope của End User, trạng thái tenant (suspended ⇒ 403 tenant_suspended). Tên truy cập của mọi nút
// bắt đầu bằng chữ hiển thị (WCAG 2.5.3).
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { api, call } from "../../api/client";
import { ApiError } from "../../api/problem";
import { can } from "../../auth/permissions";
import { ProblemAlert } from "../../components/ProblemAlert";
import { ConfirmDialog } from "../../ui/ConfirmDialog";
import { EmptyState } from "../../ui/Data";
import { StatusBadge, useCodeText } from "../../ui/Status";
import { Timestamp, useNow } from "../../ui/time";
import { TagList } from "../devices/DeviceBits";
import { invalidateEnrollment } from "./api";
import { isRevocable, problemReason, type EnrollmentIssue, type EnrollmentRequest } from "./model";

type ActionKind = "approve" | "reject" | "revoke";

export interface RequestTableProps {
  tenantId: string;
  role: string;
  membershipId: string | null;
  readOnly: boolean;
  items: readonly EnrollmentRequest[];
  /** membership id ⇒ tên hiển thị (khi người gọi đọc được /users) */
  names: ReadonlyMap<string, string>;
  /** cột chủ thiết bị + tag/tùy chọn của key (trang Enrollment key) */
  wide?: boolean;
  caption: string;
  /** danh sách rỗng ⇒ EmptyState với chữ này — bảng vẫn mount nên thông báo `done` và hộp đang mở không mất khi hàng cuối rời
   * danh sách đã lọc (duyệt/từ chối yêu cầu cuối của hàng chờ) */
  empty: string;
  testId?: string;
  /** `/start` thành công ⇒ credential cho màn hình hiển thị (một lần) */
  onIssued: (issue: EnrollmentIssue) => void;
}

export function RequestTable(props: RequestTableProps) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const codeText = useCodeText();
  const { tenantId, role, membershipId, readOnly, items, names, wide = false } = props;
  const now = useNow();
  // bản chụp của hàng lúc mở hộp: 409/404 ⇒ tải lại có thể làm hàng rời danh sách đã lọc — hộp vẫn mở cùng lỗi
  const [action, setAction] = useState<{ kind: ActionKind; request: EnrollmentRequest } | null>(null);
  const [done, setDone] = useState<string | null>(null);
  const [startError, setStartError] = useState<{ id: string; error: unknown } | null>(null);
  const [starting, setStarting] = useState<string | null>(null);

  const nameOf = (id: string | null | undefined) => {
    if (!id) return null;
    if (id === membershipId) return t("enroll.you");
    return names.get(id) ?? t("enroll.memberShort", { id: id.slice(0, 8) });
  };
  const labelOf = (r: EnrollmentRequest) => r.device_label ?? t("enroll.noLabel");

  const decide = useMutation({
    mutationFn: async ({ kind, id }: { kind: ActionKind; id: string }) => {
      const path = { tenantId, enrollmentRequestId: id };
      if (kind === "approve") return call(api.POST("/tenants/{tenantId}/enrollment/requests/{enrollmentRequestId}/approve", { params: { path } }));
      if (kind === "reject") return call(api.POST("/tenants/{tenantId}/enrollment/requests/{enrollmentRequestId}/reject", { params: { path } }));
      return call(api.POST("/tenants/{tenantId}/enrollment/requests/{enrollmentRequestId}/revoke", { params: { path } }));
    },
    onSuccess: (r, v) => {
      setAction(null);
      setDone(t(`enroll.actions.done.${v.kind}`, { label: labelOf(r) }));
      void invalidateEnrollment(queryClient, tenantId);
    },
    onError: (e) => {
      // đã đổi trạng thái ở nơi khác ⇒ tải lại (hộp vẫn mở với lỗi — dựng từ bản chụp `action.request`)
      if (e instanceof ApiError && (e.code === "conflict" || e.code === "not_found")) void invalidateEnrollment(queryClient, tenantId);
    },
  });
  const open = (kind: ActionKind, request: EnrollmentRequest) => {
    setDone(null);
    decide.reset();
    setAction({ kind, request });
  };

  // /start không có Idempotency-Key (gọi lại ⇒ 409 already_started) và trả credential ⇒ không qua cache của mutation
  const start = async (r: EnrollmentRequest) => {
    setStarting(r.id);
    setStartError(null);
    setDone(null);
    try {
      const issue = await call(
        api.POST("/tenants/{tenantId}/enrollment/requests/{enrollmentRequestId}/start", { params: { path: { tenantId, enrollmentRequestId: r.id } } }),
      );
      props.onIssued(issue);
      void invalidateEnrollment(queryClient, tenantId);
    } catch (e) {
      setStartError({ id: r.id, error: e });
      void invalidateEnrollment(queryClient, tenantId);
    } finally {
      setStarting(null);
    }
  };

  const canApprove = can(role, "tenant.enrollment:approve");
  const canRequest = can(role, "tenant.enrollment:request");
  const canRevoke = can(role, "tenant.enrollment:revoke");

  return (
    <div>
      {done ? (
        <p role="status" className="mb-3 text-sm" data-testid="enroll-done">
          {done}
        </p>
      ) : null}
      {startError ? (
        <div className="mb-3" data-testid="start-error">
          <StartError error={startError.error} />
        </div>
      ) : null}
      {items.length === 0 ? (
        <EmptyState>{props.empty}</EmptyState>
      ) : (
        <div className="overflow-x-auto">
          <table className="data-table" data-testid={props.testId ?? "enroll-table"}>
            <caption className="sr-only">{props.caption}</caption>
            <thead>
              <tr>
                <th scope="col">{t("enroll.col.device")}</th>
                <th scope="col">{t("enroll.col.method")}</th>
                <th scope="col">{t("enroll.col.status")}</th>
                <th scope="col">{t("enroll.col.requester")}</th>
                {wide ? <th scope="col">{t("enroll.col.owner")}</th> : null}
                {wide ? <th scope="col">{t("enroll.col.options")}</th> : null}
                <th scope="col">{t("enroll.col.created")}</th>
                <th scope="col">{t("enroll.col.expires")}</th>
                <th scope="col">{t("enroll.col.actions")}</th>
              </tr>
            </thead>
            <tbody>
              {items.map((r) => {
                const mine = r.requested_by_membership_id === membershipId;
                const showDecide = canApprove && r.status === "pending_approval";
                const showStart = canRequest && mine && r.status === "approved";
                const showRevoke = canRevoke && isRevocable(r, now);
                const label = labelOf(r);
                return (
                  <tr key={r.id} data-testid="enroll-row" data-request={r.id} data-status={r.status}>
                    <td className="font-medium">{label}</td>
                    <td>{t(`enroll.method.${r.method}`)}</td>
                    <td>
                      <StatusBadge status={r.status}>{t(`status.enrollment.${r.status}`)}</StatusBadge>
                      {r.failure_code ? <div className="text-xs text-muted">{codeText("enroll.failure", r.failure_code)}</div> : null}
                      {r.approver_support_grant_id ? (
                        // người quyết định là nhân viên nền tảng qua Support Access Grant (0028) — tenant thấy rõ (§8.7 bước 3)
                        <div className="text-xs text-muted" data-testid="decided-by-support">
                          {r.status === "rejected" ? t("enroll.decider.supportRejected") : t("enroll.decider.supportApproved")}
                        </div>
                      ) : null}
                      {decide.isPending && decide.variables.id === r.id && decide.variables.kind === "revoke" ? (
                        <div className="text-xs text-warn" data-testid="revoke-pending">
                          {t("enroll.actions.revoking")}
                        </div>
                      ) : null}
                    </td>
                    <td>{nameOf(r.requested_by_membership_id)}</td>
                    {wide ? <td>{r.target_membership_id ? nameOf(r.target_membership_id) : <span className="text-muted">{t("enroll.tagOnly")}</span>}</td> : null}
                    {wide ? (
                      <td>
                        <TagList tags={r.tags} />
                        {r.reusable ? <StatusBadge tone="warn">{t("enroll.key.reusable")}</StatusBadge> : null}{" "}
                        {r.ephemeral ? <StatusBadge tone="info">{t("enroll.key.ephemeral")}</StatusBadge> : null}
                      </td>
                    ) : null}
                    <td>
                      <Timestamp iso={r.created_at} relative={false} />
                    </td>
                    <td>
                      <Timestamp iso={r.credential_expires_at} emptyKey="common.none" />
                    </td>
                    <td>
                      <div className="flex flex-col items-start gap-1">
                        {showDecide && !mine ? (
                          <>
                            <button
                              type="button"
                              className="btn-secondary"
                              disabled={readOnly}
                              aria-label={t("enroll.actions.approveFor", { label })}
                              onClick={() => {
                                open("approve", r);
                              }}
                            >
                              {t("enroll.actions.approve")}
                            </button>
                            <button
                              type="button"
                              className="btn-secondary"
                              disabled={readOnly}
                              aria-label={t("enroll.actions.rejectFor", { label })}
                              onClick={() => {
                                open("reject", r);
                              }}
                            >
                              {t("enroll.actions.reject")}
                            </button>
                          </>
                        ) : null}
                        {showDecide && mine ? (
                          <span className="text-xs text-muted" data-testid="needs-other-approver">
                            {t("enroll.actions.needsOther")}
                          </span>
                        ) : null}
                        {showStart ? (
                          // WCAG 2.5.3: tên truy cập bắt đầu bằng đúng chữ hiển thị; đang gửi ⇒ chữ "Đang gửi…" là tên + aria-busy
                          <button
                            type="button"
                            className="btn-primary"
                            disabled={readOnly || starting !== null}
                            aria-busy={starting === r.id || undefined}
                            aria-label={
                              starting === r.id
                                ? undefined
                                : t(r.method === "web_auth" ? "enroll.actions.startWebFor" : "enroll.actions.startKeyFor", { label })
                            }
                            onClick={() => void start(r)}
                          >
                            {starting === r.id ? t("common.working") : t(r.method === "web_auth" ? "enroll.actions.startWeb" : "enroll.actions.startKey")}
                          </button>
                        ) : null}
                        {showRevoke ? (
                          <button
                            type="button"
                            className="btn-secondary"
                            disabled={readOnly}
                            aria-label={t("enroll.actions.revokeFor", { label })}
                            onClick={() => {
                              open("revoke", r);
                            }}
                          >
                            {t("enroll.actions.revoke")}
                          </button>
                        ) : null}
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      {action ? (
        <ConfirmDialog
          isOpen
          onOpenChange={(isOpen) => {
            if (!isOpen && !decide.isPending) {
              setAction(null);
              decide.reset();
            }
          }}
          title={t(`enroll.actions.title.${action.kind}`, { label: labelOf(action.request) })}
          description={
            <div className="space-y-2">
              <p>{t(`enroll.actions.desc.${action.kind}`)}</p>
              <p className="text-muted">
                {t("enroll.col.requester")}: {nameOf(action.request.requested_by_membership_id)} · {t(`enroll.method.${action.request.method}`)}
              </p>
              {action.kind === "revoke" && decide.error instanceof ApiError && (decide.error.status === 502 || decide.error.status === 503) ? (
                <p className="text-danger" data-testid="revoke-not-applied">
                  {t("enroll.actions.revokeNotApplied")}
                </p>
              ) : null}
            </div>
          }
          confirmLabel={t(`enroll.actions.${action.kind}`)}
          destructive={action.kind !== "approve"}
          pending={decide.isPending}
          error={decide.error}
          onConfirm={() => {
            decide.mutate({ kind: action.kind, id: action.request.id });
          }}
        />
      ) : null}
    </div>
  );
}

const START_CONFLICTS: ReadonlySet<string> = new Set(["already_started", "request_expired", "not_approved", "not_requester"]);

function StartError({ error }: { error: unknown }) {
  const { t } = useTranslation();
  const reason = problemReason(error);
  if (reason === null) return <ProblemAlert error={error} />;
  return (
    <div role="alert" className="rounded-md border border-danger/40 bg-danger-bg p-3 text-sm">
      <p className="font-semibold text-danger">{t(`enroll.startConflict.${START_CONFLICTS.has(reason) ? reason : "other"}`)}</p>
    </div>
  );
}
