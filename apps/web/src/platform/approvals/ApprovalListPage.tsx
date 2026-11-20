// Hàng chờ phê duyệt 2P (§8.5 dual control, §12.2): GET /platform/approvals — mặc định yêu cầu đang chờ, lọc trạng thái
// và thao tác, phân trang con trỏ. Chỉ yêu cầu phạm vi platform (yêu cầu nội bộ của tenant không bao giờ hiện ở đây).
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Link } from "react-router";
import { useCursorPager } from "../../api/pagination";
import { useSession } from "../../auth/session";
import { EmptyState, Pager, QueryBlock } from "../../ui/Data";
import { StatusBadge } from "../../ui/Status";
import { Timestamp } from "../../ui/time";
import { Page } from "../../components/Page";
import { APPROVAL_STATUSES, useApprovalList, type ApprovalStatus } from "../api";
import { ActionLabel } from "./ApprovalDetailPage";

const ACTION_RE = /^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$/;

function isApprovalStatus(v: string): v is ApprovalStatus {
  return (APPROVAL_STATUSES as readonly string[]).includes(v);
}

export function ApprovalListPage() {
  const { t } = useTranslation();
  const me = useSession().data?.principal.identity_id;
  const [status, setStatus] = useState<ApprovalStatus | "">("pending");
  const [draft, setDraft] = useState("");
  const [action, setAction] = useState("");
  const actionInvalid = draft !== "" && (!ACTION_RE.test(draft) || draft.length > 100);
  const pager = useCursorPager(`${status}|${action}`);
  const list = useApprovalList({ status: status || undefined, action: action || undefined, cursor: pager.cursor });

  return (
    <Page title={t("platform.approvals.title")}>
      <p className="mb-4 text-sm text-muted">{t("platform.approvals.intro")}</p>
      <form
        role="search"
        aria-label={t("platform.approvals.filters")}
        className="mb-4 flex flex-wrap items-end gap-3"
        onSubmit={(e) => {
          e.preventDefault();
          if (!actionInvalid) setAction(draft);
        }}
      >
        <div>
          <label htmlFor="approval-status" className="label">
            {t("platform.approvals.status")}
          </label>
          <select
            id="approval-status"
            className="select"
            value={status}
            onChange={(e) => {
              setStatus(isApprovalStatus(e.target.value) ? e.target.value : "");
            }}
          >
            <option value="">{t("common.all")}</option>
            {APPROVAL_STATUSES.map((s) => (
              <option key={s} value={s}>
                {t(`status.approval.${s}`)}
              </option>
            ))}
          </select>
        </div>
        <div>
          <label htmlFor="approval-action" className="label">
            {t("platform.approvals.action")}
          </label>
          <input
            id="approval-action"
            className="input font-mono"
            placeholder={t("platform.approvals.actionPlaceholder")}
            value={draft}
            aria-invalid={actionInvalid}
            onChange={(e) => {
              setDraft(e.target.value.trim());
            }}
          />
        </div>
        <button type="submit" className="btn-secondary" disabled={actionInvalid}>
          {t("common.search")}
        </button>
      </form>
      <QueryBlock query={list}>
        {(data) =>
          data.items.length === 0 ? (
            <EmptyState>{status === "pending" && !action ? t("platform.approvals.emptyPending") : t("platform.approvals.empty")}</EmptyState>
          ) : (
            <>
              <div className="relative overflow-x-auto rounded-lg border border-line bg-surface">
                <table className="data-table">
                  <caption className="sr-only">{t("platform.approvals.caption")}</caption>
                  <thead>
                    <tr>
                      <th scope="col">{t("platform.approvals.col.action")}</th>
                      <th scope="col">{t("platform.approvals.col.resource")}</th>
                      <th scope="col">{t("platform.approvals.col.requestedBy")}</th>
                      <th scope="col">{t("platform.approvals.col.status")}</th>
                      <th scope="col">{t("platform.approvals.col.created")}</th>
                      <th scope="col">{t("platform.approvals.col.expires")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.items.map((a) => (
                      <tr key={a.id}>
                        <td>
                          <Link to={`/platform/approvals/${a.id}`} className="link">
                            <ActionLabel action={a.action} />
                          </Link>
                        </td>
                        <td>
                          <code className="text-xs">{`${a.resource_type}${a.resource_id ? `:${a.resource_id}` : ""}`}</code>
                        </td>
                        <td>
                          {a.requested_by.display_name}
                          {a.requested_by.identity_id === me ? <span className="hint block">{t("platform.approvals.you")}</span> : null}
                        </td>
                        <td>
                          <StatusBadge status={a.status}>{t(`status.approval.${a.status}`)}</StatusBadge>
                        </td>
                        <td>
                          <Timestamp iso={a.created_at} emptyKey="common.none" />
                        </td>
                        <td>
                          <Timestamp iso={a.expires_at} emptyKey="common.none" />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <Pager pager={pager} nextCursor={data.next_cursor} label={t("platform.approvals.pagination")} />
            </>
          )
        }
      </QueryBlock>
    </Page>
  );
}
