// Job — danh sách (§12.2 "Job timeline"): GET /platform/jobs (lọc trạng thái, kind; con trỏ). Còn job chưa xong ⇒ làm
// mới mỗi 5 s (polling — §12.4). Bảng job dùng lại ở chi tiết tenant.
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Link } from "react-router";
import { JOB_STATUSES, type Job, type JobStatus } from "../../api/jobs";
import { useCursorPager } from "../../api/pagination";
import { EmptyState, Pager, QueryBlock } from "../../ui/Data";
import { StatusBadge } from "../../ui/Status";
import { Timestamp } from "../../ui/time";
import { Page } from "../../components/Page";
import { useJobList } from "../api";

const KIND_RE = /^[a-z][a-z_]*(\.[a-z][a-z_]*)+$/;

function isJobStatus(v: string): v is JobStatus {
  return (JOB_STATUSES as readonly string[]).includes(v);
}

export function JobTable({ jobs, showTenant, caption }: { jobs: readonly Job[]; showTenant: boolean; caption: string }) {
  const { t } = useTranslation();
  return (
    <div className="relative overflow-x-auto rounded-lg border border-line bg-surface">
      <table className="data-table">
        <caption className="sr-only">{caption}</caption>
        <thead>
          <tr>
            <th scope="col">{t("platform.jobs.col.kind")}</th>
            {showTenant ? <th scope="col">{t("platform.jobs.col.tenant")}</th> : null}
            <th scope="col">{t("platform.jobs.col.status")}</th>
            <th scope="col">{t("platform.jobs.col.step")}</th>
            <th scope="col">{t("platform.jobs.col.created")}</th>
          </tr>
        </thead>
        <tbody>
          {jobs.map((j) => (
            <tr key={j.id}>
              <td>
                <Link to={`/platform/jobs/${j.id}`} className="link font-mono">
                  {j.kind}
                </Link>
              </td>
              {showTenant ? (
                <td>
                  {j.tenant_id ? (
                    <Link to={`/platform/tenants/${j.tenant_id}`} className="link font-mono text-xs">
                      {j.tenant_id}
                    </Link>
                  ) : (
                    <span className="text-muted">{t("platform.jobs.platformJob")}</span>
                  )}
                </td>
              ) : null}
              <td>
                <StatusBadge status={j.status}>{t(`status.job.${j.status}`)}</StatusBadge>
              </td>
              <td>{j.current_step ? <code>{j.current_step}</code> : <span className="text-muted">{t("common.none")}</span>}</td>
              <td>
                <Timestamp iso={j.created_at} emptyKey="common.none" />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function JobListPage() {
  const { t } = useTranslation();
  const [status, setStatus] = useState<JobStatus | "">("");
  const [draft, setDraft] = useState("");
  const [kind, setKind] = useState("");
  const kindInvalid = draft !== "" && !KIND_RE.test(draft);
  const pager = useCursorPager(`${status}|${kind}`);
  const list = useJobList({ status: status || undefined, kind: kind || undefined, cursor: pager.cursor });

  return (
    <Page title={t("platform.jobs.title")}>
      <form
        role="search"
        aria-label={t("platform.jobs.filters")}
        className="mb-4 flex flex-wrap items-end gap-3"
        onSubmit={(e) => {
          e.preventDefault();
          if (!kindInvalid) setKind(draft);
        }}
      >
        <div>
          <label htmlFor="job-kind" className="label">
            {t("platform.jobs.kind")}
          </label>
          <input
            id="job-kind"
            className="input font-mono"
            placeholder={t("platform.jobs.kindPlaceholder")}
            value={draft}
            aria-invalid={kindInvalid}
            aria-describedby="job-kind-hint"
            onChange={(e) => {
              setDraft(e.target.value.trim());
            }}
          />
          <p id="job-kind-hint" className={kindInvalid ? "field-error" : "hint"}>
            {t("platform.jobs.kindHint")}
          </p>
        </div>
        <div>
          <label htmlFor="job-status" className="label">
            {t("platform.jobs.status")}
          </label>
          <select
            id="job-status"
            className="select"
            value={status}
            onChange={(e) => {
              setStatus(isJobStatus(e.target.value) ? e.target.value : "");
            }}
          >
            <option value="">{t("common.all")}</option>
            {JOB_STATUSES.map((s) => (
              <option key={s} value={s}>
                {t(`status.job.${s}`)}
              </option>
            ))}
          </select>
        </div>
        <button type="submit" className="btn-secondary" disabled={kindInvalid}>
          {t("common.search")}
        </button>
      </form>
      <QueryBlock query={list}>
        {(data) =>
          data.items.length === 0 ? (
            <EmptyState>{status || kind ? t("platform.jobs.emptyFiltered") : t("platform.jobs.empty")}</EmptyState>
          ) : (
            <>
              <JobTable jobs={data.items} showTenant caption={t("platform.jobs.caption")} />
              <Pager pager={pager} nextCursor={data.next_cursor} label={t("platform.jobs.pagination")} />
            </>
          )
        }
      </QueryBlock>
    </Page>
  );
}
