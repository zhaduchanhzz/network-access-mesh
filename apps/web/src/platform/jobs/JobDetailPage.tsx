// Job timeline (§12.2 "Tenant wizard → Job timeline — hiển thị từng step; retry/cancel/rollback"): GET
// /platform/jobs/{id} (chi tiết thô đã redaction của từng step + lỗi gốc — chỉ phía platform, §13.3), poll tới trạng thái
// cuối. tenant.provision có danh mục 19 bước (§11.3) ⇒ hiện cả bước chưa chạy. Điều khiển theo §11.3 và quyền
// platform.job:control: cancel (queued/running), retry (failed_resumable; tenant.provision đã rolled_back ⇒ job mới),
// rollback (failed_resumable) — server quyết định (trạng thái khác ⇒ 409, qua điểm không quay lại ⇒ 409).
import { useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Link, useLocation, useNavigate, useParams } from "react-router";
import { api, callWithResponse } from "../../api/client";
import { useIdempotentMutation } from "../../api/idempotency";
import { isSettled, jobFromLocation, plannedSteps, type JobStepStatus, type PlatformJob } from "../../api/jobs";
import { ApiError } from "../../api/problem";
import { isUuid } from "../../api/queryClient";
import { can } from "../../auth/permissions";
import { ConfirmDialog } from "../../ui/ConfirmDialog";
import { Field, JsonBlock } from "../../ui/Data";
import { StatusBadge } from "../../ui/Status";
import { Timestamp } from "../../ui/time";
import { Loading, Page } from "../../components/Page";
import { ProblemAlert } from "../../components/ProblemAlert";
import { NotFoundPage } from "../../pages/StatusPages";
import { invalidatePlatform, useJob } from "../api";
import { usePlatformRole } from "../PlatformScope";

type Step = PlatformJob["steps"][number];
type Row = { name: string; step: Step | null };
type Control = "cancel" | "retry" | "rollback";

/** Bước đã ghi theo thứ tự của danh mục (nếu có), bước chưa chạy ⇒ step null; bước ngoài danh mục giữ nguyên thứ tự. */
export function timelineRows(job: Pick<PlatformJob, "kind" | "steps">): Row[] {
  const planned = plannedSteps(job.kind);
  const byName = new Map<string, Step>();
  for (const s of job.steps) byName.set(s.name, s);
  const rows: Row[] = planned.map((name) => ({ name, step: byName.get(name) ?? null }));
  for (const s of job.steps) if (!planned.includes(s.name)) rows.push({ name: s.name, step: s });
  return rows;
}

export function controlsFor(job: Pick<PlatformJob, "kind" | "status">): Control[] {
  const out: Control[] = [];
  if (job.status === "queued" || job.status === "running") out.push("cancel");
  if (job.status === "failed_resumable" || (job.status === "rolled_back" && job.kind === "tenant.provision")) out.push("retry");
  if (job.status === "failed_resumable") out.push("rollback");
  return out;
}

export function JobDetailPage() {
  const { jobId: raw = "" } = useParams();
  const jobId = raw.toLowerCase();
  if (!isUuid(jobId)) return <NotFoundPage />;
  return <JobDetail key={jobId} jobId={jobId} />;
}

function JobDetail({ jobId }: { jobId: string }) {
  const { t } = useTranslation();
  const role = usePlatformRole();
  const location = useLocation();
  const [since] = useState(Date.now);
  const job = useJob(jobId, since);
  const createdTenant = (location.state as { createdTenant?: string } | null)?.createdTenant;

  if (job.isPending) return <Loading />;
  if (job.isError) {
    if (job.error instanceof ApiError && job.error.status === 404) return <NotFoundPage />;
    return (
      <Page title={t("platform.job.title")}>
        <ProblemAlert error={job.error} onRetry={() => void job.refetch()} />
      </Page>
    );
  }
  const j = job.data;
  const rows = timelineRows(j);
  const done = rows.filter((r) => r.step?.status === "succeeded" || r.step?.status === "skipped").length;
  const settled = isSettled(j.status);

  return (
    <Page title={t("platform.job.titleKind", { kind: j.kind })} actions={can(role, "platform.job:control") ? <JobControls job={j} /> : null}>
      <p className="mb-4">
        <Link to="/platform/jobs" className="link text-sm">
          {t("platform.job.back")}
        </Link>
      </p>
      {createdTenant ? (
        <div role="status" className="banner banner-warn mb-4" data-testid="tenant-created">
          <p>{t("platform.job.tenantCreated")}</p>
          <Link to={`/platform/tenants/${createdTenant}`} className="link">
            {t("platform.job.openTenant")}
          </Link>
        </div>
      ) : null}

      <div className="card mb-6">
        <dl className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          <Field label={t("platform.jobs.col.status")}>
            <StatusBadge status={j.status}>{t(`status.job.${j.status}`)}</StatusBadge>
          </Field>
          <Field label={t("platform.jobs.col.kind")}>
            <code>{j.kind}</code>
          </Field>
          <Field label={t("platform.jobs.col.tenant")}>
            {j.tenant_id ? (
              <Link to={`/platform/tenants/${j.tenant_id}`} className="link font-mono text-xs">
                {j.tenant_id}
              </Link>
            ) : (
              t("platform.jobs.platformJob")
            )}
          </Field>
          <Field label={t("platform.jobs.col.step")}>{j.current_step ? <code>{j.current_step}</code> : t("common.none")}</Field>
          <Field label={t("platform.jobs.col.created")}>
            <Timestamp iso={j.created_at} emptyKey="common.none" />
          </Field>
          <Field label={t("platform.job.resource")}>
            {j.resource ? <code className="text-xs">{`${j.resource.type}:${j.resource.id}`}</code> : t("common.none")}
          </Field>
          <Field label={t("platform.job.id")}>
            <code className="text-xs">{j.id}</code>
          </Field>
        </dl>
        <p role="status" className="mt-3 text-sm text-muted" data-testid="poll-status">
          {settled ? t("platform.job.settled") : t("platform.job.polling")}
        </p>
      </div>

      {j.error ? (
        <section aria-labelledby="job-error" className="mb-6 rounded-md border border-danger/40 bg-danger-bg p-4">
          <h2 id="job-error" className="font-semibold text-danger">
            {t("platform.job.error", { code: j.error.code })}
          </h2>
          {j.error.message ? <p className="mt-1 text-sm">{j.error.message}</p> : null}
          {j.error.detail ? (
            <div className="mt-2">
              <JsonBlock value={j.error.detail} />
            </div>
          ) : null}
        </section>
      ) : null}

      <section aria-labelledby="job-steps">
        <h2 id="job-steps" className="mb-1 text-lg font-semibold">
          {t("platform.job.steps")}
        </h2>
        {rows.length > 0 && plannedSteps(j.kind).length > 0 ? (
          <p className="mb-3 text-sm text-muted" data-testid="progress">
            {t("platform.job.progress", { done, total: rows.length })}
          </p>
        ) : null}
        {rows.length === 0 ? (
          <p className="text-sm text-muted">{t("platform.job.noSteps")}</p>
        ) : (
          <ol className="space-y-2" aria-label={t("platform.job.timeline")}>
            {rows.map((r, i) => (
              <StepItem key={`${r.name}:${String(i)}`} index={i + 1} row={r} current={j.current_step === r.name} kind={j.kind} />
            ))}
          </ol>
        )}
      </section>
    </Page>
  );
}

function StepItem({ index, row, current, kind }: { index: number; row: Row; current: boolean; kind: string }) {
  const { t } = useTranslation();
  const s = row.step;
  const status: JobStepStatus | "pending" = s?.status ?? "pending";
  const label = kind === "tenant.provision" ? t(`platform.steps.provision.${row.name.replaceAll(".", "_")}`, { defaultValue: "" }) : "";
  return (
    <li
      className={`rounded-md border p-3 ${current ? "border-accent" : "border-line"} bg-surface`}
      aria-current={current ? "step" : undefined}
      data-step={row.name}
      data-step-status={status}
    >
      <div className="flex flex-wrap items-center gap-2">
        <span className="w-6 text-right text-xs text-muted tabular-nums">{index}</span>
        <code className="font-medium">{row.name}</code>
        {label ? <span className="text-sm text-muted">{label}</span> : null}
        <StatusBadge status={status}>{t(`status.step.${status}`)}</StatusBadge>
        {s?.compensation_status ? (
          <StatusBadge status={s.compensation_status}>{t("platform.job.compensation", { status: t(`status.step.${s.compensation_status}`) })}</StatusBadge>
        ) : null}
      </div>
      {s ? (
        <div className="mt-2 space-y-1 ps-8 text-sm">
          <p className="text-muted">
            {t("platform.job.attempt", { n: s.attempt })}
            {" · "}
            {t("platform.job.started")} <Timestamp iso={s.started_at} emptyKey="common.none" />
            {" · "}
            {t("platform.job.finished")} <Timestamp iso={s.finished_at} emptyKey="common.none" />
          </p>
          {s.message ? <p>{s.message}</p> : null}
          {s.detail && Object.keys(s.detail).length > 0 ? (
            <details>
              <summary className="cursor-pointer text-sm text-accent">{t("platform.job.detail")}</summary>
              <div className="mt-2">
                <JsonBlock value={s.detail} />
              </div>
            </details>
          ) : null}
        </div>
      ) : null}
    </li>
  );
}

function JobControls({ job }: { job: PlatformJob }) {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [open, setOpen] = useState<Control | null>(null);
  const control = useIdempotentMutation({
    fingerprint: (c: Control) => `${job.id}:${c}`,
    mutationFn: (c: Control, key: string) => {
      const params = { path: { jobId: job.id }, header: { "Idempotency-Key": key } };
      return callWithResponse(
        c === "cancel"
          ? api.POST("/platform/jobs/{jobId}/cancel", { params })
          : c === "retry"
            ? api.POST("/platform/jobs/{jobId}/retry", { params })
            : api.POST("/platform/jobs/{jobId}/rollback", { params }),
      );
    },
    onSuccess: async (r) => {
      setOpen(null);
      const next = jobFromLocation(r.response.headers.get("Location"))?.jobId ?? r.data.id;
      await Promise.all([
        invalidatePlatform(queryClient, "job", job.id),
        invalidatePlatform(queryClient, "jobs"),
        invalidatePlatform(queryClient, "tenant"),
      ]);
      if (next !== job.id) void navigate(`/platform/jobs/${next}`);
    },
  });
  const controls = controlsFor(job);
  if (controls.length === 0) return null;
  return (
    <div className="flex flex-wrap gap-2" role="group" aria-label={t("platform.job.controls")}>
      {controls.map((c) => (
        <button
          key={c}
          type="button"
          className={c === "retry" ? "btn-primary" : "btn-secondary"}
          onClick={() => {
            setOpen(c);
          }}
        >
          {t(`platform.job.control.${c}`)}
        </button>
      ))}
      <ConfirmDialog
        isOpen={open !== null}
        onOpenChange={(o) => {
          if (!o) {
            setOpen(null);
            control.reset();
          }
        }}
        title={open ? t(`platform.job.control.${open}Title`, { kind: job.kind }) : ""}
        description={<p>{open ? t(`platform.job.control.${open}Desc`) : null}</p>}
        confirmLabel={open ? t(`platform.job.control.${open}`) : ""}
        destructive={open === "cancel" || open === "rollback"}
        pending={control.isPending}
        error={control.error}
        onConfirm={() => {
          if (open) control.mutate(open);
        }}
      />
    </div>
  );
}
