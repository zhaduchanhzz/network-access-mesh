// Trạng thái áp dụng (P4-T11, §7.3): "đã áp dụng lên Headscale lúc …" (lần áp hiện hành — GetPolicy đọc lại khớp
// applied_sha256) tách bạch với "client đã hội tụ" (không quan sát được — T-18); lần áp gần nhất nếu khác (pending,
// failed, unknown); job policy.apply của một thao tác apply/rollback (202) poll tới trạng thái cuối.
import { useQueryClient } from "@tanstack/react-query";
import { useEffect } from "react";
import { useTranslation } from "react-i18next";
import { Link } from "react-router";
import { isSettled, useTenantJob } from "../../api/jobs";
import { ProblemAlert } from "../../components/ProblemAlert";
import { StatusBadge } from "../../ui/Status";
import { Timestamp } from "../../ui/time";
import { useTenant } from "../TenantScope";
import { policyKeys } from "./api";
import { shortSha, type PolicyApplication, type PolicyCurrent } from "./model";

function Application({ a, testId }: { a: PolicyApplication; testId: string }) {
  const { t } = useTranslation();
  const { tenantId } = useTenant();
  return (
    <div className="space-y-1 text-sm" data-testid={testId} data-state={a.state} data-sha={a.applied_sha256}>
      <p className="flex flex-wrap items-center gap-2">
        <StatusBadge status={a.state === "applied" ? "succeeded" : a.state}>{t(`policies.applied.states.${a.state}`)}</StatusBadge>
        <span>{t(`policies.applied.triggers.${a.trigger}`)}</span>
        <Link className="link" to={`/t/${tenantId}/policies/${a.policy_version_id}`}>
          {t("policies.applied.version")}
        </Link>
      </p>
      {a.state === "applied" ? (
        <p>
          {t("policies.applied.at")} <Timestamp iso={a.headscale_updated_at ?? a.finished_at ?? a.created_at} />
        </p>
      ) : null}
      <p>
        {t("policies.applied.sha")}{" "}
        <code title={a.applied_sha256} data-testid={`${testId}-sha`}>
          {shortSha(a.applied_sha256)}
        </code>
      </p>
      {a.error_code ? (
        <p className="text-danger">
          {t("policies.applied.error")} <code>{a.error_code}</code>
        </p>
      ) : null}
    </div>
  );
}

export function CurrentPanel({ current }: { current: PolicyCurrent }) {
  const { t } = useTranslation();
  const { tenantId } = useTenant();
  const { desired, applied, latest } = current;
  return (
    <section className="card space-y-3" aria-labelledby="pol-current" data-testid="policy-current">
      <h2 id="pol-current" className="font-semibold">
        {t("policies.current.title")}
      </h2>
      <dl className="grid gap-x-6 gap-y-2 text-sm md:grid-cols-[max-content_1fr]">
        <dt className="text-muted">{t("policies.current.desired")}</dt>
        <dd data-testid="current-desired">
          {desired ? (
            <Link className="link" to={`/t/${tenantId}/policies/${desired.id}`}>
              {t("policies.versionN", { n: desired.version })}
            </Link>
          ) : (
            t("policies.current.noDesired")
          )}
        </dd>
        <dt className="text-muted">{t("policies.current.applied")}</dt>
        <dd>{applied ? <Application a={applied} testId="current-applied" /> : t("policies.current.notApplied")}</dd>
        {latest && latest.id !== applied?.id ? (
          <>
            <dt className="text-muted">{t("policies.current.latest")}</dt>
            <dd>
              <Application a={latest} testId="current-latest" />
            </dd>
          </>
        ) : null}
        <dt className="text-muted">{t("policies.current.converged")}</dt>
        <dd className="text-muted">{t("policies.current.convergedUnknown")}</dd>
        <dt className="text-muted">{t("policies.current.review")}</dt>
        <dd className="flex flex-wrap gap-2" data-testid="current-review">
          <StatusBadge tone={current.four_eyes ? "info" : "neutral"}>{t(current.four_eyes ? "policies.current.fourEyesOn" : "policies.current.fourEyesOff")}</StatusBadge>
          {current.apply_step_up ? <StatusBadge tone="warn">{t("policies.current.stepUp")}</StatusBadge> : null}
        </dd>
      </dl>
    </section>
  );
}

/** Job policy.apply của một apply/rollback: poll tới trạng thái cuối rồi làm mới trạng thái áp dụng + danh sách. */
export function ApplyJobPanel({ jobId }: { jobId: string }) {
  const { t } = useTranslation();
  const { tenantId } = useTenant();
  const queryClient = useQueryClient();
  const job = useTenantJob(tenantId, jobId);
  const status = job.data?.status;
  useEffect(() => {
    if (isSettled(status)) void queryClient.invalidateQueries({ queryKey: policyKeys.all(tenantId) });
  }, [status, queryClient, tenantId]);
  return (
    <section className="card space-y-2" aria-labelledby="pol-job" data-testid="apply-job" data-status={status}>
      <h2 id="pol-job" className="font-semibold">
        {t("policies.job.title")}
      </h2>
      {job.isError ? <ProblemAlert error={job.error} onRetry={() => void job.refetch()} /> : null}
      {job.data ? (
        <div aria-live="polite" className="space-y-2 text-sm">
          <p className="flex flex-wrap items-center gap-2">
            <StatusBadge status={job.data.status}>{t(`jobs.status.${job.data.status}`)}</StatusBadge>
            <code>{job.data.id}</code>
            <span className="text-muted">{isSettled(status) ? t("policies.job.final") : t("policies.job.polling")}</span>
          </p>
          {job.data.steps.length > 0 ? (
            <ol className="list-decimal ps-5" aria-label={t("policies.job.steps")}>
              {job.data.steps.map((s) => (
                <li key={s.name} data-step-status={s.status}>
                  <code>{s.name}</code> <StatusBadge status={s.status}>{t(`status.step.${s.status}`)}</StatusBadge>
                </li>
              ))}
            </ol>
          ) : null}
          {job.data.error ? (
            <p className="text-danger">
              {t("policies.applied.error")}{" "}
              <span className="text-xs" data-code={job.data.error.code}>
                {t("ui.jobErrorCode", { code: job.data.error.code })}
              </span>
            </p>
          ) : null}
          {status === "succeeded" ? <p data-testid="apply-done">{t("policies.job.succeeded")}</p> : null}
        </div>
      ) : null}
    </section>
  );
}
