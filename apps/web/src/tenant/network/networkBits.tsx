// Mảnh nhỏ chỉ dùng cho ba màn hình mạng của Tenant Portal (P4-T12): lỗi 422 theo field, dòng trạng thái job (poll bằng
// api/jobs.ts — chỉ báo "đã áp dụng" khi job `succeeded`), khung báo đã tạo yêu cầu phê duyệt (202 khi tenant bật
// 4-eyes). Hạ tầng chung (client, idempotency, etag, jobs, ConfirmDialog…) không nhân bản ở đây.
import { useEffect, useRef } from "react";
import { useTranslation } from "react-i18next";
import { useTenantJob, isSettled } from "../../api/jobs";
import { ApiError } from "../../api/problem";
import { ProblemAlert } from "../../components/ProblemAlert";
import { StatusBadge } from "../../ui/Status";
import { Timestamp } from "../../ui/time";
import type { components } from "../../api/schema";

export type ApprovalRequest = components["schemas"]["ApprovalRequest"];

/** Lỗi 422 `validation_failed` theo field (`field`, `field[i]`, `field.x`) ⇒ câu hiển thị cạnh ô nhập: bản dịch theo mã
 * (`network.fieldErrors.<code>`) nếu có, nếu không là `message` của server (không bao giờ chứa secret — §13.1). */
export function useFieldErrors(error: unknown): (field: string) => string | undefined {
  const { t, i18n } = useTranslation();
  const errors = error instanceof ApiError && error.code === "validation_failed" ? (error.problem?.errors ?? []) : [];
  return (field) => {
    const e = errors.find((f) => f.field === field || f.field.startsWith(`${field}[`) || f.field.startsWith(`${field}.`));
    if (!e) return undefined;
    const key = `network.fieldErrors.${e.code}`;
    return i18n.exists(key) ? t(key) : e.message;
  };
}

/** Lỗi cần hiện ở khung chung: mọi lỗi, trừ 422 mà mọi field lỗi đã hiện cạnh ô nhập của form (`fields`). */
export function formLevelError(error: unknown, fields: readonly string[]): unknown {
  if (!(error instanceof ApiError) || error.code !== "validation_failed") return error;
  const errs = error.problem?.errors ?? [];
  const shown = (f: string) => fields.some((n) => f === n || f.startsWith(`${n}[`) || f.startsWith(`${n}.`));
  return errs.length > 0 && errs.every((e) => shown(e.field)) ? null : error;
}

/** Thuộc tính ARIA của một ô nhập có thể mang lỗi field. */
export function invalidProps(id: string, message: string | undefined, hintId?: string) {
  const describedBy = [message ? `${id}-err` : null, hintId ?? null].filter(Boolean).join(" ");
  return { "aria-invalid": message !== undefined, "aria-describedby": describedBy || undefined };
}

export function FieldError({ id, message }: { id: string; message: string | undefined }) {
  if (!message) return null;
  return (
    <p id={`${id}-err`} className="field-error" data-testid={`${id}-err`}>
      {message}
    </p>
  );
}

/**
 * Trạng thái một job phạm vi tenant (poll tới trạng thái cuối). `onSucceeded` chạy đúng một lần khi job `succeeded`
 * (làm mới dữ liệu đọc). Chữ "đã áp dụng" chỉ xuất hiện khi job thành công — trước đó là "đang áp dụng".
 */
export function JobProgress({
  tenantId,
  jobId,
  label,
  doneText,
  onSucceeded,
  testId,
}: {
  tenantId: string;
  jobId: string;
  label: string;
  doneText: string;
  onSucceeded?: () => void;
  testId: string;
}) {
  const { t } = useTranslation();
  const job = useTenantJob(tenantId, jobId);
  const status = job.data?.status;
  const fired = useRef(false);
  const succeeded = status === "succeeded";
  useEffect(() => {
    if (succeeded && !fired.current) {
      fired.current = true;
      onSucceeded?.();
    }
  }, [succeeded, onSucceeded]);
  if (job.isError) return <ProblemAlert error={job.error} />;
  const settled = isSettled(status);
  return (
    <div role="status" className="mt-2 text-sm" data-testid={testId} data-job-status={status ?? "loading"}>
      <span className="font-medium">{label}</span>{" "}
      {status ? (
        <StatusBadge tone={succeeded ? "ok" : settled ? "danger" : "warn"}>{t(`jobs.status.${status}`)}</StatusBadge>
      ) : (
        <span className="text-muted">{t("common.loading")}</span>
      )}
      <span className="ms-2">{succeeded ? doneText : settled ? t("network.job.failed") : t("network.job.inProgress")}</span>
      {job.data?.error ? <code className="ms-2">{job.data.error.code}</code> : null}
    </div>
  );
}

/** 202 của thao tác cần người thứ hai (tenant bật 4-eyes): CHƯA thay đổi gì — đã tạo yêu cầu phê duyệt. Màn hình phê
 * duyệt phía tenant thuộc P4-T13: ở đây hiện mã yêu cầu, trạng thái và hạn để người thứ hai tra cứu. */
export function ApprovalCreated({ approval, onDismiss }: { approval: { id: string; data: ApprovalRequest }; onDismiss: () => void }) {
  const { t } = useTranslation();
  return (
    <div role="status" className="mb-4 rounded-md border border-line bg-surface p-4 text-sm" data-testid="approval-created">
      <p className="font-semibold">{t("network.approval.title")}</p>
      <p className="mt-1">{t("network.approval.description")}</p>
      <dl className="mt-2 grid gap-x-4 gap-y-1 md:grid-cols-[max-content_1fr]">
        <dt className="text-muted">{t("network.approval.id")}</dt>
        <dd>
          <code data-testid="approval-id">{approval.id}</code>
        </dd>
        <dt className="text-muted">{t("network.approval.status")}</dt>
        <dd>
          <StatusBadge status={approval.data.status}>{t(`status.approval.${approval.data.status}`)}</StatusBadge>
        </dd>
        <dt className="text-muted">{t("network.approval.expires")}</dt>
        <dd>
          <Timestamp iso={approval.data.expires_at} />
        </dd>
      </dl>
      <button type="button" className="btn-secondary mt-3" onClick={onDismiss}>
        {t("common.dismiss")}
      </button>
    </div>
  );
}
