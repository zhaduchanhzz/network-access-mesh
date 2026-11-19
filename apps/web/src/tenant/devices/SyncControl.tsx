// Đồng bộ sổ thiết bị (P4-T04): POST /tenants/{t}/devices/sync (CSRF + Idempotency-Key) ⇒ 202 Job + Location; poll
// GET /tenants/{t}/jobs/{id} tới khi xong rồi làm mới danh sách và dashboard. Chỉ role có tenant.device:sync (§8.6).
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { api, callWithResponse } from "../../api/client";
import { queryKeys } from "../../api/queryClient";
import { ProblemAlert } from "../../components/ProblemAlert";
import { useIdempotencyKey } from "../../api/idempotency";
import { isSettled, tenantJobFromLocation, useTenantJob } from "../../api/jobs";
import { StatusBadge } from "../../ui/Status";
import { useTenant } from "../TenantScope";

export function SyncControl() {
  const { t } = useTranslation();
  const { tenantId, readOnly } = useTenant();
  const queryClient = useQueryClient();
  const key = useIdempotencyKey();
  const [jobId, setJobId] = useState<string | null>(null);
  const sync = useMutation({
    mutationFn: () =>
      callWithResponse(
        api.POST("/tenants/{tenantId}/devices/sync", { params: { path: { tenantId }, header: { "Idempotency-Key": key.current() } } }),
      ),
    onSuccess: ({ data, response }) => {
      key.reset();
      setJobId(tenantJobFromLocation(response.headers.get("Location"), tenantId) ?? data.id);
    },
  });
  const job = useTenantJob(tenantId, jobId);
  const status = job.data?.status;
  const done = isSettled(status);

  useEffect(() => {
    if (status === "succeeded") {
      void queryClient.invalidateQueries({ queryKey: queryKeys.tenant(tenantId, "devices") });
      void queryClient.invalidateQueries({ queryKey: queryKeys.tenant(tenantId, "dashboard") });
    }
  }, [status, queryClient, tenantId]);

  const running = sync.isPending || (jobId !== null && !done && !job.isError);
  return (
    <div className="flex flex-col items-end gap-2">
      <button type="button" className="btn-secondary" disabled={readOnly || running} onClick={() => sync.mutate()}>
        {t("devices.sync.action")}
      </button>
      <div aria-live="polite" className="text-sm">
        {jobId !== null && status ? (
          <span data-testid="sync-status">
            <StatusBadge tone={status === "succeeded" ? "ok" : done ? "danger" : "warn"}>{t(`jobs.status.${status}`)}</StatusBadge>
            {job.data?.error ? <code className="ms-2">{job.data.error.code}</code> : null}
          </span>
        ) : null}
      </div>
      {sync.isError ? <ProblemAlert error={sync.error} /> : null}
      {job.isError ? <ProblemAlert error={job.error} /> : null}
    </div>
  );
}
