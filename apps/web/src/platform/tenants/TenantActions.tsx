// Thao tác vòng đời trên chi tiết tenant (§11.4, §8.5): suspend/resume (platform.tenant:suspend — job, theo dõi ở
// timeline) và xin xóa (platform.tenant:delete — LUÔN 2P: người yêu cầu step-up + gõ lại slug + lý do ⇒ 202 + Location
// của yêu cầu phê duyệt; người thứ hai duyệt ở hàng chờ). Nút chỉ hiện theo role và trạng thái (UX); server quyết định
// (trạng thái, job vòng đời đang chạy ⇒ 409, step-up ⇒ 401 reauth_required, slug sai ⇒ 422).
import { useQueryClient } from "@tanstack/react-query";
import { useId, useState } from "react";
import { useTranslation } from "react-i18next";
import { useNavigate } from "react-router";
import { api, callWithResponse } from "../../api/client";
import { useIdempotentMutation } from "../../api/idempotency";
import { approvalFromLocation, jobFromLocation } from "../../api/jobs";
import { can } from "../../auth/permissions";
import { ConfirmDialog } from "../../ui/ConfirmDialog";
import { invalidatePlatform, type Tenant } from "../api";

type Dialog = "suspend" | "resume" | "delete" | null;

export function TenantActions({ tenant, role }: { tenant: Tenant; role: string | null }) {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [open, setOpen] = useState<Dialog>(null);
  const [reason, setReason] = useState("");
  const [skipBackup, setSkipBackup] = useState(false);
  const reasonId = useId();
  const skipId = useId();

  const refresh = () => Promise.all([invalidatePlatform(queryClient, "tenant", tenant.id), invalidatePlatform(queryClient, "tenants"), invalidatePlatform(queryClient, "jobs")]);
  const toJob = (location: string | null, fallback: string) => {
    void navigate(`/platform/jobs/${jobFromLocation(location)?.jobId ?? fallback}`);
  };

  const lifecycle = useIdempotentMutation({
    fingerprint: (action: "suspend" | "resume") => `${tenant.id}:${action}`,
    mutationFn: (action: "suspend" | "resume", key: string) => {
      const params = { path: { tenantId: tenant.id }, header: { "Idempotency-Key": key } };
      return callWithResponse(
        action === "suspend"
          ? api.POST("/platform/tenants/{tenantId}/suspend", { params })
          : api.POST("/platform/tenants/{tenantId}/resume", { params }),
      );
    },
    onSuccess: async (r) => {
      setOpen(null);
      await refresh();
      toJob(r.response.headers.get("Location"), r.data.id);
    },
  });

  const remove = useIdempotentMutation({
    mutationFn: (body: { confirm_slug: string; reason: string; skip_final_backup: boolean }, key: string) =>
      callWithResponse(
        api.DELETE("/platform/tenants/{tenantId}", {
          params: { path: { tenantId: tenant.id }, header: { "Idempotency-Key": key } },
          body,
        }),
      ),
    onSuccess: async (r) => {
      setOpen(null);
      await Promise.all([refresh(), invalidatePlatform(queryClient, "approvals")]);
      const id = approvalFromLocation(r.response.headers.get("Location")) ?? r.data.id;
      void navigate(`/platform/approvals/${id}`, { state: { requested: true } });
    },
  });

  const canSuspend = can(role, "platform.tenant:suspend");
  const canDelete = can(role, "platform.tenant:delete");
  const showSuspend = canSuspend && tenant.status === "active";
  const showResume = canSuspend && tenant.status === "suspended";
  const showDelete = canDelete && (tenant.status === "active" || tenant.status === "suspended" || tenant.status === "failed");
  if (!showSuspend && !showResume && !showDelete) return null;

  const close = (o: boolean) => {
    if (!o) {
      setOpen(null);
      lifecycle.reset();
      remove.reset();
      setReason("");
      setSkipBackup(false);
    }
  };

  return (
    <div className="flex flex-wrap gap-2" role="group" aria-label={t("platform.tenantDetail.actions")}>
      {showSuspend ? (
        <button type="button" className="btn-secondary" onClick={() => { setOpen("suspend"); }}>
          {t("platform.tenantDetail.suspend")}
        </button>
      ) : null}
      {showResume ? (
        <button type="button" className="btn-secondary" onClick={() => { setOpen("resume"); }}>
          {t("platform.tenantDetail.resume")}
        </button>
      ) : null}
      {showDelete ? (
        <button type="button" className="btn-danger" onClick={() => { setOpen("delete"); }}>
          {t("platform.tenantDetail.delete")}
        </button>
      ) : null}

      <ConfirmDialog
        isOpen={open === "suspend" || open === "resume"}
        onOpenChange={close}
        title={open === "resume" ? t("platform.tenantDetail.resumeTitle", { slug: tenant.slug }) : t("platform.tenantDetail.suspendTitle", { slug: tenant.slug })}
        description={<p>{open === "resume" ? t("platform.tenantDetail.resumeDesc") : t("platform.tenantDetail.suspendDesc")}</p>}
        confirmLabel={open === "resume" ? t("platform.tenantDetail.resume") : t("platform.tenantDetail.suspend")}
        destructive={open === "suspend"}
        pending={lifecycle.isPending}
        error={lifecycle.error}
        onConfirm={() => {
          if (open === "suspend" || open === "resume") lifecycle.mutate(open);
        }}
      />

      <ConfirmDialog
        isOpen={open === "delete"}
        onOpenChange={close}
        title={t("platform.tenantDetail.deleteTitle", { slug: tenant.slug })}
        description={
          <div className="space-y-2">
            <p>{t("platform.tenantDetail.deleteDesc")}</p>
            <p className="font-medium">{t("platform.tenantDetail.deleteTwoPerson")}</p>
          </div>
        }
        confirmLabel={t("platform.tenantDetail.deleteConfirm")}
        destructive
        typedConfirmation={{ expected: tenant.slug, label: t("platform.tenantDetail.typeSlug") }}
        canConfirm={reason.trim().length > 0}
        pending={remove.isPending}
        error={remove.error}
        onConfirm={() => {
          remove.mutate({ confirm_slug: tenant.slug, reason: reason.trim(), skip_final_backup: skipBackup });
        }}
      >
        <div>
          <label htmlFor={reasonId} className="label">
            {t("platform.tenantDetail.reason")}
          </label>
          <textarea
            id={reasonId}
            className="input"
            rows={3}
            maxLength={1000}
            value={reason}
            onChange={(e) => {
              setReason(e.target.value);
            }}
          />
        </div>
        <div className="flex items-start gap-2">
          <input
            id={skipId}
            type="checkbox"
            checked={skipBackup}
            onChange={(e) => {
              setSkipBackup(e.target.checked);
            }}
          />
          <label htmlFor={skipId} className="text-sm">
            {t("platform.tenantDetail.skipBackup")}
          </label>
        </div>
      </ConfirmDialog>
    </div>
  );
}
