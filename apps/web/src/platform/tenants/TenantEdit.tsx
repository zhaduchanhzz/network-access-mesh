// Sửa tenant (§12.2 "Quota — Plan + override theo tenant"; §8.5 platform.tenant:update): PATCH /platform/tenants/{id}
// với If-Match = ETag giữ từ chi tiết tenant (P4-T02) — tên, gói (danh sách gói đang mở — GET /platform/plans), override
// hạn mức. API chỉ trả hạn mức HIỆU LỰC (gói + override), không trả riêng override ⇒ override chỉ gửi khi người dùng chọn
// "thay toàn bộ override" (giá trị gửi thay tài liệu override; để trống mọi ô = `{}` gỡ hết). 412 ⇒ bản mới được tải lại.
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { api, call } from "../../api/client";
import { ifMatch, isStaleVersion } from "../../api/etag";
import { can } from "../../auth/permissions";
import { CheckboxField, SelectField, TextField } from "../../ui/Form";
import { FormDialog } from "../../ui/FormDialog";
import { invalidatePlatform, type Tenant } from "../api";
import { usePlans, type PlanLimits } from "../opsApi";
import { LimitsFields } from "../plans/PlansPage";
import { checkPlanLimits, fieldOfLimitError, limitsFormOf, limitsOf, type LimitsForm } from "../plans/planForm";

type Body = { name?: string; plan_key?: string; limits_override?: PlanLimits };

export function TenantEdit({ tenant, etag, role }: { tenant: Tenant; etag: string | null; role: string | null }) {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  if (!can(role, "platform.tenant:update") || tenant.status === "deleted" || tenant.status === "deprovisioning") return null;
  return (
    <>
      <button
        type="button"
        className="btn-secondary"
        onClick={() => {
          setOpen(true);
        }}
      >
        {t("platform.tenantEdit.edit")}
      </button>
      {open ? (
        <EditDialog
          tenant={tenant}
          etag={etag}
          canListPlans={can(role, "platform.plan:read")}
          onClose={() => {
            setOpen(false);
          }}
        />
      ) : null}
    </>
  );
}

function EditDialog({ tenant, etag, canListPlans, onClose }: { tenant: Tenant; etag: string | null; canListPlans: boolean; onClose: () => void }) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const plans = usePlans(canListPlans);
  const [name, setName] = useState(tenant.name);
  const [plan, setPlan] = useState(tenant.plan);
  const [override, setOverride] = useState(false);
  const [limits, setLimits] = useState<LimitsForm>(() => limitsFormOf(undefined));
  const [tried, setTried] = useState(false);
  const save = useMutation({
    mutationFn: (body: Body) =>
      call(api.PATCH("/platform/tenants/{tenantId}", { params: { path: { tenantId: tenant.id }, header: ifMatch(etag) }, body })),
    onSuccess: async () => {
      await Promise.all([invalidatePlatform(queryClient, "tenant", tenant.id), invalidatePlatform(queryClient, "tenants")]);
      onClose();
    },
    onError: async (e) => {
      if (isStaleVersion(e)) await invalidatePlatform(queryClient, "tenant", tenant.id);
    },
  });
  const overrideValue = limitsOf(limits);
  const limitError = override ? checkPlanLimits(overrideValue, true) : "";
  const nameBad = name.trim() === "" || name.length > 128;
  const body: Body = {
    ...(name.trim() !== tenant.name ? { name: name.trim() } : {}),
    ...(plan !== tenant.plan && plan !== "" ? { plan_key: plan } : {}),
    ...(override ? { limits_override: overrideValue } : {}),
  };
  const open = (plans.data?.items ?? []).filter((p) => p.is_active || p.key === tenant.plan);
  return (
    <FormDialog
      isOpen
      onOpenChange={(o) => {
        if (!o) onClose();
      }}
      title={t("platform.tenantEdit.title", { slug: tenant.slug })}
      description={<p>{t("platform.tenantEdit.desc")}</p>}
      submitLabel={t("platform.tenantEdit.save")}
      canSubmit={Object.keys(body).length > 0}
      pending={save.isPending}
      error={save.error}
      onSubmit={() => {
        setTried(true);
        if (!nameBad && limitError === "") save.mutate(body);
      }}
    >
      <TextField label={t("platform.tenantCreate.name")} value={name} onChange={setName} error={tried && nameBad ? t("platform.tenantCreate.errors.name") : undefined} maxLength={128} autoFocus />
      {canListPlans && open.length > 0 ? (
        <SelectField
          label={t("platform.tenantCreate.plan")}
          value={plan}
          onChange={setPlan}
          options={open.map((p) => ({ value: p.key, label: `${p.key} — ${p.name}` }))}
        />
      ) : (
        <TextField label={t("platform.tenantCreate.plan")} hint={t("platform.tenantCreate.planHint")} value={plan} onChange={setPlan} mono />
      )}
      <CheckboxField label={t("platform.tenantEdit.override")} hint={t("platform.tenantEdit.overrideHint")} checked={override} onChange={setOverride} />
      {override ? <LimitsFields form={limits} onChange={setLimits} errorField={tried && limitError ? fieldOfLimitError(limitError) : null} required={false} /> : null}
    </FormDialog>
  );
}
