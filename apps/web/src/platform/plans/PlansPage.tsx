// Gói dịch vụ (§12.2 "Billing & usage — Plans", "Quota — Plan + override theo tenant"; §8.5 platform.plan:read /
// :manage): GET /platform/plans (kèm số tenant đang dùng), POST (Idempotency-Key) và PATCH (If-Match) — chỉ Super Admin.
// `key` bất biến; limits theo PlanLimits, đủ bốn khóa quota (checkPlanLimits — mirror của backend); gói đóng không nhận
// tenant mới, tenant đang dùng giữ gói. Hạn mức mới có hiệu lực ở lần kiểm quota kế tiếp.
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { api, call } from "../../api/client";
import { ifMatch } from "../../api/etag";
import { useIdempotentMutation } from "../../api/idempotency";
import { can } from "../../auth/permissions";
import { EmptyState, QueryBlock } from "../../ui/Data";
import { CheckboxField, TextField } from "../../ui/Form";
import { FormDialog } from "../../ui/FormDialog";
import { StatusBadge } from "../../ui/Status";
import { Timestamp } from "../../ui/time";
import { Page } from "../../components/Page";
import { invalidatePlatform } from "../api";
import { usePlans, type Plan, type PlanLimits } from "../opsApi";
import { usePlatformRole } from "../PlatformScope";
import { checkPlanLimits, fieldOfLimitError, LIMIT_FIELDS, limitsFormOf, limitsOf, QUOTA_KEYS, type LimitsForm } from "./planForm";

const PLAN_KEY_RE = /^[a-z][a-z0-9_-]{0,62}$/;

export function PlansPage() {
  const { t } = useTranslation();
  const role = usePlatformRole();
  const q = usePlans();
  const canManage = can(role, "platform.plan:manage");
  const [dialog, setDialog] = useState<{ plan: Plan | null } | null>(null);
  return (
    <Page
      title={t("nav.platform.plans")}
      actions={
        canManage ? (
          <button
            type="button"
            className="btn-primary"
            onClick={() => {
              setDialog({ plan: null });
            }}
          >
            {t("platform.plans.create")}
          </button>
        ) : null
      }
    >
      <p className="mb-4 text-sm text-muted">{t("platform.plans.intro")}</p>
      <QueryBlock query={q}>
        {(data) =>
          data.items.length === 0 ? (
            <EmptyState>{t("platform.plans.empty")}</EmptyState>
          ) : (
            <div className="relative overflow-x-auto rounded-lg border border-line bg-surface">
              <table className="data-table">
                <caption className="sr-only">{t("nav.platform.plans")}</caption>
                <thead>
                  <tr>
                    <th scope="col">{t("platform.plans.col.key")}</th>
                    <th scope="col">{t("platform.plans.col.status")}</th>
                    <th scope="col">{t("platform.plans.col.tenants")}</th>
                    <th scope="col">{t("platform.plans.col.limits")}</th>
                    <th scope="col">{t("platform.plans.col.updated")}</th>
                    {canManage ? <th scope="col">{t("platform.settings.col.actions")}</th> : null}
                  </tr>
                </thead>
                <tbody>
                  {data.items.map((p) => (
                    <tr key={p.id} data-testid="plan-row" data-key={p.key}>
                      <th scope="row" className="font-normal">
                        <code className="font-medium">{p.key}</code>
                        <span className="hint block">{p.name}</span>
                      </th>
                      <td>
                        <StatusBadge tone={p.is_active ? "ok" : "neutral"}>{t(p.is_active ? "platform.plans.open" : "platform.plans.closed")}</StatusBadge>
                      </td>
                      <td>{p.tenant_count === undefined ? t("common.none") : String(p.tenant_count)}</td>
                      <td>
                        <LimitsList limits={p.limits} />
                      </td>
                      <td>
                        <Timestamp iso={p.updated_at} emptyKey="common.none" />
                      </td>
                      {canManage ? (
                        <td>
                          <button
                            type="button"
                            className="btn-secondary"
                            aria-label={t("platform.plans.editLabel", { key: p.key })}
                            onClick={() => {
                              setDialog({ plan: p });
                            }}
                          >
                            {t("platform.plans.edit")}
                          </button>
                        </td>
                      ) : null}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )
        }
      </QueryBlock>
      {dialog ? (
        <PlanDialog
          plan={dialog.plan}
          onClose={() => {
            setDialog(null);
          }}
        />
      ) : null}
    </Page>
  );
}

export function LimitsList({ limits }: { limits: PlanLimits }) {
  const { t } = useTranslation();
  const rows: [string, number][] = [];
  for (const k of [...QUOTA_KEYS, "backup_interval_minutes"] as const) {
    const v = limits[k];
    if (v !== undefined) rows.push([k, v]);
  }
  for (const k of ["cpus", "memory_mb", "pids"] as const) {
    const v = limits.instance?.[k];
    if (v !== undefined) rows.push([k, v]);
  }
  if (rows.length === 0) return <span className="text-muted">{t("platform.tenantDetail.noLimits")}</span>;
  return (
    <ul className="text-xs">
      {rows.map(([k, v]) => (
        <li key={k}>
          {t(`platform.plans.limit.${k}`)}
          {": "}
          <strong>{String(v)}</strong>
        </li>
      ))}
    </ul>
  );
}

/** Ô của giới hạn (dùng chung cho gói và override của tenant). */
export function LimitsFields({ form, onChange, errorField, required }: { form: LimitsForm; onChange: (f: LimitsForm) => void; errorField: keyof LimitsForm | "limits" | null; required: boolean }) {
  const { t } = useTranslation();
  return (
    <fieldset className="grid gap-3 sm:grid-cols-2">
      <legend className="label">{t(required ? "platform.plans.limitsRequired" : "platform.plans.limitsOptional")}</legend>
      {LIMIT_FIELDS.map((k) => (
        <TextField
          key={k}
          label={t(`platform.plans.limit.${k}`)}
          value={form[k]}
          onChange={(v) => {
            onChange({ ...form, [k]: v });
          }}
          error={errorField === k ? t("platform.plans.errors.limit") : undefined}
          numeric={k !== "cpus"}
        />
      ))}
      {errorField === "limits" ? <p className="field-error sm:col-span-2">{t("platform.plans.errors.limits")}</p> : null}
    </fieldset>
  );
}

function PlanDialog({ plan, onClose }: { plan: Plan | null; onClose: () => void }) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [key, setKey] = useState(plan?.key ?? "");
  const [name, setName] = useState(plan?.name ?? "");
  const [active, setActive] = useState(plan?.is_active ?? true);
  const [limits, setLimits] = useState<LimitsForm>(() => limitsFormOf(plan?.limits));
  const [tried, setTried] = useState(false);
  const done = async () => {
    await invalidatePlatform(queryClient, "plans");
    onClose();
  };
  const create = useIdempotentMutation({
    mutationFn: (body: { key: string; name: string; limits: PlanLimits; is_active: boolean }, idem: string) =>
      call(api.POST("/platform/plans", { params: { header: { "Idempotency-Key": idem } }, body })),
    onSuccess: done,
  });
  const update = useMutation({
    mutationFn: (v: { plan: Plan; body: { name?: string; limits?: PlanLimits; is_active?: boolean } }) =>
      call(api.PATCH("/platform/plans/{planId}", { params: { path: { planId: v.plan.id }, header: ifMatch(v.plan.etag) }, body: v.body })),
    onSuccess: done,
    onError: async () => {
      await invalidatePlatform(queryClient, "plans");
    },
  });
  const value = limitsOf(limits);
  const limitError = checkPlanLimits(value, false);
  const keyBad = plan === null && !PLAN_KEY_RE.test(key);
  const nameBad = name.trim() === "" || name.length > 200;
  const valid = !keyBad && !nameBad && limitError === "";
  const m = plan === null ? create : update;
  return (
    <FormDialog
      isOpen
      onOpenChange={(o) => {
        if (!o) onClose();
      }}
      title={plan === null ? t("platform.plans.createTitle") : t("platform.plans.editTitle", { key: plan.key })}
      description={<p>{t(plan === null ? "platform.plans.createDesc" : "platform.plans.editDesc")}</p>}
      submitLabel={t(plan === null ? "platform.plans.create" : "platform.plans.save")}
      pending={m.isPending}
      error={m.error}
      onSubmit={() => {
        setTried(true);
        if (!valid) return;
        if (plan === null) {
          create.mutate({ key, name: name.trim(), limits: value, is_active: active });
          return;
        }
        const body: { name?: string; limits?: PlanLimits; is_active?: boolean } = {};
        if (name.trim() !== plan.name) body.name = name.trim();
        if (JSON.stringify(value) !== JSON.stringify(limitsOf(limitsFormOf(plan.limits)))) body.limits = value;
        if (active !== plan.is_active) body.is_active = active;
        if (Object.keys(body).length === 0) {
          onClose();
          return;
        }
        update.mutate({ plan, body });
      }}
    >
      <TextField
        label={t("platform.plans.key")}
        hint={t(plan === null ? "platform.plans.keyHint" : "platform.plans.keyImmutable")}
        value={key}
        onChange={setKey}
        error={tried && keyBad ? t("platform.tenantCreate.errors.plan") : undefined}
        readOnly={plan !== null}
        mono
        autoFocus={plan === null}
      />
      <TextField label={t("platform.plans.name")} value={name} onChange={setName} error={tried && nameBad ? t("platform.plans.errors.name") : undefined} maxLength={200} autoFocus={plan !== null} />
      <LimitsFields form={limits} onChange={setLimits} errorField={tried && limitError ? fieldOfLimitError(limitError) : null} required />
      <CheckboxField label={t("platform.plans.active")} hint={t("platform.plans.activeHint")} checked={active} onChange={setActive} />
    </FormDialog>
  );
}
