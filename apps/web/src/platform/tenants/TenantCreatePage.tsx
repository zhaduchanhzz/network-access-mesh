// Wizard tạo tenant (§12.2 "Tenant wizard → Job timeline", §11.3): ba bước — thông tin, Identity Provider, xem lại —
// rồi POST /platform/tenants (Idempotency-Key — gửi lại cùng nội dung sau lỗi mạng/409 nhận lại đúng job) ⇒ 202 +
// Location của job tenant.provision ⇒ chuyển tới timeline của job (19 bước). Kiểm tra phía client chỉ là hướng dẫn
// (cùng pattern của spec); server kiểm lại tất cả (slug cấm, slug đã dùng, gói, quota).
// `client_secret` của IdP ngoài là trường chỉ-ghi: chỉ nằm trong state của form tới khi gửi, không vào khóa
// idempotency, không bao giờ được hiển thị lại.
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Link, useNavigate } from "react-router";
import { api, callWithResponse } from "../../api/client";
import { fingerprintOf, useIdempotentMutation } from "../../api/idempotency";
import { jobFromLocation } from "../../api/jobs";
import { useQueryClient } from "@tanstack/react-query";
import { can } from "../../auth/permissions";
import { SLUG_RE } from "../../auth/session";
import { Field } from "../../ui/Data";
import { TextField } from "../../ui/Form";
import { Page } from "../../components/Page";
import { ProblemAlert } from "../../components/ProblemAlert";
import { ForbiddenPage } from "../../pages/StatusPages";
import { invalidatePlatform, type TenantCreate } from "../api";
import { usePlatformRole } from "../PlatformScope";

const PLAN_RE = /^[a-z][a-z0-9_-]{0,62}$/;
const REGION_RE = /^[a-z0-9][a-z0-9-]{0,62}$/;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const DOMAIN_RE = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;

export interface TenantForm {
  slug: string;
  name: string;
  ownerEmail: string;
  planKey: string;
  region: string;
  driver: "keycloak" | "external";
  issuer: string;
  clientId: string;
  clientSecret: string;
  domains: string;
}

const EMPTY: TenantForm = {
  slug: "",
  name: "",
  ownerEmail: "",
  planKey: "standard",
  region: "",
  driver: "keycloak",
  issuer: "",
  clientId: "",
  clientSecret: "",
  domains: "",
};

type Errors = Partial<Record<keyof TenantForm, string>>;

function isHttpsUrl(raw: string): boolean {
  try {
    return new URL(raw).protocol === "https:";
  } catch {
    return false;
  }
}

function domainsOf(raw: string): string[] {
  return raw
    .split(/[\s,]+/)
    .map((d) => d.trim().toLowerCase())
    .filter(Boolean);
}

/** Lỗi theo trường của bước `step` (0: thông tin, 1: IdP) — khóa i18n. */
export function validate(f: TenantForm, step: 0 | 1): Errors {
  const e: Errors = {};
  if (step === 0) {
    if (!SLUG_RE.test(f.slug) || f.slug.includes("--")) e.slug = "platform.tenantCreate.errors.slug";
    if (f.name.trim() === "" || f.name.length > 128) e.name = "platform.tenantCreate.errors.name";
    if (!EMAIL_RE.test(f.ownerEmail) || f.ownerEmail.length > 320) e.ownerEmail = "platform.tenantCreate.errors.email";
    if (!PLAN_RE.test(f.planKey)) e.planKey = "platform.tenantCreate.errors.plan";
    if (f.region !== "" && !REGION_RE.test(f.region)) e.region = "platform.tenantCreate.errors.region";
  } else {
    const domains = domainsOf(f.domains);
    if (domains.length > 32 || domains.some((d) => !DOMAIN_RE.test(d))) e.domains = "platform.tenantCreate.errors.domains";
    if (f.driver === "external") {
      if (!isHttpsUrl(f.issuer) || f.issuer.length > 512) e.issuer = "platform.tenantCreate.errors.issuer";
      if (f.clientId.trim() === "" || f.clientId.length > 255) e.clientId = "platform.tenantCreate.errors.clientId";
      if (f.clientSecret === "" || f.clientSecret.length > 4096) e.clientSecret = "platform.tenantCreate.errors.clientSecret";
    }
  }
  return e;
}

/** Body của POST /platform/tenants (TenantCreate — additionalProperties: false). */
export function toRequest(f: TenantForm): TenantCreate {
  const domains = domainsOf(f.domains);
  const idp: TenantCreate["identity_provider"] =
    f.driver === "external"
      ? { driver: "external", issuer: f.issuer.trim(), client_id: f.clientId.trim(), client_secret: f.clientSecret }
      : { driver: "keycloak" };
  if (domains.length > 0) idp.allowed_email_domains = domains;
  return {
    slug: f.slug,
    name: f.name.trim(),
    plan_key: f.planKey,
    owner_email: f.ownerEmail.trim(),
    identity_provider: idp,
    ...(f.region ? { deployment_region: f.region } : {}),
  };
}

const STEPS = ["details", "identity", "review"] as const;

export function TenantCreatePage() {
  const { t } = useTranslation();
  const role = usePlatformRole();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [step, setStep] = useState(0);
  const [form, setForm] = useState<TenantForm>(EMPTY);
  const [shown, setShown] = useState<Errors>({});

  const create = useIdempotentMutation({
    // server bỏ client_secret khỏi request_hash ⇒ khóa cũng không phụ thuộc secret (và secret không nằm trong khóa)
    fingerprint: (body: TenantCreate) =>
      fingerprintOf({ ...body, identity_provider: { ...body.identity_provider, client_secret: undefined } }),
    mutationFn: async (body: TenantCreate, key: string) =>
      callWithResponse(api.POST("/platform/tenants", { params: { header: { "Idempotency-Key": key } }, body })),
    onSuccess: async (r) => {
      setForm(EMPTY); // xóa client_secret khỏi bộ nhớ của form
      await invalidatePlatform(queryClient, "tenants");
      const ref = jobFromLocation(r.response.headers.get("Location"));
      void navigate(`/platform/jobs/${ref?.jobId ?? r.data.id}`, { state: { createdTenant: r.data.tenant_id } });
    },
  });

  if (!can(role, "platform.tenant:create")) return <ForbiddenPage />;

  const set = (k: keyof TenantForm) => (v: string) => {
    setForm((f) => ({ ...f, [k]: v }));
  };
  const next = () => {
    if (step < 2) {
      const errs = validate(form, step as 0 | 1);
      setShown(errs);
      if (Object.keys(errs).length === 0) setStep(step + 1);
    }
  };
  const err = (k: keyof TenantForm) => (shown[k] ? t(shown[k]) : undefined);
  const body = toRequest(form);

  return (
    <Page title={t("platform.tenantCreate.title")}>
      <p className="mb-4">
        <Link to="/platform/tenants" className="link text-sm">
          {t("platform.tenantCreate.back")}
        </Link>
      </p>
      <ol aria-label={t("platform.tenantCreate.steps")} className="mb-6 flex flex-wrap gap-2 text-sm">
        {STEPS.map((s, i) => (
          <li
            key={s}
            aria-current={i === step ? "step" : undefined}
            className={i === step ? "badge badge-ok" : i < step ? "badge" : "badge opacity-70"}
          >
            {t("platform.tenantCreate.stepLabel", { n: i + 1, name: t(`platform.tenantCreate.step.${s}`) })}
          </li>
        ))}
      </ol>

      <form
        noValidate
        className="card space-y-4"
        aria-labelledby="wizard-step-title"
        onSubmit={(e) => {
          e.preventDefault();
          if (step < 2) next();
          else if (!create.isPending) create.mutate(body);
        }}
      >
        <h2 id="wizard-step-title" className="text-lg font-semibold">
          {t(`platform.tenantCreate.step.${STEPS[step] ?? "details"}`)}
        </h2>

        {step === 0 ? (
          <>
            <TextField label={t("platform.tenantCreate.slug")} hint={t("platform.tenantCreate.slugHint")} value={form.slug} onChange={set("slug")} error={err("slug")} mono autoFocus />
            <TextField label={t("platform.tenantCreate.name")} value={form.name} onChange={set("name")} error={err("name")} />
            <TextField label={t("platform.tenantCreate.ownerEmail")} hint={t("platform.tenantCreate.ownerEmailHint")} type="email" value={form.ownerEmail} onChange={set("ownerEmail")} error={err("ownerEmail")} />
            <TextField label={t("platform.tenantCreate.plan")} hint={t("platform.tenantCreate.planHint")} value={form.planKey} onChange={set("planKey")} error={err("planKey")} mono />
            <TextField label={t("platform.tenantCreate.region")} hint={t("platform.tenantCreate.regionHint")} value={form.region} onChange={set("region")} error={err("region")} mono />
          </>
        ) : null}

        {step === 1 ? (
          <>
            <fieldset>
              <legend className="label">{t("platform.tenantCreate.driver")}</legend>
              {(["keycloak", "external"] as const).map((d) => (
                <label key={d} className="flex items-start gap-2 py-1">
                  <input
                    type="radio"
                    name="driver"
                    value={d}
                    checked={form.driver === d}
                    onChange={() => {
                      setForm((f) => ({ ...f, driver: d }));
                    }}
                  />
                  <span>
                    <span className="font-medium">{t(`platform.tenantCreate.drivers.${d}`)}</span>
                    <span className="hint block">{t(`platform.tenantCreate.drivers.${d}Hint`)}</span>
                  </span>
                </label>
              ))}
            </fieldset>
            {form.driver === "external" ? (
              <>
                <TextField label={t("platform.tenantCreate.issuer")} type="url" value={form.issuer} onChange={set("issuer")} error={err("issuer")} mono />
                <TextField label={t("platform.tenantCreate.clientId")} value={form.clientId} onChange={set("clientId")} error={err("clientId")} mono />
                <TextField label={t("platform.tenantCreate.clientSecret")} hint={t("platform.tenantCreate.clientSecretHint")} type="password" value={form.clientSecret} onChange={set("clientSecret")} error={err("clientSecret")} />
              </>
            ) : null}
            <TextField label={t("platform.tenantCreate.domains")} hint={t("platform.tenantCreate.domainsHint")} value={form.domains} onChange={set("domains")} error={err("domains")} mono />
          </>
        ) : null}

        {step === 2 ? (
          <>
            <dl className="grid gap-3 sm:grid-cols-2">
              <Field label={t("platform.tenantCreate.slug")}>
                <code>{body.slug}</code>
              </Field>
              <Field label={t("platform.tenantCreate.name")}>{body.name}</Field>
              <Field label={t("platform.tenantCreate.ownerEmail")}>{body.owner_email}</Field>
              <Field label={t("platform.tenantCreate.plan")}>
                <code>{body.plan_key}</code>
              </Field>
              <Field label={t("platform.tenantCreate.region")}>{body.deployment_region ?? t("platform.tenantCreate.regionDefault")}</Field>
              <Field label={t("platform.tenantCreate.driver")}>{t(`platform.tenantCreate.drivers.${form.driver}`)}</Field>
              {form.driver === "external" ? (
                <>
                  <Field label={t("platform.tenantCreate.issuer")}>
                    <code>{body.identity_provider.issuer}</code>
                  </Field>
                  <Field label={t("platform.tenantCreate.clientSecret")}>{t("platform.tenantCreate.secretSet")}</Field>
                </>
              ) : null}
              <Field label={t("platform.tenantCreate.domains")}>
                {(body.identity_provider.allowed_email_domains ?? []).join(", ") || t("common.none")}
              </Field>
            </dl>
            <p className="text-sm text-muted">{t("platform.tenantCreate.reviewNote")}</p>
            {create.isError ? <ProblemAlert error={create.error} /> : null}
          </>
        ) : null}

        <div className="flex flex-wrap justify-between gap-2 pt-2">
          <button
            type="button"
            className="btn-secondary"
            disabled={step === 0 || create.isPending}
            onClick={() => {
              setShown({});
              setStep(Math.max(0, step - 1));
            }}
          >
            {t("common.back")}
          </button>
          <button type="submit" className="btn-primary" disabled={create.isPending}>
            {step < 2 ? t("common.next") : create.isPending ? t("common.working") : t("platform.tenantCreate.submit")}
          </button>
        </div>
      </form>
    </Page>
  );
}
