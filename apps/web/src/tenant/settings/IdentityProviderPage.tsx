// Identity Provider của tenant (P4-T13 — UI của API P4-T03a; §8.2, §8.6 tenant.idp:read / :update): GET
// /identity-provider (Owner, Admin) — issuer, client_id, driver bất biến (đổi IdP là quy trình di trú); Owner sửa ràng
// buộc claim, domain e-mail và — IdP `external` — client secret (chỉ-ghi, không bao giờ hiện lại) bằng PATCH (step-up,
// If-Match). 412 ⇒ tải lại bản mới.
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { api } from "../../api/client";
import { callWithETag, ifMatch, isStaleVersion } from "../../api/etag";
import { queryKeys } from "../../api/queryClient";
import type { components } from "../../api/schema";
import { can } from "../../auth/permissions";
import { Page } from "../../components/Page";
import { ProblemAlert } from "../../components/ProblemAlert";
import { Field, JsonBlock, QueryBlock } from "../../ui/Data";
import { StatusBadge } from "../../ui/Status";
import { Timestamp } from "../../ui/time";
import { useTenant } from "../TenantScope";

type IdentityProvider = components["schemas"]["IdentityProvider"];
type IdPUpdate = components["schemas"]["TenantIdentityProviderUpdate"];

const DOMAIN_RE = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;

function parseObject(text: string): Record<string, unknown> | null {
  if (text.trim() === "") return {};
  try {
    const v: unknown = JSON.parse(text);
    return v !== null && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

function stringMap(v: Record<string, unknown> | null): Record<string, string> | null {
  if (v === null) return null;
  const out: Record<string, string> = {};
  for (const [k, x] of Object.entries(v)) {
    if (typeof x !== "string" || x === "") return null;
    out[k] = x;
  }
  return out;
}

export function IdentityProviderPage() {
  const { t } = useTranslation();
  const { tenantId } = useTenant();
  // lưu xong ⇒ ETag mới ⇒ form dựng lại từ bản đã lưu: thông báo "đã lưu" nằm ngoài form
  const [saved, setSaved] = useState(false);
  const q = useQuery({
    queryKey: queryKeys.tenant(tenantId, "identity-provider"),
    queryFn: () => callWithETag(api.GET("/tenants/{tenantId}/identity-provider", { params: { path: { tenantId } } })),
  });
  return (
    <Page title={t("nav.tenant.identityProvider")}>
      <p className="mb-4 text-sm text-muted">{t("idp.intro")}</p>
      <QueryBlock query={q}>
        {(v) => (
          <div className="space-y-6">
            <IdPSummary idp={v.data} />
            {saved ? <p role="status">{t("idp.saved")}</p> : null}
            <IdPForm key={v.etag ?? ""} idp={v.data} etag={v.etag} onSaved={setSaved} />
          </div>
        )}
      </QueryBlock>
    </Page>
  );
}

function IdPSummary({ idp }: { idp: IdentityProvider }) {
  const { t } = useTranslation();
  return (
    <section aria-labelledby="idp-summary" className="card">
      <h2 id="idp-summary" className="mb-3 text-lg font-semibold">
        {t("idp.registration")}
      </h2>
      <dl className="grid gap-4 sm:grid-cols-2">
        <Field label={t("idp.issuer")}>
          <code className="text-xs break-all">{idp.issuer}</code>
        </Field>
        <Field label={t("idp.clientId")}>
          <code className="text-xs">{idp.client_id}</code>
        </Field>
        <Field label={t("idp.driver")}>{t(`idp.drivers.${idp.driver}`)}</Field>
        <Field label={t("idp.status")}>
          <StatusBadge status={idp.status}>{idp.status}</StatusBadge>
        </Field>
        <Field label={t("idp.secret")}>{idp.client_secret_set ? t("idp.secretSet") : t("idp.secretUnset")}</Field>
        <Field label={t("idp.updated")}>
          <Timestamp iso={idp.updated_at} />
        </Field>
      </dl>
      <p className="hint mt-3">{t("idp.immutableNote")}</p>
    </section>
  );
}

function IdPForm({ idp, etag, onSaved }: { idp: IdentityProvider; etag: string | null; onSaved: (saved: boolean) => void }) {
  const { t } = useTranslation();
  const { tenantId, role, readOnly } = useTenant();
  const queryClient = useQueryClient();
  const editable = can(role, "tenant.idp:update") && !readOnly;
  const [domains, setDomains] = useState(idp.allowed_email_domains.join("\n"));
  const [claims, setClaims] = useState(JSON.stringify(idp.required_claims, null, 2));
  const [mapping, setMapping] = useState(JSON.stringify(idp.claim_mapping, null, 2));
  const [secret, setSecret] = useState("");
  const domainList = domains
    .split(/[\s,]+/)
    .map((d) => d.trim().toLowerCase())
    .filter(Boolean);
  const domainsBad = domainList.length > 32 || domainList.some((d) => !DOMAIN_RE.test(d));
  const claimsObj = parseObject(claims);
  const mappingObj = stringMap(parseObject(mapping));
  const secretBad = secret !== "" && (secret.length < 16 || secret.length > 512);
  const invalid = domainsBad || claimsObj === null || mappingObj === null || secretBad;
  const save = useMutation({
    mutationFn: () => {
      const body: IdPUpdate = { allowed_email_domains: domainList, required_claims: claimsObj ?? {}, claim_mapping: mappingObj ?? {} };
      if (secret !== "") body.client_secret = secret;
      return callWithETag(
        api.PATCH("/tenants/{tenantId}/identity-provider", { params: { path: { tenantId }, header: ifMatch(etag) }, body }),
      );
    },
    onMutate: () => {
      onSaved(false);
    },
    onSuccess: (v) => {
      setSecret("");
      onSaved(true);
      queryClient.setQueryData(queryKeys.tenant(tenantId, "identity-provider"), v);
    },
    onError: (e) => {
      if (isStaleVersion(e)) void queryClient.invalidateQueries({ queryKey: queryKeys.tenant(tenantId, "identity-provider") });
    },
  });
  if (!editable) {
    return (
      <section aria-labelledby="idp-constraints" className="card space-y-3">
        <h2 id="idp-constraints" className="text-lg font-semibold">
          {t("idp.constraints")}
        </h2>
        <dl>
          <Field label={t("idp.domains")}>{idp.allowed_email_domains.length ? idp.allowed_email_domains.join(", ") : t("common.none")}</Field>
        </dl>
        <p className="label">{t("idp.requiredClaims")}</p>
        <JsonBlock value={idp.required_claims} />
        <p className="label">{t("idp.claimMapping")}</p>
        <JsonBlock value={idp.claim_mapping} />
        <p className="text-sm text-muted">{t("idp.readOnlyNote")}</p>
      </section>
    );
  }
  return (
    <section aria-labelledby="idp-constraints" className="card space-y-3">
      <h2 id="idp-constraints" className="text-lg font-semibold">
        {t("idp.constraints")}
      </h2>
      <form
        className="space-y-3"
        onSubmit={(e) => {
          e.preventDefault();
          if (!invalid) save.mutate();
        }}
      >
        <fieldset disabled={save.isPending} className="space-y-3">
          <div>
            <label htmlFor="idp-domains" className="label">
              {t("idp.domains")}
            </label>
            <textarea id="idp-domains" className="input font-mono" rows={3} value={domains} aria-invalid={domainsBad} onChange={(e) => { setDomains(e.target.value); }} />
            <p className="hint">{t("idp.domainsHint")}</p>
          </div>
          <div>
            <label htmlFor="idp-claims" className="label">
              {t("idp.requiredClaims")}
            </label>
            <textarea id="idp-claims" className="input font-mono" rows={4} value={claims} aria-invalid={claimsObj === null} onChange={(e) => { setClaims(e.target.value); }} />
            {claimsObj === null ? <p className="hint text-danger">{t("idp.jsonInvalid")}</p> : null}
          </div>
          <div>
            <label htmlFor="idp-mapping" className="label">
              {t("idp.claimMapping")}
            </label>
            <textarea id="idp-mapping" className="input font-mono" rows={4} value={mapping} aria-invalid={mappingObj === null} onChange={(e) => { setMapping(e.target.value); }} />
            {mappingObj === null ? <p className="hint text-danger">{t("idp.mappingInvalid")}</p> : null}
          </div>
          {idp.driver === "external" ? (
            <div>
              <label htmlFor="idp-secret" className="label">
                {t("idp.newSecret")}
              </label>
              <input id="idp-secret" type="password" autoComplete="new-password" className="input" value={secret} aria-invalid={secretBad} onChange={(e) => { setSecret(e.target.value); }} />
              <p className="hint">{t("idp.secretHint")}</p>
            </div>
          ) : null}
        </fieldset>
        {save.isError ? <ProblemAlert error={save.error} /> : null}
        <p className="hint">{t("idp.stepUpNote")}</p>
        <button type="submit" className="btn-primary" disabled={invalid || save.isPending}>
          {save.isPending ? t("common.working") : t("idp.save")}
        </button>
      </form>
    </section>
  );
}
