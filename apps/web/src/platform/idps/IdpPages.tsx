// Identity Providers (§12.2 "SA; step-up; IdP của tenant: tenant duyệt hoặc 2P (§8.2)"; §8.5 platform.idp:read /
// :manage): GET /platform/identity-providers[/{id}] (issuer, client_id, driver, scope CHỈ ĐỌC — bất biến; client secret
// không bao giờ được trả, chỉ `client_secret_set`), PATCH /platform/identity-providers/{id} (If-Match, step-up) chỉ
// claim_mapping / required_claims / allowed_email_domains. Hàng platform ⇒ 200 áp dụng ngay; hàng của tenant ⇒ 202 +
// yêu cầu phê duyệt (Super Admin thứ hai) — chưa có hiệu lực, ghi vào audit của tenant và báo Tenant Owner.
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Link, useNavigate, useParams } from "react-router";
import { api, callWithResponse } from "../../api/client";
import { ifMatch, isStaleVersion } from "../../api/etag";
import { approvalFromLocation } from "../../api/jobs";
import { useCursorPager } from "../../api/pagination";
import { ApiError } from "../../api/problem";
import { isUuid } from "../../api/queryClient";
import { can } from "../../auth/permissions";
import { EmptyState, Field, JsonBlock, Pager, QueryBlock } from "../../ui/Data";
import { TextField } from "../../ui/Form";
import { FormDialog } from "../../ui/FormDialog";
import { StatusBadge } from "../../ui/Status";
import { Timestamp } from "../../ui/time";
import { Loading, Page } from "../../components/Page";
import { ProblemAlert } from "../../components/ProblemAlert";
import { NotFoundPage } from "../../pages/StatusPages";
import { invalidatePlatform } from "../api";
import { useIdentityProvider, useIdentityProviders, type IdentityProvider } from "../opsApi";
import { usePlatformRole } from "../PlatformScope";
import { formOf, idpUpdate, MAPPED_FIELDS, type IdpForm } from "./idpForm";

export function IdpListPage() {
  const { t } = useTranslation();
  const [scope, setScope] = useState<"" | "platform" | "tenant">("");
  const pager = useCursorPager(scope);
  const q = useIdentityProviders({ scope: scope || undefined, cursor: pager.cursor });
  return (
    <Page title={t("nav.platform.identityProviders")}>
      <p className="mb-4 text-sm text-muted">{t("platform.idps.intro")}</p>
      <div className="mb-4">
        <label htmlFor="idp-scope" className="label">
          {t("platform.idps.scope")}
        </label>
        <select
          id="idp-scope"
          className="select"
          value={scope}
          onChange={(e) => {
            const v = e.target.value;
            setScope(v === "platform" || v === "tenant" ? v : "");
          }}
        >
          <option value="">{t("common.all")}</option>
          <option value="platform">{t("platform.idps.scopes.platform")}</option>
          <option value="tenant">{t("platform.idps.scopes.tenant")}</option>
        </select>
      </div>
      <QueryBlock query={q}>
        {(data) =>
          data.items.length === 0 ? (
            <EmptyState>{t("platform.idps.empty")}</EmptyState>
          ) : (
            <>
              <div className="relative overflow-x-auto rounded-lg border border-line bg-surface">
                <table className="data-table">
                  <caption className="sr-only">{t("nav.platform.identityProviders")}</caption>
                  <thead>
                    <tr>
                      <th scope="col">{t("platform.idps.col.issuer")}</th>
                      <th scope="col">{t("platform.idps.col.scope")}</th>
                      <th scope="col">{t("platform.idps.col.driver")}</th>
                      <th scope="col">{t("platform.idps.col.status")}</th>
                      <th scope="col">{t("platform.idps.col.updated")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.items.map((i) => (
                      <tr key={i.id} data-testid="idp-row">
                        <td>
                          <Link to={`/platform/identity-providers/${i.id}`} className="link font-mono text-xs break-all">
                            {i.issuer}
                          </Link>
                          <code className="hint block">{i.client_id}</code>
                        </td>
                        <td>
                          {t(`platform.idps.scopes.${i.scope}`)}
                          {i.tenant_id ? (
                            <Link to={`/platform/tenants/${i.tenant_id}`} className="link hint block font-mono">
                              {i.tenant_id}
                            </Link>
                          ) : null}
                        </td>
                        <td>{t(`platform.tenantCreate.drivers.${i.driver}`)}</td>
                        <td>
                          <StatusBadge status={i.status}>{t(`status.idp.${i.status}`)}</StatusBadge>
                        </td>
                        <td>
                          <Timestamp iso={i.updated_at} emptyKey="common.none" />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <Pager pager={pager} nextCursor={data.next_cursor} label={t("platform.idps.pagination")} />
            </>
          )
        }
      </QueryBlock>
    </Page>
  );
}

export function IdpDetailPage() {
  const { idpId: raw = "" } = useParams();
  const idpId = raw.toLowerCase();
  if (!isUuid(idpId)) return <NotFoundPage />;
  return <IdpDetail key={idpId} idpId={idpId} />;
}

function IdpDetail({ idpId }: { idpId: string }) {
  const { t } = useTranslation();
  const role = usePlatformRole();
  const q = useIdentityProvider(idpId);
  const [editing, setEditing] = useState(false);
  if (q.isPending) return <Loading />;
  if (q.isError) {
    if (q.error instanceof ApiError && q.error.status === 404) return <NotFoundPage />;
    return (
      <Page title={t("platform.idp.title")}>
        <ProblemAlert error={q.error} onRetry={() => void q.refetch()} />
      </Page>
    );
  }
  const { data: idp, etag } = q.data;
  return (
    <Page
      title={t("platform.idp.title")}
      actions={
        can(role, "platform.idp:manage") ? (
          <button
            type="button"
            className="btn-primary"
            onClick={() => {
              setEditing(true);
            }}
          >
            {t("platform.idp.edit")}
          </button>
        ) : null
      }
    >
      <p className="mb-4">
        <Link to="/platform/identity-providers" className="link text-sm">
          {t("platform.idp.back")}
        </Link>
      </p>
      <div className="space-y-6">
        <section aria-labelledby="idp-identity" className="card">
          <h2 id="idp-identity" className="mb-1 text-lg font-semibold">
            {t("platform.idp.identity")}
          </h2>
          <p className="mb-3 text-sm text-muted">{t("platform.idp.immutable")}</p>
          <dl className="grid gap-4 sm:grid-cols-2">
            <Field label={t("platform.idps.col.issuer")}>
              <code className="break-all" data-testid="idp-issuer">
                {idp.issuer}
              </code>
            </Field>
            <Field label={t("platform.idp.clientId")}>
              <code>{idp.client_id}</code>
            </Field>
            <Field label={t("platform.idps.col.driver")}>{t(`platform.tenantCreate.drivers.${idp.driver}`)}</Field>
            <Field label={t("platform.idps.col.scope")}>
              {t(`platform.idps.scopes.${idp.scope}`)}
              {idp.tenant_id ? (
                <Link to={`/platform/tenants/${idp.tenant_id}`} className="link hint block font-mono">
                  {idp.tenant_id}
                </Link>
              ) : null}
            </Field>
            <Field label={t("platform.idps.col.status")}>
              <StatusBadge status={idp.status}>{t(`status.idp.${idp.status}`)}</StatusBadge>
            </Field>
            <Field label={t("platform.idp.secret")}>{t(idp.client_secret_set ? "platform.idp.secretSet" : "platform.idp.secretUnset")}</Field>
            <Field label={t("platform.idp.emailVerified")}>{t(idp.require_email_verified ? "platform.idp.yes" : "platform.idp.no")}</Field>
            <Field label={t("platform.idps.col.updated")}>
              <Timestamp iso={idp.updated_at} emptyKey="common.none" />
              <span className="hint block">{t("platform.settings.version", { version: idp.version })}</span>
            </Field>
          </dl>
        </section>
        <section aria-labelledby="idp-claims" className="card">
          <h2 id="idp-claims" className="mb-3 text-lg font-semibold">
            {t("platform.idp.claims")}
          </h2>
          <dl className="grid gap-4 sm:grid-cols-2">
            <Field label={t("platform.idp.mapping")}>
              {Object.keys(idp.claim_mapping).length === 0 ? (
                t("platform.idp.defaultMapping")
              ) : (
                <ul className="text-sm">
                  {Object.entries(idp.claim_mapping).map(([k, v]) => (
                    <li key={k}>
                      <code>{k}</code>
                      {" ← "}
                      <code>{v}</code>
                    </li>
                  ))}
                </ul>
              )}
            </Field>
            <Field label={t("platform.idp.domains")}>
              {idp.allowed_email_domains.length === 0 ? t("platform.idp.anyDomain") : <code className="text-sm">{idp.allowed_email_domains.join(", ")}</code>}
            </Field>
          </dl>
          <h3 className="mt-4 text-sm font-semibold">{t("platform.idp.requiredClaims")}</h3>
          <JsonBlock value={idp.required_claims} />
        </section>
      </div>
      {editing ? (
        <EditIdp
          idp={idp}
          etag={etag}
          onClose={() => {
            setEditing(false);
          }}
        />
      ) : null}
    </Page>
  );
}

function EditIdp({ idp, etag, onClose }: { idp: IdentityProvider; etag: string | null; onClose: () => void }) {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [form, setForm] = useState<IdpForm>(() => formOf(idp));
  const [tried, setTried] = useState(false);
  const { errors, body } = idpUpdate(idp, form);
  const tenantRow = idp.scope === "tenant";
  const save = useMutation({
    mutationFn: () =>
      callWithResponse(
        api.PATCH("/platform/identity-providers/{idpId}", {
          params: { path: { idpId: idp.id }, header: ifMatch(etag ?? idp.etag) },
          body,
        }),
      ),
    onSuccess: async (r) => {
      await Promise.all([invalidatePlatform(queryClient, "idp", idp.id), invalidatePlatform(queryClient, "idps"), invalidatePlatform(queryClient, "approvals")]);
      onClose();
      if (r.response.status === 202) {
        const id = approvalFromLocation(r.response.headers.get("Location"));
        if (id) void navigate(`/platform/approvals/${id}`, { state: { requested: true } });
      }
    },
    onError: async (e) => {
      if (isStaleVersion(e)) await invalidatePlatform(queryClient, "idp", idp.id);
    },
  });
  const err = (k: keyof typeof errors) => (tried && errors[k] ? t(errors[k]) : undefined);
  const changed = Object.keys(body).length > 0;
  return (
    <FormDialog
      isOpen
      onOpenChange={(o) => {
        if (!o) onClose();
      }}
      title={t("platform.idp.editTitle")}
      description={
        <div className="space-y-2">
          <p>{t("platform.idp.editDesc")}</p>
          {tenantRow ? (
            <p className="font-medium" data-testid="tenant-idp-2p">
              {t("platform.idp.tenantTwoPerson")}
            </p>
          ) : null}
        </div>
      }
      submitLabel={t(tenantRow ? "platform.idp.requestChange" : "platform.idp.save")}
      canSubmit={changed || Object.keys(errors).length > 0}
      pending={save.isPending}
      error={save.error}
      onSubmit={() => {
        setTried(true);
        if (Object.keys(errors).length === 0 && changed) save.mutate();
      }}
    >
      <fieldset className="space-y-2">
        <legend className="label">{t("platform.idp.mapping")}</legend>
        {MAPPED_FIELDS.map((k, i) => (
          <TextField
            key={k}
            label={t("platform.idp.mapField", { field: k })}
            value={form.mapping[k]}
            onChange={(v) => {
              setForm((f) => ({ ...f, mapping: { ...f.mapping, [k]: v } }));
            }}
            error={i === 0 ? err("mapping") : undefined}
            mono
            autoFocus={i === 0}
          />
        ))}
      </fieldset>
      <TextField
        label={t("platform.idp.requiredClaims")}
        hint={t("platform.idp.requiredClaimsHint")}
        value={form.requiredClaims}
        onChange={(v) => {
          setForm((f) => ({ ...f, requiredClaims: v }));
        }}
        error={err("requiredClaims")}
        rows={4}
        mono
      />
      <TextField
        label={t("platform.idp.domains")}
        hint={t("platform.idp.domainsHint")}
        value={form.domains}
        onChange={(v) => {
          setForm((f) => ({ ...f, domains: v }));
        }}
        error={err("domains")}
        rows={3}
        mono
      />
    </FormDialog>
  );
}
