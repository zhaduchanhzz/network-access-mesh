// Chi tiết tenant (§12.2): metadata registry (GET /platform/tenants/{id} — ETag giữ cho PATCH của P4-T03a), instance
// (GET /platform/tenants/{id}/instances), relay (GET /platform/tenants/{id}/relay-regions — số đo không có nguồn hiện
// "không khả dụng" kèm lý do, §10.6/§12.4), job gần đây (GET /platform/tenants/{id}/jobs) và thao tác vòng đời.
// Không có dữ liệu nội bộ của tenant (thiết bị, policy…) — muốn xem phải có Support Access Grant (§8.7).
import type { ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { Link, useParams } from "react-router";
import { ApiError } from "../../api/problem";
import { isUuid } from "../../api/queryClient";
import { useCursorPager } from "../../api/pagination";
import { can } from "../../auth/permissions";
import { DateTime, EmptyState, Field, Pager, QueryBlock, StatusBadge } from "../../components/Data";
import { Loading, Page } from "../../components/Page";
import { ProblemAlert } from "../../components/ProblemAlert";
import { NotFoundPage } from "../../pages/StatusPages";
import { useTenant, useTenantInstances, useTenantJobs, useTenantRelay, type Tenant } from "../api";
import { JobTable } from "../jobs/JobListPage";
import { usePlatformRole } from "../PlatformScope";
import { TenantActions } from "./TenantActions";

export function TenantDetailPage() {
  const { tenantId: raw = "" } = useParams();
  const tenantId = raw.toLowerCase();
  if (!isUuid(tenantId)) return <NotFoundPage />;
  return <TenantDetail key={tenantId} tenantId={tenantId} />;
}

function TenantDetail({ tenantId }: { tenantId: string }) {
  const { t } = useTranslation();
  const role = usePlatformRole();
  const tenant = useTenant(tenantId);

  if (tenant.isPending) return <Loading />;
  if (tenant.isError) {
    if (tenant.error instanceof ApiError && tenant.error.status === 404) return <NotFoundPage />;
    return (
      <Page title={t("platform.tenantDetail.title")}>
        <ProblemAlert error={tenant.error} onRetry={() => void tenant.refetch()} />
      </Page>
    );
  }
  const tn = tenant.data.data;
  return (
    <Page title={tn.name} actions={<TenantActions tenant={tn} role={role} />}>
      <p className="mb-4">
        <Link to="/platform/tenants" className="link text-sm">
          {t("platform.tenantDetail.back")}
        </Link>
      </p>
      <div className="space-y-6">
        <Summary tenant={tn} />
        <InstanceSection tenantId={tenantId} enabled={can(role, "platform.instance:read")} />
        <RelaySection tenantId={tenantId} enabled={can(role, "platform.relay:read")} />
        <JobsSection tenantId={tenantId} enabled={can(role, "platform.job:read")} />
      </div>
    </Page>
  );
}

function Section({ id, title, children }: { id: string; title: string; children: ReactNode }) {
  return (
    <section aria-labelledby={id} className="card">
      <h2 id={id} className="mb-3 text-lg font-semibold">
        {title}
      </h2>
      {children}
    </section>
  );
}

function Summary({ tenant }: { tenant: Tenant }) {
  const { t } = useTranslation();
  const limits = Object.entries(tenant.limits).flatMap(([k, v]) => (typeof v === "number" ? [[k, v] as const] : []));
  return (
    <Section id="tenant-summary" title={t("platform.tenantDetail.summary")}>
      <dl className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        <Field label={t("platform.tenants.col.slug")}>
          <code>{tenant.slug}</code>
        </Field>
        <Field label={t("platform.tenants.col.status")}>
          <StatusBadge status={tenant.status} label={t(`status.tenant.${tenant.status}`)} />
        </Field>
        <Field label={t("platform.tenants.col.plan")}>
          <code>{tenant.plan}</code>
        </Field>
        <Field label={t("platform.tenants.col.region")}>{tenant.deployment_region}</Field>
        <Field label={t("platform.tenantDetail.controlUrl")}>
          <code>{tenant.control_url}</code>
        </Field>
        <Field label={t("platform.tenantDetail.id")}>
          <code className="text-xs">{tenant.id}</code>
        </Field>
        <Field label={t("platform.tenants.col.created")}>
          <DateTime value={tenant.created_at} />
        </Field>
        <Field label={t("platform.tenantDetail.updated")}>
          <DateTime value={tenant.updated_at} />
        </Field>
        <Field label={t("platform.tenantDetail.limits")}>
          {limits.length === 0 ? (
            t("platform.tenantDetail.noLimits")
          ) : (
            <ul className="text-sm">
              {limits.map(([k, v]) => (
                <li key={k}>
                  <code>{k}</code>
                  {": "}
                  {String(v)}
                </li>
              ))}
            </ul>
          )}
        </Field>
      </dl>
    </Section>
  );
}

function NoPermission() {
  const { t } = useTranslation();
  return <p className="text-sm text-muted">{t("platform.tenantDetail.noPermission")}</p>;
}

function InstanceSection({ tenantId, enabled }: { tenantId: string; enabled: boolean }) {
  const { t } = useTranslation();
  const q = useTenantInstances(tenantId, enabled);
  return (
    <Section id="tenant-instance" title={t("platform.tenantDetail.instance")}>
      {!enabled ? (
        <NoPermission />
      ) : (
        <QueryBlock query={q}>
          {(data) =>
            data.items.length === 0 ? (
              <EmptyState>{t("platform.tenantDetail.noInstance")}</EmptyState>
            ) : (
              <ul className="space-y-4">
                {data.items.map((i) => (
                  <li key={i.id} data-testid="instance">
                    <dl className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
                      <Field label={t("platform.tenantDetail.instanceStatus")}>
                        <StatusBadge status={i.status} label={t(`status.instance.${i.status}`)} />
                      </Field>
                      <Field label={t("platform.tenantDetail.health")}>
                        <StatusBadge status={i.health.status} label={t(`status.health.${i.health.status}`)} />
                        {i.health.reason ? <code className="ms-2 text-xs">{i.health.reason}</code> : null}
                      </Field>
                      <Field label={t("platform.tenantDetail.checkedAt")}>
                        <DateTime value={i.health.checked_at} />
                      </Field>
                      <Field label={t("platform.tenantDetail.version")}>
                        <code>{i.headscale_version}</code>
                      </Field>
                      <Field label={t("platform.tenantDetail.controlHost")}>
                        <code>{i.control_hostname}</code>
                      </Field>
                      <Field label={t("platform.tenantDetail.host")}>
                        <code className="text-xs">{i.host_id}</code>
                      </Field>
                      <Field label={t("platform.tenantDetail.netCidr")}>
                        <code>{i.net_cidr}</code>
                      </Field>
                      <Field label={t("platform.tenantDetail.derpRegion")}>
                        {i.derp_region_id === undefined ? t("common.none") : String(i.derp_region_id)}
                      </Field>
                      <Field label={t("platform.tenantDetail.apiKeyExpires")}>
                        <DateTime value={i.api_key_expires_at} />
                      </Field>
                    </dl>
                  </li>
                ))}
              </ul>
            )
          }
        </QueryBlock>
      )}
    </Section>
  );
}

function RelaySection({ tenantId, enabled }: { tenantId: string; enabled: boolean }) {
  const { t } = useTranslation();
  const q = useTenantRelay(tenantId, enabled);
  return (
    <Section id="tenant-relay" title={t("platform.tenantDetail.relay")}>
      {!enabled ? (
        <NoPermission />
      ) : (
        <QueryBlock query={q}>
          {(data) => (
            <div className="space-y-4">
              {data.items.length === 0 ? (
                <EmptyState>{t("platform.tenantDetail.noRelay")}</EmptyState>
              ) : (
                <div className="overflow-x-auto">
                  <table className="table">
                    <caption className="sr-only">{t("platform.tenantDetail.relay")}</caption>
                    <thead>
                      <tr>
                        <th scope="col">{t("platform.tenantDetail.relayCode")}</th>
                        <th scope="col">{t("platform.tenantDetail.relayKind")}</th>
                        <th scope="col">{t("platform.tenantDetail.relayHost")}</th>
                        <th scope="col">{t("platform.tenantDetail.relayStatus")}</th>
                        <th scope="col">{t("platform.tenantDetail.health")}</th>
                        <th scope="col">{t("platform.tenantDetail.checkedAt")}</th>
                      </tr>
                    </thead>
                    <tbody>
                      {data.items.map((r) => (
                        <tr key={r.region.id}>
                          <td>
                            <code>{r.region.code}</code>
                            <span className="hint block">{t("platform.tenantDetail.derpId", { id: r.region.derp_region_id })}</span>
                          </td>
                          <td>{t(`platform.tenantDetail.relayKinds.${r.region.kind}`)}</td>
                          <td>
                            <code>{`${r.region.hostname}:${String(r.region.derp_port)}`}</code>
                          </td>
                          <td>
                            <StatusBadge status={r.region.status} label={t(`status.relay.${r.region.status}`)} />
                          </td>
                          <td>
                            <StatusBadge status={r.health.status} label={t(`status.health.${r.health.status}`)} />
                            {r.health.reason ? <code className="ms-2 text-xs">{r.health.reason}</code> : null}
                          </td>
                          <td>
                            <DateTime value={r.health.checked_at} />
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
              {data.unavailable.length > 0 ? (
                <div data-testid="relay-unavailable">
                  <h3 className="text-sm font-semibold">{t("platform.tenantDetail.unmeasured")}</h3>
                  <ul className="mt-1 list-disc ps-5 text-sm text-muted">
                    {data.unavailable.map((u) => (
                      <li key={u.metric}>
                        <code>{u.metric}</code>
                        {": "}
                        {t("platform.tenantDetail.unavailableReason", { reason: u.reason })}
                      </li>
                    ))}
                  </ul>
                </div>
              ) : null}
            </div>
          )}
        </QueryBlock>
      )}
    </Section>
  );
}

function JobsSection({ tenantId, enabled }: { tenantId: string; enabled: boolean }) {
  const { t } = useTranslation();
  const pager = useCursorPager(tenantId);
  const q = useTenantJobs(tenantId, pager.cursor, enabled);
  return (
    <Section id="tenant-jobs" title={t("platform.tenantDetail.jobs")}>
      {!enabled ? (
        <NoPermission />
      ) : (
        <QueryBlock query={q}>
          {(data) =>
            data.items.length === 0 ? (
              <EmptyState>{t("platform.tenantDetail.noJobs")}</EmptyState>
            ) : (
              <>
                <JobTable jobs={data.items} showTenant={false} caption={t("platform.tenantDetail.jobs")} />
                <Pager pager={pager} nextCursor={data.next_cursor} label={t("platform.tenantDetail.jobsPagination")} />
              </>
            )
          }
        </QueryBlock>
      )}
    </Section>
  );
}
