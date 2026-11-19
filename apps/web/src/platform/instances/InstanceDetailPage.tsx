// Instance detail (§12.2): GET /platform/instances/{id} (trạng thái, version Headscale + image digest, health có
// checked_at), GET /platform/instances/{id}/config-versions (version cấu hình — `current` là version đang hiệu lực;
// P4-T03), bản backup gần đây (GET /platform/backups?instance= — platform.backup:read) và thao tác vận hành
// (InstanceActions). Không có dữ liệu nội bộ của tenant (§8.4 bất biến 2).
import type { ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { Link, useParams } from "react-router";
import { ApiError } from "../../api/problem";
import { useCursorPager } from "../../api/pagination";
import { isUuid } from "../../api/queryClient";
import { can } from "../../auth/permissions";
import { EmptyState, Field, JsonBlock, Pager, QueryBlock } from "../../ui/Data";
import { StatusBadge } from "../../ui/Status";
import { Timestamp } from "../../ui/time";
import { Loading, Page } from "../../components/Page";
import { ProblemAlert } from "../../components/ProblemAlert";
import { NotFoundPage } from "../../pages/StatusPages";
import { useInstance, useInstanceBackups, useInstanceConfigVersions, type Instance } from "../opsApi";
import { usePlatformRole } from "../PlatformScope";
import { InstanceActions } from "./InstanceActions";
import { HealthCell } from "./InstanceBits";

export function InstanceDetailPage() {
  const { instanceId: raw = "" } = useParams();
  const instanceId = raw.toLowerCase();
  if (!isUuid(instanceId)) return <NotFoundPage />;
  return <InstanceDetail key={instanceId} instanceId={instanceId} />;
}

function InstanceDetail({ instanceId }: { instanceId: string }) {
  const { t } = useTranslation();
  const role = usePlatformRole();
  const q = useInstance(instanceId);
  if (q.isPending) return <Loading />;
  if (q.isError) {
    if (q.error instanceof ApiError && q.error.status === 404) return <NotFoundPage />;
    return (
      <Page title={t("platform.instance.title")}>
        <ProblemAlert error={q.error} onRetry={() => void q.refetch()} />
      </Page>
    );
  }
  const i = q.data;
  const canBackups = can(role, "platform.backup:read");
  return (
    <Page title={i.control_hostname} actions={<InstanceActions instance={i} role={role} />}>
      <p className="mb-4">
        <Link to="/platform/instances" className="link text-sm">
          {t("platform.instance.back")}
        </Link>
      </p>
      <div className="space-y-6">
        <Summary instance={i} />
        <ConfigVersions instanceId={i.id} />
        <Section id="instance-backups" title={t("platform.instance.backups")}>
          {canBackups ? <Backups instanceId={i.id} /> : <p className="text-sm text-muted">{t("platform.tenantDetail.noPermission")}</p>}
        </Section>
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

function Summary({ instance: i }: { instance: Instance }) {
  const { t } = useTranslation();
  return (
    <Section id="instance-summary" title={t("platform.instance.summary")}>
      <dl className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        <Field label={t("platform.instances.col.status")}>
          <StatusBadge status={i.status}>{t(`status.instance.${i.status}`)}</StatusBadge>
        </Field>
        <Field label={t("platform.instances.col.health")}>
          <HealthCell health={i.health} />
        </Field>
        <Field label={t("platform.instances.col.version")}>
          <code>{i.headscale_version}</code>
        </Field>
        <Field label={t("platform.instance.digest")}>
          <code className="text-xs break-all" data-testid="image-digest">
            {i.image_digest}
          </code>
        </Field>
        <Field label={t("platform.instances.col.tenant")}>
          <Link to={`/platform/tenants/${i.tenant_id}`} className="link font-mono text-xs">
            {i.tenant_id}
          </Link>
        </Field>
        <Field label={t("platform.instances.col.host")}>
          <Link to={`/platform/hosts/${i.host_id}`} className="link font-mono text-xs">
            {i.host_id}
          </Link>
        </Field>
        <Field label={t("platform.instance.serverUrl")}>
          <code className="text-xs">{i.server_url}</code>
        </Field>
        <Field label={t("platform.tenantDetail.netCidr")}>
          <code>{i.net_cidr}</code>
        </Field>
        <Field label={t("platform.instance.runUid")}>
          <code>{String(i.run_uid)}</code>
        </Field>
        <Field label={t("platform.tenantDetail.derpRegion")}>{i.derp_region_id === undefined ? t("common.none") : String(i.derp_region_id)}</Field>
        <Field label={t("platform.tenantDetail.apiKeyExpires")}>
          <Timestamp iso={i.api_key_expires_at} emptyKey="common.none" />
        </Field>
        <Field label={t("platform.instance.noiseKey")}>
          {i.noise_key_fingerprint ? <code className="text-xs break-all">{i.noise_key_fingerprint}</code> : t("common.none")}
        </Field>
        <Field label={t("platform.instance.rowVersion")}>
          <code>{String(i.version)}</code>
        </Field>
      </dl>
    </Section>
  );
}

function ConfigVersions({ instanceId }: { instanceId: string }) {
  const { t } = useTranslation();
  const pager = useCursorPager(instanceId);
  const q = useInstanceConfigVersions(instanceId, pager.cursor);
  return (
    <Section id="instance-config" title={t("platform.instance.config")}>
      <QueryBlock query={q}>
        {(data) => {
          const current = data.items.find((v) => v.current);
          return data.items.length === 0 ? (
            <EmptyState>{t("platform.instance.noConfig")}</EmptyState>
          ) : (
            <div className="space-y-4">
              <p className="text-sm" data-testid="config-current">
                {current
                  ? t("platform.instance.currentConfig", { version: current.version })
                  : t("platform.instance.noCurrentConfig")}
              </p>
              <div className="overflow-x-auto">
                <table className="data-table">
                  <caption className="sr-only">{t("platform.instance.config")}</caption>
                  <thead>
                    <tr>
                      <th scope="col">{t("platform.instance.cv.version")}</th>
                      <th scope="col">{t("platform.instance.cv.status")}</th>
                      <th scope="col">{t("platform.instance.cv.template")}</th>
                      <th scope="col">{t("platform.instance.cv.sha")}</th>
                      <th scope="col">{t("platform.instance.cv.created")}</th>
                      <th scope="col">{t("platform.instance.cv.applied")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.items.map((v) => (
                      <tr key={v.id} aria-current={v.current ? "true" : undefined} data-testid="config-version">
                        <td>
                          <code>{String(v.version)}</code>
                          {v.current ? (
                            <span className="ms-2">
                              <StatusBadge tone="ok">{t("platform.instance.current")}</StatusBadge>
                            </span>
                          ) : null}
                        </td>
                        <td>
                          <StatusBadge status={v.status}>{t(`status.configVersion.${v.status}`, { defaultValue: v.status })}</StatusBadge>
                        </td>
                        <td>
                          <code className="text-xs">{v.template_version}</code>
                        </td>
                        <td>
                          <code className="text-xs" title={v.config_sha256}>
                            {v.config_sha256.slice(0, 12)}
                          </code>
                        </td>
                        <td>
                          <Timestamp iso={v.created_at} emptyKey="common.none" />
                        </td>
                        <td>
                          <Timestamp iso={v.applied_at} emptyKey="common.none" />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              {current ? (
                <details>
                  <summary className="cursor-pointer text-sm font-semibold">{t("platform.instance.params", { version: current.version })}</summary>
                  <div className="mt-2">
                    <JsonBlock value={current.params} />
                  </div>
                </details>
              ) : null}
              <Pager pager={pager} nextCursor={data.next_cursor} label={t("platform.instance.configPagination")} />
            </div>
          );
        }}
      </QueryBlock>
    </Section>
  );
}

function Backups({ instanceId }: { instanceId: string }) {
  const { t } = useTranslation();
  const q = useInstanceBackups(instanceId, true);
  return (
    <QueryBlock query={q}>
      {(data) =>
        data.items.length === 0 ? (
          <EmptyState>{t("platform.instance.noBackups")}</EmptyState>
        ) : (
          <div className="overflow-x-auto">
            <table className="data-table">
              <caption className="sr-only">{t("platform.instance.backups")}</caption>
              <thead>
                <tr>
                  <th scope="col">{t("platform.instance.bk.started")}</th>
                  <th scope="col">{t("platform.instance.bk.method")}</th>
                  <th scope="col">{t("platform.instance.bk.size")}</th>
                  <th scope="col">{t("platform.instance.bk.version")}</th>
                  <th scope="col">{t("platform.instance.bk.verified")}</th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((b) => (
                  <tr key={b.id}>
                    <td>
                      <Timestamp iso={b.started_at} emptyKey="common.none" />
                    </td>
                    <td>{b.method ? <code>{b.method}</code> : t("common.none")}</td>
                    <td>{b.size_bytes === null || b.size_bytes === undefined ? t("common.none") : <FormattedBytes value={b.size_bytes} />}</td>
                    <td>{b.headscale_version ? <code>{b.headscale_version}</code> : t("common.none")}</td>
                    <td>
                      <Timestamp iso={b.verified_at} emptyKey="common.none" />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )
      }
    </QueryBlock>
  );
}

export function FormattedBytes({ value }: { value: number }) {
  const { i18n } = useTranslation();
  const fmt = new Intl.NumberFormat(i18n.language, { style: "unit", unit: "kilobyte", maximumFractionDigits: 1 });
  return <span>{fmt.format(value / 1024)}</span>;
}
