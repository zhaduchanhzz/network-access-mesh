// Relay Regions (§12.2 "Ở MVP chỉ đọc (embedded theo tenant)"): GET /platform/relay-regions — region, tenant sở hữu,
// assignment, health có checked_at; số đo relay không có nguồn nằm trong `unavailable` ⇒ "không khả dụng — <lý do>"
// (§10.6, §12.4). Ghi (POST/PATCH/DELETE) thuộc P7-T04 — không có nút.
import { useTranslation } from "react-i18next";
import { Link } from "react-router";
import { useCursorPager } from "../../api/pagination";
import { EmptyState, Pager, QueryBlock } from "../../ui/Data";
import { StatusBadge, UnavailableBox, useCodeText } from "../../ui/Status";
import { Page } from "../../components/Page";
import { HealthCell } from "../instances/InstanceBits";
import { usePlatformRelayRegions } from "../opsApi";
import { TenantRef } from "../Refs";

export function RelayRegionListPage() {
  const { t } = useTranslation();
  const code = useCodeText();
  const pager = useCursorPager("");
  const q = usePlatformRelayRegions(pager.cursor);
  return (
    <Page title={t("nav.platform.relayRegions")}>
      <p className="mb-4 text-sm text-muted">{t("platform.relayRegions.readOnly")}</p>
      <QueryBlock query={q}>
        {(data) => (
          <div className="space-y-6">
            {data.items.length === 0 ? (
              <EmptyState>{t("platform.relayRegions.empty")}</EmptyState>
            ) : (
              <div className="relative overflow-x-auto rounded-lg border border-line bg-surface">
                <table className="data-table">
                  <caption className="sr-only">{t("nav.platform.relayRegions")}</caption>
                  <thead>
                    <tr>
                      <th scope="col">{t("platform.tenantDetail.relayCode")}</th>
                      <th scope="col">{t("platform.tenantDetail.relayKind")}</th>
                      <th scope="col">{t("platform.tenantDetail.relayHost")}</th>
                      <th scope="col">{t("platform.tenantDetail.relayStatus")}</th>
                      <th scope="col">{t("platform.tenantDetail.health")}</th>
                      <th scope="col">{t("platform.relayRegions.owner")}</th>
                      <th scope="col">{t("platform.relayRegions.assignments")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.items.map((r) => (
                      <tr key={r.region.id} data-testid="relay-row">
                        <td>
                          <code>{r.region.code}</code>
                          <span className="hint block">{t("platform.tenantDetail.derpId", { id: r.region.derp_region_id })}</span>
                        </td>
                        <td>{t(`platform.tenantDetail.relayKinds.${r.region.kind}`)}</td>
                        <td>
                          <code>{`${r.region.hostname}:${String(r.region.derp_port)}`}</code>
                        </td>
                        <td>
                          <StatusBadge status={r.region.status}>{t(`status.relay.${r.region.status}`)}</StatusBadge>
                        </td>
                        <td>
                          <HealthCell health={r.health} />
                        </td>
                        <td>
                          {r.tenant_id ? (
                            <TenantRef id={r.tenant_id} slug={r.tenant_slug} name={r.tenant_name} />
                          ) : (
                            t("platform.relayRegions.shared")
                          )}
                        </td>
                        <td>
                          {r.assignments.length === 0 ? (
                            t("common.none")
                          ) : (
                            <ul className="text-xs">
                              {r.assignments.map((a) => (
                                <li key={a.id}>
                                  <Link to={`/platform/instances/${a.instance_id}`} className="link font-mono">
                                    {a.instance_id.slice(0, 8)}
                                  </Link>{" "}
                                  <StatusBadge status={a.instance_status}>{t(`status.instance.${a.instance_status}`)}</StatusBadge>
                                </li>
                              ))}
                            </ul>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            {data.unavailable.length > 0 ? (
              <section aria-labelledby="relay-unmeasured" data-testid="relay-unavailable">
                <h2 id="relay-unmeasured" className="mb-2 text-lg font-semibold">
                  {t("platform.tenantDetail.unmeasured")}
                </h2>
                <div className="grid gap-3 sm:grid-cols-2">
                  {data.unavailable.map((u) => (
                    <UnavailableBox key={u.metric} title={code("relay.metrics", u.metric)} reason={code("relay.reasons", u.reason)} code={u.reason} />
                  ))}
                </div>
              </section>
            ) : null}
            <Pager pager={pager} nextCursor={data.next_cursor} label={t("platform.relayRegions.pagination")} />
          </div>
        )}
      </QueryBlock>
    </Page>
  );
}
