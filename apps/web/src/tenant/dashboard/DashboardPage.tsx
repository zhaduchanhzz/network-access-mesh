// Tổng quan của tenant (P4-T04, §12.3 "mọi số có synced_at; không có số giả"): GET /tenants/{t}/dashboard — số thiết
// bị (tổng/trực tuyến theo control plane) kèm `synced_at`, health của instance kèm `checked_at`; mục chưa có nguồn
// (`unavailable`) hiển thị "không khả dụng" kèm lý do. Thêm thẻ rà soát tagged node không hết hạn (§7.4, ADR-23) — số
// đếm từ GET /devices?tagged=true&has_expiry=false.
import { useQuery } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { Link } from "react-router";
import { api, call } from "../../api/client";
import { queryKeys } from "../../api/queryClient";
import type { components } from "../../api/schema";
import { can } from "../../auth/permissions";
import { Loading, Page } from "../../components/Page";
import { ProblemAlert } from "../../components/ProblemAlert";
import { StatusBadge, UnavailableBox, useCodeText, type Tone } from "../../ui/Status";
import { ObservedAt } from "../../ui/time";
import { useTenant } from "../TenantScope";
import { REVIEW_QUERY } from "../devices/deviceModel";

type Dashboard = components["schemas"]["TenantDashboard"];
type HealthStatus = components["schemas"]["HealthStatus"];

export const DASHBOARD_POLL_MS = 30_000;
const REVIEW_LIMIT = 200;

export const HEALTH_TONE: Record<HealthStatus, Tone> = { healthy: "ok", unhealthy: "danger", unknown: "warn" };

export function DashboardPage() {
  const { t } = useTranslation();
  const { tenantId, role } = useTenant();
  const code = useCodeText();
  const dash = useQuery({
    queryKey: queryKeys.tenant(tenantId, "dashboard"),
    queryFn: () => call(api.GET("/tenants/{tenantId}/dashboard", { params: { path: { tenantId } } })),
    refetchInterval: DASHBOARD_POLL_MS,
  });
  const canDevices = can(role, "tenant.device:read");
  const review = useQuery({
    queryKey: queryKeys.tenant(tenantId, "devices", "review-count"),
    queryFn: () =>
      call(api.GET("/tenants/{tenantId}/devices", { params: { path: { tenantId }, query: { ...REVIEW_QUERY, limit: REVIEW_LIMIT } } })),
    enabled: canDevices,
  });

  if (dash.isPending) return <Loading />;
  if (dash.isError) {
    return (
      <Page title={t("nav.tenant.overview")}>
        <ProblemAlert error={dash.error} onRetry={() => void dash.refetch()} />
      </Page>
    );
  }
  const d: Dashboard = dash.data;
  const devicesUnavailable = d.unavailable.find((u) => u.section === "devices") ?? (d.devices.synced_at === null ? { section: "devices", reason: "never_synced" } : undefined);
  const others = d.unavailable.filter((u) => u.section !== "devices");

  return (
    <Page title={t("nav.tenant.overview")}>
      <div className="grid gap-4 md:grid-cols-2">
        <section className="card" aria-labelledby="dash-devices" data-testid="dash-devices">
          <h2 id="dash-devices" className="font-semibold">
            {t("dashboard.devices")}
          </h2>
          {devicesUnavailable ? (
            <div className="mt-2">
              <UnavailableBox
                title={t("dashboard.devices")}
                reason={code("dashboard.reasons", devicesUnavailable.reason)}
                code={devicesUnavailable.reason}
              />
            </div>
          ) : (
            <>
              <dl className="mt-2 grid grid-cols-2 gap-2">
                <div>
                  <dt className="text-sm text-muted">{t("dashboard.total")}</dt>
                  <dd className="text-2xl font-semibold" data-testid="dash-total">
                    {d.devices.total}
                  </dd>
                </div>
                <div>
                  <dt className="text-sm text-muted">{t("dashboard.online")}</dt>
                  <dd className="text-2xl font-semibold" data-testid="dash-online">
                    {d.devices.online}
                  </dd>
                </div>
              </dl>
              <p className="mt-1 text-xs text-muted">{t("dashboard.onlineNote")}</p>
              <ObservedAt labelKey="ui.syncedAt" iso={d.devices.synced_at} />
            </>
          )}
          {canDevices ? (
            <Link to={`/t/${tenantId}/devices`} className="link mt-2 inline-block text-sm">
              {t("dashboard.openDevices")}
            </Link>
          ) : null}
        </section>

        <section className="card" aria-labelledby="dash-instance" data-testid="dash-instance">
          <h2 id="dash-instance" className="font-semibold">
            {t("dashboard.instance")}
          </h2>
          <p className="mt-2">
            <StatusBadge tone={HEALTH_TONE[d.instance.status]} testId="dash-instance-status">
              {t(`health.status.${d.instance.status}`)}
            </StatusBadge>
          </p>
          {d.instance.reason ? (
            <p className="mt-1 text-sm">
              {code("health.reason", d.instance.reason)} <code>{`(${d.instance.reason})`}</code>
            </p>
          ) : null}
          <ObservedAt labelKey="ui.checkedAt" iso={d.instance.checked_at} />
        </section>

        {canDevices ? (
          <section className="card" aria-labelledby="dash-review" data-testid="dash-review">
            <h2 id="dash-review" className="font-semibold">
              {t("devices.review.title")}
            </h2>
            <p className="mt-1 text-sm text-muted">{t("devices.review.description")}</p>
            {review.isError ? <ProblemAlert error={review.error} /> : null}
            {review.isSuccess ? (
              <p className="mt-2 text-2xl font-semibold" data-testid="dash-review-count">
                {review.data.next_cursor ? `${review.data.items.length}+` : review.data.items.length}
              </p>
            ) : null}
            {devicesUnavailable ? null : <ObservedAt labelKey="ui.syncedAt" iso={d.devices.synced_at} />}
            <Link to={`/t/${tenantId}/devices?view=review`} className="link mt-2 inline-block text-sm">
              {t("devices.review.open")}
            </Link>
          </section>
        ) : null}
      </div>

      {others.length > 0 ? (
        <section className="mt-6" aria-labelledby="dash-unavailable">
          <h2 id="dash-unavailable" className="mb-2 font-semibold">
            {t("dashboard.unavailableTitle")}
          </h2>
          <div className="grid gap-3 md:grid-cols-2">
            {others.map((u) => (
              <UnavailableBox
                key={u.section}
                title={code("dashboard.sections", u.section, "dashboard.sections.other")}
                reason={code("dashboard.reasons", u.reason)}
                code={u.reason}
              />
            ))}
          </div>
        </section>
      ) : null}
    </Page>
  );
}
