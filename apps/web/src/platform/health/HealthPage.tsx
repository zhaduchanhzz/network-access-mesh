// Platform Health (§12.2 "Theo dõi health — số liệu thật, có checked_at"; §16.2): GET /platform/health, tự làm mới mỗi
// 30 s. Mọi số là của API tại `checked_at`; thành phần chưa có nguồn đo (status `unknown` + `reason`: no_probe,
// not_deployed, no_heartbeat…) hiện "không khả dụng" kèm lý do — không số giả (§12.4). Không có dữ liệu nội bộ tenant.
import type { ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { Link } from "react-router";
import { QueryBlock } from "../../ui/Data";
import { UnavailableBox, useCodeText } from "../../ui/Status";
import { ObservedAt } from "../../ui/time";
import { Page } from "../../components/Page";
import { HealthCell } from "../instances/InstanceBits";
import { usePlatformHealth, type PlatformHealth } from "../opsApi";

export function HealthPage() {
  const { t } = useTranslation();
  const q = usePlatformHealth();
  return (
    <Page title={t("nav.platform.health")}>
      <QueryBlock query={q}>{(h) => <HealthView health={h} />}</QueryBlock>
    </Page>
  );
}

function Counts({ counts, prefix }: { counts: Record<string, number>; prefix: string }) {
  const { t } = useTranslation();
  const entries = Object.entries(counts).filter(([, n]) => n > 0);
  if (entries.length === 0) return <p className="text-sm text-muted">{t("platform.health.none")}</p>;
  return (
    <ul className="mt-1 space-y-0.5 text-sm">
      {entries.map(([k, n]) => (
        <li key={k} data-count={k}>
          {prefix ? t(`${prefix}.${k}`, { defaultValue: k }) : <code>{k}</code>}
          {": "}
          <strong>{String(n)}</strong>
        </li>
      ))}
    </ul>
  );
}

function Tile({ id, title, value, children }: { id: string; title: string; value: ReactNode; children?: ReactNode }) {
  return (
    <section aria-labelledby={id} className="card" data-testid={id}>
      <h2 id={id} className="text-sm font-semibold text-muted">
        {title}
      </h2>
      <p className="mt-1 text-2xl font-semibold">{value}</p>
      {children}
    </section>
  );
}

function HealthView({ health: h }: { health: PlatformHealth }) {
  const { t } = useTranslation();
  const code = useCodeText();
  const unfinished = Object.values(h.jobs.unfinished).reduce((a, b) => a + b, 0);
  const measured = h.components.filter((c) => c.status !== "unknown");
  const unmeasured = h.components.filter((c) => c.status === "unknown");
  return (
    <div className="space-y-6">
      <ObservedAt labelKey="ui.checkedAt" iso={h.checked_at} />
      <div className="grid gap-4 sm:grid-cols-3">
        <Tile id="health-tenants" title={t("platform.health.tenants")} value={String(h.tenants.total)}>
          <Counts counts={h.tenants.by_status} prefix="status.tenant" />
          <Link to="/platform/tenants" className="link mt-2 inline-block text-sm">
            {t("platform.health.openTenants")}
          </Link>
        </Tile>
        <Tile id="health-instances" title={t("platform.health.instances")} value={String(h.instances.total)}>
          <p className={h.instances.unhealthy > 0 ? "text-sm font-semibold text-danger" : "text-sm"} data-testid="unhealthy">
            {t("platform.health.unhealthy", { count: h.instances.unhealthy })}
          </p>
          <Counts counts={h.instances.by_status} prefix="status.instance" />
          <h3 className="mt-2 text-xs font-semibold text-muted">{t("platform.health.byHealth")}</h3>
          <Counts counts={h.instances.by_health} prefix="status.health" />
          <h3 className="mt-2 text-xs font-semibold text-muted">{t("platform.health.byVersion")}</h3>
          <Counts counts={h.instances.by_version} prefix="" />
          <Link to="/platform/instances" className="link mt-2 inline-block text-sm">
            {t("platform.health.openInstances")}
          </Link>
        </Tile>
        <Tile id="health-jobs" title={t("platform.health.jobs")} value={String(unfinished)}>
          <Counts counts={h.jobs.unfinished} prefix="status.job" />
          <p className={h.jobs.failed_last_24h > 0 ? "mt-2 text-sm font-semibold text-danger" : "mt-2 text-sm"} data-testid="failed-24h">
            {t("platform.health.failed24h", { count: h.jobs.failed_last_24h })}
          </p>
          <ObservedAt labelKey="ui.checkedAt" iso={h.jobs.checked_at} />
          <Link to="/platform/jobs" className="link mt-2 inline-block text-sm">
            {t("platform.health.openJobs")}
          </Link>
        </Tile>
      </div>
      <section aria-labelledby="health-components" className="card">
        <h2 id="health-components" className="mb-3 text-lg font-semibold">
          {t("platform.health.components")}
        </h2>
        {measured.length === 0 ? null : (
          <ul className="mb-4 grid gap-3 sm:grid-cols-2" data-testid="components-measured">
            {measured.map((c) => (
              <li key={c.name} className="rounded-md border border-line p-3" data-component={c.name}>
                <p className="mb-1 font-mono text-sm">{c.name}</p>
                <HealthCell health={c} />
              </li>
            ))}
          </ul>
        )}
        {unmeasured.length === 0 ? null : (
          <div className="grid gap-3 sm:grid-cols-2" data-testid="components-unavailable">
            {unmeasured.map((c) => (
              <div key={c.name} data-component={c.name}>
                <UnavailableBox title={c.name} reason={c.reason ? code("health.reason", c.reason, "health.reasonOther") : t("platform.health.noReason")} code={c.reason} />
                <ObservedAt labelKey="ui.checkedAt" iso={c.checked_at} />
              </div>
            ))}
          </div>
        )}
        {h.components.length === 0 ? <p className="text-sm text-muted">{t("platform.health.noComponents")}</p> : null}
      </section>
    </div>
  );
}
